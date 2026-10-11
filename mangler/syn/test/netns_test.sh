#!/usr/bin/env bash
# Root-only, isolated VPS integration test. All generated files live in mktemp.
set -euo pipefail
export PATH=/usr/local/go/bin:/usr/sbin:/usr/bin:/sbin:/bin
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[[ $(id -u) == 0 ]] || { printf '%s\n' 'Run as root on Linux.' >&2; exit 1; }
for tool in ip nft ethtool tcpdump python3 p0f go setpriv; do command -v "$tool" >/dev/null; done
WORK=$(mktemp -d /tmp/mirsyn-test-XXXXXX)
chmod 0755 "$WORK"
TX="mirsyn-send-$$"
RX="mirsyn-recv-$$"
VA="mirsyn-$$-a"
VB="mirsyn-$$-b"
MARK=0x6d735901
PIDS=()
CORE_BEFORE=$(sysctl -n net.core.rmem_max)
cleanup() {
    status=$?
    trap - EXIT INT TERM
    set +e
    for pid in "${PIDS[@]}"; do kill -TERM "$pid" 2>/dev/null; done
    for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null; done
    ip netns exec "$TX" "$WORK/mirage-syn" rules uninstall 2>/dev/null
    for ns in "$TX" "$RX"; do
        for pid in $(ip netns pids "$ns" 2>/dev/null); do kill -KILL "$pid" 2>/dev/null; done
        ip netns del "$ns" 2>/dev/null
    done
    ip link del "$VA" 2>/dev/null
    ip link del "$VB" 2>/dev/null
    if [[ $status != 0 ]]; then
        printf '%s\n' 'Failure diagnostics:'
        for log in "$WORK"/*.log; do [[ -f $log ]] && { printf '%s\n' "$log"; tail -40 "$log"; }; done
    fi
    rm -rf "$WORK"
    printf 'cleanup: namespaces removed; global rmem_max before=%s after=%s\n' "$CORE_BEFORE" "$(sysctl -n net.core.rmem_max)"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
go -C "$ROOT" build -o "$WORK/mirage-syn" ./cmd/mirage-syn
python3 - "$WORK/config.yaml" "$MARK" <<'PY'
import sys
with open(sys.argv[1], 'w') as stream:
    stream.write('mark: %s\nipv6: block\nsyn:\n  enabled: true\n  queue_num: 4949\n  profile: macos\n  mss: 1460\n' % sys.argv[2])
PY
ip netns add "$TX"
ip netns add "$RX"
ip link add "$VA" type veth peer name "$VB"
ip link set "$VA" netns "$TX"
ip link set "$VB" netns "$RX"
ip -n "$TX" link set "$VA" name tx0
ip -n "$RX" link set "$VB" name rx0
for ns in "$TX" "$RX"; do ip -n "$ns" link set lo up; done
ip -n "$TX" addr add 192.0.2.1/24 dev tx0
ip -n "$RX" addr add 192.0.2.2/24 dev rx0
ip -n "$TX" -6 addr add 2001:db8:1::1/64 dev tx0 nodad
ip -n "$RX" -6 addr add 2001:db8:1::2/64 dev rx0 nodad
ip -n "$TX" link set tx0 mtu 1500 up
ip -n "$RX" link set rx0 mtu 1500 up
# Disable receive aggregation so captures have ordinary wire-sized segments.
ip netns exec "$RX" ethtool -K rx0 gro off gso off tso off
ip netns exec "$RX" python3 "$ROOT/test/traffic.py" server >"$WORK/server.log" 2>&1 &
SERVER=$!; PIDS+=("$SERVER")
ip netns exec "$RX" python3 "$ROOT/test/traffic.py" server --ipv6 >"$WORK/server6.log" 2>&1 &
SERVER6=$!; PIDS+=("$SERVER6")
wait_log() {
    local file=$1 text=$2 pid=$3
    for _ in $(seq 1 100); do
        if rg -q "$text" "$file" 2>/dev/null || grep -q "$text" "$file" 2>/dev/null; then return; fi
        kill -0 "$pid" 2>/dev/null || { cat "$file"; return 1; }
        sleep 0.05
    done
    cat "$file"; return 1
}
wait_log "$WORK/server.log" ready "$SERVER"
wait_log "$WORK/server6.log" ready "$SERVER6"
ip netns exec "$RX" p0f -i rx0 -o "$WORK/p0f.log" >"$WORK/p0f.console.log" 2>&1 &
P0F=$!; PIDS+=("$P0F")
sleep 0.5
kill -0 "$P0F"
capture() {
    local name=$1 mark=$2 shape=$3 scale=$4 bulk=${5:-}
    ip netns exec "$RX" tcpdump --immediate-mode -i rx0 -nn -s 0 -U -w "$WORK/$name.pcap" 'tcp port 18080 and tcp[tcpflags] & tcp-syn != 0' >"$WORK/$name.capture.log" 2>&1 &
    local cap=$!; PIDS+=("$cap")
    wait_log "$WORK/$name.capture.log" listening "$cap"
    ip netns exec "$TX" python3 "$ROOT/test/traffic.py" client --mark "$mark" ${bulk:+--bulk}
    sleep 0.15
    kill -INT "$cap"; wait "$cap"
    printf '\ncase=%s\n' "$name"
    local baseline=()
    if [[ $name == unmarked-* || $name == bypass ]]; then baseline=(--baseline "$WORK/native6.json"); fi
    python3 "$ROOT/test/verify_capture.py" "$WORK/$name.pcap" "$shape" "$scale" "${baseline[@]}" >"$WORK/$name.json"
    cat "$WORK/$name.json"
    tcpdump -nn -vvv -r "$WORK/$name.pcap" 'src host 192.0.2.1 and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn' 2>/dev/null
    # Also show full p0f signatures, not just the cached OS guess.
    p0f -r "$WORK/$name.pcap" >"$WORK/$name.p0f.log" 2>&1
    printf 'p0f case=%s\n' "$name"
    cat "$WORK/$name.p0f.log"
}
DEFAULT_SCALE=$(ip netns exec "$TX" python3 -c 'import math,sys; print(max(0,min(14,int(math.log2(max(int(open("/proc/sys/net/ipv4/tcp_rmem").read().split()[2]),int(sys.argv[1]))))-15)))' "$CORE_BEFORE")
capture native-default 0 native "$DEFAULT_SCALE"
printf '\nnamespace sysctl scope:\n'
ip netns exec "$TX" sysctl net.ipv4.tcp_rmem
ip netns exec "$TX" sysctl net.core.rmem_max || true
printf 'global net.core.rmem_max=%s (read only; not changed)\n' "$CORE_BEFORE"
# Apply only the namespaced keys in the deliverable fragment. rmem_max is global
# on this 6.1 kernel and is intentionally not written by this test.
awk '/^net.ipv4\./ { print }' "$ROOT/deploy/99-mirage-syn.sysctl.conf" >"$WORK/netns.sysctl.conf"
ip netns exec "$TX" sysctl -p "$WORK/netns.sysctl.conf"
capture native6 0 native 6
ip netns exec "$TX" "$WORK/mirage-syn" rules install -c "$WORK/config.yaml"
ip netns exec "$TX" "$WORK/mirage-syn" run -c "$WORK/config.yaml" --no-rules >"$WORK/daemon.log" 2>&1 &
DAEMON=$!; PIDS+=("$DAEMON")
wait_log "$WORK/daemon.log" ready "$DAEMON"
ip netns exec "$TX" "$WORK/mirage-syn" check -c "$WORK/config.yaml"
for mode in on off; do
    printf '\nTX checksum offload=%s\n' "$mode"
    ip netns exec "$TX" ethtool -K tx0 tx "$mode"
    ip netns exec "$TX" ethtool -k tx0
    capture "unmarked-$mode" 0 native 6
    capture "rewritten-$mode" "$MARK" macos 6 bulk
done
ip netns exec "$TX" python3 "$ROOT/test/traffic.py" client --ipv6
ip netns exec "$TX" python3 "$ROOT/test/traffic.py" client --mark "$MARK" --ipv6 --expect-block
ip netns exec "$TX" nft list table inet mirage_syn
kill -KILL "$DAEMON"
wait "$DAEMON" 2>/dev/null || true
sleep 0.25
capture bypass "$MARK" native 6
ip netns exec "$TX" "$WORK/mirage-syn" rules uninstall
if ip netns exec "$TX" nft list table inet mirage_syn >"$WORK/uninstall.log" 2>&1; then
    printf '%s\n' 'table left after uninstall' >&2; exit 1
fi
printf '%s\n' 'uninstall: inet mirage_syn absent'
# Exercise automatic rule ownership and graceful removal independently of bypass.
ip netns exec "$TX" ethtool -K tx0 tx on
ip netns exec "$TX" setpriv --reuid=65534 --regid=65534 --clear-groups --bounding-set=-all,+net_admin --inh-caps=+net_admin --ambient-caps=+net_admin --no-new-privs "$WORK/mirage-syn" run -c "$WORK/config.yaml" >"$WORK/graceful.log" 2>&1 &
GRACEFUL=$!; PIDS+=("$GRACEFUL")
wait_log "$WORK/graceful.log" ready "$GRACEFUL"
printf '\nnonroot daemon capability proof:\n'
awk '/^Uid:|^Cap(Inh|Prm|Eff|Bnd|Amb):|^NoNewPrivs:/ { print }' "/proc/$GRACEFUL/status"
[[ $(awk '/^CapEff:/ { print $2 }' "/proc/$GRACEFUL/status") == 0000000000001000 ]]
[[ $(awk '/^Uid:/ { print $2 }' "/proc/$GRACEFUL/status") == 65534 ]]
ip netns exec "$TX" python3 "$ROOT/test/traffic.py" client --mark "$MARK"
kill -TERM "$GRACEFUL"; wait "$GRACEFUL"
cat "$WORK/graceful.log"
if ip netns exec "$TX" nft list table inet mirage_syn >/dev/null 2>&1; then exit 1; fi
kill -TERM "$P0F"; wait "$P0F" || true
printf '\nlive p0f receiver log:\n'
cat "$WORK/p0f.log"
[[ $(sysctl -n net.core.rmem_max) == "$CORE_BEFORE" ]]
printf '\n%s\n' 'PASS: both offload modes, bulk SHA256, unmarked isolation, IPv6 blocking, bypass, rule lifecycle'
