#!/bin/bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH
[[ $EUID == 0 ]] || { printf 'Run as root on Linux.\n' >&2; exit 1; }
# ip netns exec remounts /sys, hiding the host bpffs. Keep a dedicated bpffs in
# a private mount namespace at a path unaffected by that remount.
if [[ ${MIRRTT_PRIVATE_MOUNT:-0} != 1 ]]; then
    exec unshare --mount --propagation private env MIRRTT_PRIVATE_MOUNT=1 bash "$0" "$@"
fi
repo=$(cd "$(dirname "$0")/.." && pwd)
runid=$$
sender=mirrtt-s$runid
receiver=mirrtt-r$runid
work=$(mktemp -d /tmp/mirrtt-test.XXXXXX)
pins=$work/bpf
daemon='' server='' capture=''
cleaned=0
snapshot() {
    tc qdisc show | sort > "$work/$1.qdisc"
    tc qdisc show dev ens4 | sort > "$work/$1.ens4"
    tc -j qdisc show | python3 -c 'import json,sys; print(json.dumps(sorted(json.load(sys.stdin),key=lambda q:json.dumps(q,sort_keys=True)),sort_keys=True))' > "$work/$1.qdisc.json"
    tc -j qdisc show dev ens4 | python3 -c 'import json,sys; print(json.dumps(sorted(json.load(sys.stdin),key=lambda q:json.dumps(q,sort_keys=True)),sort_keys=True))' > "$work/$1.ens4.json"
    bpftool -j prog show | python3 -c 'import json,sys; print(json.dumps(sorted(json.load(sys.stdin),key=lambda p:p["id"]),sort_keys=True))' > "$work/$1.bpf"
}
cleanup() {
    [[ $cleaned == 1 ]] && return
    cleaned=1
    set +e
    local result=0
    for pid in "$daemon" "$server" "$capture"; do
        if [[ -n $pid ]]; then kill -TERM "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
    done
    if [[ -f $work/state/veth0.json ]]; then ip netns exec "$sender" "$work/mirage-rtt" uninstall -c "$work/config.yaml" --state-dir "$work/state" --pin-dir "$pins" || true; fi
    ip netns del "$sender" 2>/dev/null || true
    ip netns del "$receiver" 2>/dev/null || true
    ip link del mirrtt-v$runid 2>/dev/null || true
    ip link del mirrtt-w$runid 2>/dev/null || true
    rm -rf "$pins/veth0"
    umount "$pins" 2>/dev/null || true
    snapshot after
    cmp "$work/before.qdisc" "$work/after.qdisc" || result=1
    cmp "$work/before.ens4" "$work/after.ens4" || result=1
    cmp "$work/before.bpf" "$work/after.bpf" || result=1
    cmp "$work/before.qdisc.json" "$work/after.qdisc.json" || result=1
    cmp "$work/before.ens4.json" "$work/after.ens4.json" || result=1
    if ip netns list | grep -q "mirrtt-"; then printf 'Namespace leftovers found\n' >&2; result=1; fi
    if [[ $result == 0 ]]; then printf 'T7 host qdiscs, ens4 and complete BPF inventory unchanged; no mirrtt-* namespaces/pins\n'; fi
    printf 'Main namespace before/after qdiscs:\n'; cat "$work/before.qdisc" "$work/after.qdisc"
    printf 'ens4 before/after:\n'; cat "$work/before.ens4" "$work/after.ens4"
    if [[ -n ${MIRRTT_RESULTS:-} ]]; then
        mkdir -p "$MIRRTT_RESULTS"
        cp "$work"/{before,after}.{qdisc,ens4,bpf,qdisc.json,ens4.json} "$MIRRTT_RESULTS/"
        cp "$work"/*.{json,jsonl,pcap,log} "$MIRRTT_RESULTS/" 2>/dev/null || true
    fi
    rm -rf "$work"
    return "$result"
}
on_exit() {
    local status=$?
    if [[ $status != 0 ]]; then for logfile in "$work/daemon.log" "$work/server.log" "$work/tcpdump.log"; do if [[ -f $logfile ]]; then printf '%s\n' "$logfile"; cat "$logfile"; fi; done; fi
    cleanup || status=1
    exit "$status"
}
trap on_exit EXIT
snapshot before
cp /proc/sys/net/core/default_qdisc "$work/default-qdisc"
mkdir "$pins"
mount -t bpf bpf "$pins"
if [[ -n ${MIRRTT_BINARY:-} ]]; then cp "$MIRRTT_BINARY" "$work/mirage-rtt"; else /usr/local/go/bin/go build -o "$work/mirage-rtt" "$repo/cmd/mirage-rtt"; fi
ip netns add "$sender"
ip netns add "$receiver"
ip link add mirrtt-v$runid type veth peer name mirrtt-w$runid
ip link set mirrtt-v$runid netns "$sender"
ip link set mirrtt-w$runid netns "$receiver"
ip -n "$sender" link set mirrtt-v$runid name veth0
ip -n "$receiver" link set mirrtt-w$runid name veth0
# Complete checksums in validate_xmit_skb after clsact. TCP still submits GSO
# super-packets and CHECKSUM_PARTIAL to the BPF program before this validation;
# telemetry proves those inputs, and receiver tcpdump validates each wire segment.
ip netns exec "$sender" ethtool -K veth0 tx off gro on > /dev/null
ip netns exec "$receiver" ethtool -K veth0 tx off gro on > /dev/null
ip -n "$receiver" link set veth0 gro_max_size 1500
# Emulate a physical NIC's per-flow RSS queue even when the shaping-side GRO
# variant is off. Otherwise veth's per-CPU backlogs reorder downstream data and
# create fresh SACK blocks on piggybacked uploads (the documented SACK limit).
ip netns exec "$sender" sh -c 'printf 1 > /sys/class/net/veth0/queues/rx-0/rps_cpus'
ip netns exec "$receiver" sh -c 'printf 1 > /sys/class/net/veth0/queues/rx-0/rps_cpus'
# veth GRO enables its single NAPI receive queue. Turning it off at the capture
# end uses per-CPU netif_rx backlogs, which can reverse packets sent by different
# CPUs even with strictly ordered fq EDTs. An MTU-sized GRO limit keeps the NAPI
# FIFO without aggregating TCP headers in the wire-checksum capture.
ip -n "$sender" link set lo up
ip -n "$receiver" link set lo up
ip -n "$sender" addr add 10.77.0.1/24 dev veth0
ip -n "$receiver" addr add 10.77.0.2/24 dev veth0
ip -n "$sender" link set veth0 mtu 1500 up
ip -n "$receiver" link set veth0 mtu 1500 up
ip netns exec "$receiver" tc qdisc replace dev veth0 root fq
printf 'mark: 0x4d49\nrtt:\n  enabled: true\n  iface: veth0\n  base_delay_ms: 160\n  jitter_ms: 8\n  jitter_rho: 0.9\n  min_delay_ms: 0\n  max_delay_ms: 600\n' > "$work/config.yaml"
ip netns exec "$sender" tc qdisc show dev veth0 > "$work/ns-before.qdisc"
ip netns exec "$sender" "$work/mirage-rtt" install -c "$work/config.yaml" --install-qdisc --state-dir "$work/state" --pin-dir "$pins"
ip netns exec "$sender" "$work/mirage-rtt" run -c "$work/config.yaml" --state-dir "$work/state" --pin-dir "$pins" --samples "$work/samples.jsonl" > "$work/daemon.log" 2>&1 & daemon=$!
# Keep every outbound client segment and server SYN-ACK. Capturing the unmarked
# 50 MiB download at local throughput can overflow even an 8 MiB packet ring;
# its payload is irrelevant to ACK order/checksums and is checked by SHA256.
ip netns exec "$receiver" tcpdump -B 8192 -U -n -i veth0 -s 0 -w "$work/capture.pcap" 'tcp and (dst port 18449 or (src port 18449 and tcp[13] & 18 = 18))' > "$work/tcpdump.log" 2>&1 & capture=$!
ip netns exec "$receiver" python3 "$repo/test/lab.py" server "$work/server.json" > "$work/server.log" 2>&1 & server=$!
sleep 1
kill -0 "$daemon" "$server" "$capture"
ip netns exec "$sender" python3 "$repo/test/lab.py" client "$work/client.json"
wait "$server"; server=
sleep 1 # Drain the maximum 600ms EDT horizon, including the final flow's ACKs.
kill -TERM "$daemon"; wait "$daemon"; daemon=
kill -INT "$capture"; wait "$capture"; capture=
grep -q '^0 packets dropped by kernel$' "$work/tcpdump.log"
printf 'tcpdump capture drops=0\n'
ip netns exec "$sender" tc -s -j qdisc show dev veth0 > "$work/qdisc-stats.json"
python3 -c 'import json,sys; qs=json.load(open(sys.argv[1])); assert all(q.get("drops",0)==0 for q in qs),qs; print("fq qdisc drops=0")' "$work/qdisc-stats.json"
python3 "$repo/test/lab.py" analyze "$work"
ip netns exec "$sender" "$work/mirage-rtt" uninstall -c "$work/config.yaml" --state-dir "$work/state" --pin-dir "$pins"
ip netns exec "$sender" tc qdisc show dev veth0 > "$work/ns-after.qdisc"
cmp "$work/ns-before.qdisc" "$work/ns-after.qdisc"
[[ -z $(ip netns exec "$sender" tc filter show dev veth0 egress) ]]
# The kernel frees a detached program after an RCU grace period, so poll
# briefly instead of racing the deferred release.
for _ in {1..50}; do bpftool prog show | grep -q mirage_rtt || break; sleep 0.1; done
if bpftool prog show | grep -q mirage_rtt; then printf 'BPF program remains\n' >&2; exit 1; fi
if [[ -z ${MIRRTT_CASES:-} ]]; then bash "$repo/test/installer_test.sh" "$sender" "$work/mirage-rtt" "$work" "$pins"; fi
cleanup || exit 1
trap - EXIT
