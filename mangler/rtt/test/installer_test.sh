#!/bin/bash
# Called by netns_test.sh with its private namespace, bpffs and cleanup trap.
set -euo pipefail
ns=$1
binary=$2
work=$3
pins=$4
[[ $ns == mirrtt-* ]] || exit 1
tcns() { ip netns exec "$ns" tc "$@"; }
run() { ip netns exec "$ns" "$binary" "$@" -c "$work/installer.yaml" --state-dir "$work/state" --pin-dir "$pins" --default-qdisc-file "$work/default-qdisc"; }
config() { printf 'mark: 0x4d49\nrtt:\n  iface: %s\n  base_delay_ms: 160\n' "$1" > "$work/installer.yaml"; }
config veth0
tcns qdisc replace dev veth0 root handle 42: fq_codel target 7ms interval 91ms quantum 1514 memory_limit 16777216 ecn
tcns -j qdisc show dev veth0 > "$work/codel-before.json"
if run install --dry-run > "$work/refusal.log" 2>&1; then printf 'Missing default refusal\n' >&2; exit 1; fi
grep -q 'refusing qdisc changes' "$work/refusal.log"
run install --install-qdisc --dry-run > "$work/dry-run.log"
tcns -j qdisc show dev veth0 > "$work/codel-after-dry.json"
cmp "$work/codel-before.json" "$work/codel-after-dry.json"
[[ ! -e $work/state/veth0.json ]]
run install --install-qdisc
run check
run uninstall
tcns -j qdisc show dev veth0 > "$work/codel-after.json"
cmp "$work/codel-before.json" "$work/codel-after.json"
printf 'Installer fq_codel root rollback JSON identical; default refusal and dry-run leave layout untouched\n'
ip -n "$ns" link add mirrtt-mq0 numtxqueues 4 numrxqueues 4 type veth peer name mirrtt-mq1 numtxqueues 4 numrxqueues 4
tcns qdisc replace dev mirrtt-mq0 root handle 43: mq
for queue in 1 2 3 4; do tcns qdisc replace dev mirrtt-mq0 parent 43:$queue handle 10$queue: fq_codel target 7ms interval 91ms quantum 1514; done
config mirrtt-mq0
tcns -j qdisc show dev mirrtt-mq0 > "$work/mq-before.json"
run install --install-qdisc
run check
run uninstall
tcns -j qdisc show dev mirrtt-mq0 > "$work/mq-after.json"
cmp "$work/mq-before.json" "$work/mq-after.json"
printf 'Installer mq root and four fq_codel children restored exactly (JSON identical)\n'
ip -n "$ns" link del mirrtt-mq0
ip netns exec "$ns" python3 "$(dirname "$0")/mq_test.py" "$binary" "$work" "$pins"
ip -n "$ns" link add mirrtt-mq0 numtxqueues 4 numrxqueues 4 type veth peer name mirrtt-mq1 numtxqueues 4 numrxqueues 4
ip -n "$ns" link set mirrtt-mq0 txqueuelen 1000 up
ip -n "$ns" link set mirrtt-mq1 txqueuelen 1000 up
# Linux 6.1 veth has IFF_NO_QUEUE: root deletion restores noqueue, not mq.
# An explicit mq root exercises anonymous default leaves without misrepresenting
# veth as a physical queued device. Recreating that same root preserves its ID.
tcns qdisc replace dev mirrtt-mq0 root handle 44: mq
tcns -j qdisc show dev mirrtt-mq0 > "$work/default-mq-before.json"
python3 -c 'import json,sys; q=json.load(open(sys.argv[1])); assert q[0]["kind"]=="mq" and q[0]["handle"]=="44:" and len(q)==5 and all(x["handle"]=="0:" for x in q[1:]),q' "$work/default-mq-before.json"
config mirrtt-mq0
run install --install-qdisc
run check
run uninstall
tcns -j qdisc show dev mirrtt-mq0 > "$work/default-mq-after.json"
cmp "$work/default-mq-before.json" "$work/default-mq-after.json"
printf 'Installer kernel-default mq plus four anonymous fq_codel children: before/rollback JSON identical\n'
# An anonymous custom leaf must still be refused, even with authorization.
tcns qdisc replace dev mirrtt-mq0 parent 44:1 fq_codel target 7ms
if run install --install-qdisc > "$work/default-mq-refusal.log" 2>&1; then printf 'Custom anonymous layout accepted\n' >&2; exit 1; fi
ip -n "$ns" link del mirrtt-mq0
