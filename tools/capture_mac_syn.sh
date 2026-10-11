#!/bin/zsh
# Capture this Mac's real SYN on the VPS side; needs no local sudo.
# Usage: tools/capture_mac_syn.sh <ssh-host> [vps-iface]
# The VPS user needs passwordless sudo for tcpdump. Each `ssh` opens a new TCP
# connection to port 22, so the capture sees three genuine macOS SYNs.
set -eu
host=${1:?usage: capture_mac_syn.sh <ssh-host> [vps-iface]}
iface=${2:-eth0}
out=$(mktemp -t mirage-mac-syn)
ssh -o BatchMode=yes "$host" "sudo timeout 40 tcpdump -nn -vvv -c 3 -i '$iface' 'tcp dst port 22 and tcp[tcpflags] == tcp-syn' 2>&1" > "$out" 2>&1 &
sleep 5
for _ in 1 2 3; do ssh -o BatchMode=yes -o ControlMaster=no -o ControlPath=none "$host" true; sleep 1; done
wait
cat "$out"
rm -f "$out"
