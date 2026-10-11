#!/bin/zsh
# Capture the VPS's native (unshaped) outbound Linux SYN.
# Usage: tools/capture_vps_syn.sh <ssh-host> [vps-iface]
set -eu
host=${1:?usage: capture_vps_syn.sh <ssh-host> [vps-iface]}
iface=${2:-eth0}
ssh -o BatchMode=yes "$host" "sudo timeout 20 tcpdump -nn -vvv -c 2 -i '$iface' 'tcp dst port 80 and tcp[tcpflags] == tcp-syn' 2>&1 & sleep 3; curl -s -o /dev/null http://example.com; curl -s -o /dev/null http://example.com; wait"
