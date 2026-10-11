#!/usr/bin/env python3
"""Check anonymous mq root-delete rollback on a queued private TAP device.

Linux 6.1 veth always has IFF_NO_QUEUE, so its root-delete default is noqueue.
The accompanying veth test covers four anonymous children under an explicit mq
root. TAP supplies a genuine anonymous kernel-default mq root without changing
the host's physical interface, driver flags or default_qdisc sysctl.
"""
import fcntl
import json
import os
import struct
import subprocess
import sys

binary, work, pins = sys.argv[1:]
iface = "mirrtt-tap0"
fds = []


def command(*args):
    return subprocess.check_output(args, text=True)


def layout():
    return command("tc", "-j", "qdisc", "show", "dev", iface)


def run(action, *options):
    print(command(binary, action, *options, "-c", work + "/installer.yaml",
                  "--state-dir", work + "/state", "--pin-dir", pins,
                  "--default-qdisc-file", work + "/default-qdisc"), end="")


try:
    for _ in range(4):
        fd = os.open("/dev/net/tun", os.O_RDWR)
        fds.append(fd)
        # IFF_TAP | IFF_NO_PI | IFF_MULTI_QUEUE; no persistence or traffic.
        fcntl.ioctl(fd, 0x400454ca, struct.pack("16sH", iface.encode(), 0x1102))
    command("ip", "link", "set", "dev", iface, "mtu", "1500", "up")
    before = layout()
    qs = json.loads(before)
    assert qs[0]["kind"] == "mq" and qs[0]["handle"] == "0:", qs
    assert len(qs) == 5 and all(q["handle"] == "0:" for q in qs), qs
    with open(work + "/installer.yaml", "w") as f:
        f.write("mark: 0x4d49\nrtt:\n  iface: %s\n  base_delay_ms: 160\n" % iface)
    with open(work + "/tap-mq-before.json", "w") as f:
        f.write(before)
    run("install", "--install-qdisc")
    with open(work + "/state/" + iface + ".json") as f:
        rollback = json.load(f)["Plan"]["rollback"]
    assert rollback == [["tc", "qdisc", "del", "dev", iface, "root"]], rollback
    run("check")
    run("uninstall")
    after = layout()
    with open(work + "/tap-mq-after.json", "w") as f:
        f.write(after)
    assert before == after, (before, after)
    print("Installer anonymous kernel-default mq root-delete rollback: four TAP queues, before/after JSON identical")
finally:
    # Closing the last nonpersistent queue destroys this namespace-only device.
    for fd in fds:
        os.close(fd)
