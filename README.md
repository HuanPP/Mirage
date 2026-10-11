# Mirage

English | [简体中文](README.zh-CN.md)

![Mirage](docs/social-preview.png)

Mirage makes traffic from a proxy VPS look like it comes from a Mac running stock Chrome, from the TCP handshake up to the JS environment.

The browser on your Mac is stock Chrome, so its TLS, HTTP/2 and JS environment already belong to a real Mac. Mirage covers the two things a browser cannot: the Linux TCP fingerprint of the VPS's outbound handshake, and the RTT gap the proxy hop adds.

## How it works

```
Mac                                         VPS (Linux)                              Target site
stock Chrome (TZ / lang aligned to egress)
  -> mihomo / sing-box TUN  ==VLESS REALITY==>  mirage-singbox (outbound SO_MARK 0x4d49)
     IPv6 off, UDP 443 rejected,                  |-> mirage-syn  SYN reshaped to Darwin --> L4 reads macOS
     DNS through the tunnel                       |-> mirage-rtt  ACK information delayed -> TCP RTT = real client RTT
```

Both shapers touch only the packet headers of traffic carrying the mark. SSH and other services on the VPS run as before.

mirage-syn (nftables + NFQUEUE, Go) rewrites outbound SYNs into the shape of a real macOS 15 machine, based on packets captured from a real Mac (`captures/macos_syn.txt`): window 65535; options in the order `mss, nop, wscale, nop, nop, TS, sackOK, eol`, padded to 24 bytes; IP ID set to 0. The kernel announces wscale 6 itself, set through a sysctl fragment, so connection state always matches the wire. Measured with p0f, native traffic reads as `Linux 2.2.x-3.x` and rewritten traffic as `Mac OS X`.

mirage-rtt (eBPF tc egress + fq Earliest Departure Time) makes the RTT the target measures at the TCP layer match the real client-to-VPS RTT. The third handshake ACK and the ClientHello right behind it are held together. Pure ACKs are delayed by a per-flow base delay plus AR(1)-correlated jitter, in strictly increasing order. Data segments leave on time, but the ACK number, TSecr and window they carry are rewritten to values that have already departed on the delayed path, so `min_rtt` stays near the client RTT even under full-duplex traffic. The base delay is measured automatically from TCP_INFO of inbound connections.

## Install

### VPS

Debian 12 / Ubuntu 22.04 or newer, amd64 or arm64, root access.

```sh
git clone https://github.com/HuanPP/Mirage.git mirage && cd mirage
sudo ./install-vps.sh
```

The installer builds both shapers (if Go is missing it downloads a pinned, checksum-verified official toolchain into `/opt/mirage/go`), deploys a separate `mirage-singbox.service` (VLESS + REALITY, no domain or certificate needed), installs the sysctl fragment and starts the systemd services. Existing sing-box, xray or other proxy services stay as they are. At the end it prints the client profile and writes it to `/etc/mirage/client/mirage.yaml`.

Common options: `--port N`, `--sni HOST[:PORT]`, `--no-rtt`, `--dry-run`, `--status` (includes a SYN shape self-test on the real interface), `--show-client`, `--uninstall` (exact rollback from the install record).

Notes:

1. Open the chosen port in your cloud firewall yourself.
2. GCP's default MTU of 1460 limits the announced MSS to 1420, and the installer warns about it. Run `gcloud compute networks update <vpc> --mtu=1500` and reboot the instance to announce the usual 1460.
3. mirage-rtt swaps the egress qdisc to fq and installs only when an exact rollback exists. Otherwise only mirage-syn runs, with a warning.
4. mirage-singbox is bound to the shapers with `BindsTo=`, so the proxy stops if either shaper exits. The NFQUEUE rule uses `bypass`, so a crashed daemon does not cut traffic.
5. The sysctl fragment lowers the global `tcp_rmem` and `rmem_max` ceilings to 2 MiB to get wscale 6, which caps single-flow throughput at about 2 MiB / RTT.

### Mac

macOS 13 or newer. The default path runs without sudo.

```sh
git clone https://github.com/HuanPP/Mirage.git mirage && cd mirage
./install-local.sh --import <path or https URL of mirage.yaml>
```

The profile is a valid mihomo config (TUN, IPv4 only, UDP 443 rejected to disable QUIC, DoH through the tunnel, a single exit) with one extra top-level `mirage:` section for egress IP, time zone, language and profile name, which mihomo ignores. Import the file into Clash Verge Rev or mihomo, enable TUN, then run:

```sh
mirage-launch            # start the aligned, separate Chrome instance
mirage-launch --print    # print the resolved command only
mirage-launch --check    # check egress IP, time zone and IPv6 reachability
```

`mirage-launch` first compares the current egress IP with `expect_egress` from the profile and stops on a mismatch, so a missing tunnel or wrong node cannot turn into a direct connection. It then starts Chrome in its own profile with `TZ=<zone>` (Chrome on macOS honors it, checked by experiment), `--lang`, `--accept-lang`, `--disable-quic` and `--enforce-webrtc-ip-permission-check`. The instance has no debugging port, and your system time zone and everyday Chrome stay as they are.

`--with-mihomo` downloads a pinned official mihomo into `~/.mirage/bin` and prints the sudo command that starts TUN. Running it is up to you.

## Known limitations

1. v1 is IPv4 only. Marked IPv6 SYNs are dropped by default.
2. A hosting ASN stays a hosting ASN. Looking like a home user takes an ISP or residential line.
3. `nmap -O` against the VPS still sees Linux, so restrict inbound ports with a firewall.
4. SACK blocks in data segments pass through unchanged and can be fresher than the delayed ACK.
5. mirage-rtt refuses interfaces whose qdisc layout it cannot restore exactly.

## License

[GPL-3.0](LICENSE). The eBPF program in `mangler/rtt/internal/shaper/bpf.c` declares the GPL license, which the kernel requires for the helpers it uses.
