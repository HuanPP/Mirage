# Mirage

English | [简体中文](README.zh-CN.md)

![Mirage](docs/social-preview.png)

Mirage makes traffic that leaves a proxy VPS present one identity at every layer from L4 to L7: a macOS desktop running stock Chrome.

The browser on your Mac is stock Chrome, and its TLS, HTTP/2 and JS environment already belong to a real Mac. Mirage handles the two things a browser cannot: the Linux TCP fingerprint of the VPS's outbound handshake, and the RTT gap the proxy hop adds.

## How it works

```
Mac                                         VPS (Linux)                              Target site
stock Chrome (TZ / lang aligned to egress)
  -> mihomo / sing-box TUN  ==VLESS REALITY==>  mirage-singbox (outbound SO_MARK 0x4d49)
     IPv6 off, UDP 443 rejected,                  |-> mirage-syn  SYN reshaped to Darwin --> L4 reads macOS
     DNS through the tunnel                       |-> mirage-rtt  ACK information delayed -> TCP RTT = real client RTT
```

Both shapers act only on traffic carrying the mark, and only on packet headers. SSH and other services on the VPS run as before.

mirage-syn (nftables + NFQUEUE, Go) rewrites outbound SYNs into the shape of a real macOS 15 machine, based on packets captured from a real Mac (`captures/macos_syn.txt`): window 65535; options in the order `mss, nop, wscale, nop, nop, TS, sackOK, eol`, padded to 24 bytes; IP ID set to 0. The kernel announces wscale 6 itself, set through a sysctl fragment, so connection state always matches the wire. Measured with p0f: native traffic is classified as `Linux 2.2.x-3.x`, rewritten traffic as `Mac OS X`.

mirage-rtt (eBPF tc egress + fq Earliest Departure Time) makes the RTT the target measures at the TCP layer equal the real client-to-VPS RTT. It follows three rules. During the handshake, the third ACK and the ClientHello right behind it are held together. Pure ACKs are delayed by a per-flow base delay plus AR(1)-correlated jitter, strictly monotonic. Data segments leave at their natural time, but their ACK number, TSecr and window are rewritten to the values that have already departed on the delayed path, so `min_rtt` stays near the client RTT even under full-duplex traffic. By default the base delay is measured automatically from TCP_INFO of inbound connections.

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

1. Open the chosen port in your cloud firewall yourself; the script manages only the machine it runs on.
2. When the interface MTU is below 1500 (GCP defaults to 1460), the SYN can only announce an MSS of `MTU-40`, and the installer warns about it. On GCP, run `gcloud compute networks update <vpc> --mtu=1500` and reboot the instance to announce the macOS-typical 1460.
3. mirage-rtt replaces the egress interface's qdisc with fq, and installs only when it can generate an exact rollback. Otherwise it falls back to mirage-syn only and prints a warning. A GCP instance whose MTU has not been raised yet is one such case.
4. mirage-singbox is tied to the shapers with `BindsTo=`: if either shaper exits, the proxy stops too. The NFQUEUE rule itself uses `bypass`, so a crashed daemon does not cut traffic, and the service-level binding stops the proxy before traffic could leave with the native Linux fingerprint.
5. The sysctl fragment lowers the global `tcp_rmem` and `rmem_max` ceilings to 2 MiB to obtain wscale 6. Single-flow throughput is therefore capped at about 2 MiB / RTT, as it would be for a genuine distant client.

### Mac

macOS 13 or newer. The default path runs without sudo.

```sh
git clone https://github.com/HuanPP/Mirage.git mirage && cd mirage
./install-local.sh --import <path or https URL of mirage.yaml>
```

The profile is a valid mihomo config: TUN, IPv4 only, UDP 443 rejected first to disable QUIC, DNS via DoH through the tunnel, a single exit. It adds one top-level `mirage:` section (egress IP, time zone, language, profile name) that mihomo ignores. Import the same file into Clash Verge Rev or mihomo, enable TUN, then run:

```sh
mirage-launch            # start the aligned, separate Chrome instance
mirage-launch --print    # print the resolved command only
mirage-launch --check    # check egress IP, time zone and IPv6 reachability
```

Before launching, `mirage-launch` compares the current egress IP with `expect_egress` from the profile. A mismatch stops the launch, so a missing tunnel or wrong node cannot turn into a direct connection. Chrome is exec'd directly with `TZ=<zone>`; Chrome on macOS honors this variable, which was verified by experiment. It starts with `--lang`, `--accept-lang`, `--disable-quic`, `--enforce-webrtc-ip-permission-check` and its own `--user-data-dir`. The instance runs in its own profile with no debugging port, and the system time zone and your everyday Chrome stay as they are.

`--with-mihomo` downloads a pinned official mihomo into `~/.mirage/bin` and prints the sudo command needed to start TUN. Running it is up to you.

## Repository layout

```
mangler/syn/   mirage-syn: SYN rewrite, nft rules, sysctl fragment, systemd unit, netns integration test
mangler/rtt/   mirage-rtt: eBPF program (pre-generated .o committed, building needs only Go), daemon,
               qdisc install and rollback, netns integration test
server/        sing-box server template and mirage-singbox.service
launcher/      mirage-launch, config example, mihomo / sing-box client templates
captures/      the real macOS SYN capture the rewrite is based on
tools/         scripts that capture macOS and native VPS SYNs
```

## Tests

```sh
cd mangler/syn && go vet ./... && go test ./...
cd mangler/rtt && go vet ./... && go test ./...
sudo bash mangler/syn/test/netns_test.sh   # Linux, root, private netns only
sudo bash mangler/rtt/test/netns_test.sh
```

The mirage-rtt netns test, at a 160 ms base delay, covers: handshake RTT; a 50 MiB download (srtt, retransmits, ACK reordering); agreement of application-level and TCP-level RTT in request/response traffic; isolation of unmarked traffic; jitter statistics (standard deviation and lag-1 autocorrelation); throughput comparison; the `min_rtt` floor and absence of ACK/TSecr regressions under full-duplex and back-to-back overlapping requests, with offloads both on and off; exact rollback of multi-queue qdiscs; and an unchanged host after the test.

## Known limitations

1. v1 is IPv4 only. Marked IPv6 SYNs are dropped by default (fail closed).
2. The VPS IP's ownership (a hosting ASN) cannot be changed at the protocol level. Looking like a home user requires an ISP or residential line.
3. Active probing of the VPS public IP (for example `nmap -O`) still sees the Linux stack. Restrict inbound ports with a firewall.
4. SACK blocks in data segments are kept as is and may be fresher than the delayed cumulative ACK.
5. mirage-rtt's qdisc install requires an exact rollback; interfaces with non-default layouts are refused.

## License

[GPL-3.0](LICENSE). The eBPF program in `mangler/rtt/internal/shaper/bpf.c` declares the GPL license, which the kernel requires for the helpers it uses.
