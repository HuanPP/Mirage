# Mirage

Mirage 让经由代理 VPS 发出的流量，在 L4 到 L7 的每一层都呈现同一个身份：一台使用原版 Chrome 的 macOS 桌面电脑。

本地浏览器保持零篡改，不注入 JS，不改写 Canvas、WebGL 或字体，也不编译定制内核。TLS、HTTP/2 和 JS 环境本身就是真 Mac 的，Mirage 只改造浏览器管不到的两个缺口：VPS 出站 TCP 握手暴露的 Linux 协议栈特征，以及代理链路造成的 RTT 撕裂。

## 原理

```
Mac                                         VPS (Linux)                              目标网站
原版 Chrome (TZ / lang 对齐出口)
  -> mihomo / sing-box TUN  ==VLESS REALITY==>  mirage-singbox (出站 SO_MARK 0x4d49)
     IPv6 关闭, UDP 443 拒绝,                     |-> mirage-syn  SYN 重排为 Darwin 形态 ---> L4 判定 macOS
     DNS 走隧道                                   |-> mirage-rtt  ACK 信息整体延迟 -------> TCP RTT = 真实远端 RTT
```

两个整形组件只处理带 mark 的流量，VPS 上的其他连接（SSH、别的服务）不受影响，也不修改任何载荷。

mirage-syn（nftables + NFQUEUE，Go）把出站 SYN 改写成 macOS 15 的真机形态。改写依据是从真实 Mac 抓到的包（`captures/macos_syn.txt`），具体包括：窗口 65535；选项顺序 `mss, nop, wscale, nop, nop, TS, sackOK, eol` 并补齐到 24 字节；IP ID 置 0。wscale 6 不改写包内字段，而是通过 sysctl 让内核自己通告，保证内核连接状态与报文一致。p0f 实测：原生判定为 `Linux 2.2.x-3.x`，改写后为 `Mac OS X`。

mirage-rtt（eBPF tc egress + fq 的 EDT 发送时间戳）让目标站在 TCP 层测到的 RTT 等于客户端到 VPS 的真实 RTT。它的规则分三条：握手阶段把第三次 ACK 和紧随的 ClientHello 一起推迟；纯 ACK 按"流基准延迟 + AR(1) 相关抖动"延迟，并严格保持单调；数据段按原时机发出，但其中的 ACK 号、TSecr 和窗口字段改写为已经"离开"延迟路径的值，这样全双工场景下 `min_rtt` 也不会塌到机房延迟。基准延迟默认根据入站连接的 TCP_INFO 自动测量。

## 安装

### VPS

要求 Debian 12 / Ubuntu 22.04 及以上，amd64 或 arm64，具备 root 权限。

```sh
git clone <repo> mirage && cd mirage
sudo ./install-vps.sh
```

安装器会完成以下工作：编译两个整形组件（缺 Go 时下载固定版本和校验和的官方工具链到 `/opt/mirage/go`）；部署一个独立的 `mirage-singbox.service`（VLESS + REALITY，无需域名和证书）；写入 sysctl 片段；启动 systemd 服务。它不会改动机器上已有的 sing-box、xray 或其他代理服务。结束时会打印客户端画像，并写入 `/etc/mirage/client/mirage.yaml`。

常用参数：`--port N`、`--sni HOST[:PORT]`、`--no-rtt`、`--dry-run`、`--status`（含一次真实网卡上的 SYN 形态自检）、`--show-client`、`--uninstall`（按安装记录精确回滚）。

注意事项：

1. 云防火墙需要放行所选端口，脚本不会修改云防火墙。
2. 网卡 MTU 低于 1500 时（GCP 默认 1460），SYN 只能通告 `MTU-40` 的 MSS，安装器会给出警告。在 GCP 上执行 `gcloud compute networks update <vpc> --mtu=1500` 并重启实例后，才能通告 macOS 典型的 1460。
3. mirage-rtt 需要把出口网卡的 qdisc 换成 fq，且只有在能生成精确回滚方案时才会安装，否则自动降级为仅启用 mirage-syn 并发出警告。GCP 实例在 MTU 调整前的 qdisc 布局属于不能精确回滚的情况。
4. mirage-singbox 通过 `BindsTo=` 绑定整形服务，任一整形服务退出时代理随之停止。NFQUEUE 规则本身带 `bypass`，守护进程崩溃不会造成断网，服务级联动则保证不会以原生 Linux 指纹继续出站。
5. sysctl 片段会把全局 `tcp_rmem` 与 `rmem_max` 上限降到 2 MiB，以得到 wscale 6。单流吞吐上限因此约为 2 MiB / RTT，这与真实远端客户端的表现一致。

### Mac

要求 macOS 13 及以上，默认路径不需要 sudo。

```sh
git clone <repo> mirage && cd mirage
./install-local.sh --import <mirage.yaml 的路径或 https 地址>
```

画像文件本身是一份合法的 mihomo 配置，规则包括：TUN、仅 IPv4、优先拒绝 UDP 443 以禁用 QUIC、DNS 经隧道走 DoH、单一出口。除此之外多一个顶层 `mirage:` 段，内容为出口 IP、时区、语言和画像名，mihomo 会忽略这一段。把同一份文件导入 Clash Verge Rev 或 mihomo 并开启 TUN 后，运行：

```sh
mirage-launch            # 启动对齐后的独立 Chrome 实例
mirage-launch --print    # 只打印解析后的命令
mirage-launch --check    # 检查出口 IP、时区和 IPv6 可达性
```

`mirage-launch` 启动前会校验当前出口 IP 是否等于画像中的 `expect_egress`，不一致就拒绝启动（隧道未生效或节点不对时，不会裸连）。Chrome 以 `TZ=<时区>` 直接 exec 启动；macOS 上的 Chrome 认这个环境变量，已实测验证。启动参数为 `--lang`、`--accept-lang`、`--disable-quic`、`--enforce-webrtc-ip-permission-check`，使用独立的 `--user-data-dir`，不开放调试端口，也不修改系统时区和你正在使用的 Chrome。

`--with-mihomo` 会下载固定版本的官方 mihomo 到 `~/.mirage/bin`，并打印启动 TUN 所需的 sudo 命令，脚本本身从不执行 sudo。

## 仓库结构

```
mangler/syn/   mirage-syn：SYN 改写、nft 规则、sysctl 片段、systemd 单元、netns 集成测试
mangler/rtt/   mirage-rtt：eBPF 程序（预生成的 .o 已提交，构建只需 Go）、守护进程、qdisc 安装与回滚、netns 集成测试
server/        sing-box 服务端模板与 mirage-singbox.service
launcher/      mirage-launch、配置示例、mihomo / sing-box 客户端模板
captures/      作为改写依据的真实 macOS SYN 抓包
tools/         抓取 macOS 与 VPS 原生 SYN 的脚本
```

## 测试

```sh
cd mangler/syn && go vet ./... && go test ./...
cd mangler/rtt && go vet ./... && go test ./...
sudo bash mangler/syn/test/netns_test.sh   # Linux，root，只使用私有 netns
sudo bash mangler/rtt/test/netns_test.sh
```

mirage-rtt 的 netns 测试在 160 ms 基准延迟下覆盖以下内容：握手 RTT、50 MiB 下载（srtt、重传、ACK 乱序）、请求响应中应用层与 TCP 层 RTT 的一致性、未标记流量的隔离、抖动统计（标准差与 lag-1 自相关）、吞吐对照、全双工与无间隔重叠请求下的 `min_rtt` 下限及 ACK 和 TSecr 无回退（offload 开关两种情况都测）、多队列 qdisc 的精确回滚，以及测试后宿主机状态不变。

## 已知限制

1. v1 只支持 IPv4。带 mark 的 IPv6 SYN 默认直接丢弃（fail closed）。
2. VPS 的 IP 归属（机房 ASN）无法通过协议层改变，要做到"家庭用户"需要选择 ISP 或住宅线路。
3. 主动探测（例如对 VPS 公网 IP 执行 `nmap -O`）看到的仍是 Linux 协议栈，需要用防火墙收紧入站端口。
4. 数据段中的 SACK 块会被原样保留，可能比延迟后的累计 ACK 更新。
5. mirage-rtt 的 qdisc 安装依赖能生成精确回滚，非默认布局的网卡会被拒绝。
