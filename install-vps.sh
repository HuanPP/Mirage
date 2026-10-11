#!/usr/bin/env bash
# Mirage VPS installer. Debian 12 / Ubuntu 22.04+, amd64 or arm64.
# Never modifies existing sing-box, xray, or anytls services.
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

REPO=$(cd "$(dirname "$0")" && pwd)

GO_VERSION='1.27.2'
GO_SHA256_LINUX_AMD64='ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5'
GO_SHA256_LINUX_ARM64='94f3e30b8e374bc285e7dadc11e0865726b9bc6e85b841ccceaabc0214c6b7c8'

SINGBOX_VERSION='1.14.3'
SINGBOX_SHA256_LINUX_AMD64='e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee'
SINGBOX_SHA256_LINUX_ARM64='29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e'

ETC_DIR=/etc/mirage
BIN_DIR=/usr/local/lib/mirage/bin
LIB_DIR=/usr/local/lib/mirage
STATE_DIR=/var/lib/mirage/install-state
VAR_DIR=/var/lib/mirage
SYSCTL_SRC="$REPO/mangler/syn/deploy/99-mirage-syn.sysctl.conf"
SYSCTL_DST=/etc/sysctl.d/99-mirage-syn.conf
MARK='0x4d49'
QUEUE_NUM=4949
SINGBOX_USER=mirage-singbox
DEFAULT_SNI='www.microsoft.com:443'
PROFILE_NAME=mirage

GO=''
DRY_RUN=0
NO_RTT=0
PORT_FLAG=''
SNI_FLAG=$DEFAULT_SNI
MODE=install
IFACE=''
MTU=0
MSS=0
PUBLIC_IP=''
TIMEZONE=''
PORT=0
RTT_ENABLED=0
WARNINGS=()
TMPDIRS=()

usage() {
  cat <<'EOF'
Usage: sudo ./install-vps.sh [options]
       sudo ./install-vps.sh --show-client
       sudo ./install-vps.sh --status
       sudo ./install-vps.sh --uninstall
       sudo ./install-vps.sh --dry-run [install options]
       sudo ./install-vps.sh --help

One-command VPS install for Mirage (mirage-syn, optional mirage-rtt, a
separate mirage-singbox.service). Never touches existing proxy services.

  --port N       Listen port. Default: 443 if free, else first free of
                 8443, 2053, 2083, 2087, 2096. Refuses if the chosen port
                 is in use.
  --sni HOST[:PORT]
                 REALITY handshake server (default www.microsoft.com:443).
  --profile NAME Short name written into the client profile (default mirage).
  --no-rtt       Do not attach mirage-rtt / qdisc. Still prints a
                 mirage-rtt install --dry-run plan.
  --dry-run      Print the plan; do not change the system.
  --show-client  Reprint /etc/mirage/client/mirage.yaml
  --status       Units, nft, BPF, qdisc, wscale, optional RTT, SYN self-test.
  --uninstall    Revert exactly what this installer did.
  --help         Show this help.

The cloud firewall must allow TCP <port> inbound. This script never changes
cloud firewalls.
EOF
}

log() { printf '%s %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
warn() {
  printf 'WARNING: %s\n' "$*" >&2
  WARNINGS+=("$*")
}

cleanup_tmp() {
  local d
  for d in "${TMPDIRS[@]+"${TMPDIRS[@]}"}"; do
    rm -rf "$d"
  done
}
trap cleanup_tmp EXIT

mktempd() {
  local d
  d=$(mktemp -d /tmp/mirinst-XXXXXX)
  TMPDIRS+=("$d")
  printf '%s\n' "$d"
}

require_root() {
  [[ $(id -u) == 0 ]] || die "run as root (sudo ./install-vps.sh)"
}

linux_arch() {
  case "$(uname -m)" in
    x86_64) printf '%s\n' amd64 ;;
    aarch64|arm64) printf '%s\n' arm64 ;;
    *) die "unsupported architecture $(uname -m)" ;;
  esac
}

go_version_ok() {
  local v=$1
  v=${v#go}
  local major rest minor
  major=${v%%.*}
  rest=${v#*.}
  minor=${rest%%.*}
  major=${major:-0}
  minor=${minor:-0}
  if (( major > 1 )); then return 0; fi
  if (( major == 1 && minor >= 24 )); then return 0; fi
  return 1
}

is_port_busy() {
  local port=$1
  ss -H -l -n -t 2>/dev/null | awk -v p="$port" '
    {
      n = split($4, a, ":")
      if (n > 0 && a[n] == p) found = 1
    }
    END { exit found ? 0 : 1 }
  '
}

manifest_set() {
  [[ $DRY_RUN -eq 1 ]] && return 0
  mkdir -p "$STATE_DIR"
  local key=$1 value=$2 tmp
  tmp=$(mktemp "$STATE_DIR/manifest.XXXXXX")
  if [[ -f "$STATE_DIR/manifest" ]]; then
    awk -F= -v k="$key" '$1 != k { print }' "$STATE_DIR/manifest" >"$tmp"
  else
    : >"$tmp"
  fi
  printf '%s=%s\n' "$key" "$value" >>"$tmp"
  mv "$tmp" "$STATE_DIR/manifest"
}

manifest_get() {
  local key=$1
  [[ -f "$STATE_DIR/manifest" ]] || return 0
  awk -F= -v k="$key" '$1 == k { print substr($0, index($0, "=") + 1); exit }' "$STATE_DIR/manifest"
}

record_path() {
  [[ $DRY_RUN -eq 1 ]] && return 0
  mkdir -p "$STATE_DIR"
  if [[ -f "$STATE_DIR/paths" ]] && grep -Fxq "$1" "$STATE_DIR/paths"; then
    return 0
  fi
  printf '%s\n' "$1" >>"$STATE_DIR/paths"
}

act() {
  log "+ $*"
  if [[ $DRY_RUN -eq 1 ]]; then
    return 0
  fi
  "$@"
}

verify_sha256() {
  local file=$1 want=$2 got
  got=$(sha256sum "$file" | awk '{ print $1 }')
  [[ "$got" == "$want" ]] || die "sha256 mismatch for $(basename "$file") (got $got want $want)"
}

detect_iface() {
  IFACE=$(ip -4 route show default 2>/dev/null | awk '/default/ { print $5; exit }')
  [[ -n "$IFACE" ]] || die "could not detect default-route interface"
  MTU=$(cat "/sys/class/net/${IFACE}/mtu")
  [[ -n "$MTU" && "$MTU" -gt 40 ]] || die "could not read MTU for $IFACE"
  local cap=$((MTU - 40))
  if (( cap < 1460 )); then
    MSS=$cap
  else
    MSS=1460
  fi
  if (( MTU < 1500 )); then
    warn "egress MTU is ${MTU}; SYN will announce mss ${MSS} instead of the macOS-typical 1460. Raise the MTU on GCP with: gcloud compute networks update <vpc> --mtu=1500 then reboot the instance. Never announce an MSS larger than mtu-40 (blackhole risk)."
  fi
}

detect_public_ip() {
  local ip
  ip=$(curl -4 -fsS --max-time 8 --interface "$IFACE" https://api.ipify.org 2>/dev/null || true)
  if [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ip=$(curl -4 -fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)
  fi
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "could not detect public IPv4 via api.ipify.org"
  PUBLIC_IP=$ip
}

detect_timezone() {
  local body zone
  local urls=(
    https://ipinfo.io/timezone
    https://ipapi.co/timezone
  )
  local url
  for url in "${urls[@]}"; do
    body=$(curl -4 -fsS --max-time 5 "$url" 2>/dev/null || true)
    zone=$(printf '%s' "$body" | tr -d '\r' | head -n 1)
    zone=${zone#"${zone%%[![:space:]]*}"}
    zone=${zone%"${zone##*[![:space:]]}"}
    if [[ -n "$zone" && -f "/usr/share/zoneinfo/$zone" ]]; then
      TIMEZONE=$zone
      return 0
    fi
  done
  body=$(curl -4 -fsS --max-time 5 https://worldtimeapi.org/api/ip 2>/dev/null || true)
  zone=$(printf '%s' "$body" | awk -F'"' '/timezone/ { for (i=1;i<NF;i++) if ($i=="timezone") { print $(i+2); exit } }')
  if [[ -n "$zone" && -f "/usr/share/zoneinfo/$zone" ]]; then
    TIMEZONE=$zone
    return 0
  fi
  die "could not detect IANA timezone of egress IP"
}

choose_port() {
  local candidates=()
  local p
  if [[ -n "$PORT_FLAG" ]]; then
    candidates=("$PORT_FLAG")
  else
    candidates=(443 8443 2053 2083 2087 2096)
  fi
  for p in "${candidates[@]}"; do
    if is_port_busy "$p"; then
      log "port $p is in use"
      continue
    fi
    PORT=$p
    log "selected port $PORT"
    return 0
  done
  if [[ -n "$PORT_FLAG" ]]; then
    die "port ${PORT_FLAG} is in use"
  fi
  die "no free port among 443 8443 2053 2083 2087 2096"
}

parse_sni() {
  local s=$1
  if [[ "$s" == *:* ]]; then
    SNI_HOST=${s%:*}
    SNI_PORT=${s##*:}
  else
    SNI_HOST=$s
    SNI_PORT=443
  fi
  [[ -n "$SNI_HOST" && "$SNI_PORT" =~ ^[0-9]+$ ]] || die "invalid --sni $s"
}

resolve_go() {
  local candidate ver
  local extra
  extra=$(command -v go 2>/dev/null || true)
  for candidate in $extra /usr/local/go/bin/go /opt/mirage/go/bin/go; do
    [[ -n "$candidate" && -x "$candidate" ]] || continue
    ver=$("$candidate" version 2>/dev/null | awk '{ print $3 }' || true)
    if go_version_ok "$ver"; then
      GO=$candidate
      log "using Go toolchain $GO ($ver)"
      return 0
    fi
    log "skip $candidate ($ver), need go >= 1.24"
  done
  return 1
}

install_go() {
  if resolve_go; then
    manifest_set go_installed 0
    return 0
  fi
  local arch sha url tarball dest
  arch=$(linux_arch)
  if [[ "$arch" == amd64 ]]; then
    sha=$GO_SHA256_LINUX_AMD64
  else
    sha=$GO_SHA256_LINUX_ARM64
  fi
  url="https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz"
  log "Go >= 1.24 not found; downloading official go${GO_VERSION} into /opt/mirage/go (will not touch /usr/local/go)"
  if [[ $DRY_RUN -eq 1 ]]; then
    log "would download $url"
    GO=/opt/mirage/go/bin/go
    return 0
  fi
  dest=$(mktempd)
  tarball="$dest/go.tgz"
  curl -fL --retry 3 --max-time 180 -o "$tarball" "$url"
  verify_sha256 "$tarball" "$sha"
  mkdir -p /opt/mirage
  if [[ ! -e /opt/mirage/go ]]; then
    record_path /opt/mirage/go
  fi
  rm -rf /opt/mirage/go
  tar -C /opt/mirage -xzf "$tarball"
  [[ -x /opt/mirage/go/bin/go ]] || die "Go tarball did not contain bin/go"
  GO=/opt/mirage/go/bin/go
  manifest_set go_installed 1
  log "installed $GO ($("$GO" version))"
}

build_binaries() {
  if [[ $DRY_RUN -eq 1 ]]; then
    log "would build mirage-syn and mirage-rtt into $BIN_DIR"
    return 0
  fi
  mkdir -p "$BIN_DIR"
  record_path "$LIB_DIR"
  record_path "$BIN_DIR"
  [[ -n "$GO" && -x "$GO" ]] || die "go toolchain missing"
  export CGO_ENABLED=0
  local gocache gomod
  gocache=$(mktempd)
  gomod=$(mktempd)
  export GOCACHE=$gocache
  export GOMODCACHE=$gomod
  log "build mirage-syn"
  (cd "$REPO/mangler/syn" && "$GO" build -trimpath -o "$BIN_DIR/mirage-syn" ./cmd/mirage-syn)
  chmod 0755 "$BIN_DIR/mirage-syn"
  log "build mirage-rtt (copy of mangler/rtt)"
  local rttbuild rtt_log rc=0
  rttbuild=$(mktempd)
  rtt_log="$rttbuild/build.log"
  tar -C "$REPO/mangler/rtt" -cf - . | tar -C "$rttbuild" -xf -
  set +e
  (cd "$rttbuild" && "$GO" build -trimpath -o "$BIN_DIR/mirage-rtt" ./cmd/mirage-rtt) >"$rtt_log" 2>&1
  rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    warn "mirage-rtt failed to build (exit $rc); continuing with --no-rtt semantics"
    sed 's/^/  /' "$rtt_log" >&2 || true
    NO_RTT=1
    rm -f "$BIN_DIR/mirage-rtt"
    log "built $($BIN_DIR/mirage-syn version); mirage-rtt unavailable"
    return 0
  fi
  chmod 0755 "$BIN_DIR/mirage-rtt"
  log "built $($BIN_DIR/mirage-syn version) and $($BIN_DIR/mirage-rtt version)"
}

install_singbox_binary() {
  local arch sha url dest tarball
  arch=$(linux_arch)
  if [[ "$arch" == amd64 ]]; then
    sha=$SINGBOX_SHA256_LINUX_AMD64
  else
    sha=$SINGBOX_SHA256_LINUX_ARM64
  fi
  url="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${arch}.tar.gz"
  if [[ $DRY_RUN -eq 1 ]]; then
    log "would download $url -> $BIN_DIR/sing-box"
    return 0
  fi
  dest=$(mktempd)
  tarball="$dest/sb.tgz"
  log "download $url"
  curl -fL --retry 3 --max-time 180 -o "$tarball" "$url"
  verify_sha256 "$tarball" "$sha"
  tar -C "$dest" -xzf "$tarball"
  local bin
  bin=$(find "$dest" -type f -name sing-box | head -n 1)
  [[ -n "$bin" ]] || die "sing-box binary missing from archive"
  install -m 0755 "$bin" "$BIN_DIR/sing-box"
  log "installed $BIN_DIR/sing-box ($("$BIN_DIR/sing-box" version | head -n 1))"
}

load_or_make_secrets() {
  parse_sni "$SNI_FLAG"
  if [[ -f "$STATE_DIR/secrets.env" ]]; then
    UUID=$(awk -F= '$1=="UUID" { print substr($0, index($0,"=")+1); exit }' "$STATE_DIR/secrets.env")
    PRIVATE_KEY=$(awk -F= '$1=="PRIVATE_KEY" { print substr($0, index($0,"=")+1); exit }' "$STATE_DIR/secrets.env")
    PUBLIC_KEY=$(awk -F= '$1=="PUBLIC_KEY" { print substr($0, index($0,"=")+1); exit }' "$STATE_DIR/secrets.env")
    SHORT_ID=$(awk -F= '$1=="SHORT_ID" { print substr($0, index($0,"=")+1); exit }' "$STATE_DIR/secrets.env")
    if [[ -n "$UUID" && -n "$PRIVATE_KEY" && -n "$PUBLIC_KEY" && -n "$SHORT_ID" ]]; then
      log "reusing existing REALITY secrets"
      return 0
    fi
  fi
  if [[ $DRY_RUN -eq 1 ]]; then
    UUID='00000000-0000-0000-0000-000000000000'
    PRIVATE_KEY='dry-run'
    PUBLIC_KEY='dry-run'
    SHORT_ID='deadbeef'
    log "would generate uuid, reality-keypair, short_id"
    return 0
  fi
  [[ -x "$BIN_DIR/sing-box" ]] || die "sing-box binary missing"
  UUID=$("$BIN_DIR/sing-box" generate uuid)
  SHORT_ID=$("$BIN_DIR/sing-box" generate rand 8 --hex)
  local kp
  kp=$("$BIN_DIR/sing-box" generate reality-keypair)
  PRIVATE_KEY=$(printf '%s\n' "$kp" | awk '/PrivateKey/ { print $2; exit }')
  PUBLIC_KEY=$(printf '%s\n' "$kp" | awk '/PublicKey/ { print $2; exit }')
  [[ -n "$UUID" && -n "$PRIVATE_KEY" && -n "$PUBLIC_KEY" && -n "$SHORT_ID" ]] || die "failed to generate REALITY parameters"
  mkdir -p "$STATE_DIR"
  umask 077
  cat >"$STATE_DIR/secrets.env" <<EOF
UUID=${UUID}
PRIVATE_KEY=${PRIVATE_KEY}
PUBLIC_KEY=${PUBLIC_KEY}
SHORT_ID=${SHORT_ID}
SNI_HOST=${SNI_HOST}
SNI_PORT=${SNI_PORT}
EOF
  chmod 0600 "$STATE_DIR/secrets.env"
  umask 022
}

subst_file() {
  local src=$1 dest=$2
  local content
  content=$(cat "$src")
  content=${content//__LISTEN_PORT__/$PORT}
  content=${content//__UUID__/$UUID}
  content=${content//__PRIVATE_KEY__/$PRIVATE_KEY}
  content=${content//__PUBLIC_KEY__/$PUBLIC_KEY}
  content=${content//__SHORT_ID__/$SHORT_ID}
  content=${content//__SNI_HOST__/$SNI_HOST}
  content=${content//__SNI_PORT__/$SNI_PORT}
  content=${content//<SERVER>/$PUBLIC_IP}
  content=${content//<PORT>/$PORT}
  content=${content//<UUID>/$UUID}
  content=${content//<PUBLIC_KEY>/$PUBLIC_KEY}
  content=${content//<SHORT_ID>/$SHORT_ID}
  content=${content//<SNI>/$SNI_HOST}
  content=${content//<TIMEZONE>/$TIMEZONE}
  content=${content//<PROFILE>/$PROFILE_NAME}
  printf '%s\n' "$content" >"$dest"
}

write_mangler_yaml() {
  local rtt_en=$1
  local dest=$ETC_DIR/mangler.yaml
  if [[ $DRY_RUN -eq 1 ]]; then
    log "would write $dest (mss=$MSS iface=$IFACE inbound_port=$PORT rtt.enabled=$rtt_en)"
    return 0
  fi
  mkdir -p "$ETC_DIR"
  record_path "$ETC_DIR"
  cat >"$dest" <<EOF
mark: ${MARK}
ipv6: block
syn:
  enabled: true
  queue_num: ${QUEUE_NUM}
  profile: macos
  mss: ${MSS}
rtt:
  enabled: ${rtt_en}
  iface: ${IFACE}
  base_delay_ms: auto
  default_delay_ms: 160
  jitter_ms: 8
  jitter_rho: 0.9
  min_delay_ms: 0
  max_delay_ms: 600
  client:
    inbound_port: ${PORT}
EOF
  chmod 0644 "$dest"
  log "wrote $dest"
}

write_singbox_config() {
  local dest=$ETC_DIR/sing-box.json
  if [[ $DRY_RUN -eq 1 ]]; then
    log "would write $dest and run sing-box check"
    return 0
  fi
  subst_file "$REPO/server/templates/sing-box-server.json" "$dest"
  chmod 0640 "$dest"
  chgrp "$SINGBOX_USER" "$dest"
  "$BIN_DIR/sing-box" check -c "$dest"
  log "sing-box check passed for $dest"
}

write_client_files() {
  if [[ $DRY_RUN -eq 1 ]]; then
    log "would write $ETC_DIR/client/mirage.yaml and sing-box-client.json"
    return 0
  fi
  mkdir -p "$ETC_DIR/client"
  subst_file "$REPO/launcher/templates/mihomo-client.yaml" "$ETC_DIR/client/mirage.yaml"
  subst_file "$REPO/launcher/templates/sing-box-client.json" "$ETC_DIR/client/sing-box-client.json"
  chmod 0644 "$ETC_DIR/client/mirage.yaml" "$ETC_DIR/client/sing-box-client.json"
  log "wrote $ETC_DIR/client/mirage.yaml"
}

ensure_user() {
  if getent passwd "$SINGBOX_USER" >/dev/null; then
    log "system user $SINGBOX_USER already exists"
    return 0
  fi
  if [[ $DRY_RUN -eq 1 ]]; then
    log "would useradd --system $SINGBOX_USER"
    return 0
  fi
  useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$SINGBOX_USER"
  manifest_set user_created 1
  log "created system user $SINGBOX_USER"
}

install_sysctl() {
  log "sysctl fragment lowers the global receive-buffer maximum to 2 MiB (net.core.rmem_max and tcp_rmem max = 2097152)"
  if [[ $DRY_RUN -eq 1 ]]; then
    log "would install $SYSCTL_DST and apply it, saving previous values"
    return 0
  fi
  mkdir -p "$STATE_DIR" "$(dirname "$SYSCTL_DST")"
  if [[ ! -f "$STATE_DIR/sysctl.previous" ]]; then
    local key
    : >"$STATE_DIR/sysctl.previous"
    while read -r key; do
      printf '%s = %s\n' "$key" "$(sysctl -n "$key")" >>"$STATE_DIR/sysctl.previous"
    done < <(awk '/^net\./ { print $1 }' "$SYSCTL_SRC")
  fi
  install -m 0644 "$SYSCTL_SRC" "$SYSCTL_DST"
  record_path "$SYSCTL_DST"
  sysctl -p "$SYSCTL_DST"
  manifest_set sysctl_installed 1
}

write_unit_dropins() {
  local rtt_en=$1
  if [[ $DRY_RUN -eq 1 ]]; then
    log "would install systemd units and drop-ins (rtt=$rtt_en)"
    return 0
  fi
  install -m 0644 "$REPO/mangler/syn/deploy/mirage-syn.service" /etc/systemd/system/mirage-syn.service
  mkdir -p /etc/systemd/system/mirage-syn.service.d
  cat >/etc/systemd/system/mirage-syn.service.d/00-exec.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/local/lib/mirage/bin/mirage-syn run -c /etc/mirage/mangler.yaml
EOF
  record_path /etc/systemd/system/mirage-syn.service
  record_path /etc/systemd/system/mirage-syn.service.d/00-exec.conf

  install -m 0644 "$REPO/server/deploy/mirage-singbox.service" /etc/systemd/system/mirage-singbox.service
  mkdir -p /etc/systemd/system/mirage-singbox.service.d
  if [[ "$rtt_en" == true ]]; then
    cat >/etc/systemd/system/mirage-singbox.service.d/00-binds.conf <<'EOF'
[Unit]
After=mirage-syn.service mirage-rtt.service
BindsTo=mirage-syn.service mirage-rtt.service
EOF
  else
    cat >/etc/systemd/system/mirage-singbox.service.d/00-binds.conf <<'EOF'
[Unit]
After=mirage-syn.service
BindsTo=mirage-syn.service
EOF
  fi
  record_path /etc/systemd/system/mirage-singbox.service
  record_path /etc/systemd/system/mirage-singbox.service.d/00-binds.conf

  if [[ "$rtt_en" == true ]]; then
    install -m 0644 "$REPO/mangler/rtt/deploy/mirage-rtt.service" /etc/systemd/system/mirage-rtt.service
    mkdir -p /etc/systemd/system/mirage-rtt.service.d
    cat >/etc/systemd/system/mirage-rtt.service.d/00-exec.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/local/lib/mirage/bin/mirage-rtt run -c /etc/mirage/mangler.yaml
ExecStopPost=
ExecStopPost=/usr/local/lib/mirage/bin/mirage-rtt uninstall -c /etc/mirage/mangler.yaml
EOF
    record_path /etc/systemd/system/mirage-rtt.service
    record_path /etc/systemd/system/mirage-rtt.service.d/00-exec.conf
  fi
}

rtt_plan_exact() {
  local out=$1
  if grep -q 'Dry-run limitation: anonymous' <<<"$out"; then
    return 1
  fi
  if grep -qi 'refus' <<<"$out"; then
    return 1
  fi
  if grep -q 'Rollback script' <<<"$out"; then
    return 0
  fi
  return 1
}

maybe_install_rtt() {
  RTT_ENABLED=0
  if [[ $DRY_RUN -eq 0 && ! -x "$BIN_DIR/mirage-rtt" ]]; then
    warn "mirage-rtt binary missing; continuing with rtt disabled"
    return 0
  fi
  local cfg=$ETC_DIR/mangler.yaml
  if [[ $DRY_RUN -eq 1 ]]; then
    log "would run: $BIN_DIR/mirage-rtt install -c $cfg --dry-run"
    if [[ $NO_RTT -eq 1 ]]; then
      log "--no-rtt: would skip qdisc attach and mirage-rtt.service"
    fi
    return 0
  fi
  log "mirage-rtt install --dry-run (integration; no mutation)"
  local out rc=0
  set +e
  # Probe with --install-qdisc: without it mirage-rtt always refuses to plan a
  # root qdisc change, so the probe could never report an exact rollback.
  out=$("$BIN_DIR/mirage-rtt" install -c "$cfg" --install-qdisc --dry-run 2>&1)
  rc=$?
  set -e
  printf '%s\n' "$out"
  if [[ $NO_RTT -eq 1 ]]; then
    log "--no-rtt: skipping qdisc attach and mirage-rtt.service"
    return 0
  fi
  if [[ $rc -ne 0 ]]; then
    warn "mirage-rtt install --dry-run exited $rc; continuing with rtt disabled"
    printf '%s\n' "$out" >&2
    return 0
  fi
  if ! rtt_plan_exact "$out"; then
    warn "mirage-rtt install --dry-run did not report an exact rollback plan; continuing with rtt disabled"
    return 0
  fi
  log "mirage-rtt install --install-qdisc"
  set +e
  out=$("$BIN_DIR/mirage-rtt" install -c "$cfg" --install-qdisc 2>&1)
  rc=$?
  set -e
  printf '%s\n' "$out"
  if [[ $rc -ne 0 ]]; then
    warn "mirage-rtt install --install-qdisc refused; continuing with --no-rtt semantics"
    printf '%s\n' "$out" >&2
    return 0
  fi
  RTT_ENABLED=1
  manifest_set rtt_qdisc_installed 1
}

start_services() {
  local rtt_en=$1
  if [[ $DRY_RUN -eq 1 ]]; then
    log "would daemon-reload, enable and start mirage-syn.service, mirage-singbox.service$([[ $rtt_en == true ]] && printf ', mirage-rtt.service')"
    return 0
  fi
  systemctl daemon-reload
  systemctl enable mirage-syn.service
  if [[ "$rtt_en" == true ]]; then
    systemctl enable mirage-rtt.service
  fi
  systemctl enable mirage-singbox.service
  systemctl restart mirage-syn.service
  sleep 1
  systemctl is-active --quiet mirage-syn.service || {
    systemctl status --no-pager -l mirage-syn.service || true
    die "mirage-syn.service failed to start"
  }
  if [[ "$rtt_en" == true ]]; then
    systemctl restart mirage-rtt.service
    sleep 1
    systemctl is-active --quiet mirage-rtt.service || {
      systemctl status --no-pager -l mirage-rtt.service || true
      die "mirage-rtt.service failed to start"
    }
  fi
  systemctl restart mirage-singbox.service
  sleep 1
  systemctl is-active --quiet mirage-singbox.service || {
    systemctl status --no-pager -l mirage-singbox.service || true
    journalctl -u mirage-singbox.service -n 40 --no-pager || true
    die "mirage-singbox.service failed to start"
  }
  manifest_set syn_service 1
  manifest_set singbox_service 1
  manifest_set rtt_service "$([[ $rtt_en == true ]] && echo 1 || echo 0)"
  log "services started"
}

print_client_and_reminder() {
  echo
  echo '========== Mirage client profile (mihomo YAML) =========='
  if [[ $DRY_RUN -eq 1 ]]; then
    echo '(dry-run: profile would be written to /etc/mirage/client/mirage.yaml)'
  else
    cat "$ETC_DIR/client/mirage.yaml"
  fi
  echo '========================================================='
  echo
  echo "REMINDER: the cloud firewall must allow TCP ${PORT} inbound."
  echo 'This script never changes cloud firewalls.'
  echo "sing-box client JSON: ${ETC_DIR}/client/sing-box-client.json"
  echo "Reprint later: sudo $0 --show-client"
}

print_warning_summary() {
  local w
  if (( ${#WARNINGS[@]} == 0 )); then
    return 0
  fi
  echo
  echo '========== WARNING SUMMARY =========='
  for w in "${WARNINGS[@]}"; do
    printf 'WARNING: %s\n' "$w"
  done
  echo '====================================='
}

do_install() {
  require_root
  detect_iface
  detect_public_ip
  detect_timezone
  choose_port
  parse_sni "$SNI_FLAG"
  log "iface=$IFACE mtu=$MTU mss=$MSS public_ip=$PUBLIC_IP timezone=$TIMEZONE port=$PORT sni=${SNI_HOST}:${SNI_PORT} profile=$PROFILE_NAME no_rtt=$NO_RTT"
  install_go
  if [[ $DRY_RUN -eq 0 ]]; then
    mkdir -p "$ETC_DIR" "$BIN_DIR" "$VAR_DIR" "$STATE_DIR"
    record_path "$ETC_DIR"
    record_path "$LIB_DIR"
    record_path "$VAR_DIR"
  else
    log "would mkdir $ETC_DIR $BIN_DIR $VAR_DIR $STATE_DIR"
  fi
  build_binaries
  install_singbox_binary
  ensure_user
  load_or_make_secrets
  local rtt_yaml=false
  if [[ $NO_RTT -eq 0 ]]; then
    rtt_yaml=true
  fi
  write_mangler_yaml "$rtt_yaml"
  write_singbox_config
  write_client_files
  install_sysctl
  maybe_install_rtt
  local rtt_en=false
  if [[ $RTT_ENABLED -eq 1 ]]; then
    rtt_en=true
    write_mangler_yaml true
  else
    write_mangler_yaml false
  fi
  write_unit_dropins "$rtt_en"
  start_services "$rtt_en"
  manifest_set port "$PORT"
  manifest_set iface "$IFACE"
  manifest_set mss "$MSS"
  manifest_set public_ip "$PUBLIC_IP"
  if [[ $DRY_RUN -eq 0 ]]; then
    log "install complete"
  else
    log "dry-run complete (no changes)"
  fi
  print_client_and_reminder
  print_warning_summary
}

do_show_client() {
  require_root
  [[ -f $ETC_DIR/client/mirage.yaml ]] || die "no client profile; install first"
  cat "$ETC_DIR/client/mirage.yaml"
}

do_status() {
  require_root
  local unit
  echo '== units =='
  for unit in mirage-syn.service mirage-rtt.service mirage-singbox.service; do
    if systemctl cat "$unit" >/dev/null 2>&1; then
      printf '%s %s\n' "$unit" "$(systemctl is-active "$unit" 2>/dev/null || true) $(systemctl is-enabled "$unit" 2>/dev/null || true)"
    else
      printf '%s not-installed\n' "$unit"
    fi
  done
  echo '== nft =='
  if nft list table inet mirage_syn >/dev/null 2>&1; then
    nft list table inet mirage_syn
  else
    echo 'table inet mirage_syn: absent'
  fi
  echo '== qdisc =='
  local iface
  iface=$(manifest_get iface)
  [[ -n "$iface" ]] || iface=$(ip -4 route show default | awk '/default/ { print $5; exit }')
  if [[ -n "$iface" ]]; then
    tc qdisc show dev "$iface" || true
  fi
  echo '== BPF =='
  if [[ -e /sys/fs/bpf/mirage-rtt ]]; then
    ls -l /sys/fs/bpf/mirage-rtt || true
    if [[ -x $BIN_DIR/mirage-rtt && -f $ETC_DIR/mangler.yaml ]]; then
      "$BIN_DIR/mirage-rtt" check -c "$ETC_DIR/mangler.yaml" || true
    fi
  else
    echo 'mirage-rtt BPF pin: absent'
  fi
  echo '== mirage-syn check (wscale) =='
  if [[ -x $BIN_DIR/mirage-syn && -f $ETC_DIR/mangler.yaml ]]; then
    "$BIN_DIR/mirage-syn" check -c "$ETC_DIR/mangler.yaml" || true
  else
    echo 'mirage-syn not installed'
  fi
  echo '== SYN self-test =='
  MSS=$(manifest_get mss)
  if [[ -z "$MSS" && -f $ETC_DIR/mangler.yaml ]]; then
    MSS=$(awk '/^  mss:/ { print $2; exit }' "$ETC_DIR/mangler.yaml")
  fi
  status_selftest "$iface"
}

status_selftest() {
  local iface=$1
  local host=1.1.1.1 port=443
  if [[ -z "$iface" ]]; then
    echo 'self-test: skipped (no iface)'
    return 0
  fi
  if [[ ! -x $REPO/server/status-connect.py ]]; then
    echo 'self-test: skipped (status-connect.py missing)'
    return 0
  fi
  if ! command -v tcpdump >/dev/null; then
    echo 'self-test: skipped (tcpdump missing)'
    return 0
  fi
  local cap
  cap=$(mktemp /tmp/mirinst-selftest.XXXXXX)
  timeout 5 tcpdump -i "$iface" -nn -vvv -c 1 -l \
    "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn and host ${host} and port ${port}" \
    >"$cap" 2>&1 &
  local tdpid=$!
  sleep 0.4
  set +e
  python3 "$REPO/server/status-connect.py" "$host" "$port" "$MARK"
  local crc=$?
  set -e
  wait "$tdpid" || true
  echo "----- capture -----"
  cat "$cap"
  echo "-------------------"
  local ok=1
  if ! grep -Eq 'id 0[, ]' "$cap"; then
    echo 'self-test: FAIL ip id is not 0'
    ok=0
  fi
  if ! grep -q 'win 65535' "$cap"; then
    echo 'self-test: FAIL window is not 65535'
    ok=0
  fi
  if ! grep -q "mss ${MSS}" "$cap"; then
    echo "self-test: FAIL mss ${MSS} missing"
    ok=0
  fi
  if ! grep -q 'wscale 6' "$cap"; then
    echo 'self-test: FAIL wscale is not 6'
    ok=0
  fi
  if ! grep -q 'sackOK' "$cap"; then
    echo 'self-test: FAIL sackOK missing'
    ok=0
  fi
  if ! grep -Eq 'mss .*,nop,wscale .*,nop,nop,TS' "$cap"; then
    echo 'self-test: FAIL options order is not mss nop wscale nop nop TS ...'
    ok=0
  fi
  if [[ $crc -ne 0 ]]; then
    echo "self-test: connect helper exited $crc (SYN may still have been sent)"
  fi
  if [[ $ok -eq 1 ]]; then
    echo "self-test: PASS macOS SYN shape on ${iface} to ${host}:${port} (window 65535, id 0, wscale 6, options order)"
  else
    echo 'self-test: FAIL'
  fi
  rm -f "$cap"
}

do_uninstall() {
  require_root
  if [[ $DRY_RUN -eq 1 ]]; then
    log "would stop/disable mirage units, restore sysctl, remove user/files created by this installer"
    return 0
  fi
  local unit
  for unit in mirage-singbox.service mirage-rtt.service mirage-syn.service; do
    if systemctl cat "$unit" >/dev/null 2>&1; then
      systemctl disable --now "$unit" >/dev/null 2>&1 || systemctl stop "$unit" >/dev/null 2>&1 || true
      log "stopped $unit"
    fi
  done
  if [[ -x $BIN_DIR/mirage-rtt && -f $ETC_DIR/mangler.yaml ]]; then
    set +e
    "$BIN_DIR/mirage-rtt" uninstall -c "$ETC_DIR/mangler.yaml" >/dev/null 2>&1
    set -e
  fi
  if [[ -x $BIN_DIR/mirage-syn ]]; then
    set +e
    "$BIN_DIR/mirage-syn" rules uninstall >/dev/null 2>&1
    set -e
  fi
  rm -f /etc/systemd/system/mirage-syn.service
  rm -rf /etc/systemd/system/mirage-syn.service.d
  rm -f /etc/systemd/system/mirage-rtt.service
  rm -rf /etc/systemd/system/mirage-rtt.service.d
  rm -f /etc/systemd/system/mirage-singbox.service
  rm -rf /etc/systemd/system/mirage-singbox.service.d
  systemctl daemon-reload
  systemctl reset-failed mirage-syn.service mirage-rtt.service mirage-singbox.service >/dev/null 2>&1 || true

  if [[ -f $STATE_DIR/sysctl.previous ]]; then
    sysctl -p "$STATE_DIR/sysctl.previous"
    log "restored sysctl from $STATE_DIR/sysctl.previous"
  elif [[ -e $SYSCTL_DST ]]; then
    warn "no saved pre-install sysctl values; removing $SYSCTL_DST without restoring live values"
  fi
  rm -f "$SYSCTL_DST"

  if [[ "$(manifest_get user_created)" == 1 ]]; then
    if getent passwd "$SINGBOX_USER" >/dev/null; then
      userdel "$SINGBOX_USER" >/dev/null 2>&1 || true
      log "removed user $SINGBOX_USER"
    fi
    if getent group "$SINGBOX_USER" >/dev/null; then
      groupdel "$SINGBOX_USER" >/dev/null 2>&1 || true
    fi
  fi

  rm -rf "$ETC_DIR" "$LIB_DIR"
  if [[ "$(manifest_get go_installed)" == 1 ]]; then
    rm -rf /opt/mirage/go
    rmdir /opt/mirage 2>/dev/null || true
  fi
  rm -rf "$VAR_DIR"
  log "uninstall complete"
}

while (( $# > 0 )); do
  case "$1" in
    --port)
      [[ $# -ge 2 ]] || die "--port requires a number"
      PORT_FLAG=$2
      [[ "$PORT_FLAG" =~ ^[0-9]+$ ]] || die "--port must be an integer"
      shift 2
      ;;
    --sni)
      [[ $# -ge 2 ]] || die "--sni requires HOST[:PORT]"
      SNI_FLAG=$2
      shift 2
      ;;
    --profile)
      [[ $# -ge 2 ]] || die "--profile requires a name"
      PROFILE_NAME=$2
      shift 2
      ;;
    --no-rtt) NO_RTT=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --uninstall) MODE=uninstall; shift ;;
    --status) MODE=status; shift ;;
    --show-client) MODE=show-client; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

case "$MODE" in
  install) do_install ;;
  uninstall) do_uninstall ;;
  status) do_status ;;
  show-client) do_show_client ;;
  *) die "internal: unknown mode $MODE" ;;
esac
