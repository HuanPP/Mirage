#!/usr/bin/env bash
# Mirage macOS installer. No root. Does not touch the owner's Chrome, proxies,
# or network settings.
set -euo pipefail

REPO=$(cd "$(dirname "$0")" && pwd)
LAUNCHER_SRC="$REPO/launcher/bin/mirage-launch"

MIHOMO_VERSION='1.19.32'
MIHOMO_SHA256_DARWIN_ARM64='3312a6780652c622890fd4357c6a853bbf865464fd047ac7b7f52dab8de18652'
MIHOMO_SHA256_DARWIN_AMD64='b7de9fc46af2ca985ecfb302a6362170e04ff2023dee1e82addc54133e669bc9'

CONFIG_DIR="${MIRAGE_CONFIG_DIR:-$HOME/.config/mirage}"
BIN_LINK_DIR="${MIRAGE_BIN_DIR:-$HOME/.local/bin}"
MIHOMO_BIN_DIR="${MIRAGE_MIHOMO_DIR:-$HOME/.mirage/bin}"
STATE_DIR="$CONFIG_DIR/install-state"
PROFILES_DIR="$CONFIG_DIR/profiles"
CONF_PATH="$CONFIG_DIR/launcher.conf"
LINK_PATH="$BIN_LINK_DIR/mirage-launch"

usage() {
  cat <<'EOF'
Usage: ./install-local.sh --import <path-or-https-URL> [--with-mihomo]
       ./install-local.sh --uninstall
       ./install-local.sh --help

Install the Mirage Chrome launcher on this Mac (macOS 13+, arm64 or x86_64).
Never uses sudo.

  --import X     Fetch or copy a Mirage profile YAML (file path or https URL),
                 store it as ~/.config/mirage/profiles/<profile>.yaml, parse the
                 top-level mirage: section, and write ~/.config/mirage/launcher.conf.
  --with-mihomo  Download the pinned official mihomo darwin binary into
                 ~/.mirage/bin. Prints the sudo command to start TUN; never
                 runs sudo.
  --uninstall    Remove only files and the symlink this script created.
  --help         Show this help.

After import:
  1. Import the same YAML into Clash Verge Rev / mihomo (it is a normal mihomo
     config) and enable TUN.
  2. Run mirage-launch to open the aligned Chrome.
EOF
}

log() { printf '%s %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }

need_macos() {
  [[ "$(uname -s)" == Darwin ]] || die "install-local.sh is for macOS"
}

arch_tag() {
  case "$(uname -m)" in
    arm64) printf '%s\n' arm64 ;;
    x86_64) printf '%s\n' amd64 ;;
    *) die "unsupported architecture $(uname -m)" ;;
  esac
}

state_set() {
  mkdir -p "$STATE_DIR"
  local key=$1 value=$2
  local tmp
  tmp=$(mktemp "$STATE_DIR/manifest.XXXXXX")
  if [[ -f "$STATE_DIR/manifest" ]]; then
    awk -F= -v k="$key" '$1 != k { print }' "$STATE_DIR/manifest" >"$tmp"
  else
    : >"$tmp"
  fi
  printf '%s=%s\n' "$key" "$value" >>"$tmp"
  mv "$tmp" "$STATE_DIR/manifest"
}

state_get() {
  local key=$1
  [[ -f "$STATE_DIR/manifest" ]] || return 0
  awk -F= -v k="$key" '$1 == k { print substr($0, index($0, "=") + 1); exit }' "$STATE_DIR/manifest"
}

record_path() {
  mkdir -p "$STATE_DIR"
  printf '%s\n' "$1" >>"$STATE_DIR/paths"
}

# Strict parser: only a top-level `mirage:` mapping (or a `# mirage:` comment
# block) of 2-space indented `key: value` scalars. No nested keys, no lists.
parse_mirage_section() {
  local file=$1
  awk '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    function unquote(s) {
      if (s ~ /^".*"$/) {
        sub(/^"/, "", s)
        sub(/"$/, "", s)
        return s
      }
      if (s ~ /^'\''.*'\''$/) {
        sub(/^'\''/, "", s)
        sub(/'\''$/, "", s)
        return s
      }
      return s
    }
    BEGIN { insec = 0; cmt = 0 }
    /^[[:space:]]*#[[:space:]]*mirage:[[:space:]]*$/ { insec = 1; cmt = 1; next }
    /^mirage:[[:space:]]*$/ { insec = 1; cmt = 0; next }
    insec {
      line = $0
      if (cmt) {
        if (line ~ /^[[:space:]]*$/) next
        if (line ~ /^[[:space:]]*#/) {
          sub(/^[[:space:]]*#/, "", line)
        } else {
          insec = 0
          next
        }
      }
      if (line ~ /^[[:space:]]*$/) next
      if (line ~ /^[[:space:]]*#/) next
      if (line ~ /^[^[:space:]]/) { insec = 0; next }
      if (line ~ /^  [A-Za-z0-9_]+:[[:space:]]/) {
        key = line
        sub(/^  /, "", key)
        val = key
        sub(/:.*$/, "", key)
        sub(/^[^:]+:[[:space:]]*/, "", val)
        key = trim(key)
        val = unquote(trim(val))
        if (key == "" || val == "") {
          printf "error: empty key or value in mirage section: %s\n", $0 > "/dev/stderr"
          exit 3
        }
        if (val ~ /[[:space:]]/ && $0 !~ /:[[:space:]]*["'\'']/) {
          # bare scalars must be a single token
          printf "error: mirage scalar must be a single token: %s\n", $0 > "/dev/stderr"
          exit 3
        }
        printf "%s=%s\n", key, val
        next
      }
      printf "error: only 2-space indented key: value scalars allowed in mirage section: %s\n", $0 > "/dev/stderr"
      exit 3
    }
  ' "$file"
}

import_profile() {
  local src=$1
  local tmp
  mkdir -p "$PROFILES_DIR" "$CONFIG_DIR"
  tmp=$(mktemp "$PROFILES_DIR/.import.XXXXXX")
  if [[ "$src" == https://* ]]; then
    log "fetch $src"
    curl -fsSL --max-time 30 -o "$tmp" "$src" || { rm -f "$tmp"; die "failed to fetch $src"; }
  elif [[ "$src" == http://* ]]; then
    rm -f "$tmp"
    die "only https URLs are accepted"
  else
    [[ -f "$src" ]] || { rm -f "$tmp"; die "profile not found: $src"; }
    cp "$src" "$tmp"
  fi

  local parsed key val
  local version='' expect_egress='' timezone='' lang='' profile=''
  parsed=$(parse_mirage_section "$tmp") || { rm -f "$tmp"; die "failed to parse mirage: section"; }
  [[ -n "$parsed" ]] || { rm -f "$tmp"; die "no mirage: section found (mapping or '# mirage:' comment block)"; }
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    key=${line%%=*}
    val=${line#*=}
    case "$key" in
      version) version=$val ;;
      expect_egress) expect_egress=$val ;;
      timezone) timezone=$val ;;
      lang) lang=$val ;;
      profile) profile=$val ;;
      *)
        rm -f "$tmp"
        die "unknown mirage key: $key"
        ;;
    esac
  done <<<"$parsed"

  [[ "$version" == 1 ]] || { rm -f "$tmp"; die "mirage.version must be 1 (got '${version}')"; }
  [[ -n "$expect_egress" ]] || { rm -f "$tmp"; die "mirage.expect_egress is required"; }
  [[ -n "$timezone" ]] || { rm -f "$tmp"; die "mirage.timezone is required"; }
  [[ -n "$lang" ]] || { rm -f "$tmp"; die "mirage.lang is required"; }
  [[ -n "$profile" ]] || { rm -f "$tmp"; die "mirage.profile is required"; }
  [[ "$profile" == [A-Za-z0-9._-]* && "$profile" != *[!A-Za-z0-9._-]* ]] || {
    rm -f "$tmp"
    die "mirage.profile must match [A-Za-z0-9._-]+"
  }
  [[ "$expect_egress" == [0-9]*.[0-9]*.[0-9]*.[0-9]* ]] || {
    rm -f "$tmp"
    die "mirage.expect_egress must be an IPv4 address"
  }

  local dest="$PROFILES_DIR/${profile}.yaml"
  if [[ ! -e "$dest" ]]; then
    record_path "$dest"
  fi
  mv "$tmp" "$dest"
  chmod 0600 "$dest"
  state_set imported_profile "$profile"
  state_set imported_yaml "$dest"
  log "stored profile $dest"

  if [[ -f "$CONF_PATH" && ! -f "$STATE_DIR/launcher.conf.bak" ]]; then
    cp "$CONF_PATH" "$STATE_DIR/launcher.conf.bak"
    state_set conf_backup 1
  fi
  if [[ ! -e "$CONF_PATH" ]]; then
    record_path "$CONF_PATH"
    state_set conf_created 1
  fi
  cat >"$CONF_PATH" <<EOF
# Written by install-local.sh from ${profile}.yaml
profile=${profile}
timezone=${timezone}
lang=${lang}
expect_egress=${expect_egress}
EOF
  chmod 0600 "$CONF_PATH"
  log "wrote $CONF_PATH"

  install_symlink

  cat <<EOF

Next steps:
  1. Import ${dest} into Clash Verge Rev / mihomo (it is a normal mihomo config).
  2. Enable TUN in that client.
  3. Run: mirage-launch
     (opens stock Chrome with TZ=${timezone}, lang=${lang}; refuses to start
      unless current egress IPv4 is ${expect_egress}, unless --force)

EOF
}

install_symlink() {
  [[ -x "$LAUNCHER_SRC" ]] || die "launcher missing: $LAUNCHER_SRC"
  mkdir -p "$BIN_LINK_DIR"
  if [[ ! -e "$LINK_PATH" && ! -L "$LINK_PATH" ]]; then
    record_path "$LINK_PATH"
    state_set link_created 1
  fi
  ln -sfn "$LAUNCHER_SRC" "$LINK_PATH"
  log "symlink $LINK_PATH -> $LAUNCHER_SRC"
  case ":$PATH:" in
    *:"$BIN_LINK_DIR":*) ;;
    *)
      warn "$BIN_LINK_DIR is not in PATH; add it (e.g. export PATH=\"$BIN_LINK_DIR:\$PATH\") or run $LAUNCHER_SRC"
      ;;
  esac
  state_set link_path "$LINK_PATH"
}

install_mihomo() {
  local arch sha url gz
  arch=$(arch_tag)
  if [[ "$arch" == arm64 ]]; then
    sha=$MIHOMO_SHA256_DARWIN_ARM64
  else
    sha=$MIHOMO_SHA256_DARWIN_AMD64
  fi
  url="https://github.com/MetaCubeX/mihomo/releases/download/v${MIHOMO_VERSION}/mihomo-darwin-${arch}-v${MIHOMO_VERSION}.gz"
  mkdir -p "$MIHOMO_BIN_DIR" "$STATE_DIR"
  gz=$(mktemp "$STATE_DIR/mihomo.XXXXXX.gz")
  log "download $url"
  curl -fL --retry 3 --max-time 120 -o "$gz" "$url"
  local got
  got=$(shasum -a 256 "$gz" | awk '{ print $1 }')
  if [[ "$got" != "$sha" ]]; then
    rm -f "$gz"
    die "mihomo sha256 mismatch (got $got want $sha)"
  fi
  local dest="$MIHOMO_BIN_DIR/mihomo"
  gzip -dc "$gz" >"$dest"
  rm -f "$gz"
  chmod 0755 "$dest"
  if [[ "$(state_get mihomo_bin)" != "$dest" ]]; then
    record_path "$dest"
  fi
  state_set mihomo_bin "$dest"
  log "installed $dest (mihomo ${MIHOMO_VERSION})"

  local profile yaml
  profile=$(state_get imported_profile)
  yaml=$(state_get imported_yaml)
  if [[ -z "$yaml" && -n "$profile" ]]; then
    yaml="$PROFILES_DIR/${profile}.yaml"
  fi
  if [[ -z "$yaml" ]]; then
    yaml='<profile.yaml>'
  fi
  cat <<EOF

Start TUN yourself (this installer never runs sudo):
  sudo ${dest} -d ${CONFIG_DIR}/mihomo -f ${yaml}

EOF
}

uninstall_local() {
  local link p
  link=$(state_get link_path)
  [[ -n "$link" ]] || link=$LINK_PATH
  if [[ -L "$link" ]]; then
    local target
    target=$(readlink "$link")
    if [[ "$target" == "$LAUNCHER_SRC" ]]; then
      rm -f "$link"
      log "removed symlink $link"
    else
      warn "leaving $link (points to $target, not $LAUNCHER_SRC)"
    fi
  fi

  if [[ -f "$STATE_DIR/launcher.conf.bak" ]]; then
    mv "$STATE_DIR/launcher.conf.bak" "$CONF_PATH"
    log "restored $CONF_PATH from backup"
  elif [[ "$(state_get conf_created)" == 1 ]]; then
    rm -f "$CONF_PATH"
    log "removed $CONF_PATH"
  fi

  local yaml
  yaml=$(state_get imported_yaml)
  if [[ -n "$yaml" && -f "$yaml" ]]; then
    rm -f "$yaml"
    log "removed $yaml"
  fi

  local mihomo
  mihomo=$(state_get mihomo_bin)
  if [[ -n "$mihomo" && -f "$mihomo" ]]; then
    rm -f "$mihomo"
    log "removed $mihomo"
  fi

  if [[ -f "$STATE_DIR/paths" ]]; then
    while IFS= read -r p || [[ -n "$p" ]]; do
      [[ -e "$p" || -L "$p" ]] || continue
      if [[ -d "$p" ]]; then
        rmdir "$p" 2>/dev/null || true
      fi
    done <"$STATE_DIR/paths"
  fi

  rm -rf "$STATE_DIR"
  rmdir "$PROFILES_DIR" 2>/dev/null || true
  rmdir "$CONFIG_DIR" 2>/dev/null || true
  rmdir "$MIHOMO_BIN_DIR" 2>/dev/null || true
  rmdir "$HOME/.mirage" 2>/dev/null || true
  rmdir "$BIN_LINK_DIR" 2>/dev/null || true
  log "uninstall complete"
}

IMPORT=''
WITH_MIHOMO=0
MODE='install'

while (( $# > 0 )); do
  case "$1" in
    --import)
      [[ $# -ge 2 ]] || die "--import requires a path or https URL"
      IMPORT=$2
      shift 2
      ;;
    --with-mihomo)
      WITH_MIHOMO=1
      shift
      ;;
    --uninstall)
      MODE='uninstall'
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

need_macos

if [[ "$MODE" == uninstall ]]; then
  [[ -z "$IMPORT" && "$WITH_MIHOMO" -eq 0 ]] || die "--uninstall cannot be combined with --import/--with-mihomo"
  uninstall_local
  exit 0
fi

[[ -n "$IMPORT" ]] || { usage >&2; die "--import is required"; }
import_profile "$IMPORT"
if [[ "$WITH_MIHOMO" -eq 1 ]]; then
  install_mihomo
fi
