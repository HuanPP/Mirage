#!/usr/bin/env bash
# Explicit administrator action, separate from the CAP_NET_ADMIN-only daemon.
# Restores pre-install values on uninstall; the integration test never calls this.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
[[ $(id -u) == 0 ]] || { printf '%s\n' 'Run as root.' >&2; exit 1; }
SOURCE=$(cd "$(dirname "$0")" && pwd)/99-mirage-syn.sysctl.conf
TARGET=/etc/sysctl.d/99-mirage-syn.conf
STATE=/var/lib/mirage-syn/sysctl.previous
case ${1:-} in
    install)
        [[ ! -e $STATE && ! -e $TARGET ]] || { printf '%s\n' 'Already installed or target exists; uninstall or resolve it first.' >&2; exit 1; }
        umask 077
        mkdir -p "$(dirname "$STATE")"
        PREVIOUS=$(mktemp "$STATE.XXXXXX")
        trap 'rm -f "$PREVIOUS"' EXIT
        while read -r key; do
            value=$(sysctl -n "$key")
            printf '%s = %s\n' "$key" "$value"
        done < <(awk '/^net\./ { print $1 }' "$SOURCE") >"$PREVIOUS"
        mv "$PREVIOUS" "$STATE"
        trap - EXIT
        rollback() {
            sysctl -p "$STATE"
            rm -f "$TARGET" "$STATE"
        }
        trap rollback ERR
        install -m 0644 "$SOURCE" "$TARGET"
        sysctl -p "$TARGET"
        trap - ERR
        ;;
    uninstall)
        if [[ -f $STATE ]]; then
            sysctl -p "$STATE"
            rm -f "$TARGET" "$STATE"
            rmdir "$(dirname "$STATE")" 2>/dev/null || true
        elif [[ -e $TARGET ]]; then
            printf '%s\n' 'No saved pre-install state; refusing to guess sysctl values.' >&2
            exit 1
        fi
        ;;
    *) printf '%s\n' 'Usage: sysctl.sh install|uninstall' >&2; exit 1 ;;
esac
