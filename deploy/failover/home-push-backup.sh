#!/bin/sh
# home-push-backup.sh — run on the HOME broker. Every few minutes, push a
# consistent SQLite snapshot (plus the TLS certs) to the backup VPS so the
# failover broker can serve the same tokens/plans/codes.
#
# Requirements: ssh/scp key from home -> VPS (ssh-copy-id once), docker CLI.
#
# Configuration (environment, or deploy/.env):
#   DDNS_VPS_SSH           scp target on the backup VPS, e.g. root@203.0.113.10
#   DDNS_VPS_DEPLOY_DIR    deploy dir on the VPS (default /opt/ddns-deploy)
#   DDNS_VOLUME            broker data volume name (default ddns_broker-data;
#                          verify with `docker volume ls`)
#   DDNS_CERT_DIR          local cert dir to mirror (default ./certs)
#
# Install (home, every 5 min):
#   cp deploy/failover/home-push-backup.sh /opt/ddns-deploy/
#   cp deploy/failover/systemd/home-push-backup.{service,timer} /etc/systemd/system/
#   systemctl daemon-reload && systemctl enable --now home-push-backup.timer

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -f "$SCRIPT_DIR/.env" ]; then
    while IFS='=' read -r key val; do
        case "$key" in
            '' | \#*) continue ;;
            *) [ -z "${!key:-}" ] && export "$key=$val" ;;
        esac
    done < "$SCRIPT_DIR/.env"
fi

VPS=${DDNS_VPS_SSH:-}
VPS_DIR=${DDNS_VPS_DEPLOY_DIR:-/opt/ddns-deploy}
VOLUME=${DDNS_VOLUME:-ddns_broker-data}
CERT_DIR=${DDNS_CERT_DIR:-$SCRIPT_DIR/certs}
TMP=/tmp/ddns-backup.$$

[ -n "$VPS" ] || { echo "error: DDNS_VPS_SSH is required (e.g. root@1.2.3.4)" >&2; exit 2; }
command -v docker >/dev/null 2>&1 || { echo "error: docker required" >&2; exit 2; }

trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP"

# 1. Consistent SQLite snapshot (VACUUM INTO semantics via sqlite3 .backup).
#    The broker image has no sqlite3, so run it in a throwaway alpine
#    container against the named volume (same pattern as the backup docs).
if ! docker run --rm \
    -v "$VOLUME":/data:ro \
    -v "$TMP":/backup \
    alpine sh -c 'apk add --no-cache sqlite >/dev/null 2>&1 && sqlite3 /data/ddns.db ".backup /backup/ddns.db"' \
    >/dev/null 2>&1; then
    echo "error: sqlite snapshot failed (volume $VOLUME exists? 'docker volume ls')" >&2
    exit 1
fi

# 2. Mirror the certs (the VPS serves the same wildcard cert on failover).
[ -d "$CERT_DIR" ] && cp -f "$CERT_DIR"/*.pem "$TMP"/ 2>/dev/null || true

# 3. Push to the VPS (atomic: scp to a temp name, then rename).
ssh -o BatchMode=yes "${VPS%%:*}" \
    "mkdir -p '$VPS_DIR/backup'" >/dev/null 2>&1 || true
scp -q -o BatchMode=yes "$TMP"/ddns.db "$TMP"/*.pem \
    "$VPS:$VPS_DIR/backup/" 2>/dev/null || { echo "error: scp failed" >&2; exit 1; }
ssh -o BatchMode=yes "${VPS%%:*}" \
    "mv -f '$VPS_DIR/backup/ddns.db' '$VPS_DIR/backup/ddns.db.ready' 2>/dev/null || true; \
     ls '$VPS_DIR/backup/'" >/dev/null 2>&1

echo "backup pushed to $VPS:$VPS_DIR/backup ($(date -u +%FT%TZ))"
