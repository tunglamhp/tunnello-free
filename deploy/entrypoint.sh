#!/bin/sh
# ddns broker container entrypoint — translates env vars into CLI flags.
# The broker binary has hand-rolled flag parsing (no env support), so the
# flag set is assembled here. Exactly one certificate source is required.
set -eu

# The DB holds every secret (token hashes, provider keys are env-only but admin
# hash + tokens are in the DB). Create everything 0600/0700 regardless of the
# host umask; the mode survives the setpriv exec below.
umask 077

: "${DDNS_DOMAIN:?DDNS_DOMAIN is required (set it in deploy/.env)}"

set -- --domain "$DDNS_DOMAIN"
[ -n "${DDNS_LISTEN:-}" ]       && set -- "$@" --listen "$DDNS_LISTEN"
[ -n "${DDNS_PUBLIC_PORT:-}" ]  && set -- "$@" --public-port "$DDNS_PUBLIC_PORT"
[ -n "${DDNS_HTTP_LISTEN:-}" ]  && set -- "$@" --http-listen "$DDNS_HTTP_LISTEN"
[ -n "${DDNS_DB:-}" ]           && set -- "$@" --db "$DDNS_DB"
[ -n "${DDNS_MAX_SESSIONS:-}" ]           && set -- "$@" --max-sessions "$DDNS_MAX_SESSIONS"
[ -n "${DDNS_MAX_STREAMS_PER_SESSION:-}" ] && set -- "$@" --max-streams-per-session "$DDNS_MAX_STREAMS_PER_SESSION"
[ -n "${DDNS_WATCHDOG_MS:-}" ]  && set -- "$@" --watchdog-ms "$DDNS_WATCHDOG_MS"
[ -n "${DDNS_DOWNLOAD_DIR:-}" ] && set -- "$@" --download-dir "$DDNS_DOWNLOAD_DIR"
[ -n "${DDNS_ACME_DIRECTORY:-}" ] && set -- "$@" --acme-directory "$DDNS_ACME_DIRECTORY"
[ -n "${DDNS_STUN_PORT:-}" ]  && set -- "$@" --stun-port "$DDNS_STUN_PORT"

# Serve the ddns-web bundle (built in the Docker `web` stage) at /_assets/*.
# Default to the container path; only enable the flag when the dir exists so
# an image built without the bundle still starts (the broker then serves no
# islands and falls back to its server-rendered HTML).
web_dist="${DDNS_WEB_DIST:-/opt/ddns/web/public}"
[ -d "$web_dist" ] && set -- "$@" --web-dist "$web_dist"

# Certificate source — exactly one of: static PEM, ACME, or dev self-signed.
cert_sources=0
[ -n "${DDNS_CERT:-}" ] && [ -n "${DDNS_KEY:-}" ] && cert_sources=$((cert_sources + 1))
[ -n "${DDNS_ACME_EMAIL:-}" ] && cert_sources=$((cert_sources + 1))
[ "${DDNS_DEV:-0}" = "1" ] && cert_sources=$((cert_sources + 1))
if [ "$cert_sources" -ne 1 ]; then
    echo "error: exactly one cert source required: DDNS_CERT+DDNS_KEY, DDNS_ACME_EMAIL, or DDNS_DEV=1" >&2
    exit 1
fi
[ -n "${DDNS_CERT:-}" ]       && set -- "$@" --cert "$DDNS_CERT" --key "$DDNS_KEY"
[ -n "${DDNS_ACME_EMAIL:-}" ] && set -- "$@" --acme-email "$DDNS_ACME_EMAIL"
[ "${DDNS_DEV:-0}" = "1" ]    && set -- "$@" --dev

# /data starts root-owned on a fresh named volume — make it writable, then
# drop privileges for the broker process itself.
mkdir -p "$(dirname "${DDNS_DB:-/data/ddns.db}")" "${DDNS_DOWNLOAD_DIR:-/data/downloads}" 2>/dev/null || true
chown -R ddns:ddns /data 2>/dev/null || true

# Seed the download dir with the built client binary on first boot.
if [ -d /opt/ddns/downloads ] && [ -n "${DDNS_DOWNLOAD_DIR:-}" ] && [ -z "$(ls -A "$DDNS_DOWNLOAD_DIR" 2>/dev/null)" ]; then
    cp /opt/ddns/downloads/* "$DDNS_DOWNLOAD_DIR/"
    chown -R ddns:ddns "$DDNS_DOWNLOAD_DIR"
fi

exec setpriv --reuid=ddns --regid=ddns --clear-groups /usr/local/bin/ddns-server "$@"
