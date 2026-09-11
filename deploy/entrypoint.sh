#!/bin/sh
# ddns broker container entrypoint — translates env vars into CLI flags.
# The broker binary has hand-rolled flag parsing (no env support), so the
# flag set is assembled here. Exactly one certificate source is required.
set -eu

# The DB holds every secret (token hashes; the admin hash and tokens are in the
# DB, other secrets are env-only). Create everything 0600/0700 regardless of the
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
# DNS-01 ACME provider + credentials (Cloudflare/Porkbun). When set, the
# broker issues one certificate for the apex AND *.apex via DNS-01 TXT
# records — no inbound validation port required. Credentials are env-only.
[ -n "${DDNS_ACME_PROVIDER:-}" ] && set -- "$@" --acme-provider "$DDNS_ACME_PROVIDER"
[ -n "${DDNS_ACME_CF_TOKEN:-}" ]   && set -- "$@" --acme-cf-token "$DDNS_ACME_CF_TOKEN"
[ -n "${DDNS_ACME_CF_ZONE:-}" ]    && set -- "$@" --acme-cf-zone "$DDNS_ACME_CF_ZONE"
[ -n "${DDNS_ACME_PORKBUN_KEY:-}" ] && set -- "$@" --acme-porkbun-key "$DDNS_ACME_PORKBUN_KEY"
[ -n "${DDNS_ACME_PORKBUN_SECRET:-}" ] && set -- "$@" --acme-porkbun-secret "$DDNS_ACME_PORKBUN_SECRET"
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
# ACME provider sanity: a DNS-01 provider needs its credentials; creds
# without --acme-email are a config mistake.
if [ -n "${DDNS_ACME_EMAIL:-}" ]; then
    provider="${DDNS_ACME_PROVIDER:-manual}"
    case "$provider" in
        manual)
            if [ -n "${DDNS_ACME_CF_TOKEN:-}" ] || [ -n "${DDNS_ACME_CF_ZONE:-}" ] || [ -n "${DDNS_ACME_PORKBUN_KEY:-}" ] || [ -n "${DDNS_ACME_PORKBUN_SECRET:-}" ]; then
                echo "error: DDNS_ACME_PROVIDER=manual does not take DNS-provider credentials" >&2
                exit 1
            fi
            ;;
        cloudflare)
            [ -n "${DDNS_ACME_CF_TOKEN:-}" ] || { echo "error: DDNS_ACME_PROVIDER=cloudflare requires DDNS_ACME_CF_TOKEN and DDNS_ACME_CF_ZONE" >&2; exit 1; }
            [ -n "${DDNS_ACME_CF_ZONE:-}" ] || { echo "error: DDNS_ACME_PROVIDER=cloudflare requires DDNS_ACME_CF_TOKEN and DDNS_ACME_CF_ZONE" >&2; exit 1; }
            ;;
        porkbun)
            [ -n "${DDNS_ACME_PORKBUN_KEY:-}" ] || { echo "error: DDNS_ACME_PROVIDER=porkbun requires DDNS_ACME_PORKBUN_KEY and DDNS_ACME_PORKBUN_SECRET" >&2; exit 1; }
            [ -n "${DDNS_ACME_PORKBUN_SECRET:-}" ] || { echo "error: DDNS_ACME_PROVIDER=porkbun requires DDNS_ACME_PORKBUN_KEY and DDNS_ACME_PORKBUN_SECRET" >&2; exit 1; }
            ;;
        *) echo "error: unknown DDNS_ACME_PROVIDER=$provider (manual | cloudflare | porkbun)" >&2; exit 1 ;;
    esac
elif [ "${DDNS_ACME_PROVIDER:-manual}" != "manual" ] || [ -n "${DDNS_ACME_CF_TOKEN:-}" ] || [ -n "${DDNS_ACME_CF_ZONE:-}" ] || [ -n "${DDNS_ACME_PORKBUN_KEY:-}" ] || [ -n "${DDNS_ACME_PORKBUN_SECRET:-}" ]; then
    echo "error: DDNS_ACME_PROVIDER / DNS-provider credentials require DDNS_ACME_EMAIL" >&2
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
