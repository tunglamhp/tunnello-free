#!/usr/bin/env bash
# Tunello — one-click VPS deploy.
#
# Copy this whole `deploy/` folder to the VPS, then:
#     ./deploy.sh
# On a fresh Ubuntu VPS run as root it auto-installs Docker Engine when
# missing (DDNS_INSTALL_DOCKER=0 disables). It detects a repo checkout
# (running from deploy/ inside a clone), otherwise clones the source
# (DDNS_REPO_URL or prompt), writes deploy/.env from your answers/env, builds
# the image, starts the stack, and prints the first-run steps. Re-run with
# --update to pull + rebuild + restart.
#
# Non-interactive (for scripts/CI): provide the env vars below.
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-install}"

# ---------------------------------------------------------------------------
# 0. preflight — auto-install Docker Engine on a fresh Ubuntu VPS
# ---------------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
    if [ "${DDNS_INSTALL_DOCKER:-1}" = "1" ] && [ "$(id -u)" = "0" ]; then
        echo "docker not found — installing Docker Engine (get.docker.com) …"
        curl -fsSL https://get.docker.com | sh
    else
        echo "error: docker is required." >&2
        echo "  - fresh Ubuntu VPS: run this script as root (it auto-installs Docker), or" >&2
        echo "  - install Docker Engine manually, then run ./deploy.sh again." >&2
        echo "  - to disable auto-install: DDNS_INSTALL_DOCKER=0 ./deploy.sh" >&2
        exit 1
    fi
fi
command -v docker >/dev/null 2>&1 || { echo "error: docker install failed — install Docker Engine manually and re-run" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "error: docker compose v2 plugin is required (get.docker.com installs it; otherwise install docker-compose-plugin)" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. firewall — open the P2P STUN port so visitor browsers can reach the
# broker's WebRTC ICE endpoint (UDP hole-punching for the data plane). The
# HTTPS/WSS port is opened by the operator per deploy/README.md §2.
# ---------------------------------------------------------------------------
if command -v ufw >/dev/null 2>&1; then
    ufw allow "${DDNS_STUN_PORT:-3478}/udp" >/dev/null   # WebRTC ICE STUN (P2P data plane)
fi

# ---------------------------------------------------------------------------
# 2. configuration — deploy/.env from answers/env (never overwrite user edits
#    unless explicitly recreating).
# ---------------------------------------------------------------------------
ENV_FILE="$DEPLOY_DIR/.env"
if [ ! -f "$ENV_FILE" ] || [ "${DDNS_RECREATE_ENV:-0}" = "1" ]; then
    cp "$DEPLOY_DIR/.env.example" "$ENV_FILE"

    read_domain() { : "${DDNS_DOMAIN:?error: DDNS_DOMAIN is required — set it in deploy/.env or export DDNS_DOMAIN}"; }

    # Cert source — exactly one (mirrors entrypoint.sh).
    cert_sources=0
    [ -n "${DDNS_CERT:-}" ] && [ -n "${DDNS_KEY:-}" ] && cert_sources=$((cert_sources + 1))
    [ -n "${DDNS_ACME_EMAIL:-}" ] && cert_sources=$((cert_sources + 1))
    [ "${DDNS_DEV:-0}" = "1" ] && cert_sources=$((cert_sources + 1))
    if [ "$cert_sources" -eq 0 ]; then
        echo "Pick a certificate source:"
        echo "  1) Static PEM  (place fullchain.pem + privkey.pem in $DEPLOY_DIR/certs)"
        echo "  2) Let's Encrypt TLS-ALPN-01 (apex domain, port 443 reachable)"
        echo "  3) Dev self-signed (testing only — NEVER in production)"
        printf "choice [1/2/3]: "
        read -r cert_choice
        case "$cert_choice" in
            1) DDNS_CERT=/certs/fullchain.pem DDNS_KEY=/certs/privkey.pem ;;
            2) printf "ACME contact email: " && read -r DDNS_ACME_EMAIL ;;
            3) DDNS_DEV=1 ;;
            *) echo "invalid choice" >&2; exit 1 ;;
        esac
    elif [ "$cert_sources" -gt 1 ]; then
        echo "error: exactly one cert source: DDNS_CERT+DDNS_KEY, DDNS_ACME_EMAIL, or DDNS_DEV=1" >&2
        exit 1
    fi

    if [ "${DDNS_DEV:-0}" != "1" ]; then
        : "${DDNS_DOMAIN:?error: DDNS_DOMAIN is required — set it in deploy/.env or export DDNS_DOMAIN}"
    else
        DDNS_DOMAIN="${DDNS_DOMAIN:-test.local}"
    fi

    # Write the resolved values into .env (append after the template).
    {
        echo
        echo "# --- resolved by deploy.sh ---"
        echo "DDNS_DOMAIN=$DDNS_DOMAIN"
        [ -n "${DDNS_CERT:-}" ] && echo "DDNS_CERT=$DDNS_CERT"
        [ -n "${DDNS_KEY:-}" ] && echo "DDNS_KEY=$DDNS_KEY"
        [ -n "${DDNS_ACME_EMAIL:-}" ] && echo "DDNS_ACME_EMAIL=$DDNS_ACME_EMAIL"
        [ "${DDNS_DEV:-0}" = "1" ] && echo "DDNS_DEV=1"
    } >> "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    echo "wrote $ENV_FILE (secrets: chmod 600)"
fi

# Optional integrations pass through from the shell if set.
for var in DDNS_BASE_URL \
           DDNS_SMTP_HOST DDNS_SMTP_PORT DDNS_SMTP_USER DDNS_SMTP_PASS \
           DDNS_SMTP_FROM DDNS_SMTP_TLS; do
    if [ -n "${!var:-}" ] && ! grep -q "^$var=" "$ENV_FILE"; then
        echo "$var=${!var}" >> "$ENV_FILE"
    fi
done

# Keep generated customer links aligned with the host port. An explicit
# DDNS_BASE_URL always wins, which supports a reverse proxy on standard 443.
domain_from_env="$(grep -E '^DDNS_DOMAIN=' "$ENV_FILE" | head -1 | cut -d= -f2)"
public_port="$(grep -E '^DDNS_PUBLIC_PORT=' "$ENV_FILE" | head -1 | cut -d= -f2)"
public_port="${public_port:-443}"
if ! grep -q '^DDNS_BASE_URL=' "$ENV_FILE"; then
    if [ "$public_port" = "443" ]; then
        echo "DDNS_BASE_URL=https://$domain_from_env" >> "$ENV_FILE"
    else
        echo "DDNS_BASE_URL=https://$domain_from_env:$public_port" >> "$ENV_FILE"
    fi
fi

# ---------------------------------------------------------------------------
# 3. source — use the surrounding checkout if present, else clone.
# ---------------------------------------------------------------------------
if [ -f "$DEPLOY_DIR/../Cargo.toml" ]; then
    SRC="$(cd "$DEPLOY_DIR/.." && pwd)"
    echo "using surrounding repo checkout: $SRC"
elif [ -d "$DEPLOY_DIR/src/.git" ]; then
    SRC="$DEPLOY_DIR/src"
    echo "using existing clone: $SRC"
else
    : "${DDNS_REPO_URL:?error: run this from a repo checkout, or export DDNS_REPO_URL (git clone URL)}"
    echo "cloning $DDNS_REPO_URL …"
    git clone --depth 1 "$DDNS_REPO_URL" "$DEPLOY_DIR/src"
    SRC="$DEPLOY_DIR/src"
    # Keep the launcher's deploy files authoritative (they may be newer than
    # the clone) and carry the resolved .env into the build context.
    cp -f "$DEPLOY_DIR/Dockerfile" "$DEPLOY_DIR/entrypoint.sh" "$DEPLOY_DIR/docker-compose.yml" "$SRC/deploy/"
    cp -f "$ENV_FILE" "$SRC/deploy/.env"
fi

# ---------------------------------------------------------------------------
# 4. install / update
# ---------------------------------------------------------------------------
if [ "$MODE" = "--update" ]; then
    echo "updating …"
    if [ -d "$SRC/.git" ]; then git -C "$SRC" pull --ff-only; fi
    cp -f "$DEPLOY_DIR/entrypoint.sh" "$DEPLOY_DIR/Dockerfile" "$SRC/deploy/" 2>/dev/null || true
    cp -f "$ENV_FILE" "$SRC/deploy/.env"
fi

echo "building + starting …"
docker compose -f "$SRC/deploy/docker-compose.yml" up -d --build

# ---------------------------------------------------------------------------
# 5. done
# ---------------------------------------------------------------------------
DOMAIN="$(grep -E '^DDNS_DOMAIN=' "$ENV_FILE" | head -1 | cut -d= -f2)"
BASE_URL="$(grep -E '^DDNS_BASE_URL=' "$ENV_FILE" | head -1 | cut -d= -f2)"
cat <<EOF

Tunello is up.

    dashboard:   $BASE_URL/setup   (first run)
    afterwards:  $BASE_URL/        (login)

  secure it (https://$DOMAIN/settings):
    - Security → enable TOTP 2FA
    - Security → dashboard IP allowlist (add your IPs/CIDRs)
    - Alerts  → webhook URL + secret (events are HMAC-signed)

  logs:    docker compose -f $SRC/deploy/docker-compose.yml logs -f broker
    update:  ./deploy.sh --update
  backup:  docker compose -f $SRC/deploy/docker-compose.yml stop \
           && docker run --rm -v ddns_broker-data:/data -v \$PWD:/backup \
              alpine tar czf /backup/ddns-data-\$(date +%F).tar.gz -C /data . \
           && docker compose -f $SRC/deploy/docker-compose.yml start
EOF
