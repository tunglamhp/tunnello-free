#!/usr/bin/env bash
# Tunello — one-line VPS installer.
#
# Usage (from any fresh Ubuntu VPS, as root):
#   curl -sSL https://raw.githubusercontent.com/tunglamhp/tunnello-free/main/install-server.sh | bash
#
# What it does:
#   1. Clones the repo to /opt/tunnello
#   2. Runs deploy/deploy.sh which auto-installs Docker (if missing) and
#      starts the broker stack via Docker Compose.
#   3. Prints the URL to open for /setup.
#
# Override defaults via env vars (e.g. DDNS_DOMAIN, DDNS_ACME_EMAIL, DDNS_REPO_URL).
set -euo pipefail

REPO_URL="${DDNS_REPO_URL:-https://github.com/tunglamhp/tunnello-free.git}"
BRANCH="${DDNS_BRANCH:-main}"
INSTALL_DIR="${DDNS_INSTALL_DIR:-/opt/tunnello}"

if [ "$(id -u)" -ne 0 ]; then
    echo "error: please run as root (sudo bash …)" >&2
    exit 1
fi

# Need git to clone; if missing, install it.
if ! command -v git >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq git
fi

if [ ! -d "$INSTALL_DIR" ]; then
    echo "Cloning $REPO_URL -> $INSTALL_DIR"
    git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
else
    echo "Reusing existing $INSTALL_DIR (run deploy.sh --update to upgrade)"
fi

cd "$INSTALL_DIR/deploy"
exec bash deploy.sh
