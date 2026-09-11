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
INSTALL_DIR="${DDNS_INSTALL_DIR:-/opt/tunnello}"

if [ "$(id -u)" -ne 0 ]; then
    echo "error: please run as root (sudo bash …)" >&2
    exit 1
fi

# Need git to clone; if missing, install it.
if ! command -v git >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq git
fi

# Resolve the branch to clone. This repository defaults to `main`, but forks and
# mirrors (for example tunglamhp/tunnello) use `master`, so ask the remote
# instead of assuming: `git ls-remote --symref <url> HEAD` reports the default
# branch. Probing also makes a typo in DDNS_REPO_URL fail here with a clear
# message rather than inside `deploy.sh`.
resolve_branch() {
    local want="${DDNS_BRANCH:-}" found=""

    found="$(git ls-remote --symref "$REPO_URL" HEAD 2>/dev/null \
        | awk '/^ref:/ {sub("refs/heads/", "", $2); print $2; exit}')"

    if [ -n "$want" ]; then
        if ! git ls-remote --exit-code --heads "$REPO_URL" "$want" >/dev/null 2>&1; then
            echo "error: branch '$want' does not exist in $REPO_URL" >&2
            echo "       available: $(git ls-remote --heads "$REPO_URL" 2>/dev/null | awk '{sub("refs/heads/", "", $2); printf "%s ", $2}')" >&2
            exit 1
        fi
        printf '%s' "$want"
        return
    fi

    if [ -n "$found" ]; then
        printf '%s' "$found"
        return
    fi

    # Remote reachable but no symbolic HEAD (older servers, shallow mirrors):
    # fall back to the conventional names.
    for cand in main master; do
        if git ls-remote --exit-code --heads "$REPO_URL" "$cand" >/dev/null 2>&1; then
            printf '%s' "$cand"
            return
        fi
    done

    echo "error: cannot determine the default branch of $REPO_URL" >&2
    echo "       set DDNS_BRANCH explicitly and retry" >&2
    exit 1
}

BRANCH="$(resolve_branch)"
echo "Using branch '$BRANCH' from $REPO_URL"

if [ ! -d "$INSTALL_DIR/.git" ]; then
    echo "Cloning $REPO_URL -> $INSTALL_DIR"
    git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
else
    echo "Reusing existing $INSTALL_DIR (run deploy.sh --update to upgrade)"
fi

cd "$INSTALL_DIR/deploy"
exec bash deploy.sh
