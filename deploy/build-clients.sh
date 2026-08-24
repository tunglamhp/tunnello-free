#!/usr/bin/env bash
# build-clients.sh — cross-compile the ddns client for Linux / macOS / Windows
# (x86_64 + arm64) and copy the binaries into the broker's download directory.
#
# Usage:
#   ./deploy/build-clients.sh [OUTPUT_DIR]      # default: deploy/downloads/
#
# The broker serves whatever is in its download dir (/data/downloads in the
# container, seeded with a Linux x86_64 musl build on first boot). Upload the
# produced binaries into that volume (or bind-mount deploy/downloads) and the
# /downloads page will list them as ready.
#
# Requirements per target (only the targets whose toolchains exist are built):
#   Linux  x86_64/arm64 musl  → rustup target add x86_64-unknown-linux-musl \
#                               aarch64-unknown-linux-musl   (+ musl-tools)
#   macOS  x86_64/arm64       → osxcross (CC=o64-clang / CC=aarch64-apple-darwin-clang)
#   Windows x86_64            → rustup target add x86_64-pc-windows-gnu (+ mingw)
#   Windows arm64             → rustup target add aarch64-pc-windows-msvc (msvc cross)
# Missing toolchains are skipped with a note — the script never fails the whole
# run because one target is unavailable.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$(dirname "${BASH_SOURCE[0]}")/downloads}"
mkdir -p "$OUT"

build() {
    local target="$1" label="$2"
    if ! rustup target list --installed 2>/dev/null | grep -q "^${target}$"; then
        echo "skip ${label} (target ${target} not installed — rustup target add ${target})"
        return
    fi
    echo "building ${label} (${target}) …"
    (cd "$ROOT" && cargo build --release --target "$target" -p ddns-client)
    local triple
    case "$target" in
        *-windows-*) triple="${target}.exe" ;;
        *) triple="${target}" ;;
    esac
    cp "$ROOT/target/${target}/release/ddns${triple##*ddns}" "$OUT/ddns-${triple}" 2>/dev/null \
        || cp "$ROOT/target/${target}/release/ddns"* "$OUT/"
    echo "  -> $OUT/ddns-${triple}"
}

echo "output dir: $OUT"
build x86_64-unknown-linux-musl "Linux x86_64"
build aarch64-unknown-linux-musl "Linux arm64"
build x86_64-apple-darwin "macOS x86_64"
build aarch64-apple-darwin "macOS arm64"
build x86_64-pc-windows-gnu "Windows x86_64"
build aarch64-pc-windows-msvc "Windows arm64"

echo
echo "done. Copy these files into the broker's download dir to serve them:"
ls -la "$OUT"
echo "  e.g. docker cp ${OUT}/. deploy-broker-1:/data/downloads/"
