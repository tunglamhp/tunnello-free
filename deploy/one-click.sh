#!/usr/bin/env bash
# Tunello one-click launcher. Run this file from the uploaded deploy folder.
set -euo pipefail
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/deploy.sh" "$@"