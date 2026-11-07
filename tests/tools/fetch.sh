#!/usr/bin/env bash
# Shared release pin and file digests: third_party/gvisor/manifest.json.
# Used by make tools (external-runtime tests) and make build (embedding).
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
exec python3 "$root/scripts/fetch-gvisor.py"
