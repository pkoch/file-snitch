#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

command -v python3 >/dev/null 2>&1 || fail "missing required tool: python3"

cd "$repo_root"

exec python3 scripts/docs/check-docs.py "$@"
