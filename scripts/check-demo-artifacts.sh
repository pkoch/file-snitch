#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cast_path="$repo_root/docs/assets/demo.cast"
gif_path="$repo_root/docs/assets/demo.gif"

for path in "$cast_path" "$gif_path"; do
  [[ -f "$path" ]] || {
    echo "missing demo artifact: $path" >&2
    exit 1
  }
done

if ! command -v strings >/dev/null 2>&1; then
  echo "missing required tool: strings" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cast_scan="$tmpdir/demo.cast.txt"
gif_scan="$tmpdir/demo.gif.txt"

cp "$cast_path" "$cast_scan"
strings "$gif_path" >"$gif_scan"

patterns=(
  "BEGIN OPENSSH PRIVATE KEY"
  "BEGIN PGP PRIVATE KEY"
  "BEGIN RSA PRIVATE KEY"
  "BEGIN EC PRIVATE KEY"
  "private-keys-v1.d"
  ".gnupg"
  "id_ed25519"
  "/Users/pkoch"
  "/var/home/pkoch"
)

for scan_path in "$cast_scan" "$gif_scan"; do
  for pattern in "${patterns[@]}"; do
    if grep -F "$pattern" "$scan_path" >/dev/null 2>&1; then
      echo "demo artifact leakage check failed: found '$pattern' in $scan_path" >&2
      exit 1
    fi
  done
done

echo "demo artifact redaction checks passed"
