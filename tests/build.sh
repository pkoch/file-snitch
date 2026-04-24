#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
target_args=()

if [[ -n "${ZIG_BUILD_TARGET:-}" ]]; then
  target_args=(-Dtarget="$ZIG_BUILD_TARGET")
fi

cd "$repo_root"

echo "==> zig build"
zig build "${target_args[@]}"

echo "==> zig build test"
zig build test "${target_args[@]}"

echo "==> zig build compile-commands"
zig build compile-commands "${target_args[@]}"

echo "==> release source tarball sanity"
release_check_dir="$(mktemp -d "${TMPDIR:-/tmp}/file-snitch-release-source-check.XXXXXX")"
trap 'rm -rf "$release_check_dir"' EXIT
python3 ./scripts/release/build-release-source-tarball.py \
  --version "$(cat VERSION)" \
  --output "$release_check_dir/source.tar.gz"
tar -tzf "$release_check_dir/source.tar.gz" | grep -Fx "file-snitch-$(cat VERSION)/scripts/release/build-release-artifact.sh" >/dev/null
tar -tzf "$release_check_dir/source.tar.gz" | grep -Fx "file-snitch-$(cat VERSION)/scripts/vendor/extract-macfuse-sdk.sh" >/dev/null
rm -rf "$release_check_dir"
trap - EXIT
