#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cache_dir="${ZIG_CACHE_DIR:-$repo_root/.zig-cache}"
global_cache_dir="${ZIG_GLOBAL_CACHE_DIR:-/tmp/file-snitch-zig-global-cache}"
target_args=()

if [[ -n "${ZIG_BUILD_TARGET:-}" ]]; then
  target_args=(-Dtarget="$ZIG_BUILD_TARGET")
fi

cd "$repo_root"

echo "==> zig build"
zig build \
  "${target_args[@]}" \
  --cache-dir "$cache_dir" \
  --global-cache-dir "$global_cache_dir"

echo "==> zig build test"
zig build test \
  "${target_args[@]}" \
  --cache-dir "$cache_dir" \
  --global-cache-dir "$global_cache_dir"

echo "==> zig build compile-commands"
zig build compile-commands \
  "${target_args[@]}" \
  --cache-dir "$cache_dir" \
  --global-cache-dir "$global_cache_dir"

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
