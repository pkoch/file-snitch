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

case "$(uname -s)" in
  Darwin)
    echo "==> zig test tests/integration.zig"
    zig test \
      -cflags -std=c11 -D_FILE_OFFSET_BITS=64 -- \
      c/libfuse_shim.c \
      -lfuse \
      -ODebug \
      -I c \
      -isystem /usr/local/include \
      -isystem /opt/homebrew/include \
      -L /usr/local/lib \
      -L /opt/homebrew/lib \
      -rpath /usr/local/lib \
      -rpath /opt/homebrew/lib \
      --dep app_src \
      -Mroot=tests/integration.zig \
      -ODebug \
      -Mapp_src=src/root.zig \
      -lc \
      --cache-dir "$cache_dir" \
      --global-cache-dir "$global_cache_dir"

    echo "==> zig test src/prompt.zig"
    zig test \
      src/prompt.zig \
      -lc \
      --cache-dir "$cache_dir" \
      --global-cache-dir "$global_cache_dir"
    ;;
  *)
    echo "==> zig build test"
    zig build test \
      "${target_args[@]}" \
      --cache-dir "$cache_dir" \
      --global-cache-dir "$global_cache_dir"
    ;;
esac

echo "==> zig build compile-commands"
zig build compile-commands \
  "${target_args[@]}" \
  --cache-dir "$cache_dir" \
  --global-cache-dir "$global_cache_dir"
