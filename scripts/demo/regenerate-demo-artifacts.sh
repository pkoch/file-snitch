#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
assets_dir="$repo_root/docs/assets"
cast_path="$assets_dir/demo.cast"
gif_path="$assets_dir/demo.gif"

for tool in zig asciinema agg; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool: $tool" >&2
    exit 1
  fi
done

mkdir -p "$assets_dir"

cd "$repo_root"

zig build

asciinema rec \
  --overwrite \
  --headless \
  --idle-time-limit 1.0 \
  --window-size 100x32 \
  --command "./scripts/demo/demo-session.sh" \
  "$cast_path"

agg \
  --theme github-dark \
  --font-size 16 \
  --speed 1.2 \
  --idle-time-limit 1.0 \
  "$cast_path" \
  "$gif_path"

printf 'wrote %s\n' "$cast_path"
printf 'wrote %s\n' "$gif_path"
