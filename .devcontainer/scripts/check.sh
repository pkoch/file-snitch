#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"

log() {
  printf '==> %s\n' "$1"
}

fail() {
  printf 'devcontainer check: %s\n' "$1" >&2
  exit 1
}

require_tool() {
  local name="$1"
  command -v "$name" >/dev/null 2>&1 || fail "missing required tool: ${name}"
}

minimum_zig_version() {
  local zon_file="${repo_root}/build.zig.zon"
  [[ -f "$zon_file" ]] || fail "missing build.zig.zon at ${zon_file}; run this script from its repo-relative .devcontainer/scripts path"
  awk -F'"' '/\.minimum_zig_version[[:space:]]*=/ { print $2; exit }' "$zon_file"
}

target_args=()
if [[ -n "${ZIG_BUILD_TARGET:-}" ]]; then
  target_args=(-Dtarget="$ZIG_BUILD_TARGET")
fi

cd "$repo_root"

min_zig="$(minimum_zig_version)"
if [[ -z "$min_zig" ]]; then
  fail "could not read minimum_zig_version from build.zig.zon"
fi

log "minimum_zig_version: ${min_zig}"

require_tool zig
require_tool gpg
require_tool pass
require_tool pkg-config
require_tool python3
require_tool fusermount3

log "tool versions"
zig_version="$(zig version)"
if [[ "$zig_version" != "$min_zig" ]]; then
  fail "zig version is ${zig_version}; expected ${min_zig} from build.zig.zon. Rebuild the devcontainer or run ./.devcontainer/scripts/setup.sh."
fi
printf '%s\n' "$zig_version"
gpg --version | sed -n '1p'
pass --version | sed -n '1p'
pkg-config --version
python3 --version
fusermount3 --version | sed -n '1p'

log "checking fuse3 pkg-config visibility"
pkg-config --modversion fuse3 || fail "pkg-config cannot resolve fuse3; install fuse3 development headers"

log "zig build"
zig build "${target_args[@]}"

log "zig build test"
zig build test "${target_args[@]}"

log "zig build compile-commands"
zig build compile-commands "${target_args[@]}"

log "docs check"
./scripts/docs/check-docs.sh
