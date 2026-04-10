#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"

version=""
platform=""
output=""
source_date_epoch=""
target_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      version="$2"
      shift 2
      ;;
    --platform)
      platform="$2"
      shift 2
      ;;
    --output)
      output="$2"
      shift 2
      ;;
    --source-date-epoch)
      source_date_epoch="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

[[ -n "$version" ]] || { echo "--version is required" >&2; exit 1; }
[[ -n "$platform" ]] || { echo "--platform is required" >&2; exit 1; }
[[ -n "$output" ]] || { echo "--output is required" >&2; exit 1; }
[[ -n "$source_date_epoch" ]] || { echo "--source-date-epoch is required" >&2; exit 1; }

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/file-snitch-release-build.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

install_prefix="$tmp_dir/install"
cache_dir="$tmp_dir/.zig-cache"
global_cache_dir="$tmp_dir/.zig-global-cache"

mkdir -p "$install_prefix"

if [[ -n "${ZIG_BUILD_TARGET:-}" ]]; then
  target_args=(-Dtarget="$ZIG_BUILD_TARGET")
fi

sdkroot_args=()
if [[ "$(uname -s)" == "Darwin" && -z "${SDKROOT:-}" ]] && command -v xcrun >/dev/null 2>&1; then
  sdkroot_args=("SDKROOT=$(xcrun --sdk macosx --show-sdk-path)")
fi

cd "$repo_root"
env \
  "${sdkroot_args[@]}" \
  SOURCE_DATE_EPOCH="$source_date_epoch" \
  ZERO_AR_DATE=1 \
  TZ=UTC \
  LC_ALL=C \
  zig build -Doptimize=ReleaseSafe \
    "${target_args[@]}" \
    --prefix "$install_prefix" \
    --cache-dir "$cache_dir" \
    --global-cache-dir "$global_cache_dir"

case "$(uname -s)" in
  Darwin)
    strip -no_uuid "$install_prefix/bin/file-snitch"
    ;;
  Linux)
    strip --strip-debug "$install_prefix/bin/file-snitch"
    ;;
esac

version_command=("$install_prefix/bin/file-snitch" version)
if [[ "$(uname -s)" == "Darwin" && -n "${FILE_SNITCH_FUSE_LIB_DIR:-}" ]]; then
  DYLD_LIBRARY_PATH="$FILE_SNITCH_FUSE_LIB_DIR" "${version_command[@]}" | grep -Fx "file-snitch $version" >/dev/null
else
  "${version_command[@]}" | grep -Fx "file-snitch $version" >/dev/null
fi

python3 "$repo_root/scripts/package-release-artifact.py" \
  --version "$version" \
  --platform "$platform" \
  --binary "$install_prefix/bin/file-snitch" \
  --output "$output"
