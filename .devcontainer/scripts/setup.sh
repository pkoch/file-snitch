#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"

log() {
  printf '==> %s\n' "$1"
}

fail() {
  printf 'devcontainer setup: %s\n' "$1" >&2
  exit 1
}

run_as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    fail "need root privileges for package installation; install sudo or run as root"
  fi
}

install_linux_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    log "installing apt packages"
    run_as_root apt-get update
    run_as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      fuse3 \
      git \
      gnupg \
      libfuse3-dev \
      pass \
      pkg-config \
      python3 \
      sudo \
      xz-utils \
    ;
  else
    fail "unsupported Linux distro; install curl git pkg-config fuse3 libfuse3-dev gnupg pass python3 and Zig manually"
  fi
}

minimum_zig_version() {
  local zon_file="${repo_root}/build.zig.zon"
  [[ -f "$zon_file" ]] || fail "missing build.zig.zon at ${zon_file}; run this script from its repo-relative .devcontainer/scripts path"
  awk -F'"' '/\.minimum_zig_version[[:space:]]*=/ { print $2; exit }' "$zon_file"
}

zig_archive_name() {
  local machine
  machine="$(uname -m)"

  case "$(uname -s)-${machine}" in
    Linux-x86_64)
      printf 'x86_64-linux\n'
      ;;
    Linux-aarch64 | Linux-arm64)
      printf 'aarch64-linux\n'
      ;;
    *)
      return 1
      ;;
  esac
}

install_zig() {
  local min_zig
  min_zig="$(minimum_zig_version)"
  [[ -n "$min_zig" ]] || fail "could not read minimum_zig_version from build.zig.zon"

  if command -v zig >/dev/null 2>&1; then
    local current_zig
    current_zig="$(zig version 2>/dev/null || true)"
    if [[ "$current_zig" == "$min_zig" ]]; then
      log "zig ${current_zig} already matches build.zig.zon at $(command -v zig)"
      return
    fi
    log "zig ${current_zig:-unknown} does not match build.zig.zon minimum ${min_zig}; installing Zig"
  fi

  local archive_base archive_dir platform tmp_dir url
  platform="$(zig_archive_name)" || fail "unsupported host for automatic Zig install: $(uname -s)-$(uname -m)"
  archive_base="zig-${platform}-${min_zig}"
  archive_dir="/opt/zig/${min_zig}"
  tmp_dir="$(mktemp -d)"
  url="https://ziglang.org/download/${min_zig}/${archive_base}.tar.xz"

  log "installing Zig ${min_zig} from ${url}"
  curl -fsSL "$url" -o "${tmp_dir}/${archive_base}.tar.xz"
  tar -xJf "${tmp_dir}/${archive_base}.tar.xz" -C "$tmp_dir"
  run_as_root mkdir -p /opt/zig
  run_as_root rm -rf "$archive_dir"
  run_as_root mv "${tmp_dir}/${archive_base}" "$archive_dir"
  run_as_root ln -sf "${archive_dir}/zig" /usr/local/bin/zig
  rm -rf "$tmp_dir"

  local installed_zig
  installed_zig="$(zig version 2>/dev/null || true)"
  [[ "$installed_zig" == "$min_zig" ]] || fail "zig version is ${installed_zig:-unavailable}; expected ${min_zig} from build.zig.zon"
}

require_tool() {
  local name="$1"
  command -v "$name" >/dev/null 2>&1 || fail "missing required tool after setup: ${name}"
}

print_version() {
  local label="$1"
  shift
  log "$label"
  "$@" | sed -n '1p'
}

cd "$repo_root"

case "$(uname -s)" in
  Linux)
    if [[ "${1:-}" != "--skip-packages" ]]; then
      install_linux_packages
    fi
    ;;
  *)
    fail "setup currently supports Linux hosts only"
    ;;
esac

install_zig

require_tool curl
require_tool git
require_tool gpg
require_tool pass
require_tool pkg-config
require_tool python3
require_tool fusermount3
require_tool zig

print_version "zig version" zig version 2>/dev/null
print_version "gpg version" gpg --version
print_version "pass version" pass --version
print_version "pkg-config version" pkg-config --version
print_version "python3 version" python3 --version
print_version "fuse3 pkg-config version" pkg-config --modversion fuse3
print_version "fusermount3 version" fusermount3 --version
