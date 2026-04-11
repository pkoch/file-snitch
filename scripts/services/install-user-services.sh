#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"

platform=""
bin_path="file-snitch"

usage() {
  cat <<'EOF'
usage:
  ./scripts/services/install-user-services.sh [--platform <macos|linux>] [--bin <path>]

notes:
  - macOS installs and starts both the `agent` and `run` LaunchAgents
  - Linux installs and starts both `file-snitch-agent.service` and
    `file-snitch-run.service`
EOF
}

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

detect_platform() {
  case "$(uname -s)" in
    Darwin) printf 'macos\n' ;;
    Linux) printf 'linux\n' ;;
    *) fail "unsupported platform: $(uname -s)" ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform)
      shift
      [[ $# -gt 0 ]] || fail "missing value for --platform"
      platform="$1"
      ;;
    --bin)
      shift
      [[ $# -gt 0 ]] || fail "missing value for --bin"
      bin_path="$1"
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      fail "unsupported argument: $1"
      ;;
  esac
  shift
done

if [[ -z "$platform" ]]; then
  platform="$(detect_platform)"
fi

case "$platform" in
  macos)
    command -v launchctl >/dev/null 2>&1 || fail "launchctl is required on macOS"
    launch_agents_dir="$HOME/Library/LaunchAgents"
    mkdir -p "$launch_agents_dir"

    temp_dir="$(mktemp -d)"
    trap 'rm -rf "$temp_dir"' EXIT

    "$repo_root/scripts/services/render-user-services.sh" \
      --platform macos \
      --bin "$bin_path" \
      --output-dir "$temp_dir"

    cp "$temp_dir/dev.file-snitch.agent.plist" "$launch_agents_dir/"
    cp "$temp_dir/dev.file-snitch.run.plist" "$launch_agents_dir/"

    uid="$(id -u)"
    for label in dev.file-snitch.agent dev.file-snitch.run; do
      launchctl bootout "gui/$uid/$label" >/dev/null 2>&1 || true
    done

    launchctl bootstrap "gui/$uid" "$launch_agents_dir/dev.file-snitch.agent.plist"
    launchctl enable "gui/$uid/dev.file-snitch.agent"
    launchctl kickstart -k "gui/$uid/dev.file-snitch.agent"

    launchctl bootstrap "gui/$uid" "$launch_agents_dir/dev.file-snitch.run.plist"
    launchctl enable "gui/$uid/dev.file-snitch.run"
    launchctl kickstart -k "gui/$uid/dev.file-snitch.run"
    ;;
  linux)
    command -v systemctl >/dev/null 2>&1 || fail "systemctl is required on Linux"
    command -v zenity >/dev/null 2>&1 || fail "zenity is required for the linux-ui agent frontend"
    unit_dir="$HOME/.config/systemd/user"
    mkdir -p "$unit_dir"

    temp_dir="$(mktemp -d)"
    trap 'rm -rf "$temp_dir"' EXIT

    "$repo_root/scripts/services/render-user-services.sh" \
      --platform linux \
      --bin "$bin_path" \
      --output-dir "$temp_dir"

    cp "$temp_dir/file-snitch-agent.service" "$unit_dir/"
    cp "$temp_dir/file-snitch-run.service" "$unit_dir/"

    systemctl --user daemon-reload
    systemctl --user enable --now file-snitch-agent.service
    systemctl --user enable --now file-snitch-run.service
    ;;
  *)
    fail "unsupported platform: $platform"
    ;;
esac
