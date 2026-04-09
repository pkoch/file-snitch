#!/usr/bin/env bash
set -euo pipefail

platform=""

usage() {
  cat <<'EOF'
usage:
  ./scripts/uninstall-user-services.sh [--platform <macos|linux>]
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
    uid="$(id -u)"

    for label in dev.file-snitch.run dev.file-snitch.agent; do
      launchctl bootout "gui/$uid/$label" >/dev/null 2>&1 || true
      rm -f "$launch_agents_dir/$label.plist"
    done
    ;;
  linux)
    command -v systemctl >/dev/null 2>&1 || fail "systemctl is required on Linux"
    unit_dir="$HOME/.config/systemd/user"

    systemctl --user disable --now file-snitch-agent.service >/dev/null 2>&1 || true
    systemctl --user disable --now file-snitch-run.service >/dev/null 2>&1 || true
    rm -f "$unit_dir/file-snitch-agent.service"
    rm -f "$unit_dir/file-snitch-run.service"
    systemctl --user daemon-reload
    ;;
  *)
    fail "unsupported platform: $platform"
    ;;
esac
