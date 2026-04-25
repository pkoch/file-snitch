#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"

platform=""
bin_path=""
pass_bin_path=""
output_dir=""

usage() {
  cat <<'EOF'
usage:
  ./scripts/services/render-user-services.sh [--platform <macos|linux>] --bin <path> [--pass-bin <path>] --output-dir <dir>

notes:
  - macOS renders both `dev.file-snitch.agent.plist` and `dev.file-snitch.run.plist`
  - Linux renders both `file-snitch-agent.service` and `file-snitch-run.service`
  - the binary path is embedded directly into the rendered files
  - the pass binary path is embedded into the run service; defaults to FILE_SNITCH_PASS_BIN or `command -v pass`
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

resolve_bin_path() {
  local raw_path="$1"
  local label="${2:-binary}"
  if [[ "$raw_path" = /* ]]; then
    [[ -x "$raw_path" ]] || fail "$label is not executable: $raw_path"
    printf '%s\n' "$raw_path"
    return
  fi

  local resolved=""
  resolved="$(command -v "$raw_path" || true)"
  [[ -n "$resolved" ]] || fail "could not resolve binary: $raw_path"
  [[ -x "$resolved" ]] || fail "$label is not executable: $resolved"
  printf '%s\n' "$resolved"
}

render_template() {
  local template_path="$1"
  local destination_path="$2"
  local log_dir="$3"
  local resolved_bin_path="$4"
  local resolved_pass_bin_path="$5"

  python3 - "$template_path" "$destination_path" "$log_dir" "$resolved_bin_path" "$resolved_pass_bin_path" <<'PY'
import pathlib
import sys

template_path = pathlib.Path(sys.argv[1])
destination_path = pathlib.Path(sys.argv[2])
log_dir = sys.argv[3]
binary_path = sys.argv[4]
pass_binary_path = sys.argv[5]

rendered = template_path.read_text(encoding="utf-8")
rendered = rendered.replace("{{LOG_DIR}}", log_dir)
rendered = rendered.replace("{{FILE_SNITCH_BIN}}", binary_path)
rendered = rendered.replace("{{PASS_BIN}}", pass_binary_path)
destination_path.write_text(rendered, encoding="utf-8")
PY
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
    --pass-bin)
      shift
      [[ $# -gt 0 ]] || fail "missing value for --pass-bin"
      pass_bin_path="$1"
      ;;
    --output-dir)
      shift
      [[ $# -gt 0 ]] || fail "missing value for --output-dir"
      output_dir="$1"
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

[[ -n "$output_dir" ]] || fail "--output-dir is required"
[[ -n "$bin_path" ]] || fail "--bin is required"

if [[ -z "$platform" ]]; then
  platform="$(detect_platform)"
fi

case "$platform" in
  macos|linux) ;;
  *) fail "unsupported platform: $platform" ;;
esac

resolved_bin_path="$(resolve_bin_path "$bin_path")"
if [[ -z "$pass_bin_path" ]]; then
  pass_bin_path="${FILE_SNITCH_PASS_BIN:-pass}"
fi
resolved_pass_bin_path="$(resolve_bin_path "$pass_bin_path" "pass binary")"
log_dir="$HOME/.local/state/file-snitch/log"

mkdir -p "$output_dir" "$log_dir"

case "$platform" in
  macos)
    render_template \
      "$repo_root/packaging/launchd/dev.file-snitch.agent.plist.in" \
      "$output_dir/dev.file-snitch.agent.plist" \
      "$log_dir" \
      "$resolved_bin_path" \
      "$resolved_pass_bin_path"
    render_template \
      "$repo_root/packaging/launchd/dev.file-snitch.run.plist.in" \
      "$output_dir/dev.file-snitch.run.plist" \
      "$log_dir" \
      "$resolved_bin_path" \
      "$resolved_pass_bin_path"
    ;;
  linux)
    render_template \
      "$repo_root/packaging/systemd/file-snitch-agent.service.in" \
      "$output_dir/file-snitch-agent.service" \
      "$log_dir" \
      "$resolved_bin_path" \
      "$resolved_pass_bin_path"
    render_template \
      "$repo_root/packaging/systemd/file-snitch-run.service.in" \
      "$output_dir/file-snitch-run.service" \
      "$log_dir" \
      "$resolved_bin_path" \
      "$resolved_pass_bin_path"
    ;;
esac
