#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"

source "$repo_root/tests/smoke/lib/assertions.sh"
source "$repo_root/tests/smoke/lib/run-fixture.sh"

case "$(uname -s)" in
  Darwin) source "$repo_root/tests/smoke/lib/platform-Darwin.sh" ;;
  Linux) source "$repo_root/tests/smoke/lib/platform-Linux.sh" ;;
  *)
    echo "unsupported platform: $(uname -s)" >&2
    exit 1
    ;;
esac

fixture_cleanup_extra() {
  unset FILE_SNITCH_OSASCRIPT_BIN || true
}

queue_fake_macos_ui_decisions() {
  local queue_path="$1"
  shift
  : >"$queue_path"
  local response=""
  for response in "$@"; do
    printf '%s\n' "$response" >>"$queue_path"
  done
}

start_macos_ui_prompt_run() {
  mount_paths=("$home_dir/.kube")
  agent_frontend_args=(--frontend macos-ui)
  FILE_SNITCH_PROMPT_TIMEOUT_MS=2000 start_file_snitch_agent
  FILE_SNITCH_PROMPT_TIMEOUT_MS=2000 start_file_snitch_run prompt
}

verify_allow_read() {
  prepare_run_fixture "run-prompt-macos-ui-allow-read"
  write_fake_osascript_script
  export FILE_SNITCH_OSASCRIPT_BIN="$fake_bin_dir/osascript"
  mkdir -p "$home_dir/.kube"
  printf 'seeded kube\n' >"$home_dir/.kube/config"
  capture_file_snitch enroll "$home_dir/.kube/config" >/dev/null
  guarded_store_write_for "$home_dir/.kube/config" 'guarded seeded kube
'

  trap cleanup_run_fixture EXIT
  queue_fake_macos_ui_decisions "$fake_ui_queue_file" allow
  start_macos_ui_prompt_run
  platform_prime_guarded_path "$home_dir/.kube/config"

  assert_eq \
    "$(cat "$home_dir/.kube/config")" \
    "guarded seeded kube" \
    "expected macos-ui allow to permit a read of the enrolled file"
  assert_log_contains '"action":"prompt","path":"open O_RDONLY /config","result":1'

  cleanup_run_fixture
  trap - EXIT
}

verify_deny_write() {
  prepare_run_fixture "run-prompt-macos-ui-deny-write"
  write_fake_osascript_script
  export FILE_SNITCH_OSASCRIPT_BIN="$fake_bin_dir/osascript"
  mkdir -p "$home_dir/.kube"
  printf 'seeded kube\n' >"$home_dir/.kube/config"
  capture_file_snitch enroll "$home_dir/.kube/config" >/dev/null

  trap cleanup_run_fixture EXIT
  queue_fake_macos_ui_decisions "$fake_ui_queue_file" deny
  start_macos_ui_prompt_run
  platform_prime_guarded_path "$home_dir/.kube/config"

  if bash -c 'printf "denied write\n" >"$1"' _ "$home_dir/.kube/config" >/dev/null 2>&1; then
    fail "expected macos-ui deny to block a write"
  fi
  assert_log_matches '"action":"prompt","path":"open O_WRONLY(\|O_TRUNC)? /config","result":2'

  cleanup_run_fixture
  trap - EXIT
}

verify_timeout_write() {
  prepare_run_fixture "run-prompt-macos-ui-timeout-write"
  write_fake_osascript_script
  export FILE_SNITCH_OSASCRIPT_BIN="$fake_bin_dir/osascript"
  mkdir -p "$home_dir/.kube"
  printf 'seeded kube\n' >"$home_dir/.kube/config"
  capture_file_snitch enroll "$home_dir/.kube/config" >/dev/null

  trap cleanup_run_fixture EXIT
  queue_fake_macos_ui_decisions "$fake_ui_queue_file" timeout
  start_macos_ui_prompt_run
  platform_prime_guarded_path "$home_dir/.kube/config"

  if bash -c 'printf "timed out write\n" >"$1"' _ "$home_dir/.kube/config" >/dev/null 2>&1; then
    fail "expected macos-ui timeout to block a write"
  fi
  assert_log_matches '"action":"prompt","path":"open O_WRONLY(\|O_TRUNC)? /config","result":3'

  cleanup_run_fixture
  trap - EXIT
}

verify_allow_read
verify_deny_write
verify_timeout_write
