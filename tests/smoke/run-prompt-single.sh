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

prompt_fifo=""

fixture_cleanup_extra() {
  exec 3>&- || true
  [[ -n "$prompt_fifo" ]] && rm -f "$prompt_fifo"
  prompt_fifo=""
}

cleanup() {
  cleanup_run_fixture
}

start_prompt_run() {
  prompt_fifo="$(mktemp -u "$TMP_ROOT/file-snitch.prompt-fifo.XXXXXX")"
  mkfifo "$prompt_fifo"
  exec 3<>"$prompt_fifo"
  run_input_fd=3
  mount_paths=("$home_dir/.kube")
  FILE_SNITCH_PROMPT_TIMEOUT_MS=200 start_file_snitch_run prompt
}

queue_prompt_answers() {
  local answer="$1"
  local count="$2"
  local i=""

  for i in $(seq 1 "$count"); do
    printf '%s\n' "$answer" >&3
  done
}

verify_allow_read() {
  prepare_run_fixture "run-prompt-allow-read"
  mkdir -p "$home_dir/.kube"
  printf 'seeded kube\n' >"$home_dir/.kube/config"
  capture_file_snitch enroll "$home_dir/.kube/config" >/dev/null
  object_path="$(guarded_object_path_for "$home_dir/.kube/config")"
  printf 'guarded seeded kube\n' >"$object_path"

  trap cleanup EXIT
  start_prompt_run
  queue_prompt_answers yes 8

  assert_eq \
    "$(cat "$home_dir/.kube/config")" \
    "guarded seeded kube" \
    "expected prompt allow to permit a read of the enrolled file"
  assert_log_contains '"action":"prompt","path":"open O_RDONLY /config","result":1'

  cleanup_run_fixture
  trap - EXIT
}

verify_deny_write() {
  prepare_run_fixture "run-prompt-deny-write"
  mkdir -p "$home_dir/.kube"
  printf 'seeded kube\n' >"$home_dir/.kube/config"
  capture_file_snitch enroll "$home_dir/.kube/config" >/dev/null

  trap cleanup EXIT
  start_prompt_run
  queue_prompt_answers no 8

  if bash -c 'printf "denied write\n" >"$1"' _ "$home_dir/.kube/config" >/dev/null 2>&1; then
    fail "expected prompt deny to block a write"
  fi
  assert_log_contains '"action":"prompt","path":"open O_WRONLY /config","result":2'

  cleanup_run_fixture
  trap - EXIT
}

verify_timeout_write() {
  prepare_run_fixture "run-prompt-timeout-write"
  mkdir -p "$home_dir/.kube"
  printf 'seeded kube\n' >"$home_dir/.kube/config"
  capture_file_snitch enroll "$home_dir/.kube/config" >/dev/null

  trap cleanup EXIT
  start_prompt_run

  if bash -c 'printf "timed out write\n" >"$1"' _ "$home_dir/.kube/config" >/dev/null 2>&1; then
    fail "expected prompt timeout to block a write"
  fi
  assert_log_contains '"action":"prompt","path":"open O_WRONLY /config","result":3'

  cleanup_run_fixture
  trap - EXIT
}

verify_allow_read
verify_deny_write
verify_timeout_write
