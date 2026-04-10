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
  agent_input_fd=3
  mount_paths=("$home_dir/.kube")
  FILE_SNITCH_PROMPT_TIMEOUT_MS=250 start_file_snitch_agent --daemon
  FILE_SNITCH_PROMPT_TIMEOUT_MS=250 start_file_snitch_run prompt --daemon
}

wait_for_policy_allow_rule() {
  local attempts="${1:-50}"

  for _ in $(seq 1 "$attempts"); do
    if grep -F "approval_class: 'read_like'" "$policy_file" >/dev/null 2>&1 &&
      grep -F "outcome: 'allow'" "$policy_file" >/dev/null 2>&1; then
      return
    fi
    sleep 0.1
  done

  fail "expected remembered allow rule to be written to policy"
}

wait_for_stable_read_without_prompt() {
  local target_path="$1"
  local attempts="${2:-50}"
  local prompt_count_before="$3"

  for _ in $(seq 1 "$attempts"); do
    if [[ "$(cat "$target_path" 2>/dev/null || true)" == "guarded seeded kube" ]]; then
      local prompt_count_after_first_read=0
      prompt_count_after_first_read="$(grep -c '"action":"prompt","path":"open O_RDONLY /config"' "$log_file" || true)"
      if [[ "$prompt_count_after_first_read" == "$prompt_count_before" ]] &&
        [[ "$(cat "$target_path" 2>/dev/null || true)" == "guarded seeded kube" ]]; then
        local prompt_count_after_second_read=0
        prompt_count_after_second_read="$(grep -c '"action":"prompt","path":"open O_RDONLY /config"' "$log_file" || true)"
        if [[ "$prompt_count_after_second_read" == "$prompt_count_before" ]]; then
          return
        fi
      fi
    fi
    sleep 0.1
  done

  fail "expected remembered allow rule to permit repeated reads without prompting"
}

verify_durable_allow_read() {
  prepare_run_fixture "run-prompt-remembered-allow-read"
  mkdir -p "$home_dir/.kube"
  printf 'seeded kube\n' >"$home_dir/.kube/config"
  capture_file_snitch enroll "$home_dir/.kube/config" >/dev/null
  guarded_store_write_for "$home_dir/.kube/config" 'guarded seeded kube
'

  trap cleanup EXIT
  start_prompt_run
  printf 'a\n' >&3
  platform_prime_guarded_path "$home_dir/.kube/config"

  assert_eq \
    "$(cat "$home_dir/.kube/config")" \
    "guarded seeded kube" \
    "expected durable allow to permit the first read"

  wait_for_policy_allow_rule

  local prompt_count_before=0
  prompt_count_before="$(grep -c '"action":"prompt","path":"open O_RDONLY /config"' "$log_file" || true)"
  wait_for_stable_read_without_prompt "$home_dir/.kube/config" 50 "$prompt_count_before"

  cleanup_run_fixture
  trap - EXIT
}

verify_durable_allow_read
