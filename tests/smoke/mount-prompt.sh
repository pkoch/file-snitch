#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
source "$repo_root/tests/smoke/lib/assertions.sh"
source "$repo_root/tests/smoke/lib/mount-fixture.sh"

case "$(uname -s)" in
  Darwin)
    source "$repo_root/tests/smoke/lib/platform-Darwin.sh"
    ;;
  *)
    echo "prompt smoke is only supported on macOS" >&2
    exit 1
    ;;
esac
prompt_fifo=""

fixture_cleanup_extra() {
  exec 3>&- || true
  [[ -n "$prompt_fifo" ]] && rm -f "$prompt_fifo"
  prompt_fifo=""
}

finish() {
  cleanup_mount_fixture
}

assert_no_xattr_prompts() {
  local message="$1"

  if grep -F '"path":"xattr ' "$log_file" >/dev/null 2>&1; then
    fail "$message"
  fi
}

assert_prompt_audit() {
  local regex="$1"
  local message="$2"

  if ! grep -E "$regex" "$log_file" >/dev/null 2>&1; then
    fail "$message"
  fi
}

assert_prompt_log() {
  local regex="$1"
  local message="$2"

  if ! grep -E "$regex" "$log_file" >/dev/null 2>&1; then
    fail "$message"
  fi
}

expect_create_denied() {
  local path="$1"
  local message="$2"

  if tee "$path" </dev/null >/dev/null 2>&1; then
    fail "$message"
  fi
}

queue_prompt_answers() {
  local answer="$1"
  local count="$2"
  local i=""

  for i in $(seq 1 "$count"); do
    printf '%s\n' "$answer" >&3
  done
}

start_prompt_mount() {
  prepare_mount_fixture "file-snitch.prompt"
  prompt_fifo="$(mktemp -u "$TMP_ROOT/file-snitch.prompt-fifo.XXXXXX")"

  mkfifo "$prompt_fifo"
  exec 3<>"$prompt_fifo"
  mount_input_fd=3
  mount_extra_args=(--status-fifo "$status_fifo")
  FILE_SNITCH_PROMPT_TIMEOUT_MS=200 start_file_snitch_mount prompt
}

start_prompt_mount_with_seed_file() {
  local seed_name="$1"
  local seed_contents="$2"

  prepare_mount_fixture "file-snitch.prompt"
  prompt_fifo="$(mktemp -u "$TMP_ROOT/file-snitch.prompt-fifo.XXXXXX")"

  printf '%s' "$seed_contents" >"$store_dir/$seed_name"

  mkfifo "$prompt_fifo"
  exec 3<>"$prompt_fifo"
  mount_input_fd=3
  mount_extra_args=(--status-fifo "$status_fifo")
  FILE_SNITCH_PROMPT_TIMEOUT_MS=200 start_file_snitch_mount prompt
}

verify_allow_case() {
  start_prompt_mount

  queue_prompt_answers yes 32
  printf 'allowed through prompt\n' >"$mount_dir/allowed-note.txt"

  assert_file_exists \
    "$store_dir/allowed-note.txt" \
    "expected prompted allow to create backing-store file"
  assert_eq \
    "$(cat "$store_dir/allowed-note.txt")" \
    "allowed through prompt" \
    "expected prompted allow contents to persist"

  assert_prompt_audit \
    '"action":"prompt","path":"create O_[^"]* /allowed-note\.txt","result":1' \
    "expected prompt audit for allowed create missing"
  assert_prompt_log \
    '"action":"prompt","path":"create O_.* /allowed-note\.txt","request_path":"/allowed-note\.txt","access_class":"create","pid":' \
    "expected create prompt to include open mode"
  assert_no_xattr_prompts "expected ordinary xattr traffic to bypass the prompt path"

  cleanup_mount_fixture
}

verify_read_case() {
  start_prompt_mount_with_seed_file "seeded-read.txt" $'seeded read through prompt\n'

  queue_prompt_answers yes 32

  assert_eq \
    "$(cat "$mount_dir/seeded-read.txt")" \
    "seeded read through prompt" \
    "expected prompt allow to gate seeded regular-file reads"

  assert_prompt_audit \
    '"action":"prompt","path":"open O_RDONLY /seeded-read\.txt","result":1' \
    "expected prompt audit for allowed read missing"
  assert_prompt_log \
    '"action":"prompt","path":"open O_RDONLY /seeded-read\.txt","request_path":"/seeded-read\.txt","access_class":"read","pid":' \
    "expected read prompt to include open mode"
  assert_no_xattr_prompts "expected seeded read case to avoid xattr prompts"

  cleanup_mount_fixture
}

verify_deny_case() {
  start_prompt_mount

  queue_prompt_answers no 32
  expect_create_denied \
    "$mount_dir/denied-note.txt" \
    "expected prompt deny to block file creation"

  assert_file_missing \
    "$store_dir/denied-note.txt" \
    "expected denied prompt path to remain absent from backing store"

  assert_prompt_audit \
    '"action":"prompt","path":"create O_[^"]* /denied-note\.txt","result":2' \
    "expected prompt audit for denied create missing"
  assert_no_xattr_prompts "expected denied case to avoid xattr prompts"

  cleanup_mount_fixture
}

verify_timeout_case() {
  start_prompt_mount

  expect_create_denied \
    "$mount_dir/timed-out-note.txt" \
    "expected prompt timeout to block file creation"

  assert_file_missing \
    "$store_dir/timed-out-note.txt" \
    "expected timed-out prompt path to remain absent from backing store"

  assert_prompt_audit \
    '"action":"prompt","path":"create O_[^"]* /timed-out-note\.txt","result":3' \
    "expected prompt audit for timed-out create missing"
  assert_no_xattr_prompts "expected timeout case to avoid xattr prompts"

  cleanup_mount_fixture
}

trap finish EXIT

verify_allow_case
verify_read_case
verify_deny_case
verify_timeout_case
