#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
tmp_root="/private/tmp"
mount_dir=""
store_dir=""
log_file=""
prompt_fifo=""
daemon_pid=""

cleanup_case() {
  local status=0

  if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill -INT "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" || status=$?
  fi

  if [[ -n "$mount_dir" ]] && mount | grep -F "on $mount_dir " >/dev/null 2>&1; then
    umount "$mount_dir" || true
  fi

  exec 3>&- || true
  [[ -n "$mount_dir" ]] && rm -rf "$mount_dir"
  [[ -n "$store_dir" ]] && rm -rf "$store_dir"
  [[ -n "$log_file" ]] && rm -f "$log_file"
  [[ -n "$prompt_fifo" ]] && rm -f "$prompt_fifo"

  mount_dir=""
  store_dir=""
  log_file=""
  prompt_fifo=""
  daemon_pid=""
  return "$status"
}

finish() {
  cleanup_case
}

fail() {
  echo "$1" >&2
  if [[ -n "$log_file" && -f "$log_file" ]]; then
    cat "$log_file" >&2
  fi
  exit 1
}

assert_eq() {
  local actual="$1"
  local expected="$2"
  local message="$3"

  [[ "$actual" == "$expected" ]] || fail "$message"
}

assert_file_exists() {
  local path="$1"
  local message="$2"

  [[ -f "$path" ]] || fail "$message"
}

assert_file_missing() {
  local path="$1"
  local message="$2"

  [[ ! -e "$path" ]] || fail "$message"
}

assert_no_xattr_prompts() {
  local message="$1"

  if grep -F 'file-snitch prompt: xattr ' "$log_file" >/dev/null 2>&1; then
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

wait_for_mount_ready() {
  local status_path="$mount_dir/file-snitch-status"

  for _ in $(seq 1 50); do
    if [[ -f "$status_path" ]]; then
      return
    fi

    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      fail "prompt mount exited early"
    fi

    sleep 0.1
  done

  fail "prompt mount did not become ready"
}

start_prompt_mount() {
  mount_dir="$(mktemp -d "$tmp_root/file-snitch.prompt-mount.XXXXXX")"
  store_dir="$(mktemp -d "$tmp_root/file-snitch.prompt-store.XXXXXX")"
  log_file="$(mktemp "$tmp_root/file-snitch.prompt-log.XXXXXX")"
  prompt_fifo="$(mktemp -u "$tmp_root/file-snitch.prompt-fifo.XXXXXX")"

  mkfifo "$prompt_fifo"
  exec 3<>"$prompt_fifo"

  FILE_SNITCH_PROMPT_TIMEOUT_MS=200 \
    "$repo_root/zig-out/bin/file-snitch" mount "$mount_dir" "$store_dir" prompt <&3 >"$log_file" 2>&1 &
  daemon_pid="$!"
  wait_for_mount_ready
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

  if ! grep -F '"action":"prompt","path":"create /allowed-note.txt","result":1' "$mount_dir/file-snitch-audit" >/dev/null 2>&1; then
    fail "expected prompt audit for allowed create missing"
  fi
  assert_no_xattr_prompts "expected ordinary xattr traffic to bypass the prompt path"

  cleanup_case
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

  if ! grep -F '"action":"prompt","path":"create /denied-note.txt","result":2' "$mount_dir/file-snitch-audit" >/dev/null 2>&1; then
    fail "expected prompt audit for denied create missing"
  fi
  assert_no_xattr_prompts "expected denied case to avoid xattr prompts"

  cleanup_case
}

verify_timeout_case() {
  start_prompt_mount

  expect_create_denied \
    "$mount_dir/timed-out-note.txt" \
    "expected prompt timeout to block file creation"

  assert_file_missing \
    "$store_dir/timed-out-note.txt" \
    "expected timed-out prompt path to remain absent from backing store"

  if ! grep -F '"action":"prompt","path":"create /timed-out-note.txt","result":3' "$mount_dir/file-snitch-audit" >/dev/null 2>&1; then
    fail "expected prompt audit for timed-out create missing"
  fi
  assert_no_xattr_prompts "expected timeout case to avoid xattr prompts"

  cleanup_case
}

trap finish EXIT

verify_allow_case
verify_deny_case
verify_timeout_case
