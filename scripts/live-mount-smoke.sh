#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
platform_lib_dir="$repo_root/scripts/lib/live-mount"
platform_name="$(uname -s)"

case "$platform_name" in
  Darwin)
    # shellcheck source=scripts/lib/live-mount/macos.sh
    source "$platform_lib_dir/macos.sh"
    ;;
  Linux)
    # shellcheck source=scripts/lib/live-mount/linux.sh
    source "$platform_lib_dir/linux.sh"
    ;;
  *)
    echo "unsupported platform: $platform_name" >&2
    exit 1
    ;;
esac

mount_dir="$(mktemp -d "$TMP_ROOT/file-snitch.mount.XXXXXX")"
store_dir="$(mktemp -d "$TMP_ROOT/file-snitch.store.XXXXXX")"
log_file="$(mktemp "$TMP_ROOT/file-snitch.mount-log.XXXXXX")"
status_fifo="$(mktemp -u "$TMP_ROOT/file-snitch.status-fifo.XXXXXX")"
status_file="$(mktemp "$TMP_ROOT/file-snitch.status.XXXXXX")"
status_reader_pid=""
daemon_pid=""

cleanup() {
  local status=0

  platform_stop_mount || status=$?

  if [[ -n "$status_reader_pid" ]] && kill -0 "$status_reader_pid" 2>/dev/null; then
    kill "$status_reader_pid" 2>/dev/null || true
    wait "$status_reader_pid" || true
  fi

  rm -rf "$mount_dir" "$store_dir" "$log_file" "$status_file"
  [[ -n "$status_fifo" ]] && rm -f "$status_fifo"
  return "$status"
}

fail() {
  echo "$1" >&2
  if [[ -f "$log_file" ]]; then
    echo "--- file-snitch log ---" >&2
    cat "$log_file" >&2 || true
  fi
  exit 1
}

assert_eq() {
  local actual="$1"
  local expected="$2"
  local message="$3"

  if [[ "$actual" != "$expected" ]]; then
    fail "$message"
  fi
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

assert_store_file_contents() {
  local path="$1"
  local expected="$2"
  local message="$3"

  assert_eq "$(cat "$path")" "$expected" "$message"
}

assert_log_contains() {
  local needle="$1"

  if ! grep -F "$needle" "$log_file" >/dev/null 2>&1; then
    fail "expected log entry missing: $needle"
  fi
}

wait_for_mount_ready() {
  for _ in $(seq 1 100); do
    if [[ -s "$status_file" ]] && platform_mount_is_active "$mount_dir"; then
      return
    fi

    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      fail "mount exited before becoming ready"
    fi

    sleep 0.1
  done

  fail "mount did not become ready"
}

start_mount() {
  printf 'seeded from backing store\n' >"$store_dir/seed-from-store.txt"
  mkfifo "$status_fifo"
  head -n 1 "$status_fifo" >"$status_file" &
  status_reader_pid="$!"

  "$repo_root/zig-out/bin/file-snitch" mount "$mount_dir" "$store_dir" mutable --status-fifo "$status_fifo" >"$log_file" 2>&1 &
  daemon_pid="$!"
  wait_for_mount_ready
}

show_mount_state() {
  ls -1 "$mount_dir"
  cat "$status_file"
  cat "$mount_dir/seed-from-store.txt"
}

verify_directory_operations_fail() {
  if mkdir "$mount_dir/empty-dir" >/dev/null 2>&1; then
    fail "expected mkdir to fail on the file-only spike"
  fi

  assert_file_missing \
    "$store_dir/empty-dir" \
    "expected failed mkdir to leave backing store unchanged"

  if rmdir "$mount_dir/empty-dir" >/dev/null 2>&1; then
    fail "expected rmdir to fail on the file-only spike"
  fi
}

verify_simple_rename_flow() {
  printf 'hello from live mount\n' >"$mount_dir/live-note.txt"
  mv "$mount_dir/live-note.txt" "$mount_dir/live-note-renamed.txt"
  cat "$mount_dir/live-note-renamed.txt"

  assert_file_exists \
    "$store_dir/live-note-renamed.txt" \
    "expected renamed backing-store file missing"
}

verify_replace_existing_flow() {
  printf 'old note contents\n' >"$mount_dir/existing-note.txt"
  printf 'replacement note contents\n' >"$mount_dir/existing-note.txt.tmp"
  mv "$mount_dir/existing-note.txt.tmp" "$mount_dir/existing-note.txt"
  cat "$mount_dir/existing-note.txt"

  assert_store_file_contents \
    "$store_dir/existing-note.txt" \
    "replacement note contents" \
    "expected replacement backing-store contents missing"
}

verify_hidden_temp_replace_flow() {
  printf 'hidden old note\n' >"$mount_dir/hidden-temp-note.txt"
  printf 'hidden replacement note\n' >"$mount_dir/.hidden-temp-note.txt.tmp"
  mv "$mount_dir/.hidden-temp-note.txt.tmp" "$mount_dir/hidden-temp-note.txt"
  cat "$mount_dir/hidden-temp-note.txt"

  assert_store_file_contents \
    "$store_dir/hidden-temp-note.txt" \
    "hidden replacement note" \
    "expected hidden-temp replacement backing-store contents missing"
}

verify_backup_style_flow() {
  printf 'backup original note\n' >"$mount_dir/backup-note.txt"
  mv "$mount_dir/backup-note.txt" "$mount_dir/backup-note.txt~"
  printf 'backup replacement note\n' >"$mount_dir/.backup-note.txt.swp"
  mv "$mount_dir/.backup-note.txt.swp" "$mount_dir/backup-note.txt"
  rm "$mount_dir/backup-note.txt~"
  cat "$mount_dir/backup-note.txt"

  assert_store_file_contents \
    "$store_dir/backup-note.txt" \
    "backup replacement note" \
    "expected backup-style replacement backing-store contents missing"
}

verify_truncate_rewrite_flow() {
  printf 'truncate me down\n' >"$mount_dir/truncate-note.txt"
  printf 'trimmed\n' >"$mount_dir/truncate-note.txt"
  cat "$mount_dir/truncate-note.txt"

  assert_store_file_contents \
    "$store_dir/truncate-note.txt" \
    "trimmed" \
    "expected truncate-write backing-store contents missing"
}

verify_chmod_flow() {
  local mode_value

  printf 'chmod note\n' >"$mount_dir/mode-note.txt"
  chmod 600 "$mount_dir/mode-note.txt"
  mode_value="$(platform_mode "$store_dir/mode-note.txt")"
  assert_eq "$mode_value" "600" "expected chmod result 600, got $mode_value"
}

verify_partial_overwrite_flow() {
  printf 'partial overwrite seed\n' >"$mount_dir/partial-note.txt"
  python3 - <<PY
from pathlib import Path

path = Path("$mount_dir/partial-note.txt")
with path.open("r+b") as fh:
    fh.seek(8)
    fh.write(b"patched")
PY
  cat "$mount_dir/partial-note.txt"

  assert_store_file_contents \
    "$store_dir/partial-note.txt" \
    "partial patchedte seed" \
    "expected partial-overwrite backing-store contents missing"
}

verify_common_audit_log() {
  local -a audit_patterns=(
    '"timestamp":{"sec":'
    '"pid":'
    '"action":"create"'
    '"action":"rename"'
    '"action":"chmod"'
    '"action":"unlink"'
    '"rename":{"from":"/existing-note.txt.tmp","to":"/existing-note.txt"}'
    '"rename":{"from":"/.hidden-temp-note.txt.tmp","to":"/hidden-temp-note.txt"}'
    '"rename":{"from":"/backup-note.txt","to":"/backup-note.txt~"}'
    '"rename":{"from":"/.backup-note.txt.swp","to":"/backup-note.txt"}'
    '"file_info":{"flags":'
    '"action":"write","path":"/partial-note.txt"'
  )

  for pattern in "${audit_patterns[@]}"; do
    assert_log_contains "$pattern"
  done

  platform_assert_extra_audit_log "$log_file"
}

shutdown_mount() {
  platform_stop_mount
  daemon_pid=""
}

main() {
  trap cleanup EXIT

  start_mount
  show_mount_state

  verify_directory_operations_fail
  verify_simple_rename_flow
  verify_replace_existing_flow
  verify_hidden_temp_replace_flow
  verify_backup_style_flow
  verify_truncate_rewrite_flow
  verify_chmod_flow
  verify_partial_overwrite_flow
  platform_run_extra_checks "$mount_dir" "$store_dir" "$log_file"
  verify_common_audit_log
  shutdown_mount
}

main "$@"
