#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
tmp_root="/private/tmp"
mount_dir="$(mktemp -d "$tmp_root/file-snitch.mount.XXXXXX")"
store_dir="$(mktemp -d "$tmp_root/file-snitch.store.XXXXXX")"
log_file="$(mktemp "$tmp_root/file-snitch.mount-log.XXXXXX")"
status_fifo="$(mktemp -u "$tmp_root/file-snitch.status-fifo.XXXXXX")"
status_file="$(mktemp "$tmp_root/file-snitch.status.XXXXXX")"
status_reader_pid=""
daemon_pid=""

cleanup() {
  local status=0

  if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill -INT "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" || status=$?
  fi

  if mount | grep -F "on $mount_dir " >/dev/null 2>&1; then
    umount "$mount_dir" || true
  fi

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

wait_for_mount_ready() {
  for _ in $(seq 1 50); do
    if [[ -s "$status_file" ]] && mount | grep -F "on $mount_dir " >/dev/null 2>&1; then
      return
    fi

    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      echo "mount process exited early" >&2
      cat "$log_file" >&2
      exit 1
    fi

    sleep 0.1
  done

  echo "mount did not become ready" >&2
  mount | grep 'file-snitch' >&2 || true
  ls -la "$mount_dir" >&2 || true
  cat "$log_file" >&2
  exit 1
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

verify_simple_rename_flow() {
  printf 'hello from live mount\n' >"$mount_dir/live-note.txt"
  mv "$mount_dir/live-note.txt" "$mount_dir/live-note-renamed.txt"
  cat "$mount_dir/live-note-renamed.txt"

  assert_file_exists \
    "$store_dir/live-note-renamed.txt" \
    "expected renamed backing-store file missing"
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

verify_xattr_round_trip() {
  xattr -w com.file-snitch.test "hello-xattr" "$mount_dir/live-note-renamed.txt"
  assert_eq \
    "$(xattr -p com.file-snitch.test "$mount_dir/live-note-renamed.txt")" \
    "hello-xattr" \
    "expected mounted xattr round-trip value missing"

  if ! xattr "$mount_dir/live-note-renamed.txt" | grep -F 'com.file-snitch.test' >/dev/null 2>&1; then
    fail "expected mounted xattr listing to include com.file-snitch.test"
  fi

  assert_eq \
    "$(xattr -p com.file-snitch.test "$store_dir/live-note-renamed.txt")" \
    "hello-xattr" \
    "expected backing-store xattr round-trip value missing"

  xattr -d com.file-snitch.test "$mount_dir/live-note-renamed.txt"
  if xattr -p com.file-snitch.test "$store_dir/live-note-renamed.txt" >/dev/null 2>&1; then
    fail "expected backing-store xattr removal to clear com.file-snitch.test"
  fi
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
  mode_value="$(stat -f '%Lp' "$store_dir/mode-note.txt")"
  assert_eq "$mode_value" "600" "expected chmod result 600, got $mode_value"
}

verify_chown_flow() {
  local owner_value

  printf 'owner note\n' >"$mount_dir/owner-note.txt"
  python3 - <<PY
import os

path = "$mount_dir/owner-note.txt"
os.chown(path, os.getuid(), os.getgid())
PY

  owner_value="$(stat -f '%u:%g' "$mount_dir/owner-note.txt")"
  assert_eq \
    "$owner_value" \
    "$(id -u):$(id -g)" \
    "expected mounted owner to remain current uid/gid, got $owner_value"
}

hold_flock() {
  flock_holder_pid=""
  python3 - <<PY &
import fcntl
import time
from pathlib import Path

path = Path("$mount_dir/lock-note.txt")
with path.open("r+") as fh:
    fcntl.flock(fh, fcntl.LOCK_EX)
    time.sleep(2)
PY
  flock_holder_pid="$!"
}

assert_flock_contention() {
  python3 - <<PY
import errno
import fcntl
import sys
from pathlib import Path

path = Path("$mount_dir/lock-note.txt")
with path.open("r+") as fh:
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            sys.exit(0)
        raise

    raise SystemExit("expected flock contention")
PY
}

assert_flock_release() {
  python3 - <<PY
import fcntl
from pathlib import Path

path = Path("$mount_dir/lock-note.txt")
with path.open("r+") as fh:
    fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fcntl.flock(fh, fcntl.LOCK_UN)
PY
}

hold_posix_lock() {
  posix_lock_holder_pid=""
  python3 - <<PY &
import fcntl
import time
from pathlib import Path

path = Path("$mount_dir/lock-note.txt")
with path.open("r+") as fh:
    fcntl.lockf(fh, fcntl.LOCK_EX)
    time.sleep(2)
PY
  posix_lock_holder_pid="$!"
}

assert_posix_lock_contention() {
  python3 - <<PY
import errno
import fcntl
import sys
from pathlib import Path

path = Path("$mount_dir/lock-note.txt")
with path.open("r+") as fh:
    try:
        fcntl.lockf(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            sys.exit(0)
        raise

    raise SystemExit("expected POSIX lock contention")
PY
}

assert_posix_lock_release() {
  python3 - <<PY
import fcntl
from pathlib import Path

path = Path("$mount_dir/lock-note.txt")
with path.open("r+") as fh:
    fcntl.lockf(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fcntl.lockf(fh, fcntl.LOCK_UN)
PY
}

verify_lock_flows() {
  printf 'lock data\n' >"$mount_dir/lock-note.txt"

  hold_flock
  sleep 0.2
  assert_flock_contention
  wait "$flock_holder_pid"
  assert_flock_release

  hold_posix_lock
  sleep 0.2
  assert_posix_lock_contention
  wait "$posix_lock_holder_pid"
  assert_posix_lock_release

  printf 'swap contents\n' >"$mount_dir/.lock-note.txt.swp"
  rm "$mount_dir/.lock-note.txt.swp"
  rm "$mount_dir/lock-note.txt"

  assert_file_missing \
    "$store_dir/.lock-note.txt.swp" \
    "expected lock/swap lifecycle files to be removed from backing store"
  assert_file_missing \
    "$store_dir/lock-note.txt" \
    "expected lock/swap lifecycle files to be removed from backing store"
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

verify_transient_sidecars() {
  if find "$store_dir" -maxdepth 1 -name '._*' | grep . >/dev/null 2>&1; then
    echo "expected macOS sidecar files to remain transient, but backing store contains ._* entries" >&2
    find "$store_dir" -maxdepth 1 -name '._*' >&2
    exit 1
  fi
}

verify_audit_log() {
  local -a audit_patterns=(
    '"action":"mkdir","path":"/empty-dir"'
    '"timestamp":{"sec":'
    '"pid":'
    '"action":"rename"'
    '"action":"setxattr"'
    '"action":"listxattr"'
    '"action":"removexattr"'
    'live-note-renamed.txt'
    '"rename":{"from":"/existing-note.txt.tmp","to":"/existing-note.txt"}'
    '"rename":{"from":"/.hidden-temp-note.txt.tmp","to":"/hidden-temp-note.txt"}'
    '"rename":{"from":"/backup-note.txt","to":"/backup-note.txt~"}'
    '"rename":{"from":"/.backup-note.txt.swp","to":"/backup-note.txt"}'
    '"xattr":{"name":"com.file-snitch.test"'
    '"lock":{"cmd":'
    '"file_info":{"flags":'
    '"action":"truncate"'
    '"action":"unlink"'
    '"action":"chown"'
    '"action":"write","path":"/partial-note.txt"'
  )

  for pattern in "${audit_patterns[@]}"; do
    grep -F "$pattern" "$log_file"
  done
}

shutdown_mount() {
  kill -INT "$daemon_pid"
  wait "$daemon_pid"
  daemon_pid=""
}

main() {
  trap cleanup EXIT

  start_mount
  show_mount_state

  verify_directory_operations_fail
  verify_simple_rename_flow
  verify_xattr_round_trip
  verify_replace_existing_flow
  verify_hidden_temp_replace_flow
  verify_backup_style_flow
  verify_truncate_rewrite_flow
  verify_chmod_flow
  verify_chown_flow
  verify_lock_flows
  verify_partial_overwrite_flow
  verify_transient_sidecars
  verify_audit_log
  shutdown_mount
}

main "$@"
