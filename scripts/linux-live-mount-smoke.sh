#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
mount_dir="$(mktemp -d /tmp/file-snitch.linux-mount.XXXXXX)"
store_dir="$(mktemp -d /tmp/file-snitch.linux-store.XXXXXX)"
status_fifo="$(mktemp -u /tmp/file-snitch.linux-status.XXXXXX)"
log_file="$(mktemp /tmp/file-snitch.linux-log.XXXXXX)"
daemon_pid=""

cleanup() {
  local status=0

  if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    fusermount3 -u "$mount_dir" >/dev/null 2>&1 || true
    kill -INT "$daemon_pid" >/dev/null 2>&1 || true
    wait "$daemon_pid" || status=$?
  fi

  rm -f "$status_fifo"
  rm -rf "$mount_dir" "$store_dir"
  rm -f "$log_file"
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

wait_for_mount_ready() {
  python3 - <<'PY' "$status_fifo"
import os
import sys
import time

path = sys.argv[1]
deadline = time.time() + 20
fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
try:
    while time.time() < deadline:
        try:
            data = os.read(fd, 65536)
        except BlockingIOError:
            data = b""
        if data:
            sys.exit(0)
        time.sleep(0.1)
finally:
    os.close(fd)
sys.exit(1)
PY

  for _ in $(seq 1 100); do
    if mountpoint -q "$mount_dir"; then
      return
    fi

    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      fail "linux live mount exited before becoming ready"
    fi

    sleep 0.1
  done

  fail "linux live mount did not become ready"
}

assert_log_contains() {
  local needle="$1"

  if ! grep -F "$needle" "$log_file" >/dev/null 2>&1; then
    fail "expected log entry missing: $needle"
  fi
}

trap cleanup EXIT

cd "$repo_root"

printf 'seed-data\n' > "$store_dir/seed.txt"
mkfifo "$status_fifo"

./zig-out/bin/file-snitch mount "$mount_dir" "$store_dir" mutable --status-fifo "$status_fifo" >"$log_file" 2>&1 &
daemon_pid="$!"

wait_for_mount_ready

[[ "$(cat "$mount_dir/seed.txt")" == "seed-data" ]] || fail "seed file contents were not readable through the mount"

printf 'hello from linux\n' > "$mount_dir/live-note.txt"
mv "$mount_dir/live-note.txt" "$mount_dir/live-note-renamed.txt"
printf 'edited\n' > "$mount_dir/live-note-renamed.txt"
chmod 600 "$mount_dir/live-note-renamed.txt"
rm "$mount_dir/seed.txt"

expected_file="$(mktemp /tmp/file-snitch.expected.XXXXXX)"
printf 'edited\n' > "$expected_file"
cmp -s "$expected_file" "$store_dir/live-note-renamed.txt" || fail "backing-store contents did not match the rewritten file"
rm -f "$expected_file"

[[ ! -e "$store_dir/seed.txt" ]] || fail "seed file still existed in the backing store after unlink"

assert_log_contains '"action":"create"'
assert_log_contains '"action":"rename"'
assert_log_contains '"action":"chmod"'
assert_log_contains '"action":"unlink"'

fusermount3 -u "$mount_dir"
kill -INT "$daemon_pid" >/dev/null 2>&1 || true
wait "$daemon_pid" || true
daemon_pid=""

trap - EXIT
cleanup
