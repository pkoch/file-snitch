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

verify_chown_flow() {
  local owner_value

  printf 'owner note\n' >"$mount_dir/owner-note.txt"
  python3 - <<PY
import os

path = "$mount_dir/owner-note.txt"
os.chown(path, os.getuid(), os.getgid())
PY

  owner_value="$(platform_owner "$mount_dir/owner-note.txt")"
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

verify_transient_sidecars() {
  if find "$store_dir" -maxdepth 1 -name '._*' | grep . >/dev/null 2>&1; then
    fail "expected macOS sidecar files to remain transient, but backing store contains ._* entries"
  fi
}

platform_run_extra_checks() {
  verify_xattr_round_trip
  verify_chown_flow
  verify_lock_flows
  verify_transient_sidecars
}

platform_assert_extra_audit_log() {
  local log_file="$1"
  local -a audit_patterns=(
    '"action":"setxattr"'
    '"action":"listxattr"'
    '"action":"removexattr"'
    '"xattr":{"name":"com.file-snitch.test"'
    '"action":"chown"'
    '"lock":{"cmd":'
    '"action":"truncate"'
  )

  local pattern=""
  for pattern in "${audit_patterns[@]}"; do
    if ! grep -F "$pattern" "$log_file" >/dev/null 2>&1; then
      fail "expected log entry missing: $pattern"
    fi
  done
}
