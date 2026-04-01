#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
tmp_root="/private/tmp"
mount_dir="$(mktemp -d "$tmp_root/file-snitch.mount.XXXXXX")"
store_dir="$(mktemp -d "$tmp_root/file-snitch.store.XXXXXX")"
log_file="$(mktemp "$tmp_root/file-snitch.mount-log.XXXXXX")"
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

  rm -rf "$mount_dir" "$store_dir" "$log_file"
  return "$status"
}

trap cleanup EXIT

printf 'seeded from backing store\n' >"$store_dir/seed-from-store.txt"

"$repo_root/zig-out/bin/file-snitch" mount "$mount_dir" "$store_dir" mutable >"$log_file" 2>&1 &
daemon_pid="$!"

for _ in $(seq 1 50); do
  if [[ -f "$mount_dir/file-snitch-status" ]]; then
    break
  fi

  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    echo "mount process exited early" >&2
    cat "$log_file" >&2
    exit 1
  fi

  sleep 0.1
done

if [[ ! -f "$mount_dir/file-snitch-status" ]]; then
  echo "mount did not become ready" >&2
  mount | grep 'file-snitch' >&2 || true
  ls -la "$mount_dir" >&2 || true
  cat "$log_file" >&2
  exit 1
fi

ls -1 "$mount_dir"
cat "$mount_dir/file-snitch-status"
cat "$mount_dir/seed-from-store.txt"

printf 'hello from live mount\n' >"$mount_dir/live-note.txt"
mv "$mount_dir/live-note.txt" "$mount_dir/live-note-renamed.txt"
cat "$mount_dir/live-note-renamed.txt"

if [[ ! -f "$store_dir/live-note-renamed.txt" ]]; then
  echo "expected renamed backing-store file missing" >&2
  exit 1
fi

printf 'old note contents\n' >"$mount_dir/existing-note.txt"
printf 'replacement note contents\n' >"$mount_dir/existing-note.txt.tmp"
mv "$mount_dir/existing-note.txt.tmp" "$mount_dir/existing-note.txt"
cat "$mount_dir/existing-note.txt"

if [[ "$(cat "$store_dir/existing-note.txt")" != "replacement note contents" ]]; then
  echo "expected replacement backing-store contents missing" >&2
  exit 1
fi

printf 'hidden old note\n' >"$mount_dir/hidden-temp-note.txt"
printf 'hidden replacement note\n' >"$mount_dir/.hidden-temp-note.txt.tmp"
mv "$mount_dir/.hidden-temp-note.txt.tmp" "$mount_dir/hidden-temp-note.txt"
cat "$mount_dir/hidden-temp-note.txt"

if [[ "$(cat "$store_dir/hidden-temp-note.txt")" != "hidden replacement note" ]]; then
  echo "expected hidden-temp replacement backing-store contents missing" >&2
  exit 1
fi

printf 'backup original note\n' >"$mount_dir/backup-note.txt"
mv "$mount_dir/backup-note.txt" "$mount_dir/backup-note.txt~"
printf 'backup replacement note\n' >"$mount_dir/.backup-note.txt.swp"
mv "$mount_dir/.backup-note.txt.swp" "$mount_dir/backup-note.txt"
rm "$mount_dir/backup-note.txt~"
cat "$mount_dir/backup-note.txt"

if [[ "$(cat "$store_dir/backup-note.txt")" != "backup replacement note" ]]; then
  echo "expected backup-style replacement backing-store contents missing" >&2
  exit 1
fi

printf 'truncate me down\n' >"$mount_dir/truncate-note.txt"
printf 'trimmed\n' >"$mount_dir/truncate-note.txt"
cat "$mount_dir/truncate-note.txt"

if [[ "$(cat "$store_dir/truncate-note.txt")" != "trimmed" ]]; then
  echo "expected truncate-write backing-store contents missing" >&2
  exit 1
fi

printf 'chmod note\n' >"$mount_dir/mode-note.txt"
chmod 600 "$mount_dir/mode-note.txt"
mode_value="$(stat -f '%Lp' "$store_dir/mode-note.txt")"
if [[ "$mode_value" != "600" ]]; then
  echo "expected chmod result 600, got $mode_value" >&2
  exit 1
fi

printf 'lock data\n' >"$mount_dir/lock-note.txt"
printf 'swap contents\n' >"$mount_dir/.lock-note.txt.swp"
rm "$mount_dir/.lock-note.txt.swp"
rm "$mount_dir/lock-note.txt"

if [[ -e "$store_dir/.lock-note.txt.swp" || -e "$store_dir/lock-note.txt" ]]; then
  echo "expected lock/swap lifecycle files to be removed from backing store" >&2
  exit 1
fi

printf 'partial overwrite seed\n' >"$mount_dir/partial-note.txt"
python3 - <<PY
from pathlib import Path
path = Path("$mount_dir/partial-note.txt")
with path.open("r+b") as fh:
    fh.seek(8)
    fh.write(b"patched")
PY
cat "$mount_dir/partial-note.txt"

if [[ "$(cat "$store_dir/partial-note.txt")" != "partial patchedte seed" ]]; then
  echo "expected partial-overwrite backing-store contents missing" >&2
  exit 1
fi

if find "$store_dir" -maxdepth 1 -name '._*' | grep . >/dev/null 2>&1; then
  echo "expected macOS sidecar files to remain transient, but backing store contains ._* entries" >&2
  find "$store_dir" -maxdepth 1 -name '._*' >&2
  exit 1
fi

grep -F '"action":"rename"' "$mount_dir/file-snitch-audit"
grep -F 'live-note-renamed.txt' "$mount_dir/file-snitch-audit"
grep -F 'existing-note.txt.tmp -> /existing-note.txt' "$mount_dir/file-snitch-audit"
grep -F '.hidden-temp-note.txt.tmp -> /hidden-temp-note.txt' "$mount_dir/file-snitch-audit"
grep -F '/backup-note.txt -> /backup-note.txt~' "$mount_dir/file-snitch-audit"
grep -F '.backup-note.txt.swp -> /backup-note.txt' "$mount_dir/file-snitch-audit"
grep -F '"action":"truncate"' "$mount_dir/file-snitch-audit"
grep -F '"action":"unlink"' "$mount_dir/file-snitch-audit"
grep -F '"action":"write","path":"/partial-note.txt"' "$mount_dir/file-snitch-audit"

kill -INT "$daemon_pid"
wait "$daemon_pid"
daemon_pid=""
