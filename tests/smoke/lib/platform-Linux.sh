TMP_ROOT="/tmp"

platform_mount_is_active() {
  mountpoint -q "$1"
}

platform_stop_mount() {
  local status=0

  if [[ -n "${daemon_pid:-}" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    if platform_mount_is_active "$mount_dir"; then
      fusermount3 -u "$mount_dir" >/dev/null 2>&1 || true
    fi
    kill -INT "$daemon_pid" >/dev/null 2>&1 || true
    wait "$daemon_pid" || status=$?
  fi

  return "$status"
}

platform_mode() {
  stat -c '%a' "$1"
}
