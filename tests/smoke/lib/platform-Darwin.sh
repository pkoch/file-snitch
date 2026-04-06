TMP_ROOT="/private/tmp"

platform_mount_is_active() {
  mount | grep -F "on $1 " >/dev/null 2>&1
}

platform_stop_mount() {
  local status=0

  if [[ -n "${daemon_pid:-}" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill -INT "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" || status=$?
  fi

  if platform_mount_is_active "$mount_dir"; then
    umount "$mount_dir" >/dev/null 2>&1 || true
  fi

  return "$status"
}

platform_mode() {
  stat -f '%Lp' "$1"
}

platform_owner() {
  stat -f '%u:%g' "$1"
}
