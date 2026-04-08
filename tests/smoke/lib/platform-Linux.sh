TMP_ROOT="/tmp"

platform_mount_is_active() {
  mountpoint -q "$1"
}

platform_stop_mount_path() {
  fusermount3 -u "$1" >/dev/null 2>&1 || true
}

platform_mode() {
  stat -c '%a' "$1"
}

platform_prime_guarded_path() {
  :
}
