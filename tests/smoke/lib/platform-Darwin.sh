TMP_ROOT="/private/tmp"

platform_mount_is_active() {
  mount | grep -F "on $1 " >/dev/null 2>&1
}

platform_stop_mount_path() {
  umount "$1" >/dev/null 2>&1 || true
}

platform_mode() {
  stat -f '%Lp' "$1"
}

platform_owner() {
  stat -f '%u:%g' "$1"
}

platform_prime_guarded_path() {
  stat "$1" >/dev/null 2>&1 || true
}
