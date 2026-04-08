#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"

source "$repo_root/tests/smoke/lib/assertions.sh"
source "$repo_root/tests/smoke/lib/run-fixture.sh"

case "$(uname -s)" in
  Darwin) source "$repo_root/tests/smoke/lib/platform-Darwin.sh" ;;
  Linux) source "$repo_root/tests/smoke/lib/platform-Linux.sh" ;;
  *)
    echo "unsupported platform: $(uname -s)" >&2
    exit 1
    ;;
esac

cleanup() {
  cleanup_run_fixture
}

main() {
  trap cleanup EXIT

  prepare_run_fixture "run-single-enrollment"
  mkdir -p "$home_dir/.kube"
  printf 'host kube\n' >"$home_dir/.kube/config"
  printf 'plain sibling\n' >"$home_dir/.kube/cache"

  capture_file_snitch enroll "$home_dir/.kube/config" >/dev/null
  guarded_store_write_for "$home_dir/.kube/config" 'guarded kube
'

  mount_paths=("$home_dir/.kube")
  start_file_snitch_run allow
  platform_prime_guarded_path "$home_dir/.kube/config"

  assert_eq \
    "$(cat "$home_dir/.kube/config")" \
    "guarded kube" \
    "expected the enrolled file to be projected from the guarded object"
  assert_eq \
    "$(cat "$home_dir/.kube/cache")" \
    "plain sibling" \
    "expected sibling files to passthrough unchanged"

  platform_prime_guarded_path "$home_dir/.kube/config"
  printf 'updated guarded kube\n' >"$home_dir/.kube/config"
  assert_eq \
    "$(guarded_store_show_for "$home_dir/.kube/config")" \
    "updated guarded kube" \
    "expected writes through the mount to update the guarded object"

  stop_run_fixture

  assert_file_missing \
    "$home_dir/.kube/config" \
    "expected the enrolled plaintext path to disappear again after shutdown"
  assert_eq \
    "$(cat "$home_dir/.kube/cache")" \
    "plain sibling" \
    "expected sibling files to survive shutdown unchanged"
}

main "$@"
