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

  prepare_run_fixture "run-multi-mount"
  mkdir -p "$home_dir/.kube" "$home_dir/.ssh"
  printf 'host kube\n' >"$home_dir/.kube/config"
  printf 'host ssh\n' >"$home_dir/.ssh/id_ed25519"
  printf 'ssh config\n' >"$home_dir/.ssh/config"

  capture_file_snitch enroll "$home_dir/.kube/config" >/dev/null
  capture_file_snitch enroll "$home_dir/.ssh/id_ed25519" >/dev/null

  kube_object_path="$(guarded_object_path_for "$home_dir/.kube/config")"
  ssh_object_path="$(guarded_object_path_for "$home_dir/.ssh/id_ed25519")"
  printf 'guarded kube\n' >"$kube_object_path"
  printf 'guarded ssh\n' >"$ssh_object_path"

  mount_paths=("$home_dir/.kube" "$home_dir/.ssh")
  start_file_snitch_run allow

  assert_eq \
    "$(cat "$home_dir/.kube/config")" \
    "guarded kube" \
    "expected the kube enrollment to be projected from its guarded object"
  assert_eq \
    "$(cat "$home_dir/.ssh/id_ed25519")" \
    "guarded ssh" \
    "expected the ssh enrollment to be projected from its guarded object"
  assert_eq \
    "$(cat "$home_dir/.ssh/config")" \
    "ssh config" \
    "expected unguarded siblings to passthrough under a second mount"

  printf 'updated guarded kube\n' >"$home_dir/.kube/config"
  printf 'updated guarded ssh\n' >"$home_dir/.ssh/id_ed25519"
  assert_eq \
    "$(cat "$kube_object_path")" \
    "updated guarded kube" \
    "expected the kube guarded object to receive mounted writes"
  assert_eq \
    "$(cat "$ssh_object_path")" \
    "updated guarded ssh" \
    "expected the ssh guarded object to receive mounted writes"

  stop_run_fixture

  assert_file_missing \
    "$home_dir/.kube/config" \
    "expected the kube plaintext path to disappear again after shutdown"
  assert_file_missing \
    "$home_dir/.ssh/id_ed25519" \
    "expected the ssh plaintext path to disappear again after shutdown"
  assert_eq \
    "$(cat "$home_dir/.ssh/config")" \
    "ssh config" \
    "expected sibling passthrough files to survive shutdown"
}

main "$@"
