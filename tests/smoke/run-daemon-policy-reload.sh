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

  prepare_run_fixture "run-daemon-policy-reload"
  mkdir -p "$home_dir/.kube"
  printf 'host kube\n' >"$home_dir/.kube/config"
  printf 'plain sibling\n' >"$home_dir/.kube/cache"

  start_file_snitch_run allow --daemon

  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    fail "expected daemonized run to stay alive before the first enrollment appears"
  fi

  capture_file_snitch enroll "$home_dir/.kube/config" >/dev/null

  mount_paths=("$home_dir/.kube")
  wait_for_mounts_ready
  platform_prime_guarded_path "$home_dir/.kube/config"

  assert_eq \
    "$(cat "$home_dir/.kube/config")" \
    "host kube" \
    "expected daemonized run to project a newly enrolled file without restart"
  assert_eq \
    "$(cat "$home_dir/.kube/cache")" \
    "plain sibling" \
    "expected daemonized passthrough siblings to remain accessible"

  cat >"$policy_file" <<EOF
version: 1
enrollments: []
decisions: []
EOF

  wait_for_mounts_gone

  assert_file_missing \
    "$home_dir/.kube/config" \
    "expected daemonized run to tear the projection down when the enrollment is removed"
  assert_eq \
    "$(cat "$home_dir/.kube/cache")" \
    "plain sibling" \
    "expected daemonized passthrough siblings to remain after teardown"
}

main "$@"
