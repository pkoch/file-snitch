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

wait_for_policy_cleanup() {
  local attempts="${1:-100}"

  for _ in $(seq 1 "$attempts"); do
    if ! grep -F "expires_at:" "$policy_file" >/dev/null 2>&1; then
      return
    fi
    sleep 0.1
  done

  fail "expected run to rewrite policy.yml after pruning an expired decision"
}

main() {
  trap cleanup EXIT

  prepare_run_fixture "run-expired-decision-cleanup"
  cat >"$policy_file" <<EOF
version: 1
enrollments: []
decisions:
  - executable_path: /usr/bin/cat
    path: $home_dir/.kube/config
    approval_class: read_like
    outcome: allow
    expires_at: '1970-01-01T00:00:01Z'
EOF

  start_file_snitch_run allow
  wait_for_policy_cleanup

  if ! grep -F "decisions: []" "$policy_file" >/dev/null 2>&1; then
    fail "expected the daemon to remove expired decisions from policy.yml"
  fi
}

main "$@"
