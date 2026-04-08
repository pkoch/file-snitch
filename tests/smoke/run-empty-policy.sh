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

  prepare_run_fixture "run-empty-policy"
  start_file_snitch_run allow

  sleep 0.3
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    fail "expected run to stay alive and watch policy changes even when the policy is empty"
  fi

  if [[ -s "$log_file" ]]; then
    fail "expected empty-policy run to stay quiet while watching for future changes"
  fi
}

main "$@"
