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

  prepare_run_fixture "doctor-debug-dossier"
  mkdir -p "$home_dir/.kube"
  printf 'plain kube config\n' >"$home_dir/.kube/config"

  capture_file_snitch enroll "$home_dir/.kube/config" >/dev/null

  dossier_path="$home_dir/file-snitch-debug-dossier.md"
  doctor_output="$(capture_file_snitch doctor --export-debug-dossier "$dossier_path")"

  assert_file_exists \
    "$dossier_path" \
    "expected doctor to export a debug dossier"

  grep -F "policy: ok ($policy_file)" <<<"$doctor_output" >/dev/null || fail "expected doctor output in stdout"
  grep -F "# File Snitch Debug Dossier" "$dossier_path" >/dev/null || fail "expected dossier header"
  grep -F "## Tool Versions" "$dossier_path" >/dev/null || fail "expected tool version section"
  grep -F "## Policy Summary" "$dossier_path" >/dev/null || fail "expected policy summary section"
  grep -F 'path: `~/.kube/config`' "$dossier_path" >/dev/null || fail "expected dossier to redact the home path"
  grep -F 'store_backend: `pass`' "$dossier_path" >/dev/null || fail "expected dossier to mention the store backend"
  grep -F "## Doctor Output" "$dossier_path" >/dev/null || fail "expected doctor output section"

  if grep -F "plain kube config" "$dossier_path" >/dev/null 2>&1; then
    fail "expected debug dossier to avoid leaking guarded file contents"
  fi
}

main "$@"
