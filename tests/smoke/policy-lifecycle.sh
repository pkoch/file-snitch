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

extract_guarded_object_id() {
  guarded_object_id_for "$1"
}

main() {
  trap cleanup EXIT

  prepare_run_fixture "policy-lifecycle"
  mkdir -p "$home_dir/.kube"
  printf 'plain kube config\n' >"$home_dir/.kube/config"

  enroll_output="$(capture_file_snitch enroll "$home_dir/.kube/config")"
  if ! grep -F "file-snitch: enrolled $home_dir/.kube/config as " <<<"$enroll_output" >/dev/null 2>&1; then
    fail "expected enroll output to mention the target path"
  fi

  assert_file_missing \
    "$home_dir/.kube/config" \
    "expected enroll to evacuate the plaintext file from its original path"

  object_id="$(extract_guarded_object_id "$home_dir/.kube/config")"
  assert_eq \
    "$(guarded_store_show_for "$home_dir/.kube/config")" \
    "plain kube config" \
    "expected guarded object to preserve the enrolled plaintext"

  status_output="$(capture_file_snitch status)"
  grep -F "policy: $policy_file" <<<"$status_output" >/dev/null || fail "expected status to print the policy path"
  grep -F "enrollments: 1" <<<"$status_output" >/dev/null || fail "expected one enrollment in status"
  grep -F "projection: $home_dir/.local/state/file-snitch/projection" <<<"$status_output" >/dev/null || fail "expected the projection root in status"
  grep -F "enrollment: path=$home_dir/.kube/config " <<<"$status_output" >/dev/null || fail "expected enrollment details in status"

  doctor_output="$(capture_file_snitch doctor)"
  grep -F "policy: ok ($policy_file)" <<<"$doctor_output" >/dev/null || fail "expected doctor to validate the policy file"
  grep -F "projection: $home_dir/.local/state/file-snitch/projection for 1 enrollments" <<<"$doctor_output" >/dev/null || fail "expected doctor to report the projection root"
  grep -F "ok: FUSE runtime is available:" <<<"$doctor_output" >/dev/null || fail "expected doctor to validate the FUSE runtime"
  grep -F "ok: pass backend is usable: pass" <<<"$doctor_output" >/dev/null || fail "expected doctor to validate pass usability"
  grep -F 'hint: start `file-snitch agent` or install the per-user agent service' <<<"$doctor_output" >/dev/null || fail "expected doctor to explain how to fix a missing agent socket"
  grep -F "warn: agent socket path is absent: $runtime_dir/file-snitch/agent.sock" <<<"$doctor_output" >/dev/null || fail "expected doctor to mention missing agent socket"
  grep -F "ok: guarded object exists in store: pass:file-snitch/$object_id" <<<"$doctor_output" >/dev/null || fail "expected doctor to validate the guarded object"
  grep -F "ok: target path currently absent: $home_dir/.kube/config" <<<"$doctor_output" >/dev/null || fail "expected doctor to report the evacuated target path"

  printf 'wrong target\n' >"$home_dir/.kube/wrong-target"
  ln -s "$home_dir/.kube/wrong-target" "$home_dir/.kube/config"
  if unexpected_symlink_output="$(capture_file_snitch doctor)"; then
    fail "expected doctor to reject an enrolled path symlinked to the wrong target"
  fi
  grep -F "error: target path points at an unexpected symlink target: $home_dir/.kube/config -> $home_dir/.kube/wrong-target (expected $home_dir/.local/state/file-snitch/projection/$object_id)" <<<"$unexpected_symlink_output" >/dev/null || fail "expected doctor to report the unexpected target symlink"
  rm "$home_dir/.kube/config" "$home_dir/.kube/wrong-target"

  cat >"$policy_file" <<EOF
version: 1
enrollments:
  - path: $home_dir/.kube/config
    object_id: $object_id
decisions:
  - executable_path: /usr/bin/cat
    path: $home_dir/.kube/config
    approval_class: read_like
    outcome: allow
    expires_at: null
EOF

  unenroll_output="$(capture_file_snitch unenroll "$home_dir/.kube/config")"
  grep -F "file-snitch: unenrolled $home_dir/.kube/config from $policy_file" <<<"$unenroll_output" >/dev/null || fail "expected unenroll output to mention the target path"

  assert_file_exists \
    "$home_dir/.kube/config" \
    "expected unenroll to restore the plaintext file"
  assert_eq \
    "$(cat "$home_dir/.kube/config")" \
    "plain kube config" \
    "expected unenroll to restore the original plaintext contents"
  if guarded_store_show_for "$home_dir/.kube/config" >/dev/null 2>&1; then
    fail "expected unenroll to remove the guarded object"
  fi

  status_output="$(capture_file_snitch status)"
  grep -F "enrollments: 0" <<<"$status_output" >/dev/null || fail "expected no enrollments after unenroll"
  grep -F "decisions: 0" <<<"$status_output" >/dev/null || fail "expected no remembered decisions after unenroll"
  grep -F "projection: absent" <<<"$status_output" >/dev/null || fail "expected no projection after unenroll"
}

main "$@"
