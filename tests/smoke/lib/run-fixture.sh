home_dir=""
policy_file=""
guarded_store_dir=""
log_file=""
daemon_pid=""
run_input_fd=""
mount_paths=()

prepare_run_fixture() {
  local fixture_name="$1"

  home_dir="$(mktemp -d "$TMP_ROOT/${fixture_name}-home.XXXXXX")"
  policy_file="$home_dir/.config/file-snitch/policy.yml"
  guarded_store_dir="$home_dir/.var/file-snitch/guarded-secrets"
  log_file="$(mktemp "$TMP_ROOT/${fixture_name}-log.XXXXXX")"
  daemon_pid=""
  run_input_fd=""
  mount_paths=()

  mkdir -p \
    "$home_dir/.config/file-snitch" \
    "$guarded_store_dir"

  if declare -F fixture_prepare_extra >/dev/null 2>&1; then
    fixture_prepare_extra
  fi
}

run_file_snitch() {
  HOME="$home_dir" "$repo_root/zig-out/bin/file-snitch" "$@"
}

capture_file_snitch() {
  HOME="$home_dir" "$repo_root/zig-out/bin/file-snitch" "$@" 2>&1
}

start_file_snitch_run() {
  local mode="$1"

  if [[ -n "$run_input_fd" ]]; then
    HOME="$home_dir" "$repo_root/zig-out/bin/file-snitch" run "$mode" --foreground <&$run_input_fd >"$log_file" 2>&1 &
  else
    HOME="$home_dir" "$repo_root/zig-out/bin/file-snitch" run "$mode" --foreground >"$log_file" 2>&1 &
  fi
  daemon_pid="$!"
  wait_for_mounts_ready
}

wait_for_mounts_ready() {
  local attempts="${1:-100}"

  for _ in $(seq 1 "$attempts"); do
    local all_ready="yes"
    local mount_path=""

    for mount_path in "${mount_paths[@]}"; do
      if ! platform_mount_is_active "$mount_path"; then
        all_ready="no"
        break
      fi
    done

    if [[ "$all_ready" == "yes" ]]; then
      return
    fi

    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      fail "run exited before mounts became ready"
    fi

    sleep 0.1
  done

  fail "run did not become ready"
}

stop_run_fixture() {
  local status=0
  local mount_path=""

  if [[ -n "${daemon_pid:-}" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill -INT "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" || status=$?
  fi

  for mount_path in "${mount_paths[@]}"; do
    if platform_mount_is_active "$mount_path"; then
      platform_stop_mount_path "$mount_path" || true
    fi
  done

  if declare -F fixture_cleanup_extra >/dev/null 2>&1; then
    fixture_cleanup_extra
  fi

  daemon_pid=""
  run_input_fd=""
  mount_paths=()
  return "$status"
}

cleanup_run_fixture() {
  local status=0

  stop_run_fixture || status=$?

  [[ -n "$log_file" ]] && rm -f "$log_file"
  [[ -n "$home_dir" ]] && rm -rf "$home_dir"

  home_dir=""
  policy_file=""
  guarded_store_dir=""
  log_file=""

  return "$status"
}

guarded_object_path_for() {
  local target_path="$1"
  local status_output=""

  status_output="$(capture_file_snitch status)"
  STATUS_OUTPUT="$status_output" python3 - "$target_path" <<'PY'
import re
import sys
import os

target = sys.argv[1]
output = os.environ["STATUS_OUTPUT"].splitlines()
pattern = re.compile(r"^enrollment: path=(?P<path>.+) object_id=(?P<object_id>[^ ]+) guarded_object=(?P<guarded_object>.+)$")

for line in output:
    match = pattern.match(line)
    if match and match.group("path") == target:
        print(match.group("guarded_object"))
        raise SystemExit(0)

raise SystemExit(1)
PY
}
