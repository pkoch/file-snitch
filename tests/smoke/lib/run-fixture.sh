home_dir=""
config_home_dir=""
policy_file=""
password_store_dir=""
fake_bin_dir=""
log_file=""
daemon_pid=""
run_input_fd=""
mount_paths=()

prepare_run_fixture() {
  local fixture_name="$1"

  home_dir="$(mktemp -d "$TMP_ROOT/${fixture_name}-home.XXXXXX")"
  config_home_dir="$home_dir/.config"
  policy_file="$config_home_dir/file-snitch/policy.yml"
  password_store_dir="$home_dir/.password-store"
  fake_bin_dir="$home_dir/.local/file-snitch-test-bin"
  log_file="$(mktemp "$TMP_ROOT/${fixture_name}-log.XXXXXX")"
  daemon_pid=""
  run_input_fd=""
  mount_paths=()

  mkdir -p \
    "$config_home_dir/file-snitch" \
    "$password_store_dir" \
    "$fake_bin_dir"

  write_fake_pass_script

  if declare -F fixture_prepare_extra >/dev/null 2>&1; then
    fixture_prepare_extra
  fi
}

run_file_snitch() {
  PATH="$fake_bin_dir:$PATH" \
    HOME="$home_dir" \
    XDG_CONFIG_HOME="$config_home_dir" \
    PASSWORD_STORE_DIR="$password_store_dir" \
    "$repo_root/zig-out/bin/file-snitch" "$@"
}

capture_file_snitch() {
  PATH="$fake_bin_dir:$PATH" \
    HOME="$home_dir" \
    XDG_CONFIG_HOME="$config_home_dir" \
    PASSWORD_STORE_DIR="$password_store_dir" \
    "$repo_root/zig-out/bin/file-snitch" "$@" 2>&1
}

start_file_snitch_run() {
  local mode="$1"

  if [[ -n "$run_input_fd" ]]; then
    PATH="$fake_bin_dir:$PATH" \
      HOME="$home_dir" \
      XDG_CONFIG_HOME="$config_home_dir" \
      PASSWORD_STORE_DIR="$password_store_dir" \
      "$repo_root/zig-out/bin/file-snitch" run "$mode" --foreground <&$run_input_fd >"$log_file" 2>&1 &
  else
    PATH="$fake_bin_dir:$PATH" \
      HOME="$home_dir" \
      XDG_CONFIG_HOME="$config_home_dir" \
      PASSWORD_STORE_DIR="$password_store_dir" \
      "$repo_root/zig-out/bin/file-snitch" run "$mode" --foreground >"$log_file" 2>&1 &
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

wait_for_mounts_gone() {
  local attempts="${1:-100}"

  for _ in $(seq 1 "$attempts"); do
    local all_gone="yes"
    local mount_path=""

    for mount_path in "${mount_paths[@]}"; do
      if platform_mount_is_active "$mount_path"; then
        all_gone="no"
        break
      fi
    done

    if [[ "$all_gone" == "yes" ]]; then
      return
    fi

    if [[ -n "${daemon_pid:-}" ]] && ! kill -0 "$daemon_pid" 2>/dev/null; then
      fail "run exited before mounts were torn down"
    fi

    sleep 0.1
  done

  fail "run did not tear mounts down"
}

stop_run_fixture() {
  local status=0
  local mount_path=""

  if [[ -n "${daemon_pid:-}" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill -INT "$daemon_pid" 2>/dev/null || true
  fi

  for mount_path in "${mount_paths[@]}"; do
    if platform_mount_is_active "$mount_path"; then
      platform_stop_mount_path "$mount_path" || true
    fi
  done

  if [[ -n "${daemon_pid:-}" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    wait "$daemon_pid" || status=$?
  fi

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
  config_home_dir=""
  policy_file=""
  password_store_dir=""
  fake_bin_dir=""
  log_file=""

  return "$status"
}

guarded_object_id_for() {
  local target_path="$1"
  local status_output=""

  status_output="$(capture_file_snitch status)"
  STATUS_OUTPUT="$status_output" python3 - "$target_path" <<'PY'
import re
import sys
import os

target = sys.argv[1]
output = os.environ["STATUS_OUTPUT"].splitlines()
pattern = re.compile(r"^enrollment: path=(?P<path>.+) object_id=(?P<object_id>[^ ]+) store_ref=(?P<store_ref>.+)$")

for line in output:
    match = pattern.match(line)
    if match and match.group("path") == target:
        print(match.group("object_id"))
        raise SystemExit(0)

raise SystemExit(1)
PY
}

guarded_store_show_for() {
  local target_path="$1"
  local object_id=""
  local payload=""

  object_id="$(guarded_object_id_for "$target_path")"
  payload="$(PATH="$fake_bin_dir:$PATH" PASSWORD_STORE_DIR="$password_store_dir" pass show "file-snitch/$object_id")"
  PAYLOAD="$payload" python3 - <<'PY'
import base64
import json
import os
import sys

payload = json.loads(os.environ["PAYLOAD"])
sys.stdout.write(base64.b64decode(payload["content_base64"]).decode())
PY
}

guarded_store_write_for() {
  local target_path="$1"
  local content="$2"
  local object_id=""
  local current_payload=""
  local updated_payload=""

  object_id="$(guarded_object_id_for "$target_path")"
  current_payload="$(PATH="$fake_bin_dir:$PATH" PASSWORD_STORE_DIR="$password_store_dir" pass show "file-snitch/$object_id")"
  updated_payload="$(CURRENT_PAYLOAD="$current_payload" python3 - "$content" <<'PY'
import base64
import json
import os
import sys

payload = json.loads(os.environ["CURRENT_PAYLOAD"])
payload["content_base64"] = base64.b64encode(sys.argv[1].encode()).decode()
print(json.dumps(payload, separators=(",", ":")))
PY
)"
  printf '%s' "$updated_payload" | PATH="$fake_bin_dir:$PATH" PASSWORD_STORE_DIR="$password_store_dir" pass insert --multiline --force "file-snitch/$object_id" >/dev/null
}

write_fake_pass_script() {
  cat >"$fake_bin_dir/pass" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

store_dir="${PASSWORD_STORE_DIR:?PASSWORD_STORE_DIR is required}"
command="${1:-}"
shift || true

entry_path() {
  local entry="$1"
  printf '%s/%s' "$store_dir" "$entry"
}

case "$command" in
  show)
    entry="${1:?missing entry}"
    path="$(entry_path "$entry")"
    [[ -f "$path" ]] || exit 1
    cat "$path"
    ;;
  insert)
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -m|--multiline|--force|-f)
          shift
          ;;
        --)
          shift
          break
          ;;
        -*)
          echo "unsupported fake pass insert flag: $1" >&2
          exit 2
          ;;
        *)
          break
          ;;
      esac
    done
    entry="${1:?missing entry}"
    path="$(entry_path "$entry")"
    mkdir -p "$(dirname "$path")"
    cat >"$path"
    ;;
  rm)
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --force|-f)
          shift
          ;;
        --)
          shift
          break
          ;;
        -*)
          echo "unsupported fake pass rm flag: $1" >&2
          exit 2
          ;;
        *)
          break
          ;;
      esac
    done
    entry="${1:?missing entry}"
    path="$(entry_path "$entry")"
    rm -f "$path"
    ;;
  *)
    echo "unsupported fake pass command: $command" >&2
    exit 2
    ;;
esac
EOF
  chmod +x "$fake_bin_dir/pass"
}
