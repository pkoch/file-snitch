home_dir=""
config_home_dir=""
runtime_dir=""
policy_file=""
password_store_dir=""
fake_bin_dir=""
log_file=""
daemon_pid=""
run_input_fd=""
agent_log_file=""
agent_pid=""
agent_input_fd=""
agent_frontend_args=()
mount_paths=()
fake_ui_queue_file=""

prepare_run_fixture() {
  local fixture_name="$1"

  home_dir="$(mktemp -d "$TMP_ROOT/${fixture_name}-home.XXXXXX")"
  config_home_dir="$home_dir/.config"
  runtime_dir="$home_dir/.run"
  policy_file="$config_home_dir/file-snitch/policy.yml"
  password_store_dir="$home_dir/.password-store"
  fake_bin_dir="$home_dir/.local/file-snitch-test-bin"
  log_file="$(mktemp "$TMP_ROOT/${fixture_name}-log.XXXXXX")"
  agent_log_file="$(mktemp "$TMP_ROOT/${fixture_name}-agent-log.XXXXXX")"
  daemon_pid=""
  run_input_fd=""
  agent_pid=""
  agent_input_fd=""
  agent_frontend_args=()
  mount_paths=()
  fake_ui_queue_file=""

  mkdir -p \
    "$config_home_dir/file-snitch" \
    "$runtime_dir" \
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
    XDG_RUNTIME_DIR="$runtime_dir" \
    PASSWORD_STORE_DIR="$password_store_dir" \
    "$repo_root/zig-out/bin/file-snitch" "$@"
}

capture_file_snitch() {
  PATH="$fake_bin_dir:$PATH" \
    HOME="$home_dir" \
    XDG_CONFIG_HOME="$config_home_dir" \
    XDG_RUNTIME_DIR="$runtime_dir" \
    PASSWORD_STORE_DIR="$password_store_dir" \
    "$repo_root/zig-out/bin/file-snitch" "$@" 2>&1
}

start_file_snitch_run() {
  local mode="$1"

  if [[ -n "$run_input_fd" ]]; then
    PATH="$fake_bin_dir:$PATH" \
      HOME="$home_dir" \
      XDG_CONFIG_HOME="$config_home_dir" \
      XDG_RUNTIME_DIR="$runtime_dir" \
      PASSWORD_STORE_DIR="$password_store_dir" \
      "$repo_root/zig-out/bin/file-snitch" run "$mode" <&$run_input_fd >"$log_file" 2>&1 &
  else
    PATH="$fake_bin_dir:$PATH" \
      HOME="$home_dir" \
      XDG_CONFIG_HOME="$config_home_dir" \
      XDG_RUNTIME_DIR="$runtime_dir" \
      PASSWORD_STORE_DIR="$password_store_dir" \
      "$repo_root/zig-out/bin/file-snitch" run "$mode" >"$log_file" 2>&1 &
  fi
  daemon_pid="$!"

  wait_for_mounts_ready
}

start_file_snitch_agent() {
  if [[ -n "$agent_input_fd" ]]; then
    PATH="$fake_bin_dir:$PATH" \
      HOME="$home_dir" \
      XDG_CONFIG_HOME="$config_home_dir" \
      XDG_RUNTIME_DIR="$runtime_dir" \
      PASSWORD_STORE_DIR="$password_store_dir" \
      "$repo_root/zig-out/bin/file-snitch" agent "${agent_frontend_args[@]}" <&$agent_input_fd >"$agent_log_file" 2>&1 &
  else
    PATH="$fake_bin_dir:$PATH" \
      HOME="$home_dir" \
      XDG_CONFIG_HOME="$config_home_dir" \
      XDG_RUNTIME_DIR="$runtime_dir" \
      PASSWORD_STORE_DIR="$password_store_dir" \
      "$repo_root/zig-out/bin/file-snitch" agent "${agent_frontend_args[@]}" >"$agent_log_file" 2>&1 &
  fi
  agent_pid="$!"

  wait_for_agent_ready
}

wait_for_agent_ready() {
  local attempts="${1:-100}"
  local socket_path="$runtime_dir/file-snitch/agent.sock"

  for _ in $(seq 1 "$attempts"); do
    if [[ -S "$socket_path" ]]; then
      return
    fi

    if [[ -n "${agent_pid:-}" ]] && ! kill -0 "$agent_pid" 2>/dev/null; then
      fail "agent exited before socket became ready"
    fi

    sleep 0.1
  done

  fail "agent did not create its socket"
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

  if [[ ${#mount_paths[@]} -gt 0 ]]; then
    wait_for_mounts_gone || status=$?
  fi

  if [[ -n "${daemon_pid:-}" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    if ! wait_for_daemon_exit "$daemon_pid" 20; then
      kill -TERM "$daemon_pid" 2>/dev/null || true
      if ! wait_for_daemon_exit "$daemon_pid" 20; then
        kill -KILL "$daemon_pid" 2>/dev/null || true
        wait_for_daemon_exit "$daemon_pid" 20 || status=$?
      fi
    fi

    wait_for_run_process "$daemon_pid" || status=$?
  fi

  if declare -F fixture_cleanup_extra >/dev/null 2>&1; then
    fixture_cleanup_extra
  fi

  daemon_pid=""
  run_input_fd=""
  if [[ -n "${agent_pid:-}" ]] && kill -0 "$agent_pid" 2>/dev/null; then
    kill -INT "$agent_pid" 2>/dev/null || true
    if ! wait_for_daemon_exit "$agent_pid" 20; then
      kill -TERM "$agent_pid" 2>/dev/null || true
      if ! wait_for_daemon_exit "$agent_pid" 20; then
        kill -KILL "$agent_pid" 2>/dev/null || true
        wait_for_daemon_exit "$agent_pid" 20 || status=$?
      fi
    fi

    wait_for_run_process "$agent_pid" || status=$?
  fi
  agent_pid=""
  agent_input_fd=""
  agent_frontend_args=()
  mount_paths=()
  return "$status"
}

wait_for_daemon_exit() {
  local pid="$1"
  local attempts="${2:-100}"

  for _ in $(seq 1 "$attempts"); do
    if ! kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done

  return 1
}

wait_for_run_process() {
  local pid="$1"
  local wait_status=0

  wait "$pid" || wait_status=$?
  case "$wait_status" in
    0|130|143)
      return 0
      ;;
    *)
      return "$wait_status"
      ;;
  esac
}

cleanup_run_fixture() {
  local status=0

  stop_run_fixture || status=$?

  [[ -n "$log_file" ]] && rm -f "$log_file"
  [[ -n "$agent_log_file" ]] && rm -f "$agent_log_file"
  if [[ -n "$home_dir" ]]; then
    remove_tree_with_retries "$home_dir" || status=$?
  fi

  home_dir=""
  config_home_dir=""
  runtime_dir=""
  policy_file=""
  password_store_dir=""
  fake_bin_dir=""
  log_file=""
  agent_log_file=""
  agent_frontend_args=()
  fake_ui_queue_file=""

  return "$status"
}

remove_tree_with_retries() {
  local path="$1"
  local attempts="${2:-20}"

  for _ in $(seq 1 "$attempts"); do
    if rm -rf "$path" 2>/dev/null; then
      [[ ! -e "$path" ]] && return 0
    fi
    sleep 0.1
  done

  rm -rf "$path"
}

write_fake_osascript_script() {
  fake_ui_queue_file="$home_dir/.local/file-snitch-fake-osascript.queue"
  cat >"$fake_bin_dir/osascript" <<EOF
#!/usr/bin/env bash
set -euo pipefail

queue_path="$fake_ui_queue_file"

if [[ ! -f "\$queue_path" ]]; then
  echo "allow"
  exit 0
fi

response="\$(head -n 1 "\$queue_path" || true)"
if [[ -s "\$queue_path" ]]; then
  tail -n +2 "\$queue_path" >"\$queue_path.next" || true
  mv "\$queue_path.next" "\$queue_path"
fi

case "\$response" in
  allow|deny|timeout)
    printf '%s\n' "\$response"
    ;;
  "")
    printf 'allow\n'
    ;;
  *)
    printf '%s\n' "\$response"
    ;;
esac
EOF
  chmod +x "$fake_bin_dir/osascript"
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
  ls)
    mkdir -p "$store_dir"
    find "$store_dir" -type f | sed "s#^$store_dir/##" | sort
    ;;
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
