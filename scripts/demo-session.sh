#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
binary_path="${FILE_SNITCH_BIN:-$repo_root/zig-out/bin/file-snitch}"
session_name="file-snitch-demo-$$"

source "$repo_root/tests/smoke/lib/run-fixture.sh"

case "$(uname -s)" in
  Darwin) source "$repo_root/tests/smoke/lib/platform-Darwin.sh" ;;
  Linux) source "$repo_root/tests/smoke/lib/platform-Linux.sh" ;;
  *)
    echo "unsupported platform: $(uname -s)" >&2
    exit 1
    ;;
esac

env_file=""
agent_pane=""
daemon_pane=""
user_pane=""

cleanup() {
  if [[ -n "$session_name" ]]; then
    tmux kill-session -t "$session_name" 2>/dev/null || true
  fi
  stop_run_fixture || true
}

require_tools() {
  for tool in tmux python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      echo "missing required tool: $tool" >&2
      exit 1
    fi
  done

  if [[ ! -x "$binary_path" ]]; then
    echo "expected built file-snitch binary at $binary_path" >&2
    echo "run \`zig build\` first or set FILE_SNITCH_BIN" >&2
    exit 1
  fi

  if [[ -z "${TERM:-}" || "${TERM:-}" == "dumb" ]]; then
    export TERM="xterm-256color"
  fi
}

write_demo_env_file() {
  env_file="$home_dir/demo-env.sh"
  {
    printf 'export PATH=%q\n' "$fake_bin_dir:$PATH"
    printf 'export HOME=%q\n' "$home_dir"
    printf 'export XDG_CONFIG_HOME=%q\n' "$config_home_dir"
    printf 'export XDG_RUNTIME_DIR=%q\n' "$runtime_dir"
    printf 'export PASSWORD_STORE_DIR=%q\n' "$password_store_dir"
    printf 'export FILE_SNITCH_BIN=%q\n' "$binary_path"
    printf 'fs() { %q "$@"; }\n' "$binary_path"
    printf 'export PS1=%q\n' '$ '
  } >"$env_file"
}

pane_send() {
  local pane="$1"
  local command="$2"
  tmux send-keys -t "$pane" "$command" C-m
}

wait_for_file_contains() {
  local path="$1"
  local needle="$2"
  local attempts="${3:-100}"

  for _ in $(seq 1 "$attempts"); do
    if [[ -f "$path" ]] && grep -F "$needle" "$path" >/dev/null 2>&1; then
      return
    fi
    sleep 0.1
  done

  echo "timed out waiting for $path to contain: $needle" >&2
  exit 1
}

wait_for_agent_socket() {
  local socket_path="$runtime_dir/file-snitch/agent.sock"
  local attempts="${1:-100}"

  for _ in $(seq 1 "$attempts"); do
    [[ -S "$socket_path" ]] && return
    sleep 0.1
  done

  echo "timed out waiting for agent socket: $socket_path" >&2
  exit 1
}

wait_for_mount_active_without_pid() {
  local mount_path="$1"
  local attempts="${2:-100}"

  for _ in $(seq 1 "$attempts"); do
    platform_mount_is_active "$mount_path" && return
    sleep 0.1
  done

  echo "timed out waiting for mount to become active: $mount_path" >&2
  exit 1
}

wait_for_mount_gone_without_pid() {
  local mount_path="$1"
  local attempts="${2:-100}"

  for _ in $(seq 1 "$attempts"); do
    ! platform_mount_is_active "$mount_path" && return
    sleep 0.1
  done

  echo "timed out waiting for mount to disappear: $mount_path" >&2
  exit 1
}

setup_tmux_session() {
  tmux new-session -d -s "$session_name" -x 120 -y 36 "bash --noprofile --norc -i"
  tmux set-option -t "$session_name" status off
  tmux set-option -t "$session_name" pane-border-status top
  tmux set-option -t "$session_name" pane-border-format ' #{pane_title} '
  tmux set-option -t "$session_name" remain-on-exit on

  local initial_pane
  initial_pane="$(tmux display-message -p -t "$session_name:0.0" '#{pane_id}')"
  tmux split-window -h -t "$initial_pane" -p 60 "bash --noprofile --norc -i"
  tmux split-window -v -t "$initial_pane" -p 50 "bash --noprofile --norc -i"

  local pane_listing
  pane_listing="$(tmux list-panes -t "$session_name:0" -F '#{pane_id} #{pane_left} #{pane_top}')"
  local min_left
  local min_top
  min_left="$(awk 'NR == 1 || $2 < min { min = $2 } END { print min }' <<<"$pane_listing")"
  min_top="$(awk 'NR == 1 || $3 < min { min = $3 } END { print min }' <<<"$pane_listing")"
  agent_pane="$(awk -v left="$min_left" -v top="$min_top" '$2 == left && $3 == top { print $1 }' <<<"$pane_listing")"
  daemon_pane="$(awk -v left="$min_left" -v top="$min_top" '$2 == left && $3 > top { print $1 }' <<<"$pane_listing")"
  user_pane="$(awk -v left="$min_left" '$2 > left { print $1 }' <<<"$pane_listing")"

  if [[ -z "$agent_pane" || -z "$daemon_pane" || -z "$user_pane" ]]; then
    echo "failed to identify tmux panes" >&2
    exit 1
  fi

  tmux select-pane -t "$agent_pane" -T "agent"
  tmux select-pane -t "$daemon_pane" -T "daemon"
  tmux select-pane -t "$user_pane" -T "user"

  pane_send "$agent_pane" "source '$env_file'; export PS1='[agent]$ '; clear; printf 'file-snitch agent --foreground\\n\\n'; fs agent --foreground"
  wait_for_agent_socket

  pane_send "$daemon_pane" "source '$env_file'; export PS1='[daemon]$ '; clear; printf 'file-snitch run prompt --foreground\\n\\n'; fs run prompt --foreground"

  pane_send "$user_pane" "source '$env_file'; export PS1='[user]$ '; clear; printf 'File Snitch tmux demo\\npolicy: $policy_file\\n\\n'"
  tmux select-pane -t "$user_pane"
}

run_demo_controller() {
  (
    trap 'tmux kill-session -t "$session_name" 2>/dev/null || true' EXIT
    set +e

    sleep 1.0
    pane_send "$user_pane" "ls ~/.kube"
    sleep 1.0
    pane_send "$user_pane" "cat ~/.kube/config"
    sleep 1.2
    pane_send "$user_pane" "fs enroll ~/.kube/config"
    wait_for_file_contains "$policy_file" "$home_dir/.kube/config"
    mount_paths=("$home_dir/.kube")
    wait_for_mount_active_without_pid "$home_dir/.kube"
    sleep 0.8
    pane_send "$user_pane" "ls ~/.kube"
    sleep 1.0
    pane_send "$user_pane" "fs doctor --export-debug-dossier ~/demo-dossier.md"
    sleep 1.2
    pane_send "$user_pane" "cat ~/.kube/config"
    sleep 1.0
    tmux send-keys -t "$agent_pane" Enter
    sleep 1.2
    pane_send "$user_pane" "printf 'updated cache\\n' > ~/.kube/cache && cat ~/.kube/cache"
    sleep 1.2
    pane_send "$user_pane" "printf 'tampered\\n' > ~/.kube/config"
    sleep 1.0
    tmux send-keys -t "$agent_pane" "n" Enter
    sleep 1.2
    pane_send "$user_pane" "cat ~/.kube/config"
    sleep 1.0
    tmux send-keys -t "$agent_pane" Enter
    sleep 1.2
    tmux send-keys -t "$daemon_pane" C-c
    wait_for_mount_gone_without_pid "$home_dir/.kube"
    sleep 0.8
    pane_send "$user_pane" "test -e ~/.kube/config && echo present || echo missing"
    sleep 1.0
    pane_send "$user_pane" "fs unenroll ~/.kube/config"
    sleep 1.0
    pane_send "$user_pane" "cat ~/.kube/config"
    sleep 1.0
    pane_send "$user_pane" "printf '\\nDemo artifacts:\\n- dossier: %s\\n- policy: %s\\n' \"\$HOME/demo-dossier.md\" \"\$XDG_CONFIG_HOME/file-snitch/policy.yml\""
    sleep 2.0
  ) &
}

main() {
  trap cleanup EXIT
  require_tools

  prepare_run_fixture "demo-session"
  mkdir -p "$home_dir/.kube"
  printf 'apiVersion: v1\nclusters: []\n' >"$home_dir/.kube/config"
  printf 'warm cache\n' >"$home_dir/.kube/cache"
  write_demo_env_file

  setup_tmux_session
  run_demo_controller
  tmux attach-session -t "$session_name"
}

main "$@"
