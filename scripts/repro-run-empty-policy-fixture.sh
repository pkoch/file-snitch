#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
iterations=100
keep_success="${KEEP_SUCCESS:-0}"

usage() {
  cat <<'EOF'
usage: scripts/repro-run-empty-policy-fixture.sh [--iterations N] [--keep-success]

This reproduces the exact logic of tests/smoke/run-empty-policy.sh through the
run-fixture helpers, but it preserves the failing fixture and captures daemon
diagnostics before cleanup.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iterations)
      iterations="${2:?missing value for --iterations}"
      shift 2
      ;;
    --keep-success)
      keep_success=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

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

capture_daemon_diagnostics() {
  local root="$1"
  if [[ -n "${daemon_pid:-}" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    ps -o pid,ppid,stat,command -p "$daemon_pid" >"$root/daemon.ps.txt" 2>&1 || true
    if [[ "$(uname -s)" == "Darwin" ]] && command -v sample >/dev/null 2>&1; then
      sample "$daemon_pid" 1 1 >"$root/daemon.sample.txt" 2>&1 || true
    fi
  fi
}

run_once() {
  local iteration="$1"

  prepare_run_fixture "repro-run-empty-policy-$iteration"
  local root="$home_dir"
  local result_file="$root/result.txt"

  {
    echo "iteration=$iteration"
    echo "home_dir=$home_dir"
    echo "policy_file=$policy_file"
    echo "log_file=$log_file"
  } >"$root/meta.txt"

  start_file_snitch_run allow

  sleep 0.3
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    echo "daemon-exited-early" >"$result_file"
    capture_daemon_diagnostics "$root"
    return 1
  fi

  if [[ -s "$log_file" ]]; then
    echo "non-empty-log" >"$result_file"
    capture_daemon_diagnostics "$root"
    return 1
  fi

  local stop_status=0
  stop_run_fixture || stop_status=$?
  printf 'stop_status=%s\n' "$stop_status" >"$result_file"

  if [[ "$stop_status" -ne 0 ]]; then
    capture_daemon_diagnostics "$root"
    return 1
  fi

  if [[ "$keep_success" -ne 1 ]]; then
    [[ -n "$log_file" ]] && rm -f "$log_file"
    [[ -n "$agent_log_file" ]] && rm -f "$agent_log_file"
    remove_tree_with_retries "$root"
  else
    echo "kept fixture=$root"
  fi

  return 0
}

for ((iteration = 1; iteration <= iterations; iteration += 1)); do
  if run_once "$iteration"; then
    echo "ok iteration=$iteration"
  else
    echo "FAIL iteration=$iteration fixture=$home_dir log=$log_file"
    exit 1
  fi
done
