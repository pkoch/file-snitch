#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
binary="${FILE_SNITCH_BIN:-$repo_root/zig-out/bin/file-snitch}"
iterations=100
ready_sleep="${READY_SLEEP_SECONDS:-0.3}"
int_wait="${INT_WAIT_SECONDS:-2}"
term_wait="${TERM_WAIT_SECONDS:-2}"
keep_success="${KEEP_SUCCESS:-0}"
modes=()

usage() {
  cat <<'EOF'
usage: tests/repro/repro-run-exit.sh [--iterations N] [--ready-sleep SECONDS] [--int-wait SECONDS] [--term-wait SECONDS] [--keep-success] [--mode MODE]...

modes:
  direct   run `file-snitch run allow --foreground` directly in the background
  wrapper  run a tiny wrapper script that execs the same command

The script reproduces the empty-policy foreground run case, then tears it down
using the same signal escalation as the smoke harness: SIGINT, wait, SIGTERM,
wait, SIGKILL.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iterations)
      iterations="${2:?missing value for --iterations}"
      shift 2
      ;;
    --ready-sleep)
      ready_sleep="${2:?missing value for --ready-sleep}"
      shift 2
      ;;
    --int-wait)
      int_wait="${2:?missing value for --int-wait}"
      shift 2
      ;;
    --term-wait)
      term_wait="${2:?missing value for --term-wait}"
      shift 2
      ;;
    --keep-success)
      keep_success=1
      shift
      ;;
    --mode)
      modes+=("${2:?missing value for --mode}")
      shift 2
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

if [[ ${#modes[@]} -eq 0 ]]; then
  modes=(direct wrapper)
fi

if [[ ! -x "$binary" ]]; then
  echo "file-snitch binary is missing or not executable: $binary" >&2
  exit 1
fi

fake_tmp_root="${TMPDIR:-/tmp}"

write_fake_pass_script() {
  local fake_bin_dir="$1"

  cat >"$fake_bin_dir/pass" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exit 0
EOF
  chmod +x "$fake_bin_dir/pass"
}

make_fixture() {
  local fixture_name="$1"
  local root
  root="$(mktemp -d "$fake_tmp_root/${fixture_name}.XXXXXX")"

  local home_dir="$root/home"
  local config_home_dir="$home_dir/.config"
  local runtime_dir="$home_dir/.run"
  local password_store_dir="$home_dir/.password-store"
  local fake_bin_dir="$home_dir/.local/file-snitch-test-bin"
  local policy_file="$config_home_dir/file-snitch/policy.yml"
  local wrapper_script="$root/run-wrapper.sh"

  mkdir -p \
    "$config_home_dir/file-snitch" \
    "$runtime_dir" \
    "$password_store_dir" \
    "$fake_bin_dir"

  write_fake_pass_script "$fake_bin_dir"

  cat >"$wrapper_script" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec "$binary" run allow --foreground --policy "$policy_file"
EOF
  chmod +x "$wrapper_script"

  cat <<EOF
$root
$home_dir
$config_home_dir
$runtime_dir
$password_store_dir
$fake_bin_dir
$policy_file
$wrapper_script
EOF
}

capture_process_diagnostics() {
  local pid="$1"
  local root="$2"
  local label="$3"

  ps -o pid,ppid,stat,command -p "$pid" >"$root/$label.ps.txt" 2>&1 || true
  if [[ "$(uname -s)" == "Darwin" ]] && command -v sample >/dev/null 2>&1; then
    sample "$pid" 1 1 >"$root/$label.sample.txt" 2>&1 || true
  fi
}

wait_for_exit() {
  local pid="$1"
  local seconds="$2"
  local attempts
  attempts="$(awk "BEGIN { print int($seconds * 10) }")"
  local i
  for ((i = 0; i < attempts; i += 1)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

run_mode() {
  local mode="$1"
  local iteration="$2"

  mapfile -t fixture < <(make_fixture "repro-run-exit-${mode}-${iteration}")
  local root="${fixture[0]}"
  local home_dir="${fixture[1]}"
  local config_home_dir="${fixture[2]}"
  local runtime_dir="${fixture[3]}"
  local password_store_dir="${fixture[4]}"
  local fake_bin_dir="${fixture[5]}"
  local policy_file="${fixture[6]}"
  local wrapper_script="${fixture[7]}"

  local stdout_file="$root/stdout.txt"
  local stderr_file="$root/stderr.txt"
  local meta_file="$root/meta.txt"
  local status_file="$root/status.txt"
  local pid

  {
    echo "mode=$mode"
    echo "iteration=$iteration"
    echo "binary=$binary"
    echo "root=$root"
    echo "policy_file=$policy_file"
  } >"$meta_file"

  (
    export PATH="$fake_bin_dir:$PATH"
    export HOME="$home_dir"
    export XDG_CONFIG_HOME="$config_home_dir"
    export XDG_RUNTIME_DIR="$runtime_dir"
    export PASSWORD_STORE_DIR="$password_store_dir"

    case "$mode" in
      direct)
        exec "$binary" run allow --foreground --policy "$policy_file"
        ;;
      wrapper)
        exec "$wrapper_script"
        ;;
      *)
        echo "unsupported mode: $mode" >&2
        exit 2
        ;;
    esac
  ) >"$stdout_file" 2>"$stderr_file" &
  pid="$!"
  printf '%s\n' "$pid" >"$root/pid.txt"

  sleep "$ready_sleep"
  if ! kill -0 "$pid" 2>/dev/null; then
    local early_status=0
    wait "$pid" || early_status=$?
    printf '%s\n' "$early_status" >"$status_file"
    echo "FAIL mode=$mode iteration=$iteration reason=early-exit exit=$early_status fixture=$root"
    return 1
  fi

  kill -INT "$pid" 2>/dev/null || true
  if wait_for_exit "$pid" "$int_wait"; then
    local int_status=0
    wait "$pid" || int_status=$?
    printf '%s\n' "$int_status" >"$status_file"
    case "$int_status" in
      0|130|143)
        echo "ok mode=$mode iteration=$iteration exit=$int_status"
        if [[ "$keep_success" -ne 1 ]]; then
          rm -rf "$root"
        else
          echo "kept fixture=$root"
        fi
        return 0
        ;;
      *)
        capture_process_diagnostics "$pid" "$root" "int-exit"
        echo "FAIL mode=$mode iteration=$iteration reason=bad-int-exit exit=$int_status fixture=$root"
        return 1
        ;;
    esac
  fi

  capture_process_diagnostics "$pid" "$root" "post-int"

  kill -TERM "$pid" 2>/dev/null || true
  if wait_for_exit "$pid" "$term_wait"; then
    local term_status=0
    wait "$pid" || term_status=$?
    printf '%s\n' "$term_status" >"$status_file"
    case "$term_status" in
      0|130|143)
        echo "ok mode=$mode iteration=$iteration exit=$term_status after=term"
        if [[ "$keep_success" -ne 1 ]]; then
          rm -rf "$root"
        else
          echo "kept fixture=$root"
        fi
        return 0
        ;;
      *)
        capture_process_diagnostics "$pid" "$root" "term-exit"
        echo "FAIL mode=$mode iteration=$iteration reason=bad-term-exit exit=$term_status fixture=$root"
        return 1
        ;;
    esac
  fi

  capture_process_diagnostics "$pid" "$root" "post-term"
  kill -KILL "$pid" 2>/dev/null || true
  local kill_status=0
  wait "$pid" || kill_status=$?
  printf '%s\n' "$kill_status" >"$status_file"
  echo "FAIL mode=$mode iteration=$iteration reason=stuck-after-term exit=$kill_status fixture=$root"
  return 1
}

for mode in "${modes[@]}"; do
  case "$mode" in
    direct|wrapper) ;;
    *)
      echo "unsupported mode: $mode" >&2
      exit 2
      ;;
  esac
done

for mode in "${modes[@]}"; do
  for ((iteration = 1; iteration <= iterations; iteration += 1)); do
    run_mode "$mode" "$iteration" || exit 1
  done
done
