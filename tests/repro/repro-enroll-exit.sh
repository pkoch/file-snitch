#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
binary="${FILE_SNITCH_BIN:-$repo_root/zig-out/bin/file-snitch}"
iterations=50
timeout_seconds="${TIMEOUT_SECONDS:-5}"
keep_success="${KEEP_SUCCESS:-0}"
modes=()

usage() {
  cat <<'EOF'
usage: tests/repro/repro-enroll-exit.sh [--iterations N] [--timeout SECONDS] [--keep-success] [--mode MODE]...

modes:
  direct   run `file-snitch enroll ...` directly
  capture  run `file-snitch enroll ...` inside command substitution
  wrapper  run a tiny wrapper script that execs `file-snitch enroll ...`

environment:
  FILE_SNITCH_BIN  override the file-snitch binary path
  TIMEOUT_SECONDS  per-attempt timeout before the script samples and kills a stuck process
  KEEP_SUCCESS=1   keep successful fixtures instead of deleting them
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iterations)
      iterations="${2:?missing value for --iterations}"
      shift 2
      ;;
    --timeout)
      timeout_seconds="${2:?missing value for --timeout}"
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
  modes=(direct capture wrapper)
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

make_fixture() {
  local fixture_name="$1"
  local root
  root="$(mktemp -d "$fake_tmp_root/${fixture_name}.XXXXXX")"

  local home_dir="$root/home"
  local config_home_dir="$home_dir/.config"
  local runtime_dir="$home_dir/.run"
  local password_store_dir="$home_dir/.password-store"
  local fake_bin_dir="$home_dir/.local/file-snitch-test-bin"
  local target_dir="$home_dir/.kube"
  local target_path="$target_dir/config"
  local policy_file="$config_home_dir/file-snitch/policy.yml"
  local wrapper_script="$root/run-enroll-wrapper.sh"

  mkdir -p \
    "$config_home_dir/file-snitch" \
    "$runtime_dir" \
    "$password_store_dir" \
    "$fake_bin_dir" \
    "$target_dir"
  printf 'plain kube config\n' >"$target_path"

  write_fake_pass_script "$fake_bin_dir"

  cat >"$wrapper_script" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec "$binary" enroll "$target_path" --policy "$policy_file"
EOF
  chmod +x "$wrapper_script"

  cat <<EOF
$root
$home_dir
$config_home_dir
$runtime_dir
$password_store_dir
$fake_bin_dir
$target_path
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

run_mode() {
  local mode="$1"
  local iteration="$2"

  mapfile -t fixture < <(make_fixture "repro-enroll-exit-${mode}-${iteration}")
  local root="${fixture[0]}"
  local home_dir="${fixture[1]}"
  local config_home_dir="${fixture[2]}"
  local runtime_dir="${fixture[3]}"
  local password_store_dir="${fixture[4]}"
  local fake_bin_dir="${fixture[5]}"
  local target_path="${fixture[6]}"
  local policy_file="${fixture[7]}"
  local wrapper_script="${fixture[8]}"

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
    echo "target_path=$target_path"
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
        "$binary" enroll "$target_path" --policy "$policy_file"
        ;;
      capture)
        output="$("$binary" enroll "$target_path" --policy "$policy_file" 2>&1)"
        printf '%s\n' "$output"
        ;;
      wrapper)
        "$wrapper_script"
        ;;
      *)
        echo "unsupported mode: $mode" >&2
        exit 2
        ;;
    esac
  ) >"$stdout_file" 2>"$stderr_file" &
  pid="$!"

  local attempt
  local timed_out=1
  for ((attempt = 0; attempt < timeout_seconds * 10; attempt += 1)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      timed_out=0
      break
    fi
    sleep 0.1
  done

  if [[ "$timed_out" -eq 1 ]]; then
    echo "timeout" >"$status_file"
    capture_process_diagnostics "$pid" "$root" "timeout"
    kill -TERM "$pid" 2>/dev/null || true
    sleep 0.2
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" || true
    echo "FAIL mode=$mode iteration=$iteration reason=timeout fixture=$root"
    return 1
  fi

  local wait_status=0
  wait "$pid" || wait_status=$?
  printf '%s\n' "$wait_status" >"$status_file"

  if [[ "$wait_status" -ne 0 ]]; then
    capture_process_diagnostics "$pid" "$root" "exit"
    echo "FAIL mode=$mode iteration=$iteration exit=$wait_status fixture=$root"
    return 1
  fi

  echo "ok mode=$mode iteration=$iteration"

  if [[ "$keep_success" -ne 1 ]]; then
    rm -rf "$root"
  else
    echo "kept fixture=$root"
  fi
}

for mode in "${modes[@]}"; do
  case "$mode" in
    direct|capture|wrapper) ;;
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
