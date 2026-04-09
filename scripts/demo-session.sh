#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
binary_path="${FILE_SNITCH_BIN:-$repo_root/zig-out/bin/file-snitch}"

source "$repo_root/tests/smoke/lib/run-fixture.sh"

case "$(uname -s)" in
  Darwin) source "$repo_root/tests/smoke/lib/platform-Darwin.sh" ;;
  Linux) source "$repo_root/tests/smoke/lib/platform-Linux.sh" ;;
  *)
    echo "unsupported platform: $(uname -s)" >&2
    exit 1
    ;;
esac

repo_root="$repo_root"

cleanup() {
  stop_run_fixture
}

print_step() {
  printf '\n$ %s\n' "$1"
}

show_command_output() {
  local description="$1"
  shift

  print_step "$description"
  "$@"
}

show_file() {
  local path="$1"
  print_step "cat $path"
  cat "$path"
}

main() {
  trap cleanup EXIT

  if [[ ! -x "$binary_path" ]]; then
    echo "expected built file-snitch binary at $binary_path" >&2
    echo "run \`zig build\` first or set FILE_SNITCH_BIN" >&2
    exit 1
  fi

  prepare_run_fixture "demo-session"
  mkdir -p "$home_dir/.kube"
  printf 'apiVersion: v1\nclusters: []\n' >"$home_dir/.kube/config"
  printf 'warm cache\n' >"$home_dir/.kube/cache"

  cat <<EOF
File Snitch demo session
repo: $repo_root
temp home: $home_dir
policy: $policy_file
EOF

  show_file "$home_dir/.kube/config"
  show_file "$home_dir/.kube/cache"

  show_command_output \
    "$binary_path enroll $home_dir/.kube/config" \
    env PATH="$fake_bin_dir:$PATH" HOME="$home_dir" XDG_CONFIG_HOME="$config_home_dir" XDG_RUNTIME_DIR="$runtime_dir" PASSWORD_STORE_DIR="$password_store_dir" \
      "$binary_path" enroll "$home_dir/.kube/config"

  print_step "guarded object payload from fake pass"
  guarded_store_show_for "$home_dir/.kube/config"

  show_command_output \
    "$binary_path doctor --export-debug-dossier $home_dir/demo-dossier.md" \
    env PATH="$fake_bin_dir:$PATH" HOME="$home_dir" XDG_CONFIG_HOME="$config_home_dir" XDG_RUNTIME_DIR="$runtime_dir" PASSWORD_STORE_DIR="$password_store_dir" \
      "$binary_path" doctor --export-debug-dossier "$home_dir/demo-dossier.md"

  print_step "$binary_path run allow --foreground"
  PATH="$fake_bin_dir:$PATH" \
    HOME="$home_dir" \
    XDG_CONFIG_HOME="$config_home_dir" \
    XDG_RUNTIME_DIR="$runtime_dir" \
    PASSWORD_STORE_DIR="$password_store_dir" \
    "$binary_path" run allow --foreground >"$log_file" 2>&1 &
  daemon_pid="$!"
  mount_paths=("$home_dir/.kube")
  run_mode="allow"
  run_execution_mode="--foreground"
  wait_for_mounts_ready

  show_file "$home_dir/.kube/config"

  print_step "printf 'updated cache\n' > $home_dir/.kube/cache"
  printf 'updated cache\n' >"$home_dir/.kube/cache"
  show_file "$home_dir/.kube/cache"

  stop_run_fixture

  print_step "test -e $home_dir/.kube/config && echo present || echo missing"
  if [[ -e "$home_dir/.kube/config" ]]; then
    echo "present"
  else
    echo "missing"
  fi

  show_command_output \
    "$binary_path unenroll $home_dir/.kube/config" \
    env PATH="$fake_bin_dir:$PATH" HOME="$home_dir" XDG_CONFIG_HOME="$config_home_dir" XDG_RUNTIME_DIR="$runtime_dir" PASSWORD_STORE_DIR="$password_store_dir" \
      "$binary_path" unenroll "$home_dir/.kube/config"

  show_file "$home_dir/.kube/config"

  cat <<EOF

Demo artifacts:
- dossier: $home_dir/demo-dossier.md
- run log: $log_file
EOF
}

main "$@"
