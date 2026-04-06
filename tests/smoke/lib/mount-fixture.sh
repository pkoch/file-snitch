mount_dir=""
store_dir=""
log_file=""
status_fifo=""
status_file=""
status_reader_pid=""
daemon_pid=""
mount_input_fd=""
mount_extra_args=()

prepare_mount_fixture() {
  local fixture_name="$1"

  mount_dir="$(mktemp -d "$TMP_ROOT/${fixture_name}-mount.XXXXXX")"
  store_dir="$(mktemp -d "$TMP_ROOT/${fixture_name}-store.XXXXXX")"
  log_file="$(mktemp "$TMP_ROOT/${fixture_name}-log.XXXXXX")"
  status_fifo="$(mktemp -u "$TMP_ROOT/${fixture_name}-status-fifo.XXXXXX")"
  status_file="$(mktemp "$TMP_ROOT/${fixture_name}-status.XXXXXX")"
  status_reader_pid=""
  daemon_pid=""
  mount_input_fd=""
  mount_extra_args=()

  if declare -F fixture_prepare_extra >/dev/null 2>&1; then
    fixture_prepare_extra
  fi
}

start_status_reader() {
  mkfifo "$status_fifo"
  head -n 1 "$status_fifo" >"$status_file" &
  status_reader_pid="$!"
}

wait_for_mount_ready() {
  local attempts="${1:-100}"

  for _ in $(seq 1 "$attempts"); do
    if [[ -s "$status_file" ]] && platform_mount_is_active "$mount_dir"; then
      return
    fi

    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      fail "mount exited before becoming ready"
    fi

    sleep 0.1
  done

  fail "mount did not become ready"
}

start_file_snitch_mount() {
  local mode="$1"

  start_status_reader

  if [[ -n "$mount_input_fd" ]]; then
    "$repo_root/zig-out/bin/file-snitch" mount "$mount_dir" "$store_dir" "$mode" "${mount_extra_args[@]}" <&$mount_input_fd >"$log_file" 2>&1 &
  else
    "$repo_root/zig-out/bin/file-snitch" mount "$mount_dir" "$store_dir" "$mode" "${mount_extra_args[@]}" >"$log_file" 2>&1 &
  fi
  daemon_pid="$!"
  wait_for_mount_ready
}

stop_mount_fixture() {
  local status=0

  platform_stop_mount || status=$?

  if [[ -n "$status_reader_pid" ]] && kill -0 "$status_reader_pid" 2>/dev/null; then
    kill "$status_reader_pid" 2>/dev/null || true
    wait "$status_reader_pid" || true
  fi

  if declare -F fixture_cleanup_extra >/dev/null 2>&1; then
    fixture_cleanup_extra
  fi

  status_reader_pid=""
  daemon_pid=""
  return "$status"
}

cleanup_mount_fixture() {
  local status=0

  stop_mount_fixture || status=$?

  [[ -n "$mount_dir" ]] && rm -rf "$mount_dir"
  [[ -n "$store_dir" ]] && rm -rf "$store_dir"
  [[ -n "$log_file" ]] && rm -f "$log_file"
  [[ -n "$status_fifo" ]] && rm -f "$status_fifo"
  [[ -n "$status_file" ]] && rm -f "$status_file"

  mount_dir=""
  store_dir=""
  log_file=""
  status_fifo=""
  status_file=""
  mount_input_fd=""
  mount_extra_args=()

  return "$status"
}
