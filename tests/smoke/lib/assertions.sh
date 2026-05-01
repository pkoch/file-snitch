fail() {
  echo "$1" >&2
  echo "--- file-snitch log ---" >&2
  if [[ -f "${log_file:-non_existing_path}" ]]; then
    cat "$log_file" >&2 || true
  else
    echo "log file not found: ${log_file:-'$log_file variable not set.'}"
  fi
  exit 1
}

assert_eq() {
  local actual="$1"
  local expected="$2"
  local message="$3"

  if [[ "$actual" != "$expected" ]]; then
    fail "$message"
  fi
}

assert_projected_file_eq_eventually() {
  local path="$1"
  local expected="$2"
  local message="$3"
  local attempts="${4:-50}"
  local actual=""
  local last_error=""
  local error_file=""

  if ! error_file="$(mktemp "${TMP_ROOT:-/tmp}/file-snitch-read.XXXXXX")"; then
    fail "failed to create temporary file under ${TMP_ROOT:-/tmp}"
  fi
  for _ in $(seq 1 "$attempts"); do
    if actual="$(cat "$path" 2>"$error_file")"; then
      if [[ "$actual" == "$expected" ]]; then
        rm -f "$error_file"
        return
      fi
      last_error=""
    else
      actual=""
      last_error="$(cat "$error_file" 2>/dev/null || true)"
    fi
    sleep 0.1
  done

  rm -f "$error_file"
  if [[ -n "$last_error" ]]; then
    echo "last projected read error for $path: $last_error" >&2
  fi
  if [[ -n "$actual" ]]; then
    echo "last projected read output for $path: $actual" >&2
  fi
  fail "$message"
}

assert_file_exists() {
  local path="$1"
  local message="$2"

  [[ -f "$path" ]] || fail "$message"
}

assert_file_contains() {
  local path="$1"
  local needle="$2"

  if ! grep -F "$needle" "$path" >/dev/null 2>&1; then
    fail "expected file entry missing from $path: $needle"
  fi
}

assert_file_missing() {
  local path="$1"
  local message="$2"

  [[ ! -e "$path" ]] || fail "$message"
}

assert_store_file_contents() {
  local path="$1"
  local expected="$2"
  local message="$3"

  assert_eq "$(cat "$path")" "$expected" "$message"
}

assert_log_contains() {
  local needle="$1"

  if ! grep -F "$needle" "$log_file" >/dev/null 2>&1; then
    fail "expected log entry missing: $needle"
  fi
}

assert_log_matches() {
  local pattern="$1"

  if ! grep -E "$pattern" "$log_file" >/dev/null 2>&1; then
    fail "expected log entry missing for pattern: $pattern"
  fi
}
