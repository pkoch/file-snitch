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
