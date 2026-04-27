#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
source "$repo_root/tests/smoke/lib/assertions.sh"

file_snitch_bin="$repo_root/zig-out/bin/file-snitch"
[[ -x "$file_snitch_bin" ]] || {
  echo "file-snitch binary is missing; run zig build first" >&2
  exit 1
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

mkdir -p "$tmp_dir/bin"
cat >"$tmp_dir/bin/file-snitch" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$tmp_dir/bin/file-snitch"
cat >"$tmp_dir/bin/pass" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$tmp_dir/bin/pass"

macos_output_dir="$tmp_dir/macos"
linux_output_dir="$tmp_dir/linux"
mkdir -p "$macos_output_dir" "$linux_output_dir"

"$file_snitch_bin" services render \
  --platform macos \
  --bin "$tmp_dir/bin/file-snitch" \
  --pass-bin "$tmp_dir/bin/pass" \
  --output-dir "$macos_output_dir"

"$file_snitch_bin" services render \
  --platform linux \
  --bin "$tmp_dir/bin/file-snitch" \
  --pass-bin "$tmp_dir/bin/pass" \
  --output-dir "$linux_output_dir"

assert_eq \
  "$(test -f "$macos_output_dir/dev.file-snitch.agent.plist" && printf yes || printf no)" \
  "yes" \
  "expected macOS agent LaunchAgent to be rendered"

assert_eq \
  "$(test -f "$macos_output_dir/dev.file-snitch.run.plist" && printf yes || printf no)" \
  "yes" \
  "expected macOS run LaunchAgent to be rendered"

assert_eq \
  "$(test -f "$linux_output_dir/file-snitch-run.service" && printf yes || printf no)" \
  "yes" \
  "expected Linux systemd unit to be rendered"

assert_eq \
  "$(test -f "$linux_output_dir/file-snitch-agent.service" && printf yes || printf no)" \
  "yes" \
  "expected Linux agent systemd unit to be rendered"

assert_file_contains "$macos_output_dir/dev.file-snitch.agent.plist" "<string>$tmp_dir/bin/file-snitch</string>"
assert_file_contains "$macos_output_dir/dev.file-snitch.agent.plist" "<string>macos-ui</string>"
assert_file_contains "$macos_output_dir/dev.file-snitch.run.plist" "<string>prompt</string>"
assert_file_contains "$macos_output_dir/dev.file-snitch.run.plist" "<key>FILE_SNITCH_PASS_BIN</key>"
assert_file_contains "$macos_output_dir/dev.file-snitch.run.plist" "<string>$tmp_dir/bin/pass</string>"
assert_file_contains "$macos_output_dir/dev.file-snitch.run.plist" "<key>PATH</key>"
assert_file_contains "$macos_output_dir/dev.file-snitch.run.plist" "<string>$tmp_dir/bin:/opt/homebrew/opt/gnu-getopt/bin:/usr/local/opt/gnu-getopt/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>"
assert_file_contains "$linux_output_dir/file-snitch-agent.service" "ExecStart=$tmp_dir/bin/file-snitch agent --frontend linux-ui"
assert_file_contains "$linux_output_dir/file-snitch-run.service" "Environment=FILE_SNITCH_PASS_BIN=$tmp_dir/bin/pass"
assert_file_contains "$linux_output_dir/file-snitch-run.service" "ExecStart=$tmp_dir/bin/file-snitch run prompt"
