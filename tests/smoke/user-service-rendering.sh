#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
source "$repo_root/tests/smoke/lib/assertions.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

mkdir -p "$tmp_dir/bin"
cat >"$tmp_dir/bin/file-snitch" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$tmp_dir/bin/file-snitch"

macos_output_dir="$tmp_dir/macos"
linux_output_dir="$tmp_dir/linux"
mkdir -p "$macos_output_dir" "$linux_output_dir"

"$repo_root/scripts/services/render-user-services.sh" \
  --platform macos \
  --bin "$tmp_dir/bin/file-snitch" \
  --output-dir "$macos_output_dir"

"$repo_root/scripts/services/render-user-services.sh" \
  --platform linux \
  --bin "$tmp_dir/bin/file-snitch" \
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
assert_file_contains "$linux_output_dir/file-snitch-agent.service" "ExecStart=$tmp_dir/bin/file-snitch agent --frontend linux-ui"
assert_file_contains "$linux_output_dir/file-snitch-run.service" "ExecStart=$tmp_dir/bin/file-snitch run prompt"
