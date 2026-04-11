#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
manifest="$repo_root/release-inputs.json"
output=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      output="$2"
      shift 2
      ;;
    --manifest)
      manifest="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

[[ -n "$output" ]] || { echo "--output is required" >&2; exit 1; }

dmg_url="$(python3 - "$manifest" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
print(data["macfuse"]["dmg_url"])
PY
)"

dmg_sha256="$(python3 - "$manifest" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
print(data["macfuse"]["sha256"])
PY
)"

pkg_path="$(python3 - "$manifest" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
print(data["macfuse"]["pkg_path"])
PY
)"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/file-snitch-macfuse.XXXXXX")"
cleanup() {
  if [[ -n "${mount_point:-}" && -d "${mount_point:-}" ]]; then
    hdiutil detach "$mount_point" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

dmg_path="$tmp_dir/macfuse.dmg"
curl -L --fail --silent --show-error "$dmg_url" -o "$dmg_path"

actual_sha256="$(python3 - "$dmg_path" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
digest = hashlib.sha256()
with path.open("rb") as handle:
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
print(digest.hexdigest())
PY
)"

if [[ "$actual_sha256" != "$dmg_sha256" ]]; then
  echo "macFUSE DMG checksum mismatch" >&2
  exit 1
fi

hdiutil attach -nobrowse -readonly "$dmg_path" > "$tmp_dir/attach.txt"
mount_point="$(awk '/\/Volumes\// { mp = $NF } END { print mp }' "$tmp_dir/attach.txt")"
[[ -n "$mount_point" ]] || { echo "failed to resolve macFUSE mount point" >&2; exit 1; }

pkgutil --expand-full "$mount_point/$pkg_path" "$tmp_dir/pkg" >/dev/null

mkdir -p "$output/include" "$output/lib"
cp -R "$tmp_dir/pkg/Core.pkg/Payload/usr/local/include/." "$output/include/"
cp -R "$tmp_dir/pkg/Core.pkg/Payload/usr/local/lib/." "$output/lib/"
