#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

usage() {
  cat <<'EOF'
usage: ./scripts/do-release.sh <major|minor|patch>

This script:
  - verifies the worktree is clean
  - bumps VERSION
  - rolls CHANGELOG.md
  - regenerates the stable Homebrew source block for the new release
  - creates one release commit
  - creates an annotated tag
  - pushes the branch and tag to trigger the release workflow
EOF
}

require_release_tools() {
  command -v gh >/dev/null 2>&1 || {
    echo "error: gh is required for release monitoring" >&2
    exit 1
  }
  command -v python3 >/dev/null 2>&1 || {
    echo "error: python3 is required" >&2
    exit 1
  }
  command -v zig >/dev/null 2>&1 || {
    echo "error: zig is required" >&2
    exit 1
  }

  gh auth status >/dev/null 2>&1 || {
    echo "error: gh must be authenticated before releasing" >&2
    exit 1
  }
}

if [[ $# -ne 1 ]]; then
  usage
  exit 1
fi

part="$1"
case "$part" in
  major|minor|patch) ;;
  *)
    usage
    exit 1
    ;;
esac

if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: worktree must be clean before releasing" >&2
  exit 1
fi

require_release_tools

current_version="$(tr -d '\n' < VERSION)"
new_version="$(python3 - "$current_version" "$part" <<'PY'
import sys

version = sys.argv[1].strip()
part = sys.argv[2]
major, minor, patch = [int(value) for value in version.split(".")]
if part == "major":
    major += 1
    minor = 0
    patch = 0
elif part == "minor":
    minor += 1
    patch = 0
else:
    patch += 1
print(f"{major}.{minor}.{patch}")
PY
)"

release_date="$(date -u +%F)"
tag="v$new_version"
source_asset="file-snitch-$new_version-source.tar.gz"
source_url="https://github.com/pkoch/file-snitch/releases/download/$tag/$source_asset"
source_date_epoch="$(git show -s --format=%ct HEAD)"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/file-snitch-release.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

run_host_release_sanity() {
  local host_os
  local host_arch
  local host_platform=""
  local host_target=""
  local host_output

  host_os="$(uname -s)"
  host_arch="$(uname -m)"
  case "$host_os-$host_arch" in
    Darwin-arm64)
      host_platform="macos-arm64"
      host_target="aarch64-macos"
      ;;
    Linux-x86_64)
      host_platform="linux-x86_64"
      host_target="x86_64-linux-gnu"
      ;;
    *)
      echo "warning: no local release-artifact sanity build for $host_os-$host_arch" >&2
      return 0
      ;;
  esac

  host_output="$tmp_dir/file-snitch-$new_version-$host_platform.tar.gz"

  if [[ "$host_platform" == "macos-arm64" ]]; then
    local sdk_dir="$tmp_dir/macfuse-sdk"
    ./scripts/extract-macfuse-sdk.sh --output "$sdk_dir"
    FILE_SNITCH_FUSE_INCLUDE_DIR="$sdk_dir/include" \
    FILE_SNITCH_FUSE_LIB_DIR="$sdk_dir/lib" \
    ZIG_BUILD_TARGET="$host_target" \
    ./scripts/build-release-artifact.sh \
      --version "$new_version" \
      --platform "$host_platform" \
      --source-date-epoch "$source_date_epoch" \
      --output "$host_output"
    return 0
  fi

  ZIG_BUILD_TARGET="$host_target" \
  ./scripts/build-release-artifact.sh \
    --version "$new_version" \
    --platform "$host_platform" \
    --source-date-epoch "$source_date_epoch" \
    --output "$host_output"
}

wait_for_release_run() {
  local release_commit="$1"
  local run_id=""
  local attempts=0

  while [[ $attempts -lt 40 ]]; do
    run_id="$(gh run list \
      --workflow release.yml \
      --commit "$release_commit" \
      --event push \
      --json databaseId,status,createdAt \
      --jq 'map(select(.status != "")) | sort_by(.createdAt) | last | .databaseId // ""')"

    if [[ -n "$run_id" ]]; then
      printf '%s\n' "$run_id"
      return 0
    fi

    attempts=$((attempts + 1))
    sleep 3
  done

  echo "error: release workflow run did not appear for commit $release_commit" >&2
  return 1
}

printf '%s\n' "$new_version" > VERSION
python3 scripts/roll-changelog-release.py \
  --changelog CHANGELOG.md \
  --version "$new_version" \
  --date "$release_date"

python3 scripts/build-release-source-tarball.py \
  --version "$new_version" \
  --output "$tmp_dir/$source_asset"
source_sha="$(python3 scripts/sha256-file.py "$tmp_dir/$source_asset")"

python3 scripts/update-formula-release.py \
  --formula Formula/file-snitch.rb \
  --version "$new_version" \
  --sha256 "$source_sha" \
  --source-url "$source_url"

zig build test
run_host_release_sanity

git add VERSION CHANGELOG.md Formula/file-snitch.rb
git commit -m "Release $new_version"
git tag -a "$tag" -m "Release $new_version"
release_commit="$(git rev-parse HEAD)"
git push origin HEAD
git push origin "$tag"

run_id="$(wait_for_release_run "$release_commit")"
echo "watching release workflow run $run_id"
if ! gh run watch "$run_id" --compact --exit-status; then
  echo "error: release workflow failed for $tag" >&2
  echo "inspect: gh run view $run_id --log-failed" >&2
  exit 1
fi

echo "pushed release commit and tag for $new_version"
echo "release workflow should publish:"
echo "  $source_url"
