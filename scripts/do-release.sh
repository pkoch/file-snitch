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
  - creates one release commit
  - creates an annotated tag
  - pushes the branch and tag to trigger the release workflow
  - opens and watches a Homebrew tap PR after the release succeeds
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
  command -v brew >/dev/null 2>&1 || {
    echo "error: brew is required to locate the Homebrew tap checkout" >&2
    exit 1
  }

  gh auth status >/dev/null 2>&1 || {
    echo "error: gh must be authenticated before releasing" >&2
    exit 1
  }
}

resolve_tap_repo() {
  if [[ -n "${FILE_SNITCH_HOMEBREW_TAP_REPO:-}" ]]; then
    printf '%s\n' "$FILE_SNITCH_HOMEBREW_TAP_REPO"
    return 0
  fi

  brew --repository pkoch/homebrew-tap
}

resolve_tap_repo_slug() {
  if [[ -n "${FILE_SNITCH_HOMEBREW_TAP_SLUG:-}" ]]; then
    printf '%s\n' "$FILE_SNITCH_HOMEBREW_TAP_SLUG"
    return 0
  fi

  printf '%s\n' "pkoch/homebrew-tap"
}

ensure_tap_publish_label() {
  local repo="$1"
  local exists

  exists="$(
    gh label list --repo "$repo" --json name --jq 'map(select(.name == "pr-pull")) | length'
  )"
  if [[ "$exists" == "1" ]]; then
    return 0
  fi

  gh label create \
    "pr-pull" \
    --repo "$repo" \
    --color "2da44e" \
    --description "Publish bottles from this PR" >/dev/null
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
tap_repo="$(resolve_tap_repo)"
tap_repo_slug="$(resolve_tap_repo_slug)"
tap_formula="$tap_repo/Formula/file-snitch.rb"

if [[ ! -f "$tap_formula" ]]; then
  echo "error: tap formula not found: $tap_formula" >&2
  echo "hint: clone or create pkoch/homebrew-tap locally, or set FILE_SNITCH_HOMEBREW_TAP_REPO" >&2
  exit 1
fi

if [[ -n "$(git -C "$tap_repo" status --porcelain)" ]]; then
  echo "error: tap worktree must be clean before releasing: $tap_repo" >&2
  exit 1
fi

git -C "$tap_repo" switch main >/dev/null 2>&1 || git -C "$tap_repo" checkout main >/dev/null
git -C "$tap_repo" pull --ff-only origin main >/dev/null

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
  local workflow_name="$1"
  local release_commit="$2"
  local run_id=""
  local attempts=0

  while [[ $attempts -lt 40 ]]; do
    run_id="$(gh run list \
      --workflow "$workflow_name" \
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

wait_for_repo_workflow_run_by_branch() {
  local repo="$1"
  local workflow_name="$2"
  local branch="$3"
  local event="$4"
  local run_id=""
  local attempts=0

  while [[ $attempts -lt 40 ]]; do
    run_id="$(gh run list \
      --repo "$repo" \
      --workflow "$workflow_name" \
      --branch "$branch" \
      --event "$event" \
      --json databaseId,status,createdAt \
      --jq 'map(select(.status != "")) | sort_by(.createdAt) | last | .databaseId // ""')"

    if [[ -n "$run_id" ]]; then
      printf '%s\n' "$run_id"
      return 0
    fi

    attempts=$((attempts + 1))
    sleep 3
  done

  echo "error: workflow $workflow_name did not appear for $repo branch $branch" >&2
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

zig build test
run_host_release_sanity

git add VERSION CHANGELOG.md
git commit -m "Release $new_version"
release_commit="$(git rev-parse HEAD)"
git push origin HEAD

run_id="$(wait_for_release_run ci.yml "$release_commit")"
echo "watching CI workflow run $run_id"
if ! gh run watch "$run_id" --compact --exit-status; then
  echo "error: CI workflow failed for release commit $release_commit" >&2
  echo "inspect: gh run view $run_id --log-failed" >&2
  exit 1
fi

git tag -a "$tag" -m "Release $new_version"
git push origin "$tag"

run_id="$(wait_for_release_run release.yml "$release_commit")"
echo "watching release workflow run $run_id"
if ! gh run watch "$run_id" --compact --exit-status; then
  echo "error: release workflow failed for $tag" >&2
  echo "inspect: gh run view $run_id --log-failed" >&2
  exit 1
fi

echo "pushed release commit and tag for $new_version"
echo "release workflow should publish:"
echo "  $source_url"

python3 scripts/update-formula-release.py \
  --formula "$tap_formula" \
  --version "$new_version" \
  --sha256 "$source_sha" \
  --source-url "$source_url"

tap_branch="file-snitch-$new_version"
tap_pr_title="file-snitch $new_version"
tap_pr_body=$(
  cat <<EOF
Update \`file-snitch\` to \`$new_version\`.

Upstream release:
- $source_url
EOF
)

git -C "$tap_repo" switch -c "$tap_branch"
git -C "$tap_repo" add Formula/file-snitch.rb
git -C "$tap_repo" commit -m "file-snitch $new_version"
git -C "$tap_repo" push -u origin "$tap_branch"

tap_pr_url="$(
  gh pr create \
    --repo "$tap_repo_slug" \
    --base main \
    --head "$tap_branch" \
    --title "$tap_pr_title" \
    --body "$tap_pr_body"
)"
tap_pr_number="$(gh pr view "$tap_pr_url" --repo "$tap_repo_slug" --json number --jq '.number')"

run_id="$(wait_for_repo_workflow_run_by_branch "$tap_repo_slug" tests.yml "$tap_branch" pull_request)"
echo "watching tap test workflow run $run_id"
if ! gh run watch "$run_id" --repo "$tap_repo_slug" --compact --exit-status; then
  echo "error: tap test workflow failed for $tap_pr_url" >&2
  echo "inspect: gh run view $run_id --repo $tap_repo_slug --log-failed" >&2
  exit 1
fi

ensure_tap_publish_label "$tap_repo_slug"
gh pr edit "$tap_pr_number" --repo "$tap_repo_slug" --add-label pr-pull >/dev/null

run_id="$(wait_for_repo_workflow_run_by_branch "$tap_repo_slug" publish.yml "$tap_branch" pull_request)"
echo "watching tap publish workflow run $run_id"
if ! gh run watch "$run_id" --repo "$tap_repo_slug" --compact --exit-status; then
  echo "error: tap publish workflow failed for $tap_pr_url" >&2
  echo "inspect: gh run view $run_id --repo $tap_repo_slug --log-failed" >&2
  exit 1
fi

git -C "$tap_repo" fetch origin main >/dev/null
git -C "$tap_repo" switch main >/dev/null
git -C "$tap_repo" pull --ff-only origin main >/dev/null
git -C "$tap_repo" branch -D "$tap_branch" >/dev/null 2>&1 || true

echo "updated Homebrew tap through PR:"
echo "  $tap_pr_url"
