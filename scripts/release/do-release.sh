#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo_root"

usage() {
  cat <<'EOF'
usage: ./scripts/release/do-release.sh <major|minor|patch>

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
    ./scripts/vendor/extract-macfuse-sdk.sh --output "$sdk_dir"
    FILE_SNITCH_FUSE_INCLUDE_DIR="$sdk_dir/include" \
    FILE_SNITCH_FUSE_LIB_DIR="$sdk_dir/lib" \
    ZIG_BUILD_TARGET="$host_target" \
    ./scripts/release/build-release-artifact.sh \
      --version "$new_version" \
      --platform "$host_platform" \
      --source-date-epoch "$source_date_epoch" \
      --output "$host_output"
    return 0
  fi

  ZIG_BUILD_TARGET="$host_target" \
  ./scripts/release/build-release-artifact.sh \
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
  local excluded_run_id="${5:-}"
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

    if [[ -n "$run_id" && "$run_id" != "$excluded_run_id" ]]; then
      printf '%s\n' "$run_id"
      return 0
    fi

    attempts=$((attempts + 1))
    sleep 3
  done

  echo "error: workflow $workflow_name did not appear for $repo branch $branch" >&2
  return 1
}

verify_tap_bottle_merge() {
  local formula="$1"
  local version="$2"
  shift 2

  python3 - "$formula" "$version" "$@" <<'PY'
import json
import pathlib
import re
import sys

formula_path = pathlib.Path(sys.argv[1])
version = sys.argv[2]
bottle_json_paths = [pathlib.Path(path) for path in sys.argv[3:]]
expected_root_url = (
    f"https://github.com/pkoch/homebrew-tap/releases/download/file-snitch-{version}"
)
expected_tags = {}

for path in bottle_json_paths:
    data = json.loads(path.read_text(encoding="utf-8"))
    try:
        bottle = data["pkoch/tap/file-snitch"]["bottle"]
    except KeyError as exc:
        raise SystemExit(f"error: malformed bottle JSON {path}: missing {exc}") from exc

    root_url = bottle.get("root_url")
    if root_url != expected_root_url:
        raise SystemExit(
            f"error: bottle JSON {path} root_url is {root_url!r}, "
            f"expected {expected_root_url!r}"
        )

    for tag, metadata in bottle.get("tags", {}).items():
        sha256 = metadata.get("sha256")
        if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise SystemExit(f"error: bottle JSON {path} has invalid sha256 for {tag}")
        previous = expected_tags.setdefault(tag, sha256)
        if previous != sha256:
            raise SystemExit(
                f"error: bottle JSON artifacts disagree for {tag}: "
                f"{previous} != {sha256}"
            )

if not expected_tags:
    raise SystemExit("error: bottle JSON artifacts did not contain any tags")

formula = formula_path.read_text(encoding="utf-8")
bottle_match = re.search(r"^\s*bottle do\n(?P<body>.*?)^\s*end\n", formula, re.M | re.S)
if not bottle_match:
    raise SystemExit(f"error: no bottle block found in {formula_path}")

bottle_body = bottle_match.group("body")
root_match = re.search(r'^\s*root_url\s+"([^"]+)"', bottle_body, re.M)
if not root_match:
    raise SystemExit(f"error: no bottle root_url found in {formula_path}")
if root_match.group(1) != expected_root_url:
    raise SystemExit(
        f"error: formula bottle root_url is {root_match.group(1)!r}, "
        f"expected {expected_root_url!r}"
    )

formula_tags = dict(
    re.findall(
        r'^\s*sha256(?:\s+cellar:\s*[^,]+,)?\s+([a-z0-9_]+):\s+"([0-9a-f]{64})"',
        bottle_body,
        re.M,
    )
)
if formula_tags != expected_tags:
    missing = sorted(set(expected_tags) - set(formula_tags))
    stale = sorted(set(formula_tags) - set(expected_tags))
    mismatched = sorted(
        tag
        for tag in set(expected_tags) & set(formula_tags)
        if expected_tags[tag] != formula_tags[tag]
    )
    details = []
    if missing:
        details.append(f"missing tags: {', '.join(missing)}")
    if stale:
        details.append(f"stale tags: {', '.join(stale)}")
    if mismatched:
        details.append(f"mismatched tags: {', '.join(mismatched)}")
    raise SystemExit("error: formula bottle SHAs do not match artifacts; " + "; ".join(details))

print(
    "verified bottle SHAs: "
    + ", ".join(f"{tag}={sha256}" for tag, sha256 in sorted(formula_tags.items()))
)
PY
}

verify_published_tap_bottles() {
  local version="$1"
  local release_json="$tmp_dir/tap-release-assets.json"

  gh release view \
    "file-snitch-$version" \
    --repo "$tap_repo_slug" \
    --json assets \
    > "$release_json"

  python3 - "$tap_formula" "$version" "$release_json" <<'PY'
import json
import pathlib
import re
import sys

formula_path = pathlib.Path(sys.argv[1])
version = sys.argv[2]
release_json_path = pathlib.Path(sys.argv[3])
expected_root_url = (
    f"https://github.com/pkoch/homebrew-tap/releases/download/file-snitch-{version}"
)
asset_prefix = f"file-snitch-{version}."
asset_suffix = ".bottle.tar.gz"

assets = json.loads(release_json_path.read_text(encoding="utf-8"))["assets"]
asset_tags = {}
for asset in assets:
    name = asset.get("name", "")
    digest = asset.get("digest", "")
    if not name.startswith(asset_prefix) or not name.endswith(asset_suffix):
        continue
    tag = name.removeprefix(asset_prefix).removesuffix(asset_suffix)
    if not digest.startswith("sha256:"):
        raise SystemExit(f"error: release asset {name} has no sha256 digest")
    sha256 = digest.removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise SystemExit(f"error: release asset {name} has invalid digest {digest!r}")
    asset_tags[tag] = sha256

if not asset_tags:
    raise SystemExit(f"error: no bottle assets found for file-snitch-{version}")

formula = formula_path.read_text(encoding="utf-8")
bottle_match = re.search(r"^\s*bottle do\n(?P<body>.*?)^\s*end\n", formula, re.M | re.S)
if not bottle_match:
    raise SystemExit(f"error: no bottle block found in {formula_path}")

bottle_body = bottle_match.group("body")
root_match = re.search(r'^\s*root_url\s+"([^"]+)"', bottle_body, re.M)
if not root_match:
    raise SystemExit(f"error: no bottle root_url found in {formula_path}")
if root_match.group(1) != expected_root_url:
    raise SystemExit(
        f"error: formula bottle root_url is {root_match.group(1)!r}, "
        f"expected {expected_root_url!r}"
    )

formula_tags = dict(
    re.findall(
        r'^\s*sha256(?:\s+cellar:\s*[^,]+,)?\s+([a-z0-9_]+):\s+"([0-9a-f]{64})"',
        bottle_body,
        re.M,
    )
)
if formula_tags != asset_tags:
    missing = sorted(set(asset_tags) - set(formula_tags))
    stale = sorted(set(formula_tags) - set(asset_tags))
    mismatched = sorted(
        tag
        for tag in set(asset_tags) & set(formula_tags)
        if asset_tags[tag] != formula_tags[tag]
    )
    details = []
    if missing:
        details.append(f"missing tags: {', '.join(missing)}")
    if stale:
        details.append(f"stale tags: {', '.join(stale)}")
    if mismatched:
        details.append(f"mismatched tags: {', '.join(mismatched)}")
    raise SystemExit(
        "error: published bottle assets do not match formula; " + "; ".join(details)
    )

print(
    "verified published bottles: "
    + ", ".join(f"{tag}={sha256}" for tag, sha256 in sorted(formula_tags.items()))
)
PY
}

merge_tap_bottle_artifacts() {
  local run_id="$1"
  local version="$2"
  local artifact_dir="$tmp_dir/tap-bottles"
  local -a bottle_jsons

  rm -rf "$artifact_dir"
  mkdir -p "$artifact_dir"
  gh run download "$run_id" \
    --repo "$tap_repo_slug" \
    --dir "$artifact_dir"

  mapfile -d '' -t bottle_jsons < <(
    find "$artifact_dir" -type f -name '*.bottle.json' -print0 | sort -z
  )

  if [[ "${#bottle_jsons[@]}" -eq 0 ]]; then
    echo "error: no bottle JSON artifacts found for tap workflow run $run_id" >&2
    return 1
  fi

  (
    cd "$tap_repo"
    brew bottle --merge --write --no-commit "${bottle_jsons[@]}"
  )

  if [[ -z "$(git -C "$tap_repo" status --porcelain -- Formula/file-snitch.rb)" ]]; then
    echo "error: bottle merge did not update Formula/file-snitch.rb" >&2
    return 1
  fi

  verify_tap_bottle_merge "$tap_formula" "$version" "${bottle_jsons[@]}"

  git -C "$tap_repo" add Formula/file-snitch.rb
  git -C "$tap_repo" commit -m "file-snitch: update $version bottle."
  git -C "$tap_repo" push
}

printf '%s\n' "$new_version" > VERSION
python3 - "$new_version" <<'PY'
import pathlib
import re
import sys

new_version = sys.argv[1]
path = pathlib.Path("build.zig.zon")
old = path.read_text(encoding="utf-8")
new, replacements = re.subn(
    r'(\.version\s*=\s*")[^"]+(")',
    rf'\g<1>{new_version}\2',
    old,
    count=1,
)
if replacements != 1:
    raise SystemExit("error: failed to update build.zig.zon .version")
path.write_text(new, encoding="utf-8")
PY
python3 scripts/release/roll-changelog-release.py \
  --changelog CHANGELOG.md \
  --version "$new_version" \
  --date "$release_date"

python3 scripts/release/build-release-source-tarball.py \
  --version "$new_version" \
  --output "$tmp_dir/$source_asset"
source_sha="$(python3 scripts/release/sha256-file.py "$tmp_dir/$source_asset")"

zig build test
run_host_release_sanity

git add VERSION CHANGELOG.md build.zig.zon
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

python3 scripts/release/update-formula-release.py \
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

tap_test_run_id="$(wait_for_repo_workflow_run_by_branch "$tap_repo_slug" tests.yml "$tap_branch" pull_request)"
echo "watching tap test workflow run $tap_test_run_id"
if ! gh run watch "$tap_test_run_id" --repo "$tap_repo_slug" --compact --exit-status; then
  echo "error: tap test workflow failed for $tap_pr_url" >&2
  echo "inspect: gh run view $tap_test_run_id --repo $tap_repo_slug --log-failed" >&2
  exit 1
fi

merge_tap_bottle_artifacts "$tap_test_run_id" "$new_version"

tap_test_run_id="$(
  wait_for_repo_workflow_run_by_branch \
    "$tap_repo_slug" \
    tests.yml \
    "$tap_branch" \
    pull_request \
    "$tap_test_run_id"
)"
echo "watching tap test workflow run $tap_test_run_id after bottle merge"
if ! gh run watch "$tap_test_run_id" --repo "$tap_repo_slug" --compact --exit-status; then
  echo "error: tap test workflow failed after bottle merge for $tap_pr_url" >&2
  echo "inspect: gh run view $tap_test_run_id --repo $tap_repo_slug --log-failed" >&2
  exit 1
fi

ensure_tap_publish_label "$tap_repo_slug"
gh pr edit "$tap_pr_number" --repo "$tap_repo_slug" --add-label pr-pull >/dev/null

run_id="$(wait_for_repo_workflow_run_by_branch "$tap_repo_slug" publish.yml "$tap_branch" pull_request_target)"
echo "watching tap publish workflow run $run_id"
if ! gh run watch "$run_id" --repo "$tap_repo_slug" --compact --exit-status; then
  echo "error: tap publish workflow failed for $tap_pr_url" >&2
  echo "inspect: gh run view $run_id --repo $tap_repo_slug --log-failed" >&2
  exit 1
fi

git -C "$tap_repo" fetch origin main >/dev/null
git -C "$tap_repo" switch main >/dev/null
git -C "$tap_repo" pull --ff-only origin main >/dev/null
verify_published_tap_bottles "$new_version"
git -C "$tap_repo" branch -D "$tap_branch" >/dev/null 2>&1 || true

echo "updated Homebrew tap through PR:"
echo "  $tap_pr_url"
