# Releasing

The release entrypoints and inputs are:

- [scripts/release/do-release.sh](../scripts/release/do-release.sh)
- [scripts/release/build-release-source-tarball.py](../scripts/release/build-release-source-tarball.py)
- [scripts/release/build-release-artifact.sh](../scripts/release/build-release-artifact.sh)
- [scripts/vendor/extract-macfuse-sdk.sh](../scripts/vendor/extract-macfuse-sdk.sh)
- [.github/workflows/release.yml](../.github/workflows/release.yml)
- [build.zig.zon](../build.zig.zon)
- [release-inputs.json](../release-inputs.json)

A release consists of:

- one version source in [VERSION](../VERSION)
- one release commit that bumps versioned metadata
- one annotated tag
- one GitHub Actions workflow that rebuilds and publishes the release artifacts
- one follow-up tap PR in `pkoch/homebrew-tap` that advances the formula to the
  new tagged source tarball and lets Homebrew bottle it

## Canonical release artifacts

Tagged releases publish:

- `file-snitch-<version>-source.tar.gz`
- `file-snitch-<version>-linux-x86_64.tar.gz`
- `file-snitch-<version>-macos-arm64.tar.gz`
- `SHA256SUMS`
- `release-manifest.json`

Homebrew consumes the tagged source tarball. The formula and bottle workflows
live in [pkoch/homebrew-tap](https://github.com/pkoch/homebrew-tap). The release
script updates the tap and waits for its checks and bottle publication, so a
release includes both app artifacts and packaging follow-through.

Other package managers can consume the source tarball, binary artifacts, or
`release-manifest.json`. If packaging moves to `homebrew/core`, revisit the
script's dependency on the tap workflow.

## Deterministic release inputs

Inputs and verification:

- the release source tarball is generated from tracked files only
- the release source tarball builder fails loudly if any tracked file appears
  under `Formula/`; the Homebrew formula lives in `pkoch/homebrew-tap` and
  shipping it inside the source tarball would create a checksum
  self-reference loop
- Zig is selected by Anyzig from `minimum_zig_version` in
  [build.zig.zon](../build.zig.zon)
- the Homebrew formula build dependency is derived from that same
  `minimum_zig_version` by
  [scripts/release/update-formula-release.py](../scripts/release/update-formula-release.py)
- existing Homebrew bottle metadata is kept when the stable source changes, but
  its `root_url` is bumped to the new version so bottle publication can replace
  the SHA lines for that release
- after tap test-bot builds bottles, the release script downloads the bottle
  JSON artifacts and merges their SHA lines into the tap formula before the
  `pr-pull` publication step
- the merged formula bottle `root_url` and SHA lines are checked against those
  bottle JSON artifacts before the tap update is committed
- after `pr-pull`, the final tap formula bottle SHA lines are checked against
  the SHA-256 digests on the uploaded bottle release assets
- macOS release builds extract a pinned macFUSE SDK from the checksum-verified
  DMG declared in [release-inputs.json](../release-inputs.json)
- tarballs are written with stable ordering and zeroed mtimes/owners
- binary builds set `SOURCE_DATE_EPOCH` and package the installed binary into a
  deterministic tarball

The release workflow rebuilds each binary artifact twice from the same source
bundle, with the same Anyzig-selected Zig version and SDK inputs, and compares
the outputs byte-for-byte before publishing them.

Reproducibility is checked on the same native runner class with the same source
bundle, Zig version, and SDK inputs. It does not establish reproducibility
across arbitrary host environments.

## Running a release

From a clean worktree:

```bash
./scripts/release/do-release.sh patch
```

Use `minor` or `major` instead of `patch` for a larger version bump.

That script:

1. bumps [VERSION](../VERSION) and `build.zig.zon` package metadata
2. rolls [CHANGELOG.md](../CHANGELOG.md)
3. runs `zig build test`
4. creates one release commit
5. pushes that commit and waits for `CI`
6. creates an annotated tag
7. pushes the tag and waits for the `Release` workflow
8. updates the formula in `pkoch/homebrew-tap`
9. opens a tap PR and waits for `brew test-bot`
10. applies the `pr-pull` label and waits for bottle publication

## What the script assumes

- `gh`, `python3`, `zig`, and `brew` are installed, and `gh` is authenticated
- the worktree is clean
- the local `pkoch/homebrew-tap` checkout exists and is clean; the script finds
  it with `brew --repository pkoch/homebrew-tap`, or uses
  `FILE_SNITCH_HOMEBREW_TAP_REPO` when set
- the current branch is the branch you actually want to release from
- `origin` is the correct push target
- GitHub push access is configured already
- the tap repo Actions workflows are enabled

`release-manifest.json` records the Zig version and macFUSE input metadata used
for the published artifacts. `SHA256SUMS` records artifact checksums.

## Changelog discipline

[CHANGELOG.md](../CHANGELOG.md) follows Keep a Changelog.

The release script moves whatever is under `## [Unreleased]` into the new
versioned section. If `Unreleased` is empty, the release notes will be sparse.

Add public-facing changes to `Unreleased` as they land.
