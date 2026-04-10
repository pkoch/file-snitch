# Releasing

Formal releases are owned by:
- [scripts/do-release.sh](../scripts/do-release.sh)
- [scripts/build-release-source-tarball.py](../scripts/build-release-source-tarball.py)
- [scripts/build-release-artifact.sh](../scripts/build-release-artifact.sh)
- [scripts/extract-macfuse-sdk.sh](../scripts/extract-macfuse-sdk.sh)
- [.github/workflows/release.yml](../.github/workflows/release.yml)
- [zig-toolchain.json](../zig-toolchain.json)
- [release-inputs.json](../release-inputs.json)

The intended release shape is:
- one version source in [VERSION](../VERSION)
- one release commit that bumps versioned metadata
- one annotated tag
- one GitHub Actions workflow that rebuilds and publishes the release artifacts
- one follow-up tap commit in `pkoch/homebrew-tap` that advances the formula to
  the new tagged source tarball

## Canonical release artifacts

Tagged releases are meant to publish:
- `file-snitch-<version>-source.tar.gz`
- `file-snitch-<version>-linux-x86_64.tar.gz`
- `file-snitch-<version>-macos-arm64.tar.gz`
- `SHA256SUMS`
- `release-manifest.json`

Those GitHub Release assets are the canonical release artifacts.

Homebrew should consume the tagged source tarball, not a branch tarball.
Other package managers should prefer the published release artifacts or
`release-manifest.json` over ad hoc branch snapshots.

The Homebrew formula itself now lives in:
- `pkoch/homebrew-tap`
- https://github.com/pkoch/homebrew-tap

This coupling is intentional for now.

The release flow updates the tap as part of a normal release so packaging drift
fails loudly instead of silently. That is an operational choice for visibility,
not an architectural claim that the tap is the only valid downstream packaging
home forever.

If `file-snitch` later moves into `homebrew/core`, revisit this and decouple the
tap update from the main release script then.

## Deterministic release inputs

The release flow is built around deterministic inputs:
- the release source tarball is generated from tracked files only
- the release source tarball intentionally excludes `Formula/` to avoid a
  checksum self-reference loop
- Zig is pinned in [zig-toolchain.json](../zig-toolchain.json)
- macOS release builds extract a pinned macFUSE SDK from the checksum-verified
  DMG declared in [release-inputs.json](../release-inputs.json)
- tarballs are written with stable ordering and zeroed mtimes/owners
- binary builds set `SOURCE_DATE_EPOCH` and package the installed binary into a
  deterministic tarball

The release workflow rebuilds each binary artifact twice from the same source
bundle, with the same pinned toolchain and SDK inputs, and compares the outputs
byte-for-byte before publishing them.

This is intentionally a pinned native-runner release flow, not a hermetic Nix
build. The current guarantee is: same source tarball, same declared toolchain
and SDK inputs, same native runner class, same bytes out.

## Running a release

From a clean worktree:

```bash
./scripts/do-release.sh patch
```

Or:

```bash
./scripts/do-release.sh minor
./scripts/do-release.sh major
```

That script:
1. bumps [VERSION](../VERSION)
2. rolls [CHANGELOG.md](../CHANGELOG.md)
3. runs `zig build test`
4. creates one release commit
5. pushes that commit and waits for `CI`
6. creates an annotated tag
7. pushes the tag and waits for the `Release` workflow
8. updates and pushes the formula in `pkoch/homebrew-tap`

## What the script assumes

- the worktree is clean
- the local `pkoch/homebrew-tap` checkout exists and is clean
- the current branch is the branch you actually want to release from
- `origin` is the correct push target
- GitHub push access is configured already

It does not try to be clever about branch selection or interactive review.

## Release provenance

Every release publishes:
- `SHA256SUMS`
- `release-manifest.json`

`release-manifest.json` includes the pinned Zig and macFUSE input metadata that
the workflow used to produce the published artifacts.

## Changelog discipline

[CHANGELOG.md](../CHANGELOG.md) follows Keep a Changelog.

The release script moves whatever is under `## [Unreleased]` into the new
versioned section. If `Unreleased` is empty, the release notes will be sparse.

That means public-facing changes should be added to `Unreleased` as they land.

## Packaging follow-through

The source release tarball is the stable input for:
- Homebrew/Linuxbrew via `pkoch/homebrew-tap`
- future `.deb` packaging
- any other downstream packaging that wants a fixed release source

The binary release tarballs are for direct download and manual installation.
