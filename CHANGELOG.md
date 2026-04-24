# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

- Changed Zig toolchain selection to use Anyzig and `build.zig.zon` instead of
  the project-specific `zig-toolchain.json` checksum manifest.

## [0.2.0] - 2026-04-11

### Changed

- Changed `file-snitch run` and `file-snitch agent` to stay in the foreground
  and rely on the caller or service manager for supervision.
- Changed the packaged `launchd` and `systemd --user` service definitions and
  helper scripts to invoke `file-snitch` without execution-mode flags.

### Removed

- Removed the `--foreground` and `--daemon` execution-mode flags from
  `file-snitch run` and `file-snitch agent`.

### Fixed

- Fixed the smoke-test harness to supervise prompt-agent processes without
  leaking orphaned `file-snitch` children during teardown.

## [0.1.12] - 2026-04-10

## [0.1.11] - 2026-04-10

## [0.1.10] - 2026-04-10

## [0.1.9] - 2026-04-10

## [0.1.8] - 2026-04-10

## [0.1.7] - 2026-04-10

## [0.1.6] - 2026-04-10

## [0.1.5] - 2026-04-10

## [0.1.4] - 2026-04-10

## [0.1.3] - 2026-04-10

## [0.1.2] - 2026-04-10

## [0.1.1] - 2026-04-10

## [0.1.0] - 2026-04-10

### Added

- Added policy-driven exact-file enrollment, guarded custody through `pass`,
  and in-place projection back into real parent directories.
- Added a local requester/agent protocol with `terminal-pinentry`,
  `macos-ui`, and `linux-ui` frontends.
- Added per-user service helpers for `launchd` and `systemd --user`.
- Added reproducible demo, install, operations, and threat-model docs.

### Fixed

- Fixed remembered decisions so they take effect inside the live worker on the
  next guarded access instead of waiting for remount.
