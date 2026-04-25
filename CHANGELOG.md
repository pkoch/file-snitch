# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.3.2] - 2026-04-25

### Fixed

- Fixed macOS run services so launchd supplies the Homebrew paths needed by
  `pass` and its helper tools before projecting guarded files.

## [0.3.1] - 2026-04-25

### Fixed

- Fixed the test-only agent frame reader to enforce the same payload length
  limit as the socket frame reader.

## [0.3.0] - 2026-04-25

### Changed

- Changed per-user service installation to pin the `pass` binary path in the
  run service environment.

### Fixed

- Fixed enrollment on macOS so a stale LaunchAgent that cannot find `pass`
  fails before moving the target file into guarded storage.
- Fixed macOS release artifact stripping so binaries keep a Mach-O UUID that
  dyld accepts.
- Reported stale macOS run services that cannot find `pass` in `doctor`.

## [0.2.3] - 2026-04-25

### Changed

- Documented the current 1 MiB `pass` JSON/base64 payload cap as a File
  Snitch store limit rather than a `pass` limit.

### Fixed

- Reported oversized guarded-store payloads with explicit CLI and `doctor`
  diagnostics.
- Allowed `unenroll` to stream oversized guarded objects back to disk as a
  recovery path before removing the store entry.

## [0.2.2] - 2026-04-25

## [0.2.1] - 2026-04-24

### Changed

- Changed Zig toolchain selection to use Anyzig and `build.zig.zon` instead of
  the project-specific `zig-toolchain.json` checksum manifest.

### Fixed

- Fixed the `config` test root to link libc when CI cross-targets Linux.

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
