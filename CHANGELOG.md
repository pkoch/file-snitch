# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
