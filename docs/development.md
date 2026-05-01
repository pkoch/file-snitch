# Development

This page is the local development and verification checklist for File Snitch.
For contribution expectations and ownership conventions, read
[../CONTRIBUTING.md](../CONTRIBUTING.md).

## Prerequisites

Install Anyzig so `zig` follows the `minimum_zig_version` pinned in
`build.zig.zon`:

```bash
brew install anyzig
```

Platform dependencies:

- Linux: `fuse3` and `libfuse3-dev`
- macOS: macFUSE with libfuse compatibility libraries
- all platforms: `pass` and a usable GPG setup for real guarded-store drills

## Development Environment

This repo ships a devcontainer at
[../.devcontainer/devcontainer.json](../.devcontainer/devcontainer.json). Use it
as the default local Linux development environment, or as a reference for
setting up another Linux runner.

- `.devcontainer/scripts/setup.sh` installs the Linux packages needed to build
against FUSE, installs the pinned Zig release from ziglang.org when `zig` is
missing or does not match the repo pin, and prints tool versions for build logs.
- `.devcontainer/scripts/check.sh` verifies command presence, prints
`minimum_zig_version` from `build.zig.zon`, checks
`pkg-config --modversion fuse3`, then runs the core build and docs checks.

## Core Loop

```bash
zig build
zig build test
zig build compile-commands
./scripts/docs/check-docs.sh
```

What each command covers:

- `zig build`: compiles the CLI binary and C `libfuse` shim
- `zig build test`: runs every Zig test artifact wired in `build.zig`
- `zig build compile-commands`: regenerates `compile_commands.json` for clangd
- `./scripts/docs/check-docs.sh`: catches docs drift in links, CLI command
  docs, and smoke-test listings

Run `zig build compile-commands` after cloning, changing build flags, or
updating FUSE-related local dependencies.

## Smoke Tests

```bash
./tests/smoke/run-empty-policy.sh
./tests/smoke/policy-lifecycle.sh
./tests/smoke/doctor-debug-dossier.sh
./tests/smoke/run-policy-reload.sh
./tests/smoke/run-expired-decision-cleanup.sh
./tests/smoke/run-single-enrollment.sh
./tests/smoke/run-multi-mount.sh
./tests/smoke/run-prompt-linux-ui.sh
./tests/smoke/run-prompt-single.sh
./tests/smoke/run-prompt-remembered-decision.sh
./tests/smoke/user-service-rendering.sh

# macOS only:
./tests/smoke/run-prompt-macos-ui.sh
./tests/smoke/run-prompt-macos-ui-agent.sh
```

Coverage map:

- `run-empty-policy.sh`: `run` stays alive and watches for future policy changes when policy is empty
- `policy-lifecycle.sh`: `enroll`, `status`, `doctor`, and `unenroll`
- `doctor-debug-dossier.sh`: debug dossier export without guarded file contents
- `run-policy-reload.sh`: live policy reload activates and tears down projections
- `run-expired-decision-cleanup.sh`: expired durable decisions are pruned from `policy.yml`
- `run-single-enrollment.sh`: one enrolled file is projected while siblings stay outside the projection
- `run-multi-mount.sh`: one projection root handles multiple enrolled paths
- `run-prompt-linux-ui.sh`: `linux-ui` through a fake `zenity` path suitable for CI
- `run-prompt-macos-ui.sh`: `macos-ui` through a fake `osascript` path on macOS
- `run-prompt-macos-ui-agent.sh`: macOS agent socket behavior with the `macos-ui` frontend
- `run-prompt-single.sh`: interactive prompt allow, deny, and timeout behavior through `terminal-pinentry`
- `run-prompt-remembered-decision.sh`: durable allow decision write and prompt suppression
- `user-service-rendering.sh`: rendered `launchd` and `systemd --user` service files

## Shell And Demo Hygiene

CI also enforces shell syntax and demo artifact freshness:

```bash
bash -n $(find scripts tests -type f -name '*.sh' | sort)
./scripts/docs/check-docs.sh
./scripts/demo/check-demo-artifacts.sh
```

Regenerate demo artifacts with:

```bash
./scripts/demo/regenerate-demo-artifacts.sh
```

That path expects:

- `zig`
- `asciinema`
- `agg`
- `tmux`

## Build Notes

`build.zig.zon` is the source of truth for the Zig version. Anyzig reads
`minimum_zig_version`, downloads that Zig release into the global Zig cache
when needed, and dispatches the requested `zig` command.

FUSE discovery:

- the Zig build prefers `pkg-config` when available
- Linux falls back to standard `fuse3` system locations if `pkg-config` is absent or cannot resolve `fuse3.pc`
- macOS falls back to standard macFUSE locations under `/usr/local` and `/opt/homebrew`
- `zig build compile-commands` uses the same discovery logic as the main build

## Real Store Drill

Smoke tests use a fake `pass` binary plus a disposable `PASSWORD_STORE_DIR`.
Production code talks to the `pass` CLI directly.

Before testing against real secrets, verify the store outside File Snitch:

```bash
pass ls
file-snitch doctor
```

For the safest real-store drill, use a disposable temp home, disposable
password store, and local GPG key, then exercise:

```text
enroll -> run -> read/write -> unenroll
```
