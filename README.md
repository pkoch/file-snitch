# File Snitch

Guarded FUSE mounts for secret files.

## Intro

The product brief lives in [docs/initial-brief.md](./docs/initial-brief.md).

Current state:
- phase-0 research docs and backlog are in place
- the repo now has an initial Zig scaffold with a thin C `libfuse` shim
- the shim exposes a stub session lifecycle that Zig can create, inspect, and destroy
- the shim now owns a real high-level `fuse_operations` table shape
- the shim now builds real mount argv and a compiled `fuse_setup`/`fuse_loop` execution path
- the synthetic root directory now answers `getattr` and `readdir` cleanly
- the mount now exposes one readable synthetic status file
- the mount now exposes one readable synthetic audit file
- the repo now has a debug inspection path for verifying synthetic filesystem behavior without mounting
- the mount now seeds one-level regular files from a host backing-store directory
- the mount now supports one-level in-memory regular files for create/read/write/truncate/unlink flows
- those one-level regular file mutations now write through into the host backing-store directory
- one-level file rename now updates both the mounted view and the backing-store directory
- one-level chmod now persists into the backing-store directory
- one-level uid/gid metadata is now tracked explicitly, and self-`chown` requests now pass through the mounted view
- macOS `._*` AppleDouble sidecars are treated as transient mount-only files and are not persisted into the backing store
- one-level xattrs now proxy to the backing-store file on macOS
- flush and fsync now act as explicit backing-store sync points for one-level regular files
- the binary now has an explicit `mount` mode for foreground live-mount runs
- mutating operations are now controlled by an explicit session policy flag
- the daemon now owns an in-memory policy engine with path-prefix rules and `allow` / `deny` / `prompt` outcomes
- the C shim now consults that policy engine for read and mutation decisions through the Zig daemon state
- the demo now exercises both the allow and deny sides of that mutation policy
- the demo now also exercises rule-driven `prompt` and `deny` outcomes, with `prompt` currently defaulting to deny until a prompt broker exists
- the session now records an in-memory audit trail for reads and mutations
- the synthetic audit file now renders that in-memory audit trail as mounted file content
- the demo app still inspects the execution plan without mounting
- a scripted macFUSE smoke test now verifies live mount, read, write, rename, audit, and teardown on macOS
- the live smoke test now also verifies temp-write replacement over an existing file
- the live smoke test now covers hidden-temp and backup-style save flows in addition to plain temp replacement
- the live smoke test now covers truncate+rewrite, chmod-after-save, swap-file cleanup, and partial overwrite flows
- the live smoke test now covers xattr set/get/list/remove round-trips on mounted files
- the live smoke test now covers BSD `flock` and POSIX lock contention/release on mounted files
- the live smoke test now covers self-`chown` handling on mounted files
- directory mirroring is still limited to one-level regular files
- the live macOS smoke test observed both `._*` sidecar traffic and aggressive xattr probing during normal file activity
- the same macOS smoke path treats behavioral lock contention/release as the main signal, because callback visibility is partial and style-dependent on macFUSE

## Layout

- `build.zig`: Zig build entrypoint
- `src/`: Zig application code
- `c/`: thin C boundary that owns `libfuse` interop
- `docs/`: brief and research notes
- `scripts/`: verification helpers including live-mount smoke tests

## Build notes

This scaffold expects:
- Zig on `PATH`
- `libfuse` development headers and libraries on Linux
- macFUSE `libfuse` compatibility libraries on macOS

FUSE discovery:
- the Zig build now prefers `pkg-config` when available
- Linux falls back to standard `fuse3` system locations if `pkg-config` is absent
- macOS falls back to standard macFUSE locations under `/usr/local` and `/opt/homebrew` if `pkg-config` is absent
- `zig build compile-commands` now writes `compile_commands.json` for clangd from the same discovery logic
- `.clangd` remains as a fallback for editor parsing when the compilation database has not been generated yet; `build.zig` remains the source of truth

Current verification:
- `zig build`
- `zig build compile-commands`
- `./zig-out/bin/file-snitch demo`
- `./scripts/live-mount-smoke.sh`
