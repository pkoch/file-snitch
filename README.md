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
- mutating operations are now controlled by an explicit session policy flag
- the demo now exercises both the allow and deny sides of that mutation policy
- the session now records an in-memory audit trail for reads and mutations
- the synthetic audit file now renders that in-memory audit trail as mounted file content
- the demo app inspects the execution plan but does not invoke a live mount
- the live mount path is compiled, but the demo intentionally avoids invoking it
- directory mirroring is still limited to one-level regular files

## Layout

- `build.zig`: Zig build entrypoint
- `src/`: Zig application code
- `c/`: thin C boundary that owns `libfuse` interop
- `docs/`: brief and research notes

## Build notes

This scaffold expects:
- Zig on `PATH`
- `libfuse` development headers and libraries on Linux
- macFUSE `libfuse` compatibility libraries on macOS

Current verification:
- `zig build`
- `./zig-out/bin/file-snitch`
