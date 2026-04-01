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
- the demo app inspects the execution plan but does not invoke a live mount
- actual mount behavior is not implemented yet

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
