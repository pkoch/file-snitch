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
- the daemon/session API now supports dry-run inspection of synthetic filesystem behavior without mounting
- the mount now seeds one-level regular files from a host backing-store directory
- the mount now supports one-level in-memory regular files for create/read/write/truncate/unlink flows
- those one-level regular file mutations now write through into the host backing-store directory
- one-level file rename now updates both the mounted view and the backing-store directory
- one-level chmod now persists into the backing-store directory
- one-level uid/gid metadata is now tracked explicitly, and self-`chown` requests now pass through the mounted view
- macOS `._*` AppleDouble sidecars are treated as transient mount-only files and are not persisted into the backing store
- one-level xattrs now proxy to the backing-store file on macOS
- xattrs now bypass prompt/deny policy entirely in the current spike; richer xattr mediation is deferred to future work
- flush and fsync now act as explicit backing-store sync points for one-level regular files
- the binary now has an explicit `mount` mode for foreground live-mount runs
- mutating operations are now controlled by a Zig-owned default mutation outcome instead of a C-owned session flag
- the daemon now owns an in-memory policy engine with path-prefix rules and `allow` / `deny` / `prompt` outcomes
- the filesystem model, audit trail, and path semantics now live in Zig
- the C shim now only owns `libfuse` ABI glue, mount execution, host-fd lock plumbing, and macOS xattr syscalls
- the daemon now has a CLI prompt broker with default-deny timeout behavior
- the session now records an in-memory audit trail for reads and mutations
- the synthetic audit file now renders that in-memory audit trail as mounted file content
- Zig integration tests now exercise the dry-run session path, execution plan, persistence, and policy behavior without mounting
- a scripted macFUSE smoke test now verifies live mount, read, write, rename, audit, and teardown on macOS
- a separate scripted macFUSE prompt smoke test now verifies live prompt allow, explicit deny, and timeout behavior
- the live smoke test now also verifies temp-write replacement over an existing file
- the live smoke test now covers hidden-temp and backup-style save flows in addition to plain temp replacement
- the live smoke test now covers truncate+rewrite, chmod-after-save, swap-file cleanup, and partial overwrite flows
- the live smoke test now covers xattr set/get/list/remove round-trips on mounted files
- the live smoke test now covers BSD `flock` and POSIX lock contention/release on mounted files
- the live smoke test now covers self-`chown` handling on mounted files
- the mounted root is intentionally file-only beyond `/`; `mkdir` and `rmdir` fail explicitly in the current spike
- directory support beyond the root itself is deferred out of the current spike scope
- the live macOS smoke test observed both `._*` sidecar traffic and aggressive xattr probing during normal file activity
- the same macOS smoke path treats behavioral lock contention/release as the main signal, because callback visibility is partial and style-dependent on macFUSE

## Layout

- `build.zig`: Zig build entrypoint
- `src/`: Zig application code
- `src/root.zig`: shared application module surface for tests and other non-CLI consumers
- `src/cli.zig`: command-line parsing, env loading, and mount command dispatch
- `src/filesystem.zig`: Zig-owned guarded-directory model and backing-store behavior
- `tests/`: Zig integration tests and scenario coverage
- `c/`: thin C boundary that owns `libfuse` interop and syscall-adjacent helpers
- `docs/`: brief and research notes
- `scripts/`: verification helpers including live-mount smoke tests

## Architecture guardrails

These are project-wide invariants. Refactors should preserve them unless the product direction changes explicitly.

- The C shim is a faithful FUSE harness, not a product-policy layer. It should preserve callback timing and raw callback data, and it should not drop or embellish information before handing it to Zig.
- Fine-grained callback visibility must remain available even when Zig chooses not to emit a user-facing audit line for a given action. Audit filtering is a Zig/business decision, not a reason to weaken the shim.
- Authorization must align with intent. If a handle was authorized for read-like access and later attempts write-like behavior, that later behavior must still be independently mediable.
- Prompting must happen before the guarded operation takes effect. The system should prevent behavior, not merely report it after the fact.

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
- after cloning or changing build flags, run `zig build compile-commands` so clangd picks up the correct C flags; `build.zig` remains the source of truth

## Verification

Current validation workflow:

```bash
zig build
zig build test
zig build compile-commands
./scripts/live-mount-smoke.sh
./scripts/prompt-mount-smoke.sh
```

What each command covers:
- `zig build`: compile the CLI binary and the C `libfuse` shim
- `zig build test`: run both Zig test roots wired in `build.zig`
  - `tests/integration.zig`: dry-run integration coverage for the session/filesystem boundary
  - `src/prompt.zig`: prompt broker unit tests
- `zig build compile-commands`: regenerate `compile_commands.json` for clangd
- `./scripts/live-mount-smoke.sh`: live macFUSE mount verification for the file-only root, file mutation flows, xattrs, locks, and audit output
- `./scripts/prompt-mount-smoke.sh`: live macFUSE prompt verification for allow once, deny once, timeout, and non-interactive ordinary xattr traffic

When debugging a specific area, the build-managed test step above is still the default, but the underlying Zig test roots are:
- `tests/integration.zig`
- `src/prompt.zig`

Prompt notes:
- `file-snitch mount <mount-path> <backing-store-path> prompt` enables the CLI broker
- on the mounted FUSE path, `prompt` mode currently targets `open` and `create`, and the prompt text includes the open mode
- later operations on an already-authorized handle may reuse that authorization when the requested behavior still aligns with the handle mode
- `readonly` still allows reads and denies mutations
- the terminal broker currently prints structured prompt JSON before each question and defaults blank terminal input to allow (`[Y/n]`)
- prompt timeout defaults to 5 seconds and falls back to deny
- set `FILE_SNITCH_PROMPT_TIMEOUT_MS` to shorten or lengthen that timeout during manual testing
- xattr traffic does not prompt in this mode; xattr mediation is deferred to future work
