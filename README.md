# File Snitch

Guarded FUSE mounts for secret files.

## Intro

The product brief lives in [docs/initial-brief.md](./docs/initial-brief.md).

Current state:
- phase-0 research docs and backlog are in place
- the repo has a Zig core with a thin C `libfuse` shim and real `fuse_setup`/`fuse_loop` execution
- the shim preserves raw callback detail; the filesystem model, policy timing, and audit semantics live in Zig
- mount mode streams audit JSON to stdout and can stream status JSON snapshots to a caller-provided FIFO
- audit JSON includes actor metadata (`pid`/`uid`/`gid` and `executable_path`), timestamps, and structured operation detail
- the CLI prompt broker is live, default-allow on blank input, and still defaults timeout to deny
- the legacy guarded-root spike still exists through `file-snitch mount <mount-path> <backing-store-path> ...`
- the new product direction is policy-driven exact-file enrollment through `file-snitch run`
- `policy.yml` is now loaded from `~/.config/file-snitch/policy.yml` by default, with `--policy` override support
- an empty or missing policy file is now a clean no-op
- remembered decisions from `policy.yml` now compile into the runtime policy engine using the documented exact-path decision key
- the CLI now has product-facing verbs:
  - `run`
  - `enroll`
  - `unenroll`
  - `status`
  - `doctor`
- `run` now requires explicit `--foreground` or `--daemon`
- `run --foreground` now supports multiple planned mounts by supervising one child mount process per path
- the remaining runtime limits are:
  - multi-mount `run --daemon`
  - multi-mount `run prompt`
- the first real enrolled-file flow is live for a kubeconfig-style target:
  - mount the real parent directory
  - shadow the enrolled file from `~/.var/file-snitch/guarded-secrets/<object_id>`
  - passthrough sibling files from the preserved underlying parent directory
- the real macOS demo was verified against `~/.kube/config`:
  - while mounted, `~/.kube/config` resolved to the guarded object
  - after unmount, the original host file was unchanged
- the same enrolled-parent path now also works for multiple guarded files under one mounted parent:
  - guarded siblings project from their backing objects
  - nested guarded paths project through synthetic intermediate directories inside the mount
  - unguarded siblings still passthrough
  - unmount restores the original host files unchanged
- the same runtime now also supervises multiple planned mounts in one foreground run:
  - one child mount process per planned parent path
  - verified live on macOS with simultaneous `.kube` and `.ssh` projections
  - parent `SIGINT` cleanly tears down the child mounts and restores the original host view
- macOS `._*` AppleDouble sidecars remain transient in the new enrolled-parent path and do not persist back into the real directory after unmount

## Layout

- `build.zig`: Zig build entrypoint
- `src/`: Zig application code
- `src/root.zig`: shared application module surface for tests and other non-CLI consumers
- `src/cli.zig`: command-line parsing, env loading, and mount command dispatch
- `src/config.zig`: `policy.yml` loading, mutation, and mount-plan derivation
- `src/filesystem.zig`: Zig-owned guarded-root and enrolled-parent filesystem behavior
- `tests/`: Zig integration tests and scenario coverage
- `c/`: thin C boundary that owns `libfuse` interop and syscall-adjacent helpers
- `docs/`: brief and research notes
- `vendor/zig-yaml/`: vendored YAML parser used for `policy.yml`

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

Toolchain pinning:
- `zig-toolchain.json` is the source of truth for the Zig toolchain we care about today:
  - one shared Zig version
  - one SHA256 per pinned platform archive
  - Linux `x86_64` for CI
  - macOS `aarch64` for local development on Apple Silicon
- CI reads `zig-toolchain.json` and verifies the downloaded Linux archive checksum before unpacking it
- `renovate.json` updates the shared Zig version plus both platform SHA256 values from Zig's official download index, filtering to stable releases only and grouping the updates as one Zig toolchain change

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
./tests/smoke/mount-allow.sh
./tests/smoke/mount-prompt.sh
```

What each command covers:
- `zig build`: compile the CLI binary and the C `libfuse` shim
- `zig build test`: run both Zig test roots wired in `build.zig`
  - `tests/integration.zig`: dry-run integration coverage for the session/filesystem boundary
  - `src/prompt.zig`: prompt broker unit tests
- `zig build compile-commands`: regenerate `compile_commands.json` for clangd
- `./tests/smoke/mount-allow.sh`: live mount verification for the allow-by-default guarded-root path, with one shared core smoke flow plus platform-specific helpers and extra coverage where the host platform supports it
- `./tests/smoke/mount-prompt.sh`: live macFUSE prompt verification for allow once, deny once, timeout, audit stdout, and status FIFO output

When debugging a specific area, the build-managed test step above is still the default, but the underlying Zig test roots are:
- `tests/integration.zig`
- `src/prompt.zig`

Prompt notes:
- `file-snitch run [allow|deny|prompt] (--foreground|--daemon) [--policy <path>]` is the new policy-driven daemon entrypoint
- `run --foreground` supports multiple planned mounts and mounts each real parent directory in place
- each planned mount is still projected as its own child mount process
- multiple enrolled files under one mounted tree are supported, including nested guarded paths
- multi-mount `run prompt` and multi-mount `run --daemon` are still unsupported
- `file-snitch enroll <path>` migrates the plaintext file into the guarded store and appends an enrollment to `policy.yml`
- `file-snitch unenroll <path>` restores the guarded file to its original path and removes remembered decisions for that path
- `file-snitch status` prints the current enrollments plus the derived mount plan
- `file-snitch doctor` validates `policy.yml`, guarded objects, and target-path health and exits non-zero on actionable problems
- durable decisions from `policy.yml` are now enforced by `run` for exact enrolled paths, keyed by `executable_path`, `uid`, and approval class
- the enrolled file's guarded object is currently resolved as `~/.var/file-snitch/guarded-secrets/<object_id>`
- `file-snitch mount <mount-path> <backing-store-path> prompt` enables the CLI broker
- `file-snitch mount ... --status-fifo <path>` writes status JSON snapshots to an existing named pipe
- mount mode always writes audit JSON lines to stdout
- `run prompt --daemon` is intentionally rejected for now because the only prompt broker is interactive
- on the mounted FUSE path, `prompt` mode currently targets `open` and `create`, and the prompt text includes the open mode
- later operations on an already-authorized handle may reuse that authorization when the requested behavior still aligns with the handle mode
- `readonly` still allows reads and denies mutations
- the terminal broker currently prints structured prompt JSON before each question and defaults blank terminal input to allow (`[Y/n]`)
- prompt timeout defaults to 5 seconds and falls back to deny
- set `FILE_SNITCH_PROMPT_TIMEOUT_MS` to shorten or lengthen that timeout during manual testing
- xattr traffic does not prompt in this mode; xattr mediation is deferred to future work
