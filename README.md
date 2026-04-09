# File Snitch

Guarded FUSE mounts for secret files.

## Intro

File Snitch keeps selected secret-bearing files out of their normal host paths
until a user-owned daemon projects them back into place through FUSE. The
daemon consults a local agent before guarded access, and unguarded siblings in
the same directory still behave normally.

The product brief lives in [docs/initial-brief.md](./docs/initial-brief.md).

## What It Does Today

- exact-file enrollment for user-owned regular files under your home directory
- policy-driven `run`, `enroll`, `unenroll`, `status`, and `doctor` commands
- guarded-object custody through `pass:file-snitch/<object_id>`
- in-place projection back into real parent directories, with sibling passthrough
- durable remembered decisions in `policy.yml`, including RFC3339 UTC expiry
- a local requester/agent socket with the current `terminal-pinentry` frontend
- Homebrew/Linuxbrew packaging from `HEAD`

## What It Explicitly Does Not Do

- protect against root
- arbitrate between local users
- act as a system-wide MAC framework
- provide a GUI agent yet
- support store backends other than `pass` yet

## Quick Evaluation

Build the binary:

```bash
zig build
```

Then choose one of these:

- safe disposable demo:
  - [docs/demo.md](./docs/demo.md)
  - `./scripts/demo-session.sh`
- real install and first-user drill:
  - [docs/install.md](./docs/install.md)
- user service examples:
  - [docs/services.md](./docs/services.md)

## Recorded Demo

[![Recorded File Snitch demo](./docs/assets/demo.gif)](./docs/demo.md)

Regenerate the embedded demo artifacts with:

```bash
./scripts/regenerate-demo-artifacts.sh
```

The checked-in demo is a tmux-driven session that shows the agent pane, the
daemon pane, and a user shell triggering guarded access and sibling
passthrough.

## Reporting Problems

Before opening an issue, export a dossier:

```bash
file-snitch doctor --export-debug-dossier ./file-snitch-debug-dossier.md
```

The dossier includes environment and policy diagnostics, but it does not export
guarded file contents. Then use the issue templates under
[.github/ISSUE_TEMPLATE](./.github/ISSUE_TEMPLATE).

Operational guidance and troubleshooting live in
[docs/operations.md](./docs/operations.md).

## Security Stance

The short threat model lives in [docs/threat-model.md](./docs/threat-model.md).
Read that before assuming File Snitch is trying to be a system security
boundary. It is not.

## Working On The Repo

- contributor guide: [CONTRIBUTING.md](./CONTRIBUTING.md)
- release and packaging checklist: [docs/releasing.md](./docs/releasing.md)

## Current State

- File Snitch is intentionally user-space and single-user. It is meant to
  mediate one user's own secret-bearing files from that same user's software.
- `file-snitch run` loads `~/.config/file-snitch/policy.yml` by default,
  derives the mount plan, and in both foreground and daemon mode stays alive to
  reconcile policy changes over time.
- `enroll` migrates plaintext into the guarded store, `unenroll` restores it,
  and `status`/`doctor` inspect the resulting policy and mount plan.
- The current store backend is `pass`, and the real `pass` path has been
  verified end to end on macOS and Linux.
- The current agent service is local-only and user-owned. `run prompt` talks to
  that socket instead of reading daemon stdin directly.
- The current agent frontend is `terminal-pinentry`:
  - `agent --foreground` uses inherited stdio when no `--tty` is provided
  - `agent --daemon` can keep serving requests by reopening an explicit or
    startup-derived TTY path
- The remaining runtime limits are:
  - the current agent frontend is still terminal-only
  - only the `pass` backend exists today
  - remote forwarding and richer agent UX are future work

## Layout

- `build.zig`: Zig build entrypoint
- `src/`: Zig application code
- `src/root.zig`: shared application module surface for tests and other non-CLI consumers
- `src/cli.zig`: command-line parsing, env loading, and runtime command dispatch
- `src/policy_commands.zig`: `enroll`, `unenroll`, `status`, and `doctor`
- `src/enrollment.zig`: guarded-object migration and path-level enrollment helpers
- `src/config.zig`: `policy.yml` loading, mutation, and mount-plan derivation
- `src/agent.zig`: local requester/agent socket protocol, agent service, and `terminal-pinentry` frontend
- `src/filesystem.zig`: Zig-owned filesystem behavior for the current enrolled-parent runtime
- `tests/`: Zig integration tests and scenario coverage
- `c/`: thin C boundary that owns `libfuse` interop and syscall-adjacent helpers
- `docs/`: brief and research notes
- `vendor/zig-yaml/`: vendored YAML parser used for `policy.yml`

## Architecture guardrails

These are project-wide invariants. Refactors should preserve them unless the product direction changes explicitly.

- File Snitch is a user-first mediation tool, not a system-wide security framework. Optimize for one user's own home-directory secrets and user-owned services.
- The C shim is a faithful FUSE harness, not a product-policy layer. It should preserve callback timing and raw callback data, and it should not drop or embellish information before handing it to Zig.
- Fine-grained callback visibility must remain available even when Zig chooses not to emit a user-facing audit line for a given action. Audit filtering is a Zig/business decision, not a reason to weaken the shim.
- Authorization must align with intent. If a handle was authorized for read-like access and later attempts write-like behavior, that later behavior must still be independently mediable.
- Prompting must happen before the guarded operation takes effect. The system should prevent behavior, not merely report it after the fact.

## Scope

V1 scope is intentionally narrow:

- exact file enrollment, not directory protection as a product concept
- user-owned files under the current user's home directory
- per-user policy, state, sockets, and lock anchors
- user service deployment (`systemd --user` / LaunchAgent), not a system daemon

Out of scope for the product stance:

- protection from root
- cross-user policy arbitration
- system-wide mandatory access control
- shared multi-user agents or TCP-facing brokers

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
- Linux falls back to standard `fuse3` system locations if `pkg-config` is absent or cannot resolve a usable `fuse3.pc`
- macOS falls back to standard macFUSE locations under `/usr/local` and `/opt/homebrew` if `pkg-config` is absent
- `zig build compile-commands` now writes `compile_commands.json` for clangd from the same discovery logic
- after cloning or changing build flags, run `zig build compile-commands` so clangd picks up the correct C flags; `build.zig` remains the source of truth

## Install notes

The first packaging slice now lives at:
- [Formula/file-snitch.rb](./Formula/file-snitch.rb)
- [docs/install.md](./docs/install.md)

This is intentionally a `HEAD`-oriented Homebrew formula plus manual runtime
setup. The current prompt frontend is still `terminal-pinentry`, so background
user services are possible but not yet the final UX story.

## Verification

Current validation workflow:

```bash
zig build
zig build test
zig build compile-commands
./tests/smoke/run-empty-policy.sh
./tests/smoke/policy-lifecycle.sh
./tests/smoke/doctor-debug-dossier.sh
./tests/smoke/run-policy-reload.sh
./tests/smoke/run-daemon-policy-reload.sh
./tests/smoke/run-expired-decision-cleanup.sh
./tests/smoke/run-single-enrollment.sh
./tests/smoke/run-multi-mount.sh
./tests/smoke/run-prompt-single.sh
```

What each command covers:
- `zig build`: compile the CLI binary and the C `libfuse` shim
- `zig build test`: run both Zig test roots wired in `build.zig`
  - `tests/core_integration.zig`: dry-run core coverage for the session/filesystem boundary
  - `src/prompt.zig`: prompt broker unit tests
  - `src/store.zig`: guarded-store unit tests for object serialization and the mock backend
  - `src/agent.zig`: requester/agent framing and ULID unit tests
- `zig build compile-commands`: regenerate `compile_commands.json` for clangd
- `./tests/smoke/run-empty-policy.sh`: black-box verification that foreground `run` stays alive and watches for future changes even when policy is currently empty
- `./tests/smoke/policy-lifecycle.sh`: black-box verification of `enroll`, `status`, `doctor`, and `unenroll`
- `./tests/smoke/doctor-debug-dossier.sh`: black-box verification that `doctor --export-debug-dossier` writes a shareable report without guarded file contents
- `./tests/smoke/run-policy-reload.sh`: black-box verification that foreground `run` watches `policy.yml`, activates a new projection after `enroll`, and tears it down again after the enrollment is removed from policy
- `./tests/smoke/run-daemon-policy-reload.sh`: black-box verification that daemonized `run` uses the same reconciler model and reacts to `policy.yml` changes without restart
- `./tests/smoke/run-expired-decision-cleanup.sh`: black-box verification that daemonized `run` prunes expired durable decisions and rewrites `policy.yml`
- `./tests/smoke/run-single-enrollment.sh`: live verification that one enrolled file is projected from the guarded store while siblings passthrough
- `./tests/smoke/run-multi-mount.sh`: live verification that one foreground `run` supervises multiple planned mounts and tears them down cleanly
- `./tests/smoke/run-prompt-single.sh`: live verification of the current local interactive prompt path for allow, deny, and timeout behavior through a daemonized agent and `terminal-pinentry`

When debugging a specific area, the build-managed test step above is still the default, but the underlying Zig test roots are:
- `tests/core_integration.zig`
- `src/prompt.zig`

Prompt notes:
- `file-snitch run [allow|deny|prompt] (--foreground|--daemon) [--policy <path>]` is the new policy-driven daemon entrypoint
- `run --foreground` is now the real long-lived reconciler: it stays alive on an empty policy, polls `policy.yml`, and adds or removes mount workers as the derived mount plan changes
- `run --daemon` now daemonizes the same reconciler model instead of using the older one-shot path
- `file-snitch agent (--foreground|--daemon)` starts the current local agent service on the default Unix socket
- the current frontend is `terminal-pinentry`
- `agent --foreground` uses inherited stdio when no `--tty` is provided
- `agent --daemon` requires `--tty <path>` or a startup TTY it can capture
- `run --foreground` supports multiple planned mounts and mounts each real parent directory in place
- each planned mount is still projected as its own child mount process
- multiple enrolled files under one mounted tree are supported, including nested guarded paths
- foreground and daemon mode now share the same policy-reconciliation behavior
- `run prompt` now resolves decisions through the local agent socket instead of reading from the daemon's stdin
- `file-snitch enroll <path>` migrates the plaintext file into the configured guarded store and appends an enrollment to `policy.yml`
- `file-snitch unenroll <path>` restores the guarded file to its original path and removes remembered decisions for that path
- `file-snitch status` prints the current enrollments plus the derived mount plan
- `file-snitch doctor` validates `policy.yml`, guarded objects, and target-path health and exits non-zero on actionable problems
- durable decisions from `policy.yml` are now enforced by `run` for exact enrolled paths, keyed by `executable_path`, `uid`, and approval class
- `expires_at` is optional on durable decisions and is enforced without requiring a daemon restart
- the reconciler also rewrites `policy.yml` after pruning expired durable decisions so the file does not accumulate dead entries
- accepted `expires_at` formats are:
  - quoted RFC3339 UTC timestamps like `"2026-04-09T12:34:56Z"`
- the current guarded-store ref is `pass:file-snitch/<object_id>`
- the production `pass` backend assumes a usable GPG environment; in practice that means `pass` must work and `GNUPGHOME` must resolve to a keyring that can decrypt the configured store
- the current agent service is intentionally paired only with a terminal frontend; the long-term goal is a fuller agent-style broker, more like `ssh-agent` or `gpg-agent`, with forwarding and richer frontends
- smoke tests use a fake `pass` binary plus a disposable `PASSWORD_STORE_DIR`; production code talks to the `pass` CLI directly
- a real local `pass` drill has been run outside CI with:
  - a disposable temp home
  - a disposable password store
  - a real local GPG key
  - `enroll -> run --foreground -> read/write -> unenroll`
- on the mounted FUSE path, `prompt` mode currently targets `open` and `create`, and the prompt text includes the open mode
- later operations on an already-authorized handle may reuse that authorization when the requested behavior still aligns with the handle mode
- `readonly` still allows reads and denies mutations
- the current `terminal-pinentry` frontend prints structured prompt JSON before each question and defaults blank terminal input to allow (`[Y/n]`)
- prompt timeout defaults to 5 seconds and falls back to deny
- set `FILE_SNITCH_PROMPT_TIMEOUT_MS` to shorten or lengthen that timeout during manual testing
- xattr traffic does not prompt in this mode; xattr mediation is deferred to future work
