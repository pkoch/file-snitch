# File Snitch

Keep tools from silently reading your kubeconfig, SSH keys, and other
secret-bearing files.

If you are evaluating the project for the first time, start with
[docs/index.md](./docs/index.md).

## Intro

File Snitch keeps selected secret-bearing files out of their normal host paths
until a user-owned daemon projects them back into place through FUSE. The
daemon consults a local agent before guarded access, and unguarded siblings in
the same directory still behave normally.

The product brief lives in
[docs/research/0 - initial-brief.md](./docs/research/0%20-%20initial-brief.md).

## What It Does Today

- exact-file enrollment for user-owned regular files under your home directory
- policy-driven `run`, `enroll`, `unenroll`, `status`, and `doctor` commands
- guarded-object custody through `pass:file-snitch/<object_id>`
- in-place projection back into real parent directories, with sibling passthrough
- durable remembered decisions in `policy.yml`, including RFC3339 UTC expiry
- a local requester/agent socket with:
  - `terminal-pinentry`
  - `macos-ui` on macOS via `osascript`
  - `linux-ui` on Linux via `zenity`
- formal release artifacts on GitHub Releases plus Homebrew/Linuxbrew packaging
- per-user service install helpers for `launchd` and `systemd --user`

## What It Explicitly Does Not Do

- protect against root
- arbitrate between local users
- act as a system-wide MAC framework
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
  - `./scripts/install-user-services.sh --bin "$(command -v file-snitch)"`

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
- Per-user service install helpers now exist under `scripts/`.
- The current agent frontends are:
  - `terminal-pinentry`
    - `agent --foreground` uses inherited stdio when no `--tty` is provided
    - `agent --daemon` can keep serving requests by reopening an explicit or
      startup-derived TTY path
  - `macos-ui`
    - macOS-only frontend backed by `osascript`
    - works in both foreground and daemon mode
  - `linux-ui`
    - Linux-only frontend backed by `zenity`
    - works in both foreground and daemon mode
- The remaining runtime limits are:
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
- `src/agent.zig`: local requester/agent socket protocol, agent service, and the current frontends
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

Current packaging and release notes live at:
- [pkoch/homebrew-tap](https://github.com/pkoch/homebrew-tap)
- [docs/install.md](./docs/install.md)
- [docs/releasing.md](./docs/releasing.md)

Formal tagged releases publish the canonical source and binary artifacts on
GitHub Releases, with Homebrew consuming the tagged source tarball. Those
releases also publish `SHA256SUMS` and `release-manifest.json` so downstream
packaging can follow the same pinned source, toolchain, and SDK inputs.
Installing unreleased `master` builds remains available through the tap
formula's `--HEAD` path when needed.

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
./tests/smoke/run-prompt-linux-ui.sh
./tests/smoke/run-prompt-single.sh
./tests/smoke/run-prompt-remembered-decision.sh
./tests/smoke/user-service-rendering.sh
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
- `./tests/smoke/run-prompt-linux-ui.sh`: black-box verification of the `linux-ui` frontend through a fake `zenity` path that can run in CI
- `./tests/smoke/run-prompt-macos-ui.sh`: black-box verification of the `macos-ui` frontend through a fake `osascript` path on macOS
- `./tests/smoke/run-prompt-single.sh`: live verification of the current local interactive prompt path for allow, deny, and timeout behavior through a daemonized agent and `terminal-pinentry`
- `./tests/smoke/run-prompt-remembered-decision.sh`: black-box verification that an `always allow` decision is written to `policy.yml`, reconciled by `run`, and suppresses later prompts
- `./tests/smoke/user-service-rendering.sh`: black-box verification that the user-service helpers render the expected `launchd` and `systemd --user` files

When debugging a specific area, the build-managed test step above is still the default, but the underlying Zig test roots are:
- `tests/core_integration.zig`
- `src/prompt.zig`

Prompt notes:
- `file-snitch run [allow|deny|prompt] (--foreground|--daemon) [--policy <path>]` is the new policy-driven daemon entrypoint
- `run --foreground` is now the real long-lived reconciler: it stays alive on an empty policy, prefers event-driven `policy.yml` wakeups where the host supports them, falls back to polling where it does not, and adds or removes mount workers as the derived mount plan changes
- the polling fallback now compares full `policy.yml` content as well as file metadata, so same-size rewrites do not rely on mtime luck or a small-file cutoff
- transient policy read/stat failures are no longer treated as “policy disappeared”; the reconciler keeps the current mounts and surfaces the real error instead
- `run --daemon` now daemonizes the same reconciler model instead of using the older one-shot path
- `file-snitch agent (--foreground|--daemon)` starts the current local agent service on the default Unix socket
- the agent now refuses to unlink an active socket or any non-socket file at the configured socket path
- the agent now handles accepted socket connections independently, so one blocked prompt no longer head-of-line blocks later requests at the socket boundary
- the default frontend is `terminal-pinentry`
- `--frontend terminal-pinentry` keeps the existing terminal behavior
- `--frontend macos-ui` uses `osascript` to show a native macOS dialog
- `--frontend linux-ui` uses `zenity` to show a native Linux dialog
- `agent --foreground` uses inherited stdio when `--frontend terminal-pinentry` has no `--tty`
- `agent --daemon` requires `--tty <path>` or a startup TTY it can capture when using `terminal-pinentry`
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
- policy updates are now serialized with a sidecar lock so `enroll`, `unenroll`, remembered decisions, and daemon expiry pruning do not clobber each other
- prompt-capable frontends now expose:
  - allow once
  - deny once
  - allow 5 min
  - always allow
  - always deny
- remembered decisions are written by the requester into `policy.yml`; the agent only returns the chosen response
- remembered decisions now take effect inside the live mount worker on the next access; they no longer wait for supervisor remount/restart to start suppressing prompts
- `expires_at` is optional on durable decisions and is enforced without requiring a daemon restart
- the reconciler also rewrites `policy.yml` after pruning expired durable decisions so the file does not accumulate dead entries
- accepted `expires_at` formats are:
  - quoted RFC3339 UTC timestamps like `"2026-04-09T12:34:56Z"`
- the current guarded-store ref is `pass:file-snitch/<object_id>`
- the production `pass` backend assumes a usable GPG environment; in practice that means `pass` must work and `GNUPGHOME` must resolve to a keyring that can decrypt the configured store
- the current agent service now has one bootstrap terminal frontend and one first native macOS frontend; the long-term goal is still a fuller agent-style broker, more like `ssh-agent` or `gpg-agent`, with forwarding and richer frontends
- smoke tests use a fake `pass` binary plus a disposable `PASSWORD_STORE_DIR`; production code talks to the `pass` CLI directly
- a real local `pass` drill has been run outside CI with:
  - a disposable temp home
  - a disposable password store
  - a real local GPG key
  - `enroll -> run --foreground -> read/write -> unenroll`
- on the mounted FUSE path, `prompt` mode currently targets `open` and `create`, and the prompt text includes the open mode
- later operations on an already-authorized handle may reuse that authorization when the requested behavior still aligns with the handle mode
- `readonly` still allows reads and denies mutations
- the current `terminal-pinentry` frontend prints structured prompt JSON before each question and supports once, timed, and durable decisions
- the current `macos-ui` and `linux-ui` frontends return once, timed, and durable decisions back to the agent
- prompt timeout defaults to 5 seconds and falls back to deny
- set `FILE_SNITCH_PROMPT_TIMEOUT_MS` to shorten or lengthen that timeout during manual testing
- xattr traffic does not prompt in this mode; xattr mediation is deferred to future work
