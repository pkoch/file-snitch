# File Snitch

Guarded FUSE mounts for secret files.

## Intro

The product brief lives in [docs/initial-brief.md](./docs/initial-brief.md).

Current state:
- The repo has a real Zig `libfuse` core with a thin C shim. The shim preserves raw callback detail; policy timing, filesystem behavior, prompting, and audit semantics live in Zig.
- The product path is now policy-driven exact-file enrollment, not the old synthetic guarded-root demo. `file-snitch run` loads `~/.config/file-snitch/policy.yml` by default, derives the mount plan, and in both foreground and daemon mode stays alive to reconcile policy changes over time.
- The product-facing CLI surface is in place:
  - `run`
  - `enroll`
  - `unenroll`
  - `status`
  - `doctor`
- `enroll` now migrates plaintext into a store-backed guarded object, records the exact enrolled path in `policy.yml`, and `unenroll` restores it.
- the current store backend is `pass`, using entries under a `file-snitch/` subtree.
- the real `pass` path has now been verified end to end on macOS against a disposable temp home and a real local GPG key.
- The live projection model now works for real parent directories:
  - an enrolled file is projected back into its original parent directory from the guarded object
  - unguarded siblings passthrough from the preserved underlying directory
  - nested guarded paths under one mounted tree are supported
  - multiple planned mounts are supported in `run allow` and `run deny` by supervising one child mount process per mount path
- This has been verified live on macOS for:
  - a real kubeconfig-style target
  - multiple guarded files under one mounted parent
  - simultaneous `.kube` and `.ssh` projections in one foreground run
  - clean `SIGINT` teardown back to the original host view
- Durable remembered decisions from `policy.yml` compile into the runtime policy engine using the documented exact-path decision key, and expired decisions age out at evaluation time.
- Audit output is structured JSON on stdout and can include status snapshots via FIFO. Audit events include actor metadata (`pid`/`uid`/`gid` and `executable_path`), timestamps, and operation-specific detail.
- The current CLI prompt broker is live as a bootstrap/debug path, defaults blank input to allow, and still defaults timeout to deny.
- The remaining runtime limits are:
  - multi-mount `run prompt`
  - the current prompt path is still a local interactive broker, not the eventual agent-style broker model
  - only the `pass` store backend exists today; `1password` and `bitwarden` are future work
- The old guarded-root spike is still implemented internally for now, but it is no longer part of the public product surface.

## Layout

- `build.zig`: Zig build entrypoint
- `src/`: Zig application code
- `src/root.zig`: shared application module surface for tests and other non-CLI consumers
- `src/cli.zig`: command-line parsing, env loading, and runtime command dispatch
- `src/policy_commands.zig`: `enroll`, `unenroll`, `status`, and `doctor`
- `src/enrollment.zig`: guarded-object migration and path-level enrollment helpers
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
./tests/smoke/run-empty-policy.sh
./tests/smoke/policy-lifecycle.sh
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
  - `tests/integration.zig`: dry-run integration coverage for the session/filesystem boundary
  - `src/prompt.zig`: prompt broker unit tests
  - `src/store.zig`: guarded-store unit tests for object serialization and the mock backend
- `zig build compile-commands`: regenerate `compile_commands.json` for clangd
- `./tests/smoke/run-empty-policy.sh`: black-box verification that foreground `run` stays alive and watches for future changes even when policy is currently empty
- `./tests/smoke/policy-lifecycle.sh`: black-box verification of `enroll`, `status`, `doctor`, and `unenroll`
- `./tests/smoke/run-policy-reload.sh`: black-box verification that foreground `run` watches `policy.yml`, activates a new projection after `enroll`, and tears it down again after the enrollment is removed from policy
- `./tests/smoke/run-daemon-policy-reload.sh`: black-box verification that daemonized `run` uses the same reconciler model and reacts to `policy.yml` changes without restart
- `./tests/smoke/run-expired-decision-cleanup.sh`: black-box verification that daemonized `run` prunes expired durable decisions and rewrites `policy.yml`
- `./tests/smoke/run-single-enrollment.sh`: live verification that one enrolled file is projected from the guarded store while siblings passthrough
- `./tests/smoke/run-multi-mount.sh`: live verification that one foreground `run` supervises multiple planned mounts and tears them down cleanly
- `./tests/smoke/run-prompt-single.sh`: live verification of single-mount `run prompt` allow, deny, and timeout behavior

When debugging a specific area, the build-managed test step above is still the default, but the underlying Zig test roots are:
- `tests/integration.zig`
- `src/prompt.zig`

Prompt notes:
- `file-snitch run [allow|deny|prompt] (--foreground|--daemon) [--policy <path>]` is the new policy-driven daemon entrypoint
- `run --foreground` is now the real long-lived reconciler: it stays alive on an empty policy, polls `policy.yml`, and adds or removes mount workers as the derived mount plan changes
- `run --daemon` now daemonizes the same reconciler model instead of using the older one-shot path
- `run --foreground` supports multiple planned mounts and mounts each real parent directory in place
- each planned mount is still projected as its own child mount process
- multiple enrolled files under one mounted tree are supported, including nested guarded paths
- foreground and daemon mode now share the same policy-reconciliation behavior
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
- `run prompt --daemon` is intentionally rejected for now because the current broker is interactive
- the long-term goal is an agent-style broker, more like `ssh-agent` or `gpg-agent`, not richer local TTY prompting per daemon
- smoke tests use a fake `pass` binary plus a disposable `PASSWORD_STORE_DIR`; production code talks to the `pass` CLI directly
- a real local `pass` drill has been run outside CI with:
  - a disposable temp home
  - a disposable password store
  - a real local GPG key
  - `enroll -> run --foreground -> read/write -> unenroll`
- on the mounted FUSE path, `prompt` mode currently targets `open` and `create`, and the prompt text includes the open mode
- later operations on an already-authorized handle may reuse that authorization when the requested behavior still aligns with the handle mode
- `readonly` still allows reads and denies mutations
- the terminal broker currently prints structured prompt JSON before each question and defaults blank terminal input to allow (`[Y/n]`)
- prompt timeout defaults to 5 seconds and falls back to deny
- set `FILE_SNITCH_PROMPT_TIMEOUT_MS` to shorten or lengthen that timeout during manual testing
- xattr traffic does not prompt in this mode; xattr mediation is deferred to future work
