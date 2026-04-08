# Backlog

Long-term task tracking for turning the brief in [docs/initial-brief.md](./docs/initial-brief.md) into a working product.

Status:
- `[ ]` not started
- `[~]` in progress
- `[x]` done
- `blocked` waiting on research or a product decision

## Current priorities

- `[~]` Make policy-driven exact-file enrollment the default product path
  - `run`, `enroll`, `unenroll`, `status`, and `doctor` now exist
  - `policy.yml` is now the durable source of truth for enrollments and remembered decisions
  - the old `mount <mount-path> <backing-store-path>` path still exists as legacy scaffolding
- `[x]` Move from projection-only protection to real secret custody
  - `enroll` already evacuates plaintext from the original path
  - guarded objects now live behind a store abstraction instead of plaintext files in `~/.var`
  - the current backend is `pass` under a `file-snitch/` subtree
  - the current `pass` path has been verified end to end against a real local `pass` installation
  - keep the boundary generic enough to add `1password` and `bitwarden` backends later
- `[x]` Make the daemon reconcile policy changes without restart
  - foreground `run` now polls `policy.yml` and adds or removes mount workers as the derived mount plan changes
  - foreground `run` now stays alive even when policy is empty
  - daemonized `run` now uses the same reconciler model
  - reload durable decisions currently happens by restarting affected mount workers on policy change
- `[ ]` Replace the current local TTY prompt path with an agent-style broker model
  - the current CLI prompt is acceptable as a bootstrap and debugging broker only
  - define one broker protocol that mount daemons can talk to locally or over forwarding
  - support forwarding prompt requests from remote hosts back to the workstation where the user is active
  - stop treating multi-mount local `run prompt` as the product goal
- `[x]` Replace the old guarded-root smoke coverage with policy-driven black-box smoke tests
  - empty policy
  - policy lifecycle
  - single-enrollment projection
  - multi-mount projection
  - single-mount prompt behavior

## Cross-cutting guardrails

These are not backlog items to “finish.” They are constraints that future changes should preserve.

- Keep the C shim as a faithful FUSE harness. It should expose complete callback detail upward even if Zig later filters or suppresses user-facing audit output.
- Keep authorization aligned with the requested behavior. A granted read-like handle must not silently authorize later write-like behavior.
- Keep prompts ahead of side effects. Authorization decisions should happen before the guarded operation takes effect.

## Phase 0: ground-truth research

Deliverable: a short report covering the selected target apps/tools, their secret file locations, and their real file IO behavior, including any targets that turn out not to be good file-enrollment fits.

- `[x]` Create a target-app matrix with space for observed paths, operations, and quirks
- `[x]` Pick 10 target apps/tools to study
- `[x]` Capture expected secret-bearing paths for each target
- `[x]` Record real file IO behavior for each target:
  - open flags
  - read vs write behavior
  - temp file plus rename behavior
  - chmod/chown usage
  - file locking behavior
  - current matrix in [docs/research/2 - target-app-matrix.md](./docs/research/2%20-%20target-app-matrix.md)
  - OpenRouter remained a useful negative finding rather than a validated file-bearing target
- `[x]` Summarize which filesystem operations v1 must mediate
  - current recommendation captured in [docs/research/7 - mediated-operation-set.md](./docs/research/7%20-%20mediated-operation-set.md)
- `[x]` Compare Linux spike implementation options and record a recommendation
- `[x]` Define the Zig/C boundary if the spike uses Zig with a thin C `libfuse` shim
- `[x]` Verify caller attribution assumptions on Linux with `fuse_get_context()`
  - current findings in [docs/research/5 - attribution-notes.md](./docs/research/5%20-%20attribution-notes.md)
  - verified for simple shell request-time flows and a real `gh` config-read path; accepted as sufficient for Phase 0
  - important caveat: `release` is not actor-bearing on Linux and must not drive policy or cache decisions
- `[x]` Verify caller attribution assumptions on macOS with macFUSE
  - current findings in [docs/research/5 - attribution-notes.md](./docs/research/5%20-%20attribution-notes.md)
  - verified for simple VFS-backed shell request-time flows and a real `gh` config-read path; accepted as sufficient for Phase 0
  - important caveat: current findings are VFS-backed observations, not a blanket claim about the FSKit backend
- `[x]` Document prompt latency constraints and timeout assumptions
  - current assumptions captured in [docs/research/8 - prompt-latency-and-timeouts.md](./docs/research/8%20-%20prompt-latency-and-timeouts.md)
- `[x]` Produce a recommendation for the exact Linux spike scope
  - current architecture recommendation captured in [docs/research/4 - file-enrollment-architecture.md](./docs/research/4%20-%20file-enrollment-architecture.md)
  - current scope: exact-path file enrollment, sparse parent-directory virtualization, full unprotected-subtree passthrough, temp files ignored as protected objects
- `[x]` Validate the minimal non-overlapping mount-planner strategy for per-file enrollment
  - recommendation captured in [docs/research/10 - mount-planner-strategy.md](./docs/research/10%20-%20mount-planner-strategy.md)
- `[x]` Produce a recommendation for the exact v1 durable decision key after attribution validation
  - floor shape: executable path + uid + exact enrolled path + approval class
  - recommendation captured in [docs/research/6 - durable-decision-key.md](./docs/research/6%20-%20durable-decision-key.md)

## Phase 1: Linux spike

Goal: a single guarded root with top-level files only, in-memory policy, and a CLI prompt.

- `[x]` Commit to a Zig core with a thin C `libfuse` shim for the spike
- `[x]` Create repo structure for daemon, policy engine, and prompt broker
- `[x]` Define a stub daemon-to-`libfuse` session lifecycle before implementing mount behavior
- `[x]` Wire a minimal high-level `fuse_operations` table before implementing real filesystem behavior
- `[x]` Build mount argv and a real `fuse_setup`/`fuse_loop` execution path
- `[x]` Implement the first safe filesystem behavior instead of all-ENOENT stubs
- `[x]` Expose one readable synthetic file from the mounted root
- `[x]` Add a dry-run inspection path for synthetic filesystem behavior
- `[x]` Support one-level in-memory regular files under the mounted root
- `[x]` Add an explicit mutation policy flag to the session model
- `[x]` Verify the deny path for the mutation policy without mounting
- `[x]` Record a minimal in-memory audit trail for reads and mutations
- `[x]` Expose the in-memory audit trail as a readable synthetic file
- `[x]` Seed one-level regular files from a host backing-store directory
- `[x]` Persist one-level regular file mutations into the host backing-store directory
- `[x]` Support one-level file rename with backing-store persistence
- `[x]` Support one-level chmod with backing-store persistence
- `[x]` Support one-level `chown` handling consistent with the backing-store view
- `[x]` Support one-level file flush and fsync against the backing-store directory
- `[x]` Support one-level xattr passthrough against the backing-store directory on macOS
- `[x]` Move the guarded-directory model out of the C shim and into Zig-owned daemon state
- `[x]` Replace the C-owned mutation flag with a Zig-owned default mutation outcome
- `[x]` Mount one guarded directory backed by a simple store
- `[x]` Verify rename-over-existing on the live mount path
- `[x]` Verify hidden-temp and backup-style save flows on the live mount path
- `[x]` Verify truncate-write, chmod, swap cleanup, and partial-overwrite flows on the live mount path
- `[x]` Keep macOS `._*` sidecar files transient instead of persisting them
- `[x]` Verify xattr round-trips on the live mount path
- `[x]` Verify BSD `flock` and POSIX lock contention on the live mount path
- `[x]` Verify self-`chown` on the live mount path
- `[x]` Make the mounted root behave like a guarded directory instead of an empty synthetic root
- `[x]` Implement the minimum file-centric FUSE operations for the current spike:
  - `getattr`
  - `readdir`
  - `open`
  - `create`
  - `read`
  - `write`
  - `flush`
  - `fsync`
  - `release`
  - `rename`
  - `unlink`
  - `truncate`
- `[x]` Reject `mkdir` and `rmdir` explicitly while the spike remains file-only
- `[x]` Add an in-memory policy engine with allow, deny, and prompt outcomes
- `[x]` Add one-shot prompt decisions for allow once, deny once, and timeout
- `[x]` Emit structured JSON audit logs with actor and operation detail
- `[x]` Test common editor temp-write and rename flows
- `[x]` Verify live prompt allow, deny, and timeout flows on macOS
- `[x]` Package a reproducible spike workflow through the maintained smoke-test entrypoints
- `[x]` Verify the live guarded-root spike on Linux

## Phase 1.5: policy-driven file enrollment pivot

Goal: keep the Phase 1 FUSE core, but replace the guarded-root demo with a real exact-file enrollment demo driven by durable policy.

- `[x]` Add a YAML parser dependency for `policy.yml`
- `[x]` Define the initial `policy.yml` schema
  - `version`
  - `enrollments`
  - `decisions`
- `[x]` Load `policy.yml` from `~/.config/file-snitch/policy.yml` by default
- `[x]` Accept an override path for `policy.yml` in the CLI
- `[x]` Make empty or missing enrollments a no-op instead of requiring a synthetic mount root
- `[x]` Add product-facing CLI verbs:
  - `run`
  - `enroll`
  - `unenroll`
  - `status`
  - `doctor`
- `[x]` Require `run` to receive either `--daemon` or `--foreground`
- `[x]` Make `enroll` migrate the plaintext file into the guarded store and update `policy.yml`
- `[x]` Make `unenroll` restore the guarded file to its original path and remove policy state
- `[x]` Make `status` report enrollments, derived mounts, and daemon-relevant configuration from `policy.yml`
- `[x]` Make `doctor` validate the policy file, guarded objects, and target-path health without mutating state
- `[~]` Replace the legacy guarded-root product path with policy-driven mount planning
  - `run` is now the real product path
  - `mount` still exists as legacy scaffolding and should not remain the public center of gravity
- `[x]` Preserve one real underlying parent-directory handle per planned mount for sibling passthrough after mounting
- `[x]` Distinguish guarded files from passthrough files in the Zig-owned lookup model
- `[x]` Move directory enumeration out of the root-only shim path so mounted parent directories can expose guarded files plus passthrough siblings
  - the shim still owns `readdir`, but it no longer hardcodes a single guarded root entry
- `[x]` Demonstrate one real exact-file flow, starting with kubeconfig-style `~/.kube/config`
  - verified live on macOS against a real `~/.kube/config` shadowed from an alternate guarded object
  - same projection model also verified live for multiple guarded siblings under one mounted parent
- `[x]` Support nested guarded paths inside a mounted parent tree
  - verified in integration coverage and live on macOS with a guarded `extensions/foo/token.json`-style path
- `[x]` Support multiple planned mounts in one foreground `run` invocation
  - implemented as one supervised child mount process per planned parent path
  - verified live on macOS with simultaneous `.kube` and `.ssh` projections plus clean `SIGINT` teardown
- `[x]` Replace the old guarded-root smoke suite with policy-driven black-box smoke coverage
  - `run-empty-policy.sh`
  - `policy-lifecycle.sh`
  - `run-single-enrollment.sh`
  - `run-multi-mount.sh`
  - `run-prompt-single.sh`

## Future work

- `[ ]` Add directory support beyond the root itself
- `[ ]` Revisit xattr mediation beyond the current passthrough-only path
- `[ ]` Add prompt decisions beyond allow once, deny once, and timeout
- `[ ]` Align editor probe and save flows, including Vim writability probes and temp-file save semantics

## Phase 2: encryption layer

- `[ ]` Design encrypted backing-store format
- `[ ]` Define metadata model for paths, modes, timestamps, and IDs
- `[ ]` Implement per-file authenticated encryption
- `[ ]` Implement crash-safe write and rename handling
- `[ ]` Add key bootstrap via passphrase or OS keystore
- `[ ]` Verify ciphertext-only persistence at rest

## Phase 3: agent-style prompt broker

- `[ ]` Define daemon-to-broker protocol
- `[ ]` Implement a local agent-style broker with default-deny timeout behavior
- `[ ]` Keep the current terminal broker as a bootstrap/debug fallback, not the final UX
- `[ ]` Support forwarding decision requests from remote hosts back to the active user workstation
- `[ ]` Add decisions: allow once, deny once, allow 5 min, always allow, always deny
- `[ ]` Persist rules independently from the daemon process
- `[ ]` Add a recent-events view
- `[ ]` Add a basic rule editor
- `[ ]` Verify daemon behavior when the UI is unavailable or restarted
- `[ ]` Add a specific warning for [LOLBins](https://gtfobins.org)

## Phase 4: macOS port

- `[ ]` Port the guarded-directory demo to macOS with macFUSE
- `[ ]` Reuse the shared rule model where possible
- `[ ]` Add signer lookup for caller attribution
- `[ ]` Validate install and permission friction around TCC and Full Disk Access
- `[ ]` Test at least 3 real target apps on macOS

## Phase 5: packaging and polish

- `[ ]` Add installers with Homebrew-focused packaging
- `[ ]` Support mount persistence across restarts
- `[ ]` Add config import and export
- `[ ]` Add debug bundle generation
- `[ ]` Write threat-model and operations docs. Be sure to include the hash of the requesting bin.
- `[ ]` Write install, usage, and troubleshooting docs

## Open decisions

- `[x]` Exact Zig/C boundary for `libfuse` interop after the current model/ABI split cleanup
- `[x]` Exact v1 protected scope: per-file enrollment with sparse parent-directory virtualization
  - architecture note: [docs/research/4 - file-enrollment-architecture.md](./docs/research/4%20-%20file-enrollment-architecture.md)
  - exact-path enrollment only, full unprotected-subtree passthrough, ignore temp files as protected objects
- `[x]` Exact v1 durable decision key
  - request-time executable path + uid + exact enrolled path + approval class
  - one-shot decisions stay ephemeral; time-bounded and persistent decisions live in a watched policy store
  - recommendation captured in [docs/research/6 - durable-decision-key.md](./docs/research/6%20-%20durable-decision-key.md)
- `[x]` Whether reads and writes need separate approval classes in v1
  - yes: keep distinct read-like and write-capable approval classes
  - read approval must not silently authorize later write behavior
- `[x]` Whether the backing store should expose filenames or only opaque IDs
  - use opaque IDs
  - canonical user paths live in enrollment and policy state, not as backing-store object names
