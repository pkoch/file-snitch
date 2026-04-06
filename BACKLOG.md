# Backlog

Long-term task tracking for turning the brief in [docs/initial-brief.md](./docs/initial-brief.md) into a working product.

Status:
- `[ ]` not started
- `[~]` in progress
- `[x]` done
- `blocked` waiting on research or a product decision

## Current priorities

- `[~]` Finish the remaining phase-0 research before expanding the phase-1 surface further
- `[ ]` Record real file IO behavior for the selected target apps/tools
- `[ ]` Narrow the v1 mediated operation set based on observed write patterns
- `[ ]` Define the smallest end-to-end Linux spike demo
- `[ ]` Validate the minimal non-overlapping mount-planner strategy for per-file enrollment

## Cross-cutting guardrails

These are not backlog items to “finish.” They are constraints that future changes should preserve.

- Keep the C shim as a faithful FUSE harness. It should expose complete callback detail upward even if Zig later filters or suppresses user-facing audit output.
- Keep authorization aligned with the requested behavior. A granted read-like handle must not silently authorize later write-like behavior.
- Keep prompts ahead of side effects. Authorization decisions should happen before the guarded operation takes effect.

## Phase 0: ground-truth research

Deliverable: a short report covering 10 target apps/tools, their secret file locations, and their real file IO behavior.

- `[x]` Create a target-app matrix with space for observed paths, operations, and quirks
- `[x]` Pick 10 target apps/tools to study
- `[~]` Capture expected secret-bearing paths for each target
- `[ ]` Record real file IO behavior for each target:
  - open flags
  - read vs write behavior
  - temp file plus rename behavior
  - chmod/chown usage
  - file locking behavior
- `[ ]` Summarize which filesystem operations v1 must mediate
- `[x]` Compare Linux spike implementation options and record a recommendation
- `[x]` Define the Zig/C boundary if the spike uses Zig with a thin C `libfuse` shim
- `[ ]` Verify caller attribution assumptions on Linux with `fuse_get_context()`
- `[ ]` Verify caller attribution assumptions on macOS with macFUSE
- `[ ]` Document prompt latency constraints and timeout assumptions
- `[x]` Produce a recommendation for the exact Linux spike scope
  - current architecture recommendation captured in [docs/research/4 - file-enrollment-architecture.md](./docs/research/4%20-%20file-enrollment-architecture.md)
  - current scope: exact-path file enrollment, sparse parent-directory virtualization, full unprotected-subtree passthrough, temp files ignored as protected objects
- `[ ]` Produce a recommendation for the exact v1 approval cache key after attribution validation
  - floor shape: caller identity + exact enrolled path + approval class

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

## Phase 3: GUI prompt broker

- `[ ]` Define daemon-to-broker protocol
- `[ ]` Implement a desktop prompt with default-deny timeout behavior
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
- `[ ]` Exact v1 approval cache key
  - move to Phase 0 recommendation work after attribution validation
- `[x]` Whether reads and writes need separate approval classes in v1
  - yes: keep distinct read-like and write-capable approval classes
  - read approval must not silently authorize later write behavior
- `[x]` Whether the backing store should expose filenames or only opaque IDs
  - use opaque IDs
  - canonical user paths live in enrollment and policy state, not as backing-store object names
