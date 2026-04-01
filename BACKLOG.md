# Backlog

Long-term task tracking for turning the brief in [docs/initial-brief.md](./docs/initial-brief.md) into a working product.

Status:
- `[ ]` not started
- `[~]` in progress
- `[x]` done
- `blocked` waiting on research or a product decision

## Current priorities

- `[~]` Convert the brief into a concrete execution backlog
- `[~]` Build a phase-0 research matrix for target apps and file IO patterns
- `[x]` Stand up the initial Zig project scaffold and thin C `libfuse` boundary
- `[ ]` Narrow the v1 mediated operation set based on observed write patterns
- `[ ]` Define the smallest end-to-end Linux spike demo

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
- `[~]` Define the Zig/C boundary if the spike uses Zig with a thin C `libfuse` shim
- `[ ]` Verify caller attribution assumptions on Linux with `fuse_get_context()`
- `[ ]` Verify caller attribution assumptions on macOS with macFUSE
- `[ ]` Document prompt latency constraints and timeout assumptions
- `[ ]` Produce a recommendation for the exact Linux spike scope

## Phase 1: Linux spike

Goal: a single guarded directory with in-memory policy and a CLI prompt.

- `[x]` Commit to a Zig core with a thin C `libfuse` shim for the spike
- `[~]` Create repo structure for daemon, policy engine, and prompt broker
- `[x]` Define a stub daemon-to-`libfuse` session lifecycle before implementing mount behavior
- `[x]` Wire a minimal high-level `fuse_operations` table before implementing real filesystem behavior
- `[x]` Build mount argv and a real `fuse_setup`/`fuse_loop` execution path
- `[~]` Implement the first safe filesystem behavior instead of all-ENOENT stubs
- `[ ]` Mount one guarded directory backed by a simple store
- `[ ]` Implement the minimum FUSE operations:
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
  - `mkdir`
  - `rmdir`
  - `truncate`
- `[ ]` Add an in-memory policy engine with allow, deny, and prompt outcomes
- `[ ]` Add a CLI prompt path with default-deny timeout behavior
- `[ ]` Support allow-once decisions
- `[ ]` Emit structured JSON audit logs
- `[ ]` Test common editor temp-write and rename flows
- `[ ]` Package a reproducible spike demo

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
- `[ ]` Write threat-model and operations docs
- `[ ]` Write install, usage, and troubleshooting docs

## Open decisions

- `[~]` Exact Zig/C boundary for `libfuse` interop
- `[ ]` Exact v1 protected scope: per-file enrollment vs path-based trees only
- `[ ]` Exact v1 approval cache key
- `[ ]` Whether reads and writes need separate approval classes in v1
- `[ ]` Whether the backing store should expose filenames or only opaque IDs
