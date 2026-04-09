# Backlog

Long-term task tracking for turning the brief in
[docs/research/0 - initial-brief.md](./docs/research/0%20-%20initial-brief.md)
into a working product.

Status:
- `[ ]` not started
- `[~]` in progress
- `[x]` done
- `blocked` waiting on research or a product decision

## Current priorities

- `[x]` Make the project stance explicitly single-user and user-first
  - this is a user-space mediation tool for one user's own secret-bearing files
  - optimize for per-user services, per-user state, and home-directory secrets
  - do not design toward system-wide policy or protection from root
- `[~]` Make policy-driven exact-file enrollment the default product path
  - `run`, `enroll`, `unenroll`, `status`, and `doctor` now exist
  - `policy.yml` is now the durable source of truth for enrollments and remembered decisions
  - the old guarded-root spike has been removed from the supported runtime and now survives only in historical notes
  - new enrollments are currently limited to regular files under the current user's home directory and owned by that user
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
  - expiring durable decisions now age out at evaluation time without waiting for a policy reload
  - the reconciler rewrites `policy.yml` after pruning expired durable decisions
- `[ ]` Replace the current local TTY prompt path with an agent-style broker model
  - a first local agent service now exists on a user-owned Unix socket
  - the current frontend is `terminal-pinentry`
  - the current terminal UI is acceptable as a bootstrap and debugging frontend only
  - define one broker protocol that mount daemons can talk to locally or over forwarding
  - support forwarding prompt requests from remote hosts back to the workstation where the user is active
  - stop treating improvements to the current terminal UI as the product goal
- `[x]` Replace the old guarded-root smoke coverage with policy-driven black-box smoke tests
  - empty policy
  - policy lifecycle
  - single-enrollment projection
  - multi-mount projection
  - single-mount prompt behavior

## Cross-cutting guardrails

These are not backlog items to “finish.” They are constraints that future changes should preserve.

- Keep the product unapologetically user-first. This is not a system policy engine or a multi-user security boundary.
- Keep the C shim as a faithful FUSE harness. It should expose complete callback detail upward even if Zig later filters or suppresses user-facing audit output.
- Keep authorization aligned with the requested behavior. A granted read-like handle must not silently authorize later write-like behavior.
- Keep prompts ahead of side effects. Authorization decisions should happen before the guarded operation takes effect.

## Completed milestones

Earlier completed phases are summarized in
[docs/research/11 - completed-milestones.md](./docs/research/11%20-%20completed-milestones.md).
That note now carries the guarded-root spike history, the policy-driven
file-enrollment pivot, and the major Phase 0 research references.

## Future work

- `[ ]` Add directory support beyond the root itself
- `[ ]` Revisit xattr mediation beyond the current passthrough-only path
- `[ ]` Add prompt decisions beyond allow once, deny once, and timeout
- `[ ]` Align editor probe and save flows, including Vim writability probes and temp-file save semantics

## Phase 2: encryption layer

- `[ ]` Design encrypted guarded-object format
- `[ ]` Define metadata model for paths, modes, timestamps, and IDs
- `[ ]` Implement per-file authenticated encryption
- `[ ]` Implement crash-safe write and rename handling
- `[ ]` Add key bootstrap via passphrase or OS keystore
- `[ ]` Verify ciphertext-only persistence at rest

## Phase 3: agent-style prompt broker

- `[~]` Define daemon-to-broker protocol
  - initial protocol note: [docs/research/12 - agent-broker-protocol.md](./docs/research/12%20-%20agent-broker-protocol.md)
- `[~]` Implement a local agent-style broker with default-deny timeout behavior
  - `file-snitch agent (--foreground|--daemon)` now speaks the first local requester/agent socket protocol
  - `run prompt` now resolves through that local agent socket in both foreground and daemon mode
  - the current frontend is still terminal-only
  - the current smoke suite now covers the daemonized agent path through `terminal-pinentry`
- `[~]` Keep the current terminal broker as a bootstrap/debug fallback, not the final UX
  - the old direct daemon-stdin prompt path is gone
  - the remaining work is better agent frontends, not richer terminal prompting
- `[ ]` Support forwarding decision requests from remote hosts back to the active user workstation
  - forwarding is still user-to-user, not a shared multi-user authority model
- `[ ]` Add decisions: allow once, deny once, allow 5 min, always allow, always deny
- `[ ]` Persist rules independently from the daemon process
- `[ ]` Add a recent-events view
- `[ ]` Add a basic rule editor
- `[ ]` Verify daemon behavior when the UI is unavailable or restarted
- `[ ]` Add a specific warning for [LOLBins](https://gtfobins.org)

## Phase 4: macOS hardening

- `[x]` Port the guarded-directory demo to macOS with macFUSE
- `[x]` Reuse the shared rule model where possible
- `[ ]` Add signer lookup for caller attribution
- `[ ]` Validate install and permission friction around TCC and Full Disk Access
- `[ ]` Test at least 3 real target apps on macOS

## Phase 5: packaging and polish

- `[~]` Add installers with Homebrew-focused packaging
  - first `HEAD`-oriented Homebrew formula now exists at [Formula/file-snitch.rb](./Formula/file-snitch.rb)
  - install notes now live at [docs/install.md](./docs/install.md)
  - daemonized agent service now exists, but the current `terminal-pinentry` frontend is not yet the final user-service UX
- `[ ]` Add a native `.deb` package in addition to the Homebrew path
- `[ ]` Support mount persistence across restarts
- `[ ]` Add config import and export
- `[x]` Add debug dossier export from `doctor`
- `[ ]` Write threat-model and operations docs. Be sure to include the hash of the requesting bin.
- `[~]` Write install, usage, and troubleshooting docs
  - install notes now live at [docs/install.md](./docs/install.md)
  - disposable demo driver now lives at [scripts/demo-session.sh](./scripts/demo-session.sh)
  - issue templates now exist under [.github/ISSUE_TEMPLATE](./.github/ISSUE_TEMPLATE)

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
- `[x]` Whether the guarded-object store should expose filenames or only opaque IDs
  - use opaque IDs
  - canonical user paths live in enrollment and policy state, not as guarded-object names
