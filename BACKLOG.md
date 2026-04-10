# Backlog

Forward-looking task tracking for File Snitch.

Status:
- `[ ]` not started
- `[~]` in progress
- `[x]` done
- `blocked` waiting on research or a product decision

## Current priorities

- `[ ]` Support remote forwarding for the requester/agent protocol
  - keep the transport stream-friendly and user-to-user
  - make it easy to forward prompts back to the workstation where the user is present
  - keep requester-side policy ownership: forwarded decisions should still land in the requester's `policy.yml`
- `[ ]` Make the packaged user-service story boring
  - verify the current `launchd` and `systemd --user` helpers in more real environments
  - tighten `doctor` around service drift and common install mistakes
  - decide later whether service install stays script-based or moves into the CLI
- `[ ]` Improve daily-driver frontend UX
  - keep `terminal-pinentry` as the bootstrap/debug fallback
  - harden `macos-ui` and `linux-ui` behavior around helper failures and restarts
  - make sure remembered decisions feel predictable and visible without adding a second policy surface
- `[ ]` Broaden packaging beyond Homebrew/Linuxbrew
  - add a native `.deb` package
  - keep Linux honest about distro FUSE prerequisites even when Homebrew is used
- `[ ]` Harden macOS-specific attribution and install behavior
  - add signer lookup for caller attribution
  - validate TCC and Full Disk Access friction explicitly
  - test more real macOS target apps against the current product path

## Active product work

- `[ ]` Support forwarding decision requests from remote hosts back to the active user workstation
  - protocol note: [docs/research/12 - agent-broker-protocol.md](./docs/research/12%20-%20agent-broker-protocol.md)
- `[ ]` Verify daemon behavior when the UI is unavailable or restarted
- `[ ]` Add a recent-events view
- `[ ]` Add a basic rule editor
- `[ ]` Add a specific warning for [LOLBins](https://gtfobins.org)
- `[ ]` Add directory support beyond the root itself
- `[ ]` Revisit xattr mediation beyond the current passthrough-only path
- `[ ]` Align editor probe and save flows, including Vim writability probes and temp-file save semantics
- `[ ]` Support mount persistence across restarts
- `[ ]` Add config import and export

## Future backend work

- `[ ]` Add more guarded-object backends beyond `pass`
  - likely first candidates: `1password`, `bitwarden`
- `[ ]` Revisit an encrypted native guarded-object format only if the project outgrows the external-store model

## Docs and packaging follow-up

- `[ ]` Keep the public docs and demo assets in sync with the real product path
- `[ ]` Keep the issue templates and debug dossier aligned with the most common support failures
- `[ ]` Add a native `.deb` package in addition to the Homebrew path

## Settled architecture

These are no longer open decisions. Future changes should preserve them unless
the product direction changes explicitly.

- File Snitch is a single-user, user-space mediation tool. It is not a system policy engine and it does not protect against root.
- Exact-file enrollment is the product shape. Unprotected siblings should keep passing through normally.
- `policy.yml` is the durable source of truth for enrollments and remembered decisions.
- The requester writes remembered decisions; the agent does not own durable policy.
- Guarded-object custody currently lives behind a store abstraction, with `pass:file-snitch/<object_id>` as the first backend.
- The agent protocol is requester/agent, local-first, and designed to be forwardable.

## Completed milestones

Earlier completed phases and the old guarded-root spike history are summarized in
[docs/research/11 - completed-milestones.md](./docs/research/11%20-%20completed-milestones.md).
