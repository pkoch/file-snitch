# Backlog

Forward-looking task tracking for File Snitch. This is not a full issue
tracker; it records durable product and engineering themes that should survive
day-to-day task churn.

Status:

- `[ ]` not started
- `[~]` in progress
- `[x]` done
- `blocked` waiting on research or a product decision

## Near-Term Engineering

- `[ ]` Wire docs checks into CI
  - run `./scripts/docs/check-docs.sh` in `.github/workflows/ci.yml`
  - keep shell syntax and demo-artifact checks beside it
- `[ ]` Add policy examples that are validated by automation
  - examples: empty policy, one enrollment, temporary allow, durable deny
  - validate examples with the real parser rather than only Markdown review
- `[ ]` Make `doctor` hints point at stable docs sections
  - operations symptoms should map to concrete recovery docs
  - policy-shape failures should map to [docs/policy.md](./docs/policy.md)
- `[ ]` Improve daily-driver frontend UX
  - keep `terminal-pinentry` as the bootstrap/debug fallback
  - harden `macos-ui` and `linux-ui` behavior around helper failures and
    restarts
  - make remembered decisions predictable and visible without adding a second
    policy surface

## Product Capabilities

- `[ ]` Support forwarding decision requests from remote hosts back to the
  active user workstation
  - protocol note:
    [docs/research/12 - agent-broker-protocol.md](./docs/research/12%20-%20agent-broker-protocol.md)
  - keep the transport stream-friendly and user-to-user
  - keep requester-side policy ownership: forwarded decisions should still land
    in the requester's `policy.yml`
- `[ ]` Add a specific warning for [GTFOBins](https://gtfobins.org)
  - Keep a trimmed down version of <https://gtfobins.org/api.json>.
  - Decide which functions are problematic regarding file access.
- `[ ]` Support mount persistence across restarts

## Platform And Packaging

- `[ ]` Broaden packaging beyond Homebrew/Linuxbrew
  - add a native `.deb` package
  - keep Linux honest about distro FUSE prerequisites even when Homebrew is used
- `[ ]` Harden macOS-specific attribution and install behavior
  - add signer lookup for caller attribution
  - validate TCC and Full Disk Access friction explicitly
  - test more real macOS target apps against the current product path

## Filesystem And Policy Research

- `[ ]` Revisit xattr mediation beyond the current passthrough-only prompt path

## Future Backend Work

- `[ ]` Add more guarded-object backends beyond `pass`
  - likely first candidates: `1password`, `bitwarden`
  - local storage candidates: `secret-tool` for linux, `security` for macOS

## Product Constraints

Do not duplicate architectural decisions here. Backlog items should stay
consistent with the canonical docs:

- product stance and non-goals: [docs/threat-model.md](./docs/threat-model.md)
- repo-level guardrails: [README.md](./README.md)
- policy ownership and format: [docs/policy.md](./docs/policy.md)
- protocol direction:
  [docs/research/12 - agent-broker-protocol.md](./docs/research/12%20-%20agent-broker-protocol.md)
- completed architecture milestones:
  [docs/research/11 - completed-milestones.md](./docs/research/11%20-%20completed-milestones.md)

Earlier completed phases and the old guarded-root spike history are summarized
in
[docs/research/11 - completed-milestones.md](./docs/research/11%20-%20completed-milestones.md).
