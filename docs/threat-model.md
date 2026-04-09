# Threat Model

File Snitch is a single-user, user-space mediation tool.

Its job is narrow:
- keep selected secret-bearing files out of their normal host paths
- project them back only while the user-owned daemon is active
- require an explicit local decision before guarded access

It is not a general system security framework.

## What It Protects Against

File Snitch is meant to protect one user's own secret files from that same
user's software.

Examples:
- a CLI that reads `~/.kube/config` without the user realizing it
- a shell pipeline that would otherwise open `~/.ssh/id_ed25519`
- a misbehaving local tool that should not silently mutate a guarded file

The intended boundary is:
- one local user
- one local policy file
- one local agent
- one local daemon

## What It Does Not Protect Against

File Snitch does not try to protect against:
- root
- other local users with stronger system privileges
- kernel compromise
- malicious software that already controls the user account end to end
- exfiltration after the user explicitly approves access

It is also not trying to be:
- system-wide mandatory access control
- a sandbox
- a shared multi-user policy authority
- a replacement for encrypted-at-rest secret storage

## Trusted Components

Today, the practical trust base includes:
- the local operating system and kernel
- FUSE or macFUSE
- the File Snitch daemon
- the local File Snitch agent
- the `pass` and GPG setup backing guarded objects

If any of those are compromised, File Snitch cannot meaningfully defend the
user's secrets.

## Security Properties File Snitch Tries To Preserve

- Enrolled plaintext should not sit at the original host path while the file is
  merely "guarded by convention".
- Prompting should happen before the guarded operation takes effect.
- Policy should stay user-owned and local.
- Sibling files under a mounted parent should not be broken just because one
  file is guarded.
- Expired durable decisions should stop applying and be cleaned out of policy.

## Operational Consequences

- If the daemon is down, enrolled files should be absent or inert, not silently
  re-exposed from the original host path.
- If the agent is unavailable, guarded requests should fail closed.
- If `pass` or GPG is unusable, guarded objects are unavailable too.

## Design Rule

When deciding whether a new feature fits, ask:

> Does this help one user control one user's own secret-bearing files from one
> user's own software?

If the answer is "not really", it probably does not belong in File Snitch's
core.
