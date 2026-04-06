# Durable Decision Key Recommendation

## Question

What should the v1 decision key on?

This is about the user-approved decision model, not low-level memoization.

The important distinction is:
- one-shot decisions are ephemeral runtime state
- time-bounded and persistent decisions are durable policy

So the main design question is not “what should the cache key on?”
It is:
- what identity should durable decisions attach to
- what should one-shot decisions reuse from that same model

## Recommendation

Use one shared decision key shape for both:
- durable policy entries
- one-shot runtime grants

The v1 decision key should be:

```text
(
  executable_identity,
  uid,
  enrolled_target_path,
  approval_class
)
```

Where:
- `executable_identity` is the normalized request-time executable path
- `uid` scopes the decision to the requesting user
- `enrolled_target_path` is the canonical protected file path
- `approval_class` is one of:
  - `read_like`
  - `write_capable`

## Decision model

The daemon should handle three different kinds of state:

### 1. One-shot runtime grants

Used for:
- allow once
- deny once

These are ephemeral and can die with the daemon process.

### 2. Durable decision entries

Used for:
- allow until time `T`
- deny until time `T`
- always allow
- always deny

These are durable policy entries, not a mere cache.

The daemon should watch the policy store for changes so that:
- policy edits do not require a daemon restart
- the active runtime view stays in sync with durable state

Platform note:
- Linux implementation would naturally use `inotify`
- macOS implementation would need a corresponding native watcher

So this should be described architecturally as a **watched policy store**, not as a Linux-specific `inotify` design.

### 3. In-flight handle grants

Used to avoid re-prompting the same approved handle for every later `read` or `write`.

This is separate from durable policy.

It is local runtime state tied to the opened handle, not a user-facing decision record.

## Why this is the right v1 floor

This matches the current evidence and guardrails:

- request-time attribution is good enough on both Linux and macOS for:
  - `open`
  - `create`
  - `read`
  - `write`
  - `rename`
- Linux teardown callbacks such as `release` are not actor-bearing, so they cannot safely participate in the decision key
- the project already decided that read approval must not silently authorize later write behavior
- the product is moving to exact-path file enrollment rather than directory protection
- temp files are explicitly being treated as compatibility traffic, not protected objects

So a v1 decision model keyed on anything broader than:
- actor
- user
- exact file
- approval class

would be too coarse.

## Actor identity

For v1, `executable_identity` should be:

- normalized executable path

Later additions may strengthen this with:
- signer identity on macOS
- executable hash

But those should not be required for the first durable decision design.

Reason:
- executable path is already available in the current audit and prompt pipeline
- it is the strongest actor signal validated across both platforms so far
- waiting for stronger attribution would block a practical v1 model unnecessarily

## User identity

The key should include:

- `uid`

Reason:
- the same executable path can run under different user identities
- approvals should not silently cross user boundaries
- `uid` is stable and already available in the current attribution path

Do not include `gid` in the v1 decision key.

Reason:
- primary user identity is the meaningful boundary for the prompt decision
- group membership is noisier and less directly tied to user approval intent
- adding `gid` now complicates the model without clear evidence that it improves safety

## Target identity

The target part of the key should be:

- the canonical enrolled file path

Not:
- the mounted parent directory
- the temp file path used during an editor save
- a path prefix

Reason:
- the product model is file-centric
- policy, prompting, and audit should stay attached to the protected file the user enrolled
- temp files are compatibility artifacts, not first-class protected objects

## Approval classes

The v1 split should be:

- `read_like`
- `write_capable`

`read_like` includes:
- `open` for read-only access
- direct reads of an enrolled target

`write_capable` includes:
- `open` with write capability
- `create`
- `truncate`
- `rename` that replaces or mutates an enrolled target
- direct writes or other mutation-side flows

The exact callback mapping can evolve, but the class split should stay two-tier in v1.

Reason:
- this is the smallest split that preserves the guardrail that read approval must not silently authorize later mutation
- going finer than that in v1 adds complexity before we have evidence that it materially improves UX or safety

## What the decision key should not use

### PID

Do not key on raw `pid`.

Reason:
- the same executable may legitimately perform repeated accesses through different short-lived processes
- `pid` churn would destroy reuse of the same user decision
- the product should care about the requesting program identity, not one OS process instance

### UID/GID alone

Do not key only on `uid` or `gid`.

Reason:
- too coarse
- many unrelated tools run as the same user

### Teardown callbacks

Do not derive or refresh durable decisions from:
- `release`
- other teardown-only callbacks

Reason:
- Linux `release` is not actor-bearing in the current evidence

### Temp-file paths

Do not attach durable decisions to temp-file names such as:
- `.swp`
- `4913`
- `.tmp`
- backup files

Reason:
- these are compatibility artifacts
- the user intent attaches to the enrolled target, not the editor’s scratch path

## Example behavior

### Repeated reads by the same tool

If `/usr/bin/gh` reads:
- `~/.config/gh/hosts.yml`

and the user grants a time-bounded allow, repeated read-like accesses by `/usr/bin/gh` to that exact enrolled file should match the same durable decision entry.

### Read then write by the same tool

If `/usr/bin/gh` has a `read_like` allow decision for:
- `~/.config/gh/hosts.yml`

and later attempts a write-capable open or mutation flow on that same file, it must prompt again unless there is a separate `write_capable` decision.

### Editor temp-save flow

If an editor writes:
- `target.txt.tmp`
- then renames it over enrolled `target.txt`

the temp-file path should not get its own durable decision entry.

The relevant lookup should happen when the enrolled target is actually affected:
- write-capable open of the enrolled file
- or rename-over-enrolled-target

### One-shot allow

If the user chooses allow once for:
- `/usr/bin/gh`
- `uid 501`
- `~/.config/gh/hosts.yml`
- `read_like`

the daemon can represent that with the same key shape, but keep it only in ephemeral runtime state.

## Suggested implementation shape

Conceptually:

```text
(
  executable_path,
  uid,
  canonical_enrolled_path,
  approval_class
) -> decision + optional expiration
```

Where:
- durable entries live in a watched policy store
- one-shot entries live only in runtime memory
- in-flight handle grants remain separate from both

## Non-goals for v1

Do not add these to the decision key yet:
- signer identity
- executable hash
- parent process
- cwd
- mount path
- temp-path ancestry

Those may become useful later, but they are not justified by the current evidence.

## Recommendation summary

Use:
- request-time executable path
- request-time uid
- exact enrolled target path
- read-like vs write-capable class

Represent decisions as:
- ephemeral one-shot runtime grants
- durable watched policy entries

Do not use:
- pid
- gid
- teardown callbacks
- temp-file paths
- directory prefixes as the primary target identity
