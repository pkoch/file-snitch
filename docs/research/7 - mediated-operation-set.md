# Mediated Operation Set Recommendation

## Question

Which filesystem operations does v1 actually need to mediate, given the
observed application behavior so far?

This note is about the product-facing mediation surface, not just the raw
FUSE callback list.

The important split is:
- decision points that should drive policy and prompting
- compatibility callbacks that the filesystem still needs to implement
- operations that should stay out of v1 policy entirely

## Current evidence base

The recommendation here is based on:
- `goose run -t - <<<"hi"` on Linux
- `gh auth status --json hosts` on Linux and macOS
- the Phase 1 live shell flows on Linux and macOS

That evidence is still incomplete.
It is good enough to narrow the v1 surface, but not to claim exhaustive
coverage of all target tools yet.

## Recommendation

v1 should treat these as the mediated decision surface for enrolled files:

- `open`
- `create`
- `rename` when the enrolled target is the source or destination
- `unlink` of the enrolled target

And v1 should keep the approval split at:

- `read_like`
- `write_capable`

`truncate` should remain implemented and understood as a mutation-side
callback, but it should not be a separate top-level approval class.
It should reuse the current write-capable decision model.

## Why this is the right v1 surface

### `open` and `create` are the real user-intent entry points

The current shell and CLI evidence points in the same direction:
- reads are best aligned with read-only `open`
- writes are best aligned with write-capable `open` or `create`

Prompting on later `read` and `write` callbacks was noisier and less aligned
with user intent.
Phase 1 already moved away from that, and the observed flows support that
choice.

### `rename` must stay in scope

Even though the traced `goose` and `gh` flows did not use temp-file plus
rename, real save flows still do.

More importantly, the product is moving to exact-path enrollment.
That means:
- temp files are not protected objects
- the enrolled target path is

So the decision point is not “did some scratch path get written?”
It is “is the enrolled file being replaced or moved?”

That keeps rename-over-target in the v1 mediated set.

### `unlink` must stay in scope

Deleting an enrolled file is a direct mutation of the protected object.
That needs to stay inside the mediated surface even if the traced target tools
so far have not emphasized it.

### `truncate` matters, but not as a separate approval concept

The current evidence already showed why `truncate` cannot be ignored:
- Linux shell redirection depended on `O_TRUNC` at `open`
- macOS shell flows exercised explicit `truncate`
- `goose` rewrote files in place with `O_WRONLY|O_CREAT|O_TRUNC`

So truncation is part of v1 mutation correctness.
But it still belongs under the same `write_capable` decision umbrella rather
than as a third approval class.

## Operations that must be implemented but should not be separate policy decisions

These operations still matter for correctness, compatibility, audit, or both:

- `getattr`
- `readdir`
- `read`
- `write`
- `truncate`
- `flush`
- `fsync`
- `release`
- `lock`
- `flock`

Why:
- `read` and `write` still carry the actual data path even if prompting is
  centered on `open` and `create`
- `flush`, `fsync`, `release`, `lock`, and `flock` are part of normal tool
  behavior and should remain visible to audit/debug paths
- `getattr` and `readdir` are required to make mounted parents behave like
  normal directories under the file-enrollment direction

These should be supported faithfully, but they should not expand the v1 prompt
surface by default.

## Operations that should stay out of v1 policy

### Xattrs

Keep xattrs out of the v1 decision surface.

Reason:
- macOS probes are too noisy
- current product direction is file-content protection, not metadata-stream
  mediation
- the shim and audit path can still preserve the detail for later work

### `chmod` and `chown`

Do not treat these as part of the minimal v1 mediated set.

Reason:
- the current target-tool evidence does not require them
- they are important compatibility callbacks, but not yet justified as first
  policy decisions for exact-path secret files

If later traces show real secret-bearing tools depending on metadata mutation,
they can be promoted back into scope explicitly.

### Directory mutation

Do not include:
- `mkdir`
- `rmdir`

Reason:
- the product direction is file enrollment, not directory protection
- mounted parent directories exist to present enrolled files, not to create a
  new directory-security model

### Temp-file names as protected objects

Do not treat editor or helper scratch paths as independently protected:
- `4913`
- `.swp`
- `.tmp`
- backup names

Reason:
- temp files are compatibility traffic
- the enrolled target path remains the protected object

## Practical v1 callback mapping

### Read-like decision points

- read-only `open` of an enrolled file

### Write-capable decision points

- write-capable `open` of an enrolled file
- `create` of an enrolled file
- `truncate` of an enrolled file when no already-approved write-capable handle
  covers it
- `rename` when it replaces, moves, or otherwise mutates an enrolled target
- `unlink` of an enrolled target

### Non-decision callbacks

- `read`
- `write`
- `flush`
- `fsync`
- `release`
- `lock`
- `flock`
- `getattr`
- `readdir`

These still need correct implementation and useful audit output.
They just should not each become their own user-facing approval concept.

## What this means for the file-enrollment direction

The move to sparse parent-directory virtualization does not widen the policy
surface.
It narrows the protected object model:

- directories are presentation and passthrough containers
- exact enrolled files are the protected objects
- policy decisions attach to those exact files

That keeps the mediated set small enough to reason about:
- entry by `open` or `create`
- destructive mutation by `rename`, `truncate`, or `unlink`

## Current v1 floor

If the project needs a concise recommendation now, it is:

1. Prompt and policy should center on `open` and `create`.
2. Keep `rename` and `unlink` as mutation-side decision points for enrolled
   targets.
3. Keep `truncate` in scope for correctness, but do not make it its own
   approval class.
4. Keep xattrs, temp-file names, and directory mutation out of v1 policy.
5. Keep lock, flush, sync, and teardown callbacks faithful for audit and
   compatibility, not for prompting.

## Remaining uncertainty

This recommendation should still be revisited if later traces show that one of
the remaining target tools depends heavily on:
- metadata mutation (`chmod` or `chown`)
- rename-heavy save flows against enrolled files
- locking patterns that need their own policy treatment

For now, the evidence argues for a smaller mediated surface, not a broader one.
