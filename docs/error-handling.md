# Error Handling

This project treats errors as part of the API contract. Code should preserve
the original failure until it reaches a boundary that is responsible for
deciding what to do with it.

## Default Rule

Propagate errors from helpers and model code. A helper that cannot complete its
job should return an error, not guess whether the caller can tolerate a partial
answer.

Avoid empty `catch {}` blocks. Swallowing an error is a strong claim that the
error cannot matter. If that is true, keep the swallowing local to a deliberately
best-effort helper whose name and comments make that contract obvious.

## FUSE Boundaries

Public operations that implement FUSE callbacks generally return `i32` errno
values instead of Zig errors. These functions are the boundary where Zig errors
are converted with `mapFsError` or a more specific errno mapper.

Internal helpers below that boundary should usually stay as `!T` so callers can
choose the right errno, retry behavior, or fallback.

## Lookups

Lookup helpers must preserve full error semantics.

`missingLookup()` means the path is definitively absent. It must not stand for
permission errors, I/O errors, allocation failures, interrupted syscalls, or
other transient failures. Those errors should propagate to the caller.

Callers that need old-style fallback behavior may wrap lookup helpers and make
that conversion explicitly at the call site.

## Audit Events

Audit recording is useful but not the core availability mechanism of the
filesystem. Audit failures should not make the original filesystem operation
fail after the fact, but they also must not disappear silently.

Use `recordAuditOrFallback` for fire-and-forget audit records:

1. Try to append the in-memory audit event.
2. If that fails, try to emit the JSON audit line directly.
3. If that also fails, log an error.

Do not call `recordAudit(...) catch {}` directly.

## Mutations And Rollback

Stateful mutations should be all-or-nothing at the model boundary. Use
`errdefer` or explicit rollback when an operation can partially mutate state and
then fail.

If rollback itself can fail, do not continue in an inconsistent state. Panic or
otherwise abort loudly. Corrupt model state is more dangerous than an unavailable
operation.

## Allocation Failures

Allocation failures should propagate unless the function is already at an errno
boundary, in which case return `ENOMEM`. Do not silently substitute an empty or
missing result for `OutOfMemory`.

## Logging

Mechanistic code should not use logging as a substitute for propagation. Logging
belongs at the boundary that decides to absorb, retry, downgrade, or report an
error.

The audit fallback path is the narrow exception because the original operation
has already produced its user-visible result and the audit pipeline is
best-effort.
