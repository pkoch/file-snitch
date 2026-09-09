# Contributing

Start with the [development guide](./docs/development.md) for setup and checks.
Before changing behavior, read the [threat model](./docs/threat-model.md) and
[error-handling conventions](./docs/error-handling.md).

File Snitch mediates individual files for one user. Policy, state, sockets,
locks, and services stay per-user. Keep product policy in Zig; the C shim owns
the FUSE boundary and syscall bridging. Authorize operations before they take
effect, and keep read-only grants from authorizing later writes.

## Commit Discipline

- keep commits small and isolated
- do not mix feature work with broad cleanup
- update docs when the user-facing behavior changes
- do not leave old compatibility shims behind unless they are explicitly needed

## Ownership Conventions

This codebase uses Zig slices heavily, so ownership must be obvious from API
shape rather than inferred from types alone.

- Functions ending in `Alloc` must return owned memory that the caller frees.
- Unit tests should default to `std.testing.allocator` unless a different
  allocator is required to exercise a specific behavior.
- Deterministic allocator-heavy helpers should use
  `std.testing.checkAllAllocationFailures` to verify cleanup on every induced
  allocation failure.
- Functions and methods named like snapshots or loaders must return fully owned
  data, including nested strings and slices.
- Borrowed results should be named as borrowed views:
  use `View` in the type or function name when returned data aliases another
  object's storage.
- Do not return outer owned containers with borrowed inner slices.
  If a returned value can outlive its source, it must own all nested memory.
- Owned aggregate types should prefer a `deinit()` method over ad hoc free
  helpers when practical.
- If an API returns borrowed data, document what owns it and how long it stays
  valid in the declaration site.

Practical examples:

- `fooAlloc()` returns owned memory.
- `fooView()` returns data tied to another object's lifetime.
- `FooSnapshot.deinit()` makes ownership explicit for aggregate results.
- `std.testing.checkAllAllocationFailures()` belongs on deterministic
  constructors, parsers, and copy helpers.

When reviewing code, be suspicious of:

- slices returned from parser output after `parsed.deinit()`
- slices returned from arena-backed data after arena teardown
- slices into stack buffers
- containers that allocate their outer slice but borrow nested fields

## Documentation

Give instructions one home and link to them from other pages. The README
introduces the project, the install guide owns the first-run walkthrough, the
CLI and policy pages describe behavior, and the development guide owns checks.
Update those guides when behavior changes. Keep experiments and superseded
proposals in [research](./docs/research/README.md), labeled as history.

For diagnostics or demo changes, follow the
[redaction review](./docs/redaction-review.md). Packaging changes belong with
the [release workflow](./docs/releasing.md).
