# Contributing

## Before You Change Code

- read [README.md](./README.md)
- read [docs/threat-model.md](./docs/threat-model.md)
- read [docs/operations.md](./docs/operations.md)
- read [docs/error-handling.md](./docs/error-handling.md)

This project is intentionally:
- single-user
- user-space
- exact-file oriented
- not a system security framework

Changes that pull it toward system-wide policy or multi-user arbitration should
be treated skeptically.

## Development Loop

Install Anyzig so the `zig` command follows this repo's `build.zig.zon`
`minimum_zig_version` pin.

The full local workflow lives in [docs/development.md](./docs/development.md).

Build:

```bash
zig build
```

Run the Zig test roots:

```bash
zig build test
```

CI also enforces a small hygiene layer:

```bash
bash -n $(find scripts tests -type f -name '*.sh' | sort)
./scripts/docs/check-docs.sh
./scripts/demo/check-demo-artifacts.sh
```

Run the smoke suite:

```bash
./tests/smoke/run-empty-policy.sh
./tests/smoke/policy-lifecycle.sh
./tests/smoke/doctor-debug-dossier.sh
./tests/smoke/run-policy-reload.sh
./tests/smoke/run-expired-decision-cleanup.sh
./tests/smoke/run-single-enrollment.sh
./tests/smoke/run-multi-mount.sh
./tests/smoke/run-prompt-linux-ui.sh
./tests/smoke/run-prompt-single.sh
./tests/smoke/run-prompt-remembered-decision.sh
./tests/smoke/user-service-rendering.sh

# macOS only:
./tests/smoke/run-prompt-macos-ui.sh
./tests/smoke/run-prompt-macos-ui-agent.sh
```

Refresh `compile_commands.json` when needed:

```bash
zig build compile-commands
```

## Demo Artifacts

The README embed is not hand-made. Regenerate it with:

```bash
./scripts/demo/regenerate-demo-artifacts.sh
```

And then sanity-check it for obvious leakage:

```bash
./scripts/demo/check-demo-artifacts.sh
```

That expects:
- `zig`
- `asciinema`
- `agg`
- `tmux`

## Reporting And Reproducing Problems

Before filing a bug, prefer exporting a dossier:

```bash
file-snitch doctor --export-debug-dossier ./file-snitch-debug-dossier.md
```

Use the templates in `.github/ISSUE_TEMPLATE/`.

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

## Packaging Reality

The current packaging story is:
- tagged release artifacts from this repo
- Homebrew/Linuxbrew formula in `pkoch/homebrew-tap`
- per-user service management embedded in the `file-snitch` binary
- FUSE remains an external system prerequisite
- `pass` is the only guarded-object backend today

Do not document or imply bottles or package-manager integrations that do not
exist yet.
