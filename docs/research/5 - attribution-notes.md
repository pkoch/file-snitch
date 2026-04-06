# Attribution Notes

## Question

How trustworthy are `pid`, `uid`, `gid`, and `executable_path` for policy decisions and audit output?

The current implementation gets:
- `pid`, `uid`, `gid`, and `umask` from `fuse_get_context()` in the C shim
- `executable_path` by resolving the `pid` in Zig
  - macOS: `proc_pidpath()`
  - Linux: `/proc/<pid>/exe`

So the real question is not whether actor data can be surfaced at all.
It is whether the `pid` from `fuse_get_context()` is a trustworthy identity for the operation that users actually care about.

## What was tested

Simple live mount runs on both platforms using the current mutable path:

1. read a seeded file with `cat`
2. write a new file with shell redirection
3. create a temp file and rename it over an existing target with `mv`

These are intentionally small tests.
They are enough to validate the common shell path before moving on to helper-heavy tools or editors.

## Current findings

### macOS

Observed on the VFS-backed macFUSE path:

- `cat mounted/seed.txt`
  - `open`, `read`, `flush`, `lock`, and `release` all carried:
    - the `cat` pid
    - the expected `uid` and `gid`
    - `executable_path` of `/bin/cat`

- `printf ... > mounted/new.txt`
  - `create`, `open`, `truncate`, `write`, `flush`, `lock`, and `release` carried:
    - the shell pid
    - the expected `uid` and `gid`
    - the Homebrew bash executable path

- temp file plus rename
  - temp-file create/write flow carried the shell identity
  - `rename` carried `/bin/mv`

Implication:
- for straightforward shell and CLI flows, macOS attribution looks good enough for policy on:
  - `open`
  - `create`
  - `read`
  - `write`
  - `rename`

### Linux

Observed on the `libfuse3` path in the Lima Ubuntu guest:

- `cat mounted/seed.txt`
  - `open`, `read`, `flush`, and `lock` carried:
    - the `cat` pid
    - the expected `uid` and `gid`
    - the resolved executable path for `cat`

- `printf ... > mounted/new.txt`
  - `create`, `open`, `write`, `flush`, and `lock` carried:
    - the shell pid
    - the expected `uid` and `gid`
    - `/usr/bin/bash`

- temp file plus rename
  - temp-file create/write flow carried the shell identity
  - `rename` carried the `mv` executable path

Implication:
- for straightforward shell and CLI flows, Linux attribution also looks good enough for policy on:
  - `open`
  - `create`
  - `read`
  - `write`
  - `rename`

## Important discrepancy

### Linux `release` is not actor-bearing

In the Linux runs, `release` arrived with:
- `pid = 0`
- `uid = 0`
- `gid = 0`
- `executable_path = null`

In the analogous macOS runs, `release` still carried the initiating process identity.

Implication:
- actor attribution is not reliable for every callback on Linux
- teardown callbacks should not be used as the source of truth for policy decisions
- the approval cache key should be based on request-time operations, not release-time cleanup

## Backend caveat on macOS

macFUSE documents that `fuse_context_t` is unavailable when using the FSKit backend, and that files are always opened read-write there.

Implication:
- the current attribution model is only plausibly valid on the VFS backend
- Phase 0 should treat “macOS attribution works” as a VFS-backed observation, not a universal macFUSE claim

## Current recommendation

Treat attribution as trustworthy enough for policy only on request-time operations:
- `open`
- `create`
- `read`
- `write`
- `rename`

Do **not** treat these as actor-bearing for policy:
- `release`
- possibly other teardown or cleanup callbacks until explicitly validated

The current floor shape for a future approval cache key is therefore:
- caller identity
- exact enrolled path
- approval class

Where “caller identity” should be based on request-time attribution only.

## What still needs validation

- helper-heavy and metadata-heavy flows on Linux
- helper-heavy and metadata-heavy flows on macOS
- whether any other callbacks besides `release` lose actor identity on Linux
- how much macOS attribution changes under FSKit-backed setups, if that backend becomes relevant

## Sources

- libfuse `fuse_context`: https://libfuse.github.io/doxygen/structfuse__context.html
- macFUSE backend differences and FSKit notes: https://github.com/macfuse/macfuse/wiki/FUSE-Backends
