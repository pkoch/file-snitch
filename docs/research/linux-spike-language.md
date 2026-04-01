# Linux Spike Language Recommendation

## Question

What should phase 1 use for the first Linux spike: Rust, Zig, or C?

## Recommendation

If the only goal is minimizing spike risk, use **C with libfuse**.

Reason:
- the brief requires a guarded FUSE mount first, not a long-term language bet
- libfuse is the reference Linux implementation and exposes the exact operations and caller context the spike needs
- macFUSE provides `libfuse.dylib` as a superset of the standard Unix FUSE API, so the C path keeps the clearest cross-platform story
- the most visible Rust option looks viable for Linux, but its own README still describes macOS support as untested
- the Zig options currently look too immature for a cross-platform product spike

If the goal is to build the product in **Zig** without turning the spike into a bindings project, use:

- **Zig for core product logic**
- **a thin C shim for `libfuse` interop**

Do **not** start with a direct, pure-Zig wrapper over the full `libfuse` high-level API.

## Evidence

### C / libfuse

- `libfuse` describes itself as the reference implementation of the Linux FUSE interface.
- `struct fuse_context` includes `uid`, `gid`, and `pid`, which are core inputs for policy decisions.
- `fuse_operations` exposes the file and directory operations the brief calls out, including `rename`, `unlink`, `mkdir`, `rmdir`, `truncate`, `open`, `read`, and `write`.

Implication:
- the C path directly matches the Linux spike requirements with the least adapter risk

### macOS / macFUSE

- macFUSE states that `libfuse.dylib` provides a superset of the standard Unix FUSE API.
- macFUSE is explicitly positioned for app-specific virtual volumes and transparent encryption/decryption use cases.

Implication:
- a libfuse-first spike is the cleanest base if the product still intends to share the core daemon model across Linux and macOS

### Rust / fuser

- `cberner/fuser` is active and widely used enough to be credible for Linux work.
- its README says the crate is developed and tested on Linux and FreeBSD.
- the same README labels macOS as `untested`.

Implication:
- Rust is a reasonable candidate for a Linux-only experiment
- it is not the safest choice if the spike is meant to de-risk the eventual cross-platform architecture

### Zig

- the visible Zig options found so far are a WIP raw `/dev/fuse` implementation and a small `libfuse` bindings repo.
- Zig's own documentation supports C translation and recommends `translate-c` when you need to pass C flags or edit translated bindings.
- Zig is therefore strong on the build and mixed-language integration side.

Inference from sources:
- Zig is not the problem
- the `libfuse` API shape is the problem
- the highest-friction pieces are ABI-sensitive structs and C bitfields such as `struct fuse_file_info`

This is consistent with the visible Zig FUSE project that explicitly avoids `libfuse` and says `libfuse`'s bitfield-heavy API is a poor fit for a direct Zig wrapper.

## Zig plus C shim shape

This is the sane boundary if Zig is the intended implementation language.

Keep these pieces in C:
- `#define FUSE_USE_VERSION`
- inclusion of `fuse.h`
- `struct fuse_operations` setup
- callback entrypoints expected by `libfuse`
- direct access to bitfield-heavy or ABI-sensitive `libfuse` structs
- mount, loop, and teardown glue

Keep these pieces in Zig:
- policy engine
- path normalization
- file and metadata mapping
- encryption design and implementation
- audit logging
- rule persistence
- prompt-broker protocol

Implication:
- this keeps the C surface narrow
- it lets Zig own the product logic
- it avoids spending the spike on binding cleanup

## Practical call

If the goal is to de-risk the product thesis as quickly as possible, use C for phase 1.

If the goal is to build in Zig and accept a modest interop layer, Zig plus a thin C `libfuse` shim is a reasonable path.

If the goal changes to a Linux-only prototype with a willingness to accept later porting risk and without a C shim, Rust is the best alternative worth reconsidering.

## Sources

- `libfuse` reference implementation overview: https://github.com/libfuse/libfuse
- `libfuse` headers with ABI-sensitive structs: https://github.com/libfuse/libfuse/blob/master/include/fuse_common.h
- `libfuse` main API surface: https://github.com/libfuse/libfuse/blob/master/include/fuse.h
- `fuse_context` fields: https://libfuse.github.io/doxygen/structfuse__context.html
- `fuse_operations` surface: https://libfuse.github.io/doxygen/structfuse__operations.html
- macFUSE overview and API notes: https://github.com/macfuse/macfuse
- macFUSE wiki overview: https://github.com/macfuse/macfuse/wiki
- `fuser` repository metadata: https://github.com/cberner/fuser
- `fuser` README: https://github.com/cberner/fuser/blob/master/README.md
- Zig raw FUSE library: https://github.com/shanoaice/zig-fuse
- Zig `libfuse` bindings repo: https://github.com/mgord9518/libfuse-zig
- Zig C translation docs: https://ziglang.org/documentation/master/#C-Translation-CLI
