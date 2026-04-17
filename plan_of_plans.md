# Patch-level improvements — plan of plans

Four self-contained patches, each focused on correctness, code hygiene, or
reducing duplication. None touch product behaviour; each warrants its own
patch release commit.

---

## Patch A — Dead code removal

Two functions exist but are never called.

- `build/fuse_support.zig` lines 85–90: `hasPkgConfig` is defined and its
  body is correct, but every call-site already uses `findPkgConfig` +
  `pkgConfigPackageExistsWithBinary` directly. → delete it.
- `src/agent.zig` lines 696–698: `buildMacosDialogPromptAlloc` is a one-liner
  that does nothing but forward to `buildDialogPromptAlloc`. The single
  call-site can call `buildDialogPromptAlloc` directly. → delete the wrapper
  and inline the call.

---

## Patch B — Defensive error handling

Two silent failure modes that surface as confusing panics or generic errors.

- **`responseFromFrame` index-out-of-bounds** (`src/agent.zig` line 789):
  `parsed.value.outcome[0]` panics on an empty `outcome` string (valid JSON,
  invalid protocol). Add a length guard and fall through to `.unavailable`.

- **Invalid `FILE_SNITCH_PROMPT_TIMEOUT_MS`** (`src/cli.zig` line 712):
  `std.fmt.parseInt` errors bubble up to `main`'s `else => return err` branch,
  printing nothing useful. Map those errors to a friendly message +
  `error.InvalidUsage`.

---

## Patch C — CLI `--policy` flag deduplication

The `--policy <path>` option-parsing block is copy-pasted verbatim across four
functions in `src/cli.zig`:

- `parseRunCommand`
- `parsePolicyCommand`
- `parseDoctorCommand`
- `parsePathCommand`

Extract a `parsePolicyFlag` helper that each call-site delegates to.

---

## Patch D — Minor Zig idiom cleanups

Small readability nits:

- **Redundant `tty_path` binding** (`src/cli.zig` line 437):
  `const tty_path = if (command.tty_path) |path| path else null;` is
  identical to `command.tty_path`. Remove the indirection.

- **Bare `else => return err`** (`src/cli.zig` line 648–650):
  A `switch` with only `else => return err` is equivalent to `try`. Replace it.

- **Duplicated `readFrame` length-parsing logic** (`src/agent.zig`):
  `readFrameAlloc` and the test-only `readFrameFromReaderAlloc` share the
  same length-prefix parsing. Confirm `readFrameFromReaderAlloc` is not
  exported (`pub`) and note the duplication for a future cleanup.
