# Phase 1 Lessons Learned

Phase 1 closed with a live guarded-root verification on both macOS and Linux.

## What held up

- A Zig-owned filesystem model with a thin C `libfuse` shim was the right split. The shim can stay focused on FUSE ABI translation, mount-loop plumbing, and syscall bridging while Zig owns policy, model state, prompting, and audit output.
- A file-only guarded root was the right spike scope. Explicitly rejecting `mkdir` and `rmdir` kept the interface honest and removed a large source of accidental complexity.
- Smoke tests were enough to make the spike reproducible. The maintained scripts ended up being a better workflow artifact than a separate manual demo runner.

## What changed the design

- The shim had to become more faithful than the first draft. Conflating `flush` with `fsync`, stringifying lock detail, or fabricating metadata in C made the boundary harder to reason about and hid real platform differences.
- Prompting on `read` and `write` callbacks was the wrong level. Prompting moved to `open` and `create`, with open-mode information shown directly to the user.
- Xattr mediation was too noisy for Phase 1, especially on macOS. Passing xattrs through and keeping them out of the prompt path produced a saner v1 while preserving the callback machinery for later work.

## Cross-platform findings

- macOS and Linux diverge enough that they must both be exercised for real, not inferred from one another.
- Linux `libfuse3` required callback-signature changes relative to the macOS path, especially around `init`, `getattr`, `readdir`, `truncate`, `chmod`, `chown`, and `rename`.
- The Linux live verification caught a real semantic bug: shell redirection depended on `O_TRUNC` during `open`, and the in-memory model initially ignored that. The fix belonged in the Zig filesystem layer, not in C.
- Caller attribution quality is still not fully settled, especially on macOS. Actor path capture is useful, but attribution assumptions still need explicit validation in Phase 0.

## Product lessons

- Audit output should preserve detailed callback information, but prompting should align with user intent rather than every low-level callback.
- Editor behavior is a separate problem from shell behavior. Bash-style read/write flows are in good shape; editor probe and save flows still need dedicated treatment.
- Control channels do not belong inside the mounted directory. Moving status and audit out of the mount root made the guarded directory model cleaner.

## What remains outside Phase 1

- Finish the remaining Phase 0 research so the v1 mediated operation set is driven by observed application behavior rather than by convenience.
- Revisit editor probe/save alignment.
- Revisit richer xattr policy, directory support, and broader prompt decisions only after the research closes.
