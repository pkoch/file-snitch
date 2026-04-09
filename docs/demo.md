# Demo

The fastest way to show File Snitch to someone who has not installed it is to
record the built-in demo driver.

Prerequisite:

```bash
zig build
```

Then record the session:

```bash
asciinema rec --command ./scripts/demo-session.sh
```

What the script demonstrates:
- `enroll` evacuates plaintext from its original path
- the guarded object lands in the configured store backend
- `doctor --export-debug-dossier` writes a shareable report without secret file contents
- `run allow --foreground` projects the guarded file back into place
- unguarded siblings under the same parent directory still passthrough normally
- stopping `run` hides the guarded path again
- `unenroll` restores the guarded file

The demo uses:
- a disposable temporary home directory
- a fake `pass` binary
- the built `zig-out/bin/file-snitch`

So it is safe to record and share. It does not touch your real `pass` store or
your real home-directory secrets.

The script leaves its temporary home directory in place and prints the dossier
and log paths at the end so you can inspect or reuse the artifacts after the
recording.
