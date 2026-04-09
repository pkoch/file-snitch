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

Or regenerate the checked-in README assets directly:

```bash
./scripts/regenerate-demo-artifacts.sh
```

That regeneration path expects:
- `zig`
- `asciinema`
- `agg`
- `tmux`

What the script demonstrates:
- a three-pane tmux session with:
  - the agent
  - the daemon
  - a user shell
- `enroll` evacuates plaintext from its original path
- the guarded object lands in the configured store backend
- `doctor --export-debug-dossier` writes a shareable report without secret file contents
- `run prompt --foreground` projects the guarded file back into place through a visible agent prompt
- unguarded siblings under the same parent directory still passthrough normally
- stopping `run` hides the guarded path again
- `unenroll` restores the guarded file

The demo uses:
- a disposable temporary home directory
- a fake `pass` binary
- `tmux`
- the built `zig-out/bin/file-snitch`

So it is safe to record and share. It does not touch your real `pass` store or
your real home-directory secrets.

The script leaves its temporary home directory in place and prints the dossier
and log paths at the end so you can inspect or reuse the artifacts after the
recording.

The generated artifacts live at:
- `docs/assets/demo.cast`
- `docs/assets/demo.gif`
