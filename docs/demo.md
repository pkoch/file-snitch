# Demo

The demo driver runs an agent, a daemon, and a user shell in three tmux panes.
It creates a disposable home and fake `pass` store, then demonstrates enrollment,
prompted reads, a denied write, dossier export, and restoration with `unenroll`.
Sibling files stay on the host filesystem throughout.

## Run the walkthrough

Set up the [build dependencies](./development.md#native-setup), including a
working FUSE runtime. The demo also needs `tmux` and Python 3.

```bash
zig build
./scripts/demo/demo-session.sh
```

The script uses `zig-out/bin/file-snitch`; set `FILE_SNITCH_BIN` to try another
build. It uses sample contents and a fake store rather than your real secrets.
It leaves its temporary home in place and prints dossier/log locations at the
end for inspection.

## Record or regenerate assets

To record a session, install `asciinema` and run:

```bash
asciinema rec --command ./scripts/demo/demo-session.sh
```

To regenerate the README recording and GIF, install `asciinema` and `agg` in
addition to the walkthrough prerequisites:

```bash
./scripts/demo/regenerate-demo-artifacts.sh
./scripts/demo/check-demo-artifacts.sh
```

The outputs are [demo.cast](./assets/demo.cast) and [demo.gif](./assets/demo.gif).
Review the recording before sharing it; the automated check only catches known
leakage markers. See [redaction review](./redaction-review.md).
