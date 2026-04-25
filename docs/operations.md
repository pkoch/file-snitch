# Operations And Troubleshooting

This is the operator's view of File Snitch.

Use it when:
- a guarded file is missing
- you expected a prompt and did not get one
- `pass` or GPG is failing
- the daemon or agent died and you want to recover safely

## First Checks

Start here:

```bash
file-snitch status
file-snitch doctor
```

`doctor` is meant to be prescriptive, not just descriptive. When it reports a
missing helper, socket, service file, or unusable `pass` setup, follow the
adjacent `hint:` lines first.

If you plan to file a bug, also export a dossier:

```bash
file-snitch doctor --export-debug-dossier ./file-snitch-debug-dossier.md
```

## If A Guarded File Is Missing

That is often the expected failure mode.

Remember:
- `enroll` evacuates the file out of its original host path
- `run` projects it back into place
- if `run` is not active, the file should normally be absent

Check:

```bash
file-snitch status
```

If the file is enrolled and `run` is not active, start the daemon:

```bash
file-snitch run allow
```

or:

```bash
file-snitch run prompt
```

## If You Expected A Prompt And Did Not Get One

Check all three layers:

1. The file must actually be enrolled.

```bash
file-snitch status
```

2. The daemon must be running in `prompt` mode.

3. The agent must be reachable on its Unix socket.

4. A remembered decision may already cover the access.
   Check `file-snitch status` or inspect `policy.yml` before assuming the
   prompt path is broken.
   Remembered decisions should apply on the next guarded access; they no longer
   need a supervisor remount before prompt suppression starts.

If the current agent frontend is terminal-based, also confirm that the agent
has a usable TTY:
- `agent` uses inherited stdio
- `agent --tty <path>` targets a specific terminal

## If `pass` Or GPG Is Failing

File Snitch depends on `pass` for the current guarded-object backend.

Check:

```bash
pass ls
gpg --version
file-snitch doctor
```

If `pass` cannot decrypt its store, File Snitch cannot load guarded objects
either.

When using the per-user service, `doctor` also checks whether the run service
can find `pass` from its own service environment. On macOS this is especially
important because launchd does not inherit your interactive shell `PATH`; if
Homebrew installed `pass` under `/opt/homebrew/bin`, reinstall the services
with:

```bash
./scripts/services/install-user-services.sh \
  --bin "$(command -v file-snitch)" \
  --pass-bin "$(command -v pass)"
```

File Snitch currently captures each stored `pass:file-snitch/<object_id>` entry
as one JSON/base64 payload capped at 1 MiB. If a guarded object exceeds that
serialized payload limit, File Snitch reports the limit explicitly. The limit is
in File Snitch's in-memory store handling, not in `pass` or GPG.

`unenroll` is the recovery path for an oversized guarded object. It streams the
stored JSON/base64 payload back to the target file without applying the normal
capture limit, then removes the `pass` entry only after the restore succeeds.

Common causes:
- wrong `GNUPGHOME`
- missing secret key
- broken pinentry/GPG agent setup
- `pass` installed but unusable for the current shell environment

## If The Daemon Dies Mid-Session

The intended behavior is:
- the projected file disappears again
- the guarded object remains in the store
- `unenroll` can restore the file later

Recovery path:

1. Restart the daemon and verify the projection returns:

```bash
file-snitch run allow
```

2. If you want to stop guarding the file entirely:

```bash
file-snitch unenroll <path>
```

3. If something still looks wrong, export a dossier before making ad hoc edits.

## If `unenroll` Refuses Because The Target Exists

That usually means the file is still projected or a stale file is sitting at
the host path.

Do this in order:

1. stop the active projection
2. confirm the path is gone
3. run `file-snitch unenroll <path>`

Do not manually overwrite the store entry unless you are intentionally doing
recovery work.

## If Policy Changes Do Not Seem To Apply

`run` now reconciles policy changes without restart.

Check:
- are you editing the same `policy.yml` the daemon is using?
- did the file parse cleanly?
- does `status` show the enrollment or decision you expect?

`doctor` is the quickest way to catch obvious policy drift.

## Before Filing A Bug

Collect:
- OS and architecture
- install method
- exact commands you ran
- `file-snitch status`
- `file-snitch doctor`
- `file-snitch doctor --export-debug-dossier ...`
- whether `pass ls` succeeds

Then use the issue templates in `.github/ISSUE_TEMPLATE/`.
