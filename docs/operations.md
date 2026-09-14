# Operations and Troubleshooting

Start with the policy summary and health checks:

```bash
file-snitch status
file-snitch doctor
```

Follow the `hint:` lines from `doctor`. `status` reads policy; it does not check
whether the daemon is alive. If you use a custom policy or socket, keep the
[environment](./cli.md#paths-and-environment) consistent with the running processes.

## Symptom cheat sheet

| Symptom | Next step |
| --- | --- |
| Guarded file is missing or a dangling symlink | [Check the projection](#if-a-guarded-file-is-missing) |
| Prompt does not appear | [Check mode, decisions, and agent](#if-you-expected-a-prompt-and-did-not-get-one) |
| `pass` or GPG fails | [Check the store and service environment](#if-pass-or-gpg-is-failing) |
| Stale or inaccessible FUSE mount | [Recover the projection root](#if-the-daemon-dies-mid-session) |
| `unenroll` waits for the target | [Resolve the existing path](#if-unenroll-waits-because-the-target-exists) |
| Policy edit has no effect | [Check the policy path and daemon logs](#if-policy-changes-do-not-seem-to-apply) |

## If a guarded file is missing

Enrollment removes the original regular file. While `run` is active, the
original path is a symlink into the state-directory projection. Without the
mount, that path can be absent or a dangling symlink; its contents remain in
`pass`.

Confirm the enrollment with `status`, then start the agent and daemon as in the
[first-run walkthrough](./install.md#first-run). Use `run prompt` for prompted
access. `run allow` allows reads and mutations by default; `run deny` still
allows reads. See [mode behavior](./cli.md#run).

To restore the file permanently, run `file-snitch unenroll <path>`. Removing a
policy entry by hand does not restore its contents.

## If you expected a prompt and did not get one

Check these in order:

1. `status` lists the intended file and policy path.
2. The daemon is running in `prompt` mode.
3. No remembered allow or deny outcome already covers that executable, enrolled
   path, and approval class. Those outcomes apply on the next access without a
   remount.
4. `doctor` can reach the agent at the same socket the daemon uses.
5. The frontend can display a prompt: inherited stdio or `--tty` for
   `terminal-pinentry`, `osascript` on macOS, or `zenity` in a Linux graphical
   session.

An already-authorized handle can reuse its grant. An application may also have
cached the contents instead of reading again. The terminal frontend treats
Enter and EOF as allow; keep it attached to a usable terminal.

If the target was replaced with a regular file or a different symlink, access
may no longer reach File Snitch. `doctor` reports that mismatch. See
[scope and bypasses](./threat-model.md#scope-and-bypasses).

## If `pass` or GPG is failing

```bash
pass ls
gpg --version
file-snitch doctor
```

Listing the store checks discovery, not decryption. File Snitch also needs the
secret key, a working GPG agent/pinentry, and the correct `GNUPGHOME` and
`PASSWORD_STORE_DIR`. A projection loads guarded objects when it starts, so GPG
may ask for access before a File Snitch authorization prompt appears.

Services do not inherit your interactive shell environment. If `doctor` reports
an incorrect `pass` path or stale service definition, reinstall with explicit
binary paths as described in [user services](./services.md).

The stored JSON/base64 payload is capped at 1 MiB, including metadata and
encoding overhead. This is a File Snitch limit. For an oversized object already
in the store, `unenroll` streams it back to disk without the normal capture
limit and removes the entry only after restoration succeeds.

## If the daemon dies mid-session

The store retains enrolled objects, but the original paths may point at an
unavailable projection. Restart the daemon and check `doctor`. The supervisor
attempts to recover an inaccessible stale mount before starting a new worker.

If recovery still fails, stop the daemon (including its user service) and
inspect the mount at the **projection root** printed by `status`. With the
same `XDG_STATE_HOME` environment as the daemon, unmount it using your platform's
command:

```bash
# Linux
fusermount3 -u "${XDG_STATE_HOME:-$HOME/.local/state}/file-snitch/projection"

# macOS
umount "${XDG_STATE_HOME:-$HOME/.local/state}/file-snitch/projection"
```

Then restart in `prompt` mode or use `unenroll` to restore the files. The FUSE
mount is in the state directory, not the enrolled file's parent directory.

## If `unenroll` waits because the target exists

`unenroll` removes the enrollment from policy so an active daemon can release
it, then waits up to 10 seconds for the target to become unavailable before
restoring the stored file. A timeout restores the enrollment for a retry.

If the target is still mounted, stop the projection and retry. If it is an
unexpected regular file or symlink, inspect and move it aside before retrying;
it may contain changes that are not in the guarded store. Preserve the stored
object until restoration succeeds.

## If policy changes do not seem to apply

`run` reconciles policy changes without a restart. Confirm that `status` reads
the same path as the daemon, check the [YAML format](./policy.md), and inspect
the daemon logs for parse or projection errors. Transient read/stat failures
leave the existing projection running and report the error.

## Before filing a bug

Export diagnostics when possible:

```bash
file-snitch doctor --export-debug-dossier ./file-snitch-debug-dossier.md
```

The dossier includes versions, enrollment paths, object IDs, remembered
decisions, and doctor output. It omits guarded file contents and replaces your
home-directory prefix with `~`. Paths and other diagnostic metadata remain
visible, so review the report before sharing it.

Use the [issue templates](../.github/ISSUE_TEMPLATE) and include the install
method, commands that reproduced the problem, and the dossier. A nonzero
`doctor` exit status means it found problems; it can still write the report.
