# CLI Reference

For a walkthrough, see [first run](./install.md#first-run). This page covers
command behavior and configuration; `file-snitch help` prints the usage summary.

## Commands

```text
file-snitch --version
file-snitch completion <bash|zsh|fish>
file-snitch agent [--socket <path>] [--frontend <terminal-pinentry|macos-ui|linux-ui>] [--tty <path>]
file-snitch run [allow|deny|prompt] [--policy <path>]
file-snitch enroll <path> [--policy <path>]
file-snitch unenroll <path> [--policy <path>]
file-snitch status [--policy <path>]
file-snitch doctor [--policy <path>] [--export-debug-dossier <path>]
file-snitch services render [--platform <macos|linux>] [--bin <path>] [--pass-bin <path>] --output-dir <dir>
file-snitch services install [--platform <macos|linux>] [--bin <path>] [--pass-bin <path>]
file-snitch services uninstall [--platform <macos|linux>]
```

## Run

`run` stays in the foreground, loads the policy, and supervises one FUSE
projection at `$XDG_STATE_HOME/file-snitch/projection`, falling back to
`$HOME/.local/state/file-snitch/projection`. Each enrollment is an `<object_id>`
entry in that mount, linked from its original path.

The mode sets the default when no remembered policy decision matches:

| Mode | Reads | Mutations |
| --- | --- | --- |
| `allow` | Allow | Allow |
| `deny` (default) | Allow | Deny |
| `prompt` | Ask the agent | Ask the agent |

**`run deny` does not block reads.** Use `run prompt` to ask before reads.
Remembered decisions take precedence in all modes, so an explicit allow or deny
can override the mode's default. Only `prompt` mode connects a prompt broker;
a policy outcome of `prompt` in another mode fails with permission denied.

`run` watches for policy changes, including when the policy is empty or missing.
Enrollment changes rebuild the projection; remembered decisions apply on the
next guarded access without a remount. Expired decisions are ignored and pruned.
The watcher uses filesystem events where supported, with a polling fallback
that compares file contents as well as metadata. Transient policy read/stat
errors are reported while the existing projection stays active.

### Authorization scope

Authorization happens before the operation takes effect. `open` and `create`
classify the requested handle as read-only or write-capable. Later reads,
writes, and truncation can reuse a matching handle grant; a read grant does not
authorize a write.

Operations on projected files also check policy for rename, deletion,
`chmod`/`chown`, and extended attributes. All xattr operations, including reads,
use the `write_capable` approval class. Xattrs are held on local lock-anchor
files, outside the stored file payload.

These checks apply to operations that reach the FUSE projection. Replacing or
removing the symlink in its original parent directory is outside that mount;
see the [threat model](./threat-model.md#scope-and-bypasses).

## Agent

`agent` stays in the foreground and listens on a user-owned Unix socket.
`run prompt` sends requests to that socket; it never reads the daemon's stdin.

| Frontend | Prompt destination |
| --- | --- |
| `terminal-pinentry` (default) | Inherited stdio, or the terminal selected by `--tty` |
| `macos-ui` | macOS dialogs through `osascript`; no `--tty` |
| `linux-ui` | Linux dialogs through `zenity`; no `--tty` |

The terminal frontend is built in; it does not invoke an external pinentry
program. Empty input (Enter) and EOF allow the request. An explicit denial,
a prompt timeout, or an unavailable broker returns permission denied.

Frontends offer allow once and deny once. When the requesting executable can be
identified, they also offer allow 5 min, always allow, and always deny. The
requester writes remembered choices to its [policy file](./policy.md).

There are two separate timeouts:

- `FILE_SNITCH_PROMPT_TIMEOUT_MS`: agent-owned user interaction, default 30000 ms.
  Set this in the agent's environment.
- `FILE_SNITCH_PROTOCOL_TIMEOUT_MS`: requester/agent protocol liveness, default
  1000 ms. This is not the time allowed to answer a dialog.

## Enroll and unenroll

`enroll <path>` stores the file contents and metadata in `pass`, records the
mapping in policy, and removes the original file. The target must resolve to a
user-owned regular file under the current user's home directory. The daemon
creates the symlink when it prepares the projection.

`unenroll <path>` removes the enrollment from policy, waits for any active
projection to release the target, and restores the stored file. It then removes
the store entry and remembered decisions for that path. A teardown timeout
restores the enrollment so the command can be retried.

The CLI uses `pass:file-snitch/<object_id>` as its store. Its JSON/base64 payload
limit is 1 MiB, including metadata and encoding overhead, so the file-content
limit is smaller. `unenroll` can stream an oversized stored payload back to
disk for recovery. See [store troubleshooting](./operations.md#if-pass-or-gpg-is-failing).

## Status and doctor

`status` reads policy and prints enrollments, remembered decisions, the derived
projection root, and store references. It does not prove that the daemon is
running or the projected files are usable.

`doctor` checks policy, store objects, target paths, agent reachability,
frontend helpers, and service configuration. It exits nonzero for actionable
problems and prints recovery hints. Use `--export-debug-dossier <path>` to save
its diagnostics; see [bug reports](./operations.md#before-filing-a-bug) for what
the report includes.

## Paths and environment

For each row, the first configured value wins:

| Setting | Precedence |
| --- | --- |
| Policy file | `--policy`, `FILE_SNITCH_POLICY_PATH`, `$XDG_CONFIG_HOME/file-snitch/policy.yml`, `$HOME/.config/file-snitch/policy.yml` |
| Agent socket | `agent --socket`, `FILE_SNITCH_AGENT_SOCKET`, `$XDG_RUNTIME_DIR/file-snitch/agent.sock`, `$HOME/.local/state/file-snitch/agent.sock` |
| Terminal for the agent | `--tty`, `FILE_SNITCH_AGENT_TTY`, inherited stdio |
| Projection root | `$XDG_STATE_HOME/file-snitch/projection`, `$HOME/.local/state/file-snitch/projection` |

`--policy` applies to `run`, `enroll`, `unenroll`, `status`, and `doctor`.
If you use `agent --socket`, set `FILE_SNITCH_AGENT_SOCKET` for `run` and `doctor`
to the same path. Changing `XDG_STATE_HOME` does not relocate the agent socket.

Helper overrides are `FILE_SNITCH_PASS_BIN`, `FILE_SNITCH_OSASCRIPT_BIN`, and
`FILE_SNITCH_ZENITY_BIN`; defaults are `pass`, `osascript`, and `zenity` from
`PATH`. `pass` and GPG also use their own environment, including
`PASSWORD_STORE_DIR` and `GNUPGHOME`.

Service installation and its environment are covered in
[user services](./services.md).

## Completion

Bash:

```bash
mkdir -p ~/.local/share/bash-completion/completions
file-snitch completion bash > ~/.local/share/bash-completion/completions/file-snitch
```

Zsh:

```bash
mkdir -p ~/.zsh/completions
file-snitch completion zsh > ~/.zsh/completions/_file-snitch
```

Fish:

```bash
mkdir -p ~/.config/fish/completions
file-snitch completion fish > ~/.config/fish/completions/file-snitch.fish
```

These are common per-user locations. Your shell configuration must load the
chosen directory; for zsh, add it to `fpath` before running `compinit`.
