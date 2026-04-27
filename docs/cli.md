# CLI Reference

This page mirrors the command surface exposed by `file-snitch help` and adds
the operational notes that are easiest to forget during manual testing.

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

## Normal Foreground Flow

Terminal 1:

```bash
file-snitch agent
```

Terminal 2:

```bash
file-snitch run prompt
```

Terminal 3:

```bash
file-snitch enroll ~/.kube/config
kubectl config view >/dev/null
file-snitch unenroll ~/.kube/config
```

Use `file-snitch run allow` when you need the projection without prompts, and
`file-snitch run deny` when you want to verify that guarded access is blocked.
If no mode is supplied, `run` defaults to `deny`.

## Agent

`file-snitch agent` starts the local user-owned agent service on a Unix socket.
The default frontend is `terminal-pinentry`.

Frontends:

- `terminal-pinentry`: prompts through inherited stdio, or through `--tty <path>`
- `macos-ui`: uses `osascript`; does not accept `--tty`
- `linux-ui`: uses `zenity`; does not accept `--tty`

Socket path precedence:

1. `--socket <path>`
2. `FILE_SNITCH_AGENT_SOCKET`
3. `XDG_RUNTIME_DIR/file-snitch/agent.sock`
4. `HOME/.local/state/file-snitch/agent.sock`

TTY path precedence for `terminal-pinentry`:

1. `--tty <path>`
2. `FILE_SNITCH_AGENT_TTY`
3. inherited stdio

Prompt-capable frontends currently offer:

- allow once
- deny once
- allow 5 min
- always allow
- always deny

The user-interaction timeout defaults to 30000 ms. Override it with
`FILE_SNITCH_PROMPT_TIMEOUT_MS`.

## Run

`file-snitch run` is the long-lived policy reconciler. It loads `policy.yml`,
derives the mount plan, starts mount workers, and reconciles future policy
changes without requiring a restart.

Policy path precedence:

1. `--policy <path>`
2. `FILE_SNITCH_POLICY_PATH`
3. `XDG_CONFIG_HOME/file-snitch/policy.yml`
4. `HOME/.config/file-snitch/policy.yml`

The policy file format is documented in [policy.md](./policy.md).

Modes:

- `allow`: allow guarded operations without prompting
- `deny`: deny guarded operations without prompting
- `prompt`: ask the local agent over the Unix socket

`run prompt` uses the agent socket; it does not prompt on the daemon's stdin.
The requester/agent protocol timeout defaults to 1000 ms. Override it with
`FILE_SNITCH_PROTOCOL_TIMEOUT_MS`.

Runtime notes:

- `run` stays alive on an empty policy and watches for future changes
- policy watching prefers event-driven wakeups where the host supports them and
  falls back to polling where needed
- the polling fallback compares full `policy.yml` content as well as file
  metadata
- transient policy read/stat failures keep the current mounts active and report
  the real error
- one `run` process can supervise multiple planned mounts
- multiple enrolled files under one mounted tree are supported, including
  nested guarded paths
- remembered decisions take effect on the next guarded access without requiring
  a remount
- expired durable decisions are pruned from `policy.yml`

Prompt scope:

- `prompt` mode currently mediates `open` and `create` on guarded paths
- later operations on an already-authorized handle may reuse that authorization
  when the requested behavior still matches the authorized handle mode
- xattr traffic does not prompt yet

## Enroll And Unenroll

`file-snitch enroll <path>` migrates plaintext from the original path into the
guarded store, records the enrollment in `policy.yml`, and leaves the original
path absent until `run` projects it back.

`file-snitch unenroll <path>` restores the guarded object to the original path,
removes the enrollment from `policy.yml`, and removes remembered decisions for
that path. If the file is currently projected by `file-snitch run`, `unenroll`
updates the policy first, waits for the daemon to tear the projection down, and
then restores the guarded object.

Current enrollment limits:

- the target must be a user-owned regular file under the current user's home
  directory
- the only guarded-store backend is `pass`
- the current store ref shape is `pass:file-snitch/<object_id>`
- each stored `pass` entry is one JSON/base64 payload capped at 1 MiB during
  normal capture
- `unenroll` can recover an oversized guarded object by streaming it back to
  disk before removing the store entry

Policy updates are serialized with a sidecar lock so `enroll`, `unenroll`,
remembered decisions, and daemon expiry pruning do not clobber each other.

## Status And Doctor

`file-snitch status` prints the policy path, enrollment count, decision count,
derived mount plan, and guarded-object refs.

`file-snitch doctor` validates policy, guarded objects, target-path health,
agent reachability, frontend helpers, and service files where applicable. It
exits non-zero when it finds actionable problems.

Export a shareable debug report with:

```bash
file-snitch doctor --export-debug-dossier ./file-snitch-debug-dossier.md
```

The dossier includes environment and policy diagnostics, but not guarded file
contents.

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
