# File Snitch

Keep tools from silently reading your kubeconfig, SSH keys, and other
secret-bearing files.

File Snitch moves selected files out of their usual paths, projects them back
through a user-owned FUSE daemon, and asks a local agent before guarded
access. The rest of the directory still behaves normally.

[![Recorded File Snitch demo](./assets/demo.gif)](./demo.md)

## Why It Exists

Some secret files are too convenient to leave in place and too useful to lock
away completely.

Examples:
- `~/.kube/config`
- `~/.ssh/id_ed25519`
- Docker auth config
- tool-specific token files

File Snitch is for the middle ground:
- keep the file out of its original path by default
- make access visible and mediable
- keep sibling files and normal workflows working

## What You Get Today

- exact-file enrollment for user-owned regular files under your home directory
- guarded-object custody through `pass:file-snitch/<object_id>`
- in-place projection back into the real parent directory
- sibling passthrough under the same mounted tree
- a local requester/agent socket with:
  - `terminal-pinentry`
  - `macos-ui` via `osascript`
  - `linux-ui` via `zenity`
- remembered decisions in `policy.yml`
  - allow once
  - deny once
  - allow 5 min
  - always allow
  - always deny
- Homebrew/Linuxbrew install path and per-user service helpers

## What It Is Not

File Snitch is intentionally narrow.

It does not try to:
- protect against root
- arbitrate between local users
- become a system-wide MAC framework
- replace encrypted-at-rest secret storage

The short version: this is a user-first secret mediation tool, not a system
security product.

Read the full stance in [threat-model.md](./threat-model.md).

## How It Feels

1. Enroll one file.
2. The plaintext disappears from its original host path.
3. Start the daemon and the local agent.
4. Use your normal tool.
5. File Snitch prompts before guarded access.
6. Stop the daemon and the guarded file disappears again.

That is the core product moment.

## Try It

If you want a safe disposable walkthrough:
- [demo.md](./demo.md)
- `./scripts/demo-session.sh`

If you want to install and try it on a real machine:
- [install.md](./install.md)

If you want per-user services:
- [services.md](./services.md)
- `./scripts/install-user-services.sh --bin "$(command -v file-snitch)"`

## If Something Goes Wrong

Start with:

```bash
file-snitch status
file-snitch doctor
```

If you need to file a bug:

```bash
file-snitch doctor --export-debug-dossier ./file-snitch-debug-dossier.md
```

Then use the issue templates under
[../.github/ISSUE_TEMPLATE](../.github/ISSUE_TEMPLATE).

Operational recovery guidance lives in [operations.md](./operations.md).

## Read More

- [install.md](./install.md)
- [demo.md](./demo.md)
- [services.md](./services.md)
- [operations.md](./operations.md)
- [threat-model.md](./threat-model.md)
- [README.md](../README.md) for repo internals, architecture notes, and the
  full verification workflow
