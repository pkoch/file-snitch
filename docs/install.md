# Install

GitHub Release assets are the canonical source of installable artifacts.

Current assumptions:
- single-user, user-space tool
- `pass` is the guarded-object backend
- FUSE support is installed outside Homebrew
- the current authorization frontends are:
  - `terminal-pinentry`
  - `macos-ui` on macOS via `osascript`
  - `linux-ui` on Linux via `zenity`

## Homebrew

Install the current tagged release with:

```bash
brew install pkoch/tap/file-snitch
```

If you explicitly want unreleased `master` changes instead, use:

```bash
brew install --HEAD --build-from-source pkoch/tap/file-snitch
```

The Homebrew formula now lives in:
- `pkoch/homebrew-tap`
- https://github.com/pkoch/homebrew-tap

The formula installs:
- `file-snitch`

It does not install or manage FUSE itself.

### macOS prerequisites

Install:
- Homebrew
- macFUSE
- `pass`
- a usable GPG setup for `pass`

Sanity check:

```bash
pass ls >/dev/null
file-snitch help >/dev/null
```

### Linux prerequisites

Install:
- Homebrew or Linuxbrew
- `pass`
- a usable GPG setup for `pass`
- `zenity` if you want the Linux `linux-ui` agent frontend or user-service path
- distro-provided FUSE 3 runtime and development files

For example, on Debian/Ubuntu-like systems:

```bash
sudo apt-get install -y fuse3 libfuse3-dev
```

This path has been verified on an Ubuntu arm64 Lima VM with Linuxbrew plus
distro `fuse3` and `libfuse3-dev`.

## First real-user drill

The manual bootstrap path can run entirely in the foreground.

Cross-platform bootstrap path:

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

macOS native dialog path:

Terminal 1:

```bash
file-snitch agent --frontend macos-ui
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

That is still intentionally manual, but it now exercises the native dialog on
macOS.

Linux native dialog path:

Terminal 1:

```bash
file-snitch agent --frontend linux-ui
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

That uses `zenity` as the current Linux native frontend.

## Disposable evaluation

If you want to see the current feature set without touching your real secrets,
use the repo demo driver:

```bash
brew install anyzig
zig build
./scripts/demo/demo-session.sh
```

For a recording-friendly version, see [docs/demo.md](./demo.md).

## Reporting install or runtime problems

Export a dossier before filing an issue when possible:

```bash
file-snitch doctor --export-debug-dossier ./file-snitch-debug-dossier.md
```

That file is meant to accompany GitHub bug reports. It includes policy and
environment diagnostics, but not guarded file contents.

## User services

Per-user service installation now has real helper scripts:
- [docs/services.md](./services.md)
- [scripts/services/render-user-services.sh](../scripts/services/render-user-services.sh)
- [scripts/services/install-user-services.sh](../scripts/services/install-user-services.sh)
- [scripts/services/uninstall-user-services.sh](../scripts/services/uninstall-user-services.sh)

macOS first-class path:

```bash
./scripts/services/install-user-services.sh --platform macos --bin "$(command -v file-snitch)"
```

Linux first-class path:

```bash
./scripts/services/install-user-services.sh --platform linux --bin "$(command -v file-snitch)"
```

That installs:
- macOS:
  - `dev.file-snitch.agent` with `macos-ui`
  - `dev.file-snitch.run` in `prompt` mode
- Linux:
  - `file-snitch-agent.service` with `linux-ui`
  - `file-snitch-run.service` in `prompt` mode

Linux requires `zenity` for that unattended prompt path.

## Shell Completion

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

These commands write the generated completion file to a common per-user location.
Whether that location is loaded automatically depends on your shell
configuration.

## Notes

- `policy.yml` lives at `FILE_SNITCH_POLICY_PATH` when set, otherwise at
  `XDG_CONFIG_HOME/file-snitch/policy.yml`, otherwise at
  `~/.config/file-snitch/policy.yml`.
- the default local agent socket lives under `XDG_RUNTIME_DIR` when it is
  set, otherwise under `~/.local/state/file-snitch/agent.sock`
- set `FILE_SNITCH_AGENT_TTY` or pass `--tty <path>` if you want a
  `terminal-pinentry` agent to use a specific terminal
- `macos-ui` uses `osascript` on macOS and does not accept `--tty`
- prompt-capable frontends offer:
  - allow once
  - deny once
  - allow 5 min
  - always allow
  - always deny
- `run prompt` defaults timeout to deny
- the current store backend is `pass:file-snitch/<object_id>`
- each `pass` entry is a File Snitch JSON/base64 payload capped at 1 MiB; this
  is a File Snitch capture/memory limit, not a `pass` limit
- `unenroll` streams oversized guarded objects back to disk without the normal
  capture limit before removing the store entry
