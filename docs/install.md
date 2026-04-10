# Install

Formal releases are moving toward GitHub Release assets as the canonical
source of installable artifacts. Until the first tagged release exists, the
repo still supports the current `HEAD`-oriented path too.

Current assumptions:
- single-user, user-space tool
- `pass` is the guarded-object backend
- FUSE support is installed outside Homebrew
- the current authorization frontends are:
  - `terminal-pinentry`
  - `macos-ui` on macOS via `osascript`
  - `linux-ui` on Linux via `zenity`

## Homebrew

This repo's [Formula/](../Formula) directory is the Homebrew/Linuxbrew entry
point.

Before the first formal release lands, install from `HEAD`:

```bash
brew tap pkoch/file-snitch https://github.com/pkoch/file-snitch
brew install --HEAD --build-from-source pkoch/file-snitch/file-snitch
```

After formal releases start, the same tap will grow a stable release block
that points at the tagged source tarball published on GitHub Releases.

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
file-snitch agent --foreground
```

Terminal 2:

```bash
file-snitch run prompt --foreground
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
file-snitch agent --frontend macos-ui --daemon
```

Terminal 2:

```bash
file-snitch run prompt --foreground
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
file-snitch agent --frontend linux-ui --daemon
```

Terminal 2:

```bash
file-snitch run prompt --foreground
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
zig build
./scripts/demo-session.sh
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
- [scripts/render-user-services.sh](../scripts/render-user-services.sh)
- [scripts/install-user-services.sh](../scripts/install-user-services.sh)
- [scripts/uninstall-user-services.sh](../scripts/uninstall-user-services.sh)

macOS first-class path:

```bash
./scripts/install-user-services.sh --platform macos --bin "$(command -v file-snitch)"
```

Linux first-class path:

```bash
./scripts/install-user-services.sh --platform linux --bin "$(command -v file-snitch)"
```

That installs:
- macOS:
  - `dev.file-snitch.agent` with `macos-ui`
  - `dev.file-snitch.run` in `prompt` mode
- Linux:
  - `file-snitch-agent.service` with `linux-ui`
  - `file-snitch-run.service` in `prompt` mode

Linux requires `zenity` for that unattended prompt path.

## Notes

- `policy.yml` lives at `~/.config/file-snitch/policy.yml` unless
  `XDG_CONFIG_HOME` overrides it.
- the default local agent socket lives under `XDG_RUNTIME_DIR` when it is
  set, otherwise under `~/.local/state/file-snitch/agent.sock`
- set `FILE_SNITCH_AGENT_TTY` or pass `--tty <path>` if you want a daemonized
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
