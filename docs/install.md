# Install

This is the first packaging slice, not the final installer story.

Current assumptions:
- single-user, user-space tool
- `pass` is the guarded-object backend
- FUSE support is installed outside Homebrew
- the current authorization frontend is still a TTY agent

## Homebrew

This formula is intentionally `HEAD`-only for now and lives in this repo's
tap-style [Formula/](../Formula) directory.

Tap the repo, then install from `HEAD`:

```bash
brew tap pkoch/file-snitch https://github.com/pkoch/file-snitch
brew install --HEAD --build-from-source pkoch/file-snitch/file-snitch
```

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
- distro-provided FUSE 3 runtime and development files

For example, on Debian/Ubuntu-like systems:

```bash
sudo apt-get install -y fuse3 libfuse3-dev
```

This path has been verified on an Ubuntu arm64 Lima VM with Linuxbrew plus
distro `fuse3` and `libfuse3-dev`.

## First real-user drill

The current prompt path uses two foreground processes:

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

That is intentionally manual for now. Background user services are deferred
until the agent has a non-interactive frontend.

## Notes

- `policy.yml` lives at `~/.config/file-snitch/policy.yml` unless
  `XDG_CONFIG_HOME` overrides it.
- the default local agent socket lives under `XDG_RUNTIME_DIR` when it is
  set, otherwise under `~/.local/state/file-snitch/agent.sock`
- `run prompt` defaults timeout to deny
- the current store backend is `pass:file-snitch/<object_id>`
