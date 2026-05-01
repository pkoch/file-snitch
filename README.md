# File Snitch

Keep tools from silently reading your kubeconfig, SSH keys, and other
secret-bearing files.

If you are evaluating the project for the first time, start with
[docs/index.md](./docs/index.md).

## What It Is

File Snitch is a single-user file mediation tool. It moves selected
secret-bearing files out of their normal host paths, keeps their contents in a
guarded store, and projects them back into place through a user-owned FUSE
daemon.

When a guarded path is accessed, the daemon can ask a local agent whether to
allow or deny that operation. Unguarded siblings in the same directory continue
to behave normally.

## What It Does Today

- exact-file enrollment for user-owned regular files under your home directory
- policy-driven `run`, `enroll`, `unenroll`, `status`, and `doctor` commands
- guarded-object custody through `pass:file-snitch/<object_id>`
- FUSE projection under the user state directory with target-path symlinks
- unguarded siblings remain on the normal filesystem
- remembered decisions in `policy.yml`, including RFC3339 UTC expiry
- local agent frontends:
  - `terminal-pinentry`
  - `macos-ui` on macOS via `osascript`
  - `linux-ui` on Linux via `zenity`
- shell completion generation for bash, zsh, and fish
- formal GitHub Release artifacts plus Homebrew/Linuxbrew packaging
- embedded per-user service management for `launchd` and `systemd --user`

## What It Does Not Do

- protect against root
- arbitrate between local users
- act as a system-wide MAC framework
- support store backends other than `pass` yet

Read [docs/threat-model.md](./docs/threat-model.md) before treating File Snitch
as a security boundary. That is intentionally not its job.

## Quick Evaluation

Install Anyzig so `zig` follows this repo's pinned toolchain:

```bash
brew install anyzig
```

Build the binary:

```bash
zig build
```

Then choose one path:

- disposable demo: [docs/demo.md](./docs/demo.md)
- real install and first-user drill: [docs/install.md](./docs/install.md)
- per-user services: [docs/services.md](./docs/services.md)
- command reference: [docs/cli.md](./docs/cli.md)
- policy file reference: [docs/policy.md](./docs/policy.md)

## Recorded Demo

[![Recorded File Snitch demo](./docs/assets/demo.gif)](./docs/demo.md)

Regenerate the embedded demo artifacts with:

```bash
./scripts/demo/regenerate-demo-artifacts.sh
```

The checked-in demo is a tmux-driven session that shows the agent pane, the
daemon pane, and a user shell triggering guarded access while sibling files
remain outside the projection.

## Development Environment

This repo includes a ready-to-use devcontainer in
[.devcontainer/devcontainer.json](./.devcontainer/devcontainer.json). Use it as
the default local Linux development environment, or as a reference for setting
up another Linux runner.

## Reporting Problems

Before opening an issue, export a dossier:

```bash
file-snitch doctor --export-debug-dossier ./file-snitch-debug-dossier.md
```

The dossier includes environment and policy diagnostics, but it does not export
guarded file contents. Then use the issue templates under
[.github/ISSUE_TEMPLATE](./.github/ISSUE_TEMPLATE).

Operational guidance and troubleshooting live in
[docs/operations.md](./docs/operations.md).

## Working On The Repo

- contributor guide: [CONTRIBUTING.md](./CONTRIBUTING.md)
- development and verification workflow: [docs/development.md](./docs/development.md)
- release and packaging checklist: [docs/releasing.md](./docs/releasing.md)
- error-handling conventions: [docs/error-handling.md](./docs/error-handling.md)

## Layout

- `build.zig`: Zig build entrypoint
- `build.zig.zon`: package metadata, Zig version pin, and dependency metadata
- `src/`: Zig application code
- `src/root.zig`: shared application module surface for tests and non-CLI consumers
- `src/cli.zig`: command-line parsing, env loading, and runtime dispatch
- `src/policy/core.zig`: `enroll`, `unenroll`, `status`, and `doctor`
- `src/enrollment.zig`: guarded-object migration and path-level enrollment helpers
- `src/config.zig`: `policy.yml` loading, mutation, and projection-plan derivation
- `src/agent.zig`: local requester/agent socket protocol and frontends
- `src/filesystem.zig`: Zig-owned filesystem behavior for projection mount
- `c/`: thin C boundary for `libfuse` interop and syscall-adjacent helpers
- `tests/`: Zig integration tests and smoke scenarios
- `scripts/`: demo, docs, release, and vendoring helpers
- `docs/`: operator docs, contributor docs, and research notes

## Architecture Guardrails

- File Snitch is a user-first mediation tool, not a system-wide security
  framework.
- V1 scope is exact file enrollment for one user's own home-directory secrets.
- Policy, state, sockets, locks, and services are per-user.
- The C shim is a faithful FUSE harness, not a product-policy layer.
- Prompting must happen before the guarded operation takes effect.
- Authorization must align with intent. Read-like authorization must not grant
  later write-like behavior.

The product brief and design history start at
[docs/research/0 - initial-brief.md](./docs/research/0%20-%20initial-brief.md).
