# File Snitch

Ask before a tool reads your kubeconfig, SSH key, or other secret-bearing file.

File Snitch moves selected files into a `pass` store and serves them through a
user-owned FUSE daemon. Each original path becomes a symlink to its projected
file; siblings stay on the normal filesystem. In `prompt` mode, a local agent
asks you to allow or deny access, with options to remember the decision.

It runs on Linux and macOS and enrolls individual, user-owned regular files
under your home directory. Read the [threat model](./docs/threat-model.md) for
the limits of mediation within your own account.

[![Recorded File Snitch demo](./docs/assets/demo.gif)](./docs/demo.md)

## Try it

With FUSE and a working `pass`/GPG setup installed:

```bash
brew install pkoch/tap/file-snitch
```

The [install guide](./docs/install.md) covers platform prerequisites and a first
run with a disposable file. To evaluate from a checkout using a fake store,
follow the [demo guide](./docs/demo.md).

## Documentation

- [CLI reference](./docs/cli.md): commands, modes, frontends, and environment
  variables
- [Policy](./docs/policy.md): enrollments and remembered decisions
- [User services](./docs/services.md): run at login with launchd or systemd
- [Troubleshooting](./docs/operations.md): missing files, failed prompts, and
  recovery
- [Documentation index](./docs/index.md): contributor guides and design history

## Development

Start with the [development guide](./docs/development.md) for the pinned Zig
toolchain, FUSE dependencies, devcontainer, and verification commands. Read
[CONTRIBUTING.md](./CONTRIBUTING.md) for code and ownership conventions.

Report problems using the [issue templates](./.github/ISSUE_TEMPLATE), with the
diagnostics described in [reporting a bug](./docs/operations.md#before-filing-a-bug).
