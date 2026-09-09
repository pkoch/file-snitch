# Development

Read [CONTRIBUTING.md](../CONTRIBUTING.md) for scope, ownership, and review
conventions.

## Development environment

The [devcontainer](../.devcontainer/devcontainer.json) provides Ubuntu, FUSE 3
build dependencies, GPG, `pass`, Python, and the Zig version pinned in
[build.zig.zon](../build.zig.zon). Open it with your editor's Dev Containers
support or the Dev Container CLI:

```bash
devcontainer up --workspace-folder .
devcontainer exec --workspace-folder . ./.devcontainer/scripts/check.sh
```

The container requires the Linux host's `/dev/fuse`; its configuration grants
the container access to that device and the capabilities needed to mount FUSE.
The check script verifies tool versions and FUSE discovery, then builds, runs
Zig tests, generates compile commands, and checks the docs. It does not run the
mounted smoke suite.

### Native setup

Use the Zig version in `build.zig.zon`. Anyzig selects it automatically:

```bash
brew install anyzig
```

A directly installed matching Zig release also works; the devcontainer setup
script uses that approach.

| Platform | Build dependencies |
| --- | --- |
| Linux | `pkg-config`, `fuse3`, and `libfuse3-dev` (Debian/Ubuntu package names) |
| macOS | Xcode Command Line Tools and macFUSE with libfuse compatibility libraries |

Python 3 is needed for docs and release-source checks. Real-store testing also
needs `pass` and a usable GPG keyring.

On macOS, export the SDK path so the C shim and Zig C imports can find headers
such as `sys/xattr.h`:

```bash
export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
```

FUSE discovery lives in [build/fuse_support.zig](../build/fuse_support.zig).
Linux uses `pkg-config fuse3`, with a fallback to system paths. macOS accepts
`FILE_SNITCH_FUSE_INCLUDE_DIR` and `FILE_SNITCH_FUSE_LIB_DIR`, then tries
`pkg-config fuse`, then standard `/usr/local` and `/opt/homebrew` locations.
Extracting the SDK for CI builds does not install a working FUSE runtime.

## Core loop

```bash
zig build
zig build test
./scripts/docs/check-docs.sh
```

`zig build` installs the CLI at `zig-out/bin/file-snitch`. `zig build test` runs
the test roots wired in [build.zig](../build.zig). The docs check builds the
binary, compares the documented command block with its help output, checks
local Markdown links, and checks the smoke-test inventory below.

Run `zig build compile-commands` after cloning or changing build flags or FUSE
locations to refresh `compile_commands.json` for clangd.

[tests/build.sh](../tests/build.sh) is the CI build entrypoint: it runs the build,
Zig tests, compile-command generation, and a release-source tarball check.
`ZIG_BUILD_TARGET` selects its target when needed.

## Smoke tests

Build the binary first. The smoke fixtures use a fake `pass` executable and a
disposable home/store. Mounted scenarios still require a working host FUSE
runtime; fake GUI helpers exercise frontend behavior without opening dialogs.

| Command | Coverage |
| --- | --- |
| `./tests/smoke/run-empty-policy.sh` | Empty-policy daemon stays alive |
| `./tests/smoke/policy-lifecycle.sh` | Enroll, status, doctor, unenroll |
| `./tests/smoke/doctor-debug-dossier.sh` | Dossier export without guarded contents |
| `./tests/smoke/run-policy-reload.sh` | Policy changes activate and remove projections |
| `./tests/smoke/run-expired-decision-cleanup.sh` | Expired decisions are pruned |
| `./tests/smoke/run-single-enrollment.sh` | One projected file with unguarded siblings |
| `./tests/smoke/run-multi-mount.sh` | Multiple enrolled paths in one projection root |
| `./tests/smoke/run-prompt-linux-ui.sh` | Linux frontend with fake `zenity` |
| `./tests/smoke/run-prompt-single.sh` | Terminal allow, deny, and timeout |
| `./tests/smoke/run-prompt-remembered-decision.sh` | Durable choice and prompt suppression |
| `./tests/smoke/user-service-rendering.sh` | launchd and systemd service rendering |
| `./tests/smoke/run-prompt-macos-ui.sh` | macOS projection with fake `osascript` |
| `./tests/smoke/run-prompt-macos-ui-agent.sh` | macOS agent socket/frontend without a mount |

The last two scripts require macOS. `run-multi-mount.sh` retains its historical
name; it checks the shared projection root.

[tests/verify.sh](../tests/verify.sh) combines the CI build entrypoint, the main
smoke suite, and demo checks. Run `run-prompt-macos-ui-agent.sh` separately on
macOS; that script and the docs check are separate CI steps. See
[repro scripts](../tests/repro/README.md) for intermittent process/harness failures.

## Shell and demo checks

To check each shell script's syntax:

```bash
find .devcontainer scripts tests -type f -name '*.sh' -exec bash -n {} ';'
```

CI also runs ShellCheck and `./scripts/demo/check-demo-artifacts.sh`. The latter
checks artifact presence and known leakage markers, not recording freshness.
See [demo](./demo.md) for regeneration and
[redaction review](./redaction-review.md) for manual review.

## Source layout

| Path | Responsibility |
| --- | --- |
| `src/cli.zig` | Argument parsing and dispatch |
| `src/cli_supervisor.zig`, `src/cli_policy_watch.zig` | Projection lifecycle and policy watching |
| `src/config/core.zig` | Policy parsing, writes, and projection plans |
| `src/policy/core.zig`, `src/enrollment.zig` | Enrollment commands, diagnostics, and file migration |
| `src/policy.zig` | Access-policy evaluation |
| `src/agent/`, `src/prompt.zig` | Socket protocol and prompt frontends |
| `src/filesystem/`, `src/daemon.zig` | Filesystem model and FUSE callbacks |
| `src/store.zig` | Guarded-object backend interface and implementations |
| `src/user_services.zig`, `packaging/` | Embedded service definitions |
| `c/` | C FUSE harness and syscall helpers |
| `src/root.zig` | Shared module exports for tests and non-CLI consumers |

`src/agent.zig`, `src/config.zig`, and `src/filesystem.zig` re-export their
submodules. Most implementation changes belong in the corresponding directory.

## Store testing

The CLI uses the `pass` backend. `src/store.zig` also provides an in-memory
backend for development and tests, with backend metadata and object-listing
interfaces. It is not a selectable persistent CLI store; the `pass` backend
does not implement object listing.

For a real-store check, follow the [first-run walkthrough](./install.md#first-run)
with its disposable file. Use a disposable home, password store, and GPG keyring
when testing migrations or recovery behavior that could damage data.
