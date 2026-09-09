# User Services

`file-snitch services` installs a per-user agent and a daemon in `prompt` mode.
The service definitions are embedded in the binary.

| Platform | Agent | Daemon | Frontend |
| --- | --- | --- | --- |
| macOS / launchd | `dev.file-snitch.agent` | `dev.file-snitch.run` | `macos-ui` via `osascript` |
| Linux / systemd --user | `file-snitch-agent.service` | `file-snitch-run.service` | `linux-ui` via `zenity` |

Complete the [foreground walkthrough](./install.md#first-run) first. Stop those
foreground processes before installing services so they do not compete for the
same socket and projection. Linux installation requires `zenity` on `PATH`;
the agent needs access to a graphical session.

## Install or remove

Install and start both services for the detected platform:

```bash
file-snitch services install \
  --bin "$(command -v file-snitch)" \
  --pass-bin "$(command -v pass)"
```

To inspect the files first, render them into a local directory:

```bash
file-snitch services render \
  --bin "$(command -v file-snitch)" \
  --pass-bin "$(command -v pass)" \
  --output-dir ./out
```

`--platform macos` or `--platform linux` selects the template set explicitly.
The binary paths are resolved to absolute paths when rendering or installing.

Remove the services with:

```bash
file-snitch services uninstall
```

Uninstalling services stops projection; it leaves enrollments and stored
objects intact. Use `unenroll` for each file you want restored.

## Environment and upgrades

The run service pins `FILE_SNITCH_PASS_BIN`. The macOS run plist also sets a
`PATH` containing the binary locations and standard helper paths. Other shell
overrides, such as `GNUPGHOME`, `PASSWORD_STORE_DIR`, custom policy/socket paths,
or `FILE_SNITCH_ZENITY_BIN`, are not copied into the service definitions by the
installer. Configure them in the service environment if needed.

The templates pass no `--policy` or `--socket` argument, so the processes use
[CLI defaults](./cli.md#paths-and-environment) within their service environment.

After upgrading the binary or moving dependencies, run `file-snitch doctor`.
It compares installed files and loaded service-manager configuration with the
current binary's render output. Reinstall if it reports stale definitions.

## Linux: systemd --user

Units are installed in `~/.config/systemd/user/`. Inspect status and logs with:

```bash
systemctl --user status file-snitch-run.service file-snitch-agent.service
journalctl --user -u file-snitch-run.service -u file-snitch-agent.service
```

Sources: [agent template](../packaging/systemd/file-snitch-agent.service.in),
[run template](../packaging/systemd/file-snitch-run.service.in).

## macOS: LaunchAgents

Plists are installed in `~/Library/LaunchAgents/`. Inspect them with:

```bash
launchctl print gui/$(id -u)/dev.file-snitch.agent
launchctl print gui/$(id -u)/dev.file-snitch.run
```

Logs are written to `~/.local/state/file-snitch/log/agent.log` and `run.log`.

Sources: [agent template](../packaging/launchd/dev.file-snitch.agent.plist.in),
[run template](../packaging/launchd/dev.file-snitch.run.plist.in).
