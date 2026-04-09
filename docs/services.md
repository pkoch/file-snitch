# User Services

File Snitch now has real per-user service install helpers:
- Linux with `systemd --user`
- macOS with `launchd`

Render the service files without installing them:

```bash
./scripts/render-user-services.sh --bin "$(command -v file-snitch)" --output-dir ./out
```

Install the default service set for the current platform:

```bash
./scripts/install-user-services.sh --bin "$(command -v file-snitch)"
```

Remove them again:

```bash
./scripts/uninstall-user-services.sh
```

Current platform stance:
- macOS installs two LaunchAgents:
  - `dev.file-snitch.agent`
  - `dev.file-snitch.run`
- Linux installs two `systemd --user` units:
  - `file-snitch-agent.service`
  - `file-snitch-run.service`
- Linux uses the `linux-ui` frontend and therefore expects `zenity` to be
  available.

## Linux: systemd --user

Templates:
- [packaging/systemd/file-snitch-agent.service.in](../packaging/systemd/file-snitch-agent.service.in)
- [packaging/systemd/file-snitch-run.service.in](../packaging/systemd/file-snitch-run.service.in)

Install it with:

```bash
./scripts/install-user-services.sh --platform linux --bin "$(command -v file-snitch)"
```

Then inspect it with:

```bash
systemctl --user status file-snitch-run.service
systemctl --user status file-snitch-agent.service
journalctl --user -u file-snitch-run.service
journalctl --user -u file-snitch-agent.service
```

## macOS: LaunchAgent

Templates:
- [packaging/launchd/dev.file-snitch.agent.plist.in](../packaging/launchd/dev.file-snitch.agent.plist.in)
- [packaging/launchd/dev.file-snitch.run.plist.in](../packaging/launchd/dev.file-snitch.run.plist.in)

Install them with:

```bash
./scripts/install-user-services.sh --platform macos --bin "$(command -v file-snitch)"
```

Then inspect it with:

```bash
launchctl print gui/$(id -u)/dev.file-snitch.agent
launchctl print gui/$(id -u)/dev.file-snitch.run
```

## Notes

- The install helper resolves and embeds an absolute `file-snitch` binary path.
- Both examples assume the default policy path:
  `~/.config/file-snitch/policy.yml`
- Rendered macOS plists log to `~/.local/state/file-snitch/log/`.
- The helper installs per-user services only. It does not create a system
  daemon or root-owned service.
- Linux service installation expects `zenity` to be on `PATH` unless you set
  `FILE_SNITCH_ZENITY_BIN` in the service environment yourself.
