# User Services

File Snitch embeds its per-user service definitions in the binary:
- Linux with `systemd --user`
- macOS with `launchd`

Render the service files without installing them:

```bash
file-snitch services render \
  --bin "$(command -v file-snitch)" \
  --pass-bin "$(command -v pass)" \
  --output-dir ./out
```

Install the default service set for the current platform:

```bash
file-snitch services install \
  --bin "$(command -v file-snitch)" \
  --pass-bin "$(command -v pass)"
```

Remove them again:

```bash
file-snitch services uninstall
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
file-snitch services install \
  --platform linux \
  --bin "$(command -v file-snitch)" \
  --pass-bin "$(command -v pass)"
```

Then inspect it with:

```bash
file-snitch doctor
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
file-snitch services install \
  --platform macos \
  --bin "$(command -v file-snitch)" \
  --pass-bin "$(command -v pass)"
```

Then inspect it with:

```bash
file-snitch doctor
launchctl print gui/$(id -u)/dev.file-snitch.agent
launchctl print gui/$(id -u)/dev.file-snitch.run
```

## Notes

- The services command resolves and embeds an absolute `file-snitch` binary path.
- The services command resolves and embeds an absolute `pass` binary path into
  the run service so launchd/systemd do not depend on an interactive shell
  `PATH`.
- Both examples assume the default policy path:
  `~/.config/file-snitch/policy.yml`
- Rendered macOS plists log to `~/.local/state/file-snitch/log/`.
- The command installs per-user services only. It does not create a system
  daemon or root-owned service.
- `file-snitch doctor` compares installed service files and loaded service
  manager config against the render output from the current binary.
- Linux service installation expects `zenity` to be on `PATH` unless you set
  `FILE_SNITCH_ZENITY_BIN` in the service environment yourself.
