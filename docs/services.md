# User Service Examples

These are examples, not an installer.

They are meant to show how File Snitch can be run as a per-user background
service on:
- Linux with `systemd --user`
- macOS with `launchd`

Current caveat:
- the agent frontend is still `terminal-pinentry`
- so the examples below focus on the long-running `run` daemon
- if you want interactive prompt mode, you still need a usable local agent and
  terminal strategy

## Linux: systemd --user

Example unit:
- [packaging/systemd/file-snitch-run.service](../packaging/systemd/file-snitch-run.service)

Install it under:

```bash
mkdir -p ~/.config/systemd/user
cp packaging/systemd/file-snitch-run.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now file-snitch-run.service
```

Then inspect it with:

```bash
systemctl --user status file-snitch-run.service
journalctl --user -u file-snitch-run.service
```

## macOS: LaunchAgent

Example plist:
- [packaging/launchd/dev.file-snitch.run.plist](../packaging/launchd/dev.file-snitch.run.plist)

Install it under:

```bash
mkdir -p ~/Library/LaunchAgents
cp packaging/launchd/dev.file-snitch.run.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.file-snitch.run.plist
launchctl enable gui/$(id -u)/dev.file-snitch.run
launchctl kickstart -k gui/$(id -u)/dev.file-snitch.run
```

Then inspect it with:

```bash
launchctl print gui/$(id -u)/dev.file-snitch.run
```

## Notes

- Both examples assume `file-snitch` is already on `PATH`.
- Both examples assume the default policy path:
  `~/.config/file-snitch/policy.yml`
- Both examples run `file-snitch run allow --foreground` because the current
  terminal-only agent frontend is not yet a good unattended service story.
- When the agent story improves, these examples should be revisited rather than
  stretched with ad hoc TTY hacks.
