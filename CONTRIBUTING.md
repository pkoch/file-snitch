# Contributing

## Before You Change Code

- read [README.md](./README.md)
- read [docs/threat-model.md](./docs/threat-model.md)
- read [docs/operations.md](./docs/operations.md)

This project is intentionally:
- single-user
- user-space
- exact-file oriented
- not a system security framework

Changes that pull it toward system-wide policy or multi-user arbitration should
be treated skeptically.

## Development Loop

Build:

```bash
zig build
```

Run the Zig test roots:

```bash
zig build test
```

CI also enforces a small hygiene layer:

```bash
bash -n $(find scripts tests/smoke -type f \( -name '*.sh' -o -path 'tests/smoke/lib/*' \) | sort)
./scripts/check-demo-artifacts.sh
```

Run the smoke suite:

```bash
./tests/smoke/run-empty-policy.sh
./tests/smoke/policy-lifecycle.sh
./tests/smoke/doctor-debug-dossier.sh
./tests/smoke/run-policy-reload.sh
./tests/smoke/run-daemon-policy-reload.sh
./tests/smoke/run-expired-decision-cleanup.sh
./tests/smoke/run-single-enrollment.sh
./tests/smoke/run-multi-mount.sh
./tests/smoke/run-prompt-single.sh
```

Refresh `compile_commands.json` when needed:

```bash
zig build compile-commands
```

## Demo Artifacts

The README embed is not hand-made. Regenerate it with:

```bash
./scripts/regenerate-demo-artifacts.sh
```

And then sanity-check it for obvious leakage:

```bash
./scripts/check-demo-artifacts.sh
```

That expects:
- `zig`
- `asciinema`
- `agg`
- `tmux`

## Reporting And Reproducing Problems

Before filing a bug, prefer exporting a dossier:

```bash
file-snitch doctor --export-debug-dossier ./file-snitch-debug-dossier.md
```

Use the templates in `.github/ISSUE_TEMPLATE/`.

## Commit Discipline

- keep commits small and isolated
- do not mix feature work with broad cleanup
- update docs when the user-facing behavior changes
- do not leave old compatibility shims behind unless they are explicitly needed

## Packaging Reality

The current packaging story is still `HEAD`-shaped:
- Homebrew/Linuxbrew formula in `Formula/`
- FUSE remains an external system prerequisite
- `pass` is the only guarded-object backend today

Do not document or imply a stronger packaging story than the repo actually
provides.
