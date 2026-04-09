# Releasing

This repo is still early and `HEAD`-oriented, but release hygiene still
matters.

## Before A Release Or Packaging Refresh

Run:

```bash
zig build
zig build test
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

## Refresh Public Artifacts

Regenerate the demo embed:

```bash
./scripts/regenerate-demo-artifacts.sh
```

That updates:
- `docs/assets/demo.cast`
- `docs/assets/demo.gif`

If the demo changed materially, make sure:
- `README.md` still describes it honestly
- `docs/demo.md` still describes how to regenerate it

## Packaging Checks

Current packaging is centered on:
- `Formula/file-snitch.rb`
- `docs/install.md`

Before publishing packaging-related changes:
- make sure the install docs still match reality
- avoid implying FUSE is installed by the formula
- avoid implying the current terminal agent frontend is already the final UX

## Release Notes Discipline

Even before formal tagged releases, keep public-facing changes easy to
understand:
- mention new commands or flags
- mention behavior changes that affect operators
- mention packaging or prerequisite changes
- mention new required tools for regenerating artifacts

If a change is only internal cleanup, say so plainly.
