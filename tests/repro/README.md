# Repro Scripts

These scripts are diagnostic tools for flaky smoke failures.

Use them when:

- a smoke test fails intermittently
- the failure looks like process teardown, signal handling, or harness
  interaction rather than a stable assertion bug
- you need a preserved fixture, `ps` output, or macOS `sample` output from the
  failing run

Do not use them as part of normal development or CI. The normal entrypoints are
the smoke tests in `tests/smoke/` and `./tests/build.sh`.

## Scripts

- `repro-enroll-exit.sh`
  Stress `file-snitch enroll` outside the smoke harness in `direct`,
  `capture`, and `wrapper` modes.

- `repro-run-exit.sh`
  Stress foreground `file-snitch run allow --foreground` teardown with the same
  `SIGINT -> SIGTERM -> SIGKILL` escalation the smoke harness uses.

- `repro-run-empty-policy-fixture.sh`
  Reproduce the `run-empty-policy` smoke path through `tests/smoke/lib/run-fixture.sh`
  while preserving the failing fixture for inspection.

## Workflow

1. Reproduce the flake with the normal smoke test if possible.
2. Pick the narrowest repro script that matches the suspected failure path.
3. Run it until it fails or gives confidence that the bug needs a different
   trigger.
4. Inspect the preserved fixture directory before rerunning anything else.

If these scripts stop being useful, delete them. They are debugging aids, not
part of the product surface.
