# Redaction Review

File Snitch now ships shareable artifacts:
- debug dossiers exported by `doctor`
- checked-in demo assets
- issue templates that ask users for environment details

That means accidental leakage is now a real maintenance risk.

## Review Surfaces

When changing user-facing diagnostics or recorded assets, review:
- `file-snitch doctor --export-debug-dossier`
- `docs/assets/demo.cast`
- `docs/assets/demo.gif`
- README snippets that show paths, environment variables, or commands
- issue templates under `.github/ISSUE_TEMPLATE/`

## What Must Never Leak

- real secret contents
- private key material
- real maintainer home-directory secret paths
- real GPG home paths
- real password-store contents

## Current Discipline

- demo assets must come from the disposable demo driver, not a real home dir
- debug dossiers must summarize state without dumping guarded file contents
- issue reporting should prefer dossiers over ad hoc environment dumps

## Mechanical Check

Run:

```bash
./scripts/check-demo-artifacts.sh
```

That script scans the checked-in demo artifacts for obvious leakage markers and
maintainer-specific path fragments.

It is not a complete proof. It is only a cheap tripwire.
