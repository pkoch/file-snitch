# Redaction Review

Review diagnostic and recording changes for information that should not appear
in public reports or checked-in assets.

## Debug dossiers

`doctor --export-debug-dossier` includes versions, enrollment paths, object IDs,
remembered decisions, and doctor output. It omits guarded contents and replaces
the home-directory prefix with `~`; it does not anonymize every path or piece of
metadata. Keep that distinction clear in issue templates and user guidance.

When changing diagnostics, ensure they do not print secret contents, private
keys, or store payloads. Check the exported dossier as well as terminal output.
Run `./tests/smoke/doctor-debug-dossier.sh` to verify the existing fixture's
content and path-redaction assertions.

## Demo assets

Generate recordings with the [disposable demo driver](./demo.md). Use sample
paths and data in README snippets and issue-template examples. Check for real
home-directory paths, GPG keyring paths, private keys, or password-store contents.

```bash
./scripts/demo/check-demo-artifacts.sh
```

This scans `demo.cast` and strings from `demo.gif` for known leakage markers and
maintainer path fragments. It does not inspect every rendered GIF frame or
prove that a recording is current. Watch the result before committing it.
