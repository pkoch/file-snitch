# Scripts

`scripts/` is organized by operator intent rather than by language.

- `scripts/demo/`: demo recording and artifact checks
- `scripts/release/`: release-maintainer entrypoints and packaging helpers
- `scripts/services/`: per-user service rendering and install helpers
- `scripts/vendor/`: third-party SDK extraction helpers used by release builds

User-facing entrypoints:

- `./scripts/demo/demo-session.sh`
- `./scripts/demo/regenerate-demo-artifacts.sh`
- `./scripts/demo/check-demo-artifacts.sh`
- `./scripts/services/install-user-services.sh`
- `./scripts/services/uninstall-user-services.sh`
- `./scripts/services/render-user-services.sh`

Release-maintainer entrypoints:

- `./scripts/release/do-release.sh`
- `./scripts/release/build-release-artifact.sh`
- `./scripts/release/build-release-source-tarball.py`
