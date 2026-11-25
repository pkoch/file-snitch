# Scripts

`scripts/` is organized by operator intent rather than by language.

- [scripts/demo/](./demo/): demo recording and artifact checks
- [scripts/docs/](./docs/): documentation drift checks
- [scripts/release/](./release/): release-maintainer entrypoints and packaging helpers
- [scripts/vendor/](./vendor/): third-party SDK extraction helpers used by release builds

User-facing entrypoints:

- [./scripts/demo/demo-session.sh](./demo/demo-session.sh)
- [./scripts/demo/regenerate-demo-artifacts.sh](./demo/regenerate-demo-artifacts.sh)
- [./scripts/demo/check-demo-artifacts.sh](./demo/check-demo-artifacts.sh)
- [./scripts/docs/check-docs.sh](./docs/check-docs.sh)

Release-maintainer entrypoints:

- [./scripts/release/do-release.sh](./release/do-release.sh)
- [./scripts/release/build-release-artifact.sh](./release/build-release-artifact.sh)
- [./scripts/release/build-release-source-tarball.py](./release/build-release-source-tarball.py)
