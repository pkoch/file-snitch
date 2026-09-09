# Documentation

New to File Snitch? The [project README](../README.md) explains what it does.
Read the [threat model](./threat-model.md), then try the
[disposable demo](./demo.md) or follow the [install guide](./install.md).

## Using File Snitch

| Guide | Use it to |
| --- | --- |
| [Install](./install.md) | Set up dependencies and enroll your first file |
| [Demo](./demo.md) | Try a fake store or record the walkthrough |
| [CLI reference](./cli.md) | Look up commands, defaults, and environment variables |
| [Policy](./policy.md) | Inspect or edit enrollments and remembered decisions |
| [User services](./services.md) | Install and inspect services that run at login |
| [Operations](./operations.md) | Diagnose problems and recover enrolled files |
| [Threat model](./threat-model.md) | Understand what the daemon can mediate |

## Contributing

- [Development](./development.md): environment setup, source layout, and checks
- [Contributing](../CONTRIBUTING.md): scope, memory ownership, and review conventions
- [Error handling](./error-handling.md): propagation, errno boundaries, and rollback
- [Redaction review](./redaction-review.md): diagnostic and recording checks
- [Releasing](./releasing.md): artifacts, provenance, and the tap release flow
- [Backlog](../BACKLOG.md): planned work
- [Changelog](../CHANGELOG.md): shipped changes

## Design history

The [research notes](./research/README.md) record experiments and proposals,
including designs that have since changed. Use the guides above for current
behavior.
