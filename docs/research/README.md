# Research and Design History

These notes record the questions, experiments, and proposals behind File
Snitch. They describe the implementation at the time of writing, and some
recommendations have been superseded. The [user guides](../index.md) describe
the current product.

| Note | Context |
| --- | --- |
| [Initial brief](./0%20-%20initial-brief.md) | Original product goals |
| [Linux spike language](./1%20-%20linux-spike-language.md) | Choice of Zig with a C FUSE shim |
| [Target app matrix](./2%20-%20target-app-matrix.md) | Observed application I/O from the research runs, not a current compatibility guarantee |
| [Phase 1 lessons](./3%20-%20phase-1-lessons-learned.md) | Guarded-root spike findings |
| [File enrollment architecture](./4%20-%20file-enrollment-architecture.md) | Parent-directory virtualization proposal; projection now uses state-directory files and symlinks |
| [Attribution](./5%20-%20attribution-notes.md) | Caller identity research |
| [Durable decision key](./6%20-%20durable-decision-key.md) | Proposed key; current persisted fields are in [policy](../policy.md#decisions) |
| [Mediated operations](./7%20-%20mediated-operation-set.md) | Scope recommendation; current coverage is in [CLI](../cli.md#authorization-scope) |
| [Prompt latency](./8%20-%20prompt-latency-and-timeouts.md) | Spike timing assumptions, including the superseded five-second timeout |
| [Future targets](./9%20-%20future-target-candidates.md) | Candidates for further application testing |
| [Mount planner](./10%20-%20mount-planner-strategy.md) | Superseded parent-mount planning strategy |
| [Completed milestones](./11%20-%20completed-milestones.md) | Earlier implementation phases |
| [Agent broker protocol](./12%20-%20agent-broker-protocol.md) | Protocol design, including future forwarding work |

Use the [changelog](../../CHANGELOG.md) for shipped changes and the
[backlog](../../BACKLOG.md) for planned work.
