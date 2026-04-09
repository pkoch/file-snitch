# Completed milestones

This note keeps high-level historical context that no longer belongs in
the forward-looking backlog.

## Phase 0: ground-truth research

Completed outputs:
- target-app matrix and real file-IO observations
- mediated-operation recommendation
- attribution notes for Linux and macOS
- prompt latency and timeout assumptions
- file-enrollment architecture recommendation
- durable decision key recommendation
- mount-planner strategy

Primary references:
- [2 - target-app-matrix.md](./2%20-%20target-app-matrix.md)
- [4 - file-enrollment-architecture.md](./4%20-%20file-enrollment-architecture.md)
- [5 - attribution-notes.md](./5%20-%20attribution-notes.md)
- [6 - durable-decision-key.md](./6%20-%20durable-decision-key.md)
- [7 - mediated-operation-set.md](./7%20-%20mediated-operation-set.md)
- [8 - prompt-latency-and-timeouts.md](./8%20-%20prompt-latency-and-timeouts.md)
- [10 - mount-planner-strategy.md](./10%20-%20mount-planner-strategy.md)

## Phase 1: guarded-root spike

Completed outputs:
- Zig core plus thin C `libfuse` shim
- dry-run inspection path and one-level guarded-root filesystem
- audit trail and policy engine
- prompt allow/deny/timeout behavior
- live Linux and macOS verification of the guarded-root spike

This phase is no longer the product direction, but it is still the origin
of the current FUSE core and shim boundary.

## Phase 1.5: policy-driven file-enrollment pivot

Completed outputs:
- `policy.yml` as the durable source of truth
- product-facing CLI verbs:
  - `run`
  - `enroll`
  - `unenroll`
  - `status`
  - `doctor`
- exact-file enrollment with parent-directory projection
- nested guarded paths and multiple planned mounts
- store-backed custody using `pass`
- policy reconciliation in both foreground and daemon mode
- policy-driven smoke coverage

This is the active product foundation. Remaining work now lives in the
forward-looking backlog.
