# Prompt Latency And Timeout Assumptions

## Question

What prompt latency and timeout assumptions are acceptable for the current
spike?

This note does **not** claim a universal maximum safe latency for all tools.
The current evidence is enough to define a v1 assumption envelope, not to
publish a broad performance guarantee.

## Current implementation facts

The CLI prompt broker currently behaves as follows:

- prompts are serialized behind a mutex
- the broker prints structured JSON before and after each prompt
- blank terminal input resolves to allow
- EOF resolves to allow
- timeout resolves to deny
- the default timeout is `5_000 ms`
- the timeout can be overridden with `FILE_SNITCH_PROMPT_TIMEOUT_MS`

Sources:
- [src/prompt.zig](/Users/pkoch/github.com/pkoch/file-snitch/src/prompt.zig)
- [README.md](/Users/pkoch/github.com/pkoch/file-snitch/README.md)

## What the current tests actually prove

The current prompt smoke test uses:

- `FILE_SNITCH_PROMPT_TIMEOUT_MS=200`

and verifies:

- allow once
- explicit deny
- timeout

against simple mounted-file shell flows on macOS.

That means the repo currently demonstrates:

- a `200 ms` timeout is enough to exercise the prompt machinery in automated
  shell-oriented smoke tests
- a `5 s` default timeout is an operator choice for manual use, not a measured
  requirement from the target tools

It does **not** prove:

- that `200 ms` is sufficient for real human interaction
- that `5 s` is safe for all target apps
- that CLI prompting is acceptable for editor-heavy or GUI-heavy workflows

## Current evidence from live use

The current manual and smoke-tested behavior supports these narrower claims:

- simple shell flows can tolerate prompting at `open` and `create`
- queued prompt requests must be serialized to avoid clobber and ambiguity
- default-deny on timeout is the safer failure mode when no explicit human
  response arrives
- editor workflows are much more latency-sensitive and behavior-sensitive than
  shell flows

That last point matters more than the exact millisecond value.
The project already learned that editor probe and save behavior is its own
problem, and Phase 1 is intentionally not claiming that the terminal broker is
editor-friendly.

## Recommendation

Treat the current latency story as:

### 1. Shell-safe, not universally app-safe

The CLI broker is acceptable for:

- manual shell access
- smoke testing
- simple CLI experimentation

It should **not** be treated as validated for:

- editors
- helper-heavy GUI workflows
- any path where a delayed terminal response would make the app feel broken

### 2. Keep default timeout deny

Timeout should continue to resolve to deny.

Reason:

- it preserves the guardrail that prompts must prevent behavior before side
  effects
- it avoids silent access when the broker is unattended
- it matches the project’s broader “default deny on uncertainty” rule

### 3. Keep the current `5 s` default as an operator convenience, not a product promise

The current `5 s` default is reasonable for the CLI broker because:

- it gives a human enough time to answer in manual testing
- it is short enough that unattended prompts fail closed

But it should be described as a **current default**, not as a researched
minimum viable latency bound.

### 4. Keep test timeouts short and explicit

Smoke tests should continue to use a much shorter timeout than the interactive
default.

Reason:

- tests are proving correctness of timeout handling, not human usability
- shorter test timeouts make failures faster and clearer

## Current v1 assumption

The v1 assumption should be:

- the terminal prompt broker is a development and shell-oriented control path
- prompt latency is acceptable only for simple manual flows
- default timeout deny is required
- broader UX claims about acceptable prompt latency are deferred until the GUI
  broker phase

## What this means for future work

The next latency-sensitive milestone is not “pick a better CLI timeout.”
It is:

- build the GUI prompt broker
- validate whether real target tools remain usable when prompts appear during
  normal operation

That work should answer the stronger version of the original research
question:

- what prompt latency is acceptable for real secret-bearing tools in normal use

The current spike is not trying to answer that yet.
