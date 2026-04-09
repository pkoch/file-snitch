# Agent Broker Protocol

This note proposes the first real broker protocol for file-snitch.

The goal is to replace the current local TTY prompt path with an
agent-style broker that:

- accepts authorization requests from one or more `file-snitch run`
  requesters
- can be forwarded over remote sessions
- is easy to inspect and debug by humans
- leaves room for richer local and GUI agents later

## Deployment stance

V1 assumes a single-user deployment model:

- one user-owned requester family
- one user-owned local agent
- one user-owned local socket
- no system-wide authority
- no cross-user arbitration
- no TCP-facing broker

The local transport should be a Unix domain socket under the user's
runtime directory, for example under `XDG_RUNTIME_DIR`.

Forwarding is still in scope, but only as user-to-user forwarding of the
same stream protocol back to the workstation where that same user is
active.

## Design goals

- Forwardable over a byte stream, like `ssh-agent` and `gpg-agent`
- Transport-neutral: Unix socket first, forwarded stream later
- Human-readable on the wire after framing
- Explicit subject and request metadata, more like polkit than a raw
  “sign this blob” agent
- Small core with an explicit extension mechanism
- Cancellation support for abandoned or stale prompts
- RFC3339 UTC timestamps only

## Non-goals

- This is not a generic RPC system.
- This is not a D-Bus API.
- This is not a UI protocol.
- This does not define remote forwarding transport yet; it only defines
  a stream protocol that forwarding can carry unchanged.
- This is not a shared multi-user policy service.

## Inspirations

### SSH agent

From the SSH agent protocol, keep:

- explicit framing over a byte stream
- requester-driven request/response flow
- ordered replies
- small mandatory core
- explicit extension discovery and extension namespaced by domain

Do not copy:

- numeric-only message typing
- binary-only payloads
- key-specific semantics baked into the base protocol

### GPG agent / Assuan

From Assuan, keep:

- text-oriented debuggability
- explicit extensibility
- cancellation-friendly request model
- the idea that agents and requesters should be easy to test directly over a
  socket

Do not copy:

- line-oriented command grammar
- separate status/inquire subprotocols
- escaping rules that make arbitrary structured payloads awkward

### polkit

From polkit, keep:

- explicit subject description
- explicit action and detail dictionaries
- clear distinction between:
  - authorized
  - not authorized
  - challenge possible but unavailable
  - dismissed / cancelled
- temporary authorization concepts and opaque IDs

Do not copy:

- D-Bus dependency
- desktop-session assumptions
- authority/agent split that depends on system-bus identities

## Chosen wire format

The protocol uses:

- a stream transport
- ASCII length framing inspired by netstrings
- one UTF-8 JSON object per framed payload

Each message is:

```text
ascii_decimal_length ":" utf8_json "\n"
```

Why this shape:

- it keeps the stream-safety benefits of explicit framing
- JSON is the right part of the Assuan/polkit model
- forwarding over SSH or another stream transport does not require
  translation
- packet boundaries are explicit and terminal-friendly
- messages are still readable in logs, fixtures, `socat`, and ad hoc
  transcript captures

This is intentionally not NDJSON. Stream forwarding and partial reads are
still easier with explicit framing.

This is intentionally not a raw binary length prefix. ASCII framing keeps
the transport parseable by simple tools and tolerable to inspect in a
terminal.

This is also intentionally not literal netstrings. The terminating byte is
newline, not comma, because transcript readability matters more here than
strict netstring compatibility.

### Framing rules

The framing grammar is:

```text
message = length ":" payload "\n"
length  = "0" | (nonzero_digit *digit)
payload = utf8_json_object_exactly_length_bytes
```

Canonical v1 rules:

- `length` is ASCII decimal
- no leading zeros are allowed unless the value is exactly `0`
- the length field must be at most 6 digits
- the parsed payload length must be at most `999999`
- the payload must be exactly `length` bytes
- the payload must decode as UTF-8
- the payload must decode to exactly one JSON object
- top-level arrays, strings, numbers, booleans, and null are invalid
- nested framed protocol messages inside the payload are forbidden by the
  protocol grammar

The agent and requester must reject non-canonical length encodings.

## Protocol versioning

Each message has:

- `protocol`: protocol name
- `version`: protocol compatibility string
- `type`: message type

For v1:

```json
{
  "protocol": "file-snitch-agent",
  "version": "1.0",
  "type": "..."
}
```

`version` is not SemVer.

It is exactly:

```text
compat "." feature
```

Where:

- `compat`
  - bumps on incompatible protocol changes
  - resets `feature` to `0`
- `feature`
  - bumps on backward-compatible protocol expansion

Negotiation rule:

- peers must match on `compat`
- the effective session feature level is the lower of the two `feature`
  values
- optional behavior should still be advertised with capabilities
- capabilities gate optional behavior; they do not replace version
  negotiation

Examples:

- `"1.0"`
- `"1.3"`
- `"2.0"`

Invalid examples:

- `"1"`
- `"1.0.0"`
- `"v1.0"`
- `"1.0-beta1"`

Versioning rules:

- incompatible wire changes require `compat` bump
- compatible built-in protocol growth uses `feature` bump
- optional behavior may still use capabilities and extensions

## Message model

All messages are JSON objects.

Common fields:

- `protocol`: always `"file-snitch-agent"`
- `version`: always `"1.0"` for this note
- `type`: message type string
- `request_id`: required on request/response/cancel flows

Message type names in the core protocol are plain strings like
`"hello"` or `"decide"`.

Extension message types and capability names must use DNS-style
namespacing, for example:

- `file-snitch.dev/query-ui-state`
- `example.com/custom-rule-editor`

Unknown extension messages must fail cleanly without tearing down the
connection.

## Roles

There are two protocol roles:

- `requester`
  - a `file-snitch run` daemon or helper acting on behalf of a daemon
- `agent`
  - the local agent-style authorization process

In v1, both roles are assumed to belong to the same local user account.

The requester initiates all requests.
The agent sends only:

- direct responses
- optional event messages for a request already in flight

One connection may carry multiple in-flight requests, distinguished by
`request_id`.

The first implementation may still process requests serially inside the
agent, but the protocol does not require one-request-per-connection.

## Session setup

The agent must begin with `hello` immediately after the connection is
established.

This handshake is mandatory on every connection. There is no fast path
that skips version or capability exchange.

### `hello`

```json
{
  "protocol": "file-snitch-agent",
  "version": "1.0",
  "type": "hello",
  "request_id": "01HXYZ...",
  "role": "agent",
  "agent_name": "file-snitch-agent",
  "agent_version": "0.1.0",
  "capabilities": [
    "decide",
    "cancel",
    "query"
  ]
}
```

### `welcome`

```json
{
  "protocol": "file-snitch-agent",
  "version": "1.0",
  "type": "welcome",
  "request_id": "01HXYZ...",
  "role": "requester",
  "requester_name": "file-snitch-run",
  "requester_version": "0.1.0",
  "capabilities": [
    "decide",
    "cancel",
    "query",
    "remember-temporary",
    "remember-durable"
  ]
}
```

After `welcome`, normal requester-driven requests may begin.

If the requester cannot speak the agent's `compat` version, it must reply
with `error` and close the connection.

## Core request flow

### `decide`

This is the main authorization request from a requester to an agent.

```json
{
  "protocol": "file-snitch-agent",
  "version": "1.0",
  "type": "decide",
  "request_id": "01HXYZ...",
  "subject": {
    "uid": 1000,
    "pid": 4242,
    "executable_path": "/usr/bin/kubectl"
  },
  "request": {
    "enrolled_path": "/home/pkoch/.kube/config",
    "approval_class": "read_like",
    "operation": "open",
    "mode": "read"
  },
  "policy_context": {
    "default_timeout": "2026-04-09T12:00:05Z",
    "can_remember": true
  },
  "forwarding": {
    "origin_host": "bolota",
    "origin_transport": "ssh",
    "forwarded": true
  },
  "details": {
    "display_path": "~/.kube/config"
  }
}
```

Required semantics:

- `subject.uid` and `subject.executable_path` are the minimum stable
  identity inputs for decision lookup, even though v1 assumes a
  single-user local deployment
- `request.enrolled_path` must be the canonical enrolled path
- `approval_class` is one of:
  - `read_like`
  - `write_capable`
- `operation` is a closed enum string in v1, not a free-form field
  - initial values:
    - `open`
    - `create`
    - `rename`
    - `unlink`
    - `metadata`
  - it is still not part of the durable decision key
- `mode` is a closed enum string in v1
  - initial values:
    - `read`
    - `write`
    - `read_write`
    - `metadata`
- `default_timeout` is an absolute RFC3339 UTC timestamp, not a relative
  number

The requester is authoritative for timeout behavior:

- the requester supplies the timeout deadline
- the agent may answer earlier with `timeout`
- the requester must still treat a missing answer past the deadline as a
  deny-like timeout

### `decision`

The agent replies with exactly one final `decision`.

```json
{
  "protocol": "file-snitch-agent",
  "version": "1.0",
  "type": "decision",
  "request_id": "01HXYZ...",
  "outcome": "allow",
  "reason": "user-approved",
  "remember": {
    "kind": "temporary",
    "expires_at": "2026-04-09T12:05:00Z"
  }
}
```

`outcome` values:

- `allow`
- `deny`
- `dismissed`
- `timeout`
- `unavailable`
- `cancelled`

Rules:

- the agent must always return one of these explicit outcomes
- `unavailable` means the agent could not or would not present the
  request, not that the user denied it
- `dismissed` means the user explicitly dismissed the interaction
- `timeout` means no answer was received before the deadline
- the requester maps all non-`allow` outcomes to deny-at-operation-time

`remember.kind` values:

- `none`
- `once`
- `temporary`
- `durable`

If omitted, the effective meaning is `none`.

For `temporary` and `durable`, `expires_at` is optional:

- omitted means no expiry
- present means RFC3339 UTC

`remember.kind = "once"` is runtime-only and must not be written to the
 durable policy file.

The agent does not mutate durable policy directly.

- the agent returns decision intent
- the requester remains responsible for writing and pruning durable
  policy

### `cancel`

The requester may cancel an in-flight request.

```json
{
  "protocol": "file-snitch-agent",
  "version": "1.0",
  "type": "cancel",
  "request_id": "01HXYZ..."
}
```

The agent should stop any UI flow associated with that request and
return:

```json
{
  "protocol": "file-snitch-agent",
  "version": "1.0",
  "type": "decision",
  "request_id": "01HXYZ...",
  "outcome": "cancelled",
  "reason": "requester-cancelled"
}
```

Cancellation and disconnect rules:

- if `cancel` arrives after a final `decision`, it is ignored
- if the requester disconnects, the agent should cancel all in-flight
  requests from that connection
- if the agent disconnects or restarts before a final `decision`, the
  requester must treat that as `unavailable` and deny the underlying
  operation

## Optional progress events

V1 includes progress `event` frames.

The agent may emit event messages before the final `decision`.

Example:

```json
{
  "protocol": "file-snitch-agent",
  "version": "1.0",
  "type": "event",
  "request_id": "01HXYZ...",
  "event": "prompt-presented"
}
```

Initial event names:

- `prompt-presented`
- `prompt-dismissed`
- `forwarded`

These are informational only. Clients must not require them for
correctness.

## Request IDs

Request IDs are requester-generated ULID strings in v1.

Why:

- the requester already owns the work item
- cancellation is simpler if the requester chooses the ID
- forwarded transports can preserve IDs unchanged
- ULIDs are sortable, log-friendly, and easy to generate

The agent must treat `request_id` as opaque.

## Query and extension discovery

Like `ssh-agent`, the agent should have a small core and explicit
extension discovery.

### `query`

```json
{
  "protocol": "file-snitch-agent",
  "version": "1.0",
  "type": "query",
  "request_id": "01HXYZ..."
}
```

### `query_result`

```json
{
  "protocol": "file-snitch-agent",
  "version": "1.0",
  "type": "query_result",
  "request_id": "01HXYZ...",
  "capabilities": [
    "decide",
    "cancel",
    "query",
    "remember-temporary",
    "remember-durable",
    "file-snitch.dev/forwarding"
  ]
}
```

Unknown extensions must fail with:

```json
{
  "protocol": "file-snitch-agent",
  "version": "1.0",
  "type": "error",
  "request_id": "01HXYZ...",
  "code": "unsupported-extension",
  "message": "extension not supported"
}
```

This is intentionally separate from generic failure to preserve the
`ssh-agent` distinction between “extension unsupported” and “operation
failed”.

## Socket and transport expectations

For the local agent:

- the socket should live under the user's runtime directory
- the containing directory should be user-owned
- the socket should not be exposed over TCP
- stale socket cleanup is the agent's responsibility at startup

The protocol assumes a user-owned local IPC endpoint, not a shared
system service endpoint.

## Subject model

The base protocol uses a Unix-process subject.

```json
{
  "uid": 1000,
  "pid": 4242,
  "executable_path": "/usr/bin/ssh"
}
```

In v1, this subject is not meant to model competing local principals. It
exists to describe which of the user's own processes is requesting
access, and to support durable decisions keyed by executable path and
user ID.

Future versions may add:

- signer identity on macOS
- Linux pidfd/start-time style anti-race details
- remote peer metadata from a forwarded transport

For v1, the durable decision key stays:

```text
(executable_path, uid, canonical_enrolled_path, approval_class)
```

The protocol may carry more subject detail than the durable decision key
uses.

## Forwarding model

Forwarding is a transport property, not a protocol fork.

The same netstring-framed JSON stream should work over:

- local Unix sockets
- SSH stream forwarding
- future relay transports

Forwarded requests should keep explicit origin metadata:

```json
{
  "forwarding": {
    "origin_host": "bolota",
    "origin_transport": "ssh",
    "forwarded": true
  }
}
```

The agent must treat forwarding metadata as informational unless the
transport layer authenticates it.

That matches the `ssh-agent` lesson: forwarded-agent semantics are only
as strong as the forwarding path.

In v1, forwarding is still user-to-user. It is not a mechanism for one
local user to request decisions from another local user on the same
machine.

## Errors

All protocol-level failures use `error`.

```json
{
  "protocol": "file-snitch-agent",
  "version": "1.0",
  "type": "error",
  "request_id": "01HXYZ...",
  "code": "invalid-request",
  "message": "subject.uid is required"
}
```

Initial error codes:

- `unsupported-version`
- `invalid-request`
- `unsupported-message-type`
- `unsupported-extension`
- `internal-error`

If a request is syntactically valid but the final answer is deny-like,
the agent should still return `decision`, not `error`.

## Why not Assuan

Assuan is a good model for debuggable agent IPC, but file-snitch wants
structured request payloads, nested detail maps, and direct forwarding of
opaque request metadata. JSON fits that better than a line grammar plus
escaping and inquire subflows.

So the protocol keeps the Assuan spirit, not the Assuan syntax.

## Why not D-Bus

polkit’s subject/result model is useful, but D-Bus is the wrong lowest
common denominator for:

- remote forwarding
- SSH-friendly transport
- small standalone agents
- test fixtures and transcript-driven debugging

The agent should be able to speak over a raw forwarded socket.

## Recommended first implementation

Start with:

- one Unix domain socket under the user's runtime directory
- one agent process
- `hello`
- `query`
- `decide`
- `cancel`
- `decision`
- `error`

And one requester role:

- `file-snitch run ... prompt`

That keeps the implementation small while locking in the right boundary.

## References

- OpenSSH specifications:
  https://www.openssh.org/specs.html
- SSH agent protocol draft:
  https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04
- GnuPG agent protocol:
  https://www.gnupg.org/documentation/manuals/gnupg/Agent-Protocol.html
- Assuan design notes:
  https://www.gnupg.org/documentation/manuals/assuan/Assuan.html
- polkit authority interface:
  https://polkit.pages.freedesktop.org/polkit/eggdbus-interface-org.freedesktop.PolicyKit1.Authority.html
- pkcheck manual:
  https://polkit.pages.freedesktop.org/polkit/pkcheck.1.html
