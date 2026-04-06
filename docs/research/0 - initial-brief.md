# File Snitch: guarded FUSE mounts for secret files

## Mission

Research and build a cross-platform developer tool that protects secret-bearing app files by mediating file opens at the filesystem layer.

Target user story:
- Developer installs random tools or AI harnesses.
- Those tools insist on storing API keys/tokens in plain files under predictable paths.
- User wants "Little Snitch for file opens": when a process tries to open a protected file, prompt the user and allow/deny that specific access.
- The solution must use guarded FUSE mounts.
- Explicitly out of scope: fanotify, Endpoint Security, "just use a vault", and simple lock/unlock volume schemes.

## Product thesis

The product should mount a virtual filesystem at the exact paths where apps expect to read/write their secret-bearing files.
Examples:
- ~/.config/opencode/
- ~/.config/block-goose/
- ~/.config/pi.dev/
- ~/.openrouter/
- arbitrary user-defined paths

The mounted filesystem:
- stores data encrypted in a backing store
- intercepts file operations in userspace
- prompts on sensitive opens
- caches decisions briefly
- decrypts only for approved file handles
- re-encrypts on write/flush/close

## Core technical hypothesis

Use a custom FUSE filesystem on both Linux and macOS.

Why this is plausible:
- libfuse exposes the operations needed for file mediation: open/create/read/write/rename/release/getattr/etc.
- libfuse exposes caller context with uid/gid/pid through fuse_get_context()
- macFUSE supports libfuse APIs on macOS, so a shared codebase is realistic

References to rely on:
- libfuse operations surface
- fuse_get_context()
- macFUSE support for libfuse2/libfuse3

## Non-goals

- Preventing exfiltration after the user approves the wrong process
- General endpoint malware prevention
- Network policy / egress control
- Perfect binary attestation
- Mandatory access control integration in v1
- Multi-user enterprise administration

## Threat model

Protect against:
- opportunistic secret vacuuming from well-known file paths
- compromised dev tools scanning home directories for tokens
- generic malware that reads dormant files but is not yet approved to open them

Do not claim to protect against:
- a process the user explicitly approved
- screen scraping / keylogging / TCC-abusing malware
- root compromise
- memory scraping after decryption in the approved process

## UX model

Inspiration:
- Little Snitch-style decision prompts
- clear per-access decision: allow once / allow for N minutes / deny once / always deny / always allow for this rule
- rule display should identify:
  - executable path
  - process name
  - parent process if available
  - target file path
  - access mode (read / write / create / rename / delete)
  - code-signing identity when available
  - content fingerprint of the executable where practical

Important: do not try to make the prompt overly smart in v1.
The real value is reliable mediation, not fancy attribution.

## Architecture

### 1. Filesystem daemon
Responsibilities:
- mount guarded files (maybe we need to support directories for programs that write temporary files and rename to final name)
- map virtual paths to encrypted backing objects
- enforce open/create/write/rename policy
- maintain short-lived approval cache
- perform crypto
- emit structured audit logs

### 2. Policy engine
Rule inputs:
- executable path
- pid
- uid
- target path
- requested mode
- time
- optional signer identity
- optional executable hash

Rule outputs:
- allow
- deny
- prompt

v1 rule key:
- (normalized executable path, target path prefix, access class)

### 3. Prompt broker
Responsibilities:
- receive access requests from daemon
- show user prompt
- return decision synchronously or near-synchronously
- persist rules

Need timeout semantics:
- no answer => deny by default

### 4. Backing store
Use encrypted objects, not plaintext mirror files.

Possible shape:
- one encrypted blob per file
- metadata database for path tree, mode bits, timestamps, inode-ish IDs
- atomic temp + rename semantics supported

### 5. Audit log
Every mediated access should be logged with:
- timestamp
- decision
- caller identity
- target
- access mode
- whether rule or interactive decision
- duration of approval if temporary

## Platform strategy

### Linux
Use libfuse3 first.
Primary implementation language should be Rust or Zig only if the FUSE bindings are mature enough; otherwise prefer C for the spike and switch later only if justified.

Need to verify:
- reliable caller PID from fuse_get_context()
- behavior around editors writing temp files + rename
- access patterns of common CLI tools
- mount behavior in home directories
- performance under small-file churn

### macOS
Use macFUSE with the libfuse-compatible path first.
Keep the UI/prompt broker separate from the filesystem daemon.

Need to verify:
- how good caller PID/process attribution is in practice
- signing identity lookup flow for caller executables
- UX around Full Disk Access, TCC, and install friction
- mount stability across sleep/wake and login/logout

## Critical research questions

1. Can we get robust enough caller attribution for policy decisions on both OSes?
2. Should v1 mediate only `open`, or also `create`, `rename`, `unlink`, `truncate`, and directory ops?
3. How do common secret-writing apps actually write files?
   - direct write
   - temp file + rename
   - chmod/chown after create
4. What approval cache key is safe enough?
5. Should the backing store expose real filenames or opaque IDs?
6. How to avoid corruption on crash/power loss?
7. What is the minimum viable prompt latency before apps start breaking?
8. Should reads and writes have separate approval classes?
9. Do we need path-based protected trees only, or per-file enrollment too?
10. How much policy state can be shared across Linux and macOS?

## Build phases

### Phase 0: ground truth research
Deliverable:
- short report on file IO patterns for 10 target apps/tools
- matrix of write patterns:
  - file path
  - open flags
  - temp+rename?
  - file permissions
  - lock usage
- recommendation for exact scope of v1 operations

### Phase 1: Linux spike
Build:
- single guarded directory
- in-memory policy engine
- CLI prompt only
- plaintext backing store temporarily allowed for spike only
- support: getattr, readdir, open, create, read, write, flush, fsync, release, rename, unlink, mkdir, rmdir, truncate

Success criteria:
- can guard one config file or directory
- prompt appears on first read or write
- deny blocks the app cleanly
- allow-once works
- temp file + rename flows still work for target apps

### Phase 2: encryption layer
Build:
- per-file encryption
- authenticated metadata
- crash-safe writes
- key derivation from a user passphrase or OS key store bootstrap

Success criteria:
- backing store remains ciphertext at rest
- no plaintext mirror remains outside controlled temporary memory/buffers

### Phase 3: GUI prompt broker
Build:
- desktop prompt
- rule editor
- recent events feed
- allow once / deny once / allow 5 min / always allow / always deny

Success criteria:
- prompt latency acceptable
- daemon survives UI restart
- no deadlock if UI unavailable; default deny

### Phase 4: macOS port
Build:
- same rule model
- same backing-store format if possible
- minimal native integration for prompting and signer lookup

Success criteria:
- same guarded-directory demo works on macOS
- at least 3 real target apps behave correctly

### Phase 5: packaging and polish
Build:
- installer (target homebrew for both linux and macos)
- mount persistence
- config import/export
- debug bundle generation
- docs and threat-model page

## Engineering rules

- Favor correctness over performance in v1
- Default deny on uncertainty
- Never leak plaintext to conventional temp dirs
- Treat rename as first-class, not an afterthought
- Separate mediation logic from crypto logic
- Structured logging in JSON everywhere
- Keep the prompt broker optional so headless testing remains possible

## Minimum viable prototype

A working MVP is:
- one guarded file/directory
- one target app path
- prompt on first open for read or write
- encrypted backing store
- allow-once and deny-once decisions
- audit log
- Linux first

Do not overbuild policy language or GUI before this exists.

## Test plan

Must test:
- cat/read
- echo/write
- atomic save from editors
- temp file + rename
- concurrent readers
- concurrent writer + reader
- delete/recreate
- chmod/chown if relevant
- process tree attribution
- symlink attempts
- path traversal attempts
- daemon crash during write
- mount disappearance
- app startup under deny
- repeated prompt suppression via short-lived cache

Target app tests:
- at least one AI CLI harness
- one plain Python script
- one shell script
- one editor
- one app that writes JSON config
- one app that writes SQLite or similar state

## Open design choices to resolve early

- Rust vs Zig vs C core
- Metadata store
- whole-file encryption vs chunked encryption
- explicit "protected directory enrollment" vs transparent path replacement
- whether rule identity uses executable path only, or path + hash, or signer + hash where available

## Likely sharp edges

- apps that expect advisory locks
- apps that watch files with fs events
- apps that use mmap heavily
- filename case sensitivity differences
- symlink semantics
- prompt recursion if the UI itself touches guarded files
- mount order and login-time races

## What good looks like

A skeptical developer should be able to say:
"I can point this at ~/.config/some-tool, let the tool keep its dumb plaintext-file behavior, and still get a trustworthy per-open decision prompt with encrypted-at-rest backing."

## Immediate next task for the next AI

Produce:
1. a concrete v1 architecture doc
2. a Linux-first implementation plan with module boundaries
3. a research matrix for 10 target apps and their actual file write patterns
4. a recommendation on implementation language
5. a first-pass list of libfuse operations required for correctness
