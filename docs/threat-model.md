# Threat Model

File Snitch helps one user notice and control file access by their own tools.
For example, `run prompt` can ask before a CLI reads `~/.kube/config` or opens a
secret file for writing.

## Scope and bypasses

Mediation applies when an operation reaches a projected file. Enrollment moves
the original contents into `pass`; the daemon loads them into memory and
serves them through FUSE. The original path becomes a symlink to that file.
Sibling files and the original parent directory remain on the host filesystem.

That means software can remove or replace the original symlink without passing
through the projection. A tool that saves by renaming a sibling temporary file
over the symlink can leave an ordinary, unguarded file at the target path.
Applications that refuse symlinks may also fail to use an enrolled file.
Validate the workflows you need before enrolling their secrets.

File Snitch does not isolate hostile software running as your user. Such
software may be able to edit policy, access `pass` directly, or interfere with
the daemon and agent. Remembered decisions identify an executable by its path,
not by a content hash or signing identity.

It also does not defend against root, kernel compromise, or exfiltration after
access has been allowed. Previously read data, backups, other copies, and
plaintext in process memory are outside its control. Removing the original
file during enrollment is not secure erasure.

## Authorization behavior

Use `run prompt` to request a decision for access not already covered by policy.
Remembered decisions take precedence over the mode's defaults. `run allow`
allows reads and mutations by default; `run deny` allows reads and denies
mutations by default.

Authorization precedes the operation. A read-only handle grant cannot authorize
a later write. Matching handle grants and remembered decisions can suppress
further prompts; the [CLI reference](./cli.md#authorization-scope) describes
operation coverage.

Denial, timeout, and an unavailable prompt broker return permission denied.
The terminal frontend treats Enter and EOF as allow, so it needs a usable
terminal. A File Snitch prompt controls access through FUSE; it does not defer
GPG decryption until approval.

## Trusted components

The operating system, FUSE/macFUSE, File Snitch daemon and agent, and `pass`/GPG
all handle or control access to secrets. Compromise of these components is
outside the protection File Snitch provides. Encryption at rest comes from the
`pass` backend.

Policy, sockets, locks, and services are per-user. There is no system-wide
mandatory access control, sandbox, or shared multi-user policy authority.

## Failure and recovery

If the daemon stops, enrolled paths become unavailable or dangling symlinks;
the original plaintext is not automatically restored. If the store cannot be
decrypted, the projection cannot load its files. Use `unenroll` to restore
contents, following the [recovery guide](./operations.md).
