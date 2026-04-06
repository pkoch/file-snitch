# File Enrollment Architecture Recommendation

## Question

Should the product protect directories, or exact files?

More concretely:
- should the daemon mount one guarded directory tree and ask users to reason in directories
- should it expose a secret store and project protected files into place with bind mounts, symlinks, or hardlinks
- or should it keep file protection as the product model while still using directory-shaped FUSE mounts as an implementation detail

## Recommendation

The product should move to **per-file enrollment**.

The user-facing model should be:
- protect this exact file
- show prompts and audit against this exact file
- persist policy against this exact file

The implementation should use **sparse parent-directory virtualization**:
- for each enrolled file, mount its parent directory
- inside that mounted directory, virtualize only the enrolled file entries
- pass through the entire unprotected subtree from the real underlying directory

This keeps the product file-centric without depending on per-file bind mounts or link tricks.

## Why the current guarded-root model is not the product shape

The Phase 1 spike proved that a file-only guarded root is a good way to de-risk the FUSE core, but it is still the wrong mental model for the product.

Users do not want to protect:
- `~/.aws/`
- `~/.config/gh/`
- `~/.kube/`

They want to protect:
- `~/.aws/credentials`
- `~/.config/gh/hosts.yml`
- `~/.kube/config`

That matters because the product boundary should match:
- enrollment
- prompting
- auditing
- rule keys
- backing-store identity

Those are all file-shaped concerns, not directory-shaped concerns.

## Mechanical picture

Assume the user enrolls:
- `~/.aws/credentials`
- `~/.kube/config`
- `~/.config/gh/hosts.yml`

The daemon computes the parent directories:
- `~/.aws`
- `~/.kube`
- `~/.config/gh`

Then it mounts one FUSE filesystem at each of those directories.

Inside each mounted directory:
- enrolled files are served from the guarded backend
- the entire unprotected subtree is served from the real underlying directory

So `~/.aws` would appear as:
- `credentials`
  - guarded virtual file
- `config`
  - passthrough real file if not enrolled
- any other sibling or descendant
  - passthrough

This is still directory virtualization mechanically, but it is **file enrollment semantically**.

## How the mounted view works

For each mounted parent directory:

1. `readdir`
- read the real underlying directory
- merge in enrolled guarded entries
- if a filename exists in both places, the guarded entry shadows the real one

2. `getattr`
- exact enrolled file path: return the guarded file view
- any other sibling: return the underlying filesystem metadata

3. `open`, `create`, `read`, `write`, `truncate`, `rename`, `unlink`
- exact enrolled file: mediate through the policy engine and guarded backend
- any unprotected sibling or descendant: passthrough

That includes editor temp files, swap files, lock files, and backup files.
They should be treated as compatibility traffic, not as protected objects.
The product should stay focused on the enrolled target path.

4. audit and prompt identity
- always report the exact enrolled file path
- do not report the parent directory as the logical target

## Why this is better than per-file bind mounts

Per-file bind mounts are attractive because they appear to match file enrollment directly.

They are still the wrong primary design.

### Linux-only viability is not enough

On Linux, a bind mount can target a single file. `mount(8)` explicitly says a single file can be remounted on a single file.

But that is not the portability story we want to build around.

On macOS, `mount(2)` is directory-oriented:
- `mount(const char *type, const char *dir, int flags, void *data);`
- the filesystem is grafted onto the tree at `dir`

Inference:
- per-file bind mounting is not a clean cross-platform primitive
- building the product around it would bias the design toward Linux-only mechanics

### Save flows and mountpoints interact badly

Editors and shells often save by:
- `open(..., O_TRUNC)`
- temp file plus rename-over-existing
- backup rename flows

Mountpoints are a bad thing to rename over. `rename(2)` documents `EBUSY` if the old or new path is in use by the system, for example as a mount point.

Inference:
- using exact protected files as mountpoints is likely to fight common save flows
- using parent-directory mounts keeps those save flows in the area FUSE is actually designed to mediate

### Operational overhead is worse

Per-file bind mounts would mean:
- one mount per file
- more mount lifecycle churn
- more special cases around target creation and replacement

Sparse parent-directory mounts let us amortize:
- mount lifecycle
- sibling passthrough
- rename and temp-save flows inside a mounted directory

## Why symlinks and hardlinks are worse

### Hardlinks

Hardlinks are a non-starter for the product model:
- they point to the same inode
- they do not create a mediation boundary
- they do not give the daemon a place to interpose policy

If the goal is “ask before this file is opened,” hardlinks do not help.

### Symlinks

Symlinks are better than hardlinks, but still the wrong main design:
- many tools treat symlinks differently
- target paths leak into user-visible behavior
- replacing a symlink during save flows changes the link itself, not just the guarded content
- they do not produce a uniform cross-platform mediation story

Symlinks are a compatibility tool, not a good primary security primitive here.

## Data model implications

This architecture changes the long-term model in useful ways.

### Enrollment table becomes exact-path based

Instead of:
- protected directory roots

Use:
- canonical file path -> backing object

Example:
- `/home/pkoch/.aws/credentials` -> object `aws-credentials`
- `/home/pkoch/.kube/config` -> object `kube-config`

### Mount planner becomes separate from enrollment

The daemon should derive mounts from enrolled files:
- enrolled files are the source of truth
- parent-directory mounts are a runtime projection

The recommended planner shape is:
- derive the parent directory of every enrolled file
- collapse those into the **minimal non-overlapping mount set**
- avoid nested mounts when one ancestor mount can already cover all enrolled descendants through passthrough

Example:
- `~/.config/gh/hosts.yml`
- `~/.config/gh/config.yml`
  - one mount at `~/.config/gh`
- `~/.config/gh/hosts.yml`
- `~/.config/gh/extensions/foo/token.json`
  - still one mount at `~/.config/gh`

This is better than nested mounts because it keeps:
- mount lifecycle simpler
- rename and temp-save handling local to one mounted directory tree
- cross-platform semantics easier to reason about

It also makes it possible later to change mount planning without changing enrollment semantics.

### Rules should stay file-centric

The policy engine should key on:
- executable identity
- exact enrolled file path
- requested access mode

Not on:
- mounted parent directory path

## Example save flows

### Direct shell overwrite

For:

```bash
echo hi > ~/.aws/credentials
```

The shell operates inside the mounted `~/.aws` directory:
- `open(credentials, O_WRONLY|O_TRUNC, ...)`
- `write(...)`

That maps cleanly onto file-level policy for `~/.aws/credentials`.

### Temp file plus rename

For an editor that saves by:
- create `.credentials.tmp`
- write temp file
- rename temp file over `credentials`

The whole flow stays inside the mounted `~/.aws` directory.

That means:
- temp-file creation can be handled locally by the mounted directory
- rename-over-enrolled-target can be mediated explicitly
- we do not ask the kernel to rename over a mountpoint

This is the main reason to keep the implementation directory-shaped even while the product is file-shaped.

Policy implication:
- do not enroll temp files
- do not prompt on temp files
- let temp-save traffic proceed as normal compatibility behavior
- mediate the enrolled target when the editor eventually replaces or opens that target

## Suggested implementation sequence

1. Keep the current FUSE core and policy model.
2. Replace the single guarded root model with:
   - exact enrolled-file records
   - derived parent-directory mounts
3. Start with exact parent-directory mounts only.
4. Inside each mounted directory:
   - support guarded exact files
   - passthrough the full unprotected subtree
5. Ignore temp-file paths as first-class protected objects.
6. Keep mount planning minimal and non-overlapping.

This lets the project preserve most of the current low-level work:
- open/create/read/write mediation
- rename handling
- prompt broker
- audit pipeline
- Zig/C seam

The big change is in the filesystem model and mount planning, not in the core interop strategy.

## Open questions after this recommendation

- Exactly how the minimal non-overlapping mount planner should be validated on real app flows
- How rename-over-enrolled-target should be modeled when the source path is an unprotected temp file
- Whether future products should add tree enrollment on top of exact-path enrollment, without changing the v1 file-centric model

## Recommendation summary

Do:
- make enrollment file-based
- keep policy and audit file-based
- mount sparse parent directories as the implementation mechanism

Do not do:
- directory protection as the product model
- per-file bind mounts as the primary design
- hardlinks
- symlink-based projection as the core mechanism

## Sources

- Linux bind mounts and single-file bind mounts: https://man7.org/linux/man-pages/man8/mount.8.html
- Linux rename `EBUSY` behavior for mount points: https://man7.org/linux/man-pages/man2/rename.2.html
- macOS `mount(2)` API and directory-oriented mountpoint semantics: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/mount.2.html
