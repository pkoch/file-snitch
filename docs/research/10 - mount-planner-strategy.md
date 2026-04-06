# Mount Planner Strategy

## Question

Given exact-path file enrollment, what mount set should the daemon derive at runtime?

More concretely:
- should it mount the immediate parent of every enrolled file
- should it aggressively coalesce mounts upward
- should it permit nested mounts

## Recommendation

Use the **minimal non-overlapping mount set**.

Planner rule:
- start from the exact enrolled file paths
- derive the parent directory of each enrolled file
- collapse those parents until no mount path is a descendant of another mount path
- do not create nested mounts unless a later platform constraint forces them

This gives the daemon:
- the smallest mount set that still covers every enrolled target
- one mounted tree for rename and temp-save flows that stay under the same ancestor
- a clean separation between:
  - exact file enrollment semantics
  - directory-shaped runtime projection

## Why this is the right default

### One mount can cover many enrolled descendants

If the enrolled files are:
- `~/.config/gh/hosts.yml`
- `~/.config/gh/config.yml`

Then the parent set is just:
- `~/.config/gh`

There is no reason to create more than one mount.

If the enrolled files are:
- `~/.config/gh/hosts.yml`
- `~/.config/gh/extensions/foo/token.json`

The minimal non-overlapping mount set is still:
- `~/.config/gh`

That single mount can:
- present the guarded `hosts.yml`
- pass through the unprotected subtree under `extensions/`
- later guard `extensions/foo/token.json` if it becomes enrolled

Nested mounts add complexity without adding product value here.

### Unrelated trees should stay separate

If the enrolled files are:
- `~/.aws/credentials`
- `~/.kube/config`

The minimal non-overlapping mount set is:
- `~/.aws`
- `~/.kube`

Coalescing upward to `~` or `~/.config` would be a bad idea:
- too much unrelated surface under one mount
- more opportunities for platform-specific oddities
- larger blast radius for bugs

So the planner should coalesce only enough to remove nested overlap, not enough to create giant “catch-all” mounts.

### Rename and temp-save flows stay local

The strongest practical reason for this planner is save-flow locality.

If an editor saves:
- `tmpfile` under `~/.config/gh`
- then renames it over `hosts.yml`

That entire flow stays inside one mounted tree if `~/.config/gh` is the mount.

That is exactly what the product wants:
- temp files stay unprotected compatibility traffic
- the enrolled target remains the policy object
- the rename-over-target path is still mediated locally

The same argument holds for:
- shell redirection with `O_TRUNC`
- backup-style rename flows
- lock or swap sidecars

## Invariants

The planner should preserve these invariants:

1. Enrollment stays exact-path based.
   - The planner never changes what is protected.
   - It only chooses where mounts go.

2. No mount path is a descendant of another mount path.
   - This avoids nested-mount reasoning by default.

3. Do not coalesce past the lowest common useful ancestor.
   - `~/.config/gh` is reasonable for multiple `gh`-related files.
   - `~/.config` is usually too broad.
   - `~` is obviously too broad.

4. Full unprotected-subtree passthrough remains intact.
   - A broader mount is acceptable only if it still behaves like a mostly normal directory tree.

5. Prompts and audit remain file-centric.
   - The mount path is never the logical policy target.

## Worked examples

### Example 1: same parent

Enrolled files:
- `~/.config/gh/hosts.yml`
- `~/.config/gh/config.yml`

Mounts:
- `~/.config/gh`

### Example 2: ancestor already covers descendant

Enrolled files:
- `~/.config/gh/hosts.yml`
- `~/.config/gh/extensions/foo/token.json`

Mounts:
- `~/.config/gh`

Not:
- `~/.config/gh`
- `~/.config/gh/extensions/foo`

### Example 3: unrelated trees

Enrolled files:
- `~/.aws/credentials`
- `~/.kube/config`
- `~/.docker/config.json`

Mounts:
- `~/.aws`
- `~/.kube`
- `~/.docker`

### Example 4: two files under a common app root

Enrolled files:
- `~/.config/goose/chatgpt_codex/tokens.json`
- `~/.config/goose/permission.yaml`

Mounts:
- `~/.config/goose`

This is acceptable even though only two files are guarded, because:
- the subtree is app-local
- unprotected descendants can still passthrough
- save and rewrite flows stay local to one mount

## What the planner should not do

- It should not mount one filesystem per file.
  - That recreates the file-bind-mount problem in different clothing.

- It should not coalesce up to broad ancestors like `~` or `~/.config` unless there is a very strong operational reason.

- It should not create nested mounts as a normal case.
  - If nested mounts ever become necessary, that should be a deliberate compatibility exception with a documented reason.

## Conclusion

The minimal non-overlapping mount set is the right v1 planner strategy.

It is:
- simple
- file-centric in product semantics
- compatible with temp-save and rename-over-target flows
- conservative about mount breadth

That is enough to close the planner question for Phase 0.
