# Policy File

`policy.yml` is the durable source of truth for enrolled files and remembered
decisions.

File Snitch writes this file itself through `enroll`, `unenroll`, and remembered
prompt decisions. Manual edits are useful for inspection and recovery, but
prefer the CLI for normal changes.

## Location

Policy path precedence:

1. `--policy <path>` where supported
2. `FILE_SNITCH_POLICY_PATH`
3. `XDG_CONFIG_HOME/file-snitch/policy.yml`
4. `HOME/.config/file-snitch/policy.yml`

Policy writes are serialized with a sidecar lock so concurrent `enroll`,
`unenroll`, remembered decisions, and daemon expiry pruning do not clobber each
other.

## Empty Policy

```yaml
version: 1
enrollments: []
decisions: []
```

`file-snitch run` stays alive with an empty policy and watches for future
changes.

## Enrollments

Each enrollment maps one absolute target path to one guarded-store object.

```yaml
version: 1
enrollments:
  - path: '/Users/alice/.kube/config'
    object_id: '2c2188feb50066333c0723302c3ad32e'
decisions: []
```

Fields:

- `path`: absolute path to the enrolled file
- `object_id`: backend object identifier under `pass:file-snitch/<object_id>`

Current constraints:

- `path` must be absolute
- `object_id` must be non-empty
- the target file must be a user-owned regular file under the current user's
  home directory when enrolled through the CLI
- exact-file enrollment is the product model; parent-directory mounts are an
  implementation detail

## Decisions

Decisions are remembered prompt outcomes. One-shot decisions are runtime-only;
temporary and durable choices are written into `policy.yml`.

```yaml
version: 1
enrollments:
  - path: '/Users/alice/.kube/config'
    object_id: '2c2188feb50066333c0723302c3ad32e'
decisions:
  - executable_path: '/usr/local/bin/kubectl'
    uid: 501
    path: '/Users/alice/.kube/config'
    approval_class: 'read_like'
    outcome: 'allow'
    expires_at: '2026-04-09T12:34:56Z'
```

Fields:

- `executable_path`: executable path that requested access
- `uid`: numeric user id that requested access
- `path`: enrolled target path the decision applies to
- `approval_class`: approval class covered by the decision
- `outcome`: remembered result
- `expires_at`: RFC3339 UTC expiry timestamp or `null`

The durable decision key is:

```text
executable_path + uid + path + approval_class
```

Writing a new remembered decision for the same key replaces the previous
outcome and expiry.

## Approval Classes

Current approval classes:

- `read_like`: read-style guarded access
- `write_capable`: create, write, rename, delete, metadata, and xattr-capable
  access classes

`prompt` mode currently prompts for `open` and `create` on guarded paths.
Lower-level operation coverage can be finer than the durable approval classes;
the classes are the remembered-decision boundary.

## Outcomes

Current outcomes:

- `allow`
- `deny`
- `prompt`

Prompt frontends expose:

- allow once
- deny once
- allow 5 min
- always allow
- always deny

Only temporary and durable choices are written to policy. `allow once` and
`deny once` apply only to the current request.

## Expiration

`expires_at` accepts:

- `null`
- `~`
- quoted or unquoted RFC3339 UTC timestamps in this exact shape:
  `YYYY-MM-DDTHH:MM:SSZ`

Examples:

```yaml
expires_at: null
expires_at: '2026-04-09T12:34:56Z'
```

Expired decisions are ignored and pruned by `file-snitch run`.

## Inspection

Use:

```bash
file-snitch status
file-snitch doctor
file-snitch doctor --export-debug-dossier ./file-snitch-debug-dossier.md
```

`status` prints enrollments, decisions, and the derived mount plan. `doctor`
also validates guarded objects, target-path health, agent reachability,
frontend helpers, and service files where applicable.
