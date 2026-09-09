# Policy File

`policy.yml` records enrollments and remembered decisions. Use `enroll`,
`unenroll`, and prompt choices for routine changes; manual edits are useful for
reviewing or removing decisions. Removing an enrollment by hand does not
restore the file from the store.

The [CLI reference](./cli.md#paths-and-environment) lists policy-path precedence.
File Snitch serializes its writes with a sidecar lock, so enrollment commands,
remembered decisions, and expiry pruning do not overwrite each other's updates.

## Empty policy

```yaml
version: 1
enrollments: []
decisions: []
```

`run` stays alive with an empty or missing policy and watches for changes.

## Enrollments

Each enrollment maps a target path to an existing guarded-store object:

```yaml
version: 1
enrollments:
  - path: '~/.kube/config'
    object_id: '2c2188feb50066333c0723302c3ad32e'
decisions: []
```

`path` must expand to an absolute path under the current user's home directory.
File Snitch writes home-relative paths as `~/...` and expands them when loading.
The target must be a user-owned regular file when enrolled through the CLI.

`object_id` identifies `pass:file-snitch/<object_id>`. It must be nonempty,
must not start with `.`, and may contain only ASCII letters, digits, `_`, `-`,
and `.`. Enrollment paths and object IDs must each be unique within the policy.
The CLI generates IDs; typing an enrollment into YAML does not create its
stored object or migrate the original file.

Home-relative paths let a policy use the corresponding home directory on
another machine. The policy alone is not a backup: restoring access also needs
the matching `pass` objects and GPG keys.

## Decisions

A decision matches an executable path, enrolled path, and approval class:

```yaml
version: 1
enrollments:
  - path: '~/.kube/config'
    object_id: '2c2188feb50066333c0723302c3ad32e'
decisions:
  - executable_path: '/usr/local/bin/kubectl'
    path: '~/.kube/config'
    approval_class: 'read_like'
    outcome: 'deny'
    expires_at: null
```

This example remembers a denial for reads by that executable. Use the actual
requesting executable path; decisions do not identify binaries by hash or
signer. Decision target paths follow the same home-directory restriction as
enrollments.

Writing a remembered decision for the same
`executable_path + path + approval_class` replaces its outcome and expiry.
Decisions take precedence over the daemon mode's defaults. Delete a decision
to return to that default; set `outcome: 'prompt'` to ask again in `run prompt`.
Only `prompt` mode connects to the agent.

### Approval classes

| Class | Access covered |
| --- | --- |
| `read_like` | Read-only access |
| `write_capable` | Create, write, truncate, rename, delete, `chmod`/`chown`, and xattr operations |

Xattr reads also use `write_capable`. These classes group policy decisions;
the [authorization scope](./cli.md#authorization-scope) explains which operations
reach the projection and when an open handle reuses a grant.

### Outcomes and prompt choices

Policy accepts `allow`, `deny`, and `prompt`.

| Prompt choice | Written to policy |
| --- | --- |
| Allow once / deny once | No; applies to the current request |
| Allow 5 min | `allow` with an expiry five minutes later |
| Always allow / always deny | `allow` / `deny` with `expires_at: null` |

Remembering a choice requires the requester to identify the executable.

## Expiration

`expires_at` accepts exact `null` or a quoted/unquoted RFC3339 UTC timestamp in
`YYYY-MM-DDTHH:MM:SSZ` form. Numeric epochs, timezone offsets, and other YAML
null spellings are not accepted.

```yaml
expires_at: '2030-01-01T12:00:00Z'
```

That decision expires at noon UTC on January 1, 2030. Expired decisions are
ignored and pruned by `run`; changes to remembered decisions apply on the next
guarded access without a remount.

Use `file-snitch status` to inspect the policy and `file-snitch doctor` to check
its objects and projection health.
