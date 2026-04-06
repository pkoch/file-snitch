# Target App Matrix

Phase-0 workspace for collecting the 10 target apps/tools and their real file IO behavior.

## Capture format

For each target, record:
- secret-bearing path
- whether the path is a file or directory
- read flow
- write flow
- temp file plus rename behavior
- permissions and ownership changes
- locking behavior
- notes that affect FUSE mediation

## Targets

| Target | Secret-bearing path | Path type | Read flow observed? | Write flow observed? | Temp + rename? | chmod/chown? | Locking? | Status | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| opencode | `~/.config/opencode/` | directory | pending | pending | pending | pending | pending | seeded from brief | Need exact files and a real trace |
| block-goose / goose | `~/.config/goose/` | directory | yes | yes | none observed in traced run | none observed in traced run | yes | Linux `strace` captured | `goose run -t - <<<"hi"` on Ubuntu 25.10 arm64 under Lima read `config.yaml` repeatedly and read `chatgpt_codex/tokens.json`. It rewrote `permission.yaml` in place with `O_WRONLY|O_CREAT|O_TRUNC` and no rename. Adjacent state writes also rewrote `~/.local/share/goose/projects.json` and `~/.local/state/goose/telemetry_installation.json` in place, appended a new CLI log file, and used SQLite WAL plus `fcntl` locking on `~/.local/share/goose/sessions/sessions.db{,-wal,-shm}`. No `chmod`, `chown`, or temp-file replacement was observed. |
| pi.dev | `~/.config/pi.dev/` | directory | pending | pending | pending | pending | pending | seeded from brief | Need exact files and a real trace |
| OpenRouter | `~/.openrouter/` | directory | pending | pending | pending | pending | pending | seeded from brief | Need exact files and a real trace |
| GitHub CLI | `$XDG_CONFIG_HOME/gh/` or `~/.config/gh/` | directory | pending | pending | pending | pending | pending | path verified | Tokens may be in the system credential store; plaintext fallback lives in the gh config directory |
| AWS CLI | `~/.aws/credentials` | file | pending | pending | pending | pending | pending | path verified | Config also lives in `~/.aws/config`; temporary credentials may be cached under `~/.aws/cli/cache` |
| npm | `~/.npmrc` | file | pending | pending | pending | pending | pending | path verified | Auth tokens commonly live in the per-user npmrc |
| Docker CLI | `~/.docker/config.json` | file | pending | pending | pending | pending | pending | path verified | Credentials may move to a credential helper, but plaintext or base64-encoded auth can live in `config.json` |
| kubectl | `~/.kube/config` | file | pending | pending | pending | pending | pending | path verified | Kubeconfig can embed tokens or reference client cert and key files |
| gcloud CLI | `~/.config/gcloud/` | directory | pending | pending | pending | pending | pending | path verified | Official docs verify the config dir; exact token-bearing files still need tracing |

## Next research actions

- Replace example paths with verified paths where needed
- Record actual syscalls and rename patterns from real runs
- Summarize which operations must be mediated for the Linux spike

## Observed run notes

### goose

Observed environment:
- Ubuntu 25.10 arm64 guest under Lima on macOS
- traced with `strace -f`

Observed command:

```bash
goose run -t - <<<"hi"
```

Observed config-side files present before and after the run:
- `~/.config/goose/chatgpt_codex/tokens.json`
- `~/.config/goose/config.yaml`
- `~/.config/goose/config.yaml.bak`
- `~/.config/goose/permission.yaml`
- `~/.config/goose/tunnel.lock`
- `~/.config/goose/mcp-apps-cache/apps_*.json`

Observed non-config files opened during the traced run:
- `~/.local/share/goose/sessions/sessions.db`
- `~/.local/share/goose/sessions/sessions.db-wal`
- `~/.local/share/goose/sessions/sessions.db-shm`
- `~/.local/share/goose/projects.json`
- `~/.local/state/goose/logs/cli/YYYY-MM-DD/<timestamp>.log`
- `~/.local/state/goose/telemetry_installation.json`

Observed read flow:
- `config.yaml` is opened repeatedly with `O_RDONLY|O_CLOEXEC`
- `chatgpt_codex/tokens.json` is opened with `O_RDONLY|O_CLOEXEC`
- no reads of `config.yaml.bak`, `tunnel.lock`, or `mcp-apps-cache/*.json` appeared in this run

Observed write flow:
- `permission.yaml` is reopened with `O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC`
- `projects.json` is reopened with `O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC`
- `telemetry_installation.json` is reopened with `O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC`
- the CLI log file is opened with `O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC`

Observed session and lock behavior:
- `sessions.db` opens with `O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC`
- `sessions.db-wal` and `sessions.db-shm` also open with `O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC`
- SQLite uses `fcntl(..., F_SETLK, ...)` and `F_GETLK` on `sessions.db` and `sessions.db-shm`
- `sessions.db-shm` is `ftruncate`d
- `sessions.db-wal` is `fsync`d repeatedly
- no `flock` calls were observed

Observed rename and metadata behavior:
- no `rename`, `renameat`, or `renameat2` calls touched goose-managed files in this run
- no `chmod`, `fchmod*`, `chown`, or `fchown*` calls touched goose-managed files in this run
- the diff across the run showed stable inodes for `permission.yaml`, `projects.json`, and `telemetry_installation.json`, which matches the in-place `O_TRUNC` rewrite pattern

Observed mediation implications:
- v1 needs ordinary read mediation for top-level config files under `~/.config/goose/`
- if we ever mediate broader goose state, in-place truncating writes matter more than temp-file replacement for this flow
- SQLite-backed session state requires `fcntl` locking, `ftruncate`, and `fsync` support on the Linux path

## Path sources

- GitHub CLI config directory: `gh help environment`
- GitHub CLI token storage behavior: `gh auth login --help`
- AWS CLI config and credentials files: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html
- npm per-user config file: https://docs.npmjs.com/cli/v11/configuring-npm/npmrc
- Docker CLI config directory and `config.json`: https://docs.docker.com/reference/cli/docker/
- Docker credential storage behavior: https://docs.docker.com/reference/cli/docker/login/
- kubeconfig default path: https://v1-32.docs.kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/
- gcloud config directory: https://cloud.google.com/sdk/docs/configurations
