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
| opencode | `~/.local/share/opencode/auth.json` | file | yes | no credential write observed | none observed in traced run | none observed on credential path | yes | Linux `strace` captured | `opencode providers list` did not read the seeded XDG config file from the README path. Instead it initialized cache and local state under `~/.cache/opencode/` and `~/.local/share/opencode/`, attempted to read `auth.json`, and opened SQLite state with `fcntl` locking, `ftruncate`, and `fsync`. The traced help/providers flows suggest the real secret-bearing file is `auth.json`, while the original config-file assumption was weak. |
| block-goose / goose | `~/.config/goose/` | directory | yes | yes | none observed in traced run | none observed in traced run | yes | Linux `strace` captured | `goose run -t - <<<"hi"` on Ubuntu 25.10 arm64 under Lima read `config.yaml` repeatedly and read `chatgpt_codex/tokens.json`. It rewrote `permission.yaml` in place with `O_WRONLY|O_CREAT|O_TRUNC` and no rename. Adjacent state writes also rewrote `~/.local/share/goose/projects.json` and `~/.local/state/goose/telemetry_installation.json` in place, appended a new CLI log file, and used SQLite WAL plus `fcntl` locking on `~/.local/share/goose/sessions/sessions.db{,-wal,-shm}`. No `chmod`, `chown`, or temp-file replacement was observed. |
| pi.dev | `~/.pi/agent/` | directory | yes | yes | none observed in traced run | yes | no file locking observed | Linux `strace` captured | The original `~/.config/pi.dev/` assumption was wrong for the traced CLI. With `PI_CODING_AGENT_DIR` set, `pi --help` and `pi --list-models` repeatedly opened `settings.json`. `pi --help` also created `auth.json` with `O_WRONLY|O_CREAT|O_TRUNC` and then `fchmod` to `0600`. No rename-based save flow or locking showed up in these runs. |
| OpenRouter | no verified local config path | unverified | no | no | n/a | n/a | n/a | target likely invalid as a file-bearing CLI | The original `~/.openrouter/` assumption is weak. `npm search` found an official CLI package (`@openrouter/cli`), but installing `@openrouter/cli@1.0.1` on Ubuntu failed because the published package depends on a missing workspace package (`@openrouter/mcp@workspace:*`). No supported local config-file path was verified. Current evidence suggests this target is env-first or otherwise not a good file-enrollment research target. |
| GitHub CLI | `$XDG_CONFIG_HOME/gh/` or `~/.config/gh/` | directory | yes | no write observed | none observed in traced run | none observed in traced run | yes | Linux and macOS mounted-runs captured | `gh auth status --json hosts`, with `GH_CONFIG_DIR` pointed at a mounted config dir, opened and read both `config.yml` and `hosts.yml` as the `gh` executable on both Ubuntu 25.10 arm64 under Lima and macOS. No writes, renames, chmod/chown, or lock-heavy behavior were observed beyond ordinary flush/lock callbacks. |
| AWS CLI | `~/.aws/credentials` | file | yes | yes | none observed in traced run | none observed in traced run | no file locking observed | Linux `strace` captured | `aws configure list` opened the credentials file with `O_RDONLY|O_CLOEXEC` and read `~/.aws/config` for region/output. `aws configure set aws_access_key_id ...` reopened `credentials` with `O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC`. No rename, chmod/chown, or locking appeared in this flow. |
| npm | `~/.npmrc` | file | yes | yes | none observed in traced run | yes | no file locking observed | Linux `strace` captured | `npm config list --location=user` opened the user `.npmrc` with `O_RDONLY|O_CLOEXEC`. `npm config set ...` rewrote `.npmrc` in place with `O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC` and then `fchmodat(..., 0600)`. No rename-based save flow or locking appeared on the config file itself. |
| Docker CLI | `~/.docker/config.json` | file | yes | yes | yes | yes | no file locking observed | Linux `strace` captured | `docker version` opened `config.json` read-only before failing against the absent daemon. `docker logout example.com` read `config.json`, created a random-suffixed temp file with `O_RDWR|O_CREAT|O_EXCL`, applied `fchmodat(..., 0664)` and `fchownat(...)`, then `renameat(...)` over the target. |
| kubectl | `~/.kube/config` | file | yes | yes | none observed on the main config file | none observed in traced run | no file locking observed | Linux `strace` captured | `kubectl config view` opened the kubeconfig read-only. `kubectl config set-cluster ...` created a sidecar lock file (`config.lock`) with `O_CREAT|O_EXCL`, reread the config, then rewrote the main file in place with `O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC`. |
| gcloud CLI | `~/.config/gcloud/` | directory | yes | yes | none observed on the config file | none observed in traced run | no file locking observed | Linux `strace` captured | With `CLOUDSDK_CONFIG` pointed at a disposable config dir, `gcloud config list` repeatedly opened `active_config` and `configurations/config_default`. `gcloud config set project ... --quiet` repeatedly reread those files and finally rewrote `config_default` with `O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC`. The CLI also touched unrelated SDK bytecode caches, so traced writes need to be separated from user config writes. |

## Outcome

- Nine targets produced usable syscall-backed file-IO evidence.
- One target, OpenRouter, produced a different but still useful finding:
  - the original local-file assumption was weak
  - the current official CLI package is not installable as published
  - current evidence suggests it is not a good v1 file-enrollment target

So this matrix now closes the “record real file IO behavior for the selected target apps/tools” item honestly, without pretending every originally named tool was a good file-centric fit.

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

### opencode

Observed environment:
- Ubuntu 25.10 arm64 guest under Lima on macOS
- traced with `strace -f`

Observed commands:

```bash
opencode --help
opencode providers list
```

Observed behavior:
- the traced flows did **not** open the seeded XDG config file at:
  - `$XDG_CONFIG_HOME/opencode/.opencode.json`
- both commands eagerly initialized local state under:
  - `~/.cache/opencode/`
  - `~/.local/share/opencode/`
  - `~/.local/state/opencode/`
- observed writes included:
  - `~/.cache/opencode/version` via `O_WRONLY|O_CREAT` plus `ftruncate`
  - lock heartbeat and metadata files under `~/.local/state/opencode/locks/...`
  - SQLite state under `~/.local/share/opencode/opencode.db{,-journal,-wal,-shm}`
  - append-only log creation under `~/.local/share/opencode/log/`
- `opencode providers list` attempted to read:
  - `~/.local/share/opencode/auth.json`
  - `~/.cache/opencode/models.json`

Observed mediation implications:
- the initial matrix assumption that opencode secrets live under `~/.config/opencode/` was too simplistic
- the credential-bearing path appears to be `~/.local/share/opencode/auth.json`
- opencode also needs SQLite-style `fcntl` locking, `ftruncate`, and `fsync` support on adjacent state

### pi

Observed environment:
- Ubuntu 25.10 arm64 guest under Lima on macOS
- traced with `strace -f`

Observed commands:

```bash
PI_CODING_AGENT_DIR="$HOME/.pi/agent" pi --help
PI_CODING_AGENT_DIR="$HOME/.pi/agent" PI_OFFLINE=1 pi --list-models
```

Observed behavior:
- the traced CLI uses:
  - `PI_CODING_AGENT_DIR`
  - defaulting to `~/.pi/agent`
- both commands repeatedly opened:
  - `settings.json`
- `pi --help` also created:
  - `auth.json` with `O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC`
  - followed by `fchmodat(..., 0600)`
- no rename-based save flow or file locking appeared in these runs

Observed mediation implications:
- the original `~/.config/pi.dev/` assumption was wrong for the traced CLI
- the actual local secret/state paths are under `~/.pi/agent/`
- direct truncating writes matter more than temp-file replacement in the observed flows

### AWS CLI

Observed environment:
- Ubuntu 25.10 arm64 guest under Lima on macOS
- traced with `strace -f`

Observed commands:

```bash
AWS_SHARED_CREDENTIALS_FILE=... AWS_CONFIG_FILE=... aws configure list
AWS_SHARED_CREDENTIALS_FILE=... AWS_CONFIG_FILE=... aws configure set aws_access_key_id WRITETESTKEY
```

Observed behavior:
- read flow:
  - `credentials` opened with `O_RDONLY|O_CLOEXEC`
  - `config` consulted for region/output
- write flow:
  - `credentials` reopened with `O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC`
- no rename, chmod/chown, or locking appeared in this flow

### npm

Observed environment:
- Ubuntu 25.10 arm64 guest under Lima on macOS
- traced with `strace -f`

Observed commands:

```bash
NPM_CONFIG_USERCONFIG=... npm config list --location=user
NPM_CONFIG_USERCONFIG=... npm config set //registry.npmjs.org/:_authToken WRITETOKEN
```

Observed behavior:
- read flow:
  - user `.npmrc` opened with `O_RDONLY|O_CLOEXEC`
- write flow:
  - `.npmrc` reopened with `O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC`
  - then `fchmodat(..., 0600)`
- no rename-based save flow or file locking appeared on the user config file

### Docker CLI

Observed environment:
- Ubuntu 25.10 arm64 guest under Lima on macOS
- traced with `strace -f`

Observed commands:

```bash
docker --config ... version
docker --config ... logout example.com
```

Observed behavior:
- read flow:
  - `config.json` opened read-only
- write flow:
  - temp file created next to the target with `O_RDWR|O_CREAT|O_EXCL`
  - `fchmodat(..., 0664)` and `fchownat(...)`
  - `renameat(...)` over `config.json`
- this is the clearest traced temp-file-plus-rename flow in the current matrix

### kubectl

Observed environment:
- Ubuntu 25.10 arm64 guest under Lima on macOS
- traced with `strace -f`

Observed commands:

```bash
KUBECONFIG=... kubectl config view
KUBECONFIG=... kubectl config set-cluster demo --server=https://changed.example.com
```

Observed behavior:
- read flow:
  - kubeconfig opened with `O_RDONLY|O_CLOEXEC`
- write flow:
  - sidecar `config.lock` created with `O_CREAT|O_EXCL`
  - main config reread
  - main config rewritten with `O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC`
- no rename-based save flow or metadata mutation appeared in this run

### gcloud CLI

Observed environment:
- Ubuntu 25.10 arm64 guest under Lima on macOS
- traced with `strace -f`

Observed commands:

```bash
CLOUDSDK_CONFIG=... gcloud config list --quiet
CLOUDSDK_CONFIG=... gcloud config set project changed-project --quiet
```

Observed behavior:
- read flow:
  - repeated opens of:
    - `active_config`
    - `configurations/config_default`
- write flow:
  - `configurations/config_default` rewritten with `O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC`
- unrelated SDK bytecode cache renames also occurred during command execution

Observed mediation implications:
- gcloud user config writes are simple truncating rewrites
- traces must distinguish real user config writes from incidental SDK self-cache writes

## Path sources

- GitHub CLI config directory: `gh help environment`
- GitHub CLI token storage behavior: `gh auth login --help`
- AWS CLI config and credentials files: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html
- npm per-user config file: https://docs.npmjs.com/cli/v11/configuring-npm/npmrc
- Docker CLI config directory and `config.json`: https://docs.docker.com/reference/cli/docker/
- Docker credential storage behavior: https://docs.docker.com/reference/cli/docker/login/
- kubeconfig default path: https://v1-32.docs.kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/
- gcloud config directory: https://cloud.google.com/sdk/docs/configurations
