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
| block-goose | `~/.config/block-goose/` | directory | pending | pending | pending | pending | pending | seeded from brief | Need exact files and a real trace |
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

## Path sources

- GitHub CLI config directory: `gh help environment`
- GitHub CLI token storage behavior: `gh auth login --help`
- AWS CLI config and credentials files: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html
- npm per-user config file: https://docs.npmjs.com/cli/v11/configuring-npm/npmrc
- Docker CLI config directory and `config.json`: https://docs.docker.com/reference/cli/docker/
- Docker credential storage behavior: https://docs.docker.com/reference/cli/docker/login/
- kubeconfig default path: https://v1-32.docs.kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/
- gcloud config directory: https://cloud.google.com/sdk/docs/configurations
