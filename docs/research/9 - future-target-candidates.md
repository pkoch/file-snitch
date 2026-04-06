# Future Target Candidates

Follow-on research note after the Phase-0 target matrix.

Goal:
- gather the concrete secret-bearing paths observed on the developer machines
- compare them with the current target set
- identify good future enrollment targets without guessing blindly

Scope:
- metadata-only surveys of the local macOS machine and the remote Linux host `bolota`
- no file contents inspected

## What showed up on both machines

These are the strongest candidates for future product attention because they are both common and actually present in the surveyed home directories.

- SSH private keys
  - local:
    - `~/.ssh/id_ed25519`
  - `bolota`:
    - `~/.ssh/id_ed25519`
- GPG private-key material
  - local:
    - `~/.gnupg/private-keys-v1.d/*.key`
  - `bolota`:
    - `~/.gnupg/private-keys-v1.d/*.key`
- Docker auth/config
  - local:
    - `~/.docker/config.json`
  - `bolota`:
    - `~/.docker/config.json`
- Codex auth
  - local:
    - `~/.codex/auth.json`
  - `bolota`:
    - `~/.codex/auth.json`
- Goose config and permission state
  - local:
    - `~/.config/goose/config.yaml`
    - `~/.config/goose/permission.yaml`
    - `~/.config/goose/chatgpt_codex/tokens.json`
  - `bolota`:
    - `~/.config/goose/config.yaml`
    - `~/.config/goose/permission.yaml`

## What showed up on one machine only

These are still useful because they broaden the kinds of secrets the product should expect in the wild.

- kubeconfig
  - local:
    - `~/.kube/config`
- Pi agent auth
  - local:
    - `~/.pi/agent/auth.json`
    - `~/.pi/agent/settings.json`
- Opencode config/auth-adjacent state
  - local:
    - `~/.opencode.json`
- mkcert private CA key material
  - local:
    - `~/.vite-plugin-mkcert/rootCA-key.pem`
- GSConnect key material
  - `bolota`:
    - `~/.config/gsconnect/private.pem`
    - `~/.config/gsconnect/certificate.pem`

## What did not show up, but is still worth keeping in mind

These are common enough to remain good generic target classes, even though they were not present in the surveyed home directories.

- `~/.netrc`
- `~/.git-credentials`
- `~/.pypirc`
- `~/.cargo/credentials.toml`
- `~/.azure/`

The local survey did show:
- `~/.cargo/`
- `~/.gem/`

But it did not show the secret-bearing files that would make them strong near-term targets:
- no `~/.cargo/credentials.toml`
- no `~/.gem/credentials`

## Candidate classes that look strongest

If the product expands beyond the original target set, these are the best next categories.

1. Private-key material
   - SSH private keys
   - GPG private-key directories
   - app-local PEM or private key files
2. Single-file CLI auth stores
   - Docker `config.json`
   - kubeconfig
   - Codex `auth.json`
   - Pi `auth.json`
   - any future `auth.json`, `tokens.json`, or `credentials`-style files
3. Directory-backed AI/tool configs with token-bearing leaf files
   - Goose
   - similar agent/tool directories

## Why this matters for the architecture

The surveys reinforce the file-enrollment direction:

- many of the strongest targets are exact files, not whole directories
- some directories are still useful enrollment roots only because they contain exact secret-bearing leaf files
- arbitrary app-local private keys are a real category and are not well-captured by a cloud-CLI-only mindset

The surveys also argue against overfitting the product to only “official CLI config dirs.”

Real user machines contain:
- standard tool credentials
- AI-tool auth files
- private keys in app-specific locations
- token-bearing JSON or YAML files that are not part of any single ecosystem

## Recommendation

Treat the current Phase-0 matrix as sufficient for the v1 mediated-op and architecture decisions, but keep the following future target classes in view:

- SSH private keys
- GPG private-key material
- Docker `config.json`
- kubeconfig
- Codex/AI-tool `auth.json` and `tokens.json`
- app-local PEM and private key files

If additional tracing work is needed later, start with:

1. SSH
2. GPG-backed tools if a file-path boundary is still meaningful
3. exact-file auth stores already present on the developer machines
