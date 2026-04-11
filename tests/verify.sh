#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

./tests/build.sh

./tests/smoke/run-empty-policy.sh
./tests/smoke/policy-lifecycle.sh
./tests/smoke/doctor-debug-dossier.sh
./tests/smoke/run-policy-reload.sh
./tests/smoke/run-expired-decision-cleanup.sh
./tests/smoke/run-single-enrollment.sh
./tests/smoke/run-multi-mount.sh
./tests/smoke/run-prompt-linux-ui.sh
./tests/smoke/run-prompt-single.sh
./tests/smoke/run-prompt-remembered-decision.sh
./tests/smoke/user-service-rendering.sh

if [[ "$(uname -s)" == "Darwin" ]]; then
  ./tests/smoke/run-prompt-macos-ui.sh
fi

./scripts/demo/check-demo-artifacts.sh
