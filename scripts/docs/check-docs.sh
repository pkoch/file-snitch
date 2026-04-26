#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

command -v python3 >/dev/null 2>&1 || fail "missing required tool: python3"

cd "$repo_root"

python3 - "$repo_root" <<'PY'
import pathlib
import re
import sys
from urllib.parse import unquote

repo_root = pathlib.Path(sys.argv[1])


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    sys.exit(1)


def markdown_files() -> list[pathlib.Path]:
    files = []
    for path in repo_root.rglob("*.md"):
        rel = path.relative_to(repo_root)
        if rel.parts[0] in {".git", "vendor", "zig-cache", "zig-out"}:
            continue
        files.append(path)
    return sorted(files)


def check_markdown_links() -> None:
    failures = []
    link_pattern = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
    external_prefixes = (
        "http://",
        "https://",
        "mailto:",
        "app://",
        "plugin://",
    )

    for path in markdown_files():
        text = path.read_text(encoding="utf-8")
        for raw_target in link_pattern.findall(text):
            target = raw_target.strip()
            if not target or target.startswith("#"):
                continue
            if target.startswith(external_prefixes):
                continue

            target_without_anchor = target.split("#", 1)[0]
            if not target_without_anchor:
                continue

            decoded = unquote(target_without_anchor)
            resolved = (path.parent / decoded).resolve()
            try:
                resolved.relative_to(repo_root)
            except ValueError:
                failures.append(f"{path.relative_to(repo_root)}: link escapes repo: {target}")
                continue

            if not resolved.exists():
                failures.append(f"{path.relative_to(repo_root)}: missing link target: {target}")

    if failures:
        fail("markdown link check failed:\n" + "\n".join(failures))

    print("markdown links ok")


def extract_fenced_block(path: pathlib.Path, heading: str) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    heading_line = f"## {heading}"
    try:
        index = lines.index(heading_line)
    except ValueError:
        fail(f"{path.relative_to(repo_root)} is missing heading: {heading_line}")

    while index < len(lines) and lines[index] != "```text":
        index += 1
    if index == len(lines):
        fail(f"{path.relative_to(repo_root)} is missing text fence after {heading_line}")

    index += 1
    block = []
    while index < len(lines) and lines[index] != "```":
        block.append(lines[index])
        index += 1
    if index == len(lines):
        fail(f"{path.relative_to(repo_root)} has an unterminated command block")
    return block


def check_cli_command_block() -> None:
    import subprocess

    subprocess.run(["zig", "build", "--summary", "none"], cwd=repo_root, check=True)
    completed = subprocess.run(
        [str(repo_root / "zig-out/bin/file-snitch"), "help"],
        cwd=repo_root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    help_text = completed.stdout + completed.stderr
    help_lines = help_text.splitlines()
    try:
        usage_index = help_lines.index("usage:")
    except ValueError:
        fail("file-snitch help output is missing usage block")

    expected = []
    for line in help_lines[usage_index + 1 :]:
        if not line.strip():
            break
        expected.append(line.strip())

    documented = extract_fenced_block(repo_root / "docs/cli.md", "Commands")
    if documented != expected:
        fail(
            "docs/cli.md command block is stale.\n"
            f"expected from file-snitch help:\n{expected}\n"
            f"documented:\n{documented}"
        )

    print("cli command block ok")


def check_documented_smoke_tests() -> None:
    text = (repo_root / "docs/development.md").read_text(encoding="utf-8")
    documented = sorted(set(re.findall(r"\./tests/smoke/([A-Za-z0-9_.-]+\.sh)", text)))
    actual = sorted(path.name for path in (repo_root / "tests/smoke").glob("*.sh"))

    missing = [name for name in documented if name not in actual]
    undocumented = [name for name in actual if name not in documented]

    if missing or undocumented:
        messages = []
        if missing:
            messages.append("documented smoke tests missing on disk: " + ", ".join(missing))
        if undocumented:
            messages.append("smoke tests missing from docs/development.md: " + ", ".join(undocumented))
        fail("smoke test docs check failed:\n" + "\n".join(messages))

    print("smoke test docs ok")


check_markdown_links()
check_cli_command_block()
check_documented_smoke_tests()
print("docs checks passed")
PY
