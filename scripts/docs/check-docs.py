"""Verify the project's Markdown and its CLI examples."""
import argparse
from dataclasses import dataclass, field
import json
import os
import pathlib
import re
import subprocess
import tempfile
from urllib.parse import unquote, urlsplit


repo_root = pathlib.Path(__file__).resolve().parents[2]
cli = repo_root / "zig-out/bin/file-snitch"
destination = r"(?:<([^>\n]+)>|((?:[^()\s]|\([^()\s]*\))+))"
link_space = r"[ \t]*(?:\n[ \t]*)?"
inline_destination = re.compile(
    r"\]\(" + link_space + destination + r"""(?:\s+(?:"[^"]*"|'[^']*'|\([^)]*\)))?""" + link_space + r"\)"
)
reference_destination = re.compile(r"^ {0,3}\[(?!\^)[^]\n]+]:" + link_space + destination, re.MULTILINE)
# Commands in the guides use these checkout-relative script paths.
repo_script_path = re.compile(r"(?<![\w./-])\./(?:\.devcontainer|scripts|tests)/[\w./-]+\.(?:sh|py)(?![\w./-])")


def fail(message: str) -> None:
    raise SystemExit(message)


@dataclass
class CodeBlock:
    language: str
    section: str
    line: int
    text: str


@dataclass
class Document:
    anchors: set[str] = field(default_factory=set)
    links: list[tuple[int, str]] = field(default_factory=list)
    blocks: list[CodeBlock] = field(default_factory=list)


def markdown_files():
    ignored = {".git", "vendor", ".cache", ".zig-cache", "zig-cache", "zig-out"}
    for directory, subdirs, files in os.walk(repo_root):
        if pathlib.Path(directory) == repo_root:
            subdirs[:] = sorted(set(subdirs) - ignored)
        for name in sorted(files):
            if name.endswith(".md"):
                yield (pathlib.Path(directory) / name).relative_to(repo_root)


def heading_anchor(title: str) -> str:
    # GitHub uses the visible heading text, including the contents of code spans.
    title = re.sub(r"\[([^]]+)\]\([^)]+\)", r"\1", title)
    title = re.sub(r"(?<!\w)(_+)(\S(?:.*?\S)?)\1(?!\w)", r"\2", title)
    title = re.sub(r"(`+)(.*?)\1|<[^>]+>", lambda match: match[2] or "", title)
    return re.sub(r"[^\w -]", "", title.lower()).replace(" ", "-")


def read_markdown(path: pathlib.Path) -> Document:
    document = Document()
    section = ""
    custom_anchors = set()
    source_lines = (repo_root / path).read_text(encoding="utf-8").splitlines()
    prose_lines = [""] * len(source_lines)
    lines = iter(enumerate(source_lines, 1))
    for number, line in lines:
        fence = re.fullmatch(r"( {0,3})(`{3,}|~{3,})(.*)", line)
        if fence:
            indent, marker, info = fence.groups()
            closing = re.compile(r" {0,3}" + marker + marker[0] + r"*[ \t]*")
            indentation = re.compile(rf"^ {{0,{len(indent)}}}")
            code = []
            for _, content in lines:
                if closing.fullmatch(content):
                    break
                code.append(indentation.sub("", content))
            else:
                fail(f"{path}:{number}: unclosed code fence")
            words = info.split()
            language = words[0] if words else ""
            document.blocks.append(CodeBlock(language, section, number + 1, "\n".join(code) + "\n"))
            continue

        heading = re.match(r"^ {0,3}#{1,6}[ \t]+(.+)", line)
        if heading:
            section = re.sub(r"[ \t]+#+$", "", heading[1].strip())
            base = heading_anchor(section)
            anchor = base
            index = 1
            while anchor in document.anchors:
                anchor = f"{base}-{index}"
                index += 1
            document.anchors.add(anchor)

        prose_lines[number - 1] = re.sub(r"(`+).*?\1", "", line)
        custom_anchors.update(re.findall(r"""<a\s+(?:id|name)=["']([^"']+)["']""", prose_lines[number - 1]))

    # Scan prose across soft line breaks. A linked image contributes two destinations.
    prose = "\n".join(prose_lines)
    for pattern in (inline_destination, reference_destination):
        for link in pattern.finditer(prose):
            number = 1 + prose.count("\n", 0, link.start())
            document.links.append((number, link[1] or link[2]))
    document.anchors.update(custom_anchors)
    return document


def check_markdown_links(documents) -> None:
    failures = []
    for path, document in documents.items():
        for line, target in document.links:
            url = urlsplit(target)
            if url.scheme or url.netloc:
                continue
            target_path = unquote(url.path)
            resolved = repo_root / path
            if target_path:
                parent = repo_root if target_path.startswith("/") else resolved.parent
                resolved = (parent / target_path.lstrip("/")).resolve()
            if not resolved.is_relative_to(repo_root):
                failures.append(f"{path}:{line}: link escapes repo: {target}")
            elif not resolved.exists():
                failures.append(f"{path}:{line}: missing link target: {target}")
            elif url.fragment:
                linked_doc = documents.get(resolved.relative_to(repo_root))
                if linked_doc and unquote(url.fragment) not in linked_doc.anchors:
                    failures.append(f"{path}:{line}: missing section: {target}")
    if failures:
        fail("\n".join(failures))
    print(f"Local links and sections checked in {len(documents)} Markdown files")


def check_snippet_syntax(documents) -> None:
    bash_env = {"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C"}
    for path, document in documents.items():
        for block in document.blocks:
            if block.language == "bash":
                result = subprocess.run(["bash", "-n"], input=block.text, capture_output=True, text=True, env=bash_env)
                if result.returncode or result.stderr:
                    fail(f"{path}:{block.line}: Bash example: {result.stderr.strip()}")
                for line, command in enumerate(block.text.splitlines(), block.line):
                    for script in repo_script_path.findall(command):
                        if not (repo_root / script).is_file():
                            fail(f"{path}:{line}: missing repository script: {script}")
            elif block.language == "json":
                try:
                    json.loads(block.text, parse_constant=reject_json_constant)
                except json.JSONDecodeError as error:
                    fail(f"{path}:{block.line + error.lineno - 1}: JSON example: {error.msg}")
                except ValueError as error:
                    fail(f"{path}:{block.line}: JSON example: {error}")
    print("Bash examples, repository script paths, and JSON examples checked")


def reject_json_constant(token: str) -> None:
    raise ValueError(f"{token} is not a JSON number")


def check_cli_version() -> None:
    expected = "file-snitch " + (repo_root / "VERSION").read_text(encoding="utf-8").strip()
    actual = subprocess.check_output([cli, "--version"], text=True).strip()
    if actual != expected:
        fail(f"file-snitch --version printed {actual!r}, expected {expected!r} from VERSION")
    print("CLI version matches VERSION")


def check_cli_command_block(document: Document) -> None:
    help_text = subprocess.check_output([cli, "help"], stderr=subprocess.STDOUT, text=True)
    lines = iter(help_text.splitlines())
    if not any(line.strip() == "usage:" for line in lines):
        fail("file-snitch help output is missing its usage block")
    expected = []
    for line in lines:
        if not line.strip():
            break
        expected.append(line.strip())

    examples = [block for block in document.blocks if block.section == "Commands" and block.language == "text"]
    if len(examples) != 1 or examples[0].text.splitlines() != expected:
        fail("docs/cli.md: the Commands block must match file-snitch help:\n" + "\n".join(expected))
    print("CLI command block matches help")


def check_policy_examples(document: Document) -> None:
    checked = set()
    with tempfile.TemporaryDirectory() as directory:
        home = pathlib.Path(directory).resolve()
        policy = home / "policy.yml"
        env = {**os.environ, "HOME": str(home), "XDG_CONFIG_HOME": str(home), "XDG_STATE_HOME": str(home)}
        read_decision = (
            f"decision: executable_path=/usr/local/bin/kubectl path={home}/.kube/config "
            "approval_class=read_like"
        )
        expectations = {
            "Empty policy": {"enrollments: 0", "decisions: 0"},
            "Enrollments": {"enrollments: 1", "decisions: 0"},
            "Decisions": {"enrollments: 1", "decisions: 1", f"{read_decision} outcome=deny expires_at=null"},
            "Expiration": {
                "enrollments: 1", "decisions: 1", f"{read_decision} outcome=allow expires_at=2030-01-01T12:00:00Z",
            },
        }
        for block in document.blocks:
            if block.language != "yaml":
                continue
            policy.write_text(block.text, encoding="utf-8")
            result = subprocess.run(
                [cli, "status", "--policy", policy], cwd=home, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            label = f"docs/policy.md:{block.line}: {block.section}"
            if result.returncode:
                fail(f"{label}: file-snitch status failed:\n{result.stdout}")
            expected = expectations.get(block.section, set())
            if not expected.issubset(result.stdout.splitlines()):
                fail(f"{label}: unexpected file-snitch status:\n{result.stdout}")
            checked.add(block.section)
    missing = sorted(expectations.keys() - checked)
    if missing:
        fail("docs/policy.md: missing YAML example under " + ", ".join(missing))
    print("Policy examples verified with file-snitch status")


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


def main() -> None:
    parser = argparse.ArgumentParser(prog="check-docs.sh", description=__doc__)
    parser.add_argument("--skip-build", action="store_true", help="use the existing zig-out/bin/file-snitch")
    args = parser.parse_args()
    documents = {path: read_markdown(path) for path in markdown_files()}
    check_markdown_links(documents)
    check_snippet_syntax(documents)
    check_documented_smoke_tests()
    if not args.skip_build:
        subprocess.run(["zig", "build", "--summary", "none"], cwd=repo_root, check=True)
    check_cli_version()
    check_cli_command_block(documents[pathlib.Path("docs/cli.md")])
    check_policy_examples(documents[pathlib.Path("docs/policy.md")])
    print("docs checks passed")


if __name__ == "__main__":
    main()
