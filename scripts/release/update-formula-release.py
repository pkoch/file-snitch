#!/usr/bin/env python3
import argparse
import pathlib
import re


def zig_dependency_from_manifest(path: pathlib.Path) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(r'\.minimum_zig_version\s*=\s*"(\d+)\.(\d+)\.(\d+)"', text)
    if match is None:
        raise SystemExit(f"missing .minimum_zig_version in {path}")

    major, minor, _patch = match.groups()
    if major == "0":
        return f"zig@0.{minor}"
    return f"zig@{major}"


def replace_once(text: str, pattern: str, replacement: str, label: str) -> str:
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise SystemExit(f"failed to update {label} in formula")
    return updated


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--formula", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--zig-package-manifest", default="build.zig.zon")
    args = parser.parse_args()

    path = pathlib.Path(args.formula)
    text = path.read_text(encoding="utf-8")
    zig_dependency = zig_dependency_from_manifest(pathlib.Path(args.zig_package_manifest))
    start_marker = "  # stable-release-start\n"
    end_marker = "  # stable-release-end\n"

    start = text.find(start_marker)
    end = text.find(end_marker)
    if start == -1 or end == -1 or end < start:
        raise SystemExit("missing stable release markers in formula")

    replacement = (
        f"{start_marker}"
        f"  url \"{args.source_url}\"\n"
        f"  sha256 \"{args.sha256}\"\n"
        f"{end_marker}"
    )
    updated = text[:start] + replacement + text[end + len(end_marker) :]
    updated = replace_once(
        updated,
        r'^  depends_on "zig(?:@\d+\.\d+)?" => :build$',
        f'  depends_on "{zig_dependency}" => :build',
        "Zig build dependency",
    )
    path.write_text(updated, encoding="utf-8")


if __name__ == "__main__":
    main()
