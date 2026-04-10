#!/usr/bin/env python3
import argparse
import pathlib


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--changelog", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--date", required=True)
    args = parser.parse_args()

    path = pathlib.Path(args.changelog)
    lines = path.read_text(encoding="utf-8").splitlines()

    unreleased_header = "## [Unreleased]"
    release_header = f"## [{args.version}] - {args.date}"

    if release_header in lines:
        raise SystemExit(f"release section already exists: {release_header}")

    try:
        start = lines.index(unreleased_header)
    except ValueError as exc:
        raise SystemExit("missing Unreleased section") from exc

    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("## ["):
            end = index
            break

    unreleased_body = lines[start + 1 : end]
    while unreleased_body and unreleased_body[0] == "":
        unreleased_body.pop(0)
    while unreleased_body and unreleased_body[-1] == "":
        unreleased_body.pop()

    replacement = [unreleased_header, "", release_header]
    if unreleased_body:
        replacement.extend([""] + unreleased_body)
    replacement.append("")

    next_lines = lines[:start] + replacement + lines[end:]
    path.write_text("\n".join(next_lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
