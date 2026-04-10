#!/usr/bin/env python3
import argparse
import pathlib


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--formula", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--source-url", required=True)
    args = parser.parse_args()

    path = pathlib.Path(args.formula)
    text = path.read_text(encoding="utf-8")
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
        f"  version \"{args.version}\"\n"
        f"{end_marker}"
    )
    updated = text[:start] + replacement + text[end + len(end_marker) :]
    path.write_text(updated, encoding="utf-8")


if __name__ == "__main__":
    main()
