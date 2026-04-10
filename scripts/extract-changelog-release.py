#!/usr/bin/env python3
import argparse
import pathlib


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--changelog", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()

    lines = pathlib.Path(args.changelog).read_text(encoding="utf-8").splitlines()
    header = f"## [{args.version}]"

    start = None
    for index, line in enumerate(lines):
        if line.startswith(header):
            start = index
            break
    if start is None:
        raise SystemExit(f"missing release section for {args.version}")

    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("## ["):
            end = index
            break

    section = lines[start:end]
    print("\n".join(section).strip())


if __name__ == "__main__":
    main()
