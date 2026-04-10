#!/usr/bin/env python3
import argparse
import hashlib
import pathlib


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    path = pathlib.Path(args.path)
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    print(digest.hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
