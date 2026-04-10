#!/usr/bin/env python3
import argparse
import gzip
import io
import os
import pathlib
import stat
import subprocess
import tarfile


def repo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent.parent


def tracked_files(root: pathlib.Path) -> list[pathlib.Path]:
    output = subprocess.check_output(
        ["git", "ls-files", "-z"],
        cwd=root,
        text=False,
    )
    paths = []
    for raw in output.split(b"\0"):
        if not raw:
            continue
        rel = pathlib.Path(raw.decode("utf-8"))
        if rel.parts and rel.parts[0] == "Formula":
            continue
        paths.append(rel)
    return sorted(paths)


def add_directory_once(
    archive: tarfile.TarFile,
    added: set[str],
    name: str,
) -> None:
    if not name or name in added:
        return
    parent = pathlib.PurePosixPath(name).parent
    if str(parent) not in (".", ""):
        add_directory_once(archive, added, str(parent))
    info = tarfile.TarInfo(name if name.endswith("/") else f"{name}/")
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    archive.addfile(info)
    added.add(name)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    root = repo_root()
    output_path = pathlib.Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    prefix = pathlib.PurePosixPath(f"file-snitch-{args.version}")
    added_dirs: set[str] = set()

    with output_path.open("wb") as raw_output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_output, compresslevel=9, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w") as archive:
                add_directory_once(archive, added_dirs, str(prefix))

                for rel_path in tracked_files(root):
                    source_path = root / rel_path
                    archive_path = prefix / rel_path.as_posix()

                    for parent in archive_path.parents:
                        parent_str = str(parent)
                        if parent_str in (".", ""):
                            continue
                        add_directory_once(archive, added_dirs, parent_str)

                    file_info = source_path.lstat()
                    info = tarfile.TarInfo(str(archive_path))
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mtime = 0

                    if stat.S_ISLNK(file_info.st_mode):
                        info.type = tarfile.SYMTYPE
                        info.mode = 0o777
                        info.linkname = os.readlink(source_path)
                        archive.addfile(info)
                        continue

                    if not stat.S_ISREG(file_info.st_mode):
                        raise SystemExit(f"unsupported tracked file type: {rel_path}")

                    info.type = tarfile.REGTYPE
                    info.mode = 0o755 if os.access(source_path, os.X_OK) else 0o644
                    info.size = file_info.st_size
                    with source_path.open("rb") as handle:
                        archive.addfile(info, handle)


if __name__ == "__main__":
    main()
