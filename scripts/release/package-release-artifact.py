#!/usr/bin/env python3
import argparse
import gzip
import pathlib
import tarfile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    binary_path = pathlib.Path(args.binary)
    output_path = pathlib.Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    root_name = f"file-snitch-{args.version}-{args.platform}"

    with output_path.open("wb") as raw_output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_output, compresslevel=9, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w") as archive:
                dir_info = tarfile.TarInfo(f"{root_name}/")
                dir_info.type = tarfile.DIRTYPE
                dir_info.mode = 0o755
                dir_info.uid = 0
                dir_info.gid = 0
                dir_info.uname = ""
                dir_info.gname = ""
                dir_info.mtime = 0
                archive.addfile(dir_info)

                file_info = tarfile.TarInfo(f"{root_name}/file-snitch")
                file_info.mode = 0o755
                file_info.uid = 0
                file_info.gid = 0
                file_info.uname = ""
                file_info.gname = ""
                file_info.mtime = 0
                file_info.size = binary_path.stat().st_size
                with binary_path.open("rb") as handle:
                    archive.addfile(file_info, handle)


if __name__ == "__main__":
    main()
