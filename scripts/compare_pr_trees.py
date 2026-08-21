#!/usr/bin/env python3
"""Fail closed unless a PR adds exactly one new immutable archive ZIP."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path


def inventory(root: Path) -> dict[str, tuple[int, str]]:
    output: dict[str, tuple[int, str]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if relative == ".git" or relative.startswith(".git/"):
            continue
        if path.is_symlink():
            raise SystemExit(f"repository tree contains a symlink: {relative}")
        if path.is_dir():
            continue
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                size += len(block)
                digest.update(block)
        output[relative] = (size, digest.hexdigest())
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("base", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()

    base = inventory(args.base.resolve())
    candidate = inventory(args.candidate.resolve())
    added = sorted(set(candidate) - set(base))
    deleted = sorted(set(base) - set(candidate))
    modified = sorted(name for name in set(base) & set(candidate) if base[name] != candidate[name])
    if deleted or modified or len(added) != 1:
        raise SystemExit(
            "archive PR must add exactly one file and modify/delete none; "
            f"added={added}, modified={modified}, deleted={deleted}"
        )
    archive = added[0]
    parts = archive.split("/")
    if len(parts) != 4 or parts[0] != "archives" or not archive.endswith(".zip"):
        raise SystemExit(f"new file is outside the immutable archive layout: {archive}")
    template_id, release_version, filename = parts[1:]
    if filename != f"{template_id}-{release_version}.zip":
        raise SystemExit("archive filename does not match templateId and releaseVersion")
    if candidate[archive][0] > 100 * 1024 * 1024:
        raise SystemExit("archive exceeds 100 MiB")

    absolute = (args.candidate.resolve() / Path(*parts)).resolve()
    print(absolute)
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(f"archive={absolute.as_posix()}\n")
            handle.write(f"template_id={template_id}\n")
            handle.write(f"release_version={release_version}\n")


if __name__ == "__main__":
    main()
