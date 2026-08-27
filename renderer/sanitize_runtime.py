#!/usr/bin/env python3
"""Remove forbidden runtime tools and every same-inode alias before finalizing an image."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
from pathlib import Path

from runtime_boundary import forbidden_python_path, forbidden_tool_name, shell_shebang_line

# Only mount-backed runtime filesystems are excluded. ``/run`` and ``/tmp``
# may contain files committed by an image layer, so both remain in the scan.
VIRTUAL_TOP_LEVEL = {"dev", "proc", "sys"}


def shell_shebang(path: Path) -> bool:
    try:
        with path.open("rb", buffering=0) as handle:
            line = handle.readline(512)
    except OSError:
        return False
    return shell_shebang_line(line)


def sanitize(root: Path) -> list[str]:
    root = root.resolve(strict=True)
    inode_paths: dict[tuple[int, int], list[Path]] = {}
    rejected_inodes: set[tuple[int, int]] = set()
    unlink_paths: set[Path] = set()
    remove_trees: set[Path] = set()

    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        if base == root:
            names[:] = [name for name in names if name not in VIRTUAL_TOP_LEVEL]
        for name in list(names):
            path = base / name
            relative = path.relative_to(root).as_posix()
            if forbidden_python_path(relative):
                remove_trees.add(path)
                names.remove(name)
        for name in [*names, *files]:
            path = base / name
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            relative = path.relative_to(root).as_posix()
            if stat.S_ISLNK(info.st_mode):
                try:
                    raw_target = os.readlink(path)
                except OSError:
                    raw_target = ""
                target_name = Path(raw_target).name
                target_forbidden = forbidden_tool_name(target_name)
                try:
                    target_info = path.stat()
                except (FileNotFoundError, OSError):
                    target_info = None
                alias_forbidden = (
                    target_info is not None
                    and bool(target_info.st_mode & 0o111)
                    and forbidden_tool_name(name)
                )
                if alias_forbidden or target_forbidden or forbidden_python_path(relative):
                    unlink_paths.add(path)
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                path.chmod(stat.S_IMODE(info.st_mode) & ~(stat.S_ISUID | stat.S_ISGID))
                info = path.lstat()
            identity = (info.st_dev, info.st_ino)
            inode_paths.setdefault(identity, []).append(path)
            if (
                forbidden_tool_name(name)
                or forbidden_python_path(relative)
                or shell_shebang(path)
            ):
                rejected_inodes.add(identity)

    for identity in rejected_inodes:
        unlink_paths.update(inode_paths.get(identity, ()))

    removed: list[str] = []
    for path in sorted(remove_trees, key=lambda item: len(item.parts), reverse=True):
        relative = path.relative_to(root).as_posix()
        try:
            if path.is_symlink():
                path.unlink()
            else:
                shutil.rmtree(path)
            removed.append(relative + "/")
        except FileNotFoundError:
            pass
    for path in sorted(unlink_paths, key=lambda item: len(item.parts), reverse=True):
        if any(tree == path or tree in path.parents for tree in remove_trees):
            continue
        try:
            path.unlink()
            removed.append(path.relative_to(root).as_posix())
        except FileNotFoundError:
            pass
    return sorted(removed)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("/"))
    args = parser.parse_args()
    removed = sanitize(args.root)
    print(f"sanitized forbidden runtime entries and aliases: {len(removed)}")
    for path in removed:
        print(path)


if __name__ == "__main__":
    main()
