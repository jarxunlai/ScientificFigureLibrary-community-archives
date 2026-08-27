#!/usr/bin/env python3
"""Audit a trusted renderer rootfs export without extracting it.

The bootstrap renderer is deliberately disabled for Archive intake.  This
audit binds the exact image that will be pushed to an executable inventory and
fails closed when package/install/download/build tools, ordinary shells, unsafe
special files, privilege bits, or aliases to forbidden tools remain.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import stat
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "renderer"))
from runtime_boundary import forbidden_python_path, forbidden_tool_name  # noqa: E402


INVENTORY_SCHEMA = "figure-library.archive-renderer-rootfs-inventory.v1"
REQUIRED_EXECUTABLES = (
    "opt/sfl/.pixi/envs/default/bin/Rscript",
    "opt/sfl/.pixi/envs/default/bin/python",
    "opt/sfl/runner.py",
)
VIRTUAL_TOP_LEVEL = frozenset({"dev", "proc", "run", "sys", "tmp"})

@dataclass(frozen=True)
class RootfsEntry:
    path: str
    kind: str
    mode: int
    size: int
    link_target: str | None
    member: tarfile.TarInfo


def fail(message: str) -> None:
    raise SystemExit(message)


def canonical_path(raw: str) -> str:
    value = raw.replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    value = value.rstrip("/")
    if not value or value.startswith("/") or "\x00" in value:
        fail(f"rootfs tar contains an invalid absolute/empty/NUL path: {raw!r}")
    if any(ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F for character in value):
        fail(f"rootfs tar path contains a control character: {raw!r}")
    parts = PurePosixPath(value).parts
    if any(part in {"", ".", ".."} for part in parts):
        fail(f"rootfs tar path is not canonical: {raw!r}")
    return "/".join(parts)


def link_destination(path: str, raw_target: str, *, hardlink: bool) -> str:
    target = raw_target.replace("\\", "/")
    if "\x00" in target or any(ord(character) < 0x20 for character in target):
        fail(f"rootfs link contains an invalid target: {path!r}")
    if target.startswith("/"):
        combined = target.lstrip("/")
    elif hardlink:
        # Docker export hard-link names are archive-root relative.
        combined = target
    else:
        combined = posixpath.join(posixpath.dirname(path), target)
    normalized = posixpath.normpath(combined)
    if normalized in {"", ".", ".."} or normalized.startswith("../") or normalized.startswith("/"):
        fail(f"rootfs link escapes the image root: {path!r} -> {raw_target!r}")
    return canonical_path(normalized)


def load_entries(handle: tarfile.TarFile) -> dict[str, RootfsEntry]:
    entries: dict[str, RootfsEntry] = {}
    for member in handle:
        path = canonical_path(member.name)
        if PurePosixPath(path).parts[0] in VIRTUAL_TOP_LEVEL:
            continue
        if path in entries:
            fail(f"rootfs tar contains a duplicate canonical path: {path}")
        if member.ischr() or member.isblk() or member.isfifo() or member.isdev():
            fail(f"rootfs tar contains a device/FIFO/special entry: {path}")
        if member.isfile():
            kind = "file"
            target = None
            if member.mode & (stat.S_ISUID | stat.S_ISGID):
                fail(f"rootfs tar contains setuid/setgid file privilege bits: {path}")
            if any("security.capability" in key for key in member.pax_headers):
                fail(f"rootfs tar contains file capabilities: {path}")
        elif member.isdir():
            kind = "directory"
            target = None
        elif member.issym():
            kind = "symlink"
            target = link_destination(path, member.linkname, hardlink=False)
        elif member.islnk():
            kind = "hardlink"
            target = link_destination(path, member.linkname, hardlink=True)
        else:
            fail(f"rootfs tar contains an unsupported entry type: {path}")
        entries[path] = RootfsEntry(path, kind, member.mode, member.size, target, member)
    return entries


def resolve_file(path: str, entries: dict[str, RootfsEntry]) -> RootfsEntry | None:
    observed: set[str] = set()
    current = path
    while True:
        if current in observed:
            fail(f"rootfs link cycle detected at: {path}")
        observed.add(current)
        entry = entries.get(current)
        if entry is None:
            return None
        if entry.kind == "file":
            return entry
        if entry.kind not in {"symlink", "hardlink"}:
            return None
        assert entry.link_target is not None
        current = entry.link_target


def streamed_member_sha256(handle: tarfile.TarFile, member: tarfile.TarInfo) -> str:
    source = handle.extractfile(member)
    if source is None:
        fail(f"failed to read rootfs regular file: {member.name}")
    digest = hashlib.sha256()
    while True:
        chunk = source.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def audit_rootfs(archive: Path) -> dict[str, object]:
    if not archive.is_file() or archive.is_symlink():
        fail("rootfs archive must be one regular non-symlink file")
    with tarfile.open(archive, "r:") as handle:
        entries = load_entries(handle)

        violations: list[str] = []
        for entry in entries.values():
            own_name = PurePosixPath(entry.path).name
            target_name = PurePosixPath(entry.link_target).name if entry.link_target else None
            forbidden_named_executable = entry.kind == "file" and bool(entry.mode & 0o111) and forbidden_tool_name(own_name)
            resolved_link = resolve_file(entry.path, entries) if entry.kind in {"symlink", "hardlink"} else None
            forbidden_link = entry.kind in {"symlink", "hardlink"} and (
                (resolved_link is not None and bool(resolved_link.mode & 0o111) and forbidden_tool_name(own_name))
                or (target_name is not None and forbidden_tool_name(target_name))
            )
            if forbidden_named_executable or forbidden_link:
                violations.append(f"forbidden tool or alias: {entry.path}" + (f" -> {entry.link_target}" if entry.link_target else ""))
            if forbidden_python_path(entry.path):
                violations.append(f"forbidden Python installer module: {entry.path}")

        executable_rows: list[dict[str, object]] = []
        digest_cache: dict[str, str] = {}
        for path in sorted(entries):
            entry = entries[path]
            resolved = resolve_file(path, entries)
            if resolved is None or not (resolved.mode & 0o111):
                continue
            names = {PurePosixPath(path).name, PurePosixPath(resolved.path).name}
            if entry.link_target:
                names.add(PurePosixPath(entry.link_target).name)
            if any(forbidden_tool_name(name) for name in names):
                violations.append(f"forbidden executable identity: {path} resolves to {resolved.path}")
            if resolved.path not in digest_cache:
                digest_cache[resolved.path] = streamed_member_sha256(handle, resolved.member)
            executable_rows.append(
                {
                    "path": path,
                    "kind": entry.kind,
                    "mode": f"{entry.mode & 0o7777:04o}",
                    "resolvedPath": resolved.path,
                    "bytes": resolved.size,
                    "sha256": digest_cache[resolved.path],
                }
            )

        for required in REQUIRED_EXECUTABLES:
            resolved = resolve_file(required, entries)
            if resolved is None or not (resolved.mode & 0o111):
                violations.append(f"required renderer executable is missing or non-executable: {required}")

        if violations:
            fail("renderer rootfs executable boundary failed:\n" + "\n".join(f"- {item}" for item in sorted(set(violations))))

        return {
            "schema": INVENTORY_SCHEMA,
            "archive": archive.name,
            "entryCount": len(entries),
            "executableCount": len(executable_rows),
            "requiredExecutables": list(REQUIRED_EXECUTABLES),
            "executables": executable_rows,
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--inventory", type=Path, required=True)
    args = parser.parse_args()
    inventory = audit_rootfs(args.archive)
    payload = json.dumps(inventory, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(args.inventory, flags, 0o600)
    except FileExistsError:
        fail("rootfs inventory target must not already exist")
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
        output.write(payload)
    print(
        json.dumps(
            {
                "schema": INVENTORY_SCHEMA,
                "entryCount": inventory["entryCount"],
                "executableCount": inventory["executableCount"],
                "inventorySha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
