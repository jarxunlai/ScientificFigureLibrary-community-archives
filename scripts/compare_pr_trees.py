#!/usr/bin/env python3
"""Validate one immutable archive addition or the exact invalid-seed withdrawal."""

from __future__ import annotations

import argparse
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


TEMPLATE_ID = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?", re.ASCII)
SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
    re.ASCII,
)
RESERVED = re.compile(r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$", re.I)
OID = re.compile(r"[a-f0-9]{40}(?:[a-f0-9]{24})?", re.ASCII)

# This is intentionally a closed, one-time allowlist.  It is not a general
# archive-removal mechanism: every path and the blob expected at that path are
# bound to the releases that were identified as invalid test seeds.
EXACT_INVALID_SEED_WITHDRAWAL = {
    "archives/ggsankeyfier-layout-color-combo/1.0.0/ggsankeyfier-layout-color-combo-1.0.0.zip": (
        "f7bf768bdceeec18757523dfc8f11c8b86c57ff6"
    ),
    "archives/single-cell-enrichment-bar-pathway-genes/1.0.0/"
    "single-cell-enrichment-bar-pathway-genes-1.0.0.zip": "55d6dcb349e012263da59bbff376194c06259444",
    "archives/umap-unchull-main-type-circles/1.0.0/umap-unchull-main-type-circles-1.0.0.zip": (
        "8ae2295402bdfa117837816b707c76c598b8bf88"
    ),
}


@dataclass(frozen=True)
class TreeEntry:
    mode: str
    kind: str
    oid: str


@dataclass(frozen=True)
class PolicyDecision:
    mode: Literal["add", "withdrawal"]
    archive: str | None = None
    withdrawn: tuple[str, ...] = ()


def valid_template_id(value: str) -> bool:
    return bool(TEMPLATE_ID.fullmatch(value)) and not RESERVED.fullmatch(value)


def git_tree(root: Path) -> dict[str, TreeEntry]:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root.resolve()), "ls-tree", "-r", "-z", "--full-tree", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = exc.stderr.decode("utf-8", "replace").strip() if isinstance(exc, subprocess.CalledProcessError) else str(exc)
        raise SystemExit(f"failed to read committed Git tree: {detail}") from None

    output: dict[str, TreeEntry] = {}
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            header, raw_path = raw.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split(" ", 2)
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            raise SystemExit("git ls-tree returned a malformed or non-UTF-8 entry") from None
        if path in output or not OID.fullmatch(oid):
            raise SystemExit(f"git tree contains a duplicate path or invalid object identity: {path!r}")
        output[path] = TreeEntry(mode=mode, kind=kind, oid=oid)
    return output


def validate_regular_blob_tree(tree: dict[str, TreeEntry], label: str) -> None:
    invalid = sorted(
        f"{name} ({entry.mode} {entry.kind})"
        for name, entry in tree.items()
        if entry.mode != "100644" or entry.kind != "blob"
    )
    if invalid:
        raise SystemExit(f"{label} tree contains a non-100644 blob (symlink, executable, gitlink, or special entry): {invalid}")


def validate_new_archive_path(archive: str) -> None:
    parts = archive.split("/")
    if len(parts) != 4 or parts[0] != "archives" or not archive.endswith(".zip"):
        raise SystemExit(f"new blob is outside the immutable archive layout: {archive}")
    template_id, release_version, filename = parts[1:]
    if not valid_template_id(template_id):
        raise SystemExit("templateId must be strict portable ASCII and not a Windows reserved name")
    if not SEMVER.fullmatch(release_version):
        raise SystemExit("releaseVersion must be strict SemVer 2.0 ASCII")
    if any(ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F for character in archive):
        raise SystemExit("archive path contains a control character")
    if any(character in archive for character in ("'", '"', "`", "\r", "\n")):
        raise SystemExit("archive path contains a shell or output delimiter")
    if filename != f"{template_id}-{release_version}.zip":
        raise SystemExit("archive filename does not match templateId and releaseVersion")


def validate_archive_tree_policy(
    base: dict[str, TreeEntry], candidate: dict[str, TreeEntry]
) -> PolicyDecision:
    """Fail closed to the normal one-add rule or one exact three-file withdrawal."""

    validate_regular_blob_tree(base, "base")
    validate_regular_blob_tree(candidate, "candidate")
    added = sorted(set(candidate) - set(base))
    deleted = sorted(set(base) - set(candidate))
    modified = sorted(name for name in set(base) & set(candidate) if base[name] != candidate[name])

    if not deleted and not modified and len(added) == 1:
        archive = added[0]
        validate_new_archive_path(archive)
        if archive in EXACT_INVALID_SEED_WITHDRAWAL:
            raise SystemExit("withdrawn invalid-seed archive identity is retired and may not be re-added")
        return PolicyDecision(mode="add", archive=archive)

    expected_deleted = sorted(EXACT_INVALID_SEED_WITHDRAWAL)
    if not added and not modified and deleted == expected_deleted:
        oid_mismatches = [
            f"{path} expected={EXACT_INVALID_SEED_WITHDRAWAL[path]} observed={base[path].oid}"
            for path in expected_deleted
            if base[path].oid != EXACT_INVALID_SEED_WITHDRAWAL[path]
        ]
        if oid_mismatches:
            raise SystemExit(
                "exact invalid-seed withdrawal base blob identity mismatch: "
                + "; ".join(oid_mismatches)
            )
        return PolicyDecision(mode="withdrawal", withdrawn=tuple(expected_deleted))

    raise SystemExit(
        "archive PR must either add exactly one committed 100644 blob and modify/delete none, "
        "or atomically delete only the three exact invalid-seed blobs with no additions or modifications; "
        f"added={added}, modified={modified}, deleted={deleted}"
    )


def validate_archive_tree_change(base: dict[str, TreeEntry], candidate: dict[str, TreeEntry]) -> str:
    """Compatibility helper for callers that require the normal archive-addition mode."""

    decision = validate_archive_tree_policy(base, candidate)
    if decision.mode != "add" or decision.archive is None:
        raise SystemExit("archive addition expected, but candidate is an exact withdrawal")
    archive = decision.archive
    return archive


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("base", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()

    decision = validate_archive_tree_policy(git_tree(args.base), git_tree(args.candidate))
    outputs = [f"mode={decision.mode}"]
    if decision.mode == "add":
        assert decision.archive is not None
        archive = decision.archive
        parts = archive.split("/")
        template_id, release_version = parts[1:3]
        archive_path = args.candidate.resolve() / Path(*parts)
        if not archive_path.is_file() or archive_path.is_symlink() or archive_path.stat().st_size > 100 * 1024 * 1024:
            raise SystemExit("committed archive blob is missing, non-regular, symlinked, or exceeds 100 MiB")
        workflow_path = f"candidate/{archive}"
        print(workflow_path)
        outputs.extend(
            (
                f"archive={workflow_path}",
                f"template_id={template_id}",
                f"release_version={release_version}",
            )
        )
    else:
        print("validated exact invalid-seed withdrawal:")
        for path in decision.withdrawn:
            print(path)
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8", newline="\n") as handle:
            for output in outputs:
                handle.write(output + "\n")


if __name__ == "__main__":
    main()
