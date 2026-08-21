#!/usr/bin/env python3
"""Validate/extract one public submission and verify its sandbox re-render."""

from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import unicodedata
import zipfile
import zlib
from pathlib import Path, PurePosixPath

MAX_ARCHIVE = 100 * 1024 * 1024
MAX_EXPANDED = 128 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_FILES = 10_000
SHA256 = re.compile(r"^[a-f0-9]{64}$")
ID = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
SEMVER = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$")
RESERVED = re.compile(r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$", re.I)
PRIVATE_PATH = re.compile(r"(?:\b[A-Za-z]:[\\/]|/(?:Users|home|mnt/[a-z]|private|var/folders)/)")


def fail(message: str) -> None:
    raise SystemExit(message)


def canonical_path(name: str) -> str:
    if not name or "\\" in name or "\x00" in name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        fail(f"unsafe ZIP path: {name!r}")
    if unicodedata.normalize("NFC", name) != name:
        fail(f"ZIP path is not NFC: {name!r}")
    directory = name.endswith("/")
    parts = name[:-1].split("/") if directory else name.split("/")
    if any(not part or part in {".", ".."} or part.endswith((".", " ")) or RESERVED.match(part) for part in parts):
        fail(f"non-portable ZIP path: {name!r}")
    normalized = PurePosixPath(*parts).as_posix() + ("/" if directory else "")
    if normalized != name:
        fail(f"non-canonical ZIP path: {name!r}")
    return normalized


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(root: Path, relative: str) -> dict:
    path = root / Path(*relative.split("/"))
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"invalid {relative}: {exc}")
    if not isinstance(value, dict):
        fail(f"{relative} must contain a JSON object")
    return value


def extract_and_validate(archive: Path, staging: Path) -> None:
    if not archive.is_file() or archive.is_symlink():
        fail("archive must be a regular file")
    if archive.stat().st_size > MAX_ARCHIVE:
        fail("archive exceeds 100 MiB")
    if staging.exists():
        fail("staging directory must not exist")
    staging.mkdir(parents=True)

    total = 0
    folded: dict[str, str] = {}
    files: list[zipfile.ZipInfo] = []
    with zipfile.ZipFile(archive, "r") as handle:
        infos = handle.infolist()
        if len(infos) > MAX_FILES:
            fail("archive contains more than 10,000 entries")
        for info in infos:
            safe = canonical_path(info.filename)
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                fail(f"archive contains a symlink: {safe}")
            if info.flag_bits & 1:
                fail(f"encrypted ZIP entry is forbidden: {safe}")
            if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                fail(f"unsupported ZIP compression for {safe}")
            key = safe.rstrip("/").casefold()
            if key in folded:
                fail(f"portable case-fold collision: {folded[key]}, {safe}")
            folded[key] = safe
            if info.is_dir():
                continue
            if info.file_size > MAX_FILE:
                fail(f"archive entry exceeds 64 MiB: {safe}")
            total += info.file_size
            if total > MAX_EXPANDED:
                fail("expanded archive exceeds 128 MiB")
            files.append(info)

        for info in sorted(files, key=lambda item: item.filename):
            target = staging / Path(*info.filename.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            with handle.open(info, "r") as source, target.open("xb") as destination:
                shutil.copyfileobj(source, destination, length=1024 * 1024)

    required = {
        "submission.json", "licenses.json", "render-receipt.json", "inventory.jsonl",
        "payload/template.json", "payload/code/render.R", "payload/preview/preview.png",
    }
    observed = {path.relative_to(staging).as_posix() for path in staging.rglob("*") if path.is_file()}
    missing = sorted(required - observed)
    if missing:
        fail(f"archive is missing required files: {missing}")
    if not any(name.startswith("payload/data/") for name in observed):
        fail("archive contains no synthetic input data")

    submission = read_json(staging, "submission.json")
    template = read_json(staging, "payload/template.json")
    licenses = read_json(staging, "licenses.json")
    receipt = read_json(staging, "render-receipt.json")
    if submission.get("schema") != "figure-library.publication-submission.v1":
        fail("unsupported submission schema")
    if template.get("schema") != "figure-library.public-template-archive.v1":
        fail("unsupported public-template archive schema")
    provider = "io.github.jarxunlai.scientific-figure-community"
    if submission.get("providerId") != provider or template.get("providerId") != provider:
        fail("central providerId mismatch")
    template_id = submission.get("templateId")
    version = submission.get("releaseVersion")
    if not isinstance(template_id, str) or not ID.fullmatch(template_id):
        fail("invalid templateId")
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        fail("invalid semantic releaseVersion")
    if template.get("templateId") != template_id or template.get("releaseVersion") != version:
        fail("submission/template identity mismatch")
    if not SHA256.fullmatch(str(submission.get("contentDigest", ""))) or template.get("contentDigest") != submission.get("contentDigest"):
        fail("content digest binding is invalid")
    if template.get("codeExecutedBySflClient") is not False:
        fail("template must state codeExecutedBySflClient=false")
    if licenses.get("code") != "MIT" or licenses.get("syntheticData") != "CC-BY-4.0" or licenses.get("preview") != "CC-BY-4.0" or licenses.get("documentation") != "CC-BY-4.0":
        fail("seed license declarations must be MIT / CC-BY-4.0")
    assets = submission.get("assets")
    if not isinstance(assets, list) or not assets:
        fail("submission asset declarations are missing")
    declared: dict[str, dict] = {}
    for asset in assets:
        if not isinstance(asset, dict) or not isinstance(asset.get("path"), str):
            fail("invalid submission asset declaration")
        name = canonical_path(asset["path"])
        if name.endswith("/") or name in declared or name not in observed:
            fail(f"invalid or duplicate declared asset: {name}")
        if asset.get("role") in {"source_reference", "evidence", "screenshot", "paper_pdf"}:
            fail(f"forbidden public asset role: {name}")
        if asset.get("include") is not True or asset.get("source") not in {"clean_room", "generated", "synthetic", "authored"}:
            fail(f"asset lacks explicit public inclusion/source declaration: {name}")
        data = (staging / Path(*name.split("/"))).read_bytes()
        if asset.get("bytes") != len(data) or asset.get("sha256") != sha256_bytes(data):
            fail(f"asset identity mismatch: {name}")
        declared[name] = asset

    inventory: list[dict] = []
    for line in (staging / "inventory.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            fail("invalid inventory entry")
        inventory.append(item)
    inventory_names = [item["path"] for item in inventory]
    if inventory_names != sorted(inventory_names) or len(inventory_names) != len(set(inventory_names)):
        fail("inventory must be unique and canonically ordered")
    expected_inventory = sorted(observed - {"inventory.jsonl"})
    if inventory_names != expected_inventory:
        fail("inventory is not the complete archive payload (excluding itself)")
    for item in inventory:
        name = canonical_path(item["path"])
        data = (staging / Path(*name.split("/"))).read_bytes()
        if item.get("bytes") != len(data) or item.get("sha256") != sha256_bytes(data):
            fail(f"inventory identity mismatch: {name}")

    for name in observed:
        path = staging / Path(*name.split("/"))
        if path.stat().st_size <= 4 * 1024 * 1024 and path.suffix.lower() in {".json", ".jsonl", ".md", ".txt", ".r", ".csv", ".tsv", ".yml", ".yaml"}:
            text = path.read_text(encoding="utf-8")
            if PRIVATE_PATH.search(text):
                fail(f"possible absolute/private machine path leaked in {name}")

    if receipt.get("schema") != "figure-library.render-receipt.v1" or receipt.get("entrypoint") != "payload/code/render.R":
        fail("invalid fixed render receipt")
    preview = (staging / "payload" / "preview" / "preview.png").read_bytes()
    if receipt.get("previewBytes") != len(preview) or receipt.get("previewSha256") != sha256_bytes(preview):
        fail("archived preview disagrees with render receipt")
    width, height, rgba = decode_png_rgba(preview)
    if receipt.get("width") != width or receipt.get("height") != height or receipt.get("mediaType") != "image/png":
        fail("preview dimensions/media type disagree with render receipt")
    if receipt.get("canonicalRgbaSha256") != sha256_bytes(rgba):
        fail("archived preview canonical RGBA digest disagrees with render receipt")


def paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    return a if pa <= pb and pa <= pc else b if pb <= pc else c


def decode_png_rgba(data: bytes) -> tuple[int, int, bytes]:
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        fail("preview is not a PNG")
    offset = 8
    ihdr = None
    idat = bytearray()
    palette = None
    transparency = None
    saw_iend = False
    while offset + 12 <= len(data):
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        kind = data[offset + 4:offset + 8]
        payload = data[offset + 8:offset + 8 + length]
        crc = struct.unpack(">I", data[offset + 8 + length:offset + 12 + length])[0]
        if len(payload) != length or (binascii.crc32(kind + payload) & 0xFFFFFFFF) != crc:
            fail("PNG chunk length/CRC is invalid")
        offset += 12 + length
        if kind == b"IHDR": ihdr = payload
        elif kind == b"IDAT": idat.extend(payload)
        elif kind == b"PLTE": palette = payload
        elif kind == b"tRNS": transparency = payload
        elif kind == b"IEND": saw_iend = True; break
    if ihdr is None or len(ihdr) != 13 or not saw_iend:
        fail("PNG is missing IHDR/IEND")
    width, height, depth, color_type, compression, filtering, interlace = struct.unpack(">IIBBBBB", ihdr)
    if depth != 8 or compression != 0 or filtering != 0 or interlace != 0 or width < 1 or height < 1 or width > 16384 or height > 16384:
        fail("PNG uses unsupported or unsafe encoding")
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color_type)
    if channels is None:
        fail("PNG color type is unsupported")
    stride = width * channels
    try:
        raw = zlib.decompress(bytes(idat))
    except Exception as exc:
        fail(f"PNG IDAT decompression failed: {exc}")
    if len(raw) != height * (stride + 1):
        fail("PNG decompressed size is inconsistent")
    rows: list[bytearray] = []
    pos = 0
    prior = bytearray(stride)
    for _ in range(height):
        filter_type = raw[pos]; pos += 1
        scan = bytearray(raw[pos:pos + stride]); pos += stride
        for i, value in enumerate(scan):
            left = scan[i - channels] if i >= channels else 0
            up = prior[i]
            upper_left = prior[i - channels] if i >= channels else 0
            if filter_type == 1: scan[i] = (value + left) & 255
            elif filter_type == 2: scan[i] = (value + up) & 255
            elif filter_type == 3: scan[i] = (value + ((left + up) // 2)) & 255
            elif filter_type == 4: scan[i] = (value + paeth(left, up, upper_left)) & 255
            elif filter_type != 0: fail("PNG uses an invalid filter")
        rows.append(scan); prior = scan
    rgba = bytearray()
    for row in rows:
        for x in range(width):
            pixel = row[x * channels:(x + 1) * channels]
            if color_type == 0: rgba.extend((pixel[0], pixel[0], pixel[0], 255))
            elif color_type == 2: rgba.extend((pixel[0], pixel[1], pixel[2], 255))
            elif color_type == 3:
                index = pixel[0]
                if palette is None or index * 3 + 2 >= len(palette): fail("PNG palette index is invalid")
                alpha = transparency[index] if transparency is not None and index < len(transparency) else 255
                rgba.extend((*palette[index * 3:index * 3 + 3], alpha))
            elif color_type == 4: rgba.extend((pixel[0], pixel[0], pixel[0], pixel[1]))
            else: rgba.extend(pixel)
    return width, height, bytes(rgba)


def post_render(staging: Path, rendered: Path) -> None:
    receipt = read_json(staging, "render-receipt.json")
    actual = rendered.read_bytes()
    width, height, rgba = decode_png_rgba(actual)
    if width != receipt.get("width") or height != receipt.get("height"):
        fail("sandbox re-rendered PNG dimensions differ from receipt")
    if sha256_bytes(rgba) != receipt.get("canonicalRgbaSha256"):
        fail("sandbox re-rendered canonical RGBA digest differs from receipt")
    print(json.dumps({"status": "ci_rendered", "width": width, "height": height, "renderedPreviewSha256": sha256_bytes(actual), "archivedPreviewSha256": receipt.get("previewSha256"), "canonicalRgbaSha256": sha256_bytes(rgba)}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--rendered", type=Path)
    args = parser.parse_args()
    staging = args.staging.resolve()
    if args.archive:
        extract_and_validate(args.archive.resolve(), staging)
        print(f"validated and extracted {args.archive}")
    elif args.rendered:
        post_render(staging, args.rendered.resolve())
    else:
        fail("choose --archive or --rendered")


if __name__ == "__main__":
    main()
