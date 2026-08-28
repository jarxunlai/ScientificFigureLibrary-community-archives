#!/usr/bin/env python3
"""Validate/extract one public submission and verify its sandbox re-render."""

from __future__ import annotations

import argparse
import binascii
import csv
import hashlib
import io
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
MAX_JSON = 1024 * 1024
MAX_TEXT_SCAN = 4 * 1024 * 1024
SHA256 = re.compile(r"^[a-f0-9]{64}$")
ID = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$", re.ASCII)
SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$",
    re.ASCII,
)
RESERVED = re.compile(r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$", re.I)
PRIVATE_PATH = re.compile(
    r"(?:\b[A-Za-z]:[\\/]|\\\\[^\\\s]+\\[^\\\s]+|"
    r"(?:^|[\s\"'`(=])/(?:Users|home|mnt/[A-Za-z]|private|var|tmp|etc|opt|root|srv|Volumes|workspace|data)/|"
    r"(?:%APPDATA%|%LOCALAPPDATA%|\$HOME|\$XDG_(?:CONFIG|DATA)_HOME)[\\/])",
    re.I | re.M,
)
PROVIDER = "io.github.jarxunlai.scientific-figure-community"
CC_BY = "CC-BY-4.0"
FIXED_METADATA_FILES = {
    "submission.json",
    "licenses.json",
    "render-receipt.json",
    "inventory.jsonl",
    "payload/template.json",
}
BINARY_MAGIC = (
    b"%PDF-",
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
    b"GIF87a",
    b"GIF89a",
    b"MZ",
    b"\x7fELF",
    b"\x1f\x8b",
    b"Rar!\x1a\x07",
    b"7z\xbc\xaf'\x1c",
)


def fail(message: str) -> None:
    raise SystemExit(message)


def canonical_path(name: str) -> str:
    if (
        not name or "\\" in name or name.startswith("/") or re.match(r"^[A-Za-z]:", name) or
        any(ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F for character in name) or
        any(character in name for character in '<>:"|?*')
    ):
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


def valid_template_id(value: str) -> bool:
    return bool(ID.fullmatch(value)) and not RESERVED.fullmatch(value)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def exact_keys(value: object, expected: set[str], label: str) -> dict:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        fail(f"{label} fields differ: missing={sorted(expected - actual)}, extra={sorted(actual - expected)}")
    return value


def nonempty_text(value: object, label: str, maximum: int = 4000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        fail(f"{label} must be non-empty text no longer than {maximum} characters")
    if PRIVATE_PATH.search(value):
        fail(f"{label} contains an absolute/private machine path")
    return value


def path_list(value: object, label: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        fail(f"{label} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
    output: list[str] = []
    for raw in value:
        if not isinstance(raw, str):
            fail(f"{label} contains a non-string path")
        name = canonical_path(raw)
        if name.endswith("/"):
            fail(f"{label} contains a directory path: {name}")
        output.append(name)
    if len(output) != len(set(output)):
        fail(f"{label} contains duplicate paths")
    return output


def read_json(root: Path, relative: str) -> dict:
    path = root / Path(*relative.split("/"))
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_JSON:
            fail(f"{relative} exceeds the 1 MiB metadata limit")
        if raw.startswith(b"\xef\xbb\xbf"):
            fail(f"{relative} must be UTF-8 without BOM")
        value = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        fail(f"invalid {relative}: {exc}")
    if not isinstance(value, dict):
        fail(f"{relative} must contain a JSON object")
    return value


def validate_inventory(staging: Path, observed: set[str]) -> None:
    inventory_path = staging / "inventory.jsonl"
    if inventory_path.stat().st_size > 4 * 1024 * 1024:
        fail("inventory.jsonl exceeds 4 MiB")
    try:
        raw_inventory = inventory_path.read_bytes()
        if raw_inventory.startswith(b"\xef\xbb\xbf"):
            fail("inventory.jsonl must be UTF-8 without BOM")
        lines = raw_inventory.decode("utf-8").splitlines()
    except Exception as exc:
        fail(f"invalid inventory.jsonl: {exc}")
    inventory: list[dict] = []
    for line in lines:
        if not line:
            fail("inventory.jsonl contains an empty line")
        try:
            item = json.loads(line)
        except Exception as exc:
            fail(f"invalid inventory entry: {exc}")
        inventory.append(exact_keys(item, {"path", "bytes", "sha256"}, "inventory entry"))
    inventory_names = [item["path"] for item in inventory]
    if inventory_names != sorted(inventory_names) or len(inventory_names) != len(set(inventory_names)):
        fail("inventory must be unique and canonically ordered")
    expected_inventory = sorted(observed - {"inventory.jsonl"})
    if inventory_names != expected_inventory:
        fail("inventory is not the complete archive payload (excluding itself)")
    for item in inventory:
        name = canonical_path(item["path"]) if isinstance(item["path"], str) else fail("invalid inventory path")
        data = (staging / Path(*name.split("/"))).read_bytes()
        if not isinstance(item["bytes"], int) or isinstance(item["bytes"], bool) or item["bytes"] != len(data) or not isinstance(item["sha256"], str) or not SHA256.fullmatch(item["sha256"]) or item["sha256"] != sha256_bytes(data):
            fail(f"inventory identity mismatch: {name}")


def validate_private_text(staging: Path, observed: set[str]) -> None:
    text_extensions = {".json", ".jsonl", ".md", ".txt", ".r", ".py", ".jl", ".m", ".sh", ".csv", ".tsv", ".yml", ".yaml"}
    for name in observed:
        path = staging / Path(*name.split("/"))
        extension = path.suffix.lower()
        if extension not in text_extensions:
            continue
        size = path.stat().st_size
        if size > MAX_TEXT_SCAN:
            fail(f"public text asset exceeds the 4 MiB fully-scanned limit: {name}")
        raw = path.read_bytes()
        stripped = raw.lstrip(b" \t\r\n")
        if any(stripped.startswith(magic) for magic in BINARY_MAGIC):
            fail(f"public text asset contains disguised binary content: {name}")
        if raw.startswith(b"\xef\xbb\xbf") or b"\x00" in raw:
            fail(f"public text asset must be UTF-8 without BOM or NUL: {name}")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            fail(f"public text asset is not valid UTF-8: {name}")
        if not text.strip():
            fail(f"public text asset must be non-empty: {name}")
        if PRIVATE_PATH.search(text):
            fail(f"possible absolute/private machine path leaked in {name}")
        if extension == ".json":
            try:
                json.loads(text)
            except Exception as exc:
                fail(f"public JSON asset is invalid: {name}: {exc}")
        elif extension in {".csv", ".tsv"}:
            try:
                rows = list(csv.reader(io.StringIO(text, newline=""), delimiter="," if extension == ".csv" else "\t", strict=True))
            except (csv.Error, UnicodeError) as exc:
                fail(f"public delimited-text asset is invalid: {name}: {exc}")
            if len(rows) < 2 or not rows[0] or any(len(row) != len(rows[0]) for row in rows):
                fail(f"public delimited-text asset requires a header, a data row, and a consistent column count: {name}")


def validate_declared_file_set(observed: set[str], declared: set[str]) -> None:
    expected = FIXED_METADATA_FILES | declared
    missing = sorted(expected - observed)
    unexpected = sorted(observed - expected)
    if missing or unexpected:
        fail(f"archive file set differs from fixed metadata and declared assets: missing={missing}, unexpected={unexpected}")


def build_isolated_render_root(staging: Path, render_root: Path, render_files: set[str]) -> None:
    if render_root.exists():
        fail("isolated render root must not exist")
    try:
        render_root.relative_to(staging)
    except ValueError:
        pass
    else:
        fail("isolated render root must be outside the extracted archive")
    if "payload/code/render.R" not in render_files or not any(name.startswith("payload/data/") for name in render_files):
        fail("isolated render root lacks the fixed entrypoint or synthetic input data")
    for name in render_files:
        canonical_path(name)
        if not (name.startswith("payload/code/") or name.startswith("payload/data/")):
            fail(f"isolated render root contains a non-render asset: {name}")

    render_root.mkdir(parents=True)
    for name in sorted(render_files):
        source = staging / Path(*name.split("/"))
        if not source.is_file() or source.is_symlink():
            fail(f"isolated render input is not a regular extracted file: {name}")
        target = render_root / Path(*name.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as input_handle, target.open("xb") as output_handle:
            shutil.copyfileobj(input_handle, output_handle, length=1024 * 1024)


def validate_expected_archive_identity(template_id: str, version: str, expected_template_id: str, expected_release_version: str) -> None:
    if not valid_template_id(expected_template_id) or not SEMVER.fullmatch(expected_release_version):
        fail("expected outer archive identity is invalid")
    if template_id != expected_template_id or version != expected_release_version:
        fail(
            "outer archive path identity disagrees with submission/template identity: "
            f"expected={expected_template_id}@{expected_release_version}, observed={template_id}@{version}"
        )


def validate_submission_contract(
    staging: Path,
    observed: set[str],
    expected_template_id: str,
    expected_release_version: str,
) -> set[str]:
    submission = exact_keys(read_json(staging, "submission.json"), {
        "schema", "providerId", "templateId", "releaseVersion", "contentDigest",
        "parentLocalRelease", "assets", "rightsAttestation", "excludedPrivateState", "createdAt",
    }, "publication submission")
    template = exact_keys(read_json(staging, "payload/template.json"), {
        "schema", "providerId", "templateId", "releaseVersion", "contentDigest",
        "metadata", "licenses", "render", "codeExecutedBySflClient",
    }, "public-template archive")
    licenses = read_json(staging, "licenses.json")
    receipt = read_json(staging, "render-receipt.json")
    if submission["schema"] != "figure-library.publication-submission.v1" or template["schema"] != "figure-library.public-template-archive.v1":
        fail("unsupported submission or public-template schema")
    if submission["providerId"] != PROVIDER or template["providerId"] != PROVIDER:
        fail("central providerId mismatch")
    template_id = submission["templateId"]
    version = submission["releaseVersion"]
    content_digest = submission["contentDigest"]
    if not isinstance(template_id, str) or not valid_template_id(template_id):
        fail("invalid templateId")
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        fail("invalid strict SemVer 2.0 releaseVersion")
    if not isinstance(content_digest, str) or not SHA256.fullmatch(content_digest):
        fail("invalid contentDigest")
    if template["templateId"] != template_id or template["releaseVersion"] != version or template["contentDigest"] != content_digest:
        fail("submission/template identity mismatch")
    validate_expected_archive_identity(template_id, version, expected_template_id, expected_release_version)
    if template["codeExecutedBySflClient"] is not False:
        fail("template must state codeExecutedBySflClient=false")

    rights = submission["rightsAttestation"]
    export_rights = {"publisher", "codeRightsConfirmed", "syntheticDataConfirmed", "generatedPreviewConfirmed", "noThirdPartyMediaConfirmed", "immutableReleaseAcknowledged"}
    seed_rights = {"codeLicense", "contentLicense", "cleanRoomAuthored", "syntheticDataOnly", "previewGeneratedByIncludedCodeAndData", "thirdPartyMediaIncluded", "screenshotsIncluded", "paperOrPdfContentIncluded", "patientOrExperimentalDataIncluded"}
    if isinstance(rights, dict) and set(rights) == export_rights:
        flavor = "publication_export"
        nonempty_text(rights["publisher"], "rightsAttestation.publisher", 200)
        if any(rights[name] is not True for name in export_rights - {"publisher"}):
            fail("publication-export rightsAttestation is incomplete")
        exact_keys(submission["parentLocalRelease"], {"relationship", "explicitlySelectedAssetsOnly", "privateLifecycleIdentifiersIncluded"}, "publication-export parentLocalRelease")
        parent = submission["parentLocalRelease"]
        if parent != {"relationship": "sanitized-export-from-local-published", "explicitlySelectedAssetsOnly": True, "privateLifecycleIdentifiersIncluded": False}:
            fail("publication-export parentLocalRelease is invalid")
        exact_keys(licenses, {"schema", "code", "syntheticData", "preview", "documentation"}, "publication-export licenses")
    elif isinstance(rights, dict) and set(rights) == seed_rights:
        flavor = "frozen_clean_room_seed"
        expected_rights = {"codeLicense": "MIT", "contentLicense": CC_BY, "cleanRoomAuthored": True, "syntheticDataOnly": True, "previewGeneratedByIncludedCodeAndData": True, "thirdPartyMediaIncluded": False, "screenshotsIncluded": False, "paperOrPdfContentIncluded": False, "patientOrExperimentalDataIncluded": False}
        if rights != expected_rights:
            fail("frozen clean-room seed rightsAttestation is invalid")
        exact_keys(submission["parentLocalRelease"], {"relationship", "bytesCopied", "metadataCopied", "privateAssetsIncluded"}, "seed parentLocalRelease")
        parent = submission["parentLocalRelease"]
        if parent != {"relationship": "design-and-exclusion-audit-only", "bytesCopied": False, "metadataCopied": False, "privateAssetsIncluded": False}:
            fail("frozen clean-room seed parentLocalRelease is invalid")
        exact_keys(licenses, {"schema", "code", "syntheticData", "preview", "documentation", "assetLicenses"}, "seed licenses")
    else:
        fail("rightsAttestation matches neither supported submission contract")
    if licenses["schema"] != "figure-library.publication-licenses.v1" or licenses["code"] != "MIT" or any(licenses[name] != CC_BY for name in ("syntheticData", "preview", "documentation")):
        fail("public license declarations must be MIT / CC-BY-4.0")

    excluded = submission["excludedPrivateState"]
    if not isinstance(excluded, list) or not excluded or any(not isinstance(item, str) or not item.strip() or PRIVATE_PATH.search(item) for item in excluded):
        fail("excludedPrivateState must be unique safe non-empty labels")
    if len(excluded) != len(set(excluded)):
        fail("excludedPrivateState must not contain duplicate labels")
    if not isinstance(submission["createdAt"], str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", submission["createdAt"], re.ASCII):
        fail("createdAt must be an RFC 3339 UTC timestamp")

    assets = submission["assets"]
    if not isinstance(assets, list) or not assets:
        fail("submission asset declarations are missing")
    declared: dict[str, dict] = {}
    by_role: dict[str, list[str]] = {}
    preview_trace: list[str] = []
    base_asset_keys = {"path", "role", "include", "source", "license", "bytes", "sha256"}
    for raw in assets:
        if not isinstance(raw, dict) or not isinstance(raw.get("path"), str):
            fail("invalid submission asset declaration")
        role = raw.get("role")
        expected_keys = base_asset_keys | ({"generatedFrom"} if flavor == "publication_export" and role == "generated_preview" else set())
        asset = exact_keys(raw, expected_keys, "submission asset")
        name = canonical_path(asset["path"])
        if name.endswith("/") or name in declared or name not in observed or asset["include"] is not True:
            fail(f"invalid, duplicate, or absent declared asset: {name}")
        if role in {"source_reference", "evidence", "screenshot", "paper_pdf"}:
            fail(f"forbidden public asset role: {name}")
        if flavor == "publication_export":
            allowed_roles = {"code", "synthetic_data", "generated_preview", "documentation"}
            allowed_sources = {"clean_room", "generated", "synthetic", "authored"}
        else:
            allowed_roles = {"metadata", "render_code", "synthetic_data", "generated_preview", "documentation"}
            allowed_sources = {"metadata": {"authored"}, "render_code": {"clean_room", "authored"}, "synthetic_data": {"synthetic"}, "generated_preview": {"generated"}, "documentation": {"authored"}}
        if role not in allowed_roles or (flavor == "publication_export" and asset["source"] not in allowed_sources) or (flavor != "publication_export" and asset["source"] not in allowed_sources[role]):
            fail(f"asset source/role contract is invalid: {name}")
        normalized_role = "code" if role == "render_code" else role
        expected_prefix = {"metadata": "payload/template.json", "code": "payload/code/", "synthetic_data": "payload/data/", "generated_preview": "payload/preview/", "documentation": "payload/docs/"}[normalized_role]
        if (normalized_role == "metadata" and name != expected_prefix) or (normalized_role != "metadata" and not name.startswith(expected_prefix)):
            fail(f"asset role/path mismatch: {name}")
        extension = PurePosixPath(name).suffix.lower()
        extension_ok = (normalized_role == "metadata" and name == "payload/template.json") or (normalized_role == "code" and extension in {".r", ".py", ".jl", ".m", ".sh"}) or (normalized_role == "synthetic_data" and extension in {".csv", ".tsv", ".json", ".txt"}) or (normalized_role == "generated_preview" and name == "payload/preview/preview.png") or (normalized_role == "documentation" and extension in {".md", ".txt"})
        if not extension_ok:
            fail(f"asset type is outside the code-generated publication policy: {name}")
        expected_license = "MIT" if normalized_role == "code" else CC_BY
        if asset["license"] != expected_license:
            fail(f"asset license mismatch: {name}")
        data = (staging / Path(*name.split("/"))).read_bytes()
        if not isinstance(asset["bytes"], int) or isinstance(asset["bytes"], bool) or asset["bytes"] != len(data) or not isinstance(asset["sha256"], str) or not SHA256.fullmatch(asset["sha256"]) or asset["sha256"] != sha256_bytes(data):
            fail(f"asset identity mismatch: {name}")
        if flavor == "publication_export" and role == "generated_preview":
            preview_trace = path_list(asset["generatedFrom"], "generated preview trace")
        declared[name] = asset
        by_role.setdefault(role, []).append(name)
    required_roles = {"code", "synthetic_data", "generated_preview", "documentation"} if flavor == "publication_export" else {"metadata", "render_code", "synthetic_data", "generated_preview", "documentation"}
    if any(not by_role.get(role) for role in required_roles) or len(by_role.get("generated_preview", [])) != 1:
        fail("submission lacks a required asset role or contains multiple generated previews")
    if flavor == "frozen_clean_room_seed" and (by_role["metadata"] != ["payload/template.json"] or by_role["render_code"] != ["payload/code/render.R"]):
        fail("seed must declare exactly the fixed metadata and render entrypoint")
    validate_declared_file_set(observed, set(declared))
    if flavor == "frozen_clean_room_seed":
        asset_licenses = licenses["assetLicenses"]
        if not isinstance(asset_licenses, dict) or set(asset_licenses) != set(declared) or any(asset_licenses[name] != declared[name]["license"] for name in declared):
            fail("seed assetLicenses must exactly bind every declared asset")

    if receipt.get("schema") != "figure-library.render-receipt.v1" or receipt.get("entrypoint") != "payload/code/render.R":
        fail("invalid fixed render receipt")
    if flavor == "publication_export":
        exact_keys(receipt, {"schema", "entrypoint", "inputPaths", "codePaths", "previewPath", "previewBytes", "previewSha256", "mediaType", "width", "height", "canonicalRgbaSha256", "sourceExecution", "codeExecutedBySflClient"}, "publication-export render receipt")
        code_paths = path_list(receipt["codePaths"], "render code paths")
        input_paths = path_list(receipt["inputPaths"], "render input paths")
        if receipt["previewPath"] != "payload/preview/preview.png" or receipt["sourceExecution"] != "publisher_attested" or receipt["codeExecutedBySflClient"] is not False:
            fail("publication-export render authority fields are invalid")
        if "payload/code/render.R" not in code_paths or set(code_paths) != set(by_role["code"]) or set(input_paths) != set(by_role["synthetic_data"]) or set(preview_trace) != set(code_paths + input_paths):
            fail("publication-export render trace does not exactly bind code, data, and preview")
    else:
        exact_keys(receipt, {"schema", "entrypoint", "inputFiles", "code", "output", "publisherRuntime", "reviewedCiRuntime", "randomSeed", "previewBytes", "previewSha256", "width", "height", "mediaType", "canonicalRgbaSha256", "generatedFromSubmittedCodeAndSyntheticData"}, "seed render receipt")
        if receipt["generatedFromSubmittedCodeAndSyntheticData"] is not True:
            fail("seed preview lacks included-code/data provenance")
        code = exact_keys(receipt["code"], {"path", "bytes", "sha256", "license"}, "seed render code")
        code_path = canonical_path(code["path"]) if isinstance(code["path"], str) else fail("invalid seed render code path")
        code_data = (staging / Path(*code_path.split("/"))).read_bytes()
        if code_path != "payload/code/render.R" or code_path not in by_role["render_code"] or code["bytes"] != len(code_data) or code["sha256"] != sha256_bytes(code_data) or code["license"] != "MIT":
            fail("seed render code identity is invalid")
        if not isinstance(receipt["inputFiles"], list) or not receipt["inputFiles"]:
            fail("seed render receipt lacks synthetic inputs")
        input_paths = []
        for raw in receipt["inputFiles"]:
            item = exact_keys(raw, {"path", "bytes", "sha256"}, "seed render input")
            input_path = canonical_path(item["path"]) if isinstance(item["path"], str) else fail("invalid seed input path")
            data = (staging / Path(*input_path.split("/"))).read_bytes()
            if input_path not in by_role["synthetic_data"] or item["bytes"] != len(data) or item["sha256"] != sha256_bytes(data):
                fail(f"seed input identity is invalid: {input_path}")
            input_paths.append(input_path)
        if set(input_paths) != set(by_role["synthetic_data"]):
            fail("seed render receipt must bind every synthetic input")
        output = exact_keys(receipt["output"], {"path", "license"}, "seed render output")
        if output != {"path": "payload/preview/preview.png", "license": CC_BY}:
            fail("seed render output identity is invalid")
        if not isinstance(receipt["publisherRuntime"], dict) or receipt["publisherRuntime"].get("engine") != "R" or not isinstance(receipt["reviewedCiRuntime"], dict) or receipt["reviewedCiRuntime"].get("engine") != "R" or receipt["reviewedCiRuntime"].get("networkRequired") is not False:
            fail("seed runtime attestation is invalid")
        code_paths = [code_path]

    preview = (staging / "payload" / "preview" / "preview.png").read_bytes()
    if receipt.get("previewBytes") != len(preview) or receipt.get("previewSha256") != sha256_bytes(preview) or receipt.get("mediaType") != "image/png":
        fail("archived preview disagrees with render receipt")
    width, height, rgba = decode_png_rgba(preview, strict_chunks=False)
    if receipt.get("width") != width or receipt.get("height") != height or receipt.get("canonicalRgbaSha256") != sha256_bytes(rgba):
        fail("preview pixel identity disagrees with render receipt")

    template_licenses = exact_keys(template["licenses"], {"code", "syntheticData", "preview", "documentation"}, "public-template licenses")
    if template_licenses != {"code": "MIT", "syntheticData": CC_BY, "preview": CC_BY, "documentation": CC_BY}:
        fail("public-template licenses are invalid")
    metadata = template["metadata"]
    render = template["render"]
    if flavor == "publication_export":
        metadata = exact_keys(metadata, {"title", "description", "application", "dataProfile", "plotFamily", "language", "tags", "provenance", "upstreamStatus", "publisherVerified", "curationStatus", "renderValidation", "localReviewStatus", "plotExecutionByRecipient"}, "publication-export metadata")
        for name, maximum in (("title", 300), ("description", 4000), ("application", 4000), ("dataProfile", 4000), ("plotFamily", 200), ("language", 100)):
            nonempty_text(metadata[name], f"template metadata {name}", maximum)
        if not isinstance(metadata["tags"], list) or len(metadata["tags"]) > 100 or any(not isinstance(item, str) or not item.strip() or len(item) > 100 for item in metadata["tags"]):
            fail("publication tags are invalid")
        if not isinstance(metadata["provenance"], list) or len(metadata["provenance"]) > 100:
            fail("publication provenance is invalid")
        for item in metadata["provenance"]:
            exact_keys(item, {"type", "value"}, "publication provenance item")
            if item["type"] not in {"doi", "url", "inspiration", "note"}:
                fail("publication provenance type is invalid")
            nonempty_text(item["value"], "publication provenance value")
        exact_keys(render, {"entrypoint", "previewPath", "sourceCode", "sourceData", "previewBytes", "previewSha256", "mediaType", "width", "height", "canonicalRgbaSha256"}, "publication-export render")
        render_code_paths = path_list(render["sourceCode"], "template render sourceCode")
        render_data_paths = path_list(render["sourceData"], "template render sourceData")
        if render["entrypoint"] != "payload/code/render.R" or render["previewPath"] != "payload/preview/preview.png" or set(render_code_paths) != set(code_paths) or set(render_data_paths) != set(input_paths) or render["previewBytes"] != len(preview) or render["previewSha256"] != sha256_bytes(preview) or render["mediaType"] != "image/png" or render["width"] != width or render["height"] != height or render["canonicalRgbaSha256"] != sha256_bytes(rgba):
            fail("publication-export template render identity is invalid")
        public_metadata = {name: metadata[name] for name in ("title", "description", "application", "dataProfile", "plotFamily", "language", "tags", "provenance")}
        digest_assets = [{name: asset[name] for name in ("path", "bytes", "sha256", "role", "license", "source")} for asset in assets]
        computed_digest = sha256_bytes(canonical_json({"schema": "figure-library.public-template-content-digest.v1", "providerId": PROVIDER, "templateId": template_id, "releaseVersion": version, "metadata": public_metadata, "licenses": {"code": "MIT", "content": CC_BY, "documentation": CC_BY}, "assets": digest_assets, "render": render}))
    else:
        metadata = exact_keys(metadata, {"title", "summary", "keywords", "upstreamStatus", "publisherVerified", "curationStatus", "renderValidation", "localReviewStatus", "plotExecutionByRecipient", "provenance", "contentDigestAlgorithm"}, "seed metadata")
        nonempty_text(metadata["title"], "seed title", 300)
        nonempty_text(metadata["summary"], "seed summary", 4000)
        nonempty_text(metadata["provenance"], "seed provenance", 4000)
        if not isinstance(metadata["keywords"], list) or not metadata["keywords"] or any(not isinstance(item, str) or not item.strip() or len(item) > 100 for item in metadata["keywords"]):
            fail("seed keywords are invalid")
        if metadata["contentDigestAlgorithm"] != "sha256(canonical JSON list of code, data, preview, and documentation identities)":
            fail("unsupported seed contentDigestAlgorithm")
        exact_keys(render, {"entrypoint", "inputDirectory", "outputMediaType", "width", "height", "canonicalRgbaSha256", "clientExecutionRequired"}, "seed render")
        if render != {"entrypoint": "payload/code/render.R", "inputDirectory": "payload/data", "outputMediaType": "image/png", "width": width, "height": height, "canonicalRgbaSha256": sha256_bytes(rgba), "clientExecutionRequired": False}:
            fail("seed template render identity is invalid")
        rows = sorted(({"path": asset["path"], "bytes": asset["bytes"], "sha256": asset["sha256"]} for asset in assets if asset["path"] != "payload/template.json"), key=lambda item: item["path"])
        computed_digest = sha256_bytes(json.dumps(rows, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    expected_status = {"upstreamStatus": "published", "publisherVerified": flavor == "frozen_clean_room_seed", "curationStatus": "unreviewed", "renderValidation": "publisher_attested", "localReviewStatus": "not_reviewed", "plotExecutionByRecipient": "not_run"}
    if any(metadata.get(name) != value for name, value in expected_status.items()):
        fail("public template six-field status is invalid")
    if computed_digest != content_digest:
        fail("contentDigest does not match the actual public assets and metadata")
    return set(code_paths) | set(input_paths)


def canonical_order_key(value: str) -> bytes:
    return value.encode("utf-16-be")


def validate_zip_structure(archive: Path) -> None:
    data = archive.read_bytes()
    if len(data) < 22 or data[:4] != b"PK\x03\x04":
        fail("archive must begin with a local ZIP header and may not have a prepended payload")
    eocd = data.rfind(b"PK\x05\x06", max(0, len(data) - 65_557))
    if eocd < 0 or eocd + 22 > len(data):
        fail("archive has no valid ZIP end record")
    disk, central_disk, disk_entries, total_entries, central_size, central_offset, comment_length = struct.unpack_from("<HHHHIIH", data, eocd + 4)
    if disk != 0 or central_disk != 0 or disk_entries != total_entries or total_entries == 0:
        fail("multi-disk ZIP archives are forbidden")
    if total_entries == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
        fail("ZIP64 archives are forbidden")
    if comment_length != 0 or eocd + 22 != len(data):
        fail("ZIP global comments and trailing bytes are forbidden")
    if central_offset + central_size != eocd:
        fail("ZIP central directory has a gap, overlap, or hidden payload")

    cursor = central_offset
    expected_local_offset = 0
    names: list[str] = []
    for _ in range(total_entries):
        if cursor + 46 > eocd or data[cursor:cursor + 4] != b"PK\x01\x02":
            fail("ZIP central directory entry is invalid")
        made_by, needed, flags, method, dos_time, dos_date, crc, compressed_size, expanded_size, name_length, extra_length, entry_comment_length, starting_disk, internal_attr, external_attr, local_offset = struct.unpack_from(
            "<HHHHHHIIIHHHHHII", data, cursor + 4
        )
        central_end = cursor + 46 + name_length + extra_length + entry_comment_length
        if central_end > eocd:
            fail("ZIP central directory entry exceeds its declared bounds")
        raw_name = data[cursor + 46:cursor + 46 + name_length]
        try:
            name = raw_name.decode("utf-8")
        except UnicodeDecodeError:
            fail("ZIP entry name is not valid UTF-8")
        if name.encode("utf-8") != raw_name:
            fail("ZIP entry name is not canonical UTF-8")
        canonical_path(name)
        if name.endswith("/"):
            fail("ZIP directory entries are forbidden")
        expected_flags = 0x0800 if any(byte >= 0x80 for byte in raw_name) else 0
        if (
            made_by != 20 or needed != 20 or flags != expected_flags or method != zipfile.ZIP_DEFLATED or
            dos_time != 0x4000 or dos_date != 0x0021 or extra_length != 0 or entry_comment_length != 0 or
            starting_disk != 0 or internal_attr != 0 or external_attr != 0
        ):
            fail(f"ZIP entry metadata is outside the deterministic publication dialect: {name}")
        if local_offset != expected_local_offset or local_offset + 30 > central_offset or data[local_offset:local_offset + 4] != b"PK\x03\x04":
            fail("ZIP local records must be contiguous and follow canonical central order")
        local_needed, local_flags, local_method, local_time, local_date, local_crc, local_compressed, local_expanded, local_name_length, local_extra_length = struct.unpack_from(
            "<HHHHHIIIHH", data, local_offset + 4
        )
        local_name_start = local_offset + 30
        local_name = data[local_name_start:local_name_start + local_name_length]
        data_start = local_name_start + local_name_length + local_extra_length
        data_end = data_start + compressed_size
        if (
            local_needed != needed or local_flags != flags or local_method != method or
            local_time != dos_time or local_date != dos_date or local_crc != crc or
            local_compressed != compressed_size or local_expanded != expanded_size or
            local_name_length != name_length or local_extra_length != 0 or local_name != raw_name or
            data_end > central_offset
        ):
            fail(f"ZIP local and central identities disagree: {name}")
        names.append(name)
        expected_local_offset = data_end
        cursor = central_end

    if cursor != eocd or cursor != central_offset + central_size:
        fail("ZIP central directory size or entry count is inconsistent")
    if expected_local_offset != central_offset:
        fail("ZIP local records contain a gap or hidden payload before the central directory")
    if names != sorted(names, key=canonical_order_key) or len(names) != len(set(names)):
        fail("ZIP entries must be unique and canonically ordered")



CODE_LICENSES_V2 = {"MIT", "Apache-2.0", "BSD-3-Clause", "GPL-3.0"}
CONTENT_LICENSES_V2 = {"CC-BY-4.0", "CC0-1.0", "CC-BY-SA-4.0"}
EXCLUDED_PRIVATE_STATE_V2 = [
    "library.json", "libraryId", "series/history", "working revisions", "operations", "receipts",
    "imports", "quarantine", "locator", "absolute machine paths", "unselected assets", "other templates",
]
V2_TOP_LEVEL = {
    "submission.json", "licenses.json", "render-receipt.json", "inventory.jsonl", "assets.jsonl",
}


def parse_jsonl_objects(path: Path, label: str) -> list[dict]:
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        fail(f"{label} must be UTF-8 without BOM")
    try:
        lines = raw.decode("utf-8").splitlines()
    except Exception as exc:
        fail(f"invalid {label}: {exc}")
    rows: list[dict] = []
    for index, line in enumerate(lines, start=1):
        if not line:
            fail(f"{label} contains an empty line")
        try:
            item = json.loads(line)
        except Exception as exc:
            fail(f"invalid {label} line {index}: {exc}")
        if not isinstance(item, dict):
            fail(f"{label} line {index} must be an object")
        rows.append(item)
    return rows


def optional_exact_keys(value: object, required: set[str], optional: set[str], label: str) -> dict:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    actual = set(value)
    missing = sorted(required - actual)
    extra = sorted(actual - required - optional)
    if missing or extra:
        fail(f"{label} fields differ: missing={missing}, extra={extra}")
    return value


def validate_submission_contract_v2(
    staging: Path,
    observed: set[str],
    expected_template_id: str,
    expected_release_version: str,
) -> set[str]:
    submission = exact_keys(read_json(staging, "submission.json"), {
        "schema", "providerId", "templateId", "releaseVersion", "contentDigest",
        "publicAssetKind", "language", "parentLocalRelease", "assets",
        "rightsAttestation", "excludedPrivateState", "createdAt",
    }, "publication submission v2")
    template = exact_keys(read_json(staging, "payload/template.json"), {
        "schema", "providerId", "templateId", "releaseVersion", "contentDigest",
        "publicAssetKind", "language", "metadata", "licenses", "render", "codeExecutedBySflClient",
    }, "public-template archive v2")
    if submission["schema"] != "figure-library.publication-submission.v2":
        fail("unsupported publication-submission schema")
    if template["schema"] != "figure-library.public-template-archive.v2":
        fail("unsupported public-template archive schema")
    if "publicAssetKind" in read_json(staging, "submission.json") and submission["schema"].endswith(".v1"):
        fail("hybrid v1 submission with v2 keys is forbidden")
    if submission["providerId"] != PROVIDER or template["providerId"] != PROVIDER:
        fail("central providerId mismatch")
    template_id = submission["templateId"]
    version = submission["releaseVersion"]
    content_digest = submission["contentDigest"]
    if not isinstance(template_id, str) or not valid_template_id(template_id):
        fail("invalid templateId")
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        fail("invalid strict SemVer 2.0 releaseVersion")
    if not isinstance(content_digest, str) or not SHA256.fullmatch(content_digest):
        fail("invalid contentDigest")
    if (
        template["templateId"] != template_id or template["releaseVersion"] != version or
        template["contentDigest"] != content_digest
    ):
        fail("submission/template identity mismatch")
    validate_expected_archive_identity(template_id, version, expected_template_id, expected_release_version)
    kind = submission["publicAssetKind"]
    language = submission["language"]
    if kind not in {"plot_template", "visual_reference"}:
        fail("publicAssetKind is invalid")
    if language not in {"R", "Python"}:
        fail("language is invalid")
    if template["publicAssetKind"] != kind or template["language"] != language:
        fail("template publicAssetKind/language mismatch")
    if template["codeExecutedBySflClient"] is not False:
        fail("template must state codeExecutedBySflClient=false")

    parent = exact_keys(submission["parentLocalRelease"], {
        "relationship", "explicitlySelectedAssetsOnly", "privateLifecycleIdentifiersIncluded",
    }, "publication-export parentLocalRelease")
    if parent != {
        "relationship": "sanitized-export-from-local-published",
        "explicitlySelectedAssetsOnly": True,
        "privateLifecycleIdentifiersIncluded": False,
    }:
        fail("publication-export parentLocalRelease is invalid")
    if submission["excludedPrivateState"] != EXCLUDED_PRIVATE_STATE_V2:
        fail("excludedPrivateState must match the canonical v2 exclusion list")
    if not isinstance(submission["createdAt"], str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", submission["createdAt"], re.ASCII
    ):
        fail("createdAt must be an RFC 3339 UTC timestamp")

    assets_meta = exact_keys(submission["assets"], {"schema", "path", "count", "bytes", "sha256"}, "submission.assets")
    if assets_meta["schema"] != "figure-library.publication-assets.v2" or assets_meta["path"] != "assets.jsonl":
        fail("submission.assets must point at assets.jsonl")
    assets_path = staging / "assets.jsonl"
    assets_bytes = assets_path.read_bytes()
    if (
        not isinstance(assets_meta["count"], int) or isinstance(assets_meta["count"], bool) or
        not isinstance(assets_meta["bytes"], int) or isinstance(assets_meta["bytes"], bool) or
        assets_meta["bytes"] != len(assets_bytes) or
        not isinstance(assets_meta["sha256"], str) or not SHA256.fullmatch(assets_meta["sha256"]) or
        assets_meta["sha256"] != sha256_bytes(assets_bytes)
    ):
        fail("submission.assets identity differs from assets.jsonl")

    rows = parse_jsonl_objects(assets_path, "assets.jsonl")
    if assets_meta["count"] != len(rows):
        fail("submission.assets.count differs from assets.jsonl")

    payload_files = sorted(name for name in observed if name.startswith("payload/"))
    declared: dict[str, dict] = {}
    code_paths: list[str] = []
    data_paths: list[str] = []
    preview_path = None
    preview_trace: list[str] = []
    role_licenses: dict[str, str] = {}
    for index, raw in enumerate(rows, start=1):
        asset = optional_exact_keys(
            raw,
            {"schema", "path", "role", "bytes", "sha256", "mediaType", "license", "provenance"},
            {"generatedFrom"},
            f"assets.jsonl[{index}]",
        )
        if asset["schema"] != "figure-library.publication-assets.v2":
            fail(f"assets.jsonl[{index}] schema is invalid")
        name = canonical_path(asset["path"])
        role = asset["role"]
        if role not in {"code", "synthetic_data", "preview", "documentation"}:
            fail(f"assets.jsonl[{index}] role is invalid")
        prefix = {
            "code": "payload/code/",
            "synthetic_data": "payload/data/",
            "preview": "payload/preview/",
            "documentation": "payload/docs/",
        }[role]
        if not name.startswith(prefix):
            fail(f"assets.jsonl[{index}] role/path mismatch")
        if role == "preview" and name != "payload/preview/preview.png":
            fail("public Archive v2 preview path must be payload/preview/preview.png")
        if role == "code" and not re.search(r"\.(?:R|r|py)$", name):
            fail("public Archive v2 code only permits .R, .r, and .py files")
        if name in declared or name not in observed:
            fail(f"invalid, duplicate, or absent declared asset: {name}")
        data = (staging / Path(*name.split("/"))).read_bytes()
        if (
            not isinstance(asset["bytes"], int) or isinstance(asset["bytes"], bool) or asset["bytes"] != len(data) or
            not isinstance(asset["sha256"], str) or not SHA256.fullmatch(asset["sha256"]) or asset["sha256"] != sha256_bytes(data)
        ):
            fail(f"assets.jsonl identity mismatch: {name}")
        license_name = asset["license"]
        if role == "code":
            if license_name not in CODE_LICENSES_V2:
                fail(f"assets.jsonl[{index}] code license is invalid")
        elif license_name not in CONTENT_LICENSES_V2:
            fail(f"assets.jsonl[{index}] content license is invalid")
        if role in role_licenses and role_licenses[role] != license_name:
            fail(f"assets.jsonl mixes licenses inside the {role} role")
        role_licenses[role] = license_name
        provenance = exact_keys(asset["provenance"], {"kind"}, f"assets.jsonl[{index}].provenance")
        kind_name = provenance["kind"]
        if kind_name not in {"clean_room", "generated", "synthetic", "authored"}:
            fail(f"assets.jsonl[{index}] provenance is invalid")
        if role == "code" and kind_name not in {"clean_room", "authored"}:
            fail("public Archive v2 code provenance is invalid")
        if role == "synthetic_data" and kind_name != "synthetic":
            fail("public Archive v2 data must be synthetic")
        if role == "preview" and kind_name != "generated":
            fail("public Archive v2 preview must be generated")
        if role == "documentation" and kind_name not in {"clean_room", "authored"}:
            fail("public Archive v2 documentation provenance is invalid")
        generated = asset.get("generatedFrom")
        if role == "preview":
            if not isinstance(generated, list) or not generated:
                fail("preview generatedFrom is required")
            preview_trace = path_list(generated, "preview generatedFrom")
            preview_path = name
        elif generated is not None:
            fail("only the preview asset may carry generatedFrom")
        if role == "code":
            code_paths.append(name)
        elif role == "synthetic_data":
            if asset["bytes"] == 0:
                fail("public Archive v2 synthetic data cannot be an empty placeholder")
            data_paths.append(name)
        declared[name] = asset

    expected_payload = set(declared)
    extra_payload = sorted(set(payload_files) - expected_payload - {"payload/template.json"})
    missing_payload = sorted(expected_payload - set(payload_files))
    if extra_payload or missing_payload:
        fail(f"assets.jsonl does not cover payload files: missing={missing_payload}, extra={extra_payload}")
    if "payload/template.json" not in observed:
        fail("payload/template.json is required")

    has_r = "payload/code/render.R" in declared
    has_py = "payload/code/render.py" in declared
    if has_r == has_py:
        fail("public Archive v2 requires exactly one of payload/code/render.R or payload/code/render.py")
    entrypoint = "payload/code/render.R" if has_r else "payload/code/render.py"
    derived_language = "R" if has_r else "Python"
    if language != derived_language:
        fail("language must be derived from the unique render entrypoint")
    if preview_path != "payload/preview/preview.png":
        fail("public Archive v2 requires one preview.png")
    if kind == "plot_template" and not data_paths:
        fail("public Archive v2 plot_template requires synthetic data")
    expected_trace = sorted(code_paths + data_paths)
    if sorted(preview_trace) != expected_trace or len(preview_trace) != len(set(preview_trace)):
        fail("preview generatedFrom must exactly cover all included code and data paths")

    licenses = optional_exact_keys(
        read_json(staging, "licenses.json"),
        {"schema", "code", "preview"},
        {"syntheticData", "documentation"},
        "licenses.json",
    )
    if licenses["schema"] != "figure-library.publication-licenses.v2":
        fail("licenses.json schema is invalid")
    if licenses["code"] not in CODE_LICENSES_V2 or licenses["preview"] not in CONTENT_LICENSES_V2:
        fail("licenses.json mandatory licenses are invalid")
    if licenses.get("syntheticData") not in (None, *tuple(CONTENT_LICENSES_V2)):
        fail("licenses.json syntheticData is invalid")
    if licenses.get("documentation") not in (None, *tuple(CONTENT_LICENSES_V2)):
        fail("licenses.json documentation is invalid")
    if licenses["code"] != role_licenses.get("code") or licenses["preview"] != role_licenses.get("preview"):
        fail("licenses.json mandatory role licenses differ from assets.jsonl")
    if licenses.get("syntheticData") != role_licenses.get("synthetic_data"):
        fail("licenses.json syntheticData differs from assets.jsonl")
    if licenses.get("documentation") != role_licenses.get("documentation"):
        fail("licenses.json documentation differs from assets.jsonl")
    if ("syntheticData" in licenses) != ("synthetic_data" in role_licenses):
        fail("licenses.json syntheticData must exist only when synthetic data is present")
    if ("documentation" in licenses) != ("documentation" in role_licenses):
        fail("licenses.json documentation must exist only when documentation is present")

    rights = exact_keys(submission["rightsAttestation"], {
        "publisher", "codeRightsConfirmed", "dataAttestation", "generatedPreviewConfirmed",
        "noThirdPartyMediaConfirmed", "immutableReleaseAcknowledged",
    }, "rightsAttestation")
    nonempty_text(rights["publisher"], "rightsAttestation.publisher", 200)
    if any(rights[name] is not True for name in (
        "codeRightsConfirmed", "generatedPreviewConfirmed", "noThirdPartyMediaConfirmed", "immutableReleaseAcknowledged"
    )):
        fail("publication-export rightsAttestation is incomplete")
    attestation = rights["dataAttestation"]
    if data_paths or kind == "plot_template":
        exact_keys(attestation, {"kind", "confirmed"}, "dataAttestation")
        if attestation != {"kind": "synthetic_data_included", "confirmed": True}:
            fail("submission data attestation must confirm included synthetic data")
    else:
        exact_keys(attestation, {"kind", "acknowledged"}, "dataAttestation")
        if attestation != {"kind": "no_data_required_for_visual_reference", "acknowledged": True}:
            fail("submission data attestation must acknowledge a data-free visual_reference")

    metadata = exact_keys(template["metadata"], {
        "title", "description", "application", "dataProfile", "plotFamily", "language", "tags",
        "provenance", "upstreamStatus", "publisherVerified", "curationStatus", "renderValidation",
        "localReviewStatus", "plotExecutionByRecipient",
    }, "template.metadata")
    for field in ("title", "description", "application", "dataProfile", "plotFamily"):
        nonempty_text(metadata[field], f"template.metadata.{field}", 4000 if field != "title" else 300)
    if metadata["language"] != derived_language:
        fail("template.metadata.language differs from the derived language")
    if metadata["upstreamStatus"] != "published" or metadata["publisherVerified"] is not False or metadata["curationStatus"] != "unreviewed" or metadata["renderValidation"] != "publisher_attested" or metadata["localReviewStatus"] != "not_reviewed" or metadata["plotExecutionByRecipient"] != "not_run":
        fail("public template six-field status is invalid")
    if not isinstance(metadata["tags"], list):
        fail("template.metadata.tags must be an array")
    for item in metadata["tags"]:
        nonempty_text(item, "template.metadata.tags[]", 100)
    if not isinstance(metadata["provenance"], list):
        fail("template.metadata.provenance must be an array")
    for item in metadata["provenance"]:
        exact_keys(item, {"type", "value"}, "template.metadata.provenance")
        if item["type"] not in {"doi", "url", "inspiration", "note"}:
            fail("template.metadata.provenance type is invalid")
        nonempty_text(item["value"], "template.metadata.provenance.value")

    template_licenses = optional_exact_keys(template["licenses"], {"code", "preview"}, {"syntheticData", "documentation"}, "template.licenses")
    expected_template_licenses = {key: licenses[key] for key in licenses if key != "schema"}
    if template_licenses != expected_template_licenses:
        fail("Archive template licenses differ from licenses.json")
    render = exact_keys(template["render"], {
        "entrypoint", "previewPath", "sourceCode", "sourceData", "canonicalRgbaSha256",
    }, "template.render")
    if render["entrypoint"] != entrypoint or render["previewPath"] != "payload/preview/preview.png":
        fail("template.render entrypoint/previewPath mismatch")
    if path_list(render["sourceCode"], "template.render.sourceCode") != sorted(code_paths):
        fail("template.render.sourceCode must list every code asset")
    if path_list(render["sourceData"], "template.render.sourceData", allow_empty=True) != sorted(data_paths):
        fail("template.render.sourceData must list every data asset")
    preview = (staging / Path("payload/preview/preview.png")).read_bytes()
    width, height, rgba = decode_png_rgba(preview, strict_chunks=False)
    if not isinstance(render["canonicalRgbaSha256"], str) or not SHA256.fullmatch(render["canonicalRgbaSha256"]) or render["canonicalRgbaSha256"] != sha256_bytes(rgba):
        fail("template.render.canonicalRgbaSha256 mismatch")

    receipt = exact_keys(read_json(staging, "render-receipt.json"), {
        "schema", "language", "entrypoint", "codeAssets", "dataAssets", "preview",
        "generatedFrom", "environment", "sourceExecution", "codeExecutedBySflClient",
    }, "render-receipt.json")
    if receipt["schema"] != "figure-library.render-receipt.v2":
        fail("render-receipt.json schema is invalid")
    if (
        receipt["language"] != derived_language or receipt["entrypoint"] != entrypoint or
        receipt["sourceExecution"] != "publisher_attested" or receipt["codeExecutedBySflClient"] is not False
    ):
        fail("render receipt v2 trace is invalid")
    if path_list(receipt["generatedFrom"], "render.generatedFrom") != preview_trace:
        fail("render receipt generatedFrom must match preview generatedFrom")
    if not isinstance(receipt["codeAssets"], list) or not isinstance(receipt["dataAssets"], list):
        fail("render receipt asset identity arrays are invalid")
    receipt_code = [exact_keys(item, {"path", "bytes", "sha256"}, "render.codeAssets[]") for item in receipt["codeAssets"]]
    receipt_data = [exact_keys(item, {"path", "bytes", "sha256"}, "render.dataAssets[]") for item in receipt["dataAssets"]]
    def identities(paths: list[str]) -> list[dict]:
        output = []
        for name in paths:
            data = (staging / Path(*name.split("/"))).read_bytes()
            output.append({"path": name, "bytes": len(data), "sha256": sha256_bytes(data)})
        return output
    if receipt_code != identities(sorted(code_paths)) and {item["path"] for item in receipt_code} != set(code_paths):
        # allow either canonical order or set-equal identities
        if sorted(receipt_code, key=lambda item: item["path"]) != identities(sorted(code_paths)):
            fail("render receipt codeAssets identity mismatch")
    if sorted(receipt_data, key=lambda item: item["path"]) != identities(sorted(data_paths)):
        fail("render receipt dataAssets identity mismatch")
    preview_meta = exact_keys(receipt["preview"], {
        "path", "bytes", "sha256", "mediaType", "width", "height", "canonicalRgbaSha256",
    }, "render.preview")
    if (
        preview_meta["path"] != "payload/preview/preview.png" or preview_meta["bytes"] != len(preview) or
        preview_meta["sha256"] != sha256_bytes(preview) or preview_meta["mediaType"] != "image/png" or
        preview_meta["width"] != width or preview_meta["height"] != height or
        preview_meta["canonicalRgbaSha256"] != sha256_bytes(rgba)
    ):
        fail("render receipt preview identity mismatch")
    environment = exact_keys(receipt["environment"], {"runtime", "runtimeVersion", "renderer", "dependencies"}, "render.environment")
    if environment["runtime"] != derived_language:
        fail("render.environment.runtime must match language")
    nonempty_text(environment["runtimeVersion"], "render.environment.runtimeVersion", 100)
    nonempty_text(environment["renderer"], "render.environment.renderer", 400)
    if not isinstance(environment["dependencies"], list):
        fail("render.environment.dependencies must be an array")
    for item in environment["dependencies"]:
        exact_keys(item, {"name", "version"}, "render.environment.dependencies[]")
        nonempty_text(item["name"], "dependency.name", 200)
        nonempty_text(item["version"], "dependency.version", 100)

    template_licenses_for_digest = None  # contentDigest is trusted via file identities and traces
    return set(code_paths) | set(data_paths)



def build_isolated_render_root_v2_optional_data(staging: Path, render_root: Path, render_files: set[str]) -> None:
    if render_root.exists():
        fail("isolated render root must not exist")
    try:
        render_root.relative_to(staging)
    except ValueError:
        pass
    else:
        fail("isolated render root must be outside the extracted archive")
    if "payload/code/render.R" not in render_files and "payload/code/render.py" not in render_files:
        fail("isolated render root lacks the fixed entrypoint")
    for name in render_files:
        canonical_path(name)
        if not (name.startswith("payload/code/") or name.startswith("payload/data/")):
            fail(f"isolated render root contains a non-render asset: {name}")
    render_root.mkdir(parents=True)
    for name in sorted(render_files):
        source = staging / Path(*name.split("/"))
        if not source.is_file() or source.is_symlink():
            fail(f"isolated render input is not a regular extracted file: {name}")
        target = render_root / Path(*name.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as input_handle, target.open("xb") as output_handle:
            shutil.copyfileobj(input_handle, output_handle, length=1024 * 1024)


def extract_and_validate(
    archive: Path,
    staging: Path,
    render_root: Path,
    expected_template_id: str,
    expected_release_version: str,
) -> None:
    if not archive.is_file() or archive.is_symlink():
        fail("archive must be a regular file")
    if archive.stat().st_size > MAX_ARCHIVE:
        fail("archive exceeds 100 MiB")
    validate_zip_structure(archive)
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

    observed = {path.relative_to(staging).as_posix() for path in staging.rglob("*") if path.is_file()}
    if "submission.json" not in observed:
        fail("archive is missing required files: ['submission.json']")
    schema = read_json(staging, "submission.json").get("schema")
    if schema == "figure-library.publication-submission.v2":
        required = {
            "submission.json", "licenses.json", "render-receipt.json", "inventory.jsonl",
            "assets.jsonl", "payload/template.json", "payload/preview/preview.png",
        }
        has_r = "payload/code/render.R" in observed
        has_py = "payload/code/render.py" in observed
        if has_r == has_py:
            fail("public Archive v2 requires exactly one of payload/code/render.R or payload/code/render.py")
        required.add("payload/code/render.R" if has_r else "payload/code/render.py")
        missing = sorted(required - observed)
        if missing:
            fail(f"archive is missing required files: {missing}")
        kind = read_json(staging, "submission.json").get("publicAssetKind")
        if kind == "plot_template" and not any(name.startswith("payload/data/") for name in observed):
            fail("archive contains no synthetic input data")
        unexpected_top_level = sorted(
            name for name in observed if "/" not in name and name not in V2_TOP_LEVEL
        )
        if unexpected_top_level:
            fail(f"archive contains unexpected top-level files: {unexpected_top_level}")
        validate_inventory(staging, observed)
        validate_private_text(staging, observed)
        render_files = validate_submission_contract_v2(
            staging, observed, expected_template_id, expected_release_version,
        )
        if any(name.startswith('payload/data/') for name in render_files):
            build_isolated_render_root(staging, render_root, render_files)
        else:
            build_isolated_render_root_v2_optional_data(staging, render_root, render_files)
        return

    required = {
        "submission.json", "licenses.json", "render-receipt.json", "inventory.jsonl",
        "payload/template.json", "payload/code/render.R", "payload/preview/preview.png",
    }
    missing = sorted(required - observed)
    if missing:
        fail(f"archive is missing required files: {missing}")
    if not any(name.startswith("payload/data/") for name in observed):
        fail("archive contains no synthetic input data")
    unexpected_top_level = sorted(name for name in observed if "/" not in name and name not in {"submission.json", "licenses.json", "render-receipt.json", "inventory.jsonl"})
    if unexpected_top_level:
        fail(f"archive contains unexpected top-level files: {unexpected_top_level}")

    validate_inventory(staging, observed)
    validate_private_text(staging, observed)
    render_files = validate_submission_contract(staging, observed, expected_template_id, expected_release_version)
    build_isolated_render_root(staging, render_root, render_files)



def paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    return a if pa <= pb and pa <= pc else b if pb <= pc else c


def decode_png_rgba(data: bytes, *, strict_chunks: bool = True) -> tuple[int, int, bytes]:
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        fail("preview is not a PNG")
    offset = 8
    ihdr = None
    idat = bytearray()
    palette = None
    transparency = None
    chunks: list[bytes] = []
    while offset < len(data):
        if offset + 12 > len(data):
            fail("PNG contains a truncated chunk header")
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        kind = data[offset + 4:offset + 8]
        if offset + 12 + length > len(data):
            fail("PNG chunk exceeds the file bounds")
        payload = data[offset + 8:offset + 8 + length]
        crc = struct.unpack(">I", data[offset + 8 + length:offset + 12 + length])[0]
        if len(payload) != length or (binascii.crc32(kind + payload) & 0xFFFFFFFF) != crc:
            fail("PNG chunk length/CRC is invalid")
        offset += 12 + length
        allowed = {b"IHDR", b"PLTE", b"tRNS", b"IDAT", b"IEND"}
        if kind not in allowed:
            if strict_chunks:
                fail(f"PNG chunk {kind!r} is outside the metadata-free publication dialect")
            offset  # keep walking; ancillary chunks are ignored for v2 RGBA
            continue
        chunks.append(kind)
        if kind == b"IHDR":
            if ihdr is not None or len(chunks) != 1 or length != 13:
                fail("PNG must contain one 13-byte IHDR as its first chunk")
            ihdr = payload
        elif kind == b"PLTE":
            if palette is not None or ihdr is None or idat:
                fail("PNG PLTE order or singleton contract is invalid")
            palette = payload
        elif kind == b"tRNS":
            if transparency is not None or ihdr is None or palette is None or idat:
                fail("PNG tRNS order or singleton contract is invalid")
            transparency = payload
        elif kind == b"IDAT":
            if ihdr is None or not payload:
                fail("PNG must contain a non-empty IDAT chunk after IHDR")
            if idat and strict_chunks:
                fail("PNG must contain exactly one non-empty IDAT chunk")
            idat.extend(payload)
        elif kind == b"IEND":
            if length != 0 or not idat or offset != len(data):
                fail("PNG must end with one empty IEND and no trailing bytes")
            break
    if ihdr is None or chunks.count(b"IEND") != 1 or chunks[-1:] != [b"IEND"]:
        fail("PNG is missing its unique terminal IEND")
    width, height, depth, color_type, compression, filtering, interlace = struct.unpack(">IIBBBBB", ihdr)
    if depth != 8 or compression != 0 or filtering != 0 or interlace != 0 or width < 1 or height < 1 or width > 16384 or height > 16384:
        fail("PNG uses unsupported or unsafe encoding")
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color_type)
    if channels is None:
        fail("PNG color type is unsupported")
    if color_type == 3:
        if palette is None or not 3 <= len(palette) <= 768 or len(palette) % 3 != 0:
            fail("indexed PNG requires one valid PLTE")
        if transparency is not None and (not transparency or len(transparency) > len(palette) // 3):
            fail("indexed PNG tRNS is invalid")
    elif palette is not None or transparency is not None:
        fail("non-indexed PNG may not carry PLTE or tRNS in the canonical dialect")
    if width * height * 4 > 128 * 1024 * 1024:
        fail("PNG canonical RGBA payload exceeds 128 MiB")
    stride = width * channels
    expected_raw = height * (stride + 1)
    if expected_raw > 128 * 1024 * 1024:
        fail("PNG decompressed scanline payload exceeds 128 MiB")
    try:
        decompressor = zlib.decompressobj()
        raw = decompressor.decompress(bytes(idat), expected_raw + 1)
        if decompressor.unconsumed_tail or len(raw) > expected_raw:
            fail("PNG IDAT expands beyond its declared dimensions")
        raw += decompressor.flush(expected_raw + 1 - len(raw))
    except Exception as exc:
        fail(f"PNG IDAT decompression failed: {exc}")
    if not decompressor.eof or decompressor.unused_data or len(raw) != expected_raw:
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
    expected_bytes = receipt.get("previewBytes")
    if not isinstance(expected_bytes, int) or isinstance(expected_bytes, bool) or expected_bytes < 1 or expected_bytes > MAX_FILE:
        fail("render receipt has an invalid bounded previewBytes")
    if not rendered.is_file() or rendered.is_symlink():
        fail("sandbox render output must be a regular non-symlink file")
    if rendered.stat().st_size != expected_bytes:
        fail("sandbox render output byte length differs from the archived preview receipt")
    actual = rendered.read_bytes()
    width, height, rgba = decode_png_rgba(actual)
    if width != receipt.get("width") or height != receipt.get("height"):
        fail("sandbox re-rendered PNG dimensions differ from receipt")
    if sha256_bytes(rgba) != receipt.get("canonicalRgbaSha256"):
        fail("sandbox re-rendered canonical RGBA digest differs from receipt")
    if sha256_bytes(actual) != receipt.get("previewSha256"):
        fail("sandbox re-rendered PNG SHA-256 differs from archived preview")
    print(json.dumps({"status": "ci_rendered", "width": width, "height": height, "renderedPreviewSha256": sha256_bytes(actual), "archivedPreviewSha256": receipt.get("previewSha256"), "canonicalRgbaSha256": sha256_bytes(rgba)}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--render-root", type=Path)
    parser.add_argument("--rendered", type=Path)
    parser.add_argument("--expected-template-id")
    parser.add_argument("--expected-release-version")
    args = parser.parse_args()
    staging = args.staging.resolve()
    if args.archive:
        if not args.render_root or not args.expected_template_id or not args.expected_release_version:
            fail("archive validation requires an isolated render root and expected outer templateId/releaseVersion")
        extract_and_validate(
            args.archive.resolve(),
            staging,
            args.render_root.resolve(),
            args.expected_template_id,
            args.expected_release_version,
        )
        print(f"validated and extracted {args.archive}")
    elif args.rendered:
        if args.render_root or args.expected_template_id or args.expected_release_version:
            fail("render verification does not accept a render root or outer archive identity")
        post_render(staging, args.rendered.resolve())
    else:
        fail("choose --archive or --rendered")


if __name__ == "__main__":
    main()
