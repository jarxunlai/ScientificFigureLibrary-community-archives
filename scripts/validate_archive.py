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
    r"(?:\b[A-Za-z]:[\\/]|/(?:Users|home|mnt/[a-z]|private|var/folders)/|"
    r"(?:%APPDATA%|%LOCALAPPDATA%|\$HOME|\$XDG_(?:CONFIG|DATA)_HOME)[\\/])",
    re.I,
)
PROVIDER = "io.github.jarxunlai.scientific-figure-community"
CC_BY = "CC-BY-4.0"


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
        if path.stat().st_size <= MAX_TEXT_SCAN and path.suffix.lower() in text_extensions:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                fail(f"declared text asset is not valid UTF-8: {name}")
            if PRIVATE_PATH.search(text):
                fail(f"possible absolute/private machine path leaked in {name}")


def validate_submission_contract(staging: Path, observed: set[str]) -> dict:
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
    if not isinstance(template_id, str) or not ID.fullmatch(template_id):
        fail("invalid templateId")
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        fail("invalid strict SemVer 2.0 releaseVersion")
    if not isinstance(content_digest, str) or not SHA256.fullmatch(content_digest):
        fail("invalid contentDigest")
    if template["templateId"] != template_id or template["releaseVersion"] != version or template["contentDigest"] != content_digest:
        fail("submission/template identity mismatch")
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
    for name in observed:
        if name.startswith("payload/") and name != "payload/template.json" and name not in declared:
            fail(f"submission contains an undeclared payload asset: {name}")
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
    width, height, rgba = decode_png_rgba(preview)
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
    return receipt


def validate_zip_structure(archive: Path) -> None:
    data = archive.read_bytes()
    if len(data) < 22 or data[:4] != b"PK\x03\x04":
        fail("archive must begin with a local ZIP header and may not have a prepended payload")
    eocd = data.rfind(b"PK\x05\x06", max(0, len(data) - 65_557))
    if eocd < 0 or eocd + 22 > len(data):
        fail("archive has no valid ZIP end record")
    disk, central_disk, disk_entries, total_entries, central_size, central_offset, comment_length = struct.unpack_from("<HHHHIIH", data, eocd + 4)
    if disk != 0 or central_disk != 0 or disk_entries != total_entries:
        fail("multi-disk ZIP archives are forbidden")
    if total_entries == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
        fail("ZIP64 archives are forbidden")
    if eocd + 22 + comment_length != len(data):
        fail("archive contains trailing bytes after the ZIP end record")
    if central_offset + central_size != eocd:
        fail("ZIP central directory has a gap, overlap, or hidden payload")


def extract_and_validate(archive: Path, staging: Path) -> None:
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
    unexpected_top_level = sorted(name for name in observed if "/" not in name and name not in {"submission.json", "licenses.json", "render-receipt.json", "inventory.jsonl"})
    if unexpected_top_level:
        fail(f"archive contains unexpected top-level files: {unexpected_top_level}")

    validate_inventory(staging, observed)
    validate_private_text(staging, observed)
    validate_submission_contract(staging, observed)


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
