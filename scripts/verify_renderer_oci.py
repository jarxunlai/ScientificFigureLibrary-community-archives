#!/usr/bin/env python3
"""Verify the local renderer config and its exact remote single-image manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
EXPECTED_USER = "65532:65532"
EXPECTED_WORKING_DIR = "/nonexistent"
EXPECTED_ENTRYPOINT = [
    "/opt/sfl/.pixi/envs/default/bin/python",
    "/opt/sfl/runner.py",
]
EXPECTED_OS = "linux"
EXPECTED_ARCHITECTURE = "amd64"
SINGLE_IMAGE_MEDIA_TYPES = {
    "application/vnd.docker.distribution.manifest.v2+json": "application/vnd.docker.container.image.v1+json",
    "application/vnd.oci.image.manifest.v1+json": "application/vnd.oci.image.config.v1+json",
}
LAYER_MEDIA_TYPES = {
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
}


def fail(message: str) -> None:
    raise SystemExit(message)


def require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        fail(f"{label} must be one lowercase SHA-256 digest")
    return value


def require_descriptor(value: object, label: str, media_types: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"mediaType", "size", "digest"}:
        fail(f"{label} must be one exact OCI descriptor")
    if value.get("mediaType") not in media_types:
        fail(f"{label} has an unexpected media type")
    if not isinstance(value.get("size"), int) or isinstance(value.get("size"), bool) or value["size"] < 0:
        fail(f"{label} has an invalid byte size")
    require_digest(value.get("digest"), f"{label} digest")
    return value


def verify_image_config(
    payload: object,
    expected_image_id: str,
    expected_repo_digest: str | None = None,
) -> dict[str, object]:
    expected_image_id = require_digest(expected_image_id, "expected image ID")
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        fail("docker image inspect must return exactly one image object")
    image = payload[0]
    if image.get("Id") != expected_image_id:
        fail("inspected image ID differs from the exact locally built image")
    if image.get("Os") != EXPECTED_OS or image.get("Architecture") != EXPECTED_ARCHITECTURE:
        fail("renderer image must be exactly linux/amd64")
    config = image.get("Config")
    if not isinstance(config, dict):
        fail("renderer image config is missing")
    if config.get("User") != EXPECTED_USER:
        fail("renderer image does not select the exact non-root UID/GID")
    if config.get("WorkingDir") != EXPECTED_WORKING_DIR:
        fail("renderer image working directory differs from the reviewed contract")
    if config.get("Entrypoint") != EXPECTED_ENTRYPOINT:
        fail("renderer image entrypoint differs from the reviewed contract")
    if expected_repo_digest is not None:
        if "@" not in expected_repo_digest:
            fail("expected repository digest must contain one repository and digest")
        require_digest(expected_repo_digest.rsplit("@", 1)[1], "expected repository digest")
        repo_digests = image.get("RepoDigests")
        if not isinstance(repo_digests, list) or expected_repo_digest not in repo_digests:
            fail("pulled image metadata does not bind the requested exact repository digest")
    return {
        "architecture": EXPECTED_ARCHITECTURE,
        "entrypoint": EXPECTED_ENTRYPOINT,
        "imageId": expected_image_id,
        "os": EXPECTED_OS,
        "user": EXPECTED_USER,
        "workingDir": EXPECTED_WORKING_DIR,
    }


def verify_registry_manifest(
    raw: bytes,
    expected_manifest_digest: str,
    expected_config_digest: str,
) -> dict[str, object]:
    expected_manifest_digest = require_digest(expected_manifest_digest, "expected manifest digest")
    expected_config_digest = require_digest(expected_config_digest, "expected config digest")
    actual_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if actual_digest != expected_manifest_digest:
        fail("raw registry manifest SHA-256 differs from the pushed digest")
    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"raw registry manifest is not valid UTF-8 JSON: {error}")
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2:
        fail("registry response is not a schema-v2 image manifest")
    media_type = manifest.get("mediaType")
    if media_type not in SINGLE_IMAGE_MEDIA_TYPES:
        fail("registry response is not an allowed single-image manifest")
    if "manifests" in manifest or "subject" in manifest or "artifactType" in manifest:
        fail("registry response must not be an index, artifact, or subject manifest")
    if set(manifest) - {"schemaVersion", "mediaType", "config", "layers", "annotations"}:
        fail("registry image manifest contains unexpected top-level fields")
    config = require_descriptor(
        manifest.get("config"),
        "config descriptor",
        {SINGLE_IMAGE_MEDIA_TYPES[media_type]},
    )
    if config["digest"] != expected_config_digest:
        fail("remote manifest config digest differs from the audited local image ID")
    layers = manifest.get("layers")
    if not isinstance(layers, list) or not layers:
        fail("registry image manifest must contain at least one layer")
    for index, layer in enumerate(layers):
        require_descriptor(layer, f"layer descriptor {index}", LAYER_MEDIA_TYPES)
    return {
        "configDigest": expected_config_digest,
        "layerCount": len(layers),
        "manifestDigest": expected_manifest_digest,
        "mediaType": media_type,
        "singleImage": True,
    }


def read_json(path: Path) -> object:
    try:
        return json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"failed to read Docker image inspection JSON: {error}")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    image = subparsers.add_parser("image-config")
    image.add_argument("inspection", type=Path)
    image.add_argument("--expected-image-id", required=True)
    image.add_argument("--expected-repo-digest")

    manifest = subparsers.add_parser("registry-manifest")
    manifest.add_argument("manifest", type=Path)
    manifest.add_argument("--expected-manifest-digest", required=True)
    manifest.add_argument("--expected-config-digest", required=True)

    args = parser.parse_args()
    if args.command == "image-config":
        result = verify_image_config(
            read_json(args.inspection),
            args.expected_image_id,
            args.expected_repo_digest,
        )
    else:
        try:
            raw = args.manifest.read_bytes()
        except OSError as error:
            fail(f"failed to read raw registry manifest: {error}")
        result = verify_registry_manifest(
            raw,
            args.expected_manifest_digest,
            args.expected_config_digest,
        )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
