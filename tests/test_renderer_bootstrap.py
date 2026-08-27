from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "renderer"))


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


audit = load("audit_renderer_rootfs", "scripts/audit_renderer_rootfs.py")
sanitize = load("sanitize_runtime", "renderer/sanitize_runtime.py")
boundary = load("runtime_boundary_test", "renderer/runtime_boundary.py")
oci = load("verify_renderer_oci", "scripts/verify_renderer_oci.py")
r_runner = load("renderer_r_runner", "renderer/r/runner.py")
python_runner = load("renderer_python_runner", "renderer/python/runner.py")


class RendererBootstrapTests(unittest.TestCase):
    @staticmethod
    def write_tar(path: Path, entries: list[tuple[str, bytes, int, bytes | None]]) -> None:
        """Write (path, type, mode, payload/link target) entries."""
        with tarfile.open(path, "w") as handle:
            for name, kind, mode, payload in entries:
                item = tarfile.TarInfo(name)
                item.mode = mode
                if kind == b"file":
                    data = payload or b""
                    item.size = len(data)
                    handle.addfile(item, io.BytesIO(data))
                else:
                    item.type = kind
                    item.linkname = (payload or b"").decode("utf-8")
                    handle.addfile(item)

    @staticmethod
    def minimum_rootfs(extra: list[tuple[str, bytes, int, bytes | None]] | None = None):
        entries = [
            ("opt/sfl/.pixi/envs/default/bin/python", b"file", 0o755, b"python"),
            ("opt/sfl/.pixi/envs/default/bin/Rscript", b"file", 0o755, b"Rscript"),
            ("opt/sfl/runner.py", b"file", 0o755, b"runner"),
        ]
        return entries + (extra or [])

    def test_rootfs_audit_accepts_and_inventories_minimal_disabled_renderer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "rootfs.tar"
            self.write_tar(archive, self.minimum_rootfs())
            inventory = audit.audit_rootfs(archive)
            self.assertEqual(inventory["schema"], audit.INVENTORY_SCHEMA)
            self.assertEqual(inventory["executableCount"], 3)
            rows = inventory["executables"]
            self.assertEqual({row["path"] for row in rows}, set(audit.REQUIRED_EXECUTABLES))
            self.assertTrue(all(len(row["sha256"]) == 64 for row in rows))

    def test_rootfs_audit_rejects_forbidden_tools_and_symlink_hardlink_aliases(self) -> None:
        cases = {
            "direct make": [("usr/bin/make", b"file", 0o755, b"make")],
            "versioned curl": [("usr/bin/curl-9", b"file", 0o755, b"curl")],
            "triplet compiler": [("usr/bin/x86_64-linux-gnu-gcc", b"file", 0o755, b"gcc")],
            "symlink alias": [
                ("usr/bin/curl", b"file", 0o755, b"curl"),
                ("usr/local/bin/neutral", tarfile.SYMTYPE, 0o777, b"/usr/bin/curl"),
            ],
            "hardlink alias": [
                ("usr/bin/make", b"file", 0o755, b"make"),
                ("usr/local/bin/neutral", tarfile.LNKTYPE, 0o755, b"usr/bin/make"),
            ],
            "installer module": [
                ("opt/sfl/.pixi/envs/default/lib/python3.12/site-packages/pip/__init__.py", b"file", 0o644, b""),
            ],
            "committed run tool": [("run/make", b"file", 0o755, b"make")],
            "committed tmp tool": [("tmp/bash", b"file", 0o755, b"bash")],
            "neutral shell shebang": [("usr/local/bin/neutral", b"file", 0o755, b"#!/bin/sh\n")],
            "env shell shebang": [("usr/local/bin/also-neutral", b"file", 0o755, b"#!/usr/bin/env -S bash -eu\n")],
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, (label, extra) in enumerate(cases.items()):
                archive = root / f"case-{index}.tar"
                self.write_tar(archive, self.minimum_rootfs(extra))
                with self.subTest(label=label), self.assertRaisesRegex(SystemExit, "executable boundary failed"):
                    audit.audit_rootfs(archive)

    def test_rootfs_audit_rejects_privilege_bits_special_files_and_escaping_links(self) -> None:
        cases = {
            "setuid": [("usr/bin/neutral", b"file", 0o4755, b"x")],
            "device": [("opt/device-neutral", tarfile.CHRTYPE, 0o600, None)],
            "escaping symlink": [("usr/bin/neutral", tarfile.SYMTYPE, 0o777, b"../../../host")],
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, (label, extra) in enumerate(cases.items()):
                archive = root / f"unsafe-{index}.tar"
                self.write_tar(archive, self.minimum_rootfs(extra))
                with self.subTest(label=label), self.assertRaises(SystemExit):
                    audit.audit_rootfs(archive)

    def test_runtime_sanitizer_removes_same_inode_alias_shell_script_and_installer_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_dir = root / "usr" / "bin"
            bin_dir.mkdir(parents=True)
            make = bin_dir / "make"
            alias = bin_dir / "neutral-alias"
            make.write_bytes(b"tool")
            make.chmod(0o755)
            os.link(make, alias)
            shell_script = bin_dir / "neutral-script"
            shell_script.write_bytes(b"#!/bin/sh\nexit 0\n")
            shell_script.chmod(0o755)
            safe = bin_dir / "python"
            safe.write_bytes(b"safe")
            safe.chmod(0o755)
            pip_file = root / "opt" / "env" / "lib" / "python3.12" / "site-packages" / "pip" / "__init__.py"
            pip_file.parent.mkdir(parents=True)
            pip_file.write_bytes(b"")

            removed = sanitize.sanitize(root)

            self.assertFalse(make.exists())
            self.assertFalse(alias.exists())
            self.assertFalse(shell_script.exists())
            self.assertFalse(pip_file.parent.exists())
            self.assertTrue(safe.exists())
            self.assertTrue(any("neutral-alias" in item for item in removed))

    def test_runtime_sanitizer_scans_committed_run_and_tmp_trees(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unsafe: list[Path] = []
            for relative, payload in (
                ("run/make", b"tool"),
                ("tmp/neutral-shell", b"#!/usr/bin/env sh\n"),
            ):
                target = root / Path(*relative.split("/"))
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
                target.chmod(0o755)
                unsafe.append(target)
            virtual = root / "dev" / "make"
            virtual.parent.mkdir(parents=True)
            virtual.write_bytes(b"runtime mount placeholder")
            virtual.chmod(0o755)

            removed = sanitize.sanitize(root)

            self.assertTrue(all(not path.exists() for path in unsafe))
            self.assertTrue(virtual.exists())
            self.assertIn("run/make", removed)
            self.assertIn("tmp/neutral-shell", removed)

    def test_product_neutral_canary_proves_both_bootstrap_runners_refuse_intake(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_dir = root / "input"
            input_dir.mkdir()
            for renderer in ("r", "python"):
                output = root / f"{renderer}.png"
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "renderer" / renderer / "runner.py"),
                        "--input-dir",
                        str(input_dir),
                        "--output",
                        str(output),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(completed.stdout, "")
                self.assertEqual(completed.stderr, "v2 intake is disabled for this renderer bootstrap\n")
                self.assertFalse(output.exists())

    def test_runtime_identity_requires_exact_non_root_uid_and_gid(self) -> None:
        class Identity:
            def __init__(self, uid: int, gid: int):
                self.uid = uid
                self.gid = gid

            def getuid(self) -> int:
                return self.uid

            def getgid(self) -> int:
                return self.gid

        for runner in (r_runner, python_runner):
            with self.subTest(runner=runner.__name__):
                original = runner.os
                try:
                    runner.os = Identity(65532, 65532)
                    runner.verify_runtime_identity()
                    for identity in (Identity(0, 0), Identity(65532, 0), Identity(0, 65532)):
                        runner.os = identity
                        with self.assertRaisesRegex(SystemExit, "non-root contract"):
                            runner.verify_runtime_identity()
                finally:
                    runner.os = original

    @staticmethod
    def registry_manifest(config_digest: str, *, media_type: str = "application/vnd.oci.image.manifest.v1+json") -> bytes:
        return json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": media_type,
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "size": 123,
                    "digest": config_digest,
                },
                "layers": [
                    {
                        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                        "size": 456,
                        "digest": "sha256:" + "2" * 64,
                    }
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def test_oci_verifier_binds_exact_local_config_and_single_remote_manifest(self) -> None:
        image_id = "sha256:" + "1" * 64
        local = [{
            "Id": image_id,
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {
                "User": "65532:65532",
                "WorkingDir": "/nonexistent",
                "Entrypoint": [
                    "/opt/sfl/.pixi/envs/default/bin/python",
                    "/opt/sfl/runner.py",
                ],
            },
        }]
        identity = oci.verify_image_config(local, image_id)
        self.assertEqual(identity["imageId"], image_id)
        raw = self.registry_manifest(image_id)
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        manifest = oci.verify_registry_manifest(raw, digest, image_id)
        self.assertTrue(manifest["singleImage"])
        self.assertEqual(manifest["configDigest"], image_id)

    def test_oci_verifier_rejects_config_drift_index_and_raw_digest_mismatch(self) -> None:
        image_id = "sha256:" + "1" * 64
        valid = [{
            "Id": image_id,
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {
                "User": "65532:65532",
                "WorkingDir": "/nonexistent",
                "Entrypoint": [
                    "/opt/sfl/.pixi/envs/default/bin/python",
                    "/opt/sfl/runner.py",
                ],
            },
        }]
        for label, mutate in (
            ("root user", lambda item: item[0]["Config"].update(User="0")),
            ("wrong workdir", lambda item: item[0]["Config"].update(WorkingDir="/tmp")),
            ("wrong entrypoint", lambda item: item[0]["Config"].update(Entrypoint=["python"])),
            ("wrong platform", lambda item: item[0].update(Architecture="arm64")),
        ):
            candidate = json.loads(json.dumps(valid))
            mutate(candidate)
            with self.subTest(label=label), self.assertRaises(SystemExit):
                oci.verify_image_config(candidate, image_id)

        raw = self.registry_manifest(image_id)
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        with self.assertRaisesRegex(SystemExit, "raw registry manifest SHA-256"):
            oci.verify_registry_manifest(raw + b"\n", digest, image_id)
        with self.assertRaisesRegex(SystemExit, "config digest differs"):
            oci.verify_registry_manifest(
                self.registry_manifest("sha256:" + "3" * 64),
                "sha256:" + hashlib.sha256(self.registry_manifest("sha256:" + "3" * 64)).hexdigest(),
                image_id,
            )
        index = json.dumps({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [],
        }, separators=(",", ":")).encode()
        with self.assertRaisesRegex(SystemExit, "single-image manifest"):
            oci.verify_registry_manifest(index, "sha256:" + hashlib.sha256(index).hexdigest(), image_id)

    def test_forbidden_name_policy_covers_required_tool_families(self) -> None:
        for name in (
            "sh", "bash", "curl", "curl-9", "wget", "pip3.12", "make", "gcc",
            "x86_64-linux-gnu-gcc", "apt-get", "micromamba", "pixi", "git-lfs",
        ):
            with self.subTest(name=name):
                self.assertTrue(boundary.forbidden_tool_name(name))
        for name in ("python", "python3.12", "Rscript", "R", "fontconfig", "ld-linux-x86-64.so.2"):
            with self.subTest(name=name):
                self.assertFalse(boundary.forbidden_tool_name(name))

    def test_renderer_lock_contains_no_fabricated_digest(self) -> None:
        lock = json.loads((ROOT / "renderer" / "renderer-lock.json").read_text(encoding="utf-8"))
        self.assertFalse(lock["v2IntakeEnabled"])
        self.assertFalse(lock["trustedLinuxBuildVerified"])
        self.assertTrue(lock["publishBootstrapImages"])
        self.assertTrue(all(item["publishedImageDigest"] is None for item in lock["renderers"].values()))


if __name__ == "__main__":
    unittest.main()
