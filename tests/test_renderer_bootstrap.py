from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


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
r_launcher = load("renderer_r_launcher", "renderer/r_launcher.py")
protocol_shim = load("renderer_protocol_shim", "renderer/protocol_shim.py")


class RendererBootstrapTests(unittest.TestCase):
    def test_shell_free_r_launcher_execs_only_the_pinned_direct_binary(self):
        original = list(sys.argv)
        try:
            sys.argv = ["R", "--vanilla", "-e", "cat(getRversion())"]
            with mock.patch.object(r_launcher.os, "execve") as execute:
                r_launcher.main()
            execute.assert_called_once()
            executable, arguments, environment = execute.call_args.args
            self.assertEqual(executable, "/opt/sfl/.pixi/envs/default/lib/R/bin/exec/R")
            self.assertEqual(
                arguments,
                [executable, "--vanilla", "-e", "cat(getRversion())"],
            )
            self.assertEqual(environment["R_HOME"], "/opt/sfl/.pixi/envs/default/lib/R")
            self.assertEqual(environment["R_SHARE_DIR"], f'{environment["R_HOME"]}/share')
            self.assertEqual(environment["R_INCLUDE_DIR"], f'{environment["R_HOME"]}/include')
            self.assertEqual(environment["R_DOC_DIR"], f'{environment["R_HOME"]}/doc')
            self.assertEqual(environment["R_ARCH"], "")
            self.assertEqual(environment["R_LIBS_SITE"], f'{environment["R_HOME"]}/library')
            self.assertEqual(environment["R_LIBS_USER"], "/nonexistent")
            self.assertEqual(
                environment["LD_LIBRARY_PATH"],
                "/opt/sfl/.pixi/envs/default/lib/R/lib:/opt/sfl/.pixi/envs/default/lib",
            )
        finally:
            sys.argv = original

    def test_renderer_runtime_verification_binds_explicit_r_library_paths(self) -> None:
        for runner in (r_runner, python_runner):
            with self.subTest(runner=runner.__name__), mock.patch.object(
                runner, "verify_runtime_identity"
            ), mock.patch.object(
                runner.sys, "version_info", (3, 12, 12)
            ), mock.patch(
                "importlib.metadata.version",
                side_effect=lambda package: runner.EXPECTED_PYTHON_PACKAGES[package],
            ), mock.patch.object(runner.subprocess, "run") as run:
                runner.verify_runtime()
                run.assert_called_once()
                command = run.call_args.args[0]
                environment = run.call_args.kwargs["env"]
                self.assertEqual(command[:3], [
                    "/opt/sfl/.pixi/envs/default/bin/Rscript", "--vanilla", "-e",
                ])
                self.assertIn('invisible(loadNamespace("utils"))', command[3])
                self.assertIn('utils::packageVersion("ggplot2")', command[3])
                self.assertEqual(environment["R_DEFAULT_PACKAGES"], "NULL")
                self.assertEqual(environment["R_HOME"], "/opt/sfl/.pixi/envs/default/lib/R")
                self.assertEqual(environment["R_LIBS_SITE"], "/opt/sfl/.pixi/envs/default/lib/R/library")
                self.assertEqual(environment["R_LIBS_USER"], "/nonexistent")

    def test_protocol_shim_accepts_only_the_fixed_r_to_python_helper_argv(self):
        command = (
            "'/opt/sfl/mixed_helper.py' --helper payload/code/helpers/model.py "
            "-- --label 'value with spaces'"
        )
        self.assertEqual(
            protocol_shim.parse_allowed_command(["/bin/sh", "-c", command]),
            ["--helper", "payload/code/helpers/model.py", "--", "--label", "value with spaces"],
        )

        rejected = (
            ["/bin/sh", "-ec", command],
            ["/bin/sh", "-c", command, "extra"],
            ["/bin/sh", "-c", "/usr/bin/which 'uname' 2>/dev/null"],
            ["/bin/sh", "-c", "LANG=C /opt/sfl/mixed_helper.py --helper payload/code/helper.py"],
            ["/bin/sh", "-c", "/opt/sfl/mixed_helper.py payload/code/helper.py"],
            ["/bin/sh", "-c", "/opt/sfl/mixed_helper.py --helper payload/code/render.py"],
            ["/bin/sh", "-c", "/opt/sfl/mixed_helper.py --helper payload/code/helper.R"],
            ["/bin/sh", "-c", "/opt/sfl/mixed_helper.py --helper payload/code/helper.py --helper payload/code/other.R"],
            ["/bin/sh", "-c", "/opt/sfl/mixed_helper.py --helper payload/code/helper.py --value 7"],
            ["/bin/sh", "-c", "/opt/sfl/mixed_helper.py --helper payload/code/../helper.py"],
            ["/bin/sh", "-c", "/opt/sfl/mixed_helper.py --helper payload/code/helper.py; /bin/id"],
            ["/bin/sh", "-c", "/opt/sfl/mixed_helper.py --helper payload/code/helper.py > /tmp/out"],
            ["/bin/sh", "-c", "/opt/sfl/mixed_helper.py --helper payload/code/helper.py $(id)"],
            ["/bin/sh", "-c", "/opt/sfl/mixed_helper.py --helper payload/code/helper.py `id`"],
            ["/bin/sh", "-c", "/opt/sfl/mixed_helper.py --helper 'unterminated"],
            ["/bin/sh", "-c", "/opt/sfl/mixed_helper.py\n--helper payload/code/helper.py"],
        )
        for arguments in rejected:
            with self.subTest(arguments=arguments):
                self.assertIsNone(protocol_shim.parse_allowed_command(arguments))

    def test_protocol_shim_rejects_absent_helper_and_execs_with_fixed_argv_and_environment(self):
        original = list(sys.argv)
        command = "/opt/sfl/mixed_helper.py --helper payload/code/helper.py -- --value 7"
        try:
            sys.argv = ["/bin/sh", "-c", command]
            with mock.patch.object(protocol_shim.os.path, "isfile", return_value=False), mock.patch.object(
                protocol_shim.os, "execve"
            ) as execute:
                self.assertEqual(protocol_shim.main(), protocol_shim.REJECTED)
                execute.assert_not_called()

            with mock.patch.dict(protocol_shim.os.environ, {"LANG": "C.UTF-8", "UNSAFE": "drop-me"}, clear=True), mock.patch.object(
                protocol_shim.os.path, "isfile", return_value=True
            ), mock.patch.object(protocol_shim.os.path, "islink", return_value=False), mock.patch.object(
                protocol_shim.os, "execve", side_effect=RuntimeError("execve replaces the process")
            ) as execute:
                with self.assertRaisesRegex(RuntimeError, "execve replaces the process"):
                    protocol_shim.main()
                execute.assert_called_once()
                executable, arguments, environment = execute.call_args.args
                self.assertEqual(executable, protocol_shim.PYTHON)
                self.assertEqual(
                    arguments,
                    [
                        protocol_shim.PYTHON,
                        "-I",
                        "-B",
                        protocol_shim.MIXED_HELPER,
                        "--helper",
                        "payload/code/helper.py",
                        "--",
                        "--value",
                        "7",
                    ],
                )
                self.assertEqual(environment["LANG"], "C.UTF-8")
                self.assertNotIn("UNSAFE", environment)
                self.assertEqual(environment["PATH"], "/opt/sfl/.pixi/envs/default/bin")
                self.assertEqual(environment["SFL_MIXED_HELPER_RUNNER"], protocol_shim.MIXED_HELPER)

            with mock.patch.object(protocol_shim.os.path, "isfile", return_value=True), mock.patch.object(
                protocol_shim.os.path, "islink", return_value=False
            ), mock.patch.object(protocol_shim.os, "execve", side_effect=OSError("exec failed")):
                self.assertEqual(protocol_shim.main(), protocol_shim.REJECTED)
        finally:
            sys.argv = original

    def test_finalize_runtime_uses_python_for_mode_and_bootstrap_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "opt" / "sfl" / "runner.py"
            tools = root / "opt" / "sfl" / "bootstrap-tools"
            runner.parent.mkdir(parents=True)
            tools.mkdir(parents=True)
            runner.write_text("print('runner')\n", encoding="utf-8")
            runner.chmod(0o644)
            (tools / "temporary.py").write_text("pass\n", encoding="utf-8")
            forbidden = root / "usr" / "bin" / "make"
            forbidden.parent.mkdir(parents=True)
            forbidden.write_bytes(b"forbidden build tool")

            removed = sanitize.finalize_runtime(root, runner, tools)

            self.assertEqual(removed, ["usr/bin/make"])
            self.assertFalse(forbidden.exists())
            self.assertTrue(runner.is_file())
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(runner.stat().st_mode), 0o555)
            self.assertFalse(tools.exists())

    def test_finalize_runtime_rejects_unsafe_runner_and_cleanup_relationships(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "opt" / "sfl" / "runner.py"
            tools = root / "opt" / "sfl" / "bootstrap-tools"
            runner.parent.mkdir(parents=True)
            tools.mkdir(parents=True)
            runner.write_text("print('runner')\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "separate paths"):
                sanitize.finalize_runtime(root, runner, root)
            with self.assertRaisesRegex(ValueError, "separate paths"):
                sanitize.finalize_runtime(root, runner, runner.parent)

            cleanup_file = root / "cleanup-file"
            cleanup_file.write_text("not a directory\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "regular non-symlink directory"):
                sanitize.finalize_runtime(root, runner, cleanup_file)
            self.assertTrue(cleanup_file.is_file())

            outside = root.parent / f"{root.name}-outside"
            outside.mkdir()
            try:
                with self.assertRaisesRegex(ValueError, "inside the finalized root"):
                    sanitize.finalize_runtime(root, runner, outside)
                self.assertTrue(outside.is_dir())
            finally:
                outside.rmdir()

    def test_finalize_runtime_rejects_symlink_cleanup_without_following_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "runner.py"
            tools = root / "bootstrap-tools"
            sibling = root / "must-remain"
            runner.write_text("print('runner')\n", encoding="utf-8")
            tools.mkdir()
            sibling.mkdir()
            (sibling / "evidence.txt").write_text("retain\n", encoding="utf-8")
            original_lstat = Path.lstat
            symlink_info = os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 1, 0, 0, 0, 0, 0, 0))

            def observed_lstat(path):
                return symlink_info if path == tools else original_lstat(path)

            with mock.patch.object(Path, "lstat", observed_lstat):
                with self.assertRaisesRegex(ValueError, "regular non-symlink directory"):
                    sanitize.finalize_runtime(root, runner, tools)
            self.assertEqual((sibling / "evidence.txt").read_text(encoding="utf-8"), "retain\n")

    def test_finalize_runtime_rejects_symlink_runner(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "runner.py"
            tools = root / "bootstrap-tools"
            runner.write_text("print('runner')\n", encoding="utf-8")
            tools.mkdir()
            symlink_info = os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            with mock.patch.object(Path, "lstat", return_value=symlink_info):
                with self.assertRaisesRegex(ValueError, "regular non-symlink"):
                    sanitize.finalize_runtime(root, runner, tools)

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
    def minimum_rootfs(
        extra: list[tuple[str, bytes, int, bytes | None]] | None = None,
        *,
        shim_payload: bytes | None = None,
        shim_mode: int = 0o555,
        bin_target: bytes = b"usr/bin",
    ):
        if shim_payload is None:
            shim_payload = (ROOT / "renderer" / "protocol_shim.py").read_bytes()
        entries = [
            ("bin", tarfile.SYMTYPE, 0o777, bin_target),
            ("usr/bin/sh", b"file", shim_mode, shim_payload),
            ("opt/sfl/.pixi/envs/default/bin/R", b"file", 0o555, b"R launcher"),
            ("opt/sfl/.pixi/envs/default/bin/python", b"file", 0o755, b"python"),
            ("opt/sfl/.pixi/envs/default/bin/Rscript", b"file", 0o755, b"Rscript"),
            ("opt/sfl/.pixi/envs/default/lib/R/bin/R", b"file", 0o555, b"R launcher"),
            ("opt/sfl/.pixi/envs/default/lib/R/bin/exec/R", b"file", 0o755, b"native R"),
            ("opt/sfl/runner.py", b"file", 0o555, b"runner"),
        ]
        return entries + (extra or [])

    def test_rootfs_audit_accepts_and_inventories_minimal_disabled_renderer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "rootfs.tar"
            self.write_tar(archive, self.minimum_rootfs())
            inventory = audit.audit_rootfs(archive)
            self.assertEqual(inventory["schema"], audit.INVENTORY_SCHEMA)
            self.assertEqual(inventory["executableCount"], len(audit.REQUIRED_EXECUTABLES))
            rows = inventory["executables"]
            self.assertEqual({row["path"] for row in rows}, set(audit.REQUIRED_EXECUTABLES))
            self.assertTrue(all(len(row["sha256"]) == 64 for row in rows))

    def test_rootfs_audit_requires_every_pinned_runtime_executable(self) -> None:
        baseline = self.minimum_rootfs()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, required in enumerate(audit.REQUIRED_EXECUTABLES):
                archive = root / f"missing-required-{index}.tar"
                self.write_tar(archive, [entry for entry in baseline if entry[0] != required])
                with self.subTest(required=required), self.assertRaisesRegex(
                    SystemExit, "executable boundary failed"
                ):
                    audit.audit_rootfs(archive)

    def test_rootfs_audit_binds_the_only_shell_path_to_exact_protocol_shim(self) -> None:
        cases = {
            "changed bytes": self.minimum_rootfs(shim_payload=b"#!/fixed/python\nraise SystemExit(126)\n"),
            "changed mode": self.minimum_rootfs(shim_mode=0o755),
            "changed merged usr target": self.minimum_rootfs(bin_target=b"opt/sfl"),
            "non-exact merged usr target": self.minimum_rootfs(bin_target=b"./usr/bin"),
            "additional shell": self.minimum_rootfs([("usr/local/bin/sh", b"file", 0o555, b"fake")]),
            "shell symlink alias": self.minimum_rootfs(
                [("usr/local/bin/sh", tarfile.SYMTYPE, 0o777, b"/bin/python")]
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, (label, entries) in enumerate(cases.items()):
                archive = root / f"protocol-{index}.tar"
                self.write_tar(archive, entries)
                with self.subTest(label=label), self.assertRaisesRegex(SystemExit, "executable boundary failed"):
                    audit.audit_rootfs(archive)

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
