from __future__ import annotations

import importlib.util
import binascii
import hashlib
import json
import struct
import sys
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


compare = load("compare_pr_trees", "scripts/compare_pr_trees.py")
archive = load("validate_archive", "scripts/validate_archive.py")


class PolicyTests(unittest.TestCase):
    def test_workflow_run_name_binds_exact_trusted_and_candidate_revisions(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "validate-archive-pr.yml").read_text(encoding="utf-8")
        base_expression = "${{ github.event.pull_request.base.sha }}"
        head_expression = "${{ github.event.pull_request.head.sha }}"
        expected = f"run-name: sfl-archive-validation-v2 base={base_expression} head={head_expression}"
        run_names = [line for line in workflow.splitlines() if line.lstrip().startswith("run-name:")]

        self.assertEqual(run_names, [expected])
        self.assertEqual(workflow.count(f"ref: {base_expression}"), 1)
        self.assertEqual(workflow.count(f"ref: {head_expression}"), 1)

    @staticmethod
    def png(width: int = 1, height: int = 1, rgba: bytes = bytes((20, 40, 60, 255))) -> bytes:
        def chunk(kind: bytes, payload: bytes) -> bytes:
            return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", binascii.crc32(kind + payload) & 0xFFFFFFFF)

        ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
        scanlines = b"".join(b"\x00" + rgba[row * width * 4:(row + 1) * width * 4] for row in range(height))
        return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(scanlines)) + chunk(b"IEND", b"")

    @staticmethod
    def canonical_zip(files: dict[str, bytes], *, sort_names: bool = True) -> bytes:
        with tempfile.TemporaryFile() as output:
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as handle:
                entries = sorted(files.items()) if sort_names else files.items()
                for name, data in entries:
                    info = zipfile.ZipInfo(name, (1980, 1, 1, 8, 0, 0))
                    info.create_system = 0
                    info.create_version = 20
                    info.extract_version = 20
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.flag_bits = 0x0800 if any(ord(character) > 127 for character in name) else 0
                    info.external_attr = 0
                    info.internal_attr = 0
                    handle.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
            output.seek(0)
            data = bytearray(output.read())
            eocd = data.rfind(b"PK\x05\x06")
            cursor = struct.unpack_from("<I", data, eocd + 16)[0]
            entries = struct.unpack_from("<H", data, eocd + 10)[0]
            for _ in range(entries):
                struct.pack_into("<I", data, cursor + 38, 0)
                name_length, extra_length, comment_length = struct.unpack_from("<HHH", data, cursor + 28)
                cursor += 46 + name_length + extra_length + comment_length
            return bytes(data)

    def test_strict_ascii_template_identity(self) -> None:
        for value in ("example-template", "a", "plot.v2"):
            self.assertIsNotNone(compare.TEMPLATE_ID.fullmatch(value))
            self.assertIsNotNone(archive.ID.fullmatch(value))
        for value in ("Example", "模板", "a\nbranch", "-leading", "trailing-"):
            self.assertIsNone(compare.TEMPLATE_ID.fullmatch(value))
            self.assertIsNone(archive.ID.fullmatch(value))

    def test_strict_semver_2(self) -> None:
        accepted = ("1.0.0", "0.0.0-alpha.1", "2.3.4-rc.1+build.9")
        rejected = ("01.0.0", "1.0", "1.0.0-01", "1.0.0-'bad'", "1.0.0\nnext")
        for value in accepted:
            self.assertIsNotNone(compare.SEMVER.fullmatch(value))
            self.assertIsNotNone(archive.SEMVER.fullmatch(value))
        for value in rejected:
            self.assertIsNone(compare.SEMVER.fullmatch(value))
            self.assertIsNone(archive.SEMVER.fullmatch(value))

    def test_portable_path_rejects_control_and_windows_metacharacters(self) -> None:
        self.assertEqual(archive.canonical_path("payload/code/render.R"), "payload/code/render.R")
        for value in ("payload/../secret", "payload/a:b", "payload/a\nname", "payload/CON"):
            with self.assertRaises(SystemExit):
                archive.canonical_path(value)

    def test_committed_tree_observes_one_matching_archive_blob(self) -> None:
        archive_path = "archives/example-template/1.0.0/example-template-1.0.0.zip"
        base = {"README.md": compare.TreeEntry("100644", "blob", "1" * 40)}
        candidate = {**base, archive_path: compare.TreeEntry("100644", "blob", "2" * 40)}
        self.assertEqual(compare.validate_archive_tree_change(base, candidate), archive_path)
        decision = compare.validate_archive_tree_policy(base, candidate)
        self.assertEqual(decision.mode, "add")
        self.assertEqual(decision.archive, archive_path)

    @staticmethod
    def invalid_seed_withdrawal_trees() -> tuple[dict[str, object], dict[str, object]]:
        base: dict[str, object] = {
            "README.md": compare.TreeEntry("100644", "blob", "1" * 40),
            ".github/workflows/validate-archive-pr.yml": compare.TreeEntry("100644", "blob", "2" * 40),
            "scripts/compare_pr_trees.py": compare.TreeEntry("100644", "blob", "3" * 40),
            "schemas/public-template-archive.v1.schema.json": compare.TreeEntry("100644", "blob", "4" * 40),
        }
        base.update({
            path: compare.TreeEntry("100644", "blob", oid)
            for path, oid in compare.EXACT_INVALID_SEED_WITHDRAWAL.items()
        })
        candidate = {
            path: entry
            for path, entry in base.items()
            if path not in compare.EXACT_INVALID_SEED_WITHDRAWAL
        }
        return base, candidate

    def test_exact_three_invalid_seed_withdrawal_is_atomic_and_oid_bound(self) -> None:
        base, candidate = self.invalid_seed_withdrawal_trees()
        decision = compare.validate_archive_tree_policy(base, candidate)
        self.assertEqual(decision.mode, "withdrawal")
        self.assertIsNone(decision.archive)
        self.assertEqual(decision.withdrawn, tuple(sorted(compare.EXACT_INVALID_SEED_WITHDRAWAL)))

    def test_invalid_seed_withdrawal_rejects_partial_extra_or_wrong_path_deletion(self) -> None:
        base, exact_candidate = self.invalid_seed_withdrawal_trees()
        paths = sorted(compare.EXACT_INVALID_SEED_WITHDRAWAL)
        cases = {
            "partial": {**exact_candidate, paths[0]: base[paths[0]]},
            "extra": {path: entry for path, entry in exact_candidate.items() if path != "README.md"},
            "case drift": {
                **exact_candidate,
                paths[0].upper(): base[paths[0]],
            },
        }
        for label, candidate in cases.items():
            with self.subTest(label=label), self.assertRaisesRegex(SystemExit, "atomically delete only the three exact"):
                compare.validate_archive_tree_policy(base, candidate)

    def test_invalid_seed_withdrawal_rejects_any_addition_modification_or_policy_drift(self) -> None:
        base, exact_candidate = self.invalid_seed_withdrawal_trees()
        cases = {
            "addition": {
                **exact_candidate,
                "archives/other/1.0.0/other-1.0.0.zip": compare.TreeEntry("100644", "blob", "5" * 40),
            },
            "ordinary modification": {
                **exact_candidate,
                "README.md": compare.TreeEntry("100644", "blob", "6" * 40),
            },
            "workflow drift": {
                **exact_candidate,
                ".github/workflows/validate-archive-pr.yml": compare.TreeEntry("100644", "blob", "7" * 40),
            },
            "schema drift": {
                **exact_candidate,
                "schemas/public-template-archive.v1.schema.json": compare.TreeEntry("100644", "blob", "8" * 40),
            },
            "policy drift": {
                **exact_candidate,
                "scripts/compare_pr_trees.py": compare.TreeEntry("100644", "blob", "9" * 40),
            },
        }
        for label, candidate in cases.items():
            with self.subTest(label=label), self.assertRaisesRegex(SystemExit, "atomically delete only the three exact"):
                compare.validate_archive_tree_policy(base, candidate)

    def test_invalid_seed_withdrawal_rejects_base_blob_oid_drift(self) -> None:
        base, candidate = self.invalid_seed_withdrawal_trees()
        path = sorted(compare.EXACT_INVALID_SEED_WITHDRAWAL)[0]
        base[path] = compare.TreeEntry("100644", "blob", "a" * 40)
        with self.assertRaisesRegex(SystemExit, "base blob identity mismatch"):
            compare.validate_archive_tree_policy(base, candidate)

    def test_withdrawn_invalid_seed_identity_cannot_be_readded(self) -> None:
        base = {"README.md": compare.TreeEntry("100644", "blob", "1" * 40)}
        for path, oid in compare.EXACT_INVALID_SEED_WITHDRAWAL.items():
            with self.subTest(path=path):
                candidate = {**base, path: compare.TreeEntry("100644", "blob", oid)}
                with self.assertRaisesRegex(SystemExit, "identity is retired"):
                    compare.validate_archive_tree_policy(base, candidate)

    def test_invalid_seed_withdrawal_rejects_mode_or_symlink_drift(self) -> None:
        base, exact_candidate = self.invalid_seed_withdrawal_trees()
        cases = {
            "executable": {
                **exact_candidate,
                "README.md": compare.TreeEntry("100755", "blob", "1" * 40),
            },
            "symlink": {
                **exact_candidate,
                "README.md": compare.TreeEntry("120000", "blob", "1" * 40),
            },
        }
        for label, candidate in cases.items():
            with self.subTest(label=label), self.assertRaisesRegex(SystemExit, "non-100644"):
                compare.validate_archive_tree_policy(base, candidate)

    def test_workflow_renders_additions_and_never_renders_withdrawals(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "validate-archive-pr.yml").read_text(encoding="utf-8")
        self.assertEqual(workflow.count("if: steps.policy.outputs.mode == 'add'"), 4)
        self.assertEqual(workflow.count("if: steps.policy.outputs.mode == 'withdrawal'"), 1)
        self.assertIn("python3 trusted/scripts/compare_pr_trees.py", workflow)
        self.assertIn("Archive extraction and rendering are intentionally skipped", workflow)

    def test_committed_tree_rejects_gitlink_even_with_one_zip(self) -> None:
        archive_path = "archives/example-template/1.0.0/example-template-1.0.0.zip"
        base = {"README.md": compare.TreeEntry("100644", "blob", "1" * 40)}
        candidate = {
            **base,
            archive_path: compare.TreeEntry("100644", "blob", "2" * 40),
            "vendor/submodule": compare.TreeEntry("160000", "commit", "3" * 40),
        }
        with self.assertRaisesRegex(SystemExit, "gitlink"):
            compare.validate_archive_tree_change(base, candidate)

    def test_committed_tree_rejects_existing_mode_change(self) -> None:
        base = {"scripts/validator.py": compare.TreeEntry("100644", "blob", "1" * 40)}
        candidate = {
            "scripts/validator.py": compare.TreeEntry("100755", "blob", "1" * 40),
            "archives/example-template/1.0.0/example-template-1.0.0.zip": compare.TreeEntry("100644", "blob", "2" * 40),
        }
        with self.assertRaisesRegex(SystemExit, "non-100644"):
            compare.validate_archive_tree_change(base, candidate)

    def test_template_identity_rejects_windows_reserved_names(self) -> None:
        for value in ("con", "aux.txt", "nul", "com1", "lpt9.json"):
            self.assertFalse(compare.valid_template_id(value))
            self.assertFalse(archive.valid_template_id(value))

    def test_png_decoder_rejects_oversized_canonical_rgba_before_allocation(self) -> None:
        def chunk(kind: bytes, payload: bytes) -> bytes:
            return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", binascii.crc32(kind + payload) & 0xFFFFFFFF)

        width = 16_384
        height = 16_384
        ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
        png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(b"")) + chunk(b"IEND", b"")
        with self.assertRaisesRegex(SystemExit, "canonical RGBA payload exceeds"):
            archive.decode_png_rgba(png)

    def test_post_render_requires_exact_archived_png_sha(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staging = root / "submission"
            staging.mkdir()
            rendered = root / "preview.png"
            png = self.png()
            rendered.write_bytes(png)
            (staging / "render-receipt.json").write_text(json.dumps({
                "width": 1,
                "height": 1,
                "previewBytes": len(png),
                "canonicalRgbaSha256": hashlib.sha256(bytes((20, 40, 60, 255))).hexdigest(),
                "previewSha256": "0" * 64,
            }), encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "PNG SHA-256 differs"):
                archive.post_render(staging, rendered)

    def test_archive_rejects_every_undeclared_nested_file(self) -> None:
        declared = {
            "payload/template.json",
            "payload/code/render.R",
            "payload/data/synthetic.csv",
            "payload/docs/README.md",
            "payload/preview/preview.png",
        }
        observed = archive.FIXED_METADATA_FILES | declared
        archive.validate_declared_file_set(observed, declared)
        for extra in (
            "extras/patient-record.pdf",
            "payload/source-reference/paper.pdf",
            "payload/docs/undeclared-extra.md",
        ):
            with self.subTest(extra=extra), self.assertRaisesRegex(SystemExit, "unexpected=.*" + extra.replace(".", r"\.")):
                archive.validate_declared_file_set(observed | {extra}, declared)

    def test_outer_archive_identity_must_match_inner_submission(self) -> None:
        archive.validate_expected_archive_identity("example-template", "1.0.0", "example-template", "1.0.0")
        with self.assertRaisesRegex(SystemExit, "outer archive path identity disagrees"):
            archive.validate_expected_archive_identity("inner-template", "1.0.0", "outer-template", "1.0.0")
        with self.assertRaisesRegex(SystemExit, "outer archive path identity disagrees"):
            archive.validate_expected_archive_identity("example-template", "1.0.1", "example-template", "1.0.0")

    def test_png_decoder_rejects_bytes_after_iend(self) -> None:
        with self.assertRaisesRegex(SystemExit, "no trailing bytes"):
            archive.decode_png_rgba(self.png() + b"hidden-payload")

    def test_png_decoder_rejects_metadata_and_unknown_chunks(self) -> None:
        def chunk(kind: bytes, payload: bytes) -> bytes:
            return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", binascii.crc32(kind + payload) & 0xFFFFFFFF)

        png = self.png()
        for kind in (b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"vpAg"):
            candidate = png[:-12] + chunk(kind, b"hidden metadata") + png[-12:]
            with self.subTest(kind=kind), self.assertRaisesRegex(SystemExit, "metadata-free publication dialect"):
                archive.decode_png_rgba(candidate)

    def test_png_decoder_rejects_noncanonical_chunk_order_and_singletons(self) -> None:
        def chunk(kind: bytes, payload: bytes) -> bytes:
            return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", binascii.crc32(kind + payload) & 0xFFFFFFFF)

        ihdr_payload = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
        ihdr = chunk(b"IHDR", ihdr_payload)
        idat = chunk(b"IDAT", zlib.compress(b"\x00\x14\x28\x3c\xff"))
        iend = chunk(b"IEND", b"")
        signature = b"\x89PNG\r\n\x1a\n"
        cases = {
            "duplicate IHDR": signature + ihdr + ihdr + idat + iend,
            "multiple IDAT": signature + ihdr + idat + chunk(b"IDAT", b"x") + iend,
            "PLTE after IDAT": signature + ihdr + idat + chunk(b"PLTE", b"\x00\x00\x00") + iend,
            "non-empty IEND": signature + ihdr + idat + chunk(b"IEND", b"x"),
            "duplicate IEND": signature + ihdr + idat + iend + iend,
            "IDAT before IHDR": signature + idat + ihdr + iend,
            "missing IEND": signature + ihdr + idat,
            "tRNS before PLTE": signature + ihdr + chunk(b"tRNS", b"\xff") + idat + iend,
        }
        for label, candidate in cases.items():
            with self.subTest(label=label), self.assertRaises(SystemExit):
                archive.decode_png_rgba(candidate)

    def test_zip_metadata_channels_and_local_gaps_are_rejected(self) -> None:
        canonical = self.canonical_zip({"a.txt": b"a", "b.txt": b"b"})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def assert_rejected(data: bytes, message: str) -> None:
                target = root / f"case-{len(list(root.iterdir()))}.zip"
                target.write_bytes(data)
                with self.assertRaisesRegex(SystemExit, message):
                    archive.validate_zip_structure(target)

            accepted = root / "accepted.zip"
            accepted.write_bytes(canonical)
            archive.validate_zip_structure(accepted)

            with tempfile.TemporaryFile() as output:
                with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as handle:
                    info = zipfile.ZipInfo("a.txt", (1980, 1, 1, 8, 0, 0))
                    info.create_system = 0
                    info.comment = b"hidden entry comment"
                    info.extra = b"\x99\x99\x02\x00xx"
                    handle.writestr(info, b"a")
                    handle.comment = b"hidden global comment"
                output.seek(0)
                assert_rejected(output.read(), "global comments")

            data = bytearray(canonical)
            eocd = data.rfind(b"PK\x05\x06")
            central_offset = struct.unpack_from("<I", data, eocd + 16)[0]
            gap = b"HIDDEN"
            data[central_offset:central_offset] = gap
            struct.pack_into("<I", data, eocd + len(gap) + 16, central_offset + len(gap))
            assert_rejected(bytes(data), "gap or hidden payload")

            with tempfile.TemporaryFile() as output:
                with zipfile.ZipFile(output, "w") as handle:
                    handle.writestr("directory/", b"")
                    handle.writestr("directory/a.txt", b"a")
                output.seek(0)
                assert_rejected(output.read(), "directory entries")

    def test_zip_dialect_rejects_each_metadata_deviation_and_entry_order(self) -> None:
        canonical = self.canonical_zip({"a.txt": b"a", "b.txt": b"b"})

        def central_offset(data: bytes) -> int:
            eocd = data.rfind(b"PK\x05\x06")
            return struct.unpack_from("<I", data, eocd + 16)[0]

        def mutate_both(data: bytes, central_field: int, local_field: int, value: int, fmt: str = "<H") -> bytes:
            changed = bytearray(data)
            central = central_offset(changed)
            local = struct.unpack_from("<I", changed, central + 42)[0]
            struct.pack_into(fmt, changed, central + central_field, value)
            struct.pack_into(fmt, changed, local + local_field, value)
            return bytes(changed)

        def add_central_payload(data: bytes, *, field_offset: int, payload: bytes) -> bytes:
            changed = bytearray(data)
            old_eocd = changed.rfind(b"PK\x05\x06")
            central = central_offset(changed)
            name_length, extra_length, comment_length = struct.unpack_from("<HHH", changed, central + 28)
            insert_at = central + 46 + name_length + extra_length + comment_length
            changed[insert_at:insert_at] = payload
            struct.pack_into("<H", changed, central + field_offset, len(payload))
            new_eocd = old_eocd + len(payload)
            old_size = struct.unpack_from("<I", changed, new_eocd + 12)[0]
            struct.pack_into("<I", changed, new_eocd + 12, old_size + len(payload))
            return bytes(changed)

        central = central_offset(canonical)
        local = struct.unpack_from("<I", canonical, central + 42)[0]
        local_extra = bytearray(canonical)
        struct.pack_into("<H", local_extra, local + 28, 1)

        external_attr = bytearray(canonical)
        struct.pack_into("<I", external_attr, central + 38, 1)

        cases = {
            "entry comment": add_central_payload(canonical, field_offset=32, payload=b"x"),
            "central extra": add_central_payload(canonical, field_offset=30, payload=b"x"),
            "local extra": bytes(local_extra),
            "timestamp": mutate_both(canonical, 12, 10, 0x4001),
            "flags": mutate_both(canonical, 8, 6, 0x0008),
            "method": mutate_both(canonical, 10, 8, zipfile.ZIP_STORED),
            "external attributes": bytes(external_attr),
            "entry order": self.canonical_zip({"b.txt": b"b", "a.txt": b"a"}, sort_names=False),
            "prepended bytes": b"HIDDEN" + canonical,
            "trailing bytes": canonical + b"HIDDEN",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, (label, data) in enumerate(cases.items()):
                target = root / f"case-{index}.zip"
                target.write_bytes(data)
                with self.subTest(label=label), self.assertRaises(SystemExit):
                    archive.validate_zip_structure(target)

    def test_isolated_render_root_cannot_read_archived_preview(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staging = root / "submission"
            render_root = root / "render-root"
            files = {
                "payload/code/render.R": b"writeBin(raw(), output_file)",
                "payload/data/synthetic.csv": b"x,y\n1,2\n",
                "payload/preview/preview.png": self.png(),
                "payload/docs/README.md": b"public documentation",
                "payload/template.json": b"{}",
                "submission.json": b"{}",
            }
            for name, data in files.items():
                target = staging / Path(*name.split("/"))
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)

            selected = {"payload/code/render.R", "payload/data/synthetic.csv"}
            archive.build_isolated_render_root(staging, render_root, selected)
            self.assertEqual((render_root / "payload/code/render.R").read_bytes(), files["payload/code/render.R"])
            self.assertEqual((render_root / "payload/data/synthetic.csv").read_bytes(), files["payload/data/synthetic.csv"])
            with self.assertRaises(FileNotFoundError):
                (render_root / "payload/preview/preview.png").read_bytes()
            self.assertFalse((render_root / "payload/docs/README.md").exists())
            self.assertFalse((render_root / "payload/template.json").exists())
            self.assertFalse((render_root / "submission.json").exists())

    def test_public_text_validation_rejects_disguised_binary_bom_nul_and_private_paths(self) -> None:
        cases = {
            "payload/code/fake-pdf.R": b"%PDF-1.7\n",
            "payload/docs/fake-zip.md": b"PK\x03\x04binary",
            "payload/docs/bom.md": b"\xef\xbb\xbftext",
            "payload/docs/nul.txt": b"text\x00hidden",
            "payload/docs/unc.md": b"see \\\\private-server\\patient-share\\case.txt",
            "payload/docs/unix.md": b"source=/workspace/private/data.txt",
        }
        for name, data in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                target = root / Path(*name.split("/"))
                target.parent.mkdir(parents=True)
                target.write_bytes(data)
                with self.assertRaises(SystemExit):
                    archive.validate_private_text(root, {name})

    def test_public_json_and_delimited_text_require_basic_structure(self) -> None:
        cases = {
            "payload/data/bad.json": b"{not-json}",
            "payload/data/header-only.csv": b"x,y\n",
            "payload/data/ragged.tsv": b"x\ty\n1\n",
        }
        for name, data in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                target = root / Path(*name.split("/"))
                target.parent.mkdir(parents=True)
                target.write_bytes(data)
                with self.assertRaises(SystemExit):
                    archive.validate_private_text(root, {name})

    def test_post_render_rejects_size_before_reading_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staging = root / "submission"
            staging.mkdir()
            rendered = root / "preview.png"
            rendered.write_bytes(self.png())
            (staging / "render-receipt.json").write_text(json.dumps({"previewBytes": len(self.png()) + 1}), encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "byte length differs"):
                archive.post_render(staging, rendered)

            class SymlinkOutput:
                read_attempted = False

                @staticmethod
                def is_file() -> bool:
                    return True

                @staticmethod
                def is_symlink() -> bool:
                    return True

                def read_bytes(self) -> bytes:
                    self.read_attempted = True
                    raise AssertionError("symlink output must be rejected before reading")

            (staging / "render-receipt.json").write_text(json.dumps({"previewBytes": 1}), encoding="utf-8")
            symlink = SymlinkOutput()
            with self.assertRaisesRegex(SystemExit, "regular non-symlink"):
                archive.post_render(staging, symlink)  # type: ignore[arg-type]
            self.assertFalse(symlink.read_attempted)


if __name__ == "__main__":
    unittest.main()
