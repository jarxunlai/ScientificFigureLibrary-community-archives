from __future__ import annotations

import importlib.util
import binascii
import hashlib
import json
import struct
import tempfile
import unittest
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


compare = load("compare_pr_trees", "scripts/compare_pr_trees.py")
archive = load("validate_archive", "scripts/validate_archive.py")


class PolicyTests(unittest.TestCase):
    @staticmethod
    def png(width: int = 1, height: int = 1, rgba: bytes = bytes((20, 40, 60, 255))) -> bytes:
        def chunk(kind: bytes, payload: bytes) -> bytes:
            return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", binascii.crc32(kind + payload) & 0xFFFFFFFF)

        ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
        scanlines = b"".join(b"\x00" + rgba[row * width * 4:(row + 1) * width * 4] for row in range(height))
        return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(scanlines)) + chunk(b"IEND", b"")

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

    def test_inventory_observes_one_matching_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / "base"
            candidate = root / "candidate"
            (base / "archives").mkdir(parents=True)
            target = candidate / "archives" / "example-template" / "1.0.0" / "example-template-1.0.0.zip"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"zip")
            added = set(compare.inventory(candidate)) - set(compare.inventory(base))
            self.assertEqual(added, {"archives/example-template/1.0.0/example-template-1.0.0.zip"})

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
                "canonicalRgbaSha256": hashlib.sha256(bytes((20, 40, 60, 255))).hexdigest(),
                "previewSha256": "0" * 64,
            }), encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "PNG SHA-256 differs"):
                archive.post_render(staging, rendered)


if __name__ == "__main__":
    unittest.main()
