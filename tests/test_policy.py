from __future__ import annotations

import importlib.util
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
