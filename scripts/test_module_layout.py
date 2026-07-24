#!/usr/bin/env python3
"""Tests for the Cloudflare-scope thin-lib.rs layout gate (issue #429)."""

from __future__ import annotations

import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-module-layout.py"


class ModuleLayoutTests(unittest.TestCase):
    def run_checker(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(CHECKER), *args],
            text=True,
            capture_output=True,
            check=False,
        )

    def write_crate(self, root: pathlib.Path, crate: str, lines: int) -> None:
        src = root / "crates" / crate / "src"
        src.mkdir(parents=True)
        (src / "lib.rs").write_text("// filler\n" * lines, encoding="utf-8")

    def test_repository_tree_passes(self) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("validated modular layout", result.stdout)

    def test_accepts_thin_entry_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_crate(root, "ferrogate-cloudflare", 120)
            result = self.run_checker("--root", str(root))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_oversized_non_baselined_entry_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_crate(root, "ferrogate-cloudflare", 801)
            result = self.run_checker("--root", str(root))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ferrogate-cloudflare/src/lib.rs: 801 lines", result.stderr)

    def test_baseline_covers_pre_existing_offender(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_crate(root, "ferrogate-storage", 21_000)
            result = self.run_checker("--root", str(root))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_baseline_still_bounds_new_growth(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_crate(root, "ferrogate-storage", 21_501)
            result = self.run_checker("--root", str(root))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("21500-line cap", result.stderr)

    def test_threshold_override(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_crate(root, "ferrogate-cloudflare", 120)
            result = self.run_checker("--root", str(root), "--threshold", "100")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
