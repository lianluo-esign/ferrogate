#!/usr/bin/env python3
"""Tests for the repo-wide thin-lib.rs layout gate (issues #429/#433)."""

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

    def write_crate(
        self, root: pathlib.Path, crate: str, lines: int, entry: str = "lib.rs"
    ) -> None:
        src = root / "crates" / crate / "src"
        src.mkdir(parents=True, exist_ok=True)
        (src / entry).write_text("// filler\n" * lines, encoding="utf-8")

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

    def test_scans_every_crate_not_just_the_cloudflare_scope(self) -> None:
        # Issue #433: the gate covers ALL crates, including ones that were
        # outside the original #429 Cloudflare scope and brand-new ones.
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_crate(root, "brand-new-crate", 801)
            result = self.run_checker("--root", str(root))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("brand-new-crate/src/lib.rs: 801 lines", result.stderr)

    def test_scans_main_rs_entry_files_too(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_crate(root, "some-binary-crate", 801, entry="main.rs")
            result = self.run_checker("--root", str(root))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("some-binary-crate/src/main.rs: 801 lines", result.stderr)

    def test_split_auth_crate_needs_no_baseline(self) -> None:
        # ferrogate-auth was split under the cap in the same change that
        # widened the gate (#433); it must never regrow a baseline entry.
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_crate(root, "ferrogate-auth", 801)
            result = self.run_checker("--root", str(root))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ferrogate-auth/src/lib.rs: 801 lines", result.stderr)

    def test_baseline_covers_pre_existing_offender(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_crate(root, "ferrogate-storage", 18_400)
            result = self.run_checker("--root", str(root))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_baseline_still_bounds_new_growth(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_crate(root, "ferrogate-storage", 18_601)
            result = self.run_checker("--root", str(root))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("18600-line cap", result.stderr)

    def test_stale_baseline_is_flagged_for_removal(self) -> None:
        # A baselined crate refactored under the default cap should surface a
        # ratchet note so the stale entry gets deleted (as happened for
        # ferrogate-secrets after #423 and ferrogate-mcp after #432).
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_crate(root, "ferrogate-guardrails", 500)
            result = self.run_checker("--root", str(root))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("stale and should be removed", result.stdout)

    def test_threshold_override(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_crate(root, "ferrogate-cloudflare", 120)
            result = self.run_checker("--root", str(root), "--threshold", "100")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
