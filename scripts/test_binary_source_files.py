#!/usr/bin/env python3
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-25
# description: Tests for the binary-source-file gate (issue #487).
"""Tests for the gate rejecting tracked source files git treats as binary.

The point of these tests is that the gate can FAIL: a guard nobody has watched
reject something is indistinguishable from no guard at all.
"""

from __future__ import annotations

import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-binary-source-files.py"


class BinarySourceFileTests(unittest.TestCase):
    def run_checker(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(CHECKER), *args],
            text=True,
            capture_output=True,
            check=False,
        )

    def git(self, root: pathlib.Path, *args: str) -> None:
        subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
        )

    def make_repo(self, root: pathlib.Path) -> None:
        self.git(root, "init", "-q")
        self.git(root, "config", "user.email", "gate@example.invalid")
        self.git(root, "config", "user.name", "gate")

    def write(self, root: pathlib.Path, relative: str, data: bytes) -> None:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        self.git(root, "add", "--", relative)

    def test_repository_tree_passes(self) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("are text to git", result.stdout)

    def test_live_offender_is_detected_without_the_allowlist(self) -> None:
        """The allowlist is the only thing keeping the tree green, not luck."""
        result = self.run_checker("--no-allowlist")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("admin-console/src/pages/assets.tsx", result.stderr)

    def test_rejects_tracked_source_file_holding_a_nul_byte(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.make_repo(root)
            self.write(root, "src/ok.ts", b"export const ok = 1;\n")
            self.write(root, "src/bad.ts", b'export const d = "a\x00b";\n')
            result = self.run_checker("--root", str(root), "--no-allowlist")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("src/bad.ts", result.stderr)
        self.assertIn("first at byte 19 (line 1)", result.stderr)
        self.assertNotIn("src/ok.ts", result.stderr)

    def test_ignores_genuinely_binary_non_source_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.make_repo(root)
            self.write(root, "assets/logo.png", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
            self.write(root, "fixtures/corpus.bin", bytes(range(256)))
            self.write(root, "src/ok.rs", b"pub const OK: u8 = 1;\n")
            result = self.run_checker("--root", str(root), "--no-allowlist")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_respects_gitattributes_binary_declaration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.make_repo(root)
            self.write(root, ".gitattributes", b"fixtures/blob.json binary\n")
            self.write(root, "fixtures/blob.json", b"\x00\x01\x02payload")
            result = self.run_checker("--root", str(root), "--no-allowlist")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("declared binary in .gitattributes", result.stdout)

    def test_empty_source_file_is_not_binary(self) -> None:
        """`git grep -e ''` lists no lines for a 0-byte file; that is not binary."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.make_repo(root)
            self.write(root, "src/empty.rs", b"")
            result = self.run_checker("--root", str(root), "--no-allowlist")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_symlink_with_source_extension_is_not_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.make_repo(root)
            self.write(root, "src/real.rs", b"pub const OK: u8 = 1;\n")
            (root / "src" / "link.rs").symlink_to("real.rs")
            self.git(root, "add", "--", "src/link.rs")
            result = self.run_checker("--root", str(root), "--no-allowlist")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_stale_allowlist_entry_fails(self) -> None:
        """A reviewed entry whose file is clean must be deleted, not left to rot."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.make_repo(root)
            self.write(root, "src/ok.ts", b"export const ok = 1;\n")
            result = self.run_checker("--root", str(root))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("stale REVIEWED_BINARY_FILES entry", result.stderr)


if __name__ == "__main__":
    unittest.main()
