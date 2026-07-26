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

import contextlib
import importlib.util
import io
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-binary-source-files.py"


def load_checker():
    """Import the gate as a module (its filename is not a Python identifier)."""
    spec = importlib.util.spec_from_file_location("check_binary_source_files", CHECKER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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

    def test_tree_is_clean_without_any_allowlist(self) -> None:
        """No tracked source file needs an exemption any more.

        When this gate landed, `admin-console/src/pages/assets.tsx` was its one
        allowlisted offender. #344 removed the NUL bytes (a JSON-encoded
        composite map key replaced the NUL delimiter) and deleted the entry, so
        the tree must now pass with the allowlist disabled entirely — i.e. the
        table is empty because nothing needs it, not because it was emptied.
        """
        result = self.run_checker("--no-allowlist")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_the_assets_page_holds_no_nul_byte(self) -> None:
        """Regression lock on the specific file this gate was written for.

        Named directly (rather than only via the tree-wide sweep) because the
        page's composite map key is the exact construct that reintroduces a NUL
        byte: a template literal joining an asset type and a name. A failure
        here points at the cause, not just at "something is binary".
        """
        page = ROOT / "admin-console" / "src" / "pages" / "assets.tsx"
        self.assertEqual(page.read_bytes().count(b"\0"), 0)

    def test_empty_allowlist_is_not_an_empty_table_of_stale_entries(self) -> None:
        """The stale-entry check still fires — it is what forced #344's fix.

        The live table is empty, so the tree-level run can no longer exercise
        this branch. Inject a table naming a clean path and assert the gate
        rejects it, otherwise a future entry could rot unnoticed.
        """
        module = load_checker()
        entry = module.ReviewedBinaryFile(
            path="admin-console/src/pages/assets.tsx",
            owner="test",
            reason="file is clean, so this entry must be reported as stale",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.make_repo(root)
            self.write(root, "src/ok.ts", b"export const ok = 1;\n")
            module.REVIEWED_BINARY_FILES = (entry,)
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = module.main(["--root", str(root)])
        self.assertEqual(code, 1, stdout.getvalue())
        self.assertIn("stale REVIEWED_BINARY_FILES entry", stderr.getvalue())

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



if __name__ == "__main__":
    unittest.main()
