#!/usr/bin/env python3
"""Tests for the D1 unimplemented-surface drift gate (issue #456)."""

from __future__ import annotations

import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-d1-surface-map.py"

BEGIN = "<!-- BEGIN D1-ERRORING-SURFACE -->"
END = "<!-- END D1-ERRORING-SURFACE -->"


class D1SurfaceMapTests(unittest.TestCase):
    def run_checker(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(CHECKER), *args],
            text=True,
            capture_output=True,
            check=False,
        )

    def write_tree(
        self,
        root: pathlib.Path,
        *,
        call_sites: list[str],
        mod_listed: list[str],
        doc_listed: list[str],
        external_call_sites: list[str] | None = None,
        mod_markers: bool = True,
        doc_markers: bool = True,
        extra_mod_body: str = "",
    ) -> None:
        """Lay down the minimal file set the checker reads."""
        src = root / "crates" / "ferrogate-storage" / "src"
        module = src / "control_plane_store_d1"
        module.mkdir(parents=True, exist_ok=True)
        (root / "docs").mkdir(parents=True, exist_ok=True)

        block = "\n".join(f"//! - `{name}`" for name in mod_listed)
        mod_doc = f"//! {BEGIN}\n{block}\n//! {END}\n" if mod_markers else block + "\n"
        calls = "\n".join(
            f'    fn {name}() {{ Err(unimplemented_surface("{name}")) }}'
            for name in call_sites
        )
        (module / "mod.rs").write_text(
            f"{mod_doc}\n{extra_mod_body}\nimpl Store {{\n{calls}\n}}\n",
            encoding="utf-8",
        )

        external = external_call_sites or []
        for name in ("guardrail_evidence.rs", "mcp_identity.rs"):
            body = "\n".join(
                f"    CloudflareD1(_) => Err(unimplemented_surface(\"{call}\")),"
                for call in external
            )
            (src / name).write_text(f"match backend {{\n{body}\n}}\n", encoding="utf-8")
            external = []  # only seed the first file

        doc_block = "\n".join(f"- `{name}`" for name in doc_listed)
        doc_body = f"{BEGIN}\n{doc_block}\n{END}\n" if doc_markers else doc_block + "\n"
        (root / "docs" / "cloudflare-d1-backend.md").write_text(
            f"# D1 backend\n\n{doc_body}", encoding="utf-8"
        )

    def test_repository_tree_passes(self) -> None:
        """The real checkout must be in sync -- this is the gate's live assertion."""
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("in sync", result.stdout)

    def test_accepts_matching_sets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_tree(
                root,
                call_sites=["add_agent_burn", "get_agent_burn"],
                mod_listed=["add_agent_burn", "get_agent_burn"],
                doc_listed=["get_agent_burn", "add_agent_burn"],
            )
            result = self.run_checker("--root", str(root))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("2 erroring methods", result.stdout)

    def test_flags_method_erroring_but_undocumented(self) -> None:
        """The #454/#455/#460 drift shape: code lands, prose does not follow."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_tree(
                root,
                call_sites=["add_agent_burn", "sweep_expired_wallet_reservations"],
                mod_listed=["add_agent_burn"],
                doc_listed=["add_agent_burn"],
            )
            result = self.run_checker("--root", str(root))
            self.assertEqual(result.returncode, 1)
            self.assertIn("erroring in code but NOT listed", result.stderr)
            self.assertIn("sweep_expired_wallet_reservations", result.stderr)
            self.assertIn("mod.rs", result.stderr)
            self.assertIn("cloudflare-d1-backend.md", result.stderr)

    def test_flags_documented_but_implemented(self) -> None:
        """The other drift direction: a family lands and stays listed as erroring."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_tree(
                root,
                call_sites=["add_agent_burn"],
                mod_listed=["add_agent_burn", "list_wallets"],
                doc_listed=["add_agent_burn"],
            )
            result = self.run_checker("--root", str(root))
            self.assertEqual(result.returncode, 1)
            self.assertIn("listed but NOT erroring in code", result.stderr)
            self.assertIn("list_wallets", result.stderr)

    def test_counts_enum_dispatched_call_sites_outside_the_module(self) -> None:
        """guardrail_evidence.rs / mcp_identity.rs dispatch to the same surface."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_tree(
                root,
                call_sites=["add_agent_burn"],
                external_call_sites=["append_guardrail_evaluation"],
                mod_listed=["add_agent_burn"],
                doc_listed=["add_agent_burn"],
            )
            result = self.run_checker("--root", str(root))
            self.assertEqual(result.returncode, 1)
            self.assertIn("append_guardrail_evaluation", result.stderr)

    def test_ignores_dynamic_call_sites(self) -> None:
        """`proxy_client(method)` fails closed on an IMPLEMENTED method."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_tree(
                root,
                call_sites=["add_agent_burn"],
                mod_listed=["add_agent_burn"],
                doc_listed=["add_agent_burn"],
                extra_mod_body="fn proxy_client(m: &str) { unimplemented_surface(m) }",
            )
            result = self.run_checker("--root", str(root))
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_missing_markers(self) -> None:
        for label, kwargs in (
            ("mod.rs", {"mod_markers": False}),
            ("doc", {"doc_markers": False}),
        ):
            with self.subTest(label), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                self.write_tree(
                    root,
                    call_sites=["add_agent_burn"],
                    mod_listed=["add_agent_burn"],
                    doc_listed=["add_agent_burn"],
                    **kwargs,
                )
                result = self.run_checker("--root", str(root))
                self.assertEqual(result.returncode, 1)
                self.assertIn("BEGIN D1-ERRORING-SURFACE", result.stderr)

    def test_rejects_missing_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_checker("--root", directory)
            self.assertEqual(result.returncode, 1)
            self.assertIn("not found", result.stderr)

    def test_rejects_empty_extraction(self) -> None:
        """A moved module must fail loudly, not silently validate nothing."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.write_tree(root, call_sites=[], mod_listed=[], doc_listed=[])
            result = self.run_checker("--root", str(root))
            self.assertEqual(result.returncode, 1)
            self.assertIn("no unimplemented_surface", result.stderr)


if __name__ == "__main__":
    unittest.main()
