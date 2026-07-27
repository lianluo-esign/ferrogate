#!/usr/bin/env python3
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-27
# description: Tests for the workspace-member CI coverage gate (issue #561).
"""Tests for `scripts/check-ci-crate-coverage.py`.

The gate exists because nothing noticed that a 136k-line crate ran nowhere, so
the one thing these tests must rule out is the gate itself being the next thing
that notices nothing. Every case below is built as a throwaway workspace on
disk and run through the real script, and each negative case is paired with the
positive that differs only in the fact under test.
"""

from __future__ import annotations

import pathlib
import subprocess
import tempfile
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-ci-crate-coverage.py"


class CiCrateCoverageTests(unittest.TestCase):
    def build_workspace(
        self,
        root: pathlib.Path,
        members: list[str],
        ci_workflow: str,
        called_workflows: dict[str, str] | None = None,
        local_runner: str = "",
    ) -> None:
        quoted = "".join(f'    "crates/{member}",\n' for member in members)
        (root / "Cargo.toml").write_text(
            f"[workspace]\nmembers = [\n{quoted}]\n", encoding="utf-8"
        )
        for member in members:
            directory = root / "crates" / member
            directory.mkdir(parents=True)
            (directory / "Cargo.toml").write_text(
                f'[package]\nname = "{member}"\nversion = "0.0.0"\n', encoding="utf-8"
            )
        workflows = root / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(ci_workflow, encoding="utf-8")
        for name, body in (called_workflows or {}).items():
            (workflows / name).write_text(body, encoding="utf-8")
        scripts = root / "scripts"
        scripts.mkdir()
        (scripts / "local-test-modules.sh").write_text(local_runner, encoding="utf-8")

    def run_checker(self, **kwargs) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.build_workspace(root, **kwargs)
            return subprocess.run(
                ["python3", str(CHECKER), "--root", str(root)],
                text=True,
                capture_output=True,
                check=False,
            )

    def test_accepts_a_member_selected_in_both_ci_and_the_local_runner(self) -> None:
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-gateway\n",
            local_runner="cargo test -p ferrogate-gateway --all-features\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("validated 1 workspace members", result.stdout)

    def test_rejects_the_member_that_no_workflow_selects(self) -> None:
        """The literal #561 shape: compiled everywhere, executed nowhere."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-cli\n",
            local_runner="cargo test -p ferrogate-gateway\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ferrogate-gateway", result.stderr)
        self.assertIn("in any workflow", result.stderr)

    def test_rejects_the_member_the_local_runner_dropped(self) -> None:
        """CI-only coverage is the drift half of #561, and also fails."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-gateway\n",
            local_runner="cargo test -p ferrogate-cli\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("local-test-modules.sh", result.stderr)

    def test_compiling_a_crate_is_not_testing_it(self) -> None:
        """`cargo build -p X` is exactly what #561's crates already had."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo build -p ferrogate-gateway --locked\n",
            local_runner="cargo build -p ferrogate-gateway\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ferrogate-gateway", result.stderr)

    def test_resolves_a_matrix_package_key_through_the_templated_run_line(self) -> None:
        """Every real slice in this repo names its crate in the matrix, not the

        run line, so a gate that only reads the run line would pass everything
        vacuously."""
        result = self.run_checker(
            members=["ferrogate-secrets"],
            ci_workflow=textwrap.dedent(
                """
                jobs:
                  t:
                    strategy:
                      matrix:
                        include:
                          - slice: secrets
                            package: ferrogate-secrets
                    steps:
                      - run: cargo test -p "${{ matrix.package }}" --all-features
                """
            ),
            local_runner="cargo test -p ferrogate-secrets\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_matrix_package_key_alone_does_not_count(self) -> None:
        """The counterpart of the case above: a `package:` key in a workflow

        that never runs `cargo test` must not be credited."""
        result = self.run_checker(
            members=["ferrogate-secrets"],
            ci_workflow=textwrap.dedent(
                """
                jobs:
                  t:
                    strategy:
                      matrix:
                        include:
                          - package: ferrogate-secrets
                    steps:
                      - run: cargo build -p "${{ matrix.package }}"
                """
            ),
            local_runner="cargo test -p ferrogate-secrets\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ferrogate-secrets", result.stderr)

    def test_follows_reusable_workflow_calls_from_the_entry_point(self) -> None:
        result = self.run_checker(
            members=["ferrogate-payments"],
            ci_workflow="jobs:\n  p:\n    uses: ./.github/workflows/rust-x.yml\n",
            called_workflows={
                "rust-x.yml": "jobs:\n  t:\n    run: cargo test -p ferrogate-payments\n"
            },
            local_runner="cargo test -p ferrogate-payments\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_ignores_a_workflow_the_entry_point_never_calls(self) -> None:
        """`firecracker-boot-validation.yml` is `workflow_dispatch`-only and

        needs a KVM runner, so the `cargo test -p agent-worker` inside it is not
        coverage. Reading every `.yml` in the directory -- which is how #561's
        own survey was done -- would have called that crate covered."""
        result = self.run_checker(
            members=["agent-worker"],
            ci_workflow="jobs:\n  q:\n    run: cargo test -p ferrogate-cli\n",
            called_workflows={
                "manual.yml": "on:\n  workflow_dispatch:\njobs:\n  t:\n"
                "    run: cargo test -p agent-worker\n"
            },
            local_runner="cargo test -p agent-worker\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("agent-worker", result.stderr)

    def test_the_real_repository_passes_its_own_gate(self) -> None:
        result = subprocess.run(
            ["python3", str(CHECKER)], text=True, capture_output=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
