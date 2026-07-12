#!/usr/bin/env python3
"""Tests for the GitHub Actions immutable-reference policy."""

from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-workflow-action-pins.py"


class WorkflowActionPinTests(unittest.TestCase):
    def run_checker(self, workflow: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "workflows").mkdir()
            (root / "workflows" / "test.yml").write_text(workflow, encoding="utf-8")
            env = os.environ.copy()
            env["FERROGATE_ACTION_PIN_ROOT"] = str(root)
            return subprocess.run(
                ["python3", str(CHECKER)],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

    def test_accepts_commit_pins_and_local_actions(self) -> None:
        result = self.run_checker(
            "steps:\n"
            "  - uses: actions/checkout@" + "a" * 40 + " # v5\n"
            "  - uses: ./.github/actions/local\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_movable_tags(self) -> None:
        result = self.run_checker("steps:\n  - uses: actions/checkout@v5\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("actions/checkout@v5", result.stderr)


if __name__ == "__main__":
    unittest.main()
