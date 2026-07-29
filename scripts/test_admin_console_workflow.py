#!/usr/bin/env python3
"""Contract tests for the admin-console GitHub Actions workflow."""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "admin-console.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


class AdminConsoleWorkflowTests(unittest.TestCase):
    def workflow_text(self) -> str:
        self.assertTrue(
            WORKFLOW.is_file(),
            "admin-console changes must have their own path-filtered workflow",
        )
        return WORKFLOW.read_text(encoding="utf-8")

    def assert_contains_all(self, text: str, values: list[str]) -> None:
        for value in values:
            self.assertIn(value, text)

    def assert_ordered(self, text: str, values: list[str]) -> None:
        cursor = -1
        for value in values:
            position = text.find(value)
            self.assertNotEqual(position, -1, f"missing workflow step: {value}")
            self.assertGreater(position, cursor, f"workflow step is out of order: {value}")
            cursor = position

    def test_triggers_on_admin_console_changes(self) -> None:
        text = self.workflow_text()
        self.assert_contains_all(
            text,
            [
                "workflow_call:",
                "workflow_dispatch:",
                "push:",
                "pull_request:",
                '"admin-console/**"',
                '"docs/openapi/admin-api.openapi.json"',
                '"scripts/check-admin-console.sh"',
                '"scripts/test-check-admin-console.sh"',
                '"scripts/test_admin_console_workflow.py"',
                '"scripts/node-env.sh"',
                '".github/workflows/admin-console.yml"',
            ],
        )

    def test_uses_a_pinned_node_toolchain_with_lockfile_cache(self) -> None:
        text = self.workflow_text()
        self.assert_contains_all(
            text,
            [
                "uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5",
                "uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4",
                "node-version: 24",
                "cache: npm",
                "cache-dependency-path: admin-console/package-lock.json",
            ],
        )

    def test_runs_the_full_admin_console_gate(self) -> None:
        text = self.workflow_text()
        self.assert_ordered(
            text,
            [
                "npm ci --no-audit --no-fund",
                "npm run lint",
                "npx tsc -b",
                "npx tsc -p tsconfig.e2e.json --noEmit",
                "npx vitest run",
                "npm run build",
                "npm run check:api-types",
                "run: npm run test:e2e:install\n",
                "run: npm run test:e2e\n",
            ],
        )

    def test_release_ci_calls_the_admin_console_workflow(self) -> None:
        text = CI_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("uses: ./.github/workflows/admin-console.yml", text)
        self.assertIn("      - admin-console", text)


if __name__ == "__main__":
    unittest.main()
