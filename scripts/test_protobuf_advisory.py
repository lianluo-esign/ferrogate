#!/usr/bin/env python3
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-06-11
# description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
"""Contract tests for the protobuf advisory dependency floor."""

from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-protobuf-advisory.py"


class ProtobufAdvisoryPolicyTest(unittest.TestCase):
    def run_policy(self, versions: list[str]) -> subprocess.CompletedProcess[str]:
        packages = [
            '[[package]]\nname = "fixture-root"\nversion = "0.0.0"',
            *(
                f'[[package]]\nname = "protobuf"\nversion = "{version}"'
                for version in versions
            ),
        ]
        document = "\n\n".join(packages)
        with tempfile.TemporaryDirectory() as directory:
            lockfile = pathlib.Path(directory) / "Cargo.lock"
            lockfile.write_text(
                f"version = 4\n\n{document}\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["FERROGATE_CARGO_LOCK"] = str(lockfile)
            return subprocess.run(
                ["python3", str(CHECKER)],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

    def test_safe_or_absent_protobuf_passes(self) -> None:
        for versions in ([], ["3.7.2"], ["3.7.3"], ["4.0.0-alpha.1"]):
            with self.subTest(versions=versions):
                result = self.run_policy(versions)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_affected_and_floor_prerelease_versions_fail(self) -> None:
        for version in ("2.28.0", "3.7.1", "3.7.2-alpha.1"):
            with self.subTest(version=version):
                result = self.run_policy([version])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("requires protobuf >=3.7.2", result.stderr)

    def test_unparseable_version_fails_closed(self) -> None:
        result = self.run_policy(["unknown"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot parse protobuf version", result.stderr)


if __name__ == "__main__":
    unittest.main()
