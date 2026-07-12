#!/usr/bin/env python3
"""Contract tests for owned and time-bounded cargo-audit exceptions."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-audit-exceptions.py"
TODAY = "2026-07-11"


class AuditExceptionPolicyTest(unittest.TestCase):
    def run_policy(self, ignored: list[str], entries: list[dict[str, str]]) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            audit = root / "audit.toml"
            exceptions = root / "exceptions.json"
            quoted = ", ".join(json.dumps(item) for item in ignored)
            audit.write_text(f"[advisories]\nignore = [{quoted}]\n", encoding="utf-8")
            exceptions.write_text(json.dumps({"exceptions": entries}), encoding="utf-8")
            env = os.environ.copy()
            env.update(
                {
                    "FERROGATE_AUDIT_CONFIG": str(audit),
                    "FERROGATE_AUDIT_EXCEPTIONS": str(exceptions),
                    "FERROGATE_AUDIT_EXCEPTION_TODAY": TODAY,
                }
            )
            return subprocess.run(
                [str(CHECKER)],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

    @staticmethod
    def entry(**overrides: str) -> dict[str, str]:
        value = {
            "advisory": "RUSTSEC-2024-0437",
            "owner": "security-owner",
            "expires": "2026-08-11",
            "tracking_issue": "https://github.com/lianluo-esign/ferrogate/issues/218",
            "reason": "A concrete temporary risk rationale long enough for review.",
        }
        value.update(overrides)
        return value

    def test_matching_owned_unexpired_exception_passes(self) -> None:
        result = self.run_policy(["RUSTSEC-2024-0437"], [self.entry()])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_expired_and_ownerless_exceptions_fail(self) -> None:
        expired = self.run_policy(
            ["RUSTSEC-2024-0437"], [self.entry(expires="2026-07-10")]
        )
        self.assertNotEqual(expired.returncode, 0)
        self.assertIn("expired", expired.stderr)

        ownerless = self.run_policy(
            ["RUSTSEC-2024-0437"], [self.entry(owner="")]
        )
        self.assertNotEqual(ownerless.returncode, 0)
        self.assertIn("no owner", ownerless.stderr)

    def test_missing_and_stale_registry_entries_fail(self) -> None:
        missing = self.run_policy(["RUSTSEC-2024-0437"], [])
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("lack exception records", missing.stderr)

        stale = self.run_policy([], [self.entry()])
        self.assertNotEqual(stale.returncode, 0)
        self.assertIn("not active cargo-audit ignores", stale.stderr)


if __name__ == "__main__":
    unittest.main()
