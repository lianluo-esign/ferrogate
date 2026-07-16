#!/usr/bin/env python3
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-06-11
# description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
"""Tamper tests for the vendored pingora-core integrity contract."""

from __future__ import annotations

import importlib.util
import pathlib
import shutil
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-pingora-vendor.py"
SPEC = importlib.util.spec_from_file_location("check_pingora_vendor", CHECKER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER}")
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class PingoraVendorIntegrityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.vendor = pathlib.Path(self.temporary.name) / "pingora-core-0.8.0"
        shutil.copytree(POLICY.VENDOR, self.vendor)
        self.original_vendor = POLICY.VENDOR
        POLICY.VENDOR = self.vendor

    def tearDown(self) -> None:
        POLICY.VENDOR = self.original_vendor
        self.temporary.cleanup()

    def assert_policy_fails(self, expected: str) -> None:
        with self.assertRaisesRegex(SystemExit, expected):
            POLICY.main()

    def test_current_vendor_contract_passes(self) -> None:
        POLICY.main()

    def test_reintroduced_private_key_fixture_fails(self) -> None:
        fixture = self.vendor / "examples" / "keys" / "server" / "key.pem"
        fixture.write_bytes(b"-----BEGIN " + b"PRIVATE KEY-----\nfixture\n")
        self.assert_policy_fails("unexpected vendored file set")

    def test_runtime_source_change_fails(self) -> None:
        source = self.vendor / "src" / "lib.rs"
        source.write_bytes(source.read_bytes() + b"\n// unexpected change\n")
        self.assert_policy_fails("unexpected content change in src/lib.rs")

    def test_extra_manifest_change_fails(self) -> None:
        manifest = self.vendor / "Cargo.toml"
        manifest.write_bytes(manifest.read_bytes() + b"\n# unexpected change\n")
        self.assert_policy_fails("changes beyond the Prometheus")


if __name__ == "__main__":
    unittest.main()
