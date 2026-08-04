"""The Python SDK is independently buildable as a vendored package."""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parent


class PackageMetadataTests(unittest.TestCase):
    def test_declares_a_standard_build_and_runtime_package(self) -> None:
        with (PACKAGE_ROOT / "pyproject.toml").open("rb") as stream:
            document = tomllib.load(stream)

        self.assertEqual(document["build-system"]["build-backend"], "setuptools.build_meta")
        self.assertEqual(document["project"]["name"], "ferrogate-admin")
        self.assertEqual(document["project"]["dependencies"], [])
        self.assertIn("ferrogate_admin", document["tool"]["setuptools"]["packages"]["find"]["include"])


if __name__ == "__main__":
    unittest.main()
