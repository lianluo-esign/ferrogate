#!/usr/bin/env python3
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-06-11
# description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
"""Reject protobuf releases affected by RUSTSEC-2024-0437."""

from __future__ import annotations

import os
import pathlib
import re
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCKFILE = pathlib.Path(os.environ.get("FERROGATE_CARGO_LOCK", ROOT / "Cargo.lock"))
MINIMUM_SAFE_VERSION = (3, 7, 2)
VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([^+]+))?(?:\+.+)?$")


def fail(message: str) -> None:
    print(f"protobuf advisory check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def is_safe(version: str) -> bool:
    match = VERSION.fullmatch(version)
    if match is None:
        fail(f"cannot parse protobuf version {version!r}")
    release = tuple(int(component) for component in match.group(1, 2, 3))
    prerelease = match.group(4)
    return release > MINIMUM_SAFE_VERSION or (
        release == MINIMUM_SAFE_VERSION and prerelease is None
    )


def main() -> None:
    lock = tomllib.loads(LOCKFILE.read_text(encoding="utf-8"))
    packages = lock.get("package")
    if not isinstance(packages, list):
        fail("Cargo.lock has no package array")

    affected = []
    protobuf_versions = []
    for package in packages:
        if not isinstance(package, dict) or package.get("name") != "protobuf":
            continue
        version = package.get("version")
        if not isinstance(version, str):
            fail("protobuf package has no string version")
        protobuf_versions.append(version)
        if not is_safe(version):
            affected.append(version)

    if affected:
        fail(
            "RUSTSEC-2024-0437 requires protobuf >=3.7.2; found "
            + ", ".join(sorted(affected))
        )
    if protobuf_versions:
        print("validated protobuf version(s): " + ", ".join(sorted(protobuf_versions)))
    else:
        print("protobuf is absent from the locked dependency graph")


if __name__ == "__main__":
    main()
