#!/usr/bin/env python3
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-06-11
# description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
"""Verify FerroGate's narrow pingora-core advisory patch against crates.io."""

from __future__ import annotations

import hashlib
import io
import os
import pathlib
import tarfile
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor" / "pingora-core-0.8.0"
CRATE_NAME = "pingora-core-0.8.0.crate"
CRATE_URL = f"https://static.crates.io/crates/pingora-core/{CRATE_NAME}"
CRATE_SHA256 = "08973c4853cef4c682f7a592907e81a32dcad69476c4846e5de079f16448b177"

ALLOWED_REMOVED = {
    "Cargo.lock",
    "examples/keys/client-ca/key.pem",
    "examples/keys/clients/invalid-key.pem",
    "examples/keys/clients/key-1.pem",
    "examples/keys/clients/key-2.pem",
    "examples/keys/server/key.pem",
}
ALLOWED_ADDED = {"FERROGATE-PATCH.md"}
MANIFEST_PATCHES = {
    "Cargo.toml": (
        b'[dependencies.prometheus]\nversion = "0.13"',
        b'[dependencies.prometheus]\nversion = "0.14"',
    ),
    "Cargo.toml.orig": (
        b'prometheus = "0.13"',
        b'prometheus = "0.14"',
    ),
}


def fail(message: str) -> None:
    raise SystemExit(f"pingora vendor integrity check failed: {message}")


def load_crate() -> tuple[bytes, str]:
    override = os.environ.get("FERROGATE_PINGORA_CORE_CRATE")
    if override:
        path = pathlib.Path(override)
        data = path.read_bytes()
        source = str(path)
    else:
        cargo_home = pathlib.Path(os.environ.get("CARGO_HOME", pathlib.Path.home() / ".cargo"))
        cached = sorted((cargo_home / "registry" / "cache").glob(f"*/{CRATE_NAME}"))
        if cached:
            data = cached[0].read_bytes()
            source = str(cached[0])
        else:
            with urllib.request.urlopen(CRATE_URL, timeout=30) as response:
                data = response.read()
            source = CRATE_URL

    digest = hashlib.sha256(data).hexdigest()
    if digest != CRATE_SHA256:
        fail(f"crate archive from {source} has SHA-256 {digest}, expected {CRATE_SHA256}")
    return data, source


def archive_files(data: bytes) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    expected_root = "pingora-core-0.8.0"
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive.getmembers():
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts:
                fail(f"unsafe archive member {member.name!r}")
            if path.parts[0] != expected_root:
                fail(f"archive member has unexpected root: {member.name!r}")
            if member.isdir():
                continue
            if not member.isfile():
                fail(f"archive member is not a regular file: {member.name!r}")
            relative = pathlib.PurePosixPath(*path.parts[1:]).as_posix()
            extracted = archive.extractfile(member)
            if extracted is None or relative in files:
                fail(f"cannot read unique archive member {member.name!r}")
            files[relative] = extracted.read()
    return files


def vendor_files() -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for path in sorted(VENDOR.rglob("*")):
        if path.is_symlink():
            fail(f"vendored tree contains symlink {path.relative_to(VENDOR)}")
        if path.is_file():
            relative = path.relative_to(VENDOR).as_posix()
            files[relative] = path.read_bytes()
    return files


def main() -> None:
    crate, source = load_crate()
    upstream = archive_files(crate)
    vendored = vendor_files()

    missing_upstream = ALLOWED_REMOVED - upstream.keys()
    if missing_upstream:
        fail(f"declared removals are absent upstream: {sorted(missing_upstream)}")

    expected_paths = (upstream.keys() - ALLOWED_REMOVED) | ALLOWED_ADDED
    missing = expected_paths - vendored.keys()
    extra = vendored.keys() - expected_paths
    if missing or extra:
        fail(f"unexpected vendored file set; missing={sorted(missing)}, extra={sorted(extra)}")

    for relative, original in upstream.items():
        if relative in ALLOWED_REMOVED:
            continue
        current = vendored[relative]
        patch = MANIFEST_PATCHES.get(relative)
        if patch is None:
            if current != original:
                fail(f"unexpected content change in {relative}")
            continue

        before, after = patch
        if original.count(before) != 1 or current != original.replace(before, after, 1):
            fail(f"{relative} contains changes beyond the Prometheus 0.13 to 0.14 patch")

    print(
        "validated pingora-core 0.8.0 vendor against "
        f"{source}: byte-identical runtime source, six declared removals, "
        "and two Prometheus manifest edits"
    )


if __name__ == "__main__":
    main()
