#!/usr/bin/env python3
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-31
# description: Keep the D1 backend's hand-written "still erroring" maps in sync
# with the unimplemented_surface() call sites they describe (issue #456).
"""Re-derive the D1 unimplemented surface and fail when the two docs drift.

The truth is the `unimplemented_surface("<method>")` call sites. Two hand-written
copies describe them for operators:

* the ``D1-ERRORING-SURFACE`` block in ``control_plane_store_d1/mod.rs``
* the ``D1-ERRORING-SURFACE`` block in ``docs/cloudflare-d1-backend.md``

Both drifted silently across issues #454/#455/#456/#460, each time because a
landing family updated the code and not the prose. This gate makes that failure
loud: it extracts the three sets and asserts they are identical.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]

STORAGE_SRC = pathlib.Path("crates/ferrogate-storage/src")
D1_MODULE = STORAGE_SRC / "control_plane_store_d1"
MOD_RS = D1_MODULE / "mod.rs"
DOC = pathlib.Path("docs/cloudflare-d1-backend.md")

# Enum-dispatched outside control_plane_store_d1/: these two modules match on
# `RuntimeControlPlaneBackend::CloudflareD1` and call the same constructor, so
# their call sites belong to the D1 surface even though the files do not.
EXTERNAL_DISPATCH = (
    STORAGE_SRC / "guardrail_evidence.rs",
    STORAGE_SRC / "mcp_identity.rs",
)

# Only literal call sites are static facts about the surface. The dynamic one in
# provisioning.rs (`proxy_client(method)`) re-uses the typed error to fail closed
# when NO proxy Worker is bound -- a deployment condition on an IMPLEMENTED
# method, not an unimplemented surface. Requiring a string literal excludes it,
# and excludes the `fn unimplemented_surface(method: &'static str)` definition.
CALL_SITE = re.compile(r'unimplemented_surface\(\s*"([A-Za-z0-9_]+)"')

# Method names are written as `backticked` identifiers inside the marked block.
MARKED_METHOD = re.compile(r"`([a-z0-9_]+)`")

BEGIN_MARKER = "<!-- BEGIN D1-ERRORING-SURFACE -->"
END_MARKER = "<!-- END D1-ERRORING-SURFACE -->"


class SurfaceMapError(Exception):
    """A source file is missing, unreadable, or missing its marked block."""


def read(root: pathlib.Path, relative: pathlib.Path) -> str:
    path = root / relative
    if not path.is_file():
        raise SurfaceMapError(f"{relative}: not found")
    return path.read_text(encoding="utf-8")


def call_site_methods(root: pathlib.Path) -> set[str]:
    """Every method named by a literal `unimplemented_surface("…")` call site."""
    module = root / D1_MODULE
    if not module.is_dir():
        raise SurfaceMapError(f"{D1_MODULE}: not found")
    sources = sorted(module.rglob("*.rs"))
    for relative in EXTERNAL_DISPATCH:
        path = root / relative
        if not path.is_file():
            raise SurfaceMapError(f"{relative}: not found")
        sources.append(path)
    return {
        match.group(1)
        for source in sources
        for match in CALL_SITE.finditer(source.read_text(encoding="utf-8"))
    }


def marked_block_methods(text: str, relative: pathlib.Path) -> set[str]:
    """Backticked identifiers between the BEGIN/END markers."""
    start = text.find(BEGIN_MARKER)
    if start < 0:
        raise SurfaceMapError(f"{relative}: missing {BEGIN_MARKER}")
    end = text.find(END_MARKER, start)
    if end < 0:
        raise SurfaceMapError(f"{relative}: missing {END_MARKER} after the begin marker")
    return set(MARKED_METHOD.findall(text[start + len(BEGIN_MARKER) : end]))


def format_drift(label: str, expected: set[str], actual: set[str]) -> list[str]:
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if not missing and not extra:
        return []
    lines = [f"{label} disagrees with the unimplemented_surface() call sites:"]
    if missing:
        lines.append(f"  erroring in code but NOT listed ({len(missing)}):")
        lines.extend(f"    - {name}" for name in missing)
    if extra:
        lines.append(f"  listed but NOT erroring in code ({len(extra)}):")
        lines.extend(f"    - {name}" for name in extra)
    return lines


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=ROOT,
        help="repository root to check (default: this checkout)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve()

    try:
        expected = call_site_methods(root)
        blocks = {
            relative: marked_block_methods(read(root, relative), relative)
            for relative in (MOD_RS, DOC)
        }
    except SurfaceMapError as error:
        print(f"D1 surface map: {error}", file=sys.stderr)
        return 1

    if not expected:
        print(
            "D1 surface map: found no unimplemented_surface(\"…\") call sites at all; "
            "the extraction is broken or the module moved",
            file=sys.stderr,
        )
        return 1

    failures: list[str] = []
    for relative, listed in blocks.items():
        failures.extend(format_drift(str(relative), expected, listed))

    if failures:
        print("\n".join(failures), file=sys.stderr)
        print(
            "\nThe call sites are the source of truth. Update the "
            "D1-ERRORING-SURFACE block in BOTH files in the same commit.",
            file=sys.stderr,
        )
        return 1

    print(
        f"D1 surface map: {len(expected)} erroring methods, "
        f"{MOD_RS} and {DOC} both in sync"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
