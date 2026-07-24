#!/usr/bin/env python3
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-24
# description: Enforce the thin-lib.rs modular layout standard repo-wide
# (docs/engineering-standards.md, issues #429/#433).
"""Flag oversized lib.rs/main.rs entry files in every workspace crate."""

from __future__ import annotations

import argparse
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]

# Hard cap for crate entry files (upper bound of the ~500-800 line soft cap
# in docs/engineering-standards.md). Split modules before reaching it.
DEFAULT_THRESHOLD = 800

ENTRY_FILES = ("lib.rs", "main.rs")

# Pre-existing offenders, frozen slightly above their line counts on the
# date noted. This is a ratchet: lower or delete entries as refactors
# (#419/#425/#433 follow-ups) land; never raise one or add one to make new
# growth fit.
BASELINE_MAX_LINES = {
    "crates/ferrogate-storage/src/lib.rs": 18_600,  # 18,493 after #425 (was 21,146)
}


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_THRESHOLD,
        help=f"line cap for non-baselined entry files (default {DEFAULT_THRESHOLD})",
    )
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=ROOT,
        help="repository root to scan (default: this repository)",
    )
    return parser.parse_args(argv)


def crate_directories(root: pathlib.Path) -> list[pathlib.Path]:
    crates = root / "crates"
    if not crates.is_dir():
        return []
    return sorted(path for path in crates.iterdir() if path.is_dir())


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    failures: list[str] = []
    checked = 0
    for crate in crate_directories(root):
        for entry in ENTRY_FILES:
            path = crate / "src" / entry
            if not path.is_file():
                continue
            checked += 1
            relative = path.relative_to(root).as_posix()
            lines = len(path.read_text(encoding="utf-8").splitlines())
            limit = BASELINE_MAX_LINES.get(relative, args.threshold)
            if lines > limit:
                failures.append(
                    f"{relative}: {lines} lines exceeds the {limit}-line cap; "
                    "split concerns into sibling modules "
                    "(docs/engineering-standards.md, issues #429/#433)"
                )
            elif relative in BASELINE_MAX_LINES and lines <= args.threshold:
                print(
                    f"note: {relative} is {lines} lines; its baseline entry is "
                    "stale and should be removed"
                )
    if failures:
        print(
            "Crate entry files must stay thin "
            "(docs/engineering-standards.md, issues #429/#433):",
            file=sys.stderr,
        )
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(f"validated modular layout of {checked} crate entry files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
