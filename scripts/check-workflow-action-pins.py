#!/usr/bin/env python3
"""Reject external GitHub Actions references that are not commit-pinned."""

from __future__ import annotations

import os
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
ACTION_ROOT = pathlib.Path(
    os.environ.get("FERROGATE_ACTION_PIN_ROOT", ROOT / ".github")
)
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?([^\s#'\"]+)")
PINNED = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}")


def main() -> None:
    failures: list[str] = []
    files = sorted(ACTION_ROOT.glob("workflows/*.yml"))
    files.extend(sorted(ACTION_ROOT.glob("actions/**/action.yml")))
    for path in files:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = USES.match(line)
            if match is None:
                continue
            reference = match.group(1)
            if reference.startswith("./") or PINNED.fullmatch(reference):
                continue
            failures.append(f"{path}:{line_number}: {reference}")
    if failures:
        print("external GitHub Actions must use full commit SHAs:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        raise SystemExit(1)
    print(f"validated immutable action references in {len(files)} workflow/action files")


if __name__ == "__main__":
    main()
