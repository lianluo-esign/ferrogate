#!/usr/bin/env python3
"""Reject cargo-audit ignores that lack an owned, unexpired exception."""

from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import re
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]
AUDIT_CONFIG = pathlib.Path(
    os.environ.get("FERROGATE_AUDIT_CONFIG", ROOT / ".cargo" / "audit.toml")
)
EXCEPTIONS = pathlib.Path(
    os.environ.get(
        "FERROGATE_AUDIT_EXCEPTIONS", ROOT / ".cargo" / "audit-exceptions.json"
    )
)
MAX_EXCEPTION_DAYS = 90


def fail(message: str) -> None:
    print(f"audit exception check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    audit = tomllib.loads(AUDIT_CONFIG.read_text(encoding="utf-8"))
    ignored = set(audit.get("advisories", {}).get("ignore", []))
    document = json.loads(EXCEPTIONS.read_text(encoding="utf-8"))
    entries = document.get("exceptions")
    if not isinstance(entries, list):
        fail("exceptions must be an array")

    today = dt.date.fromisoformat(
        os.environ.get("FERROGATE_AUDIT_EXCEPTION_TODAY", dt.date.today().isoformat())
    )
    registered: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            fail("every exception must be an object")
        advisory = entry.get("advisory")
        owner = entry.get("owner")
        expiry_raw = entry.get("expires")
        issue = entry.get("tracking_issue")
        reason = entry.get("reason")
        if not isinstance(advisory, str) or not re.fullmatch(r"RUSTSEC-\d{4}-\d{4}", advisory):
            fail(f"invalid advisory id: {advisory!r}")
        if advisory in registered:
            fail(f"duplicate exception: {advisory}")
        registered.add(advisory)
        if not isinstance(owner, str) or not owner.strip():
            fail(f"{advisory} has no owner")
        if not isinstance(issue, str) or not re.fullmatch(
            r"https://github\.com/lianluo-esign/ferrogate/issues/\d+", issue
        ):
            fail(f"{advisory} has no FerroGate tracking issue")
        if not isinstance(reason, str) or len(reason.strip()) < 20:
            fail(f"{advisory} has no concrete risk rationale")
        try:
            expiry = dt.date.fromisoformat(expiry_raw)
        except (TypeError, ValueError):
            fail(f"{advisory} has invalid expiry {expiry_raw!r}")
        remaining = (expiry - today).days
        if remaining < 0:
            fail(f"{advisory} expired on {expiry}")
        if remaining > MAX_EXCEPTION_DAYS:
            fail(f"{advisory} expiry is {remaining} days away; maximum is {MAX_EXCEPTION_DAYS}")

    missing = ignored - registered
    stale = registered - ignored
    if missing:
        fail(f"cargo-audit ignores lack exception records: {sorted(missing)}")
    if stale:
        fail(f"exception records are not active cargo-audit ignores: {sorted(stale)}")
    print(f"validated {len(ignored)} owned, time-bounded cargo-audit exception(s)")


if __name__ == "__main__":
    main()
