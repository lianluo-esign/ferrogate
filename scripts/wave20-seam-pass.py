#!/usr/bin/env python3
"""Wave-20 seam pass: every T1 row, plus every row whose FILE this wave touched.

Derived MECHANICALLY from `docs/rewrite/MOUNT-SEAMS.md` rather than from a
hand-copied list: the app comes from the `## N. \\`apps/x\\`` heading, the file
from the `### N.M ... \\`src/y.ts\\`` heading, and the seam text from the first
backticked span of the row's "Seam (exact code)" column.

Protocol per row:
  1. sha256 + back up the file
  2. neutralise the seam (comment it out with a unique marker), requiring the
     seam text to occur EXACTLY once in the file
  3. GREP THE FILE ON DISK for the marker — a mutation that did not land makes a
     sound gate look vacuous
  4. run the app's default vitest project -> require RED
  5. restore, require the file byte-identical to before

GREEN is NOT re-run per row: the restore is verified byte-identical by sha256,
so the tree is provably the one the full `bun run test` was green on. A row that
comes back GREEN under a LANDED mutation is an UNPROVEN MOUNT and is reported.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
BAK = "/tmp/wave20-seam"
os.makedirs(BAK, exist_ok=True)

# Files this wave touched (git status), so their rows join the T1 set.
TOUCHED = {
    "apps/agent-runtime/src/ports.ts",
    "apps/agent-runtime/src/runs/do.ts",
    "apps/agent-runtime/src/runs/lifecycle.ts",
    "apps/agent-runtime/src/runs/workflow.ts",
    "apps/agent-runtime/src/workers/plane.ts",
    "apps/agent-runtime/wrangler.toml",
    "apps/control-plane/src/index.ts",
    "apps/control-plane/src/routes/billing.ts",
    "apps/control-plane/src/routes/index.ts",
    "apps/control-plane/src/routes/health.ts",
    "apps/gateway/src/metering/index.ts",
    "apps/gateway/src/metering/sink.ts",
    "apps/gateway/src/metering/budget-alerts.ts",
    "apps/gateway/src/routes/agent-discovery.ts",
    "apps/gateway/src/routes/agent-upstreams.ts",
    "apps/gateway/wrangler.toml",
    "apps/mcp/src/routes/index.ts",
    "apps/telemetry/src/app.ts",
}


def parse_rows():
    app = None
    fil = None
    rows = []
    for raw in open(os.path.join(ROOT, "docs/rewrite/MOUNT-SEAMS.md"), encoding="utf-8"):
        m = re.match(r"^## \d+\.\s+`(apps/[a-z-]+)`", raw)
        if m:
            app = m.group(1)
            fil = None
            continue
        m = re.match(r"^### .*?`([^`]+\.(?:ts|toml))`", raw)
        if m and app:
            fil = f"{app}/{m.group(1)}"
            continue
        if not raw.startswith("| ") or raw.count("|") < 7:
            continue
        cols = [c.strip() for c in raw.strip().strip("|").split("|")]
        if len(cols) < 6:
            continue
        rid = cols[0]
        if not re.match(r"^~?~?\*?\*?[A-Z]{2,4}-[A-Z]?\d+", rid):
            continue
        rid_clean = rid.strip("~* ")
        tier = cols[-1]
        if "~~" in rid:  # a withdrawn row
            continue
        if tier not in ("T1", "T2", "T3"):
            continue
        if tier != "T1" and fil not in TOUCHED:
            continue
        # §11 (telemetry) carries the file in a PER-ROW column instead of the
        # section heading; §12 (cli) has one file for the whole section. Without
        # both arms 12 rows silently parse to file=None and never run — which
        # would be this document's own dominant failure mode, in the tool that
        # checks for it.
        seam_col = 1
        row_file = fil
        if re.fullmatch(r"`[^`]+\.(?:ts|toml)`", cols[1]) and app:
            row_file = f"{app}/{cols[1].strip('`')}"
            seam_col = 2
        elif row_file is None and app == "apps/cli":
            row_file = "apps/cli/src/index.ts"
        if row_file is None:
            rows.append(dict(id=rid_clean, app=app, file=None, tier=tier, status="NO_FILE_PARSED"))
            continue
        if tier != "T1" and row_file not in TOUCHED:
            continue
        seam = re.findall(r"`([^`]+)`", cols[seam_col])
        if not seam:
            continue
        rows.append(
            dict(id=rid_clean, app=app, file=row_file, tier=tier, seam=seam[0], expected=cols[-2])
        )
    return rows


def sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def locate(text, seam, is_toml):
    """Index of the seam in `text`, or None. Three arms, tried in order.

    The table's "Seam (exact code)" column is written for a HUMAN: long seams
    are elided with `…`, and a toml row is written as `[[stanza]] key = "V"` on
    one line when the file has it on two. A driver that only did verbatim
    matching would silently skip 58 of 145 rows — and a skipped row looks
    exactly like a passing one in a summary, which is the failure this whole
    document exists to prevent. So the fallbacks are explicit and each still
    requires a UNIQUE match.
    """
    # 1. verbatim, unique
    if text.count(seam) == 1:
        return text.index(seam)
    # A `[vars] NAME = "V"` / `[[stanza]] key = "V"` row names its TABLE for the
    # reader's benefit; the file has the entry on its own line.
    stripped = re.sub(r'^\[\[?[a-z_.]+\]\]?\s+', "", seam)
    if stripped != seam and text.count(stripped) == 1:
        return text.index(stripped)
    # 2. the fragment before the first ellipsis / open paren / block brace
    for frag in (
        seam.split("…")[0].strip(),
        seam.split("(")[0].strip(),
        seam.split(" {")[0].strip(),
        stripped.split("…")[0].strip(),
    ):
        if len(frag) >= 12 and text.count(frag) == 1:
            return text.index(frag)
    # 3. a toml `[[stanza]] key = "VALUE"` row: anchor on the key/value line
    if is_toml:
        m = re.search(r'((?:binding|name|service|class_name|tag|dataset)\s*=\s*"[^"]+")', seam)
        if m and text.count(m.group(1)) == 1:
            return text.index(m.group(1))
        m = re.match(r'^([A-Z_]+)\s*=\s*"', seam)
        if m:
            anchor = f"\n{m.group(1)} ="
            if text.count(anchor) == 1:
                return text.index(anchor) + 1
    return None


def neutralise(text, seam, marker, is_toml):
    """Comment the seam's LINE out. Returns new text or None if not locatable."""
    idx = locate(text, seam, is_toml)
    if idx is None:
        return None
    start = text.rfind("\n", 0, idx) + 1
    end = text.find("\n", idx + len(seam))
    if end == -1:
        end = len(text)
    line = text[start:end]
    pre = "# " if is_toml else "// "
    return text[:start] + f"{pre}{marker} " + line.replace("\n", " ") + text[end:]


def run_suite(app):
    proc = subprocess.run(
        ["bunx", "vitest", "run"],
        cwd=os.path.join(ROOT, app),
        capture_output=True,
        text=True,
        timeout=1200,
    )
    out = proc.stdout + proc.stderr
    summary = next(
        (l.strip() for l in reversed(out.splitlines()) if l.strip().startswith("Tests ")), ""
    )
    collected_zero = "No test files found" in out or "Tests  0 " in out
    return proc.returncode == 0, summary, collected_zero


def main():
    rows = parse_rows()
    want = set(sys.argv[1:])
    if want:
        rows = [r for r in rows if r["id"] in want or r["app"] in want]
    print(f"# {len(rows)} rows", flush=True)
    results = []
    for r in rows:
        path = os.path.join(ROOT, r["file"])
        if not os.path.exists(path):
            r.update(status="FILE_MISSING")
            results.append(r)
            print(json.dumps(r), flush=True)
            continue
        marker = f"MUTW20_{r['id'].replace('-', '_')}"
        before = sha256(path)
        bak = os.path.join(BAK, r["id"] + ".bak")
        shutil.copy2(path, bak)
        text = open(path, encoding="utf-8").read()
        new = neutralise(text, r["seam"], marker, r["file"].endswith(".toml"))
        if new is None:
            r.update(status="SEAM_NOT_UNIQUE", occurrences=text.count(r["seam"]))
            results.append(r)
            print(json.dumps(r), flush=True)
            continue
        open(path, "w", encoding="utf-8").write(new)
        landed = marker in open(path, encoding="utf-8").read()
        if not landed:
            shutil.copy2(bak, path)
            r.update(status="MUTATION_DID_NOT_LAND")
            results.append(r)
            print(json.dumps(r), flush=True)
            continue
        passed, summary, zero = run_suite(r["app"])
        shutil.copy2(bak, path)
        restored = sha256(path) == before
        r.update(
            status="GREEN — UNPROVEN MOUNT" if passed else "RED",
            red=not passed,
            summary=summary,
            collected_zero=zero,
            restored_byte_identical=restored,
        )
        results.append(r)
        print(json.dumps(r), flush=True)

    print("\n=== SEAM PASS SUMMARY ===")
    red = [r for r in results if r.get("status") == "RED"]
    green = [r for r in results if r.get("status") == "GREEN — UNPROVEN MOUNT"]
    skipped = [r for r in results if r.get("status", "").startswith(("SEAM_", "FILE_", "MUTATION_"))]
    bad_restore = [r for r in results if r.get("restored_byte_identical") is False]
    print(
        json.dumps(
            dict(
                total=len(results),
                red=len(red),
                green_unproven=len(green),
                not_locatable=len(skipped),
                restore_failures=len(bad_restore),
                green_rows=[r["id"] for r in green],
                skipped_rows=[(r["id"], r.get("status")) for r in skipped],
            ),
            indent=1,
        )
    )


if __name__ == "__main__":
    main()
