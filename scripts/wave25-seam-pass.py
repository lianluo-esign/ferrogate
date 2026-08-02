#!/usr/bin/env python3
"""Wave-25 FULL seam pass (final, pre-deletion) — EVERY row in MOUNT-SEAMS.md, not an incremental subset.

This is the gate that stands between the tree and `rm -rf crates/ workers/`.
The inventory's own rule is that a full pass must precede the deletion, and a
partial pass that *reports* like a full one is the exact failure mode this file
has been fighting since wave 18.

Protocol, per row:

  1. sha256 + back up the seam's file
  2. neutralise the seam (comment its line out behind a unique marker), requiring
     the seam text to resolve to EXACTLY ONE site in the file
  3. **GREP THE MARKER BACK OFF DISK.** A mutation that never landed makes a
     sound gate look vacuous and an unsound one look proven. Concurrent writes
     have clobbered a mutation in this repo before.
  4. run ONLY the tests that row names, via `seam-proof.mjs --id <ID> --run`,
     which knows about chained (ESC) configs and cross-app fleet citations
  5. restore, and require the file to come back BYTE-IDENTICAL by sha256

RED  = the named gate failed under the mutation. The mount is proven.
GREEN under a LANDED mutation = an UNPROVEN MOUNT, reported by ID.

Rows that cannot be mutated BY CATEGORY (Channel `NONE`, quality `NOT-MUTABLE`,
`RETIRED`) are skipped WITH their reason and counted separately. A skipped
NOT-MUTABLE row is not an unproven row; conflating the two is why the Channel
column exists.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
INVENTORY = os.path.join(ROOT, "docs/rewrite/MOUNT-SEAMS.md")
BAK = "/tmp/wave25-seam"
os.makedirs(BAK, exist_ok=True)

APP_BY_PREFIX = {
    "GW": "apps/gateway",
    "CP": "apps/control-plane",
    "MCP": "apps/mcp",
    "AR": "apps/agent-runtime",
    "TEL": "apps/telemetry",
    "CLI": "apps/cli",
}


def parse_rows():
    """Parse §7-§12. Mirrors seam-proof.mjs's row regex so the two AGREE on the
    row set; a driver that sees a different population than the counter is how a
    'full' pass under-runs."""
    lines = open(INVENTORY, encoding="utf-8").read().split("\n")
    start = next(i for i, l in enumerate(lines) if l.startswith("## 7. "))
    end = next(i for i, l in enumerate(lines) if l.startswith("## 13. "))

    app = None
    fil = None
    rows = []
    for raw in lines[start:end]:
        m = re.match(r"^## \d+\.\s+`(apps/[a-z-]+)`", raw)
        if m:
            app, fil = m.group(1), None
            continue
        m = re.match(r"^### .*?`([^`]+\.(?:ts|toml))`", raw)
        if m and app:
            fil = f"{app}/{m.group(1)}"
            continue
        m = re.match(
            r"^\|\s*(?:\*\*|~~)?((?:GW|CP|MCP|AR|TEL|CLI)-[A-Za-z0-9]+)(?:\*\*|~~)?\s*\|(.*)$", raw
        )
        if not m:
            continue
        rid, rest = m.group(1), m.group(2)
        retired_id = "~~" in raw.split("|")[1]
        cells = [c.strip() for c in re.split(r"(?<!\\)\|", rest)]
        if cells and cells[-1] == "":
            cells = cells[:-1]
        tier = (re.search(r"T[123]", cells[-1]) or re.match("", "")).group(0) if re.search(
            r"T[123]", cells[-1]
        ) else "-"
        channel = cells[-2] if len(cells) >= 2 else ""
        expected = cells[-3] if len(cells) >= 3 else ""
        parts = [c.strip() for c in channel.split("·")]
        run = parts[0] if parts and parts[0] else "?"
        quality = parts[1] if len(parts) > 1 else ""

        # §11 (telemetry) puts the file in a per-row column; §12 (cli) has one
        # file for the whole section. Without both arms a dozen rows parse to
        # file=None and never run.
        seam_col = 0
        row_file = fil
        if cells and re.fullmatch(r"`[^`]+\.(?:ts|toml)`", cells[0]) and app:
            row_file = f"{app}/{cells[0].strip('`')}"
            seam_col = 1
        elif row_file is None and app == "apps/cli":
            row_file = "apps/cli/src/index.ts"

        seam_cell = cells[seam_col] if len(cells) > seam_col else ""
        rows.append(
            dict(
                id=rid,
                app=app,
                file=row_file,
                tier=tier,
                run=run,
                quality=quality,
                channel=channel,
                expected=expected,
                seam=seam_cell if re.search(r"`[^`]+`", seam_cell) else None,
                retired=retired_id or run == "RETIRED" or quality == "RETIRED",
            )
        )
    return rows


def sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def is_inert_line(line, is_toml):
    """Is this line already a comment, a docblock body, or blank?

    Commenting out a line that is ALREADY a comment changes bytes and changes no
    behaviour. Wave 23's first pass did exactly that on five rows and read the
    resulting GREEN as an unproven mount — a FALSE finding in the direction that
    manufactures work. A mutation must change what the program DOES, so a target
    line that cannot affect behaviour is rejected here rather than measured.
    """
    s = line.strip()
    if s == "":
        return True
    if is_toml:
        return s.startswith("#")
    return s.startswith("//") or s.startswith("*") or s.startswith("/*")


def seam_candidates(cell, is_toml):
    """Every backticked span in the Seam cell that could name real code, best first.

    Taking only the FIRST span (wave 23, first attempt) failed on 26 rows: the
    cell is PROSE, and its first backticked span is as often a file path
    (`src/http.ts::authenticateRequest`), a table header (`[vars]`) or a
    `{@link}`-style reference as it is the seam itself. Rows whose seam could not
    be located are rows the pass did not prove — indistinguishable, in a summary,
    from rows that passed. So every span is a candidate and the caller keeps the
    first that resolves to a UNIQUE, non-inert line.
    """
    spans = [s.replace("\\|", "|") for s in re.findall(r"`([^`]+)`", cell)]
    # A toml row often names the table (`[vars]`) first and the KEYS after; the
    # keys are what exist in the file.
    keys = re.findall(r"`?([A-Z][A-Z0-9_]{4,})`?", cell) if is_toml else []
    out = []
    for s in spans + keys:
        s = s.strip()
        if s and s not in out:
            out.append(s)
    # Longest first among same-shaped candidates: a longer span is less likely to
    # collide, and a collision is a mutation of the WRONG line.
    return sorted(out, key=lambda s: (s.startswith("["), -len(s)))


def locate(text, seam, is_toml):
    """Index of the seam in `text`, or None. Each arm demands a UNIQUE match: a
    non-unique match would mutate the wrong line and produce a RED that proves
    nothing about the seam the row names."""
    if text.count(seam) == 1:
        return text.index(seam)
    stripped = re.sub(r"^\[\[?[a-z_.]+\]\]?\s+", "", seam)
    if stripped != seam and text.count(stripped) == 1:
        return text.index(stripped)
    for frag in (
        seam.split("…")[0].strip(),
        seam.split("(")[0].strip(),
        seam.split(" {")[0].strip(),
        seam.split(" —")[0].strip(),
        stripped.split("…")[0].strip(),
    ):
        if len(frag) >= 12 and text.count(frag) == 1:
            return text.index(frag)
    if is_toml:
        m = re.search(r'((?:binding|name|service|class_name|tag|dataset)\s*=\s*"[^"]+")', seam)
        if m and text.count(m.group(1)) == 1:
            return text.index(m.group(1))
        m = re.match(r"^([A-Z_]+)", seam)
        if m:
            anchor = f"\n{m.group(1)} ="
            if text.count(anchor) == 1:
                return text.index(anchor) + 1
    return None


def neutralise(text, cell, marker, is_toml):
    """Comment out the LIVE line the Seam cell names. Returns (new_text, line).

    Tries every candidate the cell offers and keeps the first that lands on a
    line which is both uniquely located AND capable of changing behaviour.
    """
    for cand in seam_candidates(cell, is_toml):
        idx = locate(text, cand, is_toml)
        if idx is None:
            continue
        start = text.rfind("\n", 0, idx) + 1
        end = text.find("\n", idx + len(cand))
        if end == -1:
            end = len(text)
        line = text[start:end]
        if is_inert_line(line, is_toml):
            continue
        pre = "# " if is_toml else "// "
        return (
            text[:start] + f"{pre}{marker} " + line.replace("\n", " ") + text[end:],
            line.strip(),
        )
    return None, None


def run_gate(row_id):
    proc = subprocess.run(
        ["bun", "scripts/seam-proof.mjs", "--id", row_id, "--run"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=2400,
    )
    out = proc.stdout + proc.stderr
    status = "UNKNOWN"
    m = re.search(rf"^{re.escape(row_id)}\s+(GREEN|RED|NO-GATE|NO-FILE)\s", out, re.M)
    if m:
        status = m.group(1)
    return status, out


def main():
    rows = parse_rows()
    only = set(a for a in sys.argv[1:] if not a.startswith("-"))
    live = [r for r in rows if not r["retired"]]
    print(f"# parsed {len(rows)} rows ({len(rows) - len(live)} retired) -> {len(live)} live", flush=True)

    work = [r for r in live if not only or r["id"] in only or r["app"] in only]
    results = []
    t0 = time.time()
    for i, r in enumerate(work, 1):
        rid = r["id"]
        # Category skips: these are not unproven, they are un-mutatable.
        if r["run"] == "NONE" or r["quality"] == "NOT-MUTABLE":
            r.update(status="SKIP-BY-CATEGORY", reason=r["channel"])
            results.append(r)
            print(f"[{i}/{len(work)}] {rid} SKIP-BY-CATEGORY ({r['channel']})", flush=True)
            continue
        if r["file"] is None or r["seam"] is None:
            r.update(status="NO-SEAM-PARSED")
            results.append(r)
            print(f"[{i}/{len(work)}] {rid} NO-SEAM-PARSED", flush=True)
            continue
        path = os.path.join(ROOT, r["file"])
        if not os.path.exists(path):
            r.update(status="FILE-MISSING")
            results.append(r)
            print(f"[{i}/{len(work)}] {rid} FILE-MISSING {r['file']}", flush=True)
            continue

        marker = f"MUTW25_{rid.replace('-', '_')}"
        before = sha256(path)
        bak = os.path.join(BAK, rid + ".bak")
        shutil.copy2(path, bak)
        text = open(path, encoding="utf-8").read()
        new, mutated_line = neutralise(text, r["seam"], marker, r["file"].endswith(".toml"))
        if new is None:
            r.update(status="SEAM-NOT-UNIQUE", occurrences=text.count(r["seam"]))
            results.append(r)
            print(f"[{i}/{len(work)}] {rid} SEAM-NOT-UNIQUE", flush=True)
            continue
        open(path, "w", encoding="utf-8").write(new)

        # (3) grep the marker BACK OFF DISK, and require the original line to be
        # gone from live code. Byte-difference is not enough: the question is
        # whether BEHAVIOUR changed.
        ondisk = open(path, encoding="utf-8").read()
        landed = marker in ondisk
        commented = f"{'#' if r['file'].endswith('.toml') else '//'} {marker}" in ondisk
        if not (landed and commented):
            shutil.copy2(bak, path)
            r.update(status="MUTATION-DID-NOT-LAND")
            results.append(r)
            print(f"[{i}/{len(work)}] {rid} MUTATION-DID-NOT-LAND", flush=True)
            continue

        gate, out = run_gate(rid)
        shutil.copy2(bak, path)
        restored = sha256(path) == before
        r.update(
            status="RED" if gate == "RED" else ("GREEN-UNPROVEN" if gate == "GREEN" else gate),
            gate=gate,
            mutated_line=(mutated_line or "")[:160],
            restored_byte_identical=restored,
        )
        results.append(r)
        el = time.time() - t0
        print(
            f"[{i}/{len(work)}] {rid} {r['status']} restored={restored} ({el:.0f}s elapsed)",
            flush=True,
        )
        if not restored:
            print(f"!! RESTORE FAILED for {r['file']} — ABORTING", flush=True)
            break

    out_path = "/tmp/wave25-seam-results.json"
    json.dump(results, open(out_path, "w"), indent=1)
    red = [r for r in results if r["status"] == "RED"]
    green = [r for r in results if r["status"] == "GREEN-UNPROVEN"]
    skip = [r for r in results if r["status"] == "SKIP-BY-CATEGORY"]
    other = [r for r in results if r["status"] not in ("RED", "GREEN-UNPROVEN", "SKIP-BY-CATEGORY")]
    bad = [r for r in results if r.get("restored_byte_identical") is False]
    print("\n=== WAVE 25 FULL SEAM PASS ===")
    print(
        json.dumps(
            dict(
                parsed=len(rows),
                live=len(live),
                run=len(results),
                red=len(red),
                green_unproven=len(green),
                skip_by_category=len(skip),
                other=len(other),
                restore_failures=len(bad),
                green_rows=[r["id"] for r in green],
                other_rows=[(r["id"], r["status"]) for r in other],
            ),
            indent=1,
        )
    )
    print(f"results -> {out_path}")


if __name__ == "__main__":
    main()
