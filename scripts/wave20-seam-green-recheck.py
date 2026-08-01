#!/usr/bin/env python3
"""Re-verify the three rows the mechanical seam pass could not settle.

None of the three is an unproven mount; each needed a DIFFERENT mutation or a
DIFFERENT runner than the generic driver applies, and reporting them as "GREEN"
without saying so would be the same overstatement this project keeps making in
the other direction.

  GW-C8   ESC row. Its gate is `test/tenancy/mount.spec.ts`, which runs only
          under the CHAINED tenancy harness config, not the app's default
          vitest project. The generic driver runs the default project, so GREEN
          there says nothing. Re-run against the harness.

  MCP-T10 / AR-T10
          The seam text in the table is an ALREADY-COMMENTED toml line
          (`#   name = "RATE_LIMIT"` / `#   script_name = "ferrogate-gateway"`).
          Commenting a comment is a semantic NO-OP, so GREEN was guaranteed and
          meaningless. The table names the real rot-directions the local gate
          can catch; the one that is both meaningful and local is DELETING the
          commented `script_name` line, which is what turns the stanza from
          "cross-script, pointing at the gateway's namespace" into "a private
          namespace of this Worker" the day someone uncomments it.
"""

import hashlib
import json
import os
import shutil
import subprocess

ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

CASES = [
    dict(
        id="GW-C8",
        file="apps/gateway/src/index.ts",
        old="  tenantDatabase(),",
        new="  /* MUTW20_GW_C8 */",
        marker="MUTW20_GW_C8",
        cwd="apps/gateway",
        cmd=["bunx", "vitest", "run", "--config", "test/tenancy/harness/vitest.config.ts"],
        note="ESC — chained tenancy harness, not the default project",
    ),
    dict(
        id="MCP-T10",
        file="apps/mcp/wrangler.toml",
        old='#   script_name = "ferrogate-gateway"',
        new="# MUTW20_MCP_T10 script_name line deleted",
        marker="MUTW20_MCP_T10",
        cwd="apps/mcp",
        cmd=["bunx", "vitest", "run", "env-var-drift"],
        note="real rot-direction: the cross-script pin is dropped",
    ),
    dict(
        id="AR-T10",
        file="apps/agent-runtime/wrangler.toml",
        old='#   script_name = "ferrogate-gateway"',
        new="# MUTW20_AR_T10 script_name line deleted",
        marker="MUTW20_AR_T10",
        cwd="apps/agent-runtime",
        cmd=["bunx", "vitest", "run", "env-var-drift"],
        note="real rot-direction: the cross-script pin is dropped",
    ),
]


def sha256(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


for case in CASES:
    path = os.path.join(ROOT, case["file"])
    before = sha256(path)
    bak = f"/tmp/wave20-green-{case['id']}.bak"
    shutil.copy2(path, bak)
    text = open(path, encoding="utf-8").read()
    n = text.count(case["old"])
    if n != 1:
        print(json.dumps(dict(id=case["id"], status="TARGET_NOT_UNIQUE", occurrences=n)))
        continue
    open(path, "w", encoding="utf-8").write(text.replace(case["old"], case["new"]))
    landed = case["marker"] in open(path, encoding="utf-8").read()
    proc = subprocess.run(
        case["cmd"], cwd=os.path.join(ROOT, case["cwd"]), capture_output=True, text=True,
        timeout=1200,
    )
    out = proc.stdout + proc.stderr
    summary = next(
        (line.strip() for line in reversed(out.splitlines()) if line.strip().startswith("Tests ")),
        "",
    )
    shutil.copy2(bak, path)
    restored = sha256(path) == before
    print(
        json.dumps(
            dict(
                id=case["id"],
                note=case["note"],
                landed=landed,
                red=proc.returncode != 0,
                summary=summary,
                restored_byte_identical=restored,
                verdict="PROVEN" if (landed and proc.returncode != 0 and restored) else "GREEN",
            )
        ),
        flush=True,
    )
