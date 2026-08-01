#!/usr/bin/env python3
"""The 16 rows the mechanical seam-pass driver could not locate, hand-anchored.

A row the driver skipped is INDISTINGUISHABLE from a row that passed unless
someone says so, so each of the 16 is settled here into exactly one of:

  RED           — proven by a hand-anchored mutation below
  STALE ROW     — the cited code no longer exists; MOUNT-SEAMS.md must be
                  corrected (and the behaviour is proven elsewhere)
  NOT-MUTABLE   — the "seam" is a `[vars]` TABLE HEADER or an intentionally
                  COMMENTED stanza; there is no single line whose removal
                  un-deploys behaviour, so no mutation can prove it and saying
                  "GREEN" would misreport a category error as a coverage gap
"""

import hashlib
import json
import os
import shutil
import subprocess

ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

MUTABLE = [
    ("GW-A2", "apps/gateway/src/adapters.ts", "    lifecycle:", "apps/gateway", None),
    ("GW-A3", "apps/gateway/src/adapters.ts", "    rbac:", "apps/gateway", None),
    (
        "GW-W2",
        "apps/gateway/src/ratelimit/workflow.ts",
        "export function workflowDeclarationFrom(headers: Headers): WorkflowDeclarationResult {",
        "apps/gateway",
        None,
    ),
    (
        "CP-C13",
        "apps/control-plane/src/index.ts",
        'app.get("/version", (c) =>',
        "apps/control-plane",
        None,
    ),
    (
        "CP-S4",
        "apps/control-plane/src/identity/routes.ts",
        "    validated = await handleSamlAcs(identity.saml, new URL(c.req.url).search.slice(1));",
        "apps/control-plane",
        None,
    ),
    (
        "CP-S5",
        "apps/control-plane/src/identity/adapters.ts",
        '      .prepare("DELETE FROM sso_pending_flows WHERE state = ? RETURNING *")',
        "apps/control-plane",
        None,
    ),
    ("AR-P1", "apps/agent-runtime/src/ports.ts", "      ? d1ApiKeyPort(env.DB)", "apps/agent-runtime", None),
    (
        "AR-P2",
        "apps/agent-runtime/src/ports.ts",
        "      ? d1WorkerIdentityPort(env.CONTROL_DB)",
        "apps/agent-runtime",
        None,
    ),
    (
        "TEL-P1",
        "apps/telemetry/src/ports.ts",
        "  return new AnalyticsEngineSink(dataset);",
        "apps/telemetry",
        None,
    ),
    (
        "AR-T2",
        "apps/agent-runtime/wrangler.toml",
        "compatibility_date =",
        "apps/agent-runtime",
        "env-var-drift",
    ),
    (
        "AR-T9",
        "apps/agent-runtime/wrangler.toml",
        'AGENT_RUNTIME_ENABLED = "1"',
        "apps/agent-runtime",
        "env-var-drift",
    ),
]

VERDICTS = [
    dict(
        id="CP-C9",
        verdict="STALE ROW — corrected in this wave",
        detail="`app.get(\"/healthz\"/\"/readyz\")` no longer exist in "
        "apps/control-plane/src/index.ts. The wave-20 health slice DELETED both "
        "inline handlers and moved them into `src/routes/health.ts::mountSharedProbes`, "
        "which `registerRoutes` calls. The behaviour is proven by mutation M6 "
        "(3 RED in test/health.test.ts). MOUNT-SEAMS.md CP-C9 must be rewritten "
        "to cite `mountSharedProbes(app);` in `src/routes/index.ts`.",
    ),
    dict(
        id="GW-T16",
        verdict="NOT-MUTABLE — `[vars]` table header, not a seam",
        detail="The row names the whole `[vars]` TABLE. No single line's removal "
        "un-deploys a behaviour; the names are now held by "
        "apps/gateway/test/env-var-drift.test.ts in both directions.",
    ),
    dict(id="GW-T17", verdict="NOT-MUTABLE — `[vars]` table header, not a seam", detail="As GW-T16."),
    dict(id="GW-T18", verdict="NOT-MUTABLE — `[vars]` table header, not a seam", detail="As GW-T16."),
    dict(
        id="AR-T11",
        verdict="NOT-MUTABLE — the stanza is COMMENTED OUT by design",
        detail="`[[d1_databases]]` in apps/agent-runtime/wrangler.toml is committed "
        "commented (uncommenting injects empty unmigrated databases into every unit "
        "test — the measured 106-of-259 failure). Commenting an already-commented "
        "stanza is a semantic no-op. The rot-directions are gated by env-var-drift; "
        "the binding itself is DEPLOY-ONLY (CLOUD-VERIFICATION B4).",
    ),
]


def sha256(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


for (rid, rel, anchor, app, tfilter) in MUTABLE:
    path = os.path.join(ROOT, rel)
    before = sha256(path)
    bak = f"/tmp/wave20-res-{rid}.bak"
    shutil.copy2(path, bak)
    text = open(path, encoding="utf-8").read()
    if text.count(anchor) != 1:
        print(json.dumps(dict(id=rid, status="ANCHOR_NOT_UNIQUE", n=text.count(anchor))), flush=True)
        continue
    marker = f"MUTW20R_{rid.replace('-', '_')}"
    idx = text.index(anchor)
    start = text.rfind("\n", 0, idx) + 1
    end = text.find("\n", idx)
    pre = "# " if rel.endswith(".toml") else "// "
    open(path, "w", encoding="utf-8").write(
        text[:start] + f"{pre}{marker} " + text[start:end].strip() + text[end:]
    )
    landed = marker in open(path, encoding="utf-8").read()
    cmd = ["bunx", "vitest", "run"] + ([tfilter] if tfilter else [])
    proc = subprocess.run(
        cmd, cwd=os.path.join(ROOT, app), capture_output=True, text=True, timeout=1200
    )
    out = proc.stdout + proc.stderr
    summary = next(
        (l.strip() for l in reversed(out.splitlines()) if l.strip().startswith("Tests ")), ""
    )
    shutil.copy2(bak, path)
    print(
        json.dumps(
            dict(
                id=rid,
                landed=landed,
                red=proc.returncode != 0,
                summary=summary,
                restored_byte_identical=sha256(path) == before,
                verdict="RED" if (landed and proc.returncode != 0) else "GREEN — UNPROVEN",
            )
        ),
        flush=True,
    )

print("\n=== NON-MUTABLE / STALE ===")
for v in VERDICTS:
    print(json.dumps(v))
