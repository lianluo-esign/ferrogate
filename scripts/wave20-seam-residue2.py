#!/usr/bin/env python3
"""Re-do the residue rows whose line-comment mutation was a PARSE ERROR.

Commenting out a line INSIDE an object literal or a ternary does not neutralise
a seam — it makes the module unparseable, so the suite fails to collect and the
run is RED for a reason that has nothing to do with the behaviour. MOUNT-SEAMS
§5 already records this class of mistake twice (wave 15 corrected GW-C7 and
TEL-A3 for exactly it). A RED-by-parse-error is NOT a proof, so these are redone
with semantically valid substitutions: the seam's VALUE is swapped for the
fallback/no-op it guards against, and the module still compiles.
"""

import hashlib
import json
import os
import shutil
import subprocess

ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

CASES = [
    # GW-A2: the durable lifecycle gate is dropped, leaving only config.
    dict(
        id="GW-A2",
        file="apps/gateway/src/adapters.ts",
        old="""    lifecycle:
      durableLifecycle === null
        ? configuredLifecycle
        : denyIfEitherDenies(durableLifecycle, configuredLifecycle),""",
        new="""    lifecycle: configuredLifecycle, /* MUTW20R_GW_A2 */""",
        app="apps/gateway",
        filter=None,
    ),
    # GW-A3: the D1 RBAC authorizer is dropped, leaving only the config table.
    dict(
        id="GW-A3",
        file="apps/gateway/src/adapters.ts",
        old="""    rbac:
      D1RbacAuthorizer.fromEnv(env as unknown as Record<string, unknown>, {
        fallback: configuredRbac,
      }) ?? configuredRbac,""",
        new="""    rbac: configuredRbac, /* MUTW20R_GW_A3 */""",
        app="apps/gateway",
        filter=None,
    ),
    # GW-W2: the workflow declaration is never read off the headers.
    dict(
        id="GW-W2",
        file="apps/gateway/src/ratelimit/workflow.ts",
        old="export function workflowDeclarationFrom(headers: Headers): WorkflowDeclarationResult {\n"
        "  const workflowId = headers.get(WORKFLOW_ID_HEADER)?.trim() ?? \"\";",
        new="export function workflowDeclarationFrom(headers: Headers): WorkflowDeclarationResult {\n"
        "  const workflowId = \"\"; /* MUTW20R_GW_W2 */ void headers;",
        app="apps/gateway",
        filter=None,
    ),
    # AR-P1: the durable api-key port is never built, even with DB bound.
    dict(
        id="AR-P1",
        file="apps/agent-runtime/src/ports.ts",
        old="""    env.DB !== undefined
      ? d1ApiKeyPort(env.DB)
      : dev""",
        new="""    (env.DB as unknown) === "MUTW20R_AR_P1"
      ? d1ApiKeyPort(env.DB as D1Database)
      : dev""",
        app="apps/agent-runtime",
        filter=None,
    ),
    # AR-P2: the durable worker-identity port is never built.
    dict(
        id="AR-P2",
        file="apps/agent-runtime/src/ports.ts",
        old="""    env.CONTROL_DB !== undefined
      ? d1WorkerIdentityPort(env.CONTROL_DB)
      : dev""",
        new="""    (env.CONTROL_DB as unknown) === "MUTW20R_AR_P2"
      ? d1WorkerIdentityPort(env.CONTROL_DB as D1Database)
      : dev""",
        app="apps/agent-runtime",
        filter=None,
    ),
    # CP-C13: /version answers an empty document instead of the real counts.
    dict(
        id="CP-C13",
        file="apps/control-plane/src/index.ts",
        old="""app.get("/version", (c) =>
  c.json({
    api: PUBLIC_API_MAJOR,""",
        new="""app.get("/version", (c) =>
  c.json({
    /* MUTW20R_CP_C13 */ api: 0,""",
        app="apps/control-plane",
        filter=None,
    ),
    # TEL-P1 re-check: the real sink is never constructed (line-comment was
    # valid there, but the run showed 31 RED — re-stated as a value swap so the
    # module still compiles and the RED is behavioural beyond doubt).
    dict(
        id="TEL-P1",
        file="apps/telemetry/src/ports.ts",
        old="  return new AnalyticsEngineSink(dataset);",
        new="  return null; /* MUTW20R_TEL_P1 */ void dataset;",
        app="apps/telemetry",
        filter=None,
    ),
    # AR-T2: compatibility_date, anchored on the whole assignment.
    dict(
        id="AR-T2",
        file="apps/agent-runtime/wrangler.toml",
        old='compatibility_date = "2025-11-17"\n',
        new="# MUTW20R_AR_T2 compatibility_date removed\n",
        app="apps/agent-runtime",
        filter="env-var-drift",
    ),
]


def sha256(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


for c in CASES:
    path = os.path.join(ROOT, c["file"])
    before = sha256(path)
    bak = f"/tmp/wave20-res2-{c['id']}.bak"
    shutil.copy2(path, bak)
    text = open(path, encoding="utf-8").read()
    n = text.count(c["old"])
    if n != 1:
        print(json.dumps(dict(id=c["id"], status="TARGET_NOT_UNIQUE", n=n)), flush=True)
        continue
    open(path, "w", encoding="utf-8").write(text.replace(c["old"], c["new"]))
    marker = f"MUTW20R_{c['id'].replace('-', '_')}"
    landed = marker in open(path, encoding="utf-8").read()
    cmd = ["bunx", "vitest", "run"] + ([c["filter"]] if c["filter"] else [])
    proc = subprocess.run(
        cmd, cwd=os.path.join(ROOT, c["app"]), capture_output=True, text=True, timeout=1200
    )
    out = proc.stdout + proc.stderr
    summary = next(
        (l.strip() for l in reversed(out.splitlines()) if l.strip().startswith("Tests ")), ""
    )
    # The whole point of this file: a collection failure is not a proof.
    parse_error = "no tests" in summary or "Failed to load" in out or "Transform failed" in out
    shutil.copy2(bak, path)
    print(
        json.dumps(
            dict(
                id=c["id"],
                landed=landed,
                red=proc.returncode != 0,
                summary=summary,
                parse_error=parse_error,
                restored_byte_identical=sha256(path) == before,
                verdict=(
                    "RED (behavioural)"
                    if (landed and proc.returncode != 0 and not parse_error)
                    else "RED-BY-PARSE-ERROR (NOT A PROOF)"
                    if parse_error
                    else "GREEN — UNPROVEN"
                ),
            )
        ),
        flush=True,
    )
