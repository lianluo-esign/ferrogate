#!/usr/bin/env python3
"""Wave-20 integration verification: neutralise each fix, prove RED, restore, prove GREEN.

Run from the repo root. Writes a markdown table to stdout.

Protocol per row (the repo's standing mutation protocol):
  1. sha256 the file, back it up
  2. apply the neutralisation, asserting the target text occurs EXACTLY once
  3. GREP THE FILE ON DISK to confirm the edit landed (a concurrent write can
     clobber a mutation and make a sound test look vacuous)
  4. run the named test -> require FAIL
  5. restore from backup, verify sha256 is byte-identical
  6. run the named test again -> require PASS
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
BAK = "/tmp/wave20-mut"
os.makedirs(BAK, exist_ok=True)

# (id, class, file, old, new, marker, app_dir, test_filter, what_it_proves)
MUTATIONS = [
    (
        "M1",
        "A1 MONEY",
        "apps/gateway/src/metering/sink.ts",
        "    await this.#budgetAlerts(backend, charge, attribution);",
        "    /* MUT_M1_BUDGET_ALERTS_NEUTRALISED */",
        "MUT_M1_BUDGET_ALERTS_NEUTRALISED",
        "apps/gateway",
        "metering/budget-alerts",
        "the metering path calls the alert dispatcher at all",
    ),
    (
        "M2",
        "A3 SECURITY",
        "apps/gateway/src/routes/agent-discovery.ts",
        "  const upstreams = await agentUpstreamsForCaller(env, auth, parseAgentUpstreams);",
        "  const upstreams = parseAgentUpstreams(env?.GATEWAY_AGENT_UPSTREAMS);"
        " /* MUT_M2_VAR_ONLY_REGISTRY */",
        "MUT_M2_VAR_ONLY_REGISTRY",
        "apps/gateway",
        "agent-upstream-withdrawal",
        "discovery reads the DURABLE registry, not only the deploy-time var",
    ),
    (
        "M3",
        "A4 MONEY",
        "apps/control-plane/src/routes/billing.ts",
        "        return await replayOutboxReportRow(c, deps.tenantDatabases, scope, reportId);",
        '        throw new HttpError(404, "not_found", `MUT_M3_NO_ROW_REPLAY ${reportId}`);',
        "MUT_M3_NO_ROW_REPLAY",
        "apps/control-plane",
        "billing-replay",
        "a dead letter with NO document reaches the row-addressed replay",
    ),
    (
        "M4",
        "A2 gate",
        "apps/agent-runtime/src/runs/lifecycle.ts",
        """  const workflowUse = await admitWorkflowStep(c, {
    stub,
    tenantId,
    runId,
    nowUnix,
    toolCalls: plan.tool_calls,
  });""",
        "  const workflowUse = null; /* MUT_M4_WORKFLOW_GATE_BYPASSED */",
        "MUT_M4_WORKFLOW_GATE_BYPASSED",
        "apps/agent-runtime",
        "workflow-tool-gate",
        "the tool-side workflow graph gate runs on the create path",
    ),
    (
        "M5",
        "A2 contract",
        "apps/agent-runtime/src/runs/lifecycle.ts",
        """      ...(synchronousShape
        ? {
            turns_executed: created.run.turns_executed,
            output: created.run.output,
            tool_results: [],""",
        """      ...(synchronousShape
        ? {
            /* MUT_M5_CONTRACT_FIELDS_DROPPED */
            tool_results: [],""",
        "MUT_M5_CONTRACT_FIELDS_DROPPED",
        "apps/agent-runtime",
        "agent-run-contract",
        "createAgentRun answers the contract's named fields",
    ),
    (
        "M6",
        "healthz cp",
        "apps/control-plane/src/routes/health.ts",
        """  return {
    status: "ok",
    service: SERVICE_NAME,
    version: SERVICE_VERSION,
    runtime: RUNTIME_NAME,
  };
}""",
        """  return {
    status: "ok",
    service: SERVICE_NAME,
    /* MUT_M6_CP_VERSION_DROPPED */
    runtime: RUNTIME_NAME,
  };
}""",
        "MUT_M6_CP_VERSION_DROPPED",
        "apps/control-plane",
        "health",
        "control-plane /healthz carries `version`",
    ),
    (
        "M7",
        "healthz mcp",
        "apps/mcp/src/routes/index.ts",
        """    status: "ok",
    service: SERVICE_NAME,
    version: SERVICE_VERSION,""",
        """    status: "ok",
    service: SERVICE_NAME,
    /* MUT_M7_MCP_VERSION_DROPPED */""",
        "MUT_M7_MCP_VERSION_DROPPED",
        "apps/mcp",
        "health",
        "mcp /healthz carries `version`",
    ),
    (
        "M8",
        "healthz tel",
        "apps/telemetry/src/app.ts",
        """      status: "ok",
      service: SERVICE_NAME,
      version: SERVICE_VERSION,""",
        """      status: "ok",
      service: SERVICE_NAME,
      /* MUT_M8_TEL_VERSION_DROPPED */""",
        "MUT_M8_TEL_VERSION_DROPPED",
        "apps/telemetry",
        "health",
        "telemetry /healthz carries `version`",
    ),
]


def sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def run_test(app_dir, test_filter):
    """Returns (passed: bool, summary: str)."""
    # `bunx vitest run <filter>`, NOT `bun run test -- <filter>`: several apps
    # chain suites with `&&`, and the appended `--` args land on the LAST
    # command in the chain, so the filter would silently apply to a harness
    # that does not contain the named test — and the run would look GREEN under
    # a landed mutation for the most boring possible reason.
    proc = subprocess.run(
        ["bunx", "vitest", "run", test_filter],
        cwd=os.path.join(ROOT, app_dir),
        capture_output=True,
        text=True,
        timeout=1800,
    )
    out = proc.stdout + proc.stderr
    summary = ""
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("Tests "):
            summary = s
    # A parse error is NOT a legitimate RED: it proves the file was edited, not
    # that the test holds the behaviour. Flag it so it cannot pass for a proof.
    parse_error = "Transform failed" in out or "esbuild" in out.lower() and "error" in out.lower()
    return proc.returncode == 0, summary or "(no summary)", parse_error


def main():
    results = []
    only = sys.argv[1:] or None
    for (mid, cls, rel, old, new, marker, app_dir, tfilter, proves) in MUTATIONS:
        if only and mid not in only:
            continue
        path = os.path.join(ROOT, rel)
        before = sha256(path)
        bak = os.path.join(BAK, mid + ".bak")
        shutil.copy2(path, bak)

        text = open(path, encoding="utf-8").read()
        count = text.count(old)
        if count != 1:
            results.append(
                dict(id=mid, cls=cls, file=rel, status="TARGET_NOT_UNIQUE", occurrences=count)
            )
            continue

        open(path, "w", encoding="utf-8").write(text.replace(old, new))

        # STEP 3 — grep the file ON DISK. Not the string we think we wrote.
        landed = marker in open(path, encoding="utf-8").read()
        if not landed:
            shutil.copy2(bak, path)
            results.append(dict(id=mid, cls=cls, file=rel, status="MUTATION_DID_NOT_LAND"))
            continue

        red_pass, red_summary, red_parse = run_test(app_dir, tfilter)

        shutil.copy2(bak, path)
        after = sha256(path)
        restored = after == before

        green_pass, green_summary, _ = run_test(app_dir, tfilter)

        results.append(
            dict(
                id=mid,
                cls=cls,
                file=rel,
                proves=proves,
                test=f"{app_dir} :: {tfilter}",
                landed=landed,
                red=not red_pass,
                red_summary=red_summary,
                red_was_parse_error=red_parse,
                restored_byte_identical=restored,
                green=green_pass,
                green_summary=green_summary,
                verdict=(
                    "PROVEN"
                    if (landed and not red_pass and not red_parse and restored and green_pass)
                    else "NOT PROVEN"
                ),
            )
        )
        print(json.dumps(results[-1]), flush=True)

    print("\n=== SUMMARY ===")
    print(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
