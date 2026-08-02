#!/usr/bin/env python3
"""Wave-25 seam pass, the RESIDUE: the 22 rows the generic driver could not honestly prove.

`wave23-seam-pass.py` mutates by locating the Seam cell's text and commenting out
its LINE. That works for 178 of 200 rows. It cannot work for these 22, for three
reasons that are properties of the INVENTORY, not of the tree:

  1. **The row's file is not its section's file.** Twelve rows sit under a
     `### … src/index.ts` heading while their Seam cell names the module the seam
     actually lives in (`src/http.ts`, `src/identity/routes.ts`,
     `src/routes/health.ts`, …). The generic driver looked in `index.ts`, found
     nothing, and reported SEAM-NOT-UNIQUE.
  2. **The seam is a multi-line expression.** A ternary or a nested call spanning
     four lines has no single line to comment out; commenting one line yields a
     SYNTAX ERROR, and a suite that goes red because the file no longer parses
     proves nothing whatever about the gate.
  3. **The seam is ALREADY a comment** (`MCP-T10`, `AR-T10` — the deliberately
     commented cross-script `RATE_LIMIT` stanza). Commenting a comment changes
     bytes and changes nothing. Those two are NOT-MUTABLE by category and are
     recorded as such rather than counted as unproven.

So each row below carries an explicit, hand-written edit that changes what the
program DOES while leaving it parseable. The protocol is otherwise identical:
sha256 → apply → **grep the marker back off disk** → run only the tests the row
names → restore → require byte-identity.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
BAK = "/tmp/wave25-residue"
os.makedirs(BAK, exist_ok=True)

M = "MUTW25"

# (row id, file, old exact text, new text, one-line note on the BEHAVIOUR removed)
MUTATIONS = [
    (
        "GW-R17",
        "apps/gateway/src/routes/readiness.ts",
        "  return combineDrain(durable, drainStatus(env).draining);",
        f"  return /*{M}_GW_R17*/ combineDrain({{ ...durable, draining: false }}, drainStatus(env).draining);",
        "the DURABLE half of the drain is discarded; only the deploy-time var survives",
    ),
    (
        "GW-A2",
        "apps/gateway/src/adapters.ts",
        "        : denyIfEitherDenies(durableLifecycle, configuredLifecycle),",
        f"        : /*{M}_GW_A2*/ configuredLifecycle,",
        "the durable tenancy-lifecycle gate is dropped from the conjunction",
    ),
    (
        "GW-A3",
        "apps/gateway/src/adapters.ts",
        "      D1RbacAuthorizer.fromEnv(env as unknown as Record<string, unknown>, {\n"
        "        fallback: configuredRbac,\n"
        "      }) ?? configuredRbac,",
        f"      /*{M}_GW_A3*/ configuredRbac,",
        "the durable RBAC authorizer is never constructed; the config fallback always wins",
    ),
    (
        "GW-W2",
        "apps/gateway/src/ratelimit/workflow.ts",
        '      : (headers.get(AGENT_RUN_ID_HEADER)?.trim() ?? "");',
        f'      : /*{M}_GW_W2*/ "";',
        "the x-ferrogate-agent-run-id alias is deleted, so a reference-shaped client "
        "can no longer reach the workflow gate",
    ),
    (
        "CP-C9",
        "apps/control-plane/src/routes/index.ts",
        "  mountSharedProbes(app);",
        f"  /*{M}_CP_C9*/ void mountSharedProbes;",
        "/healthz and /readyz are never mounted on the control plane",
    ),
    (
        "CP-C13",
        "apps/control-plane/src/index.ts",
        'app.get("/version", (c) =>\n'
        "  c.json({\n"
        "    api: PUBLIC_API_MAJOR,\n"
        "    operations: EXPECTED_CONTROL_PLANE_OPERATION_COUNT,\n"
        "    registered: CONTROL_PLANE_OPERATIONS.length,\n"
        "    groups: CONTROL_PLANE_GROUPS.length,\n"
        "  }),\n"
        ");",
        f'/*{M}_CP_C13*/ app.get("/version", (c) => c.json({{ api: PUBLIC_API_MAJOR }}));',
        "/version stops reporting the registered-operation census",
    ),
    (
        "CP-S1",
        "apps/control-plane/src/index.ts",
        "  mountAdminConsoleSession(app);",
        f"  /*{M}_CP_S1*/ [] as unknown as ReturnType<typeof mountAdminConsoleSession>;",
        "the nine console-session routes are never mounted on the exported app",
    ),
    (
        "CP-S4",
        "apps/control-plane/src/identity/routes.ts",
        "    validated = await handleSamlAcs(identity.saml, new URL(c.req.url).search.slice(1));",
        f"    validated = await handleSamlAcs(identity.saml, /*{M}_CP_S4*/ "
        "decodeURIComponent(new URL(c.req.url).search.slice(1)));",
        "the SAML signature is verified over a RE-SERIALISED query rather than the raw octets",
    ),
    (
        "CP-S5",
        "apps/control-plane/src/identity/adapters.ts",
        '      .prepare("DELETE FROM sso_pending_flows WHERE state = ? RETURNING *")',
        f'      .prepare(/*{M}_CP_S5*/ "SELECT * FROM sso_pending_flows WHERE state = ?")',
        "the pending SSO flow is READ without being consumed — the state is no longer single-use",
    ),
    (
        "CP-P9",
        "apps/control-plane/src/routes/admin_config_ops.ts",
        '    if (scope.kind !== "platform_operator") {',
        f'    if (/*{M}_CP_P9*/ false && scope.kind !== "platform_operator") {{',
        "a tenant-scoped credential can set the deployment-wide operator drain",
    ),
    (
        "MCP-P12",
        "apps/mcp/src/http.ts",
        "    const refusal = drainRefusal(await resolveDrain(spend.env));",
        f"    const refusal = /*{M}_MCP_P12*/ (await resolveDrain(spend.env), undefined);",
        "MCP resolves the drain per request and IGNORES the answer (the M22 shape)",
    ),
    (
        "MCP-P13",
        "apps/mcp/src/routes/index.ts",
        "  const report = readinessReport(c.env, await resolveDrain(c.env as DrainBindings));",
        f"  const report = /*{M}_MCP_P13*/ readinessReport(c.env, "
        "(await resolveDrain(c.env as DrainBindings), NOT_DRAINING));",
        "/readyz on MCP stops reflecting the durable drain document",
    ),
    (
        "AR-V1",
        "apps/agent-runtime/src/index.ts",
        'app.get("/version", (c) =>\n'
        "  c.json({ api: PUBLIC_API_MAJOR, operations: EXPECTED_OWNED_OPERATION_COUNT }),\n"
        ");",
        f'/*{M}_AR_V1*/ app.get("/version", (c) => c.json({{ api: PUBLIC_API_MAJOR }}));',
        "agent-runtime's /version stops reporting its owned-operation count",
    ),
    (
        "AR-P10",
        "apps/agent-runtime/src/middleware/auth.ts",
        "  if (isDrainGuardedOperation(operation.operationId)) {",
        f"  if (/*{M}_AR_P10*/ false && isDrainGuardedOperation(operation.operationId)) {{",
        "the drain gate on the BEARER leg never fires for the 5 billable operations",
    ),
    (
        "AR-P11",
        "apps/agent-runtime/src/routes/health.ts",
        "  const draining = (!runtimeEnabled(env) || operatorDrain.draining) && !drainUnavailable;",
        f"  const draining = /*{M}_AR_P11*/ !runtimeEnabled(env) && !drainUnavailable;",
        "the durable operator drain is dropped from the /readyz conjunction",
    ),
    (
        "AR-P1",
        "apps/agent-runtime/src/ports.ts",
        "    env.DB !== undefined\n      ? d1ApiKeyPort(env.DB)",
        f"    /*{M}_AR_P1*/ false\n      ? d1ApiKeyPort(env.DB)",
        "the D1 credential port is never mounted; only the dev var table remains",
    ),
    (
        "AR-P2",
        "apps/agent-runtime/src/ports.ts",
        "    env.CONTROL_DB !== undefined\n      ? d1WorkerIdentityPort(env.CONTROL_DB)",
        f"    /*{M}_AR_P2*/ false\n      ? d1WorkerIdentityPort(env.CONTROL_DB)",
        "the durable self-hosted-worker registry is never mounted",
    ),
    (
        "AR-P5",
        "apps/agent-runtime/src/ports.ts",
        "      inMemoryAgentUpstreamPort(\n"
        "        parseJsonVar<AgentUpstream[]>(\n"
        "          env.AGENT_UPSTREAMS ?? (dev ? env.FG_DEV_AGENT_UPSTREAMS : undefined),\n"
        "          [],\n"
        "        ),\n"
        "      ),",
        f"      /*{M}_AR_P5*/ inMemoryAgentUpstreamPort([]),",
        "the operator's AGENT_UPSTREAMS var leg is discarded",
    ),
    (
        "AR-P6",
        "apps/agent-runtime/src/ports.ts",
        "      deterministicGuardrailPort(\n"
        "        parseJsonVar<{\n"
        "          keywords?: string[];\n"
        "          regex?: string[];\n"
        "          secretPatterns?: SecretPattern[];\n"
        "        }>(env.FG_DEV_A2A_GUARDRAILS, {}),\n"
        "      ),",
        f"      /*{M}_AR_P6*/ deterministicGuardrailPort({{}}),",
        "the A2A guardrail var leg is discarded",
    ),
    (
        "AR-P13",
        "apps/agent-runtime/src/ports.ts",
        "      : tenancyGatedApiKeyPort(resolvedApiKeys, d1LifecycleRowSource(env.CONTROL_DB, env.DB));",
        f"      : /*{M}_AR_P13*/ resolvedApiKeys;",
        "the FC-2 tenancy-lifecycle wrap is removed from the credential port",
    ),
]

# NOT-MUTABLE by category: the seam IS a commented-out stanza. Commenting a
# comment is a byte change with no behaviour change, so these are declared, not
# measured. Their ROT directions are what `env-var-drift.test.ts` gates.
NOT_MUTABLE = [
    ("MCP-T10", "apps/mcp/wrangler.toml", "the seam is the deliberately COMMENTED cross-script RATE_LIMIT stanza"),
    ("AR-T10", "apps/agent-runtime/wrangler.toml", "same; the inventory marks it WORKERD-REFUSAL"),
]


def sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def run_gate(row_id):
    proc = subprocess.run(
        ["bun", "scripts/seam-proof.mjs", "--id", row_id, "--run"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=2400,
    )
    out = proc.stdout + proc.stderr
    m = re.search(rf"^{re.escape(row_id)}\s+(GREEN|RED|NO-GATE|NO-FILE)\s", out, re.M)
    return (m.group(1) if m else "UNKNOWN"), out


def main():
    want = set(a for a in sys.argv[1:] if not a.startswith("-"))
    results = []
    for rid, rel, old, new, note in MUTATIONS:
        if want and rid not in want:
            continue
        path = os.path.join(ROOT, rel)
        text = open(path, encoding="utf-8").read()
        n = text.count(old)
        if n != 1:
            print(f"{rid} NOT-UNIQUE ({n} occurrences) in {rel}", flush=True)
            results.append(dict(id=rid, file=rel, status="NOT-UNIQUE", occurrences=n))
            continue
        before = sha256(path)
        bak = os.path.join(BAK, rid + ".bak")
        shutil.copy2(path, bak)
        open(path, "w", encoding="utf-8").write(text.replace(old, new, 1))

        # Grep the marker BACK OFF DISK, and require the ORIGINAL text to be gone.
        ondisk = open(path, encoding="utf-8").read()
        marker = f"{M}_{rid.replace('-', '_')}"
        if marker not in ondisk or old in ondisk:
            shutil.copy2(bak, path)
            print(f"{rid} MUTATION-DID-NOT-LAND", flush=True)
            results.append(dict(id=rid, file=rel, status="MUTATION-DID-NOT-LAND"))
            continue

        gate, _ = run_gate(rid)
        shutil.copy2(bak, path)
        restored = sha256(path) == before
        status = "RED" if gate == "RED" else ("GREEN-UNPROVEN" if gate == "GREEN" else gate)
        results.append(
            dict(id=rid, file=rel, status=status, behaviour=note, restored_byte_identical=restored)
        )
        print(f"{rid:9s} {status:15s} restored={restored}  — {note}", flush=True)
        if not restored:
            print(f"!! RESTORE FAILED {rel} — ABORTING", flush=True)
            break

    for rid, rel, why in NOT_MUTABLE:
        results.append(dict(id=rid, file=rel, status="NOT-MUTABLE", behaviour=why))
        print(f"{rid:9s} NOT-MUTABLE     — {why}", flush=True)

    json.dump(results, open("/tmp/wave25-residue-results.json", "w"), indent=1)
    from collections import Counter

    print("\n=== RESIDUE SUMMARY ===")
    print(json.dumps(Counter(r["status"] for r in results), indent=1))


if __name__ == "__main__":
    main()
