/**
 * THE RBAC GATE on the chokepoint this Worker actually RUNS.
 * (`docs/rewrite/FLEET-CONSISTENCY.md` finding **FC-7**, issue #668.)
 *
 * ## The defect this holds closed
 *
 * `src/contract.ts` parsed every operation's `rbac_action` into its
 * `ApiOperation` and **nothing read it**. A role an operator used to withhold
 * an action was enforced on `apps/gateway` and `apps/control-plane` and
 * silently ignored here — "call the other endpoint", the shape of both fleet
 * defects this project has already shipped.
 *
 * ## Why this file drives `authenticateRequest` instead of `SELF.fetch`
 *
 * Almost every test in this suite drives the deployed Worker over `SELF`, and
 * that is the right shape when a request exists that can reach the control.
 * **For FC-7 no such request exists on this Worker**: all 12 contract
 * operations carrying an `rbac_action` are `/admin/v1/guardrail-*` or
 * `/admin/v1/investigations` paths owned by `apps/control-plane`, so no URL a
 * test could fetch would carry one — and a `SELF`-driven test would stay green
 * with the gate deleted. That is FC-7's own trap (the control was unenforced
 * for a whole wave precisely BECAUSE nothing exercised it), so it is stated
 * here rather than worked around:
 *
 *  - {@link authenticateRequest} is the ONE function all five authenticated MCP
 *    surfaces call. It is driven directly, in its real order, with the real
 *    ports {@link resolvePorts} builds from this suite's REAL migrated control
 *    database. Deleting the RBAC block from `src/http.ts`, or the `rbac` line
 *    from `resolvePorts`, turns this file red.
 *  - The operation is attached with {@link recordOperation} — the SAME function
 *    `src/routes/index.ts::McpRouter.register` calls for every mounted route,
 *    not a test-only seam. Only its `rbac_action` field is synthesised.
 *  - That the ROUTER really records it is covered separately, and behaviourally:
 *    `authenticateRequest` now refuses a request with no recorded operation, so
 *    every `SELF`-driven test in this suite (`tools.test.ts`, `identity.test.ts`,
 *    `admission.test.ts`, …) fails with `500 internal_error` if the
 *    `recordOperation` call is removed from the router.
 *
 * The FLEET half — that this Worker's answer is the SAME answer `apps/gateway`,
 * `apps/control-plane` and `apps/agent-runtime` give for the same seeded grant
 * graph — is `apps/gateway/test/fleet-rbac-action.test.ts`.
 */
import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { type ApiOperation, operationById } from "../src/contract.js";
import { type AuthOutcome, authenticateRequest, recordOperation } from "../src/http.js";
import { type McpEnv, resolvePorts } from "../src/ports.js";
import { EXEC_KEY, seedFixture } from "./fixtures.js";
import {
  registerDurableObjectTenant,
  resetTenantObjectState,
  seedTenantRoleProjection,
} from "./tenant-object.js";

function controlDb(): D1Database {
  const binding = (env as unknown as { DB?: D1Database }).DB;
  if (binding === undefined) {
    // Loud, never a silent skip: `wrangler.toml` declares it, so an absent
    // binding means the declaration was removed and this suite is about to
    // prove something other than what it claims.
    throw new Error(
      "the RBAC tests expect the `DB` (control) binding — see apps/mcp/wrangler.toml",
    );
  }
  return binding;
}

/**
 * A REAL operation this Worker serves, with one field overridden.
 *
 * `executeMcpTool` is a `bearer` operation whose scope the fixture key holds,
 * so the request reaches the RBAC rung instead of stopping at
 * `insufficient_scope` — and the base operation is read out of the contract
 * rather than invented, so a contract change that removes it fails loudly here.
 */
function guardedBy(rbacAction: string | null): ApiOperation {
  const base = operationById("executeMcpTool");
  if (base === undefined) throw new Error("executeMcpTool is not in this Worker's contract slice");
  return { ...base, rbacAction };
}

/** The refusal a caller sees, or `"admitted"` when the ladder let them through. */
type Outcome = { status: number; code: string; message: string } | "admitted";

async function authenticate(operation: ApiOperation): Promise<Outcome> {
  const request = new Request("https://ferrogate.test/v1/mcp/tool/execute", {
    method: "POST",
    headers: { authorization: `Bearer ${EXEC_KEY}`, "content-type": "application/json" },
    body: JSON.stringify({ name: "echo", arguments: {} }),
  });
  // Exactly what `McpRouter.register` does before it calls the handler.
  recordOperation(request, operation);
  const outcome: AuthOutcome = await authenticateRequest(
    resolvePorts(env as unknown as McpEnv),
    request,
    "tools.execute",
    "mcp",
    { billable: false, env: undefined },
  );
  if (outcome.ok) return "admitted";
  return {
    status: outcome.status,
    code: outcome.body.error.code,
    message: outcome.body.error.message,
  };
}

const GUARDRAIL_ACTION = "guardrails.policy.activate";
/** A non-`guardrails.` action, to pin the OTHER half of the denial taxonomy. */
const PLAIN_ACTION = "mcp.servers.write";
/** This file must not reset the shared `fixtures.ts` tenant object. */
const RBAC_TENANT = "tenant-mcp-rbac-action";

async function declarePermission(key: string): Promise<void> {
  await controlDb()
    .prepare(
      "INSERT OR REPLACE INTO permissions (id, key, name, description) VALUES (?1, ?2, ?3, '')",
    )
    .bind(`perm_${key}`, key, key)
    .run();
}

/** Seed a role holding `permissionKeys` and bind it to `tenantId`. */
async function grantRole(
  roleId: string,
  permissionKeys: readonly string[],
  tenantId: string,
): Promise<void> {
  await controlDb()
    .prepare(
      "INSERT OR REPLACE INTO roles (id, name, slug, permission_keys_json) VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(roleId, roleId, roleId, JSON.stringify(permissionKeys))
    .run();
  await seedTenantRoleProjection(tenantId, roleId, permissionKeys);
}

beforeEach(async () => {
  seedFixture({ tenantId: RBAC_TENANT });
  const db = controlDb();
  await db.batch([db.prepare("DELETE FROM roles"), db.prepare("DELETE FROM permissions")]);
  await resetTenantObjectState([RBAC_TENANT, "tenant-somebody-else"]);
  // This suite authenticates as `RBAC_TENANT` (not the default `TENANT` the
  // global `setup-d1.ts` provisions), so it needs its own `tenant_databases`
  // roster row or admission 503s before the RBAC chokepoint is reached
  // (0045 tenant-object quota resolution).
  await registerDurableObjectTenant(RBAC_TENANT);
});

describe("FC-7 — the deployed MCP chokepoint consults the durable role graph", () => {
  it("admits the same credential when the operation declares NO rbac_action", async () => {
    // THE POSITIVE CONTROL, and it is not optional: without it every refusal
    // below would also pass against a Worker that refuses this credential for
    // an unrelated reason (a bad scope, a suspended tenancy, a spent quota).
    expect(await authenticate(guardedBy(null))).toBe("admitted");
  });

  it("403 guardrail_rbac_denied when no role grants the declared action", async () => {
    // The defect, inverted. Before the fix this was `"admitted"`: the field was
    // parsed off the contract and never read, so an operator who withheld
    // `guardrails.policy.activate` from every role changed nothing here.
    expect(await authenticate(guardedBy(GUARDRAIL_ACTION))).toEqual({
      status: 403,
      code: "guardrail_rbac_denied",
      message: `tenant roles do not grant required action ${GUARDRAIL_ACTION}`,
    });
  });

  it("admits once a role bound to the tenant grants it — no redeploy", async () => {
    await declarePermission(GUARDRAIL_ACTION);
    await grantRole("role_guardrail_operator", [GUARDRAIL_ACTION], RBAC_TENANT);
    // Nothing but three CONTROL rows changed between this test and the one
    // above, which is what makes the refusal a decision about the GRAPH rather
    // than a blanket denial.
    expect(await authenticate(guardedBy(GUARDRAIL_ACTION))).toBe("admitted");
  });

  it("names a non-guardrail denial `rbac_denied`, as the gateway does", async () => {
    expect(await authenticate(guardedBy(PLAIN_ACTION))).toEqual({
      status: 403,
      code: "rbac_denied",
      message: `tenant roles do not grant required action ${PLAIN_ACTION}`,
    });
  });

  it("an UNDECLARED permission grants nothing, however many roles name it", async () => {
    // Step 1 of the Rust walk (`list_permissions().any(key == …)`). Skipping it
    // would let a typo in a role's `permission_keys` mint an entitlement; the
    // role below names the action and the `permissions` row is absent.
    await grantRole("role_typo", [GUARDRAIL_ACTION], RBAC_TENANT);
    expect(await authenticate(guardedBy(GUARDRAIL_ACTION))).toMatchObject({
      status: 403,
      code: "guardrail_rbac_denied",
    });
  });

  it("a role bound to ANOTHER tenant does not grant it", async () => {
    await declarePermission(GUARDRAIL_ACTION);
    await grantRole("role_other_tenant", [GUARDRAIL_ACTION], "tenant-somebody-else");
    // The fence. A walk that ignored `tenant_id` would admit here while the
    // grant test above still passed, so both halves are needed.
    expect(await authenticate(guardedBy(GUARDRAIL_ACTION))).toMatchObject({
      status: 403,
      code: "guardrail_rbac_denied",
    });
  });

  it("503 rbac_unavailable when the grant graph cannot be read", async () => {
    // An outage is NEVER a decision: fail-open would make "flap the control
    // plane" an authorization bypass, and answering 403 would make an outage
    // indistinguishable from a policy answer. Proven by dropping the table the
    // walk reads first — the same failure an operator gets by deploying before
    // `wrangler d1 migrations apply ferrogate-control` — and restored after, so
    // the rest of the suite still has its schema.
    await controlDb().prepare("DROP TABLE permissions").run();
    try {
      expect(await authenticate(guardedBy(GUARDRAIL_ACTION))).toMatchObject({
        status: 503,
        code: "rbac_unavailable",
      });
    } finally {
      await controlDb()
        .prepare(
          "CREATE TABLE IF NOT EXISTS permissions (id TEXT PRIMARY KEY, key TEXT NOT NULL UNIQUE, " +
            "name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', " +
            "created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()), " +
            "updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch()))",
        )
        .run();
    }
  });

  it("refuses a request the router never matched, rather than skipping the gate", async () => {
    // FAIL CLOSED. `authenticateRequest` reads the operation the router
    // recorded; reading "no operation" as "no rbac_action" would make
    // forgetting the mount indistinguishable from an unguarded operation, which
    // IS the defect. This is also what makes the router's `recordOperation`
    // call provable: remove it and every `SELF` test in this suite sees this.
    const request = new Request("https://ferrogate.test/v1/mcp/tool/execute", {
      method: "POST",
      headers: { authorization: `Bearer ${EXEC_KEY}` },
      body: "{}",
    });
    const outcome = await authenticateRequest(
      resolvePorts(env as unknown as McpEnv),
      request,
      "tools.execute",
      "mcp",
      { billable: false, env: undefined },
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.status).toBe(500);
      expect(outcome.body.error.code).toBe("internal_error");
    }
  });
});
