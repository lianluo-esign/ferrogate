/**
 * THE RBAC GATE on the ladder this Worker actually RUNS.
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
 * ## Why this file drives `bearerAuth` instead of `SELF`
 *
 * Every other durable spec in this directory goes through `SELF` into the real
 * `src/worker.ts`, and that is the right shape when a request exists that can
 * reach the control. **For FC-7 no such request exists on this Worker**: all 12
 * contract operations carrying an `rbac_action` are `/admin/v1/guardrail-*` or
 * `/admin/v1/investigations` paths owned by `apps/control-plane`, so no URL a
 * test could fetch would carry one, and a `SELF`-driven test would pass with
 * the gate deleted. That is precisely FC-7's own trap — the control was
 * unenforced for a whole wave BECAUSE nothing exercised it — so it is stated
 * here rather than worked around:
 *
 *  - `bearerAuth` is the function `contractAuth` calls for EVERY bearer
 *    operation. It is imported and driven directly, in its real order, with the
 *    real deps `resolveDeps(env)` builds from the harness's REAL `CONTROL_DB`
 *    and `TENANT_DATA` — post-#863 the role BINDINGS live in the per-tenant
 *    Durable Object while `permissions`/`roles` stay in CONTROL.
 *    Deleting the RBAC block from `src/middleware/auth.ts`, or the
 *    `rbac: rbacAuthorizerFromEnv(env)` line from `resolveDeps`, turns this
 *    file red.
 *  - The only thing synthesised is the OPERATION's `rbac_action` — one field of
 *    the contract table, on an operation this Worker really serves. Everything
 *    else (the credential, the D1 rows, the scope check, the admission ladder,
 *    the composition root) is production code and real state.
 *  - `contractAuth`'s side — that it hands `bearerAuth` the operation the
 *    contract matched, so the field is never ignored — is held by
 *    `test/contract.test.ts` and by the `SELF`-driven specs here that go
 *    through the same dispatcher.
 *
 * The FLEET half — that this Worker's answer is the SAME answer `apps/gateway`,
 * `apps/control-plane` and `apps/mcp` give for the same seeded grant graph — is
 * `apps/gateway/test/fleet-rbac-action.test.ts`.
 */
import { env } from "cloudflare:test";
import { DurableObjectTenantDatabaseRouter } from "@ferrogate/storage";
import type {
  TenantDataNamespace,
  TenantDataStatement,
} from "@ferrogate/storage/durable-objects";
import { Hono } from "hono";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";

import type { ApiOperation } from "../../src/contract.js";
import { operationById } from "../../src/contract.js";
import { bearerAuth } from "../../src/middleware/auth.js";
import { HttpError } from "../../src/middleware/errors.js";
import type { AgentRuntimeEnv } from "../../src/ports.js";
import { KEY_LIVE, TENANT_A, bearer, setupDurablePorts } from "./setup.js";

/**
 * A REAL operation this Worker serves, with one field overridden.
 *
 * `submitAgentJob` is a `bearer` operation with a real scope `KEY_LIVE` holds,
 * so the request reaches the RBAC rung instead of stopping at `scope_denied` —
 * and the base operation is read out of the contract rather than invented, so a
 * contract change that removes it fails here loudly.
 */
function guardedBy(rbacAction: string | null): ApiOperation {
  const base = operationById("submitAgentJob");
  if (base === undefined) {
    throw new Error("submitAgentJob is not in this Worker's contract slice");
  }
  return { ...base, rbacAction };
}

/** The refusal a caller sees, or `"admitted"` when the ladder let them through. */
type Outcome = { status: number; code: string; message: string } | "admitted";

/**
 * Drive the REAL bearer ladder for one operation.
 *
 * A tiny Hono app is used only to obtain a real `Context` — `bearerAuth` reads
 * `c.env`, `c.req.raw.headers` and `c.set(...)`, all of which a hand-built
 * object would have to fake. The env it resolves its deps from is the
 * harness's, so `CONTROL_DB` is the same migrated database the assertions seed.
 */
async function runBearer(key: string, operation: ApiOperation): Promise<Outcome> {
  const app = new Hono<AgentRuntimeEnv>();
  let outcome: Outcome = "admitted";
  app.post("/probe", async (c) => {
    try {
      await bearerAuth(c, operation);
    } catch (error) {
      if (!(error instanceof HttpError)) throw error;
      outcome = { status: error.status, code: error.code, message: error.message };
    }
    return c.json({ ok: true });
  });
  await app.fetch(
    new Request("https://agent-runtime-durable.test/probe", {
      method: "POST",
      headers: bearer(key),
      body: "{}",
    }),
    env,
  );
  return outcome;
}

const GUARDRAIL_ACTION = "guardrails.policy.activate";
/** A non-`guardrails.` action, to pin the OTHER half of the denial taxonomy. */
const PLAIN_ACTION = "agent.runs.purge";

/**
 * The tenant object router — the same construction `rbacAuthorizerFromEnv`
 * makes, because since #863 (M9 step 5) the binding half of the grant graph is
 * AUTHORITATIVE inside the per-tenant Durable Object: control migration
 * `sql/d1-ts/control/0016_tenant_configuration_policy_legacy.sql` renamed the
 * control `tenant_role_bindings` table to `_legacy` (migration input only), and
 * the live rows are the tenant-local `tenant_role_bindings` of
 * `sql/d1-ts/tenant/0015_tenant_configuration_policy.sql`. `permissions` and
 * the shared `roles` catalog stay in CONTROL, so the walk the specs below drive
 * spans BOTH authorities — exactly the pair `#tenantRoleGrants` reads.
 */
function tenantRouter(): DurableObjectTenantDatabaseRouter {
  const namespace = (env as unknown as { TENANT_DATA?: TenantDataNamespace }).TENANT_DATA;
  if (namespace === undefined) {
    throw new Error("the durable harness requires the TENANT_DATA binding (harness/wrangler.toml)");
  }
  return new DurableObjectTenantDatabaseRouter(namespace, env.CONTROL_DB);
}

/**
 * Write into one tenant object's PRIVILEGED tables. `tenant_role_bindings` and
 * `tenant_role_catalog` refuse ordinary tenant SQL (a tenant must not mint its
 * own grant), so seeding goes through the same trusted RPC the control plane's
 * projection writer uses — not through a test-only side door.
 */
async function privilegedTenantBatch(
  objectTenantId: string,
  statements: readonly TenantDataStatement[],
): Promise<void> {
  await tenantRouter().privilegedBatch(objectTenantId, statements);
}

const INSERT_BINDING_SQL =
  "INSERT INTO tenant_role_bindings (id, tenant_id, role_id, created_at_unix) " +
  "VALUES (?, ?, ?, ?) ON CONFLICT(tenant_id, role_id) DO NOTHING";

async function declarePermission(key: string): Promise<void> {
  await env.CONTROL_DB.prepare(
    "INSERT OR REPLACE INTO permissions (id, key, name, description) VALUES (?1, ?2, ?3, '')",
  )
    .bind(`perm_${key}`, key, key)
    .run();
}

/**
 * Seed a role in the shared CONTROL catalog and bind it to the tenant in the
 * tenant's OWN object — the two writes `apps/control-plane`'s RBAC routes make
 * post-#863, one per authority.
 */
async function grantRole(roleId: string, permissionKeys: readonly string[]): Promise<void> {
  await env.CONTROL_DB.prepare(
    "INSERT OR REPLACE INTO roles (id, name, slug, permission_keys_json) VALUES (?1, ?2, ?3, ?4)",
  )
    .bind(roleId, roleId, roleId, JSON.stringify(permissionKeys))
    .run();
  await privilegedTenantBatch(TENANT_A, [
    { sql: INSERT_BINDING_SQL, params: [`${TENANT_A}:${roleId}`, TENANT_A, roleId, 1] },
  ]);
}

beforeAll(async () => {
  await setupDurablePorts();
});

beforeEach(async () => {
  // Isolated storage rolls each test's writes back, but the seed rows written
  // by `setupDurablePorts` in `beforeAll` persist — so this only has to undo
  // anything a previous FILE left behind, and it makes "no grant" explicit
  // rather than assumed. `tenant_role_bindings_legacy` is swept too so the
  // idempotent #863 backfill the authorizer runs first cannot resurrect a
  // binding some other file parked in the pre-object table.
  const db = env.CONTROL_DB;
  await db.batch([
    db.prepare("DELETE FROM tenant_role_bindings_legacy"),
    db.prepare("DELETE FROM roles"),
    db.prepare("DELETE FROM permissions"),
  ]);
  await privilegedTenantBatch(TENANT_A, [
    { sql: "DELETE FROM tenant_role_bindings", params: [] },
    { sql: "DELETE FROM tenant_role_catalog", params: [] },
  ]);
});

describe("FC-7 — the deployed bearer ladder consults the durable role graph", () => {
  it("admits the same credential when the operation declares NO rbac_action", async () => {
    // THE POSITIVE CONTROL, and it is not optional: without it every refusal
    // below would also pass against a Worker that refuses this credential for
    // an unrelated reason (a bad scope, an empty tenant, a spent quota).
    expect(await runBearer(KEY_LIVE, guardedBy(null))).toBe("admitted");
  });

  it("403 guardrail_rbac_denied when no role grants the declared action", async () => {
    // The defect, inverted. Before the fix this was `"admitted"`: the field was
    // parsed off the contract and never read, so an operator who withheld
    // `guardrails.policy.activate` from every role changed nothing here.
    expect(await runBearer(KEY_LIVE, guardedBy(GUARDRAIL_ACTION))).toEqual({
      status: 403,
      code: "guardrail_rbac_denied",
      message: `tenant roles do not grant required action ${GUARDRAIL_ACTION}`,
    });
  });

  it("admits once a role bound to the tenant grants it — no redeploy", async () => {
    await declarePermission(GUARDRAIL_ACTION);
    await grantRole("role_guardrail_operator", [GUARDRAIL_ACTION]);
    // Nothing but three CONTROL rows changed between this test and the one
    // above, which is what makes the refusal a decision about the GRAPH rather
    // than a blanket denial.
    expect(await runBearer(KEY_LIVE, guardedBy(GUARDRAIL_ACTION))).toBe("admitted");
  });

  it("names a non-guardrail denial `rbac_denied`, as the gateway does", async () => {
    expect(await runBearer(KEY_LIVE, guardedBy(PLAIN_ACTION))).toEqual({
      status: 403,
      code: "rbac_denied",
      message: `tenant roles do not grant required action ${PLAIN_ACTION}`,
    });
  });

  it("an UNDECLARED permission grants nothing, however many roles name it", async () => {
    // Step 1 of the Rust walk (`list_permissions().any(key == …)`). Skipping it
    // would let a typo in a role's `permission_keys` mint an entitlement, and
    // this is the assertion that notices — the role below names the action and
    // the `permissions` row is deliberately absent.
    await grantRole("role_typo", [GUARDRAIL_ACTION]);
    expect(await runBearer(KEY_LIVE, guardedBy(GUARDRAIL_ACTION))).toMatchObject({
      status: 403,
      code: "guardrail_rbac_denied",
    });
  });

  it("a role bound to ANOTHER tenant does not grant it", async () => {
    await declarePermission(GUARDRAIL_ACTION);
    await env.CONTROL_DB.prepare(
      "INSERT OR REPLACE INTO roles (id, name, slug, permission_keys_json) VALUES (?1, ?1, ?1, ?2)",
    )
      .bind("role_other_tenant", JSON.stringify([GUARDRAIL_ACTION]))
      .run();
    // The foreign binding is written into TENANT_A's OWN object on purpose.
    // Post-#863 another tenant's rows normally live in another object, where
    // physical isolation would make this test pass even against a walk with no
    // `tenant_id` predicate at all — vacuously. Placing the row where a
    // careless read COULD find it keeps the assertion about the fence in the
    // QUERY (`WHERE b.tenant_id = ?1`), which is the half a code change can
    // break.
    await privilegedTenantBatch(TENANT_A, [
      {
        sql: INSERT_BINDING_SQL,
        params: ["other:role_other_tenant", "tenant-somebody-else", "role_other_tenant", 1],
      },
    ]);
    // The fence. A walk that ignored `tenant_id` would admit here, and the
    // grant test above would still pass — so both halves are needed.
    expect(await runBearer(KEY_LIVE, guardedBy(GUARDRAIL_ACTION))).toMatchObject({
      status: 403,
      code: "guardrail_rbac_denied",
    });
  });

  it("503 rbac_unavailable when the grant graph cannot be read", async () => {
    // An outage is NEVER a decision: fail-open here would make "flap the
    // control plane" an authorization bypass, and fail-closed-as-403 would be
    // indistinguishable from a policy answer. Proven by dropping the table the
    // walk reads first — the same failure an operator gets by deploying before
    // `wrangler d1 migrations apply ferrogate-control`. Isolated storage rolls
    // the DROP back after this test.
    await env.CONTROL_DB.prepare("DROP TABLE permissions").run();
    expect(await runBearer(KEY_LIVE, guardedBy(GUARDRAIL_ACTION))).toMatchObject({
      status: 503,
      code: "rbac_unavailable",
    });
  });
});
