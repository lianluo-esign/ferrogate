/**
 * **ONE ROLE, EVERY DOOR** — the fleet effect of an operation's `rbac_action`.
 * (`docs/rewrite/FLEET-CONSISTENCY.md` item **FC-7**, issue #668.)
 *
 * ## The defect this holds closed
 *
 * `rbac_action` was PARSED by four Workers and CONSULTED by two:
 *
 * ```
 * # grep -rln 'rbac_action' across every Worker's src, before this fix:
 * apps/gateway/src/contract.ts        → consulted (middleware/auth.ts)
 * apps/control-plane/src/contract.ts  → consulted (middleware/auth.ts)
 * apps/mcp/src/contract.ts            → parsed, unread
 * apps/agent-runtime/src/contract.ts  → parsed, unread
 * ```
 *
 * A role an operator uses to withhold an action was enforced on two of the four
 * credential Workers and silently ignored on the other two. It cost nothing on
 * the day it was found — every rbac-guarded operation in
 * `docs/openapi/runtime-api-contract.json` is an `/admin/v1/` path those two
 * Workers do not serve — and that is exactly what made it dangerous: the
 * control was PRE-ARMED to fail the day an `rbac_action` landed on a data-plane
 * operation, with every per-Worker suite green because every Worker was
 * individually correct. That is the shape of both fleet defects this project
 * has already shipped (the wave-16 admission bypass, the wave-20 agent-upstream
 * half-withdrawal).
 *
 * ## How four Workers are reached from one test
 *
 * The five Workers are separately bundled and no app may import another's
 * module graph. This file is a TEST, not a bundle, and it reaches each side the
 * way `apps/mcp/test/drain-fleet.test.ts` established:
 *
 *  - **`apps/gateway`** — behavioural and end to end: `SELF.fetch` into this
 *    Worker's deployed app, on a REAL rbac-guarded contract operation
 *    (`GET /admin/v1/guardrail-policies`), through the real `contractAuth` and
 *    the real `depsFromEnv`;
 *  - **`apps/mcp` / `apps/agent-runtime`** — their REAL production authorizers,
 *    `rbacAuthorizerFromEnv` out of each Worker's own `src/rbac.ts`, invoked
 *    against the SAME control database handle. Not a reproduction of their SQL
 *    and not a paraphrase: the exact functions their composition roots mount.
 *    Their BEHAVIOURAL legs — that the deployed auth ladder actually calls
 *    them — are `apps/mcp/test/rbac-action.test.ts` and
 *    `apps/agent-runtime/test/durable/rbac-action.spec.ts`;
 *  - **`apps/control-plane`** — read as TEXT (`?raw`, the same inlining
 *    `test/env-var-drift.test.ts` uses), because its authorizer lives in a
 *    module that pulls half the Worker's graph with it. Its behaviour is driven
 *    over `SELF` in its own suite (`test/rbac-d1.test.ts`, `test/auth.test.ts`).
 *
 * The two cross-app imports are only sound because both `rbac.ts` modules are
 * runtime LEAVES — their only import is a TYPE — so no other Worker's module
 * graph enters this bundle. §4 asserts that off the files' own source text
 * rather than trusting this paragraph.
 *
 * ## What this file does NOT claim
 *
 * `apps/control-plane`'s authorizer answers the same way for the cases an
 * operator meets in practice, and DIFFERS from the other three in three
 * recorded ways (§3). Those are pre-existing, deliberate in their own file, and
 * NOT fixed here — recording them as assertions is the ratchet: closing any of
 * them turns this file red and forces the ledger to move with the code.
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  D1RbacAuthorizer as GatewayRbac,
  type RbacDatabase,
  rbacDenialCode as gatewayDenialCode,
  rbacDenialMessage as gatewayDenialMessage,
} from "../src/adapters.js";
import type { AuthContext as GatewayAuth, RbacDecision } from "../src/ports.js";

// --- apps/agent-runtime: the OTHER enforcer's real authorizer ---------------
import {
  rbacDenialCode as agentDenialCode,
  rbacDenialMessage as agentDenialMessage,
  rbacAuthorizerFromEnv as agentRbacFromEnv,
} from "../../agent-runtime/src/rbac.js";
// TYPE-ONLY, therefore erased: importing the caller shape from each Worker's
// own `ports.ts` costs no runtime edge and keeps the fixtures honest — a field
// rename on either Worker fails the typecheck here rather than silently
// building an `AuthContext` that Worker would never produce.
import type { AuthContext as AgentAuth } from "../../agent-runtime/src/ports.js";
import agentRbacSource from "../../agent-runtime/src/rbac.ts?raw";
// --- apps/control-plane: read as TEXT, never imported -----------------------
import controlPlaneAdapters from "../../control-plane/src/adapters.ts?raw";
import controlPlaneAuth from "../../control-plane/src/middleware/auth.ts?raw";
// --- apps/mcp: the OTHER enforcer's real authorizer -------------------------
import {
  rbacDenialCode as mcpDenialCode,
  rbacDenialMessage as mcpDenialMessage,
  rbacAuthorizerFromEnv as mcpRbacFromEnv,
} from "../../mcp/src/rbac.js";
import type { AuthContext as McpAuth } from "../../mcp/src/ports.js";
import mcpRbacSource from "../../mcp/src/rbac.ts?raw";

const bindings = env as unknown as Record<string, unknown>;

function controlDb(): D1Database {
  const binding = bindings.CONTROL_DB as D1Database | undefined;
  if (binding === undefined) {
    // Loud, never a silent skip: `wrangler.toml` declares it, so an absent
    // binding means the declaration was removed and this file is about to
    // prove something other than what it claims.
    throw new Error(
      "the fleet RBAC gate expects the `CONTROL_DB` binding (apps/gateway/wrangler.toml); " +
        "without it every Worker below would answer from an empty graph",
    );
  }
  return binding;
}

// ---------------------------------------------------------------------------
// The grant graph — ONE database, written once, read by every Worker
// ---------------------------------------------------------------------------

const TENANT = "tenant_fleet_rbac";
const OTHER_TENANT = "tenant_someone_else";
const ACTION = "guardrails.policy.read";

async function declarePermission(key: string): Promise<void> {
  await controlDb()
    .prepare(
      "INSERT OR REPLACE INTO permissions (id, key, name, description) VALUES (?1, ?2, ?3, '')",
    )
    .bind(`perm_${key}`, key, key)
    .run();
}

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
  await controlDb()
    .prepare(
      "INSERT OR REPLACE INTO tenant_role_bindings (id, tenant_id, role_id) VALUES (?1, ?2, ?3)",
    )
    .bind(`${tenantId}:${roleId}`, tenantId, roleId)
    .run();
}

async function resetGraph(): Promise<void> {
  const db = controlDb();
  await db.batch([
    db.prepare("DELETE FROM tenant_role_bindings"),
    db.prepare("DELETE FROM roles"),
    db.prepare("DELETE FROM permissions"),
  ]);
}

// ---------------------------------------------------------------------------
// The same caller, in each Worker's own `AuthContext` shape
// ---------------------------------------------------------------------------

function gatewayAuth(tenantId: string, operator = false): GatewayAuth {
  return {
    subject: "key_fleet",
    tenancy: { tenantId, projectId: null, workspaceId: null, userId: null },
    scopes: ["admin.read"],
    platformOperator: operator,
    source: "durable_native",
  };
}

function mcpAuth(tenantId: string, operator = false): McpAuth {
  return {
    apiKeyId: "key_fleet",
    organizationId: tenantId,
    scopes: ["tools.execute"],
    permissions: [],
    platformOperator: operator,
  };
}

function agentAuth(tenantId: string, operator = false): AgentAuth {
  return {
    subject: "key_fleet",
    tenancy: { tenantId },
    scopes: ["agent.runs.create"],
    platformOperator: operator,
  };
}

/** A database that fails every statement, as an outage would. */
const failingDb = {
  prepare(): never {
    throw new Error("D1_ERROR: control database is unreachable");
  },
} as unknown as D1Database;

/**
 * Ask all three importable Workers the same question, each through its OWN
 * production authorizer over the SAME database handle.
 *
 * The decisions are compared as DATA, which is what makes a divergence legible:
 * a Worker that stops checking, starts checking a different table or renames
 * its refusal shows up as one entry differing from the other two.
 */
async function fleetDecisions(
  tenantId: string,
  action: string,
  options: { operator?: boolean; db?: D1Database } = {},
): Promise<Record<string, RbacDecision>> {
  const db = options.db ?? controlDb();
  const operator = options.operator ?? false;
  return {
    gateway: await new GatewayRbac(db as unknown as RbacDatabase).authorize(
      gatewayAuth(tenantId, operator),
      action,
    ),
    mcp: await mcpRbacFromEnv({ DB: db }).authorize(mcpAuth(tenantId, operator), action),
    "agent-runtime": await agentRbacFromEnv({ CONTROL_DB: db }).authorize(
      agentAuth(tenantId, operator),
      action,
    ),
  };
}

const DENIED: RbacDecision = {
  allowed: false,
  code: "guardrail_rbac_denied",
  message: `tenant roles do not grant required action ${ACTION}`,
};

beforeAll(resetGraph);
afterEach(resetGraph);

// ---------------------------------------------------------------------------
// §1  ONE OPERATOR ACTION, OBSERVED BY EVERY ENFORCER
// ---------------------------------------------------------------------------

describe("§1 one grant graph, one answer on every Worker that can serve the action", () => {
  it("1.1 no role: every Worker denies, with the same code and the same sentence", async () => {
    const decisions = await fleetDecisions(TENANT, ACTION);
    expect(decisions).toEqual({ gateway: DENIED, mcp: DENIED, "agent-runtime": DENIED });
  });

  it("1.2 ONE role binding admits on every Worker — no redeploy anywhere", async () => {
    // The operator's single action, applied once to the durable graph. Before
    // this fix `apps/mcp` and `apps/agent-runtime` had no answer to give at
    // all: they parsed the field and never consulted anything.
    await declarePermission(ACTION);
    await grantRole("role_fleet_reader", [ACTION], TENANT);
    const decisions = await fleetDecisions(TENANT, ACTION);
    expect(decisions).toEqual({
      gateway: { allowed: true },
      mcp: { allowed: true },
      "agent-runtime": { allowed: true },
    });
  });

  it("1.3 the grant is fenced to the tenant it was bound to, fleet-wide", async () => {
    await declarePermission(ACTION);
    await grantRole("role_fleet_reader", [ACTION], TENANT);
    // Same graph, different caller. A Worker that ignored `tenant_id` would
    // admit here while 1.2 still passed, which is why both halves exist.
    const decisions = await fleetDecisions(OTHER_TENANT, ACTION);
    expect(decisions).toEqual({ gateway: DENIED, mcp: DENIED, "agent-runtime": DENIED });
  });

  it("1.4 an UNDECLARED permission grants nothing, on every Worker", async () => {
    // Step 1 of the Rust walk (`list_permissions().any(key == …)`): the role
    // names the action and no `permissions` row declares it. Skipping this step
    // is how a typo in a role's `permission_keys` would mint an entitlement,
    // and a Worker that skipped it would be the odd one out here.
    await grantRole("role_typo", [ACTION], TENANT);
    const decisions = await fleetDecisions(TENANT, ACTION);
    expect(decisions).toEqual({ gateway: DENIED, mcp: DENIED, "agent-runtime": DENIED });
  });

  it("1.5 a role WILDCARD is not a grant, on every Worker", async () => {
    // Rust compares `key == permission_key`, so `"*"` in a role's
    // `permission_keys` is a permission literally named `*`. A Worker that read
    // it as "everything" would hand every action to any tenant holding a
    // catch-all role.
    await declarePermission(ACTION);
    await grantRole("role_wildcard", ["*"], TENANT);
    const decisions = await fleetDecisions(TENANT, ACTION);
    expect(decisions).toEqual({ gateway: DENIED, mcp: DENIED, "agent-runtime": DENIED });
  });

  it("1.6 a declared platform operator is exempt on every Worker", async () => {
    const decisions = await fleetDecisions(TENANT, ACTION, { operator: true });
    expect(decisions).toEqual({
      gateway: { allowed: true },
      mcp: { allowed: true },
      "agent-runtime": { allowed: true },
    });
  });

  it("1.7 an unreadable graph is `unavailable` on every Worker, never a decision", async () => {
    // The one thing a healthy binding cannot be asked to do. Fail-open would
    // make "flap the control plane" an authorization bypass; answering 403
    // would make an outage indistinguishable from a policy answer. Both are
    // refused identically fleet-wide.
    const decisions = await fleetDecisions(TENANT, ACTION, { db: failingDb });
    for (const [app, decision] of Object.entries(decisions)) {
      expect(decision.allowed, `${app} turned an outage into a decision`).toBe("unavailable");
    }
  });

  it("1.8 the denial taxonomy is one function, computed identically fleet-wide", () => {
    // `guardrail_rbac_denied` for `guardrails.*`, `rbac_denied` otherwise —
    // Rust names the denial after the action's domain. Compared as the FUNCTION
    // each Worker ships rather than as a string a test wrote down, so a Worker
    // that renames its refusal is red here.
    for (const action of [ACTION, "guardrails.policy.activate", "agent.runs.purge", "x.y"]) {
      expect([mcpDenialCode(action), agentDenialCode(action)]).toEqual([
        gatewayDenialCode(action),
        gatewayDenialCode(action),
      ]);
      expect([mcpDenialMessage(action), agentDenialMessage(action)]).toEqual([
        gatewayDenialMessage(action),
        gatewayDenialMessage(action),
      ]);
    }
  });
});

// ---------------------------------------------------------------------------
// §2  THE GATEWAY LEG — behavioural, through the deployed app
// ---------------------------------------------------------------------------

describe("§2 the gateway enforces the same graph on a real contract operation", () => {
  const ADMIN_KEY = "fg_fleet_rbac_admin";

  beforeAll(() => {
    // A native key for a tenant with NO entry in `TENANT_RBAC_ACTIONS`
    // (`vitest.config.ts` grants `tenant_a` there), carrying the operation's
    // `admin.read` scope so the request reaches the RBAC rung rather than
    // stopping at `scope_denied`.
    bindings.GATEWAY_NATIVE_API_KEYS = JSON.stringify([
      { key: ADMIN_KEY, id: "key_fleet_rbac", tenant_id: TENANT, scopes: ["admin.read"] },
    ]);
  });

  function listPolicies(): Promise<Response> {
    return SELF.fetch("https://gw.test/admin/v1/guardrail-policies", {
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    });
  }

  it("2.1 refuses the action the graph does not grant", async () => {
    const res = await listPolicies();
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "guardrail_rbac_denied",
    );
  });

  it("2.2 clears the guard once the SAME rows §1 writes exist", async () => {
    await declarePermission(ACTION);
    await grantRole("role_fleet_reader", [ACTION], TENANT);
    // 404, not 403: the guard admitted the request and `apps/control-plane`
    // owns the route, so this Worker mounts nothing for it. Nothing but the D1
    // rows changed between 2.1 and here.
    expect((await listPolicies()).status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// §3  THE CONTROL-PLANE LEG — read as text, divergences RECORDED not fixed
// ---------------------------------------------------------------------------

describe("§3 apps/control-plane consults the same graph, with three recorded deltas", () => {
  it("3.1 it consults an authorizer for the operation's declared action", () => {
    expect(controlPlaneAuth).toContain("deps.rbac.authorize(auth, operation.rbacAction)");
  });

  it("3.2 it resolves the grant from the same two durable tables", () => {
    expect(controlPlaneAdapters).toContain("FROM tenant_role_bindings");
    expect(controlPlaneAdapters).toContain("JOIN roles ON roles.id = tenant_role_bindings.role_id");
  });

  it("3.3 RECORDED: it does not require the permission to be DECLARED", () => {
    // `apps/control-plane/src/adapters.ts` states the reason in prose — it
    // treats `permissions` as a human-facing catalogue rather than a gate. The
    // other three Workers reproduce Rust's `list_permissions()` step, so §1.4
    // passes there and would NOT pass here. Recorded rather than fixed: the
    // difference only ever DENIES less, it predates this fix, and changing an
    // admin plane's authorization semantics is a decision with its own blast
    // radius. Closing it turns this assertion red, which is the point.
    expect(controlPlaneAdapters).not.toContain("FROM permissions WHERE key");
  });

  it("3.4 RECORDED: a role wildcard IS a grant there, and is not fleet-wide", () => {
    // `granted.has("*")` — a catch-all role grants every action on the control
    // plane and nothing extra on the other three (§1.5).
    expect(controlPlaneAdapters).toContain('granted.has("*")');
  });

  it("3.5 RECORDED: every denial is named `guardrail_rbac_denied` there", () => {
    // The other three derive the code from the action's domain (§1.8), so a
    // non-guardrail action denies as `rbac_denied` on them and as
    // `guardrail_rbac_denied` on the control plane. Harmless today — the only
    // rbac-guarded operations in the contract are guardrail ones, so the two
    // spellings coincide — and a real divergence the day that changes.
    expect(controlPlaneAdapters).not.toContain("rbacDenialCode");
    expect(controlPlaneAdapters).toContain('code: "guardrail_rbac_denied"');
  });
});

// ---------------------------------------------------------------------------
// §4  THE CROSS-APP IMPORTS ARE SOUND — the two rbac modules are LEAVES
// ---------------------------------------------------------------------------

describe("§4 the imported authorizers pull no foreign module graph", () => {
  it("both rbac.ts modules import nothing but a TYPE", () => {
    // What makes importing another Worker's module from a test legitimate at
    // all (`apps/mcp/test/drain-fleet.test.ts` §"the cross-app drain modules
    // stay leaves"). A value import here would drag that Worker's ports, its
    // storage package and its bindings into this bundle — and would mean the
    // authorizer this file exercises is not the small, self-contained thing its
    // own Worker mounts.
    for (const [name, source] of [
      ["apps/mcp/src/rbac.ts", mcpRbacSource],
      ["apps/agent-runtime/src/rbac.ts", agentRbacSource],
    ] as const) {
      const imports = [...source.matchAll(/^import\s+(.*)$/gm)].map((m) => m[1] as string);
      expect(imports.length, `${name} has no imports at all — the probe went stale`).toBe(1);
      expect(imports[0], `${name} gained a runtime import`).toMatch(/^type\s/);
    }
  });

  it("both ship the SAME two statements the gateway issues", () => {
    // The durable authority, compared as text across the three Workers. A
    // Worker that quietly pointed its walk at a private table would still pass
    // §1 if its rows happened to agree; this is the assertion that does not
    // depend on the seeded state.
    for (const source of [mcpRbacSource, agentRbacSource]) {
      expect(source).toContain("SELECT 1 AS present FROM permissions WHERE key = ?1");
      expect(source).toContain("FROM tenant_role_bindings");
      expect(source).toContain("JOIN roles ON roles.id = tenant_role_bindings.role_id");
    }
  });
});
