/**
 * `D1TenancyLifecycleGate` — the full tenant → project → workspace `status`
 * walk (Rust `ferrogate-storage/src/lifecycle_gate.rs`, issue #514).
 *
 * Run against the REAL `DB` and `CONTROL_DB` bindings `wrangler.toml` declares
 * and the REAL `projects` / `workspaces` / `tenants` DDL from
 * `sql/d1-ts/{tenant,control}/0001_init_*.sql` (applied by `test/setup-d1.ts`).
 * Nothing here doubles the database — the outage tests substitute a THROWING
 * row source, which is the one thing a live binding cannot be asked to do, and
 * which Rust says outright no test held when the gate first landed.
 *
 * Four halves, each proving something the others cannot:
 *
 *  - the PURE decision table (`checkLifecycleChain` + the seam predicates);
 *  - the WALK (`resolveLifecycleChain`), including the headline #514 defect: a
 *    credential that declares only a project must still be stopped by the
 *    suspended TENANT above it, which a three-independent-lookups
 *    implementation never reads;
 *  - the DURABLE row source against real D1;
 *  - the MOUNT, driven through `SELF.fetch` — i.e. through `depsFromEnv` on the
 *    app `src/index.ts` exports. A gate that is written, tested and never
 *    reached by `depsFromEnv` is the defect class this repo has already shipped
 *    three times, so the mount gets its own assertion that fails when the
 *    wiring is removed.
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  ConfiguredTenancyLifecycleGate,
  D1LifecycleRowSource,
  D1TenancyLifecycleGate,
  LIFECYCLE_RECOVERY_OPERATIONS,
  type LifecycleRef,
  type LifecycleRowSource,
  checkLifecycleChain,
  denyIfEitherDenies,
  depsFromEnv,
  lifecycleSeamFor,
  resolveLifecycleChain,
} from "../src/adapters.js";
import { type ApiOperation, operationById } from "../src/contract.js";
import type { AuthContext, GatewayBindings, LifecycleDecision } from "../src/ports.js";
import { createGatewayApp } from "../src/routes/index.js";
import { seedApiKey, testSecret } from "./keys/seed.js";
import { seedTenantRosterRows } from "./tenant-object.js";

const BASE = "https://gateway.test";
const bindings = env as unknown as Record<string, unknown>;

function db(name: "DB" | "CONTROL_DB"): D1Database {
  const binding = bindings[name] as D1Database | undefined;
  if (binding === undefined) {
    // Loud, never a silent skip: `wrangler.toml` declares both, so an absent
    // binding means the declaration was removed and this suite is about to
    // prove something other than what it claims.
    throw new Error(
      `lifecycle tests expect the \`${name}\` D1 binding (apps/gateway/wrangler.toml). See src/adapters.ts for why the chain reads BOTH databases.`,
    );
  }
  return binding;
}

async function seedTenant(id: string, status: string): Promise<void> {
  await db("CONTROL_DB")
    .prepare("INSERT OR REPLACE INTO tenants (id, name, slug, status) VALUES (?1, ?1, ?1, ?2)")
    .bind(id, status)
    .run();
}

async function seedProject(id: string, tenantId: string, status: string): Promise<void> {
  await db("DB")
    .prepare(
      "INSERT OR REPLACE INTO projects (id, tenant_id, name, slug, status) " +
        "VALUES (?1, ?2, ?1, ?1, ?3)",
    )
    .bind(id, tenantId, status)
    .run();
}

async function seedWorkspace(
  id: string,
  projectId: string,
  tenantId: string,
  status: string,
): Promise<void> {
  await db("DB")
    .prepare(
      "INSERT OR REPLACE INTO workspaces (id, project_id, tenant_id, name, slug, status) " +
        "VALUES (?1, ?2, ?3, ?1, ?1, ?4)",
    )
    .bind(id, projectId, tenantId, status)
    .run();
}

async function clearRows(): Promise<void> {
  await db("DB").exec("DELETE FROM workspaces");
  await db("DB").exec("DELETE FROM projects");
  await db("DB").exec("DELETE FROM api_keys");
  await db("CONTROL_DB").exec("DELETE FROM tenants");
}

beforeEach(async () => {
  await clearRows();
  // `tenant_chain` is not a vitest.config fixture tenant, so `test/setup-d1.ts`
  // seeds no `tenant_databases` roster row for it — and a request the lifecycle
  // gate ADMITS then 503s downstream when the backend-dispatching router cannot
  // place the tenant. (Roster rows survive `clearRows`, which touches only
  // workspaces/projects/api_keys/tenants.)
  await seedTenantRosterRows(["tenant_chain"]);
});
afterEach(clearRows);

function auth(tenancy: Partial<AuthContext["tenancy"]>): AuthContext {
  return {
    subject: "key_x",
    tenancy: {
      tenantId: null,
      projectId: null,
      workspaceId: null,
      userId: null,
      ...tenancy,
    },
    scopes: ["*"],
    platformOperator: false,
    source: "durable_native",
  };
}

const OPERATOR: AuthContext = {
  subject: "key_root",
  tenancy: { tenantId: null, projectId: null, workspaceId: null, userId: null },
  scopes: ["*"],
  platformOperator: true,
  source: "static_config",
};

/**
 * The matched contract operation the guard hands the gate — read from the
 * COMMITTED contract, never hand-built, and asserted to be the path/method the
 * Rust handler arm served. An operation id that stops existing (or moves to a
 * different method) fails here rather than silently making a seam unreachable.
 */
function operation(operationId: string, path: string, method: string): ApiOperation {
  const matched = operationById(operationId);
  if (matched === undefined) {
    throw new Error(`runtime API contract has no operation ${operationId}`);
  }
  if (matched.path !== path || matched.method !== method) {
    throw new Error(
      `${operationId} is ${matched.method} ${matched.path}, expected ${method} ${path}`,
    );
  }
  return matched;
}

const ref = (
  kind: LifecycleRef["kind"],
  id: string,
  status: LifecycleRef["status"],
): LifecycleRef => ({ kind, id, status });

// ---------------------------------------------------------------------------
// 1. The pure decision table — Rust `check_lifecycle_chain` + `LifecycleSeam`
// ---------------------------------------------------------------------------

describe("check_lifecycle_chain", () => {
  it("admits an all-active chain", () => {
    expect(
      checkLifecycleChain("request", [
        ref("tenant", "t", "active"),
        ref("project", "p", "active"),
        ref("workspace", "w", "active"),
      ]),
    ).toEqual({ admitted: true });
  });

  it.each([
    ["suspended", "tenancy_suspended"],
    ["disabled", "tenancy_disabled"],
    ["deleted", "tenancy_deleted"],
  ] as const)("refuses a %s row with %s at the request seam", (status, code) => {
    const decision = checkLifecycleChain("request", [ref("project", "p_1", status)]);
    expect(decision).toEqual({
      admitted: false,
      code,
      message: `project p_1 is ${status}; requests authenticated against this tenancy chain are refused`,
    });
  });

  it("names the ROOT cause, not the deepest row, when a cascade marks all three", () => {
    // An operator suspends a tenant; the cascade marks its project and
    // workspace too. Telling the caller about the workspace would send them
    // chasing the wrong row — so the chain is walked shallowest-first.
    const decision = checkLifecycleChain("request", [
      ref("tenant", "t_root", "suspended"),
      ref("project", "p_child", "suspended"),
      ref("workspace", "w_leaf", "suspended"),
    ]);
    expect(decision).toMatchObject({ admitted: false, code: "tenancy_suspended" });
    expect((decision as { message: string }).message).toContain("tenant t_root");
    expect((decision as { message: string }).message).not.toContain("w_leaf");
  });

  it("empty chain admits — absence is not suspension", () => {
    expect(checkLifecycleChain("request", [])).toEqual({ admitted: true });
  });
});

describe("the recovery seam is `disabled` and NOTHING else", () => {
  it("admits `disabled` so the tenant's own off switch is not a one-way door", () => {
    expect(checkLifecycleChain("recovery", [ref("project", "p", "disabled")])).toEqual({
      admitted: true,
    });
    // …and the same row still denies every ordinary route, which is the whole
    // point of the switch: a disabled project must not keep serving inference.
    expect(checkLifecycleChain("request", [ref("project", "p", "disabled")])).toMatchObject({
      admitted: false,
      code: "tenancy_disabled",
    });
  });

  it.each(["suspended", "deleted"] as const)(
    "still refuses %s — reversing a platform-operator action is a platform-operator job",
    (status) => {
      expect(checkLifecycleChain("recovery", [ref("tenant", "t", status)])).toMatchObject({
        admitted: false,
      });
    },
  );
});

describe("lifecycleSeamFor — which contract operations run the recovery seam", () => {
  it.each([
    ["replaceProject", "/admin/v1/projects/{project_id}", "PUT"],
    ["updateProject", "/admin/v1/projects/{project_id}", "PATCH"],
    ["replaceWorkspace", "/admin/v1/workspaces/{workspace_id}", "PUT"],
    ["updateWorkspace", "/admin/v1/workspaces/{workspace_id}", "PATCH"],
  ])("%s is recovery", (operationId, path, method) => {
    expect(lifecycleSeamFor(operation(operationId, path, method))).toBe("recovery");
  });

  it.each([
    ["getProject", "/admin/v1/projects/{project_id}", "GET"],
    ["deleteProject", "/admin/v1/projects/{project_id}", "DELETE"],
    ["createProject", "/admin/v1/projects", "POST"],
    ["getWorkspace", "/admin/v1/workspaces/{workspace_id}", "GET"],
  ])("%s is the ordinary request seam", (operationId, path, method) => {
    expect(lifecycleSeamFor(operation(operationId, path, method))).toBe("request");
  });

  it("an unmatched operation is the request seam — the strict one", () => {
    expect(lifecycleSeamFor(undefined)).toBe("request");
  });

  it("every id in the recovery set is a real PUT/PATCH contract operation", () => {
    // Guards against the set drifting into naming an operation that does not
    // exist, which would silently make the carve-out unreachable.
    expect(LIFECYCLE_RECOVERY_OPERATIONS.size).toBe(4);
    for (const operationId of LIFECYCLE_RECOVERY_OPERATIONS) {
      const matched = operationById(operationId);
      expect(matched, `${operationId} is not a contract operation`).toBeDefined();
      expect(["PUT", "PATCH"]).toContain(matched?.method);
    }
  });
});

// ---------------------------------------------------------------------------
// 2. The WALK — Rust `resolve_lifecycle_chain`
// ---------------------------------------------------------------------------

/** An in-memory row source, so the walk is tested without D1 in the way. */
function rowSource(rows: {
  tenants?: Record<string, { status: string }>;
  projects?: Record<string, { status: string; tenant_id?: string }>;
  workspaces?: Record<string, { status: string; tenant_id?: string; project_id?: string }>;
}): LifecycleRowSource & { reads: string[] } {
  const reads: string[] = [];
  return {
    reads,
    async tenantRow(id) {
      reads.push(`tenant:${id}`);
      const row = rows.tenants?.[id];
      return row === undefined ? null : { id, status: row.status };
    },
    async projectRow(id) {
      reads.push(`project:${id}`);
      const row = rows.projects?.[id];
      return row === undefined
        ? null
        : { id, status: row.status, tenant_id: row.tenant_id ?? null };
    },
    async workspaceRow(id) {
      reads.push(`workspace:${id}`);
      const row = rows.workspaces?.[id];
      return row === undefined
        ? null
        : {
            id,
            status: row.status,
            tenant_id: row.tenant_id ?? null,
            project_id: row.project_id ?? null,
          };
    },
  };
}

describe("resolve_lifecycle_chain walks the HIERARCHY, not the declaration", () => {
  it("a credential that declares ONLY a project is still stopped by its suspended tenant", async () => {
    // THE #514 headline defect, reproduced as a test. Three independent
    // lookups that push only the rows the caller NAMED would produce
    // `[project(active)]` here and admit the request — i.e. suspending a tenant
    // would not stop its projects' keys.
    const source = rowSource({
      tenants: { t_owner: { status: "suspended" } },
      projects: { p_1: { status: "active", tenant_id: "t_owner" } },
    });
    const chain = await resolveLifecycleChain(source, { projectId: "p_1" });
    expect(chain).toEqual([
      { kind: "tenant", id: "t_owner", status: "suspended" },
      { kind: "project", id: "p_1", status: "active" },
    ]);
    expect(checkLifecycleChain("request", chain)).toMatchObject({
      admitted: false,
      code: "tenancy_suspended",
    });
  });

  it("a workspace-only declaration backfills BOTH ancestors", async () => {
    const source = rowSource({
      tenants: { t_owner: { status: "active" } },
      projects: { p_1: { status: "suspended", tenant_id: "t_owner" } },
      workspaces: { w_1: { status: "active", project_id: "p_1", tenant_id: "t_owner" } },
    });
    const chain = await resolveLifecycleChain(source, { workspaceId: "w_1" });
    expect(chain.map((entry) => `${entry.kind}:${entry.id}`)).toEqual([
      "tenant:t_owner",
      "project:p_1",
      "workspace:w_1",
    ]);
    expect(checkLifecycleChain("request", chain)).toMatchObject({ code: "tenancy_suspended" });
  });

  it("UNIONs declared and derived ids — a disagreeing declaration cannot skip the real parent", async () => {
    const source = rowSource({
      tenants: { t_declared: { status: "active" }, t_real: { status: "suspended" } },
      projects: { p_1: { status: "active", tenant_id: "t_real" } },
    });
    const chain = await resolveLifecycleChain(source, {
      tenantId: "t_declared",
      projectId: "p_1",
    });
    expect(chain.map((entry) => entry.id)).toEqual(["t_declared", "t_real", "p_1"]);
    expect(checkLifecycleChain("request", chain)).toMatchObject({ admitted: false });
  });

  it("dedupes a fully declared, self-consistent triple to exactly three reads", async () => {
    const source = rowSource({
      tenants: { t: { status: "active" } },
      projects: { p: { status: "active", tenant_id: "t" } },
      workspaces: { w: { status: "active", project_id: "p", tenant_id: "t" } },
    });
    await resolveLifecycleChain(source, { tenantId: "t", projectId: "p", workspaceId: "w" });
    expect(source.reads).toEqual(["workspace:w", "project:p", "tenant:t"]);
  });

  it("an id that names no row is skipped — a typo is not a suspension", async () => {
    const source = rowSource({});
    expect(
      await resolveLifecycleChain(source, {
        tenantId: "ghost",
        projectId: "ghost",
        workspaceId: "ghost",
      }),
    ).toEqual([]);
  });

  it("blank and whitespace ids are absent, and cost no read at all", async () => {
    const source = rowSource({ tenants: { "": { status: "suspended" } } });
    expect(await resolveLifecycleChain(source, { tenantId: "   ", projectId: "" })).toEqual([]);
    expect(source.reads).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 3. The gate, including the fail-CLOSED outage arm
// ---------------------------------------------------------------------------

describe("D1TenancyLifecycleGate", () => {
  const requestOp = operation("getProject", "/admin/v1/projects/{project_id}", "GET");

  it("waves a platform operator through without a single query", async () => {
    const source = rowSource({ tenants: { t: { status: "suspended" } } });
    const gate = new D1TenancyLifecycleGate(source);
    expect(await gate.admit(OPERATOR, requestOp)).toEqual({ admitted: true });
    expect(source.reads).toEqual([]);
  });

  it("refuses on a suspended ancestor discovered by the walk", async () => {
    const gate = new D1TenancyLifecycleGate(
      rowSource({
        tenants: { t_owner: { status: "suspended" } },
        projects: { p_1: { status: "active", tenant_id: "t_owner" } },
      }),
    );
    expect(await gate.admit(auth({ projectId: "p_1" }), requestOp)).toMatchObject({
      admitted: false,
      code: "tenancy_suspended",
    });
  });

  it("a FAILING lookup is `unavailable` (503), never an admission", async () => {
    // Rust states the reason at the enum: fail-open here would hand every
    // suspended tenant a trivial bypass — make the control plane flap and keep
    // serving. `admitted` is the string "unavailable", which is TRUTHY, so the
    // call site must test it before `!admitted`; `test/auth` drives that.
    const exploding: LifecycleRowSource = {
      async tenantRow() {
        throw new Error("D1_ERROR: no such table: tenants");
      },
      async projectRow() {
        return null;
      },
      async workspaceRow() {
        return null;
      },
    };
    const decision = await new D1TenancyLifecycleGate(exploding).admit(
      auth({ tenantId: "t" }),
      requestOp,
    );
    expect(decision).toEqual({
      admitted: "unavailable",
      detail: "D1_ERROR: no such table: tenants",
    });
    expect(decision.admitted).not.toBe(true);
  });

  it("honours the recovery seam for a lifecycle-reversal operation", async () => {
    const gate = new D1TenancyLifecycleGate(
      rowSource({ projects: { p_1: { status: "disabled" } } }),
    );
    const caller = auth({ projectId: "p_1" });
    expect(
      await gate.admit(
        caller,
        operation("replaceProject", "/admin/v1/projects/{project_id}", "PUT"),
      ),
    ).toEqual({ admitted: true });
    expect(
      await gate.admit(caller, operation("getProject", "/admin/v1/projects/{project_id}", "GET")),
    ).toMatchObject({ admitted: false, code: "tenancy_disabled" });
  });

  it("is `null` from an env with neither database bound", () => {
    expect(D1TenancyLifecycleGate.fromEnv({})).toBeNull();
    expect(D1TenancyLifecycleGate.fromEnv({ DB: {} })).toBeNull();
    expect(D1TenancyLifecycleGate.fromEnv({ CONTROL_DATA: bindings.CONTROL_DATA })).not.toBeNull();
  });
});

describe("D1LifecycleRowSource reads the two REAL databases", () => {
  it("finds `tenants` in CONTROL and `projects`/`workspaces` in TENANT", async () => {
    await seedTenant("t_live", "suspended");
    await seedProject("p_live", "t_live", "active");
    await seedWorkspace("w_live", "p_live", "t_live", "active");

    const source = new D1LifecycleRowSource(db("CONTROL_DB"), db("DB"));
    const chain = await resolveLifecycleChain(source, { workspaceId: "w_live" });

    expect(chain).toEqual([
      { kind: "tenant", id: "t_live", status: "suspended" },
      { kind: "project", id: "p_live", status: "active" },
      { kind: "workspace", id: "w_live", status: "active" },
    ]);
  });

  it("reads a legacy/unrecognized status as active (the #514 fail-OPEN read default)", async () => {
    // These columns were decorative before #514, so pre-existing rows carry
    // arbitrary values; failing closed on them would revoke every existing
    // tenant's traffic. Denial is opt-in.
    await seedProject("p_legacy", "t", "PROVISIONING");
    const chain = await resolveLifecycleChain(
      new D1LifecycleRowSource(db("CONTROL_DB"), db("DB")),
      { projectId: "p_legacy" },
    );
    expect(chain).toEqual([{ kind: "project", id: "p_legacy", status: "active" }]);
  });
});

// ---------------------------------------------------------------------------
// 4. Composition — a DENY table must not compose like a GRANT table
// ---------------------------------------------------------------------------

describe("denyIfEitherDenies", () => {
  const requestOp = operation("getProject", "/admin/v1/projects/{project_id}", "GET");
  const admits: { admit(): Promise<LifecycleDecision> } = {
    async admit() {
      return { admitted: true };
    },
  };
  const denies = {
    async admit(): Promise<LifecycleDecision> {
      return { admitted: false, code: "tenancy_suspended", message: "denied" };
    },
  };

  it("a refusal from the SECOND gate still refuses, even when the first admitted", async () => {
    // This is the whole reason it is not a `durable ?? fallback`: the var table
    // is the operator's kill switch, and a durable "active" must not disarm it.
    const composed = denyIfEitherDenies(admits, denies);
    expect(await composed.admit(auth({ tenantId: "t" }), requestOp)).toMatchObject({
      admitted: false,
    });
  });

  it("an outage from the first gate short-circuits and is NOT recovered by the second", async () => {
    const unavailable = {
      async admit(): Promise<LifecycleDecision> {
        return { admitted: "unavailable", detail: "boom" };
      },
    };
    expect(await denyIfEitherDenies(unavailable, admits).admit(auth({}), requestOp)).toEqual({
      admitted: "unavailable",
      detail: "boom",
    });
  });
});

describe("ConfiguredTenancyLifecycleGate keeps its var-table behaviour", () => {
  const requestOp = operation("getProject", "/admin/v1/projects/{project_id}", "GET");

  it("refuses the tenant named suspended in TENANCY_LIFECYCLE", async () => {
    const gate = new ConfiguredTenancyLifecycleGate({ tenant_b: "suspended" });
    expect(await gate.admit(auth({ tenantId: "tenant_b" }), requestOp)).toMatchObject({
      admitted: false,
      code: "tenancy_suspended",
    });
    expect(await gate.admit(auth({ tenantId: "tenant_a" }), requestOp)).toEqual({ admitted: true });
  });

  it("honours the recovery seam too", async () => {
    const gate = new ConfiguredTenancyLifecycleGate({ tenant_c: "disabled" });
    expect(
      await gate.admit(
        auth({ tenantId: "tenant_c" }),
        operation("updateProject", "/admin/v1/projects/{project_id}", "PATCH"),
      ),
    ).toEqual({ admitted: true });
  });
});

// ---------------------------------------------------------------------------
// 5. The MOUNT — through the app `src/index.ts` exports
// ---------------------------------------------------------------------------

describe("an UNAVAILABLE lifecycle lookup is 503 at the HTTP boundary", () => {
  /**
   * The truthy-string trap, held at the guard rather than at the gate.
   *
   * `admitted: "unavailable"` is TRUTHY, so a call site that tests `!admitted`
   * first reads an outage as an ADMISSION — the exact fail-open Rust names as a
   * suspension bypass ("make the control plane flap and keep serving"). Driven
   * through the real `createGatewayApp`, so `contractAuth` runs exactly as it
   * does in the Worker; the MOUNT of the durable gate itself is proven below.
   */
  function appWithLifecycle(gate: {
    admit(): Promise<LifecycleDecision>;
  }): (token: string) => Promise<Response> {
    const { app } = createGatewayApp({
      deps: (workerEnv) => ({ ...depsFromEnv(workerEnv), lifecycle: gate }),
    });
    return async (token: string) =>
      await app.request(
        `${BASE}/v1/tools`,
        { headers: { authorization: `Bearer ${token}` } },
        env as unknown as Record<string, unknown>,
      );
  }

  it("503 lifecycle_status_unavailable, never a silent admission", async () => {
    const call = appWithLifecycle({
      async admit() {
        return { admitted: "unavailable", detail: "D1_ERROR: no such table: tenants" };
      },
    });
    const res = await call("fg_tenant_tools");
    expect(res.status).toBe(503);
    expect(await res.json()).toMatchObject({
      error: {
        code: "lifecycle_status_unavailable",
        message: "tenancy lifecycle lookup failed: D1_ERROR: no such table: tenants",
      },
    });
  });

  it("CONTROL: the same credential with an admitting gate reaches the route", async () => {
    const call = appWithLifecycle({
      async admit() {
        return { admitted: true };
      },
    });
    expect((await call("fg_tenant_tools")).status).toBe(501);
  });
});

describe("the durable chain gate is MOUNTED on the exported Worker", () => {
  it("depsFromEnv composes the durable leg with the config leg", async () => {
    // Constructed from the REAL bindings, so this fails if `depsFromEnv` drops
    // `D1TenancyLifecycleGate` — no bespoke app, no injected port.
    await seedProject("p_mounted", "t_mounted", "suspended");
    const deps = depsFromEnv(env as unknown as GatewayBindings);
    const decision = await deps.lifecycle.admit(
      auth({ tenantId: "t_mounted", projectId: "p_mounted" }),
      operation("getProject", "/admin/v1/projects/{project_id}", "GET"),
    );
    expect(decision).toMatchObject({ admitted: false, code: "tenancy_suspended" });
  });

  it("403s a real request whose PROJECT is suspended while its tenant is active", async () => {
    // The end-to-end shape of the gap this closes: before the chain walk this
    // request was ADMITTED, because only the tenant tier was read.
    await seedTenant("tenant_chain", "active");
    await seedProject("project_chain", "tenant_chain", "suspended");
    const secret = testSecret("lifecycle-chain-suspended");
    await seedApiKey({
      id: "key_chain_suspended",
      secret,
      tenantId: "tenant_chain",
      projectId: "project_chain",
      workspaceId: "workspace_chain",
      scopes: ["tools.read"],
    });

    const res = await SELF.fetch(`${BASE}/v1/tools`, {
      headers: { Authorization: `Bearer ${secret}` },
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({
      error: { code: "tenancy_suspended", message: expect.stringContaining("project_chain") },
    });
  });

  it("CONTROL: the same credential under an ACTIVE project reaches the route", async () => {
    // Without this arm "403" would prove nothing — every unauthenticated or
    // misrouted request is also not-a-200.
    await seedTenant("tenant_chain", "active");
    await seedProject("project_chain", "tenant_chain", "active");
    const secret = testSecret("lifecycle-chain-active");
    await seedApiKey({
      id: "key_chain_active",
      secret,
      tenantId: "tenant_chain",
      projectId: "project_chain",
      workspaceId: "workspace_chain",
      scopes: ["tools.read"],
    });

    const res = await SELF.fetch(`${BASE}/v1/tools`, {
      headers: { Authorization: `Bearer ${secret}` },
    });
    // 501 is `listTools`'s standing PORT-TODO answer — the point is that the
    // request got PAST the lifecycle gate.
    expect(res.status).toBe(501);
  });

  it("a suspended WORKSPACE is caught even though no id but the workspace is inactive", async () => {
    await seedTenant("tenant_chain", "active");
    await seedProject("project_chain", "tenant_chain", "active");
    await seedWorkspace("workspace_chain", "project_chain", "tenant_chain", "deleted");
    const secret = testSecret("lifecycle-chain-workspace");
    await seedApiKey({
      id: "key_chain_workspace",
      secret,
      tenantId: "tenant_chain",
      projectId: "project_chain",
      workspaceId: "workspace_chain",
      scopes: ["tools.read"],
    });

    const res = await SELF.fetch(`${BASE}/v1/tools`, {
      headers: { Authorization: `Bearer ${secret}` },
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: { code: "tenancy_deleted" } });
  });
});
