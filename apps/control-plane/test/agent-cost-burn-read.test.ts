/**
 * `GET /admin/v1/agent-cost-burn` — the durable per-agent runtime cost burn,
 * driven through the exported Worker against REAL per-tenant D1 databases.
 *
 * ## The defect this file pins
 *
 * The wave-15 control-plane certification recorded `admin_agent_cost_burn` as
 * DURABLE-BUT-UNREAD:
 *
 * > this pages an `agent-cost-burn` document collection with no writer; the real
 * > accumulator is the TENANT database's typed `agent_cost_burn` table, upserted
 * > monotonically by `packages/storage/src/d1/monotonic.ts`.
 *
 * So the one operation in the group answered an empty list while the burn it
 * reports on was being recorded, per tenant, in another database. This is a
 * MONEY surface: `accumulated_usd` is what
 * `quota_policies.agent_cost_budget_usd` is compared against, and an operator
 * reading zero burn concludes an agent is not spending. Rust is explicit that
 * an empty answer here must never be fabricated —
 * `crates/ferrogate-gateway/src/server/agent_cost_burn.rs:17`: *"A durable-store
 * failure degrades to an explicit `service_unavailable`, never a fabricated
 * empty list (which would read as 'no burn')"*.
 *
 * ## Parity source
 *
 * `crates/ferrogate-gateway/src/server/agent_cost_burn.rs`
 * (`handle_admin_agent_cost_burn`), which fixes every behaviour asserted below:
 * the `?period=YYYY-MM` resolution (a malformed value falls back to the current
 * month rather than erroring), tenant isolation applied BEFORE pagination, the
 * `AdminList::paginated` envelope, the row projection that deliberately drops
 * `first_seen_unix`, and the 503 on an unreachable store.
 *
 * ## The rule every case here obeys
 *
 * The burn rows are written with RAW SQL into the tenant databases — never
 * through the code under test — because a fixture built with the reader cannot
 * show that the reader reads what is actually in the table. Two DIFFERENT
 * tenant databases are used, so a cross-tenant assertion cannot be satisfied by
 * a router that ignores its argument.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, operatorKey, tenantKey } from "./harness.js";
import {
  TENANT_A,
  TENANT_B,
  TENANT_UNROUTABLE,
  applyTenantSchema,
  registerTenantDatabases,
  resetTenantD1,
  tenantDbA,
  tenantDbB,
} from "./tenant-db.js";

const A_KEY = "key-tenant-a";
const B_KEY = "key-tenant-b";
const UNROUTABLE_KEY = "key-tenant-unrouted";

interface BurnListBody {
  object: string;
  data: Record<string, unknown>[];
  total?: number;
  offset?: number;
  limit?: number;
}

/** The billing period the surface defaults to, derived the way Rust derives it. */
function currentPeriod(): string {
  const now = new Date();
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
}

/** Insert one `agent_cost_burn` row with raw SQL, the way the accumulator does. */
async function seedBurn(
  handle: D1Database,
  row: { tenantId: string; agentKey: string; period: string; usd: number; updatedAt?: number },
): Promise<void> {
  await handle
    .prepare(
      `INSERT INTO agent_cost_burn
         (tenant_id, agent_key, period, accumulated_usd, first_seen_unix, updated_at_unix)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .bind(row.tenantId, row.agentKey, row.period, row.usd, 1, row.updatedAt ?? 2)
    .run();
}

async function readBurn(secret: string, query = ""): Promise<Response> {
  return SELF.fetch(`${BASE}/admin/v1/agent-cost-burn${query}`, { headers: bearer(secret) });
}

async function burnBody(secret: string, query = ""): Promise<BurnListBody> {
  const response = await readBurn(secret, query);
  expect(response.status, await response.clone().text()).toBe(200);
  return (await response.json()) as BurnListBody;
}

beforeAll(async () => {
  await applySchema();
  await applyTenantSchema();
});

/**
 * `resetTenantD1()` clears the hierarchy and money tables; `agent_cost_burn` is
 * cleared here rather than added to that shared helper because three other
 * suites are being written against it concurrently, and a leftover row would be
 * a `UNIQUE constraint` on the next `seedBurn` rather than a silent pass.
 */
async function clearBurn(): Promise<void> {
  for (const handle of [tenantDbA(), tenantDbB()]) {
    await handle.prepare("DELETE FROM agent_cost_burn").run();
  }
}

/** Drop the deliberately-unroutable fixture tenant from the registry. */
async function deregisterUnroutable(): Promise<void> {
  await db()
    .prepare("DELETE FROM tenant_databases WHERE tenant_id = ?")
    .bind(TENANT_UNROUTABLE)
    .run();
}

beforeEach(async () => {
  await resetD1();
  await resetTenantD1();
  await clearBurn();
  await registerTenantDatabases();
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [
      tenantKey(A_KEY, TENANT_A),
      tenantKey(B_KEY, TENANT_B),
      tenantKey(UNROUTABLE_KEY, TENANT_UNROUTABLE),
    ],
    rbac: {},
  });
});

// ---------------------------------------------------------------------------
// The headline defect
// ---------------------------------------------------------------------------

describe("the burn a tenant actually accumulated is what the admin surface reports", () => {
  it("reports the tenant's own rows from the tenant database", async () => {
    const period = currentPeriod();
    await seedBurn(tenantDbA(), {
      tenantId: TENANT_A,
      agentKey: "agent_alpha",
      period,
      usd: 12.5,
    });

    const body = await burnBody(A_KEY);
    expect(body.data).toHaveLength(1);
    expect(body.data[0]).toMatchObject({
      tenant_id: TENANT_A,
      agent_key: "agent_alpha",
      period,
      accumulated_usd: 12.5,
      updated_at_unix: 2,
    });
  });

  /**
   * Rust's `AgentCostBurnRow::from_stored` projects five fields and drops
   * `first_seen_unix` as internal bookkeeping. Surfacing it would put a second,
   * differently-shaped timestamp on a money report.
   */
  it("does not surface first_seen_unix", async () => {
    await seedBurn(tenantDbA(), {
      tenantId: TENANT_A,
      agentKey: "agent_alpha",
      period: currentPeriod(),
      usd: 1,
    });

    const [row] = (await burnBody(A_KEY)).data;
    expect(row).toBeDefined();
    expect(row).not.toHaveProperty("first_seen_unix");
  });

  /** Rust: "biggest accumulated total first". */
  it("orders by accumulated total, biggest first", async () => {
    const period = currentPeriod();
    await seedBurn(tenantDbA(), { tenantId: TENANT_A, agentKey: "small", period, usd: 1 });
    await seedBurn(tenantDbA(), { tenantId: TENANT_A, agentKey: "big", period, usd: 99 });
    await seedBurn(tenantDbA(), { tenantId: TENANT_A, agentKey: "middle", period, usd: 50 });

    expect((await burnBody(A_KEY)).data.map((row) => row.agent_key)).toEqual([
      "big",
      "middle",
      "small",
    ]);
  });
});

// ---------------------------------------------------------------------------
// Tenant isolation, applied BEFORE pagination
// ---------------------------------------------------------------------------

describe("burn is isolated per tenant", () => {
  it("never shows one tenant another tenant's burn", async () => {
    const period = currentPeriod();
    await seedBurn(tenantDbA(), { tenantId: TENANT_A, agentKey: "a_agent", period, usd: 10 });
    await seedBurn(tenantDbB(), { tenantId: TENANT_B, agentKey: "b_agent", period, usd: 20 });

    expect((await burnBody(A_KEY)).data.map((row) => row.agent_key)).toEqual(["a_agent"]);
    expect((await burnBody(B_KEY)).data.map((row) => row.agent_key)).toEqual(["b_agent"]);
  });

  /**
   * Rust isolates BEFORE pagination precisely so a tenant cannot page into
   * another tenant's rows. Windowing first and filtering after would leak the
   * total, and could serve an empty page for a tenant that has rows.
   */
  it("isolates before it paginates, so the total is the tenant's own", async () => {
    const period = currentPeriod();
    await seedBurn(tenantDbA(), { tenantId: TENANT_A, agentKey: "a1", period, usd: 3 });
    await seedBurn(tenantDbA(), { tenantId: TENANT_A, agentKey: "a2", period, usd: 2 });
    await seedBurn(tenantDbB(), { tenantId: TENANT_B, agentKey: "b1", period, usd: 100 });
    await seedBurn(tenantDbB(), { tenantId: TENANT_B, agentKey: "b2", period, usd: 100 });
    await seedBurn(tenantDbB(), { tenantId: TENANT_B, agentKey: "b3", period, usd: 100 });

    const page = await burnBody(A_KEY, "?limit=1");
    expect(page.total).toBe(2);
    expect(page.data.map((row) => row.agent_key)).toEqual(["a1"]);
  });

  /**
   * The platform operator gets the cross-tenant view (Rust `tenant_filter()`
   * answers `None`). Under database-per-tenant that is a fan-out over the
   * `tenant_databases` registry, so the unroutable fixture tenant is
   * deregistered here — the operator's behaviour when one tenant is unreachable
   * is asserted on its own, below.
   */
  it("gives the platform operator the cross-tenant view", async () => {
    await deregisterUnroutable();
    const period = currentPeriod();
    await seedBurn(tenantDbA(), { tenantId: TENANT_A, agentKey: "a_agent", period, usd: 10 });
    await seedBurn(tenantDbB(), { tenantId: TENANT_B, agentKey: "b_agent", period, usd: 20 });

    const body = await burnBody(operatorKey.secret);
    // Sorted by accumulated total across BOTH databases, biggest first.
    expect(body.data.map((row) => row.agent_key)).toEqual(["b_agent", "a_agent"]);
    expect(body.data.map((row) => row.tenant_id)).toEqual([TENANT_B, TENANT_A]);
    expect(body.total).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// The billing period
// ---------------------------------------------------------------------------

describe("the ?period window", () => {
  it("defaults to the current billing month and excludes other months", async () => {
    await seedBurn(tenantDbA(), {
      tenantId: TENANT_A,
      agentKey: "this_month",
      period: currentPeriod(),
      usd: 5,
    });
    await seedBurn(tenantDbA(), {
      tenantId: TENANT_A,
      agentKey: "last_year",
      period: "2001-01",
      usd: 500,
    });

    expect((await burnBody(A_KEY)).data.map((row) => row.agent_key)).toEqual(["this_month"]);
  });

  it("honours an explicit well-formed ?period", async () => {
    await seedBurn(tenantDbA(), {
      tenantId: TENANT_A,
      agentKey: "last_year",
      period: "2001-01",
      usd: 500,
    });

    expect((await burnBody(A_KEY, "?period=2001-01")).data.map((row) => row.agent_key)).toEqual([
      "last_year",
    ]);
  });

  /**
   * Rust `resolve_agent_cost_burn_period`: a blank or garbage `period` is
   * IGNORED in favour of the current month rather than answering an error, "so
   * the surface stays usable without a param".
   */
  it("falls back to the current month for a malformed ?period, rather than erroring", async () => {
    await seedBurn(tenantDbA(), {
      tenantId: TENANT_A,
      agentKey: "this_month",
      period: currentPeriod(),
      usd: 5,
    });

    for (const bad of ["?period=", "?period=nonsense", "?period=2001-13", "?period=20011"]) {
      const body = await burnBody(A_KEY, bad);
      expect(
        body.data.map((row) => row.agent_key),
        bad,
      ).toEqual(["this_month"]);
    }
  });
});

// ---------------------------------------------------------------------------
// Never fake a zero
// ---------------------------------------------------------------------------

describe("an unreachable store is a refusal, not an empty list", () => {
  /**
   * `TENANT_UNROUTABLE` is registered in `tenant_databases` naming a binding
   * this Worker does not have — "an operator asked for per-tenant isolation and
   * the deployment cannot deliver it". Answering `{"data":[]}` there reads as
   * "this agent has spent nothing", which is the specific lie AGENTS.md's
   * "never fake a zero" rule and Rust's `AgentCostBurnOutcome::Unavailable`
   * exist to prevent.
   */
  it("answers 503 for a tenant whose database this deployment cannot reach", async () => {
    const response = await readBurn(UNROUTABLE_KEY);
    expect(response.status).toBe(503);
    const body = (await response.json()) as { error: { code: string } };
    expect(body.error.code).toBe("tenant_database_unavailable");
  });

  /**
   * The cross-tenant view is a FAN-OUT, so it has a failure mode Rust's single
   * store did not: one unreachable tenant would silently drop that tenant's
   * spend out of a fleet-wide money total. A partial total is worse than no
   * total — an operator cannot tell it is partial — so the whole read refuses.
   */
  it("refuses the whole cross-tenant view when ANY registered tenant is unreachable", async () => {
    await seedBurn(tenantDbA(), {
      tenantId: TENANT_A,
      agentKey: "a_agent",
      period: currentPeriod(),
      usd: 10,
    });

    // The reachable tenant has rows, so a 200 here would be a plausible-looking
    // total that is missing `tenant_unrouted` entirely.
    const response = await readBurn(operatorKey.secret);
    expect(response.status).toBe(503);
    const body = (await response.json()) as { error: { code: string } };
    expect(body.error.code).toBe("tenant_database_unavailable");
  });

  /**
   * A tenant with no registry row at all is a different state: nothing has been
   * provisioned, so there are genuinely no rows. That is an empty list, and
   * distinguishing it from the case above is the whole point of
   * `store/tenancy.ts`'s `not_found` / `runtime` split.
   */
  it("answers an empty list for a tenant with no provisioned database", async () => {
    arm({
      store: "d1",
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey("key-unprovisioned", "tenant_never_seen")],
      rbac: {},
    });

    const body = await burnBody("key-unprovisioned");
    expect(body.data).toEqual([]);
    expect(body.total).toBe(0);
  });
});
