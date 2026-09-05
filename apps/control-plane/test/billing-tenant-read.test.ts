import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, operatorKey, tenantKey } from "./harness.js";
import { registerDurableObjectTenant, tenantObjectDb } from "./tenant-object.js";

const TENANT = "tenant_a";
const TENANT_SECRET = "tenant-a-secret";

function eventJson(tenantId: string): string {
  return JSON.stringify({
    request_id: `req_${tenantId}`,
    tenant: { organization_id: tenantId },
    logical_model: "chat",
    provider: "openai",
    provider_model: "gpt-4o-mini",
    cost_usd: 0.25,
  });
}

async function resetBillingState(): Promise<void> {
  // Track A migration 0045 DROPPED the control billing mirror
  // (`billing_events` / `billing_report_outbox` / `billing_ledger`): attributed
  // billing is tenant-object authoritative now, so there is no control copy to
  // reset — only the tenant object below.
  for (const tenantId of [TENANT]) {
    await tenantObjectDb(tenantId).batch([
      tenantObjectDb(tenantId).prepare("DELETE FROM billing_report_outbox"),
      tenantObjectDb(tenantId).prepare("DELETE FROM billing_events"),
      tenantObjectDb(tenantId).prepare("DELETE FROM billing_ledger"),
    ]);
  }
}

beforeAll(applySchema);

describe("billing admin reads use tenant billing authority", () => {
  beforeEach(async () => {
    await resetD1();
    await resetBillingState();
    await registerDurableObjectTenant(TENANT);
    arm({
      store: "d1",
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey(TENANT_SECRET, TENANT)],
    });
    const tenantDb = tenantObjectDb(TENANT);
    await tenantDb.batch([
      tenantDb
        .prepare(
          `INSERT INTO billing_events
             (billing_event_id, tenant_id, request_id, provider_attempt_index, occurred_at_unix, event_json)
           VALUES (?, ?, ?, 0, 1700, ?)`,
        )
        .bind("evt_tenant_a", TENANT, "req_tenant_a", eventJson(TENANT)),
      tenantDb
        .prepare(
          `INSERT INTO billing_report_outbox
             (id, tenant_id, attempts, next_attempt_unix, dead_lettered_at_unix,
              created_at_unix, updated_at_unix, event_json)
           VALUES (?, ?, 4, 1700, 1800, 1700, 1700, ?)`,
        )
        .bind("report_tenant_a", TENANT, eventJson(TENANT)),
    ]);
  });

  it("serves canonical and compatibility metering feeds from the same tenant rows", async () => {
    const canonical = await SELF.fetch(`${BASE}/admin/v1/metering-events`, {
      headers: bearer(TENANT_SECRET),
    });
    const compat = await SELF.fetch(`${BASE}/admin/v1/billing-events`, {
      headers: bearer(TENANT_SECRET),
    });

    expect(canonical.status).toBe(200);
    const canonicalBody = await canonical.json();
    expect(canonicalBody).toEqual(await compat.json());
    expect(canonicalBody as { data: { id: string; tenant_id: string }[] }).toMatchObject({
      data: [{ id: "evt_tenant_a", tenant_id: TENANT }],
    });
  });

  it("serves a tenant dead-letter list from the tenant outbox", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/billing-outbox-dead-letters`, {
      headers: bearer(TENANT_SECRET),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      data: [{ id: "report_tenant_a", tenant_id: TENANT, dead_lettered_at_unix: 1800 }],
    });
  });

  it("lets a platform operator discover the tenant authority row", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/metering-events`, {
      headers: bearer(operatorKey.secret),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      data: [{ id: "evt_tenant_a", tenant_id: TENANT }],
    });
  });

  it("pages the bounded live tenant lookup instead of returning a truncated fleet", async () => {
    const extraTenants = Array.from({ length: 51 }, (_, index) => `tenant_native_${index}`);
    await db().batch(
      extraTenants.map((tenantId) =>
        db()
          .prepare(
            `INSERT INTO tenant_databases
               (tenant_id, binding_name, schema_version, storage_backend,
                provisioning_status, migration_state, provisioned_at_unix, updated_at_unix)
             VALUES (?, 'TENANT_DB_A', 15, 'native_binding', 'ready', 'done', 1, 1)`,
          )
          .bind(tenantId),
      ),
    );

    const first = await SELF.fetch(`${BASE}/admin/v1/metering-events`, {
      headers: bearer(operatorKey.secret),
    });
    expect(first.status).toBe(200);
    expect(await first.json()).toMatchObject({
      tenant_page: { offset: 0, limit: 50, total: 52, has_more: true },
    });

    const second = await SELF.fetch(`${BASE}/admin/v1/metering-events?tenant_offset=50`, {
      headers: bearer(operatorKey.secret),
    });
    expect(second.status).toBe(200);
    expect(await second.json()).toMatchObject({
      tenant_page: { offset: 50, limit: 50, total: 52, has_more: false },
    });
  });

  // Track A hard-cut removed the control billing mirror, and migration 0045
  // DROPPED its tables outright: the cases that asserted the tenant feed MERGES
  // control `billing_events` history, that it FALLS BACK to control rows for an
  // unprovisioned tenant, that a platform replay refuses a DO-vs-control
  // collision, and that a stale control outbox copy is NOT replayed for a
  // durable tenant were exclusively about that mirror. With no control
  // projection left, there is nothing to merge, fall back to, collide with, or
  // replay from — the tenant object is the sole authority — so those cases are
  // removed.
});

// ---------------------------------------------------------------------------
// Server-side narrowing of the billing feed (#967)
// ---------------------------------------------------------------------------

/** One billing event with the dimensions an operator filters on. */
function filterEventJson(input: {
  provider: string;
  model: string;
  status: number;
  group?: string;
}): string {
  return JSON.stringify({
    request_id: "req_filter",
    tenant: { organization_id: TENANT },
    logical_model: input.model,
    provider: input.provider,
    provider_model: `${input.model}-snapshot`,
    status_code: input.status,
    cost_usd: 1,
    ...(input.group === undefined
      ? {}
      : {
          metadata: {
            billing_group_id: input.group,
            billing_multiplier: "2",
            provider_cost_multiplier: "0.5",
            provider_cost_usd: "0.25",
          },
        }),
  });
}

describe("the billing feed narrows on filters instead of shipping everything", () => {
  beforeEach(async () => {
    await resetD1();
    await resetBillingState();
    await registerDurableObjectTenant(TENANT);
    arm({ store: "d1", staticKeys: [operatorKey], nativeKeys: [tenantKey(TENANT_SECRET, TENANT)] });
    const tenantDb = tenantObjectDb(TENANT);
    const insert = (id: string, at: number, json: string) =>
      tenantDb
        .prepare(
          `INSERT INTO billing_events
             (billing_event_id, tenant_id, request_id, provider_attempt_index, occurred_at_unix, event_json)
           VALUES (?, ?, ?, 0, ?, ?)`,
        )
        .bind(id, TENANT, `req_${id}`, at, json);
    await tenantDb.batch([
      insert(
        "evt_openai",
        1000,
        filterEventJson({ provider: "openai", model: "gpt-4o", status: 200, group: "g_std" }),
      ),
      insert(
        "evt_anthropic",
        2000,
        filterEventJson({
          provider: "anthropic",
          model: "claude-4",
          status: 200,
          group: "g_premium",
        }),
      ),
      insert(
        "evt_failed",
        3000,
        filterEventJson({ provider: "openai", model: "gpt-4o", status: 429, group: "g_std" }),
      ),
    ]);
  });

  const read = async (query: string) => {
    const response = await SELF.fetch(`${BASE}/admin/v1/billing-events${query}`, {
      headers: bearer(TENANT_SECRET),
    });
    expect(response.status, await response.clone().text()).toBe(200);
    return (await response.json()) as {
      data: { id: string; metadata?: Record<string, string> }[];
      total: number;
    };
  };

  it("filters by provider", async () => {
    const page = await read("?provider=anthropic");
    expect(page.data.map((e) => e.id)).toEqual(["evt_anthropic"]);
  });

  it("does not expose supplier economics to a tenant", async () => {
    const page = await read("?provider=anthropic");
    expect(page.data[0]?.metadata).toEqual({
      billing_group_id: "g_premium",
      billing_multiplier: "2",
    });
  });

  it("retains supplier economics for a platform operator", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/billing-events?provider=anthropic`, {
      headers: bearer(operatorKey.secret),
    });
    expect(response.status, await response.clone().text()).toBe(200);
    const body = (await response.json()) as {
      data: { metadata?: Record<string, string> }[];
    };
    expect(body.data[0]?.metadata?.provider_cost_multiplier).toBe("0.5");
    expect(body.data[0]?.metadata?.provider_cost_usd).toBe("0.25");
  });

  it("filters by model, accepting either the logical or the provider spelling", async () => {
    expect((await read("?model=claude-4")).data.map((e) => e.id)).toEqual(["evt_anthropic"]);
    expect((await read("?model=claude-4-snapshot")).data.map((e) => e.id)).toEqual([
      "evt_anthropic",
    ]);
  });

  it("filters by status code", async () => {
    expect((await read("?status=429")).data.map((e) => e.id)).toEqual(["evt_failed"]);
  });

  it("filters by billing group", async () => {
    expect((await read("?billing_group_id=g_premium")).data.map((e) => e.id)).toEqual([
      "evt_anthropic",
    ]);
  });

  it("filters by time window, since inclusive and until exclusive", async () => {
    const window = await read("?since=2000&until=3000");
    expect(window.data.map((e) => e.id)).toEqual(["evt_anthropic"]);
  });

  it("combines filters with AND", async () => {
    expect((await read("?provider=openai&status=200")).data.map((e) => e.id)).toEqual([
      "evt_openai",
    ]);
  });

  it("answers an empty page rather than the whole feed when nothing matches", async () => {
    const miss = await read("?provider=zzz-nobody");
    expect(miss.data).toHaveLength(0);
  });
});

describe("an operator can narrow the fleet feed to one tenant", () => {
  beforeEach(async () => {
    await resetD1();
    await resetBillingState();
    await registerDurableObjectTenant(TENANT);
    arm({ store: "d1", staticKeys: [operatorKey], nativeKeys: [tenantKey(TENANT_SECRET, TENANT)] });
    const tenantDb = tenantObjectDb(TENANT);
    await tenantDb
      .prepare(
        `INSERT INTO billing_events
           (billing_event_id, tenant_id, request_id, provider_attempt_index, occurred_at_unix, event_json)
         VALUES (?, ?, ?, 0, 1700, ?)`,
      )
      .bind("evt_only_tenant", TENANT, "req_only", eventJson(TENANT))
      .run();
  });

  it("returns that tenant's rows for ?tenant_id=", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/billing-events?tenant_id=${TENANT}`, {
      headers: bearer(operatorKey.secret),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { data: { id: string; tenant_id: string }[] };
    expect(body.data.map((e) => e.id)).toEqual(["evt_only_tenant"]);
    expect(body.data.every((e) => e.tenant_id === TENANT)).toBe(true);
  });

  it("returns an empty page for a tenant with no billing rows", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/billing-events?tenant_id=t-nobody`, {
      headers: bearer(operatorKey.secret),
    });
    expect(response.status).toBe(200);
    expect((await response.json()) as { data: unknown[] }).toMatchObject({ data: [] });
  });
});
