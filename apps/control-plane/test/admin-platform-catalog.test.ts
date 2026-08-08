/**
 * The platform default model catalog over the admin surface (#889).
 *
 * These tests drive the SAME operation ids the tenant catalog uses and then
 * read the platform tables with RAW SQL — through `env.DB` on the `d1_compat`
 * leg and through the CONTROL_DATA facade on the `durable_object` leg. Reading
 * back through `PlatformModelCatalogStore` would prove only that the store
 * agrees with itself, which is this repo's dominant defect mode.
 *
 * The fence is asserted in BOTH directions: a tenant-scoped write must leave
 * the platform tables empty, and a platform write must leave the tenant
 * database empty. One direction alone passes against a store that writes
 * everything to one place.
 */
import { SELF, env } from "cloudflare:test";
import { controlDataObjectDatabase } from "@ferrogate/storage";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { resolveTenantStorage } from "../src/adapters.js";
import type { ControlPlaneBindings } from "../src/ports.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";
import { applyTenantSchema } from "./tenant-db.js";

const OPERATOR = operatorKey.secret;

/** The posture `wrangler.toml` pins for this app today; restored after every test. */
const DEFAULT_CONTROL_STORAGE = "durable_object";

interface JsonBody {
  readonly [key: string]: unknown;
}

interface TestResponse {
  readonly status: number;
  readonly body: JsonBody;
}

async function request(
  secret: string,
  method: string,
  path: string,
  body?: unknown,
): Promise<TestResponse> {
  const response = await SELF.fetch(
    `${BASE}${path}`,
    body === undefined || method === "GET" || method === "HEAD"
      ? { method, headers: bearer(secret) }
      : jsonRequest(secret, method, body),
  );
  return { status: response.status, body: (await response.json()) as JsonBody };
}

function controlStorage(mode: string): void {
  (env as unknown as Record<string, string | undefined>).CONTROL_PLANE_CONTROL_STORAGE = mode;
}

/** The CONTROL_DATA facade — the same handle the Worker builds under the DO posture. */
function controlObjectDb(): D1Database {
  return controlDataObjectDatabase(
    (env as unknown as { CONTROL_DATA: Parameters<typeof controlDataObjectDatabase>[0] })
      .CONTROL_DATA,
  );
}

/** Truncate the platform catalog in a database. `resetD1` only knows about `env.DB`. */
async function wipePlatformCatalog(handle: D1Database): Promise<void> {
  await handle.batch([
    handle.prepare("DELETE FROM platform_catalog_offerings"),
    handle.prepare("DELETE FROM platform_catalog_models"),
    handle.prepare("DELETE FROM platform_provider_channels"),
    handle.prepare("DELETE FROM platform_catalog_revisions"),
    handle.prepare("DELETE FROM audit_events"),
  ]);
}

/**
 * Take `env.DB` back to a pre-0025 control database, and hand back the undo.
 *
 * The DDL is read out of `sqlite_master` rather than restated here, so this
 * cannot drift from the migration; `resetD1` in the next `beforeEach` DELETEs
 * from these tables, which is why the undo must run in a `finally`.
 */
async function dropPlatformTables(): Promise<() => Promise<void>> {
  const handle = db();
  const objects = await handle
    .prepare(
      `SELECT type, name, sql FROM sqlite_master
        WHERE sql IS NOT NULL AND tbl_name LIKE 'platform!_%' ESCAPE '!'
        ORDER BY CASE type WHEN 'table' THEN 0 ELSE 1 END, name`,
    )
    .all<{ type: string; name: string; sql: string }>();
  const tables = objects.results.filter((row) => row.type === "table").map((row) => row.name);
  expect(tables.length, "0025 must have created the platform tables").toBe(4);
  expect(objects.results.length, "and its indexes, which the undo must restore").toBeGreaterThan(4);
  // Children before parents: the implicit DELETE a DROP performs is subject to
  // the same `ON DELETE RESTRICT` the offerings carry onto the channels.
  const isChild = (table: string): boolean => table === "platform_catalog_offerings";
  for (const table of [...tables.filter(isChild), ...tables.filter((t) => !isChild(t))]) {
    await handle.exec(`DROP TABLE ${table}`);
  }
  return async () => {
    for (const object of objects.results) {
      await handle.exec(object.sql.replace(/\s+/g, " "));
    }
  };
}

async function platformRevision(handle: D1Database = db()): Promise<number> {
  const row = await handle
    .prepare("SELECT revision FROM platform_catalog_revisions WHERE id = 1")
    .first<{ revision: number | string }>();
  return Number(row?.revision ?? 0);
}

async function platformIds(table: string, handle: D1Database = db()): Promise<readonly string[]> {
  const rows = await handle
    .prepare(`SELECT id FROM ${table} ORDER BY id ASC`)
    .all<{ id: string }>();
  return rows.results.map((row) => row.id);
}

/**
 * Audit rows this catalog wrote, oldest first, read straight out of the chain.
 *
 * Returns the whole tuple, not just the collection: `revision` is the ONLY
 * thing that ties an audit row to the catalog state it describes — it is what
 * #890's seeder and #891's loader key off — and `action` is what tells a remove
 * from a create. Asserting the collection alone left both free to be wrong.
 */
interface PlatformAuditRow {
  readonly collection: string;
  readonly action: string;
  readonly revision: number;
  readonly resource_id: string;
}

async function platformAuditRows(handle: D1Database = db()): Promise<readonly PlatformAuditRow[]> {
  const rows = await handle
    .prepare("SELECT audit_json, tenant FROM audit_events ORDER BY seq ASC")
    .all<{ audit_json: string; tenant: string | null }>();
  const events: PlatformAuditRow[] = [];
  for (const row of rows.results) {
    const parsed = JSON.parse(row.audit_json) as Partial<PlatformAuditRow> & {
      resource_tenant_id?: unknown;
    };
    if (typeof parsed.collection === "string" && parsed.collection.startsWith("platform_")) {
      expect(row.tenant, "a platform catalog audit row must not be tenant-attributed").toBeNull();
      events.push({
        collection: parsed.collection,
        action: String(parsed.action),
        revision: Number(parsed.revision),
        resource_id: String(parsed.resource_id),
      });
    }
  }
  return events;
}

async function platformAuditCollections(handle: D1Database = db()): Promise<readonly string[]> {
  return (await platformAuditRows(handle)).map((row) => row.collection);
}

async function createPlatformProvider(
  id: string,
  overrides: Record<string, unknown> = {},
): Promise<TestResponse> {
  return request(OPERATOR, "POST", "/admin/v1/providers", {
    id,
    name: id,
    kind: "openai-compatible",
    base_url: `https://${id}.example.test/v1`,
    enabled: true,
    ...overrides,
  });
}

async function createPlatformModel(id: string): Promise<TestResponse> {
  return request(OPERATOR, "POST", "/admin/v1/models", {
    id,
    name: `${id}-name`,
    family: "openai",
    capabilities: ["chat"],
    context_window: 128000,
    routing_strategy: "priority",
    enabled: true,
  });
}

async function createPlatformOffering(
  modelId: string,
  id: string,
  providerId: string,
  extra: Record<string, unknown> = {},
): Promise<TestResponse> {
  return request(OPERATOR, "POST", `/admin/v1/models/${modelId}/offerings`, {
    id,
    provider_id: providerId,
    upstream_model_id: `upstream-${id}`,
    role: "primary",
    priority: 0,
    input_price_per_1m: 0.25,
    output_price_per_1m: 0.5,
    ...extra,
  });
}

async function provisionTenant(tenantId: string): Promise<void> {
  const response = await request(OPERATOR, "POST", "/admin/v1/tenant-accounts", {
    id: tenantId,
    name: tenantId,
    slug: tenantId,
  });
  expect(response.status).toBe(201);
}

beforeAll(async () => {
  await applySchema();
  await applyTenantSchema();
});

beforeEach(async () => {
  controlStorage(DEFAULT_CONTROL_STORAGE);
  await resetD1();
  arm({ store: "d1", staticKeys: [operatorKey] });
});

afterEach(() => {
  // A leaked posture poisons every later FILE in this worker, not just this
  // test: `arm()` never touches the variable, so nothing else restores it.
  controlStorage(DEFAULT_CONTROL_STORAGE);
});

describe("platform model catalog admin surface", () => {
  it("round-trips providers, models and offerings for a platform operator with no tenant_id", async () => {
    const created = await createPlatformProvider("platform_channel");
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    expect(created.body.scope).toBe("platform");
    expect((created.body.provider as JsonBody).scope).toBe("platform");
    expect((created.body.provider as JsonBody).tenant_id).toBeUndefined();

    const model = await createPlatformModel("platform_model");
    expect(model.status, JSON.stringify(model.body)).toBe(201);
    expect(model.body.scope).toBe("platform");

    const offering = await createPlatformOffering(
      "platform_model",
      "platform_offering",
      "platform_channel",
    );
    expect(offering.status, JSON.stringify(offering.body)).toBe(201);
    expect(offering.body.scope).toBe("platform");

    // RAW SQL, not the store: this is the only assertion that can tell the
    // difference between "the handler wrote the platform tables" and "the
    // handler agreed with itself".
    expect(await platformIds("platform_provider_channels")).toEqual(["platform_channel"]);
    expect(await platformIds("platform_catalog_models")).toEqual(["platform_model"]);
    expect(await platformIds("platform_catalog_offerings")).toEqual(["platform_offering"]);

    const providerList = await request(OPERATOR, "GET", "/admin/v1/providers");
    expect(providerList.status).toBe(200);
    expect(providerList.body.scope).toBe("platform");
    expect((providerList.body.data as JsonBody[]).map((row) => row.id)).toEqual([
      "platform_channel",
    ]);

    const modelRead = await request(OPERATOR, "GET", "/admin/v1/models/platform_model");
    expect(modelRead.status).toBe(200);
    expect(modelRead.body.scope).toBe("platform");
    expect((modelRead.body.model as JsonBody).provider).toBe("platform_channel");
    expect((modelRead.body.model as JsonBody).provider_model).toBe("upstream-platform_offering");

    const offeringList = await request(
      OPERATOR,
      "GET",
      "/admin/v1/models/platform_model/offerings",
    );
    expect(offeringList.status).toBe(200);
    expect(offeringList.body.scope).toBe("platform");
    expect((offeringList.body.data as JsonBody[]).map((row) => row.role)).toEqual(["primary"]);

    const patched = await request(OPERATOR, "PATCH", "/admin/v1/providers/platform_channel", {
      region: "us-east-1",
    });
    expect(patched.status).toBe(200);
    expect((patched.body.provider as JsonBody).region).toBe("us-east-1");
    const storedRegion = await db()
      .prepare("SELECT region FROM platform_provider_channels WHERE id = ?")
      .bind("platform_channel")
      .first<{ region: string | null }>();
    expect(storedRegion?.region).toBe("us-east-1");

    const replacedOffering = await request(
      OPERATOR,
      "PUT",
      "/admin/v1/models/platform_model/offerings/platform_offering",
      { provider_id: "platform_channel", upstream_model_id: "upstream-v2", role: "primary" },
    );
    expect(replacedOffering.status).toBe(200);
    expect((replacedOffering.body.offering as JsonBody).upstream_model_id).toBe("upstream-v2");

    const deletedOffering = await request(
      OPERATOR,
      "DELETE",
      "/admin/v1/models/platform_model/offerings/platform_offering",
    );
    expect(deletedOffering.status).toBe(200);
    expect(deletedOffering.body.scope).toBe("platform");
    expect(deletedOffering.body.deleted).toBe(true);

    expect((await request(OPERATOR, "DELETE", "/admin/v1/models/platform_model")).status).toBe(200);
    expect((await request(OPERATOR, "DELETE", "/admin/v1/providers/platform_channel")).status).toBe(
      200,
    );
    expect(await platformIds("platform_catalog_offerings")).toEqual([]);
    expect(await platformIds("platform_catalog_models")).toEqual([]);
    expect(await platformIds("platform_provider_channels")).toEqual([]);

    const missing = await request(OPERATOR, "GET", "/admin/v1/providers/platform_channel");
    expect(missing.status).toBe(404);
  });

  it("bumps the platform revision and appends exactly one audit row per write", async () => {
    expect(await platformRevision()).toBe(0);
    expect(await platformAuditRows()).toEqual([]);

    expect((await createPlatformProvider("rev_channel")).status).toBe(201);
    const afterProvider = await platformRevision();
    expect(afterProvider).toBe(1);

    expect((await createPlatformModel("rev_model")).status).toBe(201);
    const afterModel = await platformRevision();
    expect(afterModel).toBe(afterProvider + 1);

    expect((await createPlatformOffering("rev_model", "rev_offering", "rev_channel")).status).toBe(
      201,
    );
    const afterOffering = await platformRevision();
    expect(afterOffering).toBe(afterModel + 1);

    expect(
      (await request(OPERATOR, "PATCH", "/admin/v1/models/rev_model", { owned_by: "platform" }))
        .status,
    ).toBe(200);
    expect(await platformRevision()).toBe(afterOffering + 1);

    expect((await request(OPERATOR, "DELETE", "/admin/v1/models/rev_model")).status).toBe(200);
    const afterDelete = await platformRevision();
    expect(afterDelete).toBe(afterOffering + 2);

    // The WHOLE tuple, because each field is load-bearing and none of them is
    // held by any other assertion: `revision` is what a reader compares against
    // the stamp to decide its cache is stale, `action` is what distinguishes a
    // removal from a creation in the chain, and `resource_id` is what names the
    // row the entry is about.
    expect(await platformAuditRows()).toEqual([
      {
        collection: "platform_providers",
        action: "create",
        revision: 1,
        resource_id: "rev_channel",
      },
      { collection: "platform_models", action: "create", revision: 2, resource_id: "rev_model" },
      {
        collection: "platform_offerings",
        action: "create",
        revision: 3,
        resource_id: "rev_offering",
      },
      { collection: "platform_models", action: "merge", revision: 4, resource_id: "rev_model" },
      { collection: "platform_models", action: "remove", revision: 5, resource_id: "rev_model" },
    ]);
    expect(afterDelete).toBe(5);
  });

  it("rolls the mutation back when the audit row cannot be written", async () => {
    // The audit append and the mutation must be ONE batch. With the audit
    // appended after a committed batch instead, this leaves `orphan_channel` in
    // the table and the revision at 1 while the caller is told it failed —
    // a committed change with no audit evidence, and #890/#891 acting on a
    // revision no auditor can explain.
    // The abort message names the table for the same reason a real failure
    // does — the one expected here is
    // `UNIQUE constraint failed: audit_events.chain_key, audit_events.seq`.
    await db().exec(
      "CREATE TRIGGER block_audit_append BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'audit_events append rejected'); END",
    );
    try {
      const blocked = await createPlatformProvider("orphan_channel");
      expect(blocked.status, JSON.stringify(blocked.body)).toBe(500);
    } finally {
      await db().exec("DROP TRIGGER IF EXISTS block_audit_append");
    }

    expect(await platformIds("platform_provider_channels")).toEqual([]);
    expect(await platformRevision()).toBe(0);
    expect(await platformAuditRows()).toEqual([]);

    // And the store is not wedged: the same write succeeds once audit works.
    expect((await createPlatformProvider("orphan_channel")).status).toBe(201);
    expect(await platformIds("platform_provider_channels")).toEqual(["orphan_channel"]);
    expect(await platformRevision()).toBe(1);
  });

  it("refuses to delete a platform channel with live offerings and leaves the revision alone", async () => {
    expect((await createPlatformProvider("live_channel")).status).toBe(201);
    expect((await createPlatformModel("live_model")).status).toBe(201);
    expect(
      (await createPlatformOffering("live_model", "live_offering", "live_channel")).status,
    ).toBe(201);

    const before = await platformRevision();
    const conflict = await request(OPERATOR, "DELETE", "/admin/v1/providers/live_channel");
    expect(conflict.status).toBe(409);
    expect(await platformRevision()).toBe(before);
    expect(await platformIds("platform_provider_channels")).toEqual(["live_channel"]);
  });

  it("keeps the role arity: a second primary offering on one model is a conflict", async () => {
    expect((await createPlatformProvider("arity_a")).status).toBe(201);
    expect((await createPlatformProvider("arity_b")).status).toBe(201);
    expect((await createPlatformModel("arity_model")).status).toBe(201);
    expect((await createPlatformOffering("arity_model", "arity_1", "arity_a")).status).toBe(201);

    const before = await platformRevision();
    const second = await createPlatformOffering("arity_model", "arity_2", "arity_b");
    expect(second.status, JSON.stringify(second.body)).toBe(409);
    expect(await platformRevision()).toBe(before);
    expect(await platformIds("platform_catalog_offerings")).toEqual(["arity_1"]);
  });

  it('rejects kind "platform" on a platform channel', async () => {
    const cycle = await createPlatformProvider("cycle_channel", { kind: "platform" });
    expect(cycle.status, JSON.stringify(cycle.body)).toBe(400);
    expect((cycle.body.error as JsonBody).code).toBe("invalid_request_body");
    expect(await platformIds("platform_provider_channels")).toEqual([]);

    // The rejection must survive an update too, not only a create.
    expect((await createPlatformProvider("cycle_ok")).status).toBe(201);
    const patched = await request(OPERATOR, "PATCH", "/admin/v1/providers/cycle_ok", {
      kind: "platform",
    });
    expect(patched.status).toBe(400);
    const stored = await db()
      .prepare("SELECT kind FROM platform_provider_channels WHERE id = ?")
      .bind("cycle_ok")
      .first<{ kind: string }>();
    expect(stored?.kind).toBe("openai-compatible");
  });

  it("fences tenant callers out of the platform catalog, in both directions", async () => {
    const tenantId = `tenant_platform_fence_${crypto.randomUUID().slice(0, 8)}`;
    const tenantSecret = `platform-fence-${tenantId}`;
    arm({
      store: "d1",
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey(tenantSecret, tenantId)],
    });
    await provisionTenant(tenantId);

    // A platform write must not land in the tenant's own database.
    expect((await createPlatformProvider("fenced_platform_channel")).status).toBe(201);
    const handle = await resolveTenantStorage(env as unknown as ControlPlaneBindings).forTenant(
      tenantId,
    );
    const tenantRows = await handle.db
      .prepare("SELECT id FROM provider_channels WHERE tenant_id = ?")
      .bind(tenantId)
      .all<{ id: string }>();
    // Provisioning seeds this tenant its own `<tenant>:*` platform-default
    // channel, so the tenant database is not empty — what matters is that the
    // row the OPERATOR just created at platform scope is not in it.
    expect(tenantRows.results.map((row) => row.id)).not.toContain("fenced_platform_channel");

    // A tenant write must not land in the platform catalog.
    const tenantCreate = await request(tenantSecret, "POST", "/admin/v1/providers", {
      id: "tenant_owned_channel",
      name: "tenant_owned_channel",
      kind: "openai-compatible",
      base_url: "https://tenant.example.test/v1",
    });
    expect(tenantCreate.status, JSON.stringify(tenantCreate.body)).toBe(201);
    expect(tenantCreate.body.scope).toBe("tenant");
    expect(await platformIds("platform_provider_channels")).toEqual(["fenced_platform_channel"]);

    // And a tenant caller can neither see nor address the platform row.
    const tenantList = await request(tenantSecret, "GET", "/admin/v1/providers");
    expect(tenantList.status).toBe(200);
    expect(tenantList.body.scope).toBe("tenant");
    const tenantListIds = (tenantList.body.data as JsonBody[]).map((row) => row.id);
    expect(tenantListIds).toContain("tenant_owned_channel");
    expect(tenantListIds).not.toContain("fenced_platform_channel");

    for (const [method, body] of [
      ["GET", undefined],
      ["PATCH", { region: "eu-west-1" }],
      ["DELETE", undefined],
    ] as const) {
      const response = await request(
        tenantSecret,
        method,
        "/admin/v1/providers/fenced_platform_channel",
        body,
      );
      expect(response.status, `${method} platform row as tenant`).toBe(404);
    }
    expect(await platformIds("platform_provider_channels")).toEqual(["fenced_platform_channel"]);

    // The platform operator addressing that tenant still gets the tenant
    // catalog, unchanged, and says so.
    const operatorTenantList = await request(
      OPERATOR,
      "GET",
      `/admin/v1/providers?tenant_id=${encodeURIComponent(tenantId)}`,
    );
    expect(operatorTenantList.status).toBe(200);
    expect(operatorTenantList.body.scope).toBe("tenant");
    const operatorListIds = (operatorTenantList.body.data as JsonBody[]).map((row) => row.id);
    expect(operatorListIds).toContain("tenant_owned_channel");
    expect(operatorListIds).not.toContain("fenced_platform_channel");
  });

  it("keeps the pre-#889 aggregate list while the platform catalog is empty", async () => {
    const tenantId = `tenant_platform_empty_${crypto.randomUUID().slice(0, 8)}`;
    await provisionTenant(tenantId);
    expect(await platformIds("platform_provider_channels")).toEqual([]);

    // Nothing in the platform catalog yet, so the list must still answer with
    // the per-tenant aggregate a platform operator got before this slice —
    // and must say `tenant` so the caller is not told it read the platform.
    const aggregate = await request(OPERATOR, "GET", "/admin/v1/providers");
    expect(aggregate.status).toBe(200);
    expect(aggregate.body.scope).toBe("tenant");
    const aggregateIds = (aggregate.body.data as JsonBody[]).map((row) => row.id);
    expect(aggregateIds.length).toBeGreaterThan(0);
    expect(aggregateIds).not.toContain("late_platform_channel");

    expect((await createPlatformProvider("late_platform_channel")).status).toBe(201);
    const platformList = await request(OPERATOR, "GET", "/admin/v1/providers");
    expect(platformList.status).toBe(200);
    expect(platformList.body.scope).toBe("platform");
    expect((platformList.body.data as JsonBody[]).map((row) => row.id)).toEqual([
      "late_platform_channel",
    ]);
  });

  it("keeps the pre-#889 400 on item operations until the catalog is adopted", async () => {
    const tenantId = `tenant_platform_item_${crypto.randomUUID().slice(0, 8)}`;
    await provisionTenant(tenantId);
    const tenantQuery = `tenant_id=${encodeURIComponent(tenantId)}`;
    const created = await request(OPERATOR, "POST", `/admin/v1/providers?${tenantQuery}`, {
      id: "tenant_item_channel",
      name: "tenant_item_channel",
      kind: "openai-compatible",
      base_url: "https://tenant-item.example.test/v1",
    });
    expect(created.status, JSON.stringify(created.body)).toBe(201);

    // The id the operator's own LIST just handed back. Answering 404 here is
    // not a harmless relabelling of the old 400: 404 on a DELETE is the
    // canonical "already gone", so a cleanup script that omits `tenant_id`
    // would report every tenant provider as removed while the rows stand.
    const listed = await request(OPERATOR, "GET", "/admin/v1/providers");
    expect(listed.body.scope).toBe("tenant");
    expect((listed.body.data as JsonBody[]).map((row) => row.id)).toContain("tenant_item_channel");

    for (const [method, body] of [
      ["GET", undefined],
      ["PATCH", { region: "eu-west-1" }],
      ["DELETE", undefined],
    ] as const) {
      const response = await request(
        OPERATOR,
        method,
        "/admin/v1/providers/tenant_item_channel",
        body,
      );
      expect(response.status, `${method} without tenant_id before adoption`).toBe(400);
      expect((response.body.error as JsonBody).code).toBe("invalid_request");
    }
    const offerings = await request(OPERATOR, "GET", "/admin/v1/models/anything/offerings");
    expect(offerings.status).toBe(400);

    // Adopting the catalog is what changes the meaning of a bare id, and the
    // tenant row is untouched by any of it.
    expect((await createPlatformProvider("adopting_channel")).status).toBe(201);
    const afterAdoption = await request(OPERATOR, "GET", "/admin/v1/providers/tenant_item_channel");
    expect(afterAdoption.status).toBe(404);
    const tenantRows = await request(OPERATOR, "GET", `/admin/v1/providers?${tenantQuery}`);
    expect((tenantRows.body.data as JsonBody[]).map((row) => row.id)).toContain(
      "tenant_item_channel",
    );
  });

  it("answers the provider and model lists from the SAME catalog", async () => {
    const tenantId = `tenant_platform_pair_${crypto.randomUUID().slice(0, 8)}`;
    await provisionTenant(tenantId);

    // One platform PROVIDER and no platform models. Deciding precedence per
    // resource shows this session the platform provider list and the tenant
    // aggregate model list at once — and `POST /models/<tenant model>/offerings`
    // with a platform `provider_id` then 404s, because the two pages it was
    // just served are not addressable together.
    expect((await createPlatformProvider("pair_channel")).status).toBe(201);

    const providers = await request(OPERATOR, "GET", "/admin/v1/providers");
    const models = await request(OPERATOR, "GET", "/admin/v1/models");
    expect(providers.status).toBe(200);
    expect(models.status).toBe(200);
    expect(providers.body.scope).toBe("platform");
    expect(models.body.scope).toBe("platform");
    expect((models.body.data as JsonBody[]).map((row) => row.id)).toEqual([]);

    // The mirror case: platform models, no platform providers, same answer.
    expect((await request(OPERATOR, "DELETE", "/admin/v1/providers/pair_channel")).status).toBe(
      200,
    );
    expect((await createPlatformModel("pair_model")).status).toBe(201);
    const providersAgain = await request(OPERATOR, "GET", "/admin/v1/providers");
    const modelsAgain = await request(OPERATOR, "GET", "/admin/v1/models");
    expect(providersAgain.body.scope).toBe("platform");
    expect(modelsAgain.body.scope).toBe("platform");
    expect((providersAgain.body.data as JsonBody[]).map((row) => row.id)).toEqual([]);
    expect((modelsAgain.body.data as JsonBody[]).map((row) => row.id)).toEqual(["pair_model"]);
  });

  it("labels the legacy document collection by the scope it was read at", async () => {
    // Zero provisioned tenants and an empty platform catalog: the answer is
    // `deps.store.list("providers", …)`, the platform operator's un-attributed
    // view of the pre-catalog documents. Calling that `tenant` attributes rows
    // to a tenant the response cannot name.
    expect(await platformIds("platform_provider_channels")).toEqual([]);
    const legacy = await request(OPERATOR, "GET", "/admin/v1/providers");
    expect(legacy.status, JSON.stringify(legacy.body)).toBe(200);
    expect(legacy.body.scope).toBe("platform");

    const legacyModels = await request(OPERATOR, "GET", "/admin/v1/models");
    expect(legacyModels.status).toBe(200);
    expect(legacyModels.body.scope).toBe("platform");
  });

  it("degrades to the pre-#889 answer when migration 0025 is not applied yet", async () => {
    // `wrangler.toml` pins `d1_compat`, whose migrations are applied by a
    // separate `wrangler d1 migrations apply` step rather than by
    // `wrangler deploy`, so a new Worker really can meet an old control
    // database. Two operator LIST endpoints that worked before this slice must
    // not 500 in that window.
    const restore = await dropPlatformTables();
    try {
      const providers = await request(OPERATOR, "GET", "/admin/v1/providers");
      expect(providers.status, JSON.stringify(providers.body)).toBe(200);
      const models = await request(OPERATOR, "GET", "/admin/v1/models");
      expect(models.status, JSON.stringify(models.body)).toBe(200);

      // Item operations keep their pre-#889 400, not a 500 either.
      const item = await request(OPERATOR, "GET", "/admin/v1/providers/anything");
      expect(item.status, JSON.stringify(item.body)).toBe(400);

      // A WRITE cannot be served at all, but "not deployed yet" is a 503 an
      // operator can act on rather than an opaque 500.
      const write = await createPlatformProvider("premigration_channel");
      expect(write.status, JSON.stringify(write.body)).toBe(503);
    } finally {
      await restore();
    }
    expect((await request(OPERATOR, "GET", "/admin/v1/providers")).status).toBe(200);
  });

  it("writes the platform catalog through the CONTROL_DATA object under the durable_object posture", async () => {
    const facade = controlObjectDb();
    await wipePlatformCatalog(facade);
    try {
      controlStorage("durable_object");
      const created = await createPlatformProvider("do_channel");
      expect(created.status, JSON.stringify(created.body)).toBe(201);
      expect(created.body.scope).toBe("platform");

      expect(await platformIds("platform_provider_channels", facade)).toEqual(["do_channel"]);
      expect(await platformRevision(facade)).toBe(1);
      expect(await platformAuditCollections(facade)).toEqual(["platform_providers"]);

      // Zero-D1 S5 (#881): there is no legacy `env.DB` leg any more — the object
      // facade IS the control database, so `db()` and `controlObjectDb()`
      // address the same singleton and both show the write.
      expect(await platformIds("platform_provider_channels", db())).toEqual(["do_channel"]);

      const read = await request(OPERATOR, "GET", "/admin/v1/providers/do_channel");
      expect(read.status).toBe(200);
      expect(read.body.scope).toBe("platform");

      const deleted = await request(OPERATOR, "DELETE", "/admin/v1/providers/do_channel");
      expect(deleted.status).toBe(200);
      expect(await platformIds("platform_provider_channels", facade)).toEqual([]);
      expect(await platformRevision(facade)).toBe(2);
    } finally {
      controlStorage(DEFAULT_CONTROL_STORAGE);
      await wipePlatformCatalog(facade);
    }
  });
});
