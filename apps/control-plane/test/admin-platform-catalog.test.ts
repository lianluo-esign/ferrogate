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
const DEFAULT_CONTROL_STORAGE = "d1_compat";

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

/** Audit rows this catalog wrote, newest last, read straight out of the chain. */
async function platformAuditCollections(handle: D1Database = db()): Promise<readonly string[]> {
  const rows = await handle
    .prepare("SELECT audit_json, tenant FROM audit_events ORDER BY seq ASC")
    .all<{ audit_json: string; tenant: string | null }>();
  const collections: string[] = [];
  for (const row of rows.results) {
    const parsed = JSON.parse(row.audit_json) as { collection?: string };
    if (typeof parsed.collection === "string" && parsed.collection.startsWith("platform_")) {
      expect(row.tenant, "a platform catalog audit row must not be tenant-attributed").toBeNull();
      collections.push(parsed.collection);
    }
  }
  return collections;
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
    expect(await platformAuditCollections()).toEqual([]);

    expect((await createPlatformProvider("rev_channel")).status).toBe(201);
    const afterProvider = await platformRevision();
    expect(afterProvider).toBe(1);
    expect(await platformAuditCollections()).toEqual(["platform_providers"]);

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

    expect(await platformAuditCollections()).toEqual([
      "platform_providers",
      "platform_models",
      "platform_offerings",
      "platform_models",
    ]);
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

      // The legacy D1 leg must be untouched: if the store had reached for
      // `env.DB` instead of the facade the row would be here.
      expect(await platformIds("platform_provider_channels", db())).toEqual([]);

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
