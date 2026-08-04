/**
 * Tenant-owned provider/model/offering CRUD (#813).
 *
 * These tests deliberately drive the HTTP surface and then read the same
 * tenant Durable Object through the storage router. A control-plane document
 * row, or a handler that accidentally writes the wrong tenant, must not make
 * this suite green.
 */
import { SELF, env } from "cloudflare:test";
import { DEFAULT_TENANT_MODEL_CATALOG } from "@ferrogate/storage";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { emptyModelResolver } from "../../gateway/src/inference/defaults.js";
import type { InferenceBindings } from "../../gateway/src/inference/ports.js";
import { tenantModelCatalogFromD1 } from "../../gateway/src/inference/tenant-catalog.js";
import { resolveTenantStorage } from "../src/adapters.js";
import type { ControlPlaneBindings } from "../src/ports.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";

const OPERATOR = operatorKey.secret;

const platformCatalogEnv: InferenceBindings = {
  TENANT_PRIMARY_KEY: "test-primary-key",
  GATEWAY_PROVIDERS: JSON.stringify([
    {
      name: "platform-default",
      kind: "openai-compatible",
      base_url: "https://platform.example.test/v1",
    },
  ]),
  GATEWAY_MODELS: JSON.stringify(
    DEFAULT_TENANT_MODEL_CATALOG.map((entry) => ({
      name: entry.model,
      provider: "platform-default",
      provider_model: entry.providerModel,
      capabilities: ["chat"],
      enabled: true,
    })),
  ),
};

interface JsonBody {
  readonly [key: string]: unknown;
}

interface TestResponse {
  readonly status: number;
  readonly body: JsonBody;
}

function freshTenantId(label: string): string {
  return `tenant_catalog_${label}_${crypto.randomUUID().slice(0, 8)}`;
}

function tenantDb(tenantId: string): Promise<{ db: D1Database }> {
  return resolveTenantStorage(env as unknown as ControlPlaneBindings).forTenant(tenantId);
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

async function provisionTenant(tenantId: string): Promise<void> {
  const response = await request(OPERATOR, "POST", "/admin/v1/tenant-accounts", {
    id: tenantId,
    name: tenantId,
    slug: tenantId,
  });
  expect(response.status).toBe(201);
}

async function revision(tenantId: string): Promise<number> {
  const handle = await tenantDb(tenantId);
  const row = await handle.db
    .prepare("SELECT revision FROM catalog_revisions WHERE tenant_id = ? AND id = 1")
    .bind(tenantId)
    .first<{ revision: number | string }>();
  return Number(row?.revision ?? 0);
}

async function createChannel(
  tenantId: string,
  id = "channel_primary",
  overrides: Record<string, unknown> = {},
): Promise<void> {
  const response = await request(tenantId, "POST", "/admin/v1/providers", {
    id,
    name: id,
    kind: "openai-compatible",
    base_url: `https://${id}.example.test/v1`,
    enabled: true,
    ...overrides,
  });
  expect(response.status, `${id}: ${JSON.stringify(response.body)}`).toBe(201);
}

async function createModel(tenantId: string, id = "model_catalog"): Promise<void> {
  const response = await request(tenantId, "POST", "/admin/v1/models", {
    id,
    name: "catalog-model",
    family: "openai",
    capabilities: ["chat", "streaming"],
    context_window: 128000,
    routing_strategy: "priority",
    enabled: true,
  });
  expect(response.status).toBe(201);
}

async function createOffering(
  tenantId: string,
  id: string,
  providerId: string,
  role: "primary" | "fallback" | "canary" | "shadow",
  extra: Record<string, unknown> = {},
): Promise<void> {
  const response = await request(tenantId, "POST", "/admin/v1/models/model_catalog/offerings", {
    id,
    provider_id: providerId,
    upstream_model_id: `upstream-${id}`,
    role,
    priority: role === "primary" ? 0 : 100,
    weight: 1,
    input_price_per_1m: 0.25,
    output_price_per_1m: 0.5,
    ...extra,
  });
  expect(response.status).toBe(201);
}

beforeAll(applySchema);

beforeEach(async () => {
  await resetD1();
  arm({ store: "d1", staticKeys: [operatorKey] });
});

describe("tenant model catalog CRUD", () => {
  it("writes all four offering roles into the tenant DO and the gateway resolves them", async () => {
    const tenantId = freshTenantId("crud");
    const tenantSecret = `catalog-admin-${tenantId}`;
    arm({
      store: "d1",
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey(tenantSecret, tenantId)],
    });
    await provisionTenant(tenantId);

    const providerIds: readonly [string, string, string, string] = [
      "channel_primary",
      "channel_fallback",
      "channel_canary",
      "channel_shadow",
    ];
    await createChannel(tenantSecret, providerIds[0], { api_key_var: "TENANT_PRIMARY_KEY" });
    for (const providerId of providerIds.slice(1)) await createChannel(tenantSecret, providerId);
    await createChannel(tenantSecret, "channel_anthropic", { kind: "anthropic" });
    await createModel(tenantSecret);

    await createOffering(tenantSecret, "offering_primary", providerIds[0], "primary");
    await createOffering(tenantSecret, "offering_fallback", providerIds[1], "fallback");
    await createOffering(tenantSecret, "offering_canary", providerIds[2], "canary", {
      canary_percent: 10,
    });
    await createOffering(tenantSecret, "offering_shadow", providerIds[3], "shadow", {
      shadow_percent: 10,
      shadow_max_requests: 25,
    });

    const providers = await request(tenantSecret, "GET", "/admin/v1/providers");
    expect(providers.status).toBe(200);
    const providerRows = providers.body.data as JsonBody[];
    expect(providerRows.some((row) => row.id === "channel_primary")).toBe(true);
    const createdProvider = providerRows.find((row) => row.id === "channel_primary");
    expect(createdProvider?.has_api_key).toBe(true);
    expect(createdProvider).not.toHaveProperty("api_key_var");
    const anthropicProvider = providerRows.find((row) => row.id === "channel_anthropic");
    expect(anthropicProvider?.compatibility).toBe("dedicated");

    const operatorTenantList = await request(
      OPERATOR,
      "GET",
      `/admin/v1/providers?tenant_id=${encodeURIComponent(tenantId)}`,
    );
    expect(operatorTenantList.status).toBe(200);
    expect(
      (operatorTenantList.body.data as JsonBody[]).every((row) => row.tenant_id === tenantId),
    ).toBe(true);

    const status = await request(OPERATOR, "GET", "/admin/v1/status");
    expect(status.status).toBe(200);
    expect(Number(status.body.providers)).toBe(6);

    const offerings = await request(
      tenantSecret,
      "GET",
      "/admin/v1/models/model_catalog/offerings",
    );
    expect(offerings.status).toBe(200);
    expect((offerings.body.data as JsonBody[]).map((row) => row.role).sort()).toEqual([
      "canary",
      "fallback",
      "primary",
      "shadow",
    ]);
    const offeringRead = await request(
      tenantSecret,
      "GET",
      "/admin/v1/models/model_catalog/offerings/offering_canary",
    );
    expect(offeringRead.status).toBe(200);
    expect((offeringRead.body.offering as JsonBody).role).toBe("canary");

    const handle = await tenantDb(tenantId);
    const loaded = await tenantModelCatalogFromD1().load({
      tenantId,
      db: handle.db,
      env: platformCatalogEnv,
      fallback: emptyModelResolver,
    });
    expect(loaded.ok, loaded.ok ? "" : loaded.reason).toBe(true);
    if (!loaded.ok) throw new Error(loaded.reason);
    expect(loaded.models.candidates?.("catalog-model")).toHaveLength(4);
  });

  it("requires admin.write for every catalog write verb", async () => {
    const tenantId = freshTenantId("rbac");
    const readOnlySecret = `catalog-read-${tenantId}`;
    arm({
      store: "d1",
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey(readOnlySecret, tenantId, ["admin.read"])],
    });
    await provisionTenant(tenantId);

    const writes: readonly [string, string, unknown?][] = [
      [
        "POST",
        "/admin/v1/providers",
        { id: "p", name: "p", kind: "openai-compatible", base_url: "https://p.example.test" },
      ],
      [
        "PUT",
        "/admin/v1/providers/p",
        { name: "p", kind: "openai-compatible", base_url: "https://p.example.test" },
      ],
      ["PATCH", "/admin/v1/providers/p", {}],
      ["DELETE", "/admin/v1/providers/p"],
      ["POST", "/admin/v1/models", { id: "m", name: "m" }],
      ["PUT", "/admin/v1/models/m", { name: "m" }],
      ["PATCH", "/admin/v1/models/m", {}],
      ["DELETE", "/admin/v1/models/m"],
      [
        "POST",
        "/admin/v1/models/m/offerings",
        { id: "o", provider_id: "p", upstream_model_id: "u" },
      ],
      ["PUT", "/admin/v1/models/m/offerings/o", { provider_id: "p", upstream_model_id: "u" }],
      ["PATCH", "/admin/v1/models/m/offerings/o", {}],
      ["DELETE", "/admin/v1/models/m/offerings/o"],
    ];

    for (const [method, path, body] of writes) {
      const response = await request(readOnlySecret, method, path, body);
      expect(response.status, `${method} ${path}`).toBe(403);
      expect((response.body.error as JsonBody).code).toBe("scope_denied");
    }
  });

  it("makes cross-tenant rows indistinguishable from nonexistent ids", async () => {
    const firstTenant = freshTenantId("isolation_a");
    const secondTenant = freshTenantId("isolation_b");
    const firstSecret = `catalog-a-${firstTenant}`;
    const secondSecret = `catalog-b-${secondTenant}`;
    arm({
      store: "d1",
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey(firstSecret, firstTenant), tenantKey(secondSecret, secondTenant)],
    });
    await provisionTenant(firstTenant);
    await provisionTenant(secondTenant);
    await createChannel(firstSecret, "provider_isolated");
    await createModel(firstSecret);
    await createOffering(firstSecret, "offering_isolated", "provider_isolated", "primary");

    const modelBodies: Readonly<Record<string, unknown> | undefined>[] = [
      undefined,
      { name: "not-visible" },
      { name: "not-visible" },
      undefined,
    ];
    for (const [index, method] of (["GET", "PUT", "PATCH", "DELETE"] as const).entries()) {
      const response = await request(
        secondSecret,
        method,
        "/admin/v1/models/model_catalog",
        modelBodies[index],
      );
      expect(response.status, `${method} cross-tenant model`).toBe(404);
    }

    const providerBodies: Readonly<Record<string, unknown> | undefined>[] = [
      undefined,
      { name: "not-visible", kind: "openai-compatible", base_url: "https://hidden.example.test" },
      { name: "not-visible" },
      undefined,
    ];
    for (const [index, method] of (["GET", "PUT", "PATCH", "DELETE"] as const).entries()) {
      const response = await request(
        secondSecret,
        method,
        "/admin/v1/providers/provider_isolated",
        providerBodies[index],
      );
      expect(response.status, `${method} cross-tenant provider`).toBe(404);
    }

    const offeringBodies: Readonly<Record<string, unknown> | undefined>[] = [
      undefined,
      { provider_id: "provider_isolated", upstream_model_id: "hidden" },
      { weight: 2 },
      undefined,
    ];
    for (const [index, method] of (["GET", "PUT", "PATCH", "DELETE"] as const).entries()) {
      const response = await request(
        secondSecret,
        method,
        "/admin/v1/models/model_catalog/offerings/offering_isolated",
        offeringBodies[index],
      );
      expect(response.status, `${method} cross-tenant offering`).toBe(404);
    }

    const secondList = await request(secondSecret, "GET", "/admin/v1/models");
    expect((secondList.body.data as JsonBody[]).some((row) => row.id === "model_catalog")).toBe(
      false,
    );
    const firstRead = await request(firstSecret, "GET", "/admin/v1/models/model_catalog");
    expect(firstRead.status).toBe(200);
    expect((firstRead.body.model as JsonBody).name).toBe("catalog-model");

    const tenantQueryMismatch = await request(
      firstSecret,
      "GET",
      `/admin/v1/models/model_catalog?tenant_id=${encodeURIComponent(secondTenant)}`,
    );
    expect(tenantQueryMismatch.status).toBe(404);
  });

  it("rejects deleting a channel with live offerings without changing rows or revision", async () => {
    const tenantId = freshTenantId("delete-fence");
    const tenantSecret = `catalog-delete-${tenantId}`;
    arm({
      store: "d1",
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey(tenantSecret, tenantId)],
    });
    await provisionTenant(tenantId);
    await createChannel(tenantSecret);
    await createModel(tenantSecret);
    await createOffering(tenantSecret, "offering_live", "channel_primary", "primary");

    const beforeRevision = await revision(tenantId);
    const deleted = await request(tenantSecret, "DELETE", "/admin/v1/providers/channel_primary");
    expect(deleted.status).toBe(409);
    expect(await revision(tenantId)).toBe(beforeRevision);

    const handle = await tenantDb(tenantId);
    const channel = await handle.db
      .prepare("SELECT id FROM provider_channels WHERE tenant_id = ? AND id = ?")
      .bind(tenantId, "channel_primary")
      .first<{ id: string }>();
    const offering = await handle.db
      .prepare("SELECT id FROM catalog_model_offerings WHERE tenant_id = ? AND id = ?")
      .bind(tenantId, "offering_live")
      .first<{ id: string }>();
    expect(channel?.id).toBe("channel_primary");
    expect(offering?.id).toBe("offering_live");
  });

  it("bumps the tenant revision and emits audit evidence for writes", async () => {
    const tenantId = freshTenantId("evidence");
    const tenantSecret = `catalog-evidence-${tenantId}`;
    arm({
      store: "d1",
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey(tenantSecret, tenantId)],
    });
    await provisionTenant(tenantId);

    const beforeRevision = await revision(tenantId);
    await createChannel(tenantSecret, "channel_audited");
    expect(await revision(tenantId)).toBeGreaterThan(beforeRevision);

    const auditRows = await db()
      .prepare("SELECT audit_json FROM audit_events WHERE tenant = ?")
      .bind(tenantId)
      .all<{ audit_json: string }>();
    expect(
      auditRows.results.some((row) => row.audit_json.includes("providers")),
      JSON.stringify(auditRows.results),
    ).toBe(true);
  });

  it("enforces catalog conflicts and supports successful item updates and deletes", async () => {
    const tenantId = freshTenantId("lifecycle");
    const tenantSecret = `catalog-lifecycle-${tenantId}`;
    arm({
      store: "d1",
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey(tenantSecret, tenantId)],
    });
    await provisionTenant(tenantId);
    await createChannel(tenantSecret, "channel_lifecycle");
    await createChannel(tenantSecret, "channel_lifecycle_b");
    await createModel(tenantSecret, "model_lifecycle");

    const missingCanaryPercent = await request(
      tenantSecret,
      "POST",
      "/admin/v1/models/model_lifecycle/offerings",
      {
        id: "offering_missing_canary_percent",
        provider_id: "channel_lifecycle",
        upstream_model_id: "upstream-canary",
        role: "canary",
      },
    );
    expect(missingCanaryPercent.status).toBe(400);

    const missingShadowPercent = await request(
      tenantSecret,
      "POST",
      "/admin/v1/models/model_lifecycle/offerings",
      {
        id: "offering_missing_shadow_percent",
        provider_id: "channel_lifecycle",
        upstream_model_id: "upstream-shadow",
        role: "shadow",
      },
    );
    expect(missingShadowPercent.status).toBe(400);

    const firstOffering = await request(
      tenantSecret,
      "POST",
      "/admin/v1/models/model_lifecycle/offerings",
      {
        id: "offering_lifecycle",
        provider_id: "channel_lifecycle",
        upstream_model_id: "upstream-lifecycle",
        role: "primary",
      },
    );
    expect(firstOffering.status).toBe(201);

    const duplicatePrimary = await request(
      tenantSecret,
      "POST",
      "/admin/v1/models/model_lifecycle/offerings",
      {
        id: "offering_duplicate_primary",
        provider_id: "channel_lifecycle_b",
        upstream_model_id: "upstream-lifecycle-b",
        role: "primary",
      },
    );
    expect(duplicatePrimary.status).toBe(409);

    const duplicateBinding = await request(
      tenantSecret,
      "POST",
      "/admin/v1/models/model_lifecycle/offerings",
      {
        id: "offering_duplicate_binding",
        provider_id: "channel_lifecycle",
        upstream_model_id: "upstream-lifecycle",
        role: "fallback",
      },
    );
    expect(duplicateBinding.status).toBe(409);

    const providerUpdate = await request(
      tenantSecret,
      "PATCH",
      "/admin/v1/providers/channel_lifecycle",
      { name: "channel-lifecycle-updated" },
    );
    expect(providerUpdate.status).toBe(200);

    const providerReplace = await request(
      tenantSecret,
      "PUT",
      "/admin/v1/providers/channel_lifecycle",
      {
        name: "channel-lifecycle-replaced",
        kind: "openai-compatible",
        base_url: "https://channel-lifecycle-replaced.example.test/v1",
        enabled: false,
      },
    );
    expect(providerReplace.status).toBe(200);
    expect((providerReplace.body.provider as JsonBody).enabled).toBe(false);

    const modelUpdate = await request(tenantSecret, "PUT", "/admin/v1/models/model_lifecycle", {
      name: "catalog-model-updated",
      family: "updated",
    });
    expect(modelUpdate.status).toBe(200);
    expect(modelUpdate.body.model).toMatchObject({
      name: "catalog-model-updated",
      capabilities: [],
      context_window: null,
      owned_by: null,
      routing_strategy: "priority",
      enabled: true,
    });

    const offeringUpdate = await request(
      tenantSecret,
      "PATCH",
      "/admin/v1/models/model_lifecycle/offerings/offering_lifecycle",
      { weight: 3 },
    );
    expect(offeringUpdate.status).toBe(200);
    expect((offeringUpdate.body.offering as JsonBody).weight).toBe(3);
    const offeringRead = await request(
      tenantSecret,
      "GET",
      "/admin/v1/models/model_lifecycle/offerings/offering_lifecycle",
    );
    expect(offeringRead.status).toBe(200);
    expect((offeringRead.body.offering as JsonBody).weight).toBe(3);

    const offeringDelete = await request(
      tenantSecret,
      "DELETE",
      "/admin/v1/models/model_lifecycle/offerings/offering_lifecycle",
    );
    expect(offeringDelete.status).toBe(200);
    const modelDelete = await request(tenantSecret, "DELETE", "/admin/v1/models/model_lifecycle");
    expect(modelDelete.status).toBe(200);
    const providerDelete = await request(
      tenantSecret,
      "DELETE",
      "/admin/v1/providers/channel_lifecycle",
    );
    expect(providerDelete.status).toBe(200);
  });
});
