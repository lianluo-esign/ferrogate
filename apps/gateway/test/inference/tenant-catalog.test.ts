import { describe, expect, it } from "vitest";
import { BillingGroupModelResolver } from "../../src/inference/billing-group-models.js";
import { InMemoryModelResolver } from "../../src/inference/defaults.js";
import type { ModelResolver, PhysicalRoute } from "../../src/inference/ports.js";
import { D1TenantModelCatalogSource } from "../../src/inference/tenant-catalog.js";

type CatalogRow = Record<string, unknown>;

interface FakeCatalogDatabase {
  readonly db: D1Database;
  revision: number;
  rows: CatalogRow[];
  revisionReads: number;
  catalogReads: number;
  bindings: unknown[][];
  failRevision: boolean;
  failCatalog: boolean;
}

function fakeDb(rows: CatalogRow[], revision = 1): FakeCatalogDatabase {
  const state = {
    db: undefined as unknown as D1Database,
    revision,
    rows,
    revisionReads: 0,
    catalogReads: 0,
    bindings: [] as unknown[][],
    failRevision: false,
    failCatalog: false,
  } satisfies Omit<FakeCatalogDatabase, "db"> & { db: D1Database };

  const db = {
    prepare(sql: string) {
      return {
        bind(...values: unknown[]) {
          state.bindings.push(values);
          return {
            async first<T>() {
              if (sql.includes("catalog_revisions")) {
                state.revisionReads += 1;
                if (state.failRevision) throw new Error("revision backend unavailable");
                return { revision: state.revision } as T;
              }
              throw new Error(`unexpected first query: ${sql}`);
            },
            async all<T>() {
              state.catalogReads += 1;
              if (state.failCatalog) throw new Error("catalog backend unavailable");
              return { results: state.rows as T[] };
            },
          };
        },
      };
    },
  } as unknown as D1Database;
  state.db = db;
  return state;
}

function routeRow(provider: string, index: number, overrides: CatalogRow = {}): CatalogRow {
  return {
    model_id: "model-1",
    model_name: "tenant-model",
    model_owned_by: "tenant-owner",
    model_capabilities_json: '["chat","streaming"]',
    model_context_window: 8192,
    model_routing_strategy: "priority",
    model_enabled: 1,
    offering_id: `offering-${index}`,
    upstream_model_id: `upstream-${index}`,
    offering_role: index === 0 ? "primary" : "fallback",
    offering_priority: index === 0 ? 0 : index * 10,
    offering_weight: 5 - index,
    canary_percent: null,
    shadow_percent: null,
    shadow_max_requests: null,
    offering_capabilities_json: null,
    offering_context_window: null,
    offering_region: index % 2 === 0 ? "us-east-1" : "eu-west-1",
    offering_zero_data_retention: index % 2 === 0 ? 1 : 0,
    input_price_per_1m: 1 + index,
    output_price_per_1m: 2 + index,
    cached_input_price_per_1m: 3 + index,
    cache_write_price_per_1m: 4 + index,
    reasoning_price_per_1m: 5 + index,
    audio_second_price_per_1m: 6 + index,
    audio_character_price_per_1m: 7 + index,
    offering_enabled: 1,
    provider_id: `provider-${index}`,
    provider_name: provider,
    provider_kind: "openai",
    provider_base_url: `https://${provider}.test/v1`,
    provider_api_key_var: `KEY_${index}`,
    provider_byok_alias: index === 0 ? "tenant-key" : null,
    provider_auth_scheme: null,
    provider_region: "us-east-1",
    provider_zero_data_retention: 1,
    provider_openrouter_http_referer: null,
    provider_openrouter_x_title: null,
    provider_cloudflare_ai_gateway_json: null,
    provider_enabled: 1,
    ...overrides,
  };
}

function emptyFallback(): ModelResolver {
  return new InMemoryModelResolver([]);
}

const ENV = {
  KEY_0: "secret-0",
  KEY_1: "secret-1",
  KEY_2: "secret-2",
  KEY_3: "secret-3",
};

describe("D1TenantModelCatalogSource", () => {
  it("projects one joined D1 graph into the full ordered offering ladder", async () => {
    const db = fakeDb([
      routeRow("provider-b", 1),
      routeRow("provider-a", 0),
      routeRow("provider-d", 3),
      routeRow("provider-c", 2),
    ]);
    const source = new D1TenantModelCatalogSource();

    const loaded = await source.load({
      tenantId: "tenant-a",
      db: db.db,
      env: ENV,
      fallback: emptyFallback(),
    });

    expect(loaded.ok).toBe(true);
    if (!loaded.ok) return;
    const routes = loaded.models.candidates?.("tenant-model") ?? [];
    expect(routes).toHaveLength(4);
    expect(routes.map((route) => route.provider)).toEqual([
      "provider-a",
      "provider-b",
      "provider-c",
      "provider-d",
    ]);
    expect(routes.map((route) => route.providerId)).toEqual([
      "provider-0",
      "provider-1",
      "provider-2",
      "provider-3",
    ]);
    expect(routes.map((route) => route.priority)).toEqual([0, 10, 20, 30]);
    expect(routes[2]).toMatchObject({
      inputPricePer1m: 3,
      outputPricePer1m: 4,
      cachedInputPricePer1m: 5,
      cacheWritePricePer1m: 6,
      reasoningPricePer1m: 7,
      audioSecondPricePer1m: 8,
      audioCharacterPricePer1m: 9,
      region: "us-east-1",
      contextWindow: 8192,
      capabilities: ["chat", "streaming"],
    });
    expect(loaded.models.catalog()).toHaveLength(1);
    expect(db.catalogReads).toBe(1);
  });

  it("restores mirrored provider ids before exact billing-group filtering", async () => {
    const db = fakeDb([
      routeRow("openai", 0, {
        provider_id: "tenant-a:platform:provider:openai",
      }),
    ]);
    const source = new D1TenantModelCatalogSource();

    const loaded = await source.load({
      tenantId: "tenant-a",
      db: db.db,
      env: ENV,
      fallback: emptyFallback(),
    });

    expect(loaded.ok).toBe(true);
    if (!loaded.ok) return;
    const models = new BillingGroupModelResolver(loaded.models, ["platform:provider:openai"]);
    expect(models.catalog().map((model) => model.logicalModel)).toEqual(["tenant-model"]);
    expect(models.resolve("tenant-model")?.providerId).toBe("platform:provider:openai");
  });

  it("uses the tenant graph before env data and maps platform-default through env metadata", async () => {
    const db = fakeDb([
      routeRow("platform-default", 0, {
        provider_kind: "platform",
        provider_base_url: "platform://default",
        provider_api_key_var: null,
        provider_byok_alias: null,
        provider_region: null,
        provider_zero_data_retention: null,
        upstream_model_id: "tenant-upstream",
        input_price_per_1m: 99,
      }),
    ]);
    const source = new D1TenantModelCatalogSource();
    const env = {
      ...ENV,
      GATEWAY_PROVIDERS: JSON.stringify([
        {
          name: "env-provider",
          kind: "openai",
          base_url: "https://env.test/v1",
          api_key_var: "ENV_KEY",
        },
      ]),
      GATEWAY_MODELS: JSON.stringify([
        {
          name: "tenant-model",
          provider: "env-provider",
          provider_model: "env-upstream",
        },
      ]),
      ENV_KEY: "env-secret",
    };

    const loaded = await source.load({
      tenantId: "tenant-a",
      db: db.db,
      env,
      fallback: emptyFallback(),
    });

    expect(loaded.ok).toBe(true);
    if (!loaded.ok) return;
    expect(loaded.models.resolve("tenant-model")).toMatchObject({
      provider: "env-provider",
      providerModel: "tenant-upstream",
      inputPricePer1m: 99,
    });
  });

  it("does not project disabled channels when another offering remains usable", async () => {
    const db = fakeDb([
      routeRow("disabled-provider", 0, { provider_enabled: 0 }),
      routeRow("active-provider", 1, { offering_role: "fallback" }),
    ]);
    const source = new D1TenantModelCatalogSource();

    const loaded = await source.load({
      tenantId: "tenant-a",
      db: db.db,
      env: ENV,
      fallback: emptyFallback(),
    });

    expect(loaded.ok).toBe(true);
    if (!loaded.ok) return;
    expect(loaded.models.candidates?.("tenant-model").map((route) => route.provider)).toEqual([
      "active-provider",
    ]);
  });

  it("falls back only for an empty configured catalog", async () => {
    const db = fakeDb([]);
    const fallbackRoute = {
      logicalModel: "env-model",
      provider: "env-provider",
      providerModel: "env-upstream",
      providerKind: "openai",
      baseUrl: "https://env.test/v1",
      enabled: true,
    } satisfies PhysicalRoute;
    const fallback = new InMemoryModelResolver([fallbackRoute]);
    const source = new D1TenantModelCatalogSource();

    const loaded = await source.load({
      tenantId: "tenant-a",
      db: db.db,
      env: {},
      fallback,
    });

    expect(loaded).toMatchObject({ ok: true, models: fallback, revision: 1 });
    expect(db.catalogReads).toBe(1);
  });

  it("uses the live platform catalog when the tenant only has an onboarding snapshot", async () => {
    const db = fakeDb([
      routeRow("stale-provider", 0, {
        offering_source: "platform_seed",
        provider_id: "tenant-a:stale-provider-id",
      }),
    ]);
    const liveRoute = {
      logicalModel: "current-model",
      provider: "current-provider",
      providerId: "current-provider-id",
      providerModel: "current-upstream",
      providerKind: "openai",
      baseUrl: "https://current.example.test/v1",
      enabled: true,
    } satisfies PhysicalRoute;
    const fallback = new InMemoryModelResolver([liveRoute]);
    const source = new D1TenantModelCatalogSource();

    const loaded = await source.load({
      tenantId: "tenant-a",
      db: db.db,
      env: {},
      fallback,
      platformRevision: 12,
    });

    expect(loaded).toMatchObject({ ok: true, models: fallback, revision: 1 });
    if (!loaded.ok) return;
    expect(loaded.models.resolve("tenant-model")).toBeNull();
    expect(loaded.models.resolve("current-model")?.providerId).toBe("current-provider-id");
  });

  it("keeps a tenant-owned catalog authoritative over the live platform catalog", async () => {
    const db = fakeDb([
      routeRow("tenant-provider", 0, {
        offering_source: "tenant",
      }),
    ]);
    const fallback = new InMemoryModelResolver([
      {
        logicalModel: "current-model",
        provider: "current-provider",
        providerId: "current-provider-id",
        providerModel: "current-upstream",
        providerKind: "openai",
        baseUrl: "https://current.example.test/v1",
        enabled: true,
      },
    ]);
    const source = new D1TenantModelCatalogSource();

    const loaded = await source.load({
      tenantId: "tenant-a",
      db: db.db,
      env: ENV,
      fallback,
    });

    expect(loaded.ok).toBe(true);
    if (!loaded.ok) return;
    expect(loaded.models.resolve("tenant-model")?.provider).toBe("tenant-provider");
    expect(loaded.models.resolve("current-model")).toBeNull();
  });

  it("reuses a same-revision catalog and reloads after a revision bump", async () => {
    const db = fakeDb([routeRow("provider-a", 0)]);
    const source = new D1TenantModelCatalogSource();
    const env = ENV;

    const first = await source.load({
      tenantId: "tenant-a",
      db: db.db,
      env,
      fallback: emptyFallback(),
    });
    const second = await source.load({
      tenantId: "tenant-a",
      db: db.db,
      env,
      fallback: emptyFallback(),
    });
    expect(first.ok && second.ok).toBe(true);
    expect(db.catalogReads).toBe(1);
    expect(db.revisionReads).toBe(2);

    db.revision = 2;
    db.rows = [routeRow("provider-b", 0)];
    const third = await source.load({
      tenantId: "tenant-a",
      db: db.db,
      env,
      fallback: emptyFallback(),
    });
    expect(third.ok).toBe(true);
    if (!third.ok) return;
    expect(third.revision).toBe(2);
    expect(third.models.resolve("tenant-model")?.provider).toBe("provider-b");
    expect(db.catalogReads).toBe(2);
  });

  it("keeps cache entries and D1 bindings isolated by tenant", async () => {
    const db = fakeDb([routeRow("provider-a", 0)]);
    const source = new D1TenantModelCatalogSource();

    const first = await source.load({
      tenantId: "tenant-a",
      db: db.db,
      env: ENV,
      fallback: emptyFallback(),
    });
    db.rows = [routeRow("provider-b", 0)];
    const second = await source.load({
      tenantId: "tenant-b",
      db: db.db,
      env: ENV,
      fallback: emptyFallback(),
    });

    expect(first.ok && second.ok).toBe(true);
    if (!second.ok) return;
    expect(second.models.resolve("tenant-model")?.provider).toBe("provider-b");
    expect(db.catalogReads).toBe(2);
    expect(db.bindings).toEqual([["tenant-a"], ["tenant-a"], ["tenant-b"], ["tenant-b"]]);
  });

  it("never caches a D1 or catalog failure", async () => {
    const db = fakeDb([routeRow("provider-a", 0, { provider_kind: "unknown" })]);
    const source = new D1TenantModelCatalogSource();
    const env = ENV;

    const failed = await source.load({
      tenantId: "tenant-a",
      db: db.db,
      env,
      fallback: emptyFallback(),
    });
    expect(failed.ok).toBe(false);

    db.rows = [routeRow("provider-a", 0)];
    const recovered = await source.load({
      tenantId: "tenant-a",
      db: db.db,
      env,
      fallback: emptyFallback(),
    });
    expect(recovered.ok).toBe(true);
    expect(db.catalogReads).toBe(2);

    db.failCatalog = true;
    const unavailable = await source.load({
      tenantId: "tenant-a",
      db: db.db,
      env: { fresh: true },
      fallback: emptyFallback(),
    });
    expect(unavailable.ok).toBe(false);
  });
});
