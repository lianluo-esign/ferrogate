/**
 * `ControlDataPlatformModelCatalogSource` (#890) — the data-plane read of the
 * platform default catalog #889 gave a home in the CONTROL database.
 *
 * These are hermetic unit tests against a fake control database (no workerd): a
 * revision-gated, per-env cached read that is authoritative when platform rows
 * are present, falls to the env `fallback` when they are absent, serves the last
 * good catalog on a read failure without ever caching it, and — the second half
 * of #890 — feeds its parsed registry to the tenant loader so a tenant offering
 * on a `platform`-kind channel resolves to the platform physical leg, with env
 * winning only when the platform tables are empty.
 *
 * The whole file mutates `db.rows`/`db.revision`/`db.failCatalog` on a shared
 * state object and re-loads: every assertion below FAILS if the corresponding
 * behavior is inverted (a cached failure, a swallowed error, an ignored
 * revision bump, an env leg where a platform leg exists).
 */
import { describe, expect, it } from "vitest";
import { InMemoryModelResolver } from "../../src/inference/defaults.js";
import {
  ControlDataPlatformModelCatalogSource,
  platformModelCatalogFromControlData,
} from "../../src/inference/platform-catalog.js";
import type { ModelResolver, PhysicalRoute } from "../../src/inference/ports.js";
import { D1TenantModelCatalogSource } from "../../src/inference/tenant-catalog.js";

type CatalogRow = Record<string, unknown>;

interface FakeDatabase {
  db: D1Database;
  revision: number | null;
  rows: CatalogRow[];
  revisionReads: number;
  catalogReads: number;
  failRevision: boolean;
  failCatalog: boolean;
  missing: boolean;
}

/**
 * One fake control/tenant database. `prepare()` ignores the SQL because each
 * instance backs exactly one source: `.first()` answers the revision read and
 * `.all()` answers the catalog read. `.bind()` is a no-op passthrough so the
 * same object serves the platform source (no bind) and the tenant source (binds
 * a tenant id).
 */
function fakeDb(rows: CatalogRow[], revision: number | null = 2): FakeDatabase {
  const state: FakeDatabase = {
    db: undefined as unknown as D1Database,
    revision,
    rows,
    revisionReads: 0,
    catalogReads: 0,
    failRevision: false,
    failCatalog: false,
    missing: false,
  };
  const chain = {
    bind() {
      return chain;
    },
    async first<T>() {
      state.revisionReads += 1;
      if (state.missing) {
        throw new Error("D1_ERROR: no such table: main.platform_catalog_revisions");
      }
      if (state.failRevision) throw new Error("revision backend unavailable");
      return (state.revision === null ? null : { revision: state.revision }) as T;
    },
    async all<T>() {
      state.catalogReads += 1;
      if (state.missing) {
        throw new Error("D1_ERROR: no such table: main.platform_catalog_models");
      }
      if (state.failCatalog) throw new Error("catalog backend unavailable");
      return { results: state.rows as T[] };
    },
  };
  state.db = { prepare: () => chain } as unknown as D1Database;
  return state;
}

/** A platform join row with the shared `CatalogJoinRow` column shape. */
function routeRow(overrides: CatalogRow = {}): CatalogRow {
  return {
    model_id: "model-1",
    model_name: "platform-model",
    model_owned_by: "platform",
    model_capabilities_json: '["chat"]',
    model_context_window: 8192,
    model_routing_strategy: "priority",
    model_enabled: 1,
    offering_id: "offering-0",
    upstream_model_id: "gpt-4o-mini-2024-07-18",
    offering_role: "primary",
    offering_priority: 0,
    offering_weight: 1,
    canary_percent: null,
    shadow_percent: null,
    shadow_max_requests: null,
    offering_capabilities_json: null,
    offering_context_window: null,
    offering_region: null,
    offering_zero_data_retention: null,
    input_price_per_1m: 5,
    output_price_per_1m: 10,
    cached_input_price_per_1m: null,
    cache_write_price_per_1m: null,
    reasoning_price_per_1m: null,
    audio_second_price_per_1m: null,
    audio_character_price_per_1m: null,
    offering_enabled: 1,
    provider_id: "provider-0",
    provider_name: "platform-openai",
    provider_kind: "openai",
    provider_base_url: "https://api.openai.example/v1",
    provider_api_key_var: "PLATFORM_KEY",
    provider_byok_alias: null,
    provider_auth_scheme: null,
    provider_region: null,
    provider_zero_data_retention: null,
    provider_openrouter_http_referer: null,
    provider_openrouter_x_title: null,
    provider_cloudflare_ai_gateway_json: null,
    provider_enabled: 1,
    ...overrides,
  };
}

function controlEnv(
  db: FakeDatabase,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    GATEWAY_CONTROL_STORAGE: "d1_compat",
    CONTROL_DB: db.db,
    PLATFORM_KEY: "sk-platform",
    ...extra,
  };
}

function emptyFallback(): ModelResolver {
  return new InMemoryModelResolver([]);
}

const FALLBACK_ROUTE: PhysicalRoute = {
  logicalModel: "env-model",
  provider: "env-provider",
  providerModel: "env-upstream",
  providerKind: "openai",
  baseUrl: "https://env.test/v1",
  enabled: true,
};

describe("ControlDataPlatformModelCatalogSource", () => {
  it("projects the platform graph into a resolver and a parsed registry", async () => {
    const db = fakeDb([
      routeRow(),
      routeRow({
        offering_id: "offering-1",
        offering_role: "fallback",
        offering_priority: 10,
        provider_id: "provider-1",
        provider_name: "platform-anthropic",
        provider_kind: "anthropic",
        provider_base_url: "https://api.anthropic.example/v1",
        provider_api_key_var: "PLATFORM_KEY",
        upstream_model_id: "claude-3-5-sonnet",
      }),
    ]);
    const source = new ControlDataPlatformModelCatalogSource();

    const loaded = await source.load({ env: controlEnv(db), fallback: emptyFallback() });

    expect(loaded.ok).toBe(true);
    if (!loaded.ok) return;
    const primary = loaded.models.resolve("platform-model");
    expect(primary).toMatchObject({
      provider: "platform-openai",
      providerModel: "gpt-4o-mini-2024-07-18",
      inputPricePer1m: 5,
    });
    expect(loaded.models.candidates?.("platform-model").map((r) => r.provider)).toEqual([
      "platform-openai",
      "platform-anthropic",
    ]);
    // The parsed registry the tenant loader consumes for its `platform` arm.
    expect(loaded.inputs.models.map((m) => m.name)).toEqual(["platform-model"]);
    expect(loaded.inputs.providers.map((p) => p.name).sort()).toEqual([
      "platform-anthropic",
      "platform-openai",
    ]);
    expect(loaded.revision).toBe(2);
  });

  it("reuses a same-revision catalog and reloads immediately after a revision bump", async () => {
    const db = fakeDb([routeRow()]);
    const source = new ControlDataPlatformModelCatalogSource({ now: () => 1000 });
    const env = controlEnv(db);

    const first = await source.load({ env, fallback: emptyFallback() });
    const second = await source.load({ env, fallback: emptyFallback() });
    expect(first.ok && second.ok).toBe(true);
    expect(db.catalogReads).toBe(1);
    expect(db.revisionReads).toBe(2);

    // A price edit bumps the revision in the same batch (see #889's store), so
    // it is visible on the very next load — no isolate restart, no TTL wait.
    db.revision = 3;
    db.rows = [routeRow({ input_price_per_1m: 7 })];
    const third = await source.load({ env, fallback: emptyFallback() });
    expect(third.ok).toBe(true);
    if (!third.ok) return;
    expect(third.revision).toBe(3);
    expect(third.models.resolve("platform-model")?.inputPricePer1m).toBe(7);
    expect(db.catalogReads).toBe(2);
  });

  it("bounds staleness by the TTL when an edit forgets to bump the revision", async () => {
    const clock = { now: 1000 };
    const db = fakeDb([routeRow({ input_price_per_1m: 5 })]);
    const source = new ControlDataPlatformModelCatalogSource({
      ttlMs: 5_000,
      now: () => clock.now,
    });
    const env = controlEnv(db);

    const first = await source.load({ env, fallback: emptyFallback() });
    expect(first.ok && first.ok && first.models.resolve("platform-model")?.inputPricePer1m).toBe(5);

    // Same revision, changed rows: within the TTL the cache still answers 5.
    db.rows = [routeRow({ input_price_per_1m: 9 })];
    clock.now = 1000 + 4_999;
    const cached = await source.load({ env, fallback: emptyFallback() });
    expect(cached.ok && cached.models.resolve("platform-model")?.inputPricePer1m).toBe(5);
    expect(db.catalogReads).toBe(1);

    // Past the TTL the read is retried and the new value surfaces.
    clock.now = 1000 + 5_001;
    const refreshed = await source.load({ env, fallback: emptyFallback() });
    expect(refreshed.ok && refreshed.models.resolve("platform-model")?.inputPricePer1m).toBe(9);
    expect(db.catalogReads).toBe(2);
  });

  it("serves the last good catalog on a read failure and never caches it", async () => {
    const clock = { now: 1000 };
    const db = fakeDb([routeRow({ input_price_per_1m: 5 })]);
    const source = new ControlDataPlatformModelCatalogSource({
      ttlMs: 5_000,
      now: () => clock.now,
    });
    const env = controlEnv(db);

    const warm = await source.load({ env, fallback: emptyFallback() });
    expect(warm.ok).toBe(true);

    // The control object goes unavailable; the cache is stale by TTL so a read
    // is attempted, fails, and the LAST GOOD catalog is served — not an empty
    // one and not the env fallback.
    db.failCatalog = true;
    clock.now = 1000 + 6_000;
    const stale = await source.load({ env, fallback: new InMemoryModelResolver([FALLBACK_ROUTE]) });
    expect(stale.ok).toBe(true);
    if (!stale.ok) return;
    expect(stale.models.resolve("platform-model")?.inputPricePer1m).toBe(5);
    expect(stale.models.resolve("env-model")).toBeNull();
    const readsAfterStale = db.catalogReads;

    // The failure was NOT cached: the next request retries the backend rather
    // than serving a memoized error.
    clock.now = 1000 + 7_000;
    const retry = await source.load({ env, fallback: emptyFallback() });
    expect(retry.ok).toBe(true);
    expect(db.catalogReads).toBe(readsAfterStale + 1);

    // And once the backend recovers, the fresh catalog is picked up.
    db.failCatalog = false;
    db.revision = 3;
    db.rows = [routeRow({ input_price_per_1m: 8 })];
    clock.now = 1000 + 8_000;
    const recovered = await source.load({ env, fallback: emptyFallback() });
    expect(recovered.ok && recovered.models.resolve("platform-model")?.inputPricePer1m).toBe(8);
  });

  it("refuses when a read fails and there is no last good catalog", async () => {
    const db = fakeDb([routeRow()]);
    db.failCatalog = true;
    const source = new ControlDataPlatformModelCatalogSource();

    const loaded = await source.load({ env: controlEnv(db), fallback: emptyFallback() });
    expect(loaded.ok).toBe(false);
    if (loaded.ok) return;
    expect(loaded.reason).toMatch(/platform catalog read failed/);
  });

  it("refuses when the revision read fails and there is no last good catalog", async () => {
    const db = fakeDb([routeRow()]);
    db.failRevision = true;
    const source = new ControlDataPlatformModelCatalogSource();

    const loaded = await source.load({ env: controlEnv(db), fallback: emptyFallback() });
    expect(loaded.ok).toBe(false);
    if (loaded.ok) return;
    expect(loaded.reason).toMatch(/platform catalog revision read failed/);
  });

  it("treats a missing platform table as bootstrap and serves the env fallback", async () => {
    const db = fakeDb([routeRow()]);
    db.missing = true;
    const fallback = new InMemoryModelResolver([FALLBACK_ROUTE]);
    const source = new ControlDataPlatformModelCatalogSource();

    const loaded = await source.load({ env: controlEnv(db), fallback });
    expect(loaded.ok).toBe(true);
    if (!loaded.ok) return;
    expect(loaded.models).toBe(fallback);
    expect(loaded.inputs.models).toHaveLength(0);
    // Migration lag is not a failure: no exception, no refusal.
    expect(loaded.models.resolve("env-model")?.provider).toBe("env-provider");
  });

  it("serves the env fallback when the catalog is adopted but empty", async () => {
    const db = fakeDb([], 4);
    const fallback = new InMemoryModelResolver([FALLBACK_ROUTE]);
    const source = new ControlDataPlatformModelCatalogSource();

    const loaded = await source.load({ env: controlEnv(db), fallback });
    expect(loaded).toMatchObject({ ok: true, models: fallback, revision: 4 });
    if (!loaded.ok) return;
    expect(loaded.inputs.models).toHaveLength(0);
    expect(db.catalogReads).toBe(1);
  });

  it("serves the env fallback when no control database is bound", async () => {
    const fallback = new InMemoryModelResolver([FALLBACK_ROUTE]);
    const source = new ControlDataPlatformModelCatalogSource();

    const loaded = await source.load({
      env: { GATEWAY_CONTROL_STORAGE: "d1_compat" },
      fallback,
    });
    expect(loaded.ok).toBe(true);
    if (!loaded.ok) return;
    expect(loaded.models).toBe(fallback);
    expect(loaded.inputs.models).toHaveLength(0);
  });

  it("propagates the 503 refusal on an unrecognized control-storage posture", async () => {
    const source = platformModelCatalogFromControlData();
    await expect(
      source.load({ env: { GATEWAY_CONTROL_STORAGE: "bogus" }, fallback: emptyFallback() }),
    ).rejects.toMatchObject({ status: 503, code: "control_storage_misconfigured" });
  });
});

// ---------------------------------------------------------------------------
// The tenant `platform`-kind arm resolves against the platform catalog (#890).
// ---------------------------------------------------------------------------

/** A tenant join row whose provider is the `platform` indirection. */
function tenantPlatformRow(overrides: CatalogRow = {}): CatalogRow {
  return {
    ...routeRow({
      model_name: "shared-model",
      provider_kind: "platform",
      provider_base_url: "platform://default",
      provider_api_key_var: null,
      upstream_model_id: "tenant-upstream",
      input_price_per_1m: 42,
    }),
    ...overrides,
  };
}

const ENV_REGISTRY = {
  GATEWAY_PROVIDERS: JSON.stringify([
    {
      name: "env-provider",
      kind: "openai",
      base_url: "https://env.test/v1",
      api_key_var: "ENV_KEY",
    },
  ]),
  GATEWAY_MODELS: JSON.stringify([
    { name: "shared-model", provider: "env-provider", provider_model: "env-upstream" },
  ]),
  ENV_KEY: "env-secret",
};

describe("tenant platform-kind arm against the platform catalog", () => {
  it("resolves a tenant platform-kind offering to the platform physical leg when both exist", async () => {
    const platformDb = fakeDb([
      routeRow({
        model_name: "shared-model",
        provider_name: "platform-openai",
        upstream_model_id: "platform-upstream",
      }),
    ]);
    const platform = new ControlDataPlatformModelCatalogSource();
    const platformLoaded = await platform.load({
      env: controlEnv(platformDb),
      fallback: emptyFallback(),
    });
    expect(platformLoaded.ok).toBe(true);
    if (!platformLoaded.ok) return;

    const tenantDb = fakeDb([tenantPlatformRow()]);
    const tenant = new D1TenantModelCatalogSource();
    const loaded = await tenant.load({
      tenantId: "tenant-a",
      db: tenantDb.db,
      // Env ALSO supplies `shared-model`, so a green result that read env would
      // point at `env-provider`; platform must win.
      env: { ...controlEnv(platformDb), ...ENV_REGISTRY },
      fallback: emptyFallback(),
      platformInputs: platformLoaded.inputs,
    });

    expect(loaded.ok).toBe(true);
    if (!loaded.ok) return;
    expect(loaded.models.resolve("shared-model")).toMatchObject({
      provider: "platform-openai",
      // The tenant offering's own upstream id still wins over the platform one.
      providerModel: "tenant-upstream",
    });
  });

  it("falls back to the env registry when the platform tables are empty", async () => {
    const tenantDb = fakeDb([tenantPlatformRow()]);
    const tenant = new D1TenantModelCatalogSource();

    const loaded = await tenant.load({
      tenantId: "tenant-a",
      db: tenantDb.db,
      env: ENV_REGISTRY,
      fallback: emptyFallback(),
      // Empty platform registry ⇒ the pre-#890 env behavior.
      platformInputs: { providers: [], models: [] },
    });

    expect(loaded.ok).toBe(true);
    if (!loaded.ok) return;
    expect(loaded.models.resolve("shared-model")).toMatchObject({
      provider: "env-provider",
      providerModel: "tenant-upstream",
    });
  });
});
