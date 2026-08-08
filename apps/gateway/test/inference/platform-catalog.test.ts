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
import { controlNamespaceOverD1 } from "../support/control-namespace.js";
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
  // Zero-D1 S5 (#881): the source reads through the CONTROL_DATA facade, which
  // routes BOTH `.first()` (revision) and `.all()` (catalog) through one object
  // `query` RPC. The fake therefore distinguishes the two reads by SQL rather
  // than by method: the revision statement mentions `platform_catalog_revisions`.
  const revisionResult = (): CatalogRow[] => {
    state.revisionReads += 1;
    if (state.missing) {
      throw new Error("D1_ERROR: no such table: main.platform_catalog_revisions");
    }
    if (state.failRevision) throw new Error("revision backend unavailable");
    return state.revision === null ? [] : [{ revision: state.revision }];
  };
  const catalogResult = (): CatalogRow[] => {
    state.catalogReads += 1;
    if (state.missing) {
      throw new Error("D1_ERROR: no such table: main.platform_catalog_models");
    }
    if (state.failCatalog) throw new Error("catalog backend unavailable");
    return state.rows;
  };
  // The tenant source reads this handle DIRECTLY, distinguishing revision from
  // catalog by method (`.first()` vs `.all()`). The platform source reads it
  // through the CONTROL_DATA facade, which routes both through one `query`
  // (a `.all()` on this fake), so the revision read is disambiguated by SQL.
  const chainFor = (sql: string) => ({
    bind() {
      return chainFor(sql);
    },
    async first<T>() {
      return (revisionResult()[0] ?? null) as T;
    },
    async all<T>() {
      const isRevision = sql.includes("platform_catalog_revisions");
      return { results: (isRevision ? revisionResult() : catalogResult()) as T[] };
    },
  });
  state.db = { prepare: (sql: string) => chainFor(sql) } as unknown as D1Database;
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
    // Zero-D1 S5 (#881): the catalog source reads the CONTROL_DATA object. The
    // fixture DB is adapted into a namespace double so the resolver reads it
    // through the same facade production uses.
    CONTROL_DATA: controlNamespaceOverD1(db.db),
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

  it("routes a platform provider through AI Gateway using the GATEWAY_CLOUDFLARE account block", async () => {
    // #889's CRUD legitimately persists a platform provider with a
    // `cloudflare_ai_gateway` block. The account id / base URLs it needs live in
    // the deployment's `GATEWAY_CLOUDFLARE` var, not the CONTROL tables, so the
    // platform loader must thread that account block into the build exactly as the
    // tenant loader does — otherwise cloudflareAiGatewayRouting sees no account and
    // fails the WHOLE platform catalog, a deployment-wide 503.
    const db = fakeDb([
      routeRow({ provider_cloudflare_ai_gateway_json: JSON.stringify({ gateway_id: "gw-plat" }) }),
    ]);
    const source = new ControlDataPlatformModelCatalogSource();

    const loaded = await source.load({
      env: controlEnv(db, { GATEWAY_CLOUDFLARE: JSON.stringify({ account_id: "acct-123" }) }),
      fallback: emptyFallback(),
    });

    expect(loaded.ok).toBe(true);
    if (!loaded.ok) return;
    // The routing is present and carries the env account id — proof the account
    // block flowed through, not just that the build stopped failing.
    expect(loaded.models.resolve("platform-model")?.cloudflareAiGateway).toMatchObject({
      accountId: "acct-123",
      gatewayId: "gw-plat",
    });
  });

  it("fails the platform catalog closed when a cloudflare provider lacks the account block", async () => {
    const db = fakeDb([
      routeRow({ provider_cloudflare_ai_gateway_json: JSON.stringify({ gateway_id: "gw-plat" }) }),
    ]);
    const source = new ControlDataPlatformModelCatalogSource();

    // No GATEWAY_CLOUDFLARE: the provider that asked to be routed cannot be, so
    // the build refuses (fail-closed) rather than silently dropping the routing.
    const loaded = await source.load({ env: controlEnv(db), fallback: emptyFallback() });

    expect(loaded.ok).toBe(false);
    if (loaded.ok) return;
    expect(loaded.reason).toMatch(/GATEWAY_CLOUDFLARE/);
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
    expect(loaded).toMatchObject({ ok: true, revision: 4 });
    if (!loaded.ok) return;
    // `toBe(fallback)`, not `toMatchObject({ models: fallback })`: the resolver's
    // only field is a private `#routes`, so a structural match compares zero
    // enumerable properties and would pass for ANY resolver (even an empty one).
    // A strict reference check is the only assertion that actually pins the env
    // fallback being served for the adopted-but-empty catalog.
    expect(loaded.models).toBe(fallback);
    expect(loaded.models.resolve("env-model")?.provider).toBe("env-provider");
    expect(loaded.inputs.models).toHaveLength(0);
    expect(db.catalogReads).toBe(1);
  });

  it("serves the env fallback when the catalog holds ONLY rate-card price rows (#892)", async () => {
    // The bootstrap import (#892) can write ONLY `kind='platform'` price rows —
    // e.g. an import with no env providers/models but the default rate card on.
    // Those rows carry prices but name no routable upstream. `rows.length > 0`,
    // so a raw-count presence gate would treat the catalog as authoritative and
    // shadow env with the EMPTY resolver the filter leaves behind — a
    // deployment-wide 404. The presence decision must be made AFTER excluding
    // the price rows, so this rate-card-only catalog falls to env.
    const rateCardRow = routeRow({
      model_name: "gpt-4o",
      provider_name: "platform-default",
      provider_kind: "platform",
      provider_base_url: "platform://default",
      provider_api_key_var: null,
    });
    const db = fakeDb([rateCardRow], 7);
    const fallback = new InMemoryModelResolver([FALLBACK_ROUTE]);
    const source = new ControlDataPlatformModelCatalogSource();

    const loaded = await source.load({ env: controlEnv(db), fallback });
    expect(loaded).toMatchObject({ ok: true, revision: 7 });
    if (!loaded.ok) return;
    // Strict reference: the env fallback is served, not a build over zero rows.
    expect(loaded.models).toBe(fallback);
    expect(loaded.models.resolve("env-model")?.provider).toBe("env-provider");
    // The rate-card model does NOT become a phantom (route-less) authoritative model.
    expect(loaded.models.resolve("gpt-4o")).toBeNull();
    expect(loaded.inputs.models).toHaveLength(0);
  });

  it("serves the env fallback when no control database is bound", async () => {
    const fallback = new InMemoryModelResolver([FALLBACK_ROUTE]);
    const source = new ControlDataPlatformModelCatalogSource();

    const loaded = await source.load({
      env: {},
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

  it("re-resolves a tenant platform-kind leg within the TTL when the platform revision bumps", async () => {
    // #890 revision-gate: a platform-catalog edit bumps the platform revision to
    // force IMMEDIATE visibility. A tenant using a platform-default model must see
    // the new leg on its next load, not wait out its own 5s TTL. The tenant cache
    // key therefore folds in the platform revision.
    const clock = { now: 1000 };
    const platformSource = new ControlDataPlatformModelCatalogSource({ now: () => clock.now });

    // Platform catalog rev 10: shared-model -> platform-a.
    const platformA = await platformSource.load({
      env: controlEnv(
        fakeDb(
          [
            routeRow({
              model_name: "shared-model",
              provider_name: "platform-a",
              upstream_model_id: "upstream-a",
            }),
          ],
          10,
        ),
      ),
      fallback: emptyFallback(),
    });
    expect(platformA.ok).toBe(true);
    if (!platformA.ok) return;

    const tenantDb = fakeDb([tenantPlatformRow()]);
    const tenant = new D1TenantModelCatalogSource({ now: () => clock.now });
    // ONE env object across both loads: the tenant cache is keyed on it, so a new
    // object per call would make this test vacuous (always a cache miss). Its
    // PLATFORM_KEY secret satisfies both platform providers' api_key_var.
    const tenantEnv = controlEnv(tenantDb);

    const first = await tenant.load({
      tenantId: "tenant-a",
      db: tenantDb.db,
      env: tenantEnv,
      fallback: emptyFallback(),
      platformInputs: platformA.inputs,
      platformRevision: platformA.revision,
    });
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    expect(first.models.resolve("shared-model")?.provider).toBe("platform-a");
    expect(tenantDb.catalogReads).toBe(1);

    // Operator edits the platform catalog: shared-model -> platform-b, rev 11.
    const platformB = await platformSource.load({
      env: controlEnv(
        fakeDb(
          [
            routeRow({
              model_name: "shared-model",
              provider_name: "platform-b",
              upstream_model_id: "upstream-b",
            }),
          ],
          11,
        ),
      ),
      fallback: emptyFallback(),
    });
    expect(platformB.ok).toBe(true);
    if (!platformB.ok) return;

    // Same tenant revision, same clock (well inside the TTL), same env object: the
    // tenant revision alone would keep serving the cached platform-a leg. Only the
    // platform revision changed (10 -> 11) — it must invalidate and re-resolve.
    const second = await tenant.load({
      tenantId: "tenant-a",
      db: tenantDb.db,
      env: tenantEnv,
      fallback: emptyFallback(),
      platformInputs: platformB.inputs,
      platformRevision: platformB.revision,
    });
    expect(second.ok).toBe(true);
    if (!second.ok) return;
    expect(second.models.resolve("shared-model")?.provider).toBe("platform-b");
    expect(tenantDb.catalogReads).toBe(2);
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
