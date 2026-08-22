import { SELF, env } from "cloudflare:test";
/**
 * Provider model-list sync (#944) — `POST /admin/v1/providers/{id}/sync-models`.
 *
 * The upstream `GET /v1/models` is STUBBED by injecting a `fetchImpl` into the
 * exported {@link syncProviderModelsIntoCatalog}, driven against a REAL control
 * database (`applySchema`/`db`). pool-workers 0.18.8 ships no fetch mock and an
 * app-level `SELF.fetch` cannot intercept the Worker's OUTBOUND `/v1/models`
 * call, so the three model-count invariants the issue names are proven on the
 * helper directly, and only the platform-operator FENCE — which returns before
 * any upstream fetch — is proven through the mounted route with `SELF.fetch`.
 *
 * The invariants:
 *   1. first sync ADDS every upstream model as a real offering, binding an exact
 *      public-model price where one exists and leaving the others unpriced;
 *   2. a second sync is IDEMPOTENT — nothing added, every model skipped, only the
 *      revision moves;
 *   3. a model the upstream DROPS is reported (skipped/absent), never deleted.
 */
import { PriceBook } from "@ferrogate/billing";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { CallerScope } from "../src/ports.js";
import { PlatformModelCatalogStore } from "../src/store/platform-model-catalog.js";
import {
  ProviderModelSyncError,
  fetchUpstreamModels,
  syncProviderModelsIntoCatalog,
} from "../src/store/platform-provider-sync.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, OPERATOR_KEY, arm, bearer, operatorKey, tenantKey } from "./harness.js";

const DEFAULT_CONTROL_STORAGE = "durable_object";
const PLATFORM_SCOPE: CallerScope = { kind: "platform_operator" };
const PROVIDER_ID = "platform:provider:openai";

function controlStorage(mode: string): void {
  (env as unknown as Record<string, string | undefined>).CONTROL_PLANE_CONTROL_STORAGE = mode;
}

/** Seed one platform provider channel with raw SQL, as the operator CRUD would. */
async function seedProvider(apiKeyVar: string | null): Promise<void> {
  await db()
    .prepare(
      `INSERT INTO platform_provider_channels
         (id, name, kind, base_url, api_key_var, enabled, created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, ?, ?, 1, 0, 0)`,
    )
    .bind(PROVIDER_ID, "openai", "openai-compatible", "https://api.openai.example/v1", apiKeyVar)
    .run();
}

/** Seed a second, arbitrary platform provider channel (for the multi-provider path). */
async function seedNamedProvider(
  id: string,
  name: string,
  kind: string,
  baseUrl: string,
  apiKeyVar: string | null,
): Promise<void> {
  await db()
    .prepare(
      `INSERT INTO platform_provider_channels
         (id, name, kind, base_url, api_key_var, enabled, created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, ?, ?, 1, 0, 0)`,
    )
    .bind(id, name, kind, baseUrl, apiKeyVar)
    .run();
}

/** The `(role, provider_id)` of one offering row, by its deterministic id. */
async function offeringRole(id: string): Promise<{ role: string; provider_id: string } | null> {
  return db()
    .prepare("SELECT role, provider_id FROM platform_catalog_offerings WHERE id = ?")
    .bind(id)
    .first<{ role: string; provider_id: string }>();
}

/** A stub `/v1/models` fetch that records how it was called and answers `data`. */
function stubModels(data: ReadonlyArray<{ id: string; owned_by?: string }>): {
  fetchImpl: typeof fetch;
  calls: Array<{ url: string; headers: Record<string, string> }>;
} {
  const calls: Array<{ url: string; headers: Record<string, string> }> = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init?.headers ?? {}) as Record<string, string>)) {
      headers[k.toLowerCase()] = v;
    }
    calls.push({ url: String(input), headers });
    return new Response(JSON.stringify({ object: "list", data }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

async function tableCount(table: string): Promise<number> {
  const row = await db().prepare(`SELECT COUNT(*) AS n FROM ${table}`).first<{ n: number }>();
  return Number(row?.n ?? 0);
}

async function seedPublicPrice(modelKey: string, aliases: readonly string[] = []): Promise<string> {
  const id = `public:model:${modelKey}`;
  await db()
    .prepare(
      `INSERT INTO platform_model_prices
         (id, model_key, name, aliases_json, source_type, input_price_per_1m, output_price_per_1m,
          currency, enabled, created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, ?, 'models_dev', 10, 50, 'USD', 1, 0, 0)`,
    )
    .bind(id, modelKey, modelKey, JSON.stringify([modelKey, ...aliases]))
    .run();
  return id;
}

async function offering(id: string): Promise<{
  provider_id: string;
  source: string;
  pricing_model_id: string | null;
  input_price_per_1m: number | null;
} | null> {
  return db()
    .prepare(
      `SELECT provider_id, source, pricing_model_id, input_price_per_1m
         FROM platform_catalog_offerings WHERE id = ?`,
    )
    .bind(id)
    .first<{
      provider_id: string;
      source: string;
      pricing_model_id: string | null;
      input_price_per_1m: number | null;
    }>();
}

beforeAll(async () => {
  await applySchema();
});

beforeEach(async () => {
  controlStorage(DEFAULT_CONTROL_STORAGE);
  await resetD1();
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [tenantKey("tenant-secret", "tenant_a")],
  });
});

afterEach(() => {
  controlStorage(DEFAULT_CONTROL_STORAGE);
});

describe("provider model-list sync (#944)", () => {
  it("first sync binds exact public pricing and leaves unmatched models unpriced", async () => {
    await seedProvider("OPENAI_KEY");
    const publicPriceId = await seedPublicPrice("gpt-4o");
    const store = new PlatformModelCatalogStore({ db: db() });
    const provider = await store.getProviderSeed(PROVIDER_ID);
    expect(provider, "getProviderSeed must return the raw row with api_key_var").not.toBeNull();
    // getProviderSeed carries the credential REFERENCE, unlike the masked getProvider.
    expect(provider?.api_key_var).toBe("OPENAI_KEY");

    // Only `gpt-4o` exists in the public catalog. Matching is exact.
    const { fetchImpl, calls } = stubModels([
      { id: "gpt-4o", owned_by: "openai" },
      { id: "gpt-4o-mini" },
      { id: "o1" },
    ]);
    const result = await syncProviderModelsIntoCatalog({
      store,
      scope: PLATFORM_SCOPE,
      provider: provider!,
      apiKey: "sk-live-123",
      priceBook: PriceBook.withDefaultRateCard(),
      fetchImpl,
    });

    expect(result.added).toBe(3);
    expect(result.updated).toBe(0);
    expect(result.skipped).toBe(0);
    expect(result.upstreamCount).toBe(3);
    expect(result.revision).toBe(1);

    // The upstream call hit base_url + "/models" with the resolved bearer key.
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe("https://api.openai.example/v1/models");
    expect(calls[0]?.headers.authorization).toBe("Bearer sk-live-123");

    expect(await tableCount("platform_catalog_models")).toBe(3);
    expect(await tableCount("platform_catalog_offerings")).toBe(3);

    // Provider sync stores no copied price. It binds only the exact public model.
    const priced = await offering("platform:offering:gpt-4o:openai:gpt-4o");
    expect(priced?.provider_id).toBe(PROVIDER_ID);
    expect(priced?.source).toBe("provider_sync");
    expect(priced?.pricing_model_id).toBe(publicPriceId);
    expect(priced?.input_price_per_1m).toBeNull();
    const unpriced = await offering("platform:offering:o1:openai:o1");
    expect(unpriced?.pricing_model_id).toBeNull();
    expect(unpriced?.input_price_per_1m).toBeNull();
    expect(unpriced?.source).toBe("provider_sync");
  });

  it("binds a hosted provider model through the public model alias", async () => {
    await seedProvider("OPENAI_KEY");
    const publicPriceId = await seedPublicPrice("gpt-5.5", ["openai/gpt-5.5"]);
    const store = new PlatformModelCatalogStore({ db: db() });
    const provider = await store.getProviderSeed(PROVIDER_ID);

    await syncProviderModelsIntoCatalog({
      store,
      scope: PLATFORM_SCOPE,
      provider: provider!,
      apiKey: "sk-live-123",
      priceBook: PriceBook.withDefaultRateCard(),
      fetchImpl: stubModels([{ id: "openai/gpt-5.5" }]).fetchImpl,
    });

    const bound = await offering("platform:offering:openai/gpt-5.5:openai:openai/gpt-5.5");
    expect(bound?.pricing_model_id).toBe(publicPriceId);
    expect(bound?.input_price_per_1m).toBeNull();
  });

  it("is idempotent: a re-sync adds nothing, skips all, and only bumps the revision", async () => {
    await seedProvider(null);
    const store = new PlatformModelCatalogStore({ db: db() });
    const provider = await store.getProviderSeed(PROVIDER_ID);
    const models = [{ id: "gpt-4o" }, { id: "gpt-4o-mini" }];

    const first = await syncProviderModelsIntoCatalog({
      store,
      scope: PLATFORM_SCOPE,
      provider: provider!,
      priceBook: PriceBook.withDefaultRateCard(),
      fetchImpl: stubModels(models).fetchImpl,
    });
    expect(first.added).toBe(2);
    expect(first.revision).toBe(1);
    const modelsAfterFirst = await tableCount("platform_catalog_models");
    const offeringsAfterFirst = await tableCount("platform_catalog_offerings");

    const second = await syncProviderModelsIntoCatalog({
      store,
      scope: PLATFORM_SCOPE,
      provider: provider!,
      priceBook: PriceBook.withDefaultRateCard(),
      fetchImpl: stubModels(models).fetchImpl,
    });
    expect(second.added).toBe(0);
    expect(second.skipped).toBe(2);
    expect(second.updated).toBe(0);
    // The revision moves even on a no-op (an operator action is audited), but no
    // row was inserted.
    expect(second.revision).toBe(2);
    expect(await tableCount("platform_catalog_models")).toBe(modelsAfterFirst);
    expect(await tableCount("platform_catalog_offerings")).toBe(offeringsAfterFirst);
  });

  it("a second provider serving the same model lands as a fallback, not a silent drop", async () => {
    // openai and azure-openai both serve gpt-4o. The catalog allows ONE primary
    // offering per model_id, and model_id is keyed on the model NAME, so the two
    // share a model row. The pre-fix builder wrote both as `primary`: azure's
    // INSERT OR IGNORE collided with openai's primary and was dropped ({added:0,
    // skipped:1}) behind a 200. The fix demotes azure's leg to a routable
    // `fallback`, so it is actually inserted and honestly counted.
    await seedProvider("OPENAI_KEY");
    const PROVIDER_B = "platform:provider:azure-openai";
    await seedNamedProvider(
      PROVIDER_B,
      "azure-openai",
      "openai-compatible",
      "https://azure.example/v1",
      "AZURE_KEY",
    );
    const store = new PlatformModelCatalogStore({ db: db() });
    const providerA = await store.getProviderSeed(PROVIDER_ID);
    const providerB = await store.getProviderSeed(PROVIDER_B);

    const a = await syncProviderModelsIntoCatalog({
      store,
      scope: PLATFORM_SCOPE,
      provider: providerA!,
      priceBook: PriceBook.withDefaultRateCard(),
      fetchImpl: stubModels([{ id: "gpt-4o" }]).fetchImpl,
    });
    expect(a.added).toBe(1);
    expect(a.skipped).toBe(0);

    const b = await syncProviderModelsIntoCatalog({
      store,
      scope: PLATFORM_SCOPE,
      provider: providerB!,
      priceBook: PriceBook.withDefaultRateCard(),
      fetchImpl: stubModels([{ id: "gpt-4o" }]).fetchImpl,
    });
    // The load-bearing assertion: azure's gpt-4o is ADDED (as a fallback), not
    // swallowed and mislabelled skipped. Inverting the fix (role back to
    // 'primary') turns this red — added 0, skipped 1, offering count 1.
    expect(b.added).toBe(1);
    expect(b.skipped).toBe(0);
    expect(b.upstreamCount).toBe(1);

    // One shared model row; BOTH providers' offerings persist and route.
    expect(await tableCount("platform_catalog_models")).toBe(1);
    expect(await tableCount("platform_catalog_offerings")).toBe(2);

    const primary = await offeringRole("platform:offering:gpt-4o:openai:gpt-4o");
    expect(primary?.role).toBe("primary");
    expect(primary?.provider_id).toBe(PROVIDER_ID);
    const fallback = await offeringRole("platform:offering:gpt-4o:azure-openai:gpt-4o");
    expect(fallback, "the second provider's offering must exist, not be dropped").not.toBeNull();
    expect(fallback?.role).toBe("fallback");
    expect(fallback?.provider_id).toBe(PROVIDER_B);

    // Re-syncing the second provider is a no-op: its fallback already exists.
    const reB = await syncProviderModelsIntoCatalog({
      store,
      scope: PLATFORM_SCOPE,
      provider: providerB!,
      priceBook: PriceBook.withDefaultRateCard(),
      fetchImpl: stubModels([{ id: "gpt-4o" }]).fetchImpl,
    });
    expect(reB.added).toBe(0);
    expect(reB.skipped).toBe(1);
    expect(await tableCount("platform_catalog_offerings")).toBe(2);
  });

  it("no api_key_var means no auth header (unauthenticated upstream)", async () => {
    await seedProvider(null);
    const store = new PlatformModelCatalogStore({ db: db() });
    const provider = await store.getProviderSeed(PROVIDER_ID);
    const { fetchImpl, calls } = stubModels([{ id: "local-model" }]);
    await syncProviderModelsIntoCatalog({
      store,
      scope: PLATFORM_SCOPE,
      provider: provider!,
      priceBook: PriceBook.withDefaultRateCard(),
      fetchImpl,
    });
    expect(calls[0]?.headers.authorization).toBeUndefined();
    expect(calls[0]?.headers["x-api-key"]).toBeUndefined();
  });

  it("a dropped upstream model is reported, not deleted", async () => {
    await seedProvider(null);
    const store = new PlatformModelCatalogStore({ db: db() });
    const provider = await store.getProviderSeed(PROVIDER_ID);

    await syncProviderModelsIntoCatalog({
      store,
      scope: PLATFORM_SCOPE,
      provider: provider!,
      priceBook: PriceBook.withDefaultRateCard(),
      fetchImpl: stubModels([{ id: "gpt-4o" }, { id: "gpt-4o-mini" }, { id: "o1" }]).fetchImpl,
    });
    expect(await tableCount("platform_catalog_offerings")).toBe(3);

    // The upstream drops `o1`. The sync sees only the two remaining, both already
    // present -> added 0, skipped 2; `o1` is neither reported nor removed.
    const dropped = await syncProviderModelsIntoCatalog({
      store,
      scope: PLATFORM_SCOPE,
      provider: provider!,
      priceBook: PriceBook.withDefaultRateCard(),
      fetchImpl: stubModels([{ id: "gpt-4o" }, { id: "gpt-4o-mini" }]).fetchImpl,
    });
    expect(dropped.added).toBe(0);
    expect(dropped.skipped).toBe(2);
    expect(dropped.upstreamCount).toBe(2);

    // `o1`'s rows survive the sync that dropped it from the upstream list.
    expect(await tableCount("platform_catalog_offerings")).toBe(3);
    const survivor = await offering("platform:offering:o1:openai:o1");
    expect(survivor, "a dropped upstream model must not be deleted").not.toBeNull();
  });

  it("fences a tenant-scoped caller with 403 before any upstream fetch", async () => {
    await seedProvider(null);
    const response = await SELF.fetch(`${BASE}/admin/v1/providers/${PROVIDER_ID}/sync-models`, {
      method: "POST",
      headers: bearer("tenant-secret"),
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { error?: unknown };
    expect(body.error).toBeDefined();
    // Nothing was written: the fence returns before the store is reached.
    expect(await tableCount("platform_catalog_offerings")).toBe(0);
  });

  it("fails closed 502 when a named credential is unbound, writing nothing", async () => {
    // `api_key_var` names an env slot that is NOT bound in the test Worker env,
    // so resolveProviderSecret returns {ok:false} and the handler must refuse
    // (502 provider_credential_unresolved) BEFORE any upstream fetch — the
    // fail-closed rule, exercised through the mounted route as an operator.
    await seedProvider("SYNC_MODELS_UNBOUND_SECRET_XYZ");
    const response = await SELF.fetch(`${BASE}/admin/v1/providers/${PROVIDER_ID}/sync-models`, {
      method: "POST",
      headers: bearer(OPERATOR_KEY),
    });
    expect(response.status).toBe(502);
    const body = (await response.json()) as { error?: { code?: string } };
    expect(body.error?.code).toBe("provider_credential_unresolved");
    expect(await tableCount("platform_catalog_offerings")).toBe(0);
  });
});

describe("fetchUpstreamModels upstream-failure mapping (#944)", () => {
  const provider = {
    kind: "openai-compatible",
    base_url: "https://up.example/v1",
    auth_scheme: null,
  } as const;

  it("a fetch that throws maps to 502 provider_unreachable", async () => {
    const fetchImpl = (async () => {
      throw new Error("connect ECONNREFUSED");
    }) as unknown as typeof fetch;
    await expect(fetchUpstreamModels({ provider, fetchImpl })).rejects.toMatchObject({
      status: 502,
      code: "provider_unreachable",
    });
  });

  it("a non-2xx response maps to 502 provider_models_unavailable", async () => {
    const fetchImpl = (async () =>
      new Response("nope", { status: 500 })) as unknown as typeof fetch;
    await expect(fetchUpstreamModels({ provider, fetchImpl })).rejects.toMatchObject({
      status: 502,
      code: "provider_models_unavailable",
    });
  });

  it("a body that is not JSON maps to 502 provider_models_malformed", async () => {
    const fetchImpl = (async () =>
      new Response("<html>not json</html>", { status: 200 })) as unknown as typeof fetch;
    await expect(fetchUpstreamModels({ provider, fetchImpl })).rejects.toMatchObject({
      status: 502,
      code: "provider_models_malformed",
    });
  });

  it("a JSON payload that is not a model list maps to 502 provider_models_malformed", async () => {
    const fetchImpl = (async () =>
      new Response(JSON.stringify({ object: "not-a-list" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })) as unknown as typeof fetch;
    await expect(fetchUpstreamModels({ provider, fetchImpl })).rejects.toMatchObject({
      status: 502,
      code: "provider_models_malformed",
    });
  });

  it("all four mappings are ProviderModelSyncError instances", async () => {
    const throwing = (async () => {
      throw new Error("x");
    }) as unknown as typeof fetch;
    await expect(fetchUpstreamModels({ provider, fetchImpl: throwing })).rejects.toBeInstanceOf(
      ProviderModelSyncError,
    );
  });

  it("an anthropic provider sends the mandatory anthropic-version header", async () => {
    // The x-api-key branch alone is not enough: Anthropic's /v1/models rejects
    // any request without anthropic-version (400). Inverting the fix (dropping
    // the header) turns this red.
    const seen: Array<Record<string, string>> = [];
    const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries((init?.headers ?? {}) as Record<string, string>)) {
        headers[k.toLowerCase()] = v;
      }
      seen.push(headers);
      return new Response(JSON.stringify({ object: "list", data: [{ id: "claude-3-5-sonnet" }] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch;

    await fetchUpstreamModels({
      provider: {
        kind: "anthropic",
        base_url: "https://api.anthropic.example/v1",
        auth_scheme: null,
      },
      apiKey: "sk-ant-123",
      fetchImpl,
    });
    expect(seen[0]?.["anthropic-version"]).toBe("2023-06-01");
    // anthropic resolves to the x-api-key scheme, not a bearer.
    expect(seen[0]?.["x-api-key"]).toBe("sk-ant-123");
    expect(seen[0]?.authorization).toBeUndefined();
  });
});

describe("provider connectivity protocol contract", () => {
  it("rejects protocol values outside the supported dropdown choices", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/providers/${PROVIDER_ID}/connectivity-test`,
      {
        method: "POST",
        headers: { ...bearer(OPERATOR_KEY), "content-type": "application/json" },
        body: JSON.stringify({
          action: "chat",
          model: "gpt-5.5",
          protocol: "completions",
        }),
      },
    );

    expect(response.status).toBe(400);
    const body = (await response.json()) as { error?: { code?: string } };
    expect(body.error?.code).toBe("invalid_request_body");
  });
});
