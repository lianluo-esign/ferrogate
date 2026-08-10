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
 *   1. first sync ADDS every upstream model as a real offering, priced from the
 *      rate-card seed where the card covers the name and `null` where it does not;
 *   2. a second sync is IDEMPOTENT — nothing added, every model skipped, only the
 *      revision moves;
 *   3. a model the upstream DROPS is reported (skipped/absent), never deleted.
 */
import { PriceBook } from "@ferrogate/billing";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { CallerScope } from "../src/ports.js";
import { PlatformModelCatalogStore } from "../src/store/platform-model-catalog.js";
import { syncProviderModelsIntoCatalog } from "../src/store/platform-provider-sync.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, operatorKey, tenantKey } from "./harness.js";

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

async function offering(
  id: string,
): Promise<{ provider_id: string; source: string; input_price_per_1m: number | null } | null> {
  return db()
    .prepare(
      "SELECT provider_id, source, input_price_per_1m FROM platform_catalog_offerings WHERE id = ?",
    )
    .bind(id)
    .first<{ provider_id: string; source: string; input_price_per_1m: number | null }>();
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
  it("first sync adds every upstream model as a priced-from-seed offering", async () => {
    await seedProvider("OPENAI_KEY");
    const store = new PlatformModelCatalogStore({ db: db() });
    const provider = await store.getProviderSeed(PROVIDER_ID);
    expect(provider, "getProviderSeed must return the raw row with api_key_var").not.toBeNull();
    // getProviderSeed carries the credential REFERENCE, unlike the masked getProvider.
    expect(provider?.api_key_var).toBe("OPENAI_KEY");

    // `o1` is NOT in the default rate card; `gpt-4o` and `gpt-4o-mini` are.
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

    // Rate-card seed applied by NAME: gpt-4o priced, the off-card o1 left null.
    const priced = await offering("platform:offering:gpt-4o:openai:gpt-4o");
    expect(priced?.provider_id).toBe(PROVIDER_ID);
    expect(priced?.source).toBe("provider_sync");
    expect(priced?.input_price_per_1m).toBe(2.5);
    const unpriced = await offering("platform:offering:o1:openai:o1");
    expect(unpriced?.input_price_per_1m).toBeNull();
    expect(unpriced?.source).toBe("provider_sync");
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
});
