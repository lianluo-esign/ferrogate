import {
  PLATFORM_PROVIDER_COST_SQL,
  PUBLIC_MODEL_PRICE_SQL,
  PUBLIC_PRICE_SNAPSHOT_KEY,
  type PlatformProviderCostRow,
  type PublicModelPriceRow,
  type PublicPriceSnapshot,
} from "../../../gateway/src/inference/public-price-snapshot.js";

export type PublicPriceCachePublishResult =
  | { readonly status: "unconfigured" }
  | {
      readonly status: "published";
      readonly prices: number;
      readonly providerCosts: number;
    };

/**
 * Publish the two platform-level pricing tables (`platform_model_prices` and the
 * provider cost multipliers from `platform_provider_channels`) to
 * `PLATFORM_CONFIG`, mirroring {@link publishPlatformCatalogCache} /
 * {@link publishTenantStatusCache}. The gateway `resolvePublicModelPrices` reads
 * this snapshot KV-first instead of issuing the two per-request control reads on
 * the inference build path (see `gateway/src/inference/public-price-snapshot.ts`).
 *
 * Unconditional and cheap (one batched read of two small platform tables), so
 * the scheduled pass can republish every tick to self-heal a lost write — the
 * same contract the catalog, billing-group and tenant-status caches use. Both
 * tables are PLATFORM-level (not tenant-scoped), so this snapshot carries no
 * tenant-attributed data. Rows are stored verbatim; the gateway reader applies
 * the enable/alias/multiplier projection.
 */
export async function publishPublicPriceCache(options: {
  readonly db: D1Database;
  readonly kv?: KVNamespace;
  readonly nowUnix?: number;
}): Promise<PublicPriceCachePublishResult> {
  if (options.kv === undefined) return { status: "unconfigured" };

  const results = await options.db.batch([
    options.db.prepare(PUBLIC_MODEL_PRICE_SQL),
    options.db.prepare(PLATFORM_PROVIDER_COST_SQL),
  ]);
  const priceRows = results[0] as D1Result<PublicModelPriceRow> | undefined;
  const providerRows = results[1] as D1Result<PlatformProviderCostRow> | undefined;
  if (priceRows === undefined || providerRows === undefined) {
    throw new Error("public price snapshot batch returned an incomplete result");
  }

  const snapshot: PublicPriceSnapshot = {
    schema_version: 1,
    published_at_unix: options.nowUnix ?? Math.floor(Date.now() / 1000),
    prices: priceRows.results,
    provider_costs: providerRows.results,
  };
  await options.kv.put(PUBLIC_PRICE_SNAPSHOT_KEY, JSON.stringify(snapshot));
  return {
    status: "published",
    prices: priceRows.results.length,
    providerCosts: providerRows.results.length,
  };
}
