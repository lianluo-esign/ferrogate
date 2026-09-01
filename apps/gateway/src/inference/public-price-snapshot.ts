/**
 * The public-model-price KV projection — one shared snapshot that lets the
 * gateway attach public per-1M prices to a catalog WITHOUT a per-request read of
 * the control authority.
 *
 * ## Why this exists
 *
 * `resolvePublicModelPrices` (`tenant-catalog.ts`) runs on the inference build
 * path and, for any tenant offering a `platform_seed` or explicitly-priced
 * model, issues TWO uncached `prepare().all()` reads of the control database:
 * `platform_model_prices` and the provider cost multipliers from
 * `platform_provider_channels`. Under the `"d1"` control posture those are
 * colo-local replica reads (cheap); under the `"durable_object"` posture each
 * becomes a round trip to the SINGLETON control object — the last per-request
 * control read the D1→DO cutover has to shield before the singleton stops being
 * a fleet-scale bottleneck. This snapshot removes that read under BOTH postures:
 * the two small platform-level tables are published to `PLATFORM_CONFIG` (the
 * SAME KV the model-catalog, billing-group and tenant-status snapshots ride) and
 * the reader folds prices colo-locally, exactly like
 * {@link TENANT_STATUS_SNAPSHOT_KEY} / the platform catalog snapshot.
 *
 * ## The snapshot is only ever a FAST PATH, never a new authority
 *
 * The reader in `tenant-catalog.ts` uses this snapshot when it is present and
 * well-formed, and falls THROUGH to the unchanged control read on ANY miss — an
 * absent object, a malformed blob, or a KV read that throws. The control tables
 * stay authoritative; this is a self-healing projection republished every
 * scheduled tick. Both tables are PLATFORM-level (not tenant-scoped), so this
 * carries no tenant-attributed data — it is the same class of account-global
 * config the catalog and billing-group snapshots already publish.
 *
 * Node-safe by construction (no `cloudflare:*` imports), so the control-plane
 * publisher and the node-only vitest suites can both import it — the twin of
 * `tenant-status-snapshot.ts`.
 */

/** One shared KV object, atomically replaced after every price projection. */
export const PUBLIC_PRICE_SNAPSHOT_KEY = "platform-config:public-model-price:v1";

/**
 * The public price rows the gateway consumes, verbatim from
 * `platform_model_prices`. Shared with the publisher so the two sides read the
 * SAME columns — a drift here would silently unprice a model.
 */
export const PUBLIC_MODEL_PRICE_SQL = `
  SELECT id, model_key, aliases_json, enabled, input_price_per_1m, output_price_per_1m,
         cached_input_price_per_1m, cache_write_price_per_1m,
         reasoning_price_per_1m, audio_second_price_per_1m,
         audio_character_price_per_1m
    FROM platform_model_prices`;

/** The provider cost multipliers, verbatim from `platform_provider_channels`. */
export const PLATFORM_PROVIDER_COST_SQL = `
  SELECT id, cost_multiplier FROM platform_provider_channels`;

/** A `platform_model_prices` row as the publisher reads it and the gateway folds it. */
export interface PublicModelPriceRow {
  readonly id: string;
  readonly model_key: string;
  readonly aliases_json: string;
  readonly enabled: number | string;
  readonly input_price_per_1m: number | null;
  readonly output_price_per_1m: number | null;
  readonly cached_input_price_per_1m: number | null;
  readonly cache_write_price_per_1m: number | null;
  readonly reasoning_price_per_1m: number | null;
  readonly audio_second_price_per_1m: number | null;
  readonly audio_character_price_per_1m: number | null;
}

/** A `platform_provider_channels` cost row (id + its cost multiplier). */
export interface PlatformProviderCostRow {
  readonly id: string;
  readonly cost_multiplier: number | string | null;
}

export interface PublicPriceSnapshot {
  readonly schema_version: 1;
  readonly published_at_unix: number;
  /** Every `platform_model_prices` row, verbatim. */
  readonly prices: readonly PublicModelPriceRow[];
  /** Every `platform_provider_channels` cost row, verbatim. */
  readonly provider_costs: readonly PlatformProviderCostRow[];
}

/**
 * Fold the raw provider-cost rows into `provider id → multiplier`. The SINGLE
 * derivation of this map: `resolvePublicModelPrices` folds it identically from
 * either the KV snapshot or the control read, so the two paths can never assign
 * a different multiplier to the same provider. A non-finite or negative value is
 * dropped, exactly as the pre-snapshot inline fold did — `providerCostMultiplier`
 * then substitutes the safe `1` default for any provider missing from the map.
 */
export function platformProviderCostMap(
  rows: readonly PlatformProviderCostRow[],
): Map<string, number> {
  const costs = new Map<string, number>();
  for (const provider of rows) {
    const value =
      typeof provider.cost_multiplier === "number"
        ? provider.cost_multiplier
        : Number(provider.cost_multiplier);
    if (Number.isFinite(value) && value >= 0) costs.set(provider.id, value);
  }
  return costs;
}

/** Parse and validate a stored snapshot; any shape violation is `null`. */
export function parsePublicPriceSnapshot(raw: string): PublicPriceSnapshot | null {
  try {
    const parsed = JSON.parse(raw) as Partial<PublicPriceSnapshot>;
    if (
      parsed.schema_version !== 1 ||
      !Number.isSafeInteger(parsed.published_at_unix) ||
      (parsed.published_at_unix ?? -1) < 0 ||
      !Array.isArray(parsed.prices) ||
      !Array.isArray(parsed.provider_costs)
    ) {
      return null;
    }
    return parsed as PublicPriceSnapshot;
  } catch {
    return null;
  }
}

/**
 * The `KVNamespace.get` subset the reader needs — kept structural so a test can
 * pass a stub and so this module never has to import worker types.
 */
export interface PublicPriceKvReader {
  get(key: string, options?: { cacheTtl?: number }): Promise<string | null>;
}

/**
 * Read the current snapshot from KV, or `null` when it is absent, malformed, or
 * the read throws. A `null` here is the reader's signal to fall back to the
 * control read, so a KV outage degrades to exactly today's behaviour rather than
 * to an unpriced catalog.
 */
export async function readPublicPriceSnapshot(
  kv: PublicPriceKvReader,
): Promise<PublicPriceSnapshot | null> {
  let raw: string | null;
  try {
    raw = await kv.get(PUBLIC_PRICE_SNAPSHOT_KEY, { cacheTtl: 30 });
  } catch {
    return null;
  }
  if (raw === null) return null;
  return parsePublicPriceSnapshot(raw);
}
