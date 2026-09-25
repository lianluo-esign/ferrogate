/**
 * Compatibility reads for tenant-owned catalog overrides and the bootstrap
 * platform rate card. Tenant provisioning no longer copies this card or a
 * platform graph. Shared catalog persistence belongs to CONTROL_DATA, with
 * PLATFORM_CONFIG KV serving gateway reads.
 */

/** One bootstrap rate-card entry or tenant-owned catalog projection. */
export interface TenantModelCatalogEntry {
  /** The LOGICAL name a client sends. Unique within `catalog_models`. */
  readonly model: string;
  /**
   * The serving provider, or `"*"` for "whatever the platform routes this model
   * to". The seeded card states every entry as `"*"`, because a rate card prices
   * a MODEL and the physical provider behind it is a per-request routing
   * decision.
   */
  readonly provider: string;
  /** The id put on the upstream wire. Seeded equal to {@link model}. */
  readonly providerModel: string;
  /** USD per 1M input tokens. */
  readonly inputPricePer1m: number;
  /** USD per 1M output tokens. */
  readonly outputPricePer1m: number;
  /** Cache-read rate as a RATIO of {@link inputPricePer1m} (#667); absent = none stated. */
  readonly cachedInputMultiplier?: number;
  /** Cache-write rate as a RATIO of {@link inputPricePer1m} (#667); absent = none stated. */
  readonly cacheWriteMultiplier?: number;
  /** USD per 1M transcribed seconds (#703); absent = this entry does not price audio. */
  readonly audioSecondPricePer1m?: number;
  /** USD per 1M synthesized characters (#703); absent = this entry does not price speech. */
  readonly audioCharacterPricePer1m?: number;
}

/**
 * The platform's starting card, copied from `PriceBook.withDefaultRateCard()`
 * as of 2026-08-04. Used only to bootstrap the platform catalog.
 *
 * Cache rates are ratios of each entry's own input rate, per each vendor's
 * published structure: Anthropic 0.1x read / 1.25x five-minute write, OpenAI
 * 0.5x read on the 4o family and 0.1x on the 5 family with no write charge,
 * Gemini 0.25x, DeepSeek's published cache-hit price expressed as a ratio.
 *
 * These are DEFAULTS an operator is expected to replace, exactly as they are on
 * the billing card. An entry that states no cache multiplier prices cached
 * tokens at its ordinary input rate — never at zero — so a missing multiplier
 * bills slightly high rather than free.
 */
export const DEFAULT_TENANT_MODEL_CATALOG: readonly TenantModelCatalogEntry[] = [
  chat("gpt-5.5", 5.0, 15.0, { cachedInputMultiplier: 0.1 }),
  chat("gpt-5", 5.0, 15.0, { cachedInputMultiplier: 0.1 }),
  chat("gpt-4o", 2.5, 10.0, { cachedInputMultiplier: 0.5 }),
  chat("gpt-4o-mini", 0.15, 0.6, { cachedInputMultiplier: 0.5 }),
  chat("claude-sonnet-4", 3.0, 15.0, {
    cachedInputMultiplier: 0.1,
    cacheWriteMultiplier: 1.25,
  }),
  chat("claude-opus-4", 15.0, 75.0, {
    cachedInputMultiplier: 0.1,
    cacheWriteMultiplier: 1.25,
  }),
  chat("gemini-2.5-pro", 1.25, 10.0, { cachedInputMultiplier: 0.25 }),
  chat("gemini-2.5-flash", 0.3, 2.5, { cachedInputMultiplier: 0.25 }),
  chat("grok-4", 3.0, 15.0, { cachedInputMultiplier: 0.25 }),
  chat("deepseek-chat", 0.27, 1.1, { cachedInputMultiplier: 0.07 / 0.27 }),
  chat("deepseek-reasoner", 0.55, 2.19, { cachedInputMultiplier: 0.14 / 0.55 }),
  // The audio surface (#703). Both token rates are 0 and that is not a
  // free-inference bug: a transcription emits no tokens, so the token arms of a
  // cost estimate multiply 0 by 0 and the rate that decides the row is the audio
  // one. A row carrying an audio quantity its entry does not price is still
  // `price_not_found` rather than silently free.
  audioSeconds("@cf/openai/whisper-large-v3-turbo", 1.6),
  audioSeconds("@cf/openai/whisper", 1.6),
  audioCharacters("@cf/myshell-ai/melotts", 0.1),
  audioSeconds("whisper-1", 100.0),
  audioCharacters("tts-1", 15.0),
];

/** A token-priced entry. `provider_model` is the logical name until re-pointed. */
function chat(
  model: string,
  inputPricePer1m: number,
  outputPricePer1m: number,
  cache: { cachedInputMultiplier?: number; cacheWriteMultiplier?: number } = {},
): TenantModelCatalogEntry {
  return {
    model,
    provider: "*",
    providerModel: model,
    inputPricePer1m,
    outputPricePer1m,
    ...(cache.cachedInputMultiplier === undefined
      ? {}
      : { cachedInputMultiplier: cache.cachedInputMultiplier }),
    ...(cache.cacheWriteMultiplier === undefined
      ? {}
      : { cacheWriteMultiplier: cache.cacheWriteMultiplier }),
  };
}

/** An entry priced only on transcribed seconds. */
function audioSeconds(model: string, pricePer1mSeconds: number): TenantModelCatalogEntry {
  return {
    model,
    provider: "*",
    providerModel: model,
    inputPricePer1m: 0,
    outputPricePer1m: 0,
    audioSecondPricePer1m: pricePer1mSeconds,
  };
}

/** An entry priced only on synthesized characters. */
function audioCharacters(model: string, pricePer1mCharacters: number): TenantModelCatalogEntry {
  return {
    model,
    provider: "*",
    providerModel: model,
    inputPricePer1m: 0,
    outputPricePer1m: 0,
    audioCharacterPricePer1m: pricePer1mCharacters,
  };
}

/** The `tenant_provisioning_marks.mark` that records the seed has run. */
export const MODEL_CATALOG_SEED_MARK = "model_catalog_seed";

/** `catalog_model_offerings.source` for a row this tenant has never touched. */
export const CATALOG_SOURCE_PLATFORM_SEED = "platform_seed";

/** The compatibility-shaped projection used by the provisioning health API. */
const CATALOG_COLUMNS =
  "m.name AS model, " +
  "CASE WHEN p.kind = 'platform' THEN '*' ELSE p.name END AS provider, " +
  "o.upstream_model_id AS provider_model, " +
  "CASE WHEN m.enabled = 1 AND o.enabled = 1 AND p.enabled = 1 THEN 1 ELSE 0 END AS enabled, " +
  "o.input_price_per_1m, o.output_price_per_1m, " +
  "CASE WHEN o.cached_input_price_per_1m IS NULL OR o.input_price_per_1m <= 0 " +
  "THEN NULL ELSE o.cached_input_price_per_1m / o.input_price_per_1m END " +
  "AS cached_input_multiplier, " +
  "CASE WHEN o.cache_write_price_per_1m IS NULL OR o.input_price_per_1m <= 0 " +
  "THEN NULL ELSE o.cache_write_price_per_1m / o.input_price_per_1m END " +
  "AS cache_write_multiplier, " +
  "o.audio_second_price_per_1m, o.audio_character_price_per_1m, o.source";

/**
 * The pre-#811 compatibility API returns one route per logical model. Prefer
 * its primary offering, and use the deterministic best fallback only for a
 * model that has no primary yet. The #812 loader will read the full offering
 * ladder, including every fallback, canary, and shadow row.
 */
const COMPATIBILITY_OFFERING_PREDICATE =
  "(o.role = 'primary' OR (" +
  "o.role = 'fallback' AND NOT EXISTS (" +
  "SELECT 1 FROM catalog_model_offerings primary_o " +
  "WHERE primary_o.tenant_id = o.tenant_id AND primary_o.model_id = o.model_id " +
  "AND primary_o.role = 'primary'" +
  ") AND NOT EXISTS (" +
  "SELECT 1 FROM catalog_model_offerings better_fallback " +
  "WHERE better_fallback.tenant_id = o.tenant_id " +
  "AND better_fallback.model_id = o.model_id " +
  "AND better_fallback.role = 'fallback' " +
  "AND (better_fallback.priority < o.priority " +
  "OR (better_fallback.priority = o.priority AND better_fallback.weight > o.weight) " +
  "OR (better_fallback.priority = o.priority AND better_fallback.weight = o.weight " +
  "AND better_fallback.id < o.id))" +
  ")" +
  "))";

interface CatalogRow {
  model: string;
  provider: string;
  provider_model: string;
  enabled: number;
  input_price_per_1m: number | null;
  output_price_per_1m: number | null;
  cached_input_multiplier: number | null;
  cache_write_multiplier: number | null;
  audio_second_price_per_1m: number | null;
  audio_character_price_per_1m: number | null;
  source: string;
}

/** One row as stored, including nullable prices and the two seed does not set. */
export type StoredTenantModelCatalogEntry = Omit<
  TenantModelCatalogEntry,
  "inputPricePer1m" | "outputPricePer1m"
> & {
  /** `NULL` means unpriced; `0` means free. */
  readonly inputPricePer1m: number | null;
  /** `NULL` means unpriced; `0` means free. */
  readonly outputPricePer1m: number | null;
  /** `false` disables the model WITHOUT deleting the price the tenant negotiated. */
  readonly enabled: boolean;
  /** `platform_seed` until an operator writes the row. Descriptive, not enforced. */
  readonly source: string;
};

/** Raw platform channel; secret binding names are retained for platform export. */
export interface SeedProviderChannel {
  readonly id: string;
  readonly name: string;
  readonly kind: string;
  readonly base_url: string;
  readonly upstream_protocol?: "openai.chat.completions" | "openai.responses" | null;
  readonly cost_multiplier?: number;
  readonly api_key_var: string | null;
  readonly byok_alias: string | null;
  readonly auth_scheme: string | null;
  readonly region: string | null;
  readonly zero_data_retention: number | null;
  readonly openrouter_http_referer: string | null;
  readonly openrouter_x_title: string | null;
  readonly cloudflare_ai_gateway_json: string | null;
  readonly enabled: number;
}

/** Raw logical model exported from the platform catalog. */
export interface SeedCatalogModel {
  readonly id: string;
  readonly name: string;
  readonly family: string | null;
  readonly owned_by: string | null;
  readonly capabilities_json: string;
  readonly context_window: number | null;
  readonly routing_strategy: string;
  readonly enabled: number;
}

/** Raw platform offering with platform model/channel IDs. */
export interface SeedCatalogOffering {
  readonly id: string;
  readonly model_id: string;
  readonly provider_id: string;
  readonly upstream_model_id: string;
  /** Platform public-price catalog reference; null means the route is unbound. */
  readonly pricing_model_id?: string | null;
  readonly role: string;
  readonly priority: number;
  readonly weight: number;
  readonly canary_percent: number | null;
  readonly shadow_percent: number | null;
  readonly shadow_max_requests: number | null;
  readonly capabilities_json: string | null;
  readonly context_window: number | null;
  readonly region: string | null;
  readonly zero_data_retention: number | null;
  readonly input_price_per_1m: number | null;
  readonly output_price_per_1m: number | null;
  readonly cached_input_price_per_1m: number | null;
  readonly cache_write_price_per_1m: number | null;
  readonly reasoning_price_per_1m: number | null;
  readonly audio_second_price_per_1m: number | null;
  readonly audio_character_price_per_1m: number | null;
  readonly currency: string;
  readonly enabled: number;
}

/** Raw platform graph; the legacy type name is retained for export consumers. */
export interface TenantModelCatalogSeedGraph {
  readonly providers: readonly SeedProviderChannel[];
  readonly models: readonly SeedCatalogModel[];
  readonly offerings: readonly SeedCatalogOffering[];
  readonly revision: number;
}

export async function listTenantModelCatalog(
  db: D1Database,
  tenantId: string,
): Promise<StoredTenantModelCatalogEntry[]> {
  const result = await db
    .prepare(
      `SELECT ${CATALOG_COLUMNS} FROM catalog_models m
       JOIN catalog_model_offerings o ON o.tenant_id = m.tenant_id AND o.model_id = m.id
       JOIN provider_channels p ON p.tenant_id = o.tenant_id AND p.id = o.provider_id
       WHERE m.tenant_id = ? AND ${COMPATIBILITY_OFFERING_PREDICATE} ORDER BY m.name`,
    )
    .bind(tenantId)
    .all<CatalogRow>();
  return result.results.map(catalogEntryFromRow);
}

/**
 * Resolve ONE model for this tenant — the read an inference request makes.
 *
 * Disabled rows are invisible, which is the whole reason `enabled` exists as a
 * column instead of the tenant deleting the row: a disabled model resolves to
 * nothing (so the request fails closed with `model_not_found`) while the price
 * the tenant negotiated for it survives being turned back on.
 */
export async function resolveTenantModel(
  db: D1Database,
  tenantId: string,
  model: string,
): Promise<StoredTenantModelCatalogEntry | undefined> {
  const row = await db
    .prepare(
      `SELECT ${CATALOG_COLUMNS} FROM catalog_models m
       JOIN catalog_model_offerings o ON o.tenant_id = m.tenant_id AND o.model_id = m.id
       JOIN provider_channels p ON p.tenant_id = o.tenant_id AND p.id = o.provider_id
       WHERE m.tenant_id = ? AND m.name = ? AND ${COMPATIBILITY_OFFERING_PREDICATE}
       AND m.enabled = 1 AND o.enabled = 1 AND p.enabled = 1`,
    )
    .bind(tenantId, model)
    .first<CatalogRow>();
  return row === null ? undefined : catalogEntryFromRow(row);
}

function catalogEntryFromRow(row: CatalogRow): StoredTenantModelCatalogEntry {
  return {
    model: row.model,
    provider: row.provider,
    providerModel: row.provider_model,
    enabled: row.enabled !== 0,
    inputPricePer1m: row.input_price_per_1m,
    outputPricePer1m: row.output_price_per_1m,
    ...(row.cached_input_multiplier === null
      ? {}
      : { cachedInputMultiplier: row.cached_input_multiplier }),
    ...(row.cache_write_multiplier === null
      ? {}
      : { cacheWriteMultiplier: row.cache_write_multiplier }),
    ...(row.audio_second_price_per_1m === null
      ? {}
      : { audioSecondPricePer1m: row.audio_second_price_per_1m }),
    ...(row.audio_character_price_per_1m === null
      ? {}
      : { audioCharacterPricePer1m: row.audio_character_price_per_1m }),
    source: row.source,
  };
}
