/**
 * The tenant's OWN model catalog — the `model_catalog` table in one tenant's
 * database, and the platform default card it is seeded from (#820).
 *
 * ## Why a tenant needs one
 *
 * `buildModelCatalog` (`apps/gateway/src/inference/catalog.ts`) fails closed:
 * an absent or invalid catalog yields the EMPTY catalog, and every model then
 * answers `400 model_not_found`. Under the D1-per-tenant topology that was
 * nobody's problem, because onboarding a tenant WAS a `wrangler deploy` and an
 * operator was already in the loop. Under `durable_object` an object exists the
 * moment anyone addresses it and no human is involved anywhere, so a tenant that
 * is not seeded is a tenant that 400s on its first request forever, with no
 * error naming the cause.
 *
 * ## Seeded once. Then it is the tenant's.
 *
 * {@link seedTenantModelCatalog} runs at most once per tenant, gated on the
 * `model_catalog_seed` row in that tenant's own `tenant_provisioning_marks`
 * table. The gate is a mark and NOT `INSERT OR IGNORE` on the catalog rows,
 * because those two differ exactly where it matters:
 *
 *   * `INSERT OR IGNORE` protects a row the tenant EDITED and resurrects a row
 *     the tenant DELETED. A tenant that removed `claude-opus-4` would find it
 *     back after the next resume — an edit silently reverted by a background
 *     job.
 *   * The mark is a fact about the STEP, not about any row, so it stays true
 *     however the catalog is later edited, and a resumed or re-run provisioning
 *     is a genuine no-op.
 *
 * The mark lives in the tenant's storage rather than only in the control
 * database's `tenant_databases` row for the reason
 * `sql/d1-ts/tenant/0008_model_catalog.sql` states at length: those two stores
 * cannot be written in one transaction, and if the only "already seeded" record
 * were the control-side one, then losing it (a restore, a re-registration, a
 * migration that rebuilds the table — this slice ships one) would re-seed a live
 * tenant over its own edits.
 *
 * ## The DATA is copied from `packages/billing`, the MECHANISM is not
 *
 * {@link DEFAULT_TENANT_MODEL_CATALOG} carries the same rates as
 * `PriceBook.withDefaultRateCard()` (`packages/billing/src/pricing.ts`), copied
 * rather than imported. Three reasons, in order of weight:
 *
 *  1. #814 retires that rate card as a RUNTIME price source. Importing it here
 *     would make this the last live caller and give the retirement a new
 *     blocker, one slice after the decision to retire it.
 *  2. A seed is a snapshot BY DEFINITION. If this list were a live import, a
 *     platform price edit would change what a tenant provisioned tomorrow is
 *     given while leaving every tenant provisioned yesterday alone — the two
 *     tenants would then differ for a reason neither of them can see. Copying
 *     makes the snapshot explicit and dated.
 *  3. `@ferrogate/storage` does not depend on `@ferrogate/billing`, and the
 *     dependency would run the wrong way round: billing is a consumer of stored
 *     prices, not a supplier of them.
 *
 * The cost of copying is drift, and it is real: an operator who updates the
 * billing card and not this list gets a NEW tenant seeded at the old rates.
 * That is bounded (it affects the seed only, never an existing tenant, and never
 * settlement — `charge()` still prices against the live card) and it is the
 * lesser of the two, because the alternative silently re-prices tenants.
 */
import { StorageError } from "./errors.js";

/** One seeded catalog row: a model this tenant may use, and what it costs. */
export interface TenantModelCatalogEntry {
  /** The LOGICAL name a client sends. Primary key of `model_catalog`. */
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
 * as of 2026-08-04. See the module docblock for why it is a copy.
 *
 * Sixteen entries, not the "13" an earlier note claimed: eleven token-priced
 * chat models and five audio ones. The count is stated because it is asserted —
 * a seed list that silently shrank to one entry would leave every new tenant
 * with a catalog that is technically non-empty and practically useless, and
 * "non-empty" is exactly the shape of assertion that fails to notice.
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

/** `model_catalog.source` for a row this tenant has never touched. */
export const CATALOG_SOURCE_PLATFORM_SEED = "platform_seed";

/** Columns read back by {@link listTenantModelCatalog}, in a single list. */
const CATALOG_COLUMNS =
  "model, provider, provider_model, enabled, input_price_per_1m, output_price_per_1m, " +
  "cached_input_multiplier, cache_write_multiplier, audio_second_price_per_1m, " +
  "audio_character_price_per_1m, source";

interface CatalogRow {
  model: string;
  provider: string;
  provider_model: string;
  enabled: number;
  input_price_per_1m: number;
  output_price_per_1m: number;
  cached_input_multiplier: number | null;
  cache_write_multiplier: number | null;
  audio_second_price_per_1m: number | null;
  audio_character_price_per_1m: number | null;
  source: string;
}

/** One row as stored, including the two columns the seed does not set. */
export interface StoredTenantModelCatalogEntry extends TenantModelCatalogEntry {
  /** `false` disables the model WITHOUT deleting the price the tenant negotiated. */
  readonly enabled: boolean;
  /** `platform_seed` until an operator writes the row. Descriptive, not enforced. */
  readonly source: string;
}

/** What {@link seedTenantModelCatalog} did. */
export interface TenantModelCatalogSeedOutcome {
  /** `false` when the mark was already present, i.e. this call was the no-op. */
  readonly seeded: boolean;
  /** Rows INSERTed by this call. `0` on a no-op. */
  readonly inserted: number;
  /** When the seed ran — this call's `nowUnix`, or the original mark's. */
  readonly seededAtUnix: number;
}

/**
 * Seed one tenant's catalog, at most once, ever.
 *
 * Everything happens in ONE `batch()`, which is one transaction on every backend
 * this repo routes a tenant through (`native_binding` and `durable_object`;
 * `rest` reports `supportsAtomicBatch: false` and is not a tenant backend any
 * more). That matters because the mark and the rows must land together: a mark
 * without rows is a tenant permanently stuck at an empty catalog that no resume
 * will ever fill, and rows without a mark is a catalog that gets re-seeded over
 * the tenant's edits on the next resume. Both failure modes are silent, and both
 * are removed by the same transaction.
 *
 * ## The mark is read BEFORE the batch, and that read is not redundant
 *
 * The obvious shape — put the claim and the row inserts in one `batch()` and
 * decide afterwards from the claim's `RETURNING` set — is WRONG, and a test
 * caught it: the row inserts run whether or not the claim won, so a re-run
 * against an already-seeded tenant silently RESURRECTS every model that tenant
 * had deleted. `INSERT OR IGNORE` protects an edited row and reinstates a
 * removed one, which is exactly the asymmetry this function is built around.
 *
 * So the mark is read first, and an already-marked tenant returns without
 * writing anything at all. What the transaction is still for is the OTHER
 * direction: on the seeding path the claim and the rows must land together, or a
 * crash between them leaves a mark with no rows — a tenant permanently stuck at
 * an empty catalog that no resume will ever fill, because every resume reads the
 * mark and stops.
 *
 * Two provisioners racing on a FRESH tenant both pass the pre-read and both run
 * the batch; one wins the claim and the other's inserts are `OR IGNORE` no-ops
 * over the identical seed data. That is benign, and it is only benign because
 * both are writing the same platform card at onboarding time — which is why the
 * loser is reported as `seeded: false` rather than as an error.
 *
 * @throws {@link StorageError} `runtime` if the batch comes back short — a short
 *   batch would make the claim unreadable, and an unreadable claim defaults to
 *   "seeded", which is the direction that leaves a tenant empty forever.
 */
export async function seedTenantModelCatalog(
  db: D1Database,
  tenantId: string,
  nowUnix: number,
  entries: readonly TenantModelCatalogEntry[] = DEFAULT_TENANT_MODEL_CATALOG,
): Promise<TenantModelCatalogSeedOutcome> {
  const already = await readSeedMark(db, tenantId);
  if (already !== undefined) {
    return { seeded: false, inserted: 0, seededAtUnix: already };
  }

  const claim = db
    .prepare(
      "INSERT OR IGNORE INTO tenant_provisioning_marks " +
        "(tenant_id, mark, detail, applied_at_unix) VALUES (?, ?, ?, ?) RETURNING mark",
    )
    .bind(tenantId, MODEL_CATALOG_SEED_MARK, `entries=${entries.length}`, nowUnix);

  const insert = db.prepare(
    "INSERT OR IGNORE INTO model_catalog " +
      "(tenant_id, model, provider, provider_model, enabled, input_price_per_1m, " +
      " output_price_per_1m, cached_input_multiplier, cache_write_multiplier, " +
      " audio_second_price_per_1m, audio_character_price_per_1m, source, " +
      " created_at_unix, updated_at_unix) " +
      "VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
  );

  const results = await db.batch([
    claim,
    ...entries.map((entry) =>
      // `bind()` must return a FRESH statement for this to be N rows rather than
      // the last row N times; every backend in this repo honours that, and
      // `packages/storage/test/d1/` proves it on both.
      insert.bind(
        tenantId,
        entry.model,
        entry.provider,
        entry.providerModel,
        entry.inputPricePer1m,
        entry.outputPricePer1m,
        entry.cachedInputMultiplier ?? null,
        entry.cacheWriteMultiplier ?? null,
        entry.audioSecondPricePer1m ?? null,
        entry.audioCharacterPricePer1m ?? null,
        CATALOG_SOURCE_PLATFORM_SEED,
        nowUnix,
        nowUnix,
      ),
    ),
  ]);

  if (results.length !== entries.length + 1) {
    throw StorageError.runtime(
      `seeding the tenant model catalog expected ${entries.length + 1} statement results and ` +
        `got ${results.length}; refusing to report a seed whose outcome cannot be read`,
    );
  }
  const claimed = (results[0]?.results ?? []).length > 0;
  if (!claimed) {
    // Lost the race described in the docblock: another provisioner claimed the
    // mark between this call's pre-read and its batch. Its rows are the same
    // platform card, so nothing was clobbered — but the WINNER's timestamp is
    // the honest answer to "when", not this call's clock.
    return {
      seeded: false,
      inserted: 0,
      seededAtUnix: (await readSeedMark(db, tenantId)) ?? nowUnix,
    };
  }
  const inserted = results
    .slice(1)
    .reduce((total, result) => total + (result.meta?.changes ?? 0), 0);
  return { seeded: true, inserted, seededAtUnix: nowUnix };
}

/** When the catalog seed ran for this tenant, or `undefined` if it never has. */
async function readSeedMark(db: D1Database, tenantId: string): Promise<number | undefined> {
  const row = await db
    .prepare(
      "SELECT applied_at_unix FROM tenant_provisioning_marks WHERE tenant_id = ? AND mark = ?",
    )
    .bind(tenantId, MODEL_CATALOG_SEED_MARK)
    .first<{ applied_at_unix: number }>();
  return row?.applied_at_unix;
}

/** Every catalog row this tenant holds, by model name ascending. */
export async function listTenantModelCatalog(
  db: D1Database,
  tenantId: string,
): Promise<StoredTenantModelCatalogEntry[]> {
  const result = await db
    .prepare(`SELECT ${CATALOG_COLUMNS} FROM model_catalog WHERE tenant_id = ? ORDER BY model`)
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
      `SELECT ${CATALOG_COLUMNS} FROM model_catalog WHERE tenant_id = ? AND model = ? AND enabled = 1`,
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
