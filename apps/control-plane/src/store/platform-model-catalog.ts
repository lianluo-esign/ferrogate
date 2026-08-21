import {
  type ProviderTypeId,
  inferProviderTypeIdFromKind,
  isProviderTypeId,
} from "@ferrogate/provider-types";

/**
 * The platform default model catalog (#889, epic #810).
 *
 * This is `TenantModelCatalogStore` with the tenant column removed. The tenant
 * store lives in a tenant database and qualifies every key and edge with
 * `tenant_id` because a shared or legacy router can put several tenants in one
 * database. The platform catalog lives in the CONTROL database, which has
 * exactly one occupant, so the qualifier would be a constant.
 *
 * Two structural consequences follow, and they are the whole reason this is a
 * sibling module rather than a parameter on the tenant one:
 *
 *  1. **No audit outbox.** The tenant store writes its audit intent into a
 *     tenant-local `catalog_audit_outbox` and reconciles it into the control
 *     database afterwards, because the mutation and the audit chain live in
 *     DIFFERENT databases and cannot share a transaction. Here they are the
 *     same database, so no outbox is needed — but the audit row must then
 *     actually be IN the batch: `#commit` batches the revision init, the
 *     mutation, the revision bump and the audit INSERT together, exactly as
 *     `runControlPlaneMutationWithAudit` does for single-statement control
 *     mutations, so a rejected audit append rolls the mutation back instead of
 *     leaving a committed change with an advanced revision and no evidence.
 *  2. **No tenant on the record.** `controlPlaneAuditJson` derives both
 *     `resource_tenant_id` and the audit `chain_key` from `record.tenant_id`,
 *     so a platform record deliberately carries none: these mutations join the
 *     platform (null-tenant) audit chain alongside every other platform-scoped
 *     admin write, which is exactly where an operator looks for them.
 *
 * The handle passed in as `db` MUST be the CONTROL_DATA facade
 * (`deps.controlDatabase`, resolved by `control-data.ts::controlDatabaseFrom`),
 * never a raw `env.DB` — that is the Zero-D1 seam #879 introduced and the
 * reason this store takes a database rather than reaching for a binding.
 */
import type {
  SeedCatalogModel,
  SeedCatalogOffering,
  SeedProviderChannel,
  TenantModelCatalogSeedGraph,
} from "@ferrogate/storage";
import { canonicalProviderKind } from "../../../gateway/src/inference/adapters.js";
import type { CallerScope, StoreRecord } from "../ports.js";
import { type AuditAction, controlPlaneAuditJson, controlPlaneAuditStatement } from "./d1.js";
import {
  PLATFORM_DEFAULT_PROVIDER_ID,
  type PlatformCatalogImportGraph,
} from "./platform-catalog-import.js";
import {
  type ModelCatalogInput,
  type ModelOfferingInput,
  type ProviderChannelInput,
  TenantCatalogConflictError,
  TenantCatalogNotFoundError,
  TenantCatalogValidationError,
  boolSql,
  boolValue,
  hasOwn,
  isConstraintError,
  jsonArray,
  parsedArray,
  providerCompatibility,
  urlIsValid,
} from "./tenant-model-catalog.js";

export const PLATFORM_PROVIDER_TABLE = "platform_provider_channels";
export const PLATFORM_MODEL_TABLE = "platform_catalog_models";
export const PLATFORM_OFFERING_TABLE = "platform_catalog_offerings";
export const PLATFORM_REVISION_TABLE = "platform_catalog_revisions";

/**
 * Audit `collection` values.
 *
 * Deliberately NOT the tenant store's `providers`/`models`/`offerings`: those
 * names already appear on the platform audit chain for the legacy document
 * collections, and an auditor reading the chain must be able to tell a write
 * to the platform catalog from a write to a tenant's.
 */
const PROVIDER_COLLECTION = "platform_providers";
const MODEL_COLLECTION = "platform_models";
const OFFERING_COLLECTION = "platform_offerings";

/**
 * Audit `collection` for the whole bootstrap import (#892).
 *
 * ONE row per import, not one per inserted table row: the import bumps the
 * revision exactly once and appends exactly one audit event, so a re-run — which
 * inserts nothing under `OR IGNORE` — still records that an operator ran it, and
 * an auditor sees the import as the single operator action it was.
 */
const IMPORT_COLLECTION = "platform_catalog_import";
const IMPORT_RECORD_ID = "platform:bootstrap-import";

/**
 * How many times `#commit` rebuilds its batch after a rolled-back attempt.
 *
 * Same budget `appendControlPlaneAudit` and `runControlPlaneMutationWithAudit`
 * use, and for the same reason: the only expected failure is two writers
 * claiming the same position on the platform audit chain.
 */
const PLATFORM_COMMIT_ATTEMPTS = 5;

/**
 * The control database has migration `0025` but not these tables yet.
 *
 * Real on the shipped posture: `wrangler.toml` pins
 * `CONTROL_PLANE_CONTROL_STORAGE = "d1_compat"`, whose migrations are applied
 * by a separate `wrangler d1 migrations apply` step rather than by
 * `wrangler deploy`, so there is a window in which the Worker is new and the
 * database is not. In that window the platform catalog is simply absent, which
 * is a different thing from broken.
 */
export function isMissingPlatformCatalogError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /no such table:\s*(main\.)?platform_/i.test(message);
}

/**
 * Did the AUDIT statement bring the batch down, rather than the mutation?
 *
 * `#commit` batches the two together, so `isConstraintError` alone can no
 * longer be read as "the caller's write conflicted": the expected constraint
 * failure in that batch is `UNIQUE constraint failed: audit_events.chain_key,
 * audit_events.seq` — two writers claiming one chain position, which is nobody's
 * request being wrong. Answering that `409 catalog conflict` would send an
 * operator to look at their payload instead of at the audit chain.
 */
function isAuditAppendError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /audit_events/i.test(message);
}

interface ProviderRow {
  readonly id: string;
  readonly name: string;
  readonly provider_type_id: string | null;
  readonly kind: string;
  readonly base_url: string;
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

interface ModelRow {
  readonly id: string;
  readonly name: string;
  readonly family: string | null;
  readonly owned_by: string | null;
  readonly capabilities_json: string;
  readonly context_window: number | null;
  readonly routing_strategy: string;
  readonly enabled: number;
}

interface OfferingRow {
  readonly id: string;
  readonly model_id: string;
  readonly provider_id: string;
  readonly provider_name: string | null;
  readonly upstream_model_id: string;
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
  readonly source: string;
  readonly enabled: number;
}

export interface PlatformModelCatalogStoreOptions {
  /** MUST be the CONTROL_DATA facade handle, not a raw `env.DB`. */
  readonly db: D1Database;
  readonly requestId?: string | null;
}

type CatalogRecord = StoreRecord;
type UpdateField = readonly [string, string | number | null];

const PROVIDER_SELECT = `
  SELECT id, name, provider_type_id, kind, base_url, api_key_var, byok_alias,
         auth_scheme, region, zero_data_retention, openrouter_http_referer,
         openrouter_x_title, cloudflare_ai_gateway_json, enabled
    FROM ${PLATFORM_PROVIDER_TABLE}`;

const MODEL_SELECT = `
  SELECT id, name, family, owned_by, capabilities_json,
         context_window, routing_strategy, enabled
    FROM ${PLATFORM_MODEL_TABLE}`;

const OFFERING_SELECT = `
  SELECT o.id, o.model_id, o.provider_id, p.name AS provider_name,
         o.upstream_model_id, o.role, o.priority, o.weight, o.canary_percent,
         o.shadow_percent, o.shadow_max_requests, o.capabilities_json,
         o.context_window, o.region, o.zero_data_retention,
         o.input_price_per_1m, o.output_price_per_1m,
         o.cached_input_price_per_1m, o.cache_write_price_per_1m,
         o.reasoning_price_per_1m, o.audio_second_price_per_1m,
         o.audio_character_price_per_1m, o.currency, o.source, o.enabled
    FROM ${PLATFORM_OFFERING_TABLE} o
    LEFT JOIN ${PLATFORM_PROVIDER_TABLE} p
      ON p.id = o.provider_id`;

/**
 * `scope` replaces the tenant store's `tenant_id` on every projected record.
 *
 * It is not decoration: the route layer answers the SAME operation ids for both
 * catalogs, so a caller that reads a record must be able to tell which store
 * produced it, and a filter or console that keyed off `tenant_id` gets an
 * explicit "platform" rather than a silently missing field.
 */
const PLATFORM_SCOPE = "platform" as const;

/**
 * Raw provider columns for the provisioning seed (#891).
 *
 * Every column is carried verbatim — including the credential references
 * `providerRecord` collapses into `has_api_key` — because a seed is a COPY, and
 * the tenant `provider_channels` table has the same columns to receive them.
 */
function seedProvider(row: ProviderRow): SeedProviderChannel {
  return {
    id: row.id,
    name: row.name,
    kind: row.kind,
    base_url: row.base_url,
    api_key_var: row.api_key_var,
    byok_alias: row.byok_alias,
    auth_scheme: row.auth_scheme,
    region: row.region,
    zero_data_retention: row.zero_data_retention,
    openrouter_http_referer: row.openrouter_http_referer,
    openrouter_x_title: row.openrouter_x_title,
    cloudflare_ai_gateway_json: row.cloudflare_ai_gateway_json,
    enabled: row.enabled,
  };
}

/** Raw model columns for the provisioning seed (#891). */
function seedModel(row: ModelRow): SeedCatalogModel {
  return {
    id: row.id,
    name: row.name,
    family: row.family,
    owned_by: row.owned_by,
    capabilities_json: row.capabilities_json,
    context_window: row.context_window,
    routing_strategy: row.routing_strategy,
    enabled: row.enabled,
  };
}

/**
 * Raw offering columns for the provisioning seed (#891).
 *
 * The join-derived `provider_name` is dropped and the raw `provider_id` kept —
 * the seed re-qualifies ids by tenant. The platform `source` column is dropped
 * too: the seed writer forces `platform_seed` so a tenant edit stays
 * distinguishable from an untouched seed row.
 */
function seedOffering(row: OfferingRow): SeedCatalogOffering {
  return {
    id: row.id,
    model_id: row.model_id,
    provider_id: row.provider_id,
    upstream_model_id: row.upstream_model_id,
    role: row.role,
    priority: row.priority,
    weight: row.weight,
    canary_percent: row.canary_percent,
    shadow_percent: row.shadow_percent,
    shadow_max_requests: row.shadow_max_requests,
    capabilities_json: row.capabilities_json,
    context_window: row.context_window,
    region: row.region,
    zero_data_retention: row.zero_data_retention,
    input_price_per_1m: row.input_price_per_1m,
    output_price_per_1m: row.output_price_per_1m,
    cached_input_price_per_1m: row.cached_input_price_per_1m,
    cache_write_price_per_1m: row.cache_write_price_per_1m,
    reasoning_price_per_1m: row.reasoning_price_per_1m,
    audio_second_price_per_1m: row.audio_second_price_per_1m,
    audio_character_price_per_1m: row.audio_character_price_per_1m,
    currency: row.currency,
    enabled: row.enabled,
  };
}

function providerRecord(row: ProviderRow): CatalogRecord {
  return {
    id: row.id,
    scope: PLATFORM_SCOPE,
    name: row.name,
    provider_type_id: row.provider_type_id,
    kind: row.kind,
    compatibility: providerCompatibility(row.kind),
    base_url: row.base_url,
    has_api_key: Boolean(row.api_key_var || row.byok_alias),
    byok_alias: row.byok_alias,
    auth_scheme: row.auth_scheme,
    region: row.region,
    zero_data_retention: boolValue(row.zero_data_retention),
    openrouter_http_referer: row.openrouter_http_referer,
    openrouter_x_title: row.openrouter_x_title,
    cloudflare_ai_gateway: row.cloudflare_ai_gateway_json
      ? JSON.parse(row.cloudflare_ai_gateway_json)
      : null,
    enabled: boolValue(row.enabled, true),
  };
}

function offeringRecord(row: OfferingRow): CatalogRecord {
  return {
    id: row.id,
    scope: PLATFORM_SCOPE,
    model_id: row.model_id,
    provider_id: row.provider_id,
    provider: row.provider_name,
    upstream_model_id: row.upstream_model_id,
    role: row.role,
    priority: row.priority,
    weight: row.weight,
    canary_percent: row.canary_percent,
    shadow_percent: row.shadow_percent,
    shadow_max_requests: row.shadow_max_requests,
    capabilities: parsedArray(row.capabilities_json),
    context_window: row.context_window,
    region: row.region,
    zero_data_retention: boolValue(row.zero_data_retention),
    input_price_per_1m: row.input_price_per_1m,
    output_price_per_1m: row.output_price_per_1m,
    cached_input_price_per_1m: row.cached_input_price_per_1m,
    cache_write_price_per_1m: row.cache_write_price_per_1m,
    reasoning_price_per_1m: row.reasoning_price_per_1m,
    audio_second_price_per_1m: row.audio_second_price_per_1m,
    audio_character_price_per_1m: row.audio_character_price_per_1m,
    currency: row.currency,
    source: row.source,
    enabled: boolValue(row.enabled, true),
  };
}

function routeRecord(row: OfferingRow): CatalogRecord {
  return {
    id: row.id,
    provider: row.provider_name,
    provider_model: row.upstream_model_id,
    capabilities: parsedArray(row.capabilities_json),
    priority: row.priority,
    weight: row.weight,
    input_price_per_1m: row.input_price_per_1m,
    output_price_per_1m: row.output_price_per_1m,
    cached_input_price_per_1m: row.cached_input_price_per_1m,
    cache_write_price_per_1m: row.cache_write_price_per_1m,
    reasoning_price_per_1m: row.reasoning_price_per_1m,
    audio_second_price_per_1m: row.audio_second_price_per_1m,
    audio_character_price_per_1m: row.audio_character_price_per_1m,
  };
}

function modelRecord(row: ModelRow, offerings: readonly OfferingRow[]): CatalogRecord {
  const primary = offerings.find((offering) => offering.role === "primary") ?? offerings[0];
  return {
    id: row.id,
    scope: PLATFORM_SCOPE,
    name: row.name,
    family: row.family,
    owned_by: row.owned_by,
    capabilities: parsedArray(row.capabilities_json),
    context_window: row.context_window,
    routing_strategy: row.routing_strategy,
    enabled: boolValue(row.enabled, true),
    provider: primary?.provider_name ?? null,
    provider_model: primary?.upstream_model_id ?? null,
    fallbacks: offerings.filter((offering) => offering.role === "fallback").map(routeRecord),
    offerings: offerings.map(offeringRecord),
  };
}

function updateStatement(
  db: D1Database,
  table: string,
  fields: readonly UpdateField[],
  id: string,
  now: number,
  ignoreConflicts = false,
): D1PreparedStatement {
  const assignments = fields.map(([column]) => `${column} = ?`).join(", ");
  const verb = ignoreConflicts ? "UPDATE OR IGNORE" : "UPDATE";
  return db
    .prepare(
      `${verb} ${table}
          SET ${assignments}, updated_at_unix = ?
        WHERE id = ?`,
    )
    .bind(...fields.map(([, value]) => value), now, id);
}

/** The nullable per-million price columns an offering carries. */
const PRICE_COLUMNS = [
  "input_price_per_1m",
  "output_price_per_1m",
  "cached_input_price_per_1m",
  "cache_write_price_per_1m",
  "reasoning_price_per_1m",
  "audio_second_price_per_1m",
  "audio_character_price_per_1m",
] as const;

export class PlatformModelCatalogStore {
  readonly #db: D1Database;
  readonly #requestId: string;

  constructor(options: PlatformModelCatalogStoreOptions) {
    this.#db = options.db;
    this.#requestId = options.requestId ?? "";
  }

  /**
   * Has this deployment ADOPTED the platform catalog?
   *
   * The admin surface answers the same operation ids for two stores, and the
   * question "which one does a platform operator that named no tenant mean?"
   * has no answer that is right for every deployment. This is the tie-break,
   * and it is deliberately ONE predicate for providers, models and offerings
   * alike: deciding it per resource would let one session be shown the platform
   * provider list and the tenant-aggregate model list at once, and binding a
   * model from one to a provider from the other is a 404.
   *
   * `true` once anything has been written here — the revision row survives
   * deleting every row back out again, so a catalog emptied on purpose stays
   * adopted rather than silently reverting the whole surface to tenant
   * semantics. `false` on a deployment that has never used it, including one
   * where migration `0025` has not been applied yet: a missing table means "not
   * adopted", never a 500 on a read path that worked before #889.
   */
  async isAdopted(): Promise<boolean> {
    try {
      const row = await this.#db
        .prepare(
          `SELECT (EXISTS (SELECT 1 FROM ${PLATFORM_REVISION_TABLE} WHERE id = 1)
                OR EXISTS (SELECT 1 FROM ${PLATFORM_PROVIDER_TABLE})
                OR EXISTS (SELECT 1 FROM ${PLATFORM_MODEL_TABLE})) AS adopted`,
        )
        .first<{ adopted: number }>();
      return Number(row?.adopted ?? 0) === 1;
    } catch (error) {
      if (isMissingPlatformCatalogError(error)) return false;
      throw error;
    }
  }

  /**
   * The full 3-entity graph as the tenant provisioning seed copies it (#891).
   *
   * Deliberately NOT the masked {@link providerRecord}/{@link offeringRecord}
   * projections the admin surface returns: a seed is a verbatim COPY, so this
   * carries the raw storage columns — `api_key_var`/`byok_alias` intact rather
   * than a `has_api_key` boolean, every offering role and price rather than one
   * primary per model. The `revision` is read in the same window so the caller
   * can record WHICH platform catalog seeded a tenant.
   *
   * An absent catalog (migration `0025` not applied yet — the `d1_compat`
   * window `isMissingPlatformCatalogError` describes) is an EMPTY graph, never a
   * throw: the provisioner reads that as "not adopted" and seeds the compiled-in
   * card, exactly as {@link isAdopted} returns `false` there.
   */
  async exportForSeed(): Promise<TenantModelCatalogSeedGraph> {
    try {
      const [providers, models, offerings] = await Promise.all([
        this.#db
          .prepare(`${PROVIDER_SELECT} ORDER BY created_at_unix ASC, id ASC`)
          .all<ProviderRow>(),
        this.#db.prepare(`${MODEL_SELECT} ORDER BY created_at_unix ASC, id ASC`).all<ModelRow>(),
        this.#offeringRows(),
      ]);
      // A `kind = 'platform'` channel is the bootstrap import's (#892) managed
      // record of the default rate card: it carries PRICES but names no physical
      // upstream (`platform://default`), so it is not a routable leg. #891's seed
      // copies real channels VERBATIM and the tenant loader resolves a
      // `platform`-kind row against the platform registry — which, with these
      // price-only rows excluded from the platform route build, does not know the
      // rate-card models. Seeding them would therefore give a tenant a channel it
      // can never route through, so they are excluded here, keeping the seed to
      // the "real channels stay real" invariant `seedTenantModelCatalogFromGraph`
      // is built on. A model left with no routable offering is dropped with them;
      // a model that never had any offering is preserved (pre-#892 behaviour).
      const platformProviderIds = new Set(
        providers.results.filter((row) => row.kind === "platform").map((row) => row.id),
      );
      const seedProviders = providers.results.filter((row) => !platformProviderIds.has(row.id));
      const seedOfferings = offerings.filter((row) => !platformProviderIds.has(row.provider_id));
      const modelsWithKeptOffering = new Set(seedOfferings.map((row) => row.model_id));
      const modelsWithAnyOffering = new Set(offerings.map((row) => row.model_id));
      const seedModels = models.results.filter(
        (row) => modelsWithKeptOffering.has(row.id) || !modelsWithAnyOffering.has(row.id),
      );
      return {
        revision: await this.#revision(),
        providers: seedProviders.map(seedProvider),
        models: seedModels.map(seedModel),
        offerings: seedOfferings.map(seedOffering),
      };
    } catch (error) {
      if (isMissingPlatformCatalogError(error)) {
        return { revision: 0, providers: [], models: [], offerings: [] };
      }
      throw error;
    }
  }

  /**
   * Row counts for `GET /admin/v1/status` (#893), one round-trip.
   *
   * A deployment that has NOT applied migration `0025` has no platform tables;
   * that is "not adopted", never a 500 on the status endpoint an operator hits
   * to find out what is wrong — so a missing table reads as three zeros, exactly
   * as `isAdopted()` treats it. Every other error still propagates.
   */
  async counts(): Promise<{
    readonly providers: number;
    readonly models: number;
    readonly offerings: number;
  }> {
    try {
      const row = await this.#db
        .prepare(
          `SELECT
             (SELECT COUNT(*) FROM ${PLATFORM_PROVIDER_TABLE}) AS providers,
             (SELECT COUNT(*) FROM ${PLATFORM_MODEL_TABLE}) AS models,
             (SELECT COUNT(*) FROM ${PLATFORM_OFFERING_TABLE}) AS offerings`,
        )
        .first<{
          providers: number | string;
          models: number | string;
          offerings: number | string;
        }>();
      return {
        providers: Number(row?.providers ?? 0),
        models: Number(row?.models ?? 0),
        offerings: Number(row?.offerings ?? 0),
      };
    } catch (error) {
      if (isMissingPlatformCatalogError(error)) {
        return { providers: 0, models: 0, offerings: 0 };
      }
      throw error;
    }
  }

  /**
   * The bootstrap import (#892): write a whole provider/model/offering graph,
   * bump the revision ONCE, append ONE audit row — all in one batch.
   *
   * IDEMPOTENT by construction: every row carries a deterministic id derived from
   * its natural key (`platform:provider:<name>`, `platform:model:<name>`,
   * `platform:offering:<model>:<provider>:<upstream>`) and every INSERT is
   * `OR IGNORE`, so a re-run inserts nothing and the only thing that changes is
   * the revision — exactly the invariant #892's parity test asserts.
   *
   * The batch shape mirrors {@link #commit} (revision init, mutations, revision
   * bump, audit) with two differences dictated by the bulk shape:
   *
   *  - the mutation is MANY statements rather than one, so the revision bump is
   *    UNCONDITIONAL (`#commit` guards it on the single mutation's `changes()`,
   *    which is meaningless across a batch) — an import is an operator action
   *    worth one revision whether or not it changed a row;
   *  - the audit INSERT's `changes() = 1` guard therefore reads from the bump,
   *    which the up-front `INSERT OR IGNORE` revision row guarantees is 1.
   *
   * Providers precede models precede offerings so the offering foreign keys are
   * satisfied within the single transaction. Returns both the rows this call
   * INSERTED (`0` on a re-run) and the resulting totals, which is the count
   * verification shape an operator runs in production.
   *
   * ONE cross-run correction is not a no-op: when an earlier import wrote a
   * `platform-default` rate-card PRIMARY offering for a model (the model had no
   * env route then) and this import now carries a REAL provider offering for the
   * same model — the advertised "re-run to sync env changes" flow, where a
   * default-card name like `gpt-4o` is later added to `GATEWAY_MODELS` — the
   * rate-card row still occupies the `ux_..._primary` slot, so the real primary's
   * `INSERT OR IGNORE` would be silently dropped and the model would stay
   * unroutable. The superseded `platform-default` offerings for such models are
   * therefore DELETEd first (see {@link #purgeSupersededRateCardStatements}); the
   * delete matches zero rows on a steady-state re-run, so idempotency holds.
   */
  async importGraph(
    scope: CallerScope,
    graph: PlatformCatalogImportGraph,
  ): Promise<{
    readonly revision: number;
    readonly inserted: { providers: number; models: number; offerings: number };
    readonly counts: { providers: number; models: number; offerings: number };
  }> {
    const providerInserts = graph.providers.map((provider) =>
      this.#importProviderStatement(provider),
    );
    const modelInserts = graph.models.map((model) => this.#importModelStatement(model));
    // Free the primary slot for any model this import now routes through a REAL
    // provider, dropping the stale `platform-default` rate-card offering an
    // earlier import left there (see the docblock). Ordered BEFORE the offering
    // inserts so the real primary's INSERT wins the `ux_..._primary` index.
    const rateCardPurges = this.#purgeSupersededRateCardStatements(graph);
    const offeringInserts = graph.offerings.map((offering) =>
      this.#importOfferingStatement(offering),
    );
    const mutations = [...providerInserts, ...modelInserts, ...rateCardPurges, ...offeringInserts];

    let lastError: unknown;
    for (let attempt = 1; attempt <= PLATFORM_COMMIT_ATTEMPTS; attempt += 1) {
      const now = Math.floor(Date.now() / 1000);
      const revision = (await this.#revision()) + 1;
      const record: StoreRecord = { id: IMPORT_RECORD_ID, scope: PLATFORM_SCOPE };
      let results: readonly D1Result<unknown>[];
      try {
        results = await this.#db.batch([
          this.#db
            .prepare(
              `INSERT OR IGNORE INTO ${PLATFORM_REVISION_TABLE} (id, revision, updated_at_unix)
               VALUES (1, 0, ?)`,
            )
            .bind(now),
          ...mutations,
          this.#db
            .prepare(
              `UPDATE ${PLATFORM_REVISION_TABLE}
                  SET revision = revision + 1, updated_at_unix = ?
                WHERE id = 1
                RETURNING revision`,
            )
            .bind(now),
          await controlPlaneAuditStatement(this.#db, {
            action: "create",
            collection: IMPORT_COLLECTION,
            record,
            revision,
            scope,
            requestId: this.#requestId,
            auditJson: controlPlaneAuditJson({
              action: "create",
              collection: IMPORT_COLLECTION,
              record,
              revision,
              scope,
            }),
          }),
        ]);
      } catch (error) {
        lastError = error;
        continue;
      }

      // results: [init, ...mutations, bump, audit]. The mutation slice starts at 1.
      const bumpIndex = 1 + mutations.length;
      const bump = results[bumpIndex];
      const bumped = Number(
        (bump?.results?.[0] as { revision?: number | string } | undefined)?.revision ?? 0,
      );
      if (bumped !== revision) {
        throw new Error(
          `platform model catalog revision bumped to ${bumped}, audited as ${revision}`,
        );
      }
      if (Number(results[bumpIndex + 1]?.meta.changes ?? 0) === 0) {
        throw new Error(
          "platform model catalog import audit row was not appended with the mutation",
        );
      }

      const changesIn = (start: number, count: number): number => {
        let total = 0;
        for (let index = start; index < start + count; index += 1) {
          total += Number(results[index]?.meta.changes ?? 0);
        }
        return total;
      };
      const providersInserted = changesIn(1, providerInserts.length);
      const modelsInserted = changesIn(1 + providerInserts.length, modelInserts.length);
      const offeringsInserted = changesIn(
        1 + providerInserts.length + modelInserts.length + rateCardPurges.length,
        offeringInserts.length,
      );
      return {
        revision: bumped,
        inserted: {
          providers: providersInserted,
          models: modelsInserted,
          offerings: offeringsInserted,
        },
        counts: await this.counts(),
      };
    }
    if (isConstraintError(lastError) && !isAuditAppendError(lastError)) {
      throw new TenantCatalogConflictError("platform model catalog constraint violated");
    }
    throw new Error(
      `platform model catalog import failed after ${PLATFORM_COMMIT_ATTEMPTS} attempts`,
      { cause: lastError },
    );
  }

  /**
   * DELETE the stale `platform-default` rate-card offerings for every model this
   * import routes through a REAL provider, so the real primary can take the
   * `ux_..._primary` slot on re-run (see {@link importGraph}'s docblock).
   *
   * A model is "now real" when this graph carries any offering for it on a
   * provider OTHER than `platform-default`; that offering supersedes the
   * rate-card price row, which the data-plane loader already excludes from
   * routing. On a steady-state re-run the model's only offering is the real one
   * (the rate card was purged the first time round), so the DELETE matches zero
   * rows and the run stays a no-op but for the revision.
   */
  #purgeSupersededRateCardStatements(graph: PlatformCatalogImportGraph): D1PreparedStatement[] {
    const nowRealModelIds = new Set<string>();
    for (const offering of graph.offerings) {
      if (offering.provider_id !== PLATFORM_DEFAULT_PROVIDER_ID) {
        nowRealModelIds.add(offering.model_id);
      }
    }
    return [...nowRealModelIds].map((modelId) =>
      this.#db
        .prepare(
          `DELETE FROM ${PLATFORM_OFFERING_TABLE}
             WHERE model_id = ? AND provider_id = ?`,
        )
        .bind(modelId, PLATFORM_DEFAULT_PROVIDER_ID),
    );
  }

  #importProviderStatement(provider: SeedProviderChannel): D1PreparedStatement {
    const now = Math.floor(Date.now() / 1000);
    const providerTypeId = inferProviderTypeIdFromKind(provider.kind);
    return this.#db
      .prepare(
        `INSERT OR IGNORE INTO ${PLATFORM_PROVIDER_TABLE}
           (id, name, provider_type_id, kind, base_url, api_key_var, byok_alias,
            auth_scheme, region, zero_data_retention, openrouter_http_referer,
            openrouter_x_title, cloudflare_ai_gateway_json, enabled,
            created_at_unix, updated_at_unix)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        provider.id,
        provider.name,
        providerTypeId,
        provider.kind,
        provider.base_url,
        provider.api_key_var,
        provider.byok_alias,
        provider.auth_scheme,
        provider.region,
        provider.zero_data_retention,
        provider.openrouter_http_referer,
        provider.openrouter_x_title,
        provider.cloudflare_ai_gateway_json,
        provider.enabled,
        now,
        now,
      );
  }

  #importModelStatement(model: SeedCatalogModel): D1PreparedStatement {
    const now = Math.floor(Date.now() / 1000);
    return this.#db
      .prepare(
        `INSERT OR IGNORE INTO ${PLATFORM_MODEL_TABLE}
           (id, name, family, owned_by, capabilities_json,
            context_window, routing_strategy, enabled, created_at_unix, updated_at_unix)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        model.id,
        model.name,
        model.family,
        model.owned_by,
        model.capabilities_json,
        model.context_window,
        model.routing_strategy,
        model.enabled,
        now,
        now,
      );
  }

  #importOfferingStatement(
    offering: PlatformCatalogImportGraph["offerings"][number],
  ): D1PreparedStatement {
    const now = Math.floor(Date.now() / 1000);
    return this.#db
      .prepare(
        `INSERT OR IGNORE INTO ${PLATFORM_OFFERING_TABLE}
           (id, model_id, provider_id, upstream_model_id, role,
            priority, weight, canary_percent, shadow_percent, shadow_max_requests,
            capabilities_json, context_window, region, zero_data_retention,
            input_price_per_1m, output_price_per_1m, cached_input_price_per_1m,
            cache_write_price_per_1m, reasoning_price_per_1m,
            audio_second_price_per_1m, audio_character_price_per_1m,
            currency, source, enabled, created_at_unix, updated_at_unix)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        offering.id,
        offering.model_id,
        offering.provider_id,
        offering.upstream_model_id,
        offering.role,
        offering.priority,
        offering.weight,
        offering.canary_percent,
        offering.shadow_percent,
        offering.shadow_max_requests,
        offering.capabilities_json,
        offering.context_window,
        offering.region,
        offering.zero_data_retention,
        offering.input_price_per_1m,
        offering.output_price_per_1m,
        offering.cached_input_price_per_1m,
        offering.cache_write_price_per_1m,
        offering.reasoning_price_per_1m,
        offering.audio_second_price_per_1m,
        offering.audio_character_price_per_1m,
        offering.currency,
        offering.source,
        offering.enabled,
        now,
        now,
      );
  }

  async listProviders(): Promise<readonly CatalogRecord[]> {
    const result = await this.#db
      .prepare(`${PROVIDER_SELECT} ORDER BY created_at_unix ASC, id ASC`)
      .all<ProviderRow>();
    return result.results.map(providerRecord);
  }

  async getProvider(id: string): Promise<CatalogRecord | null> {
    const row = await this.#providerRow(id);
    return row === null ? null : providerRecord(row);
  }

  /**
   * The RAW provider channel columns — including `api_key_var`/`byok_alias` —
   * for the model sync (#944).
   *
   * Deliberately NOT {@link getProvider}, whose {@link providerRecord} masks the
   * credential reference into a `has_api_key` boolean: the sync must READ
   * `api_key_var` to resolve the outbound credential it presents to the
   * upstream, so it needs the same verbatim shape {@link exportForSeed} carries
   * (`seedProvider`), never the admin projection. The resolved secret VALUE
   * never enters this store — the reference name is all it returns.
   */
  async getProviderSeed(id: string): Promise<SeedProviderChannel | null> {
    const row = await this.#providerRow(id);
    return row === null ? null : seedProvider(row);
  }

  async createProvider(scope: CallerScope, input: ProviderChannelInput): Promise<CatalogRecord> {
    const normalized = this.#validateProvider(input);
    const now = Math.floor(Date.now() / 1000);
    await this.#commit(
      scope,
      "create",
      PROVIDER_COLLECTION,
      { id: input.id, scope: PLATFORM_SCOPE },
      this.#db
        .prepare(
          `INSERT OR IGNORE INTO ${PLATFORM_PROVIDER_TABLE}
             (id, name, provider_type_id, kind, base_url, api_key_var, byok_alias,
              auth_scheme, region, zero_data_retention, openrouter_http_referer,
              openrouter_x_title, cloudflare_ai_gateway_json, enabled,
              created_at_unix, updated_at_unix)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          input.id,
          normalized.name,
          normalized.provider_type_id,
          normalized.kind,
          normalized.base_url,
          input.api_key_var ?? null,
          input.byok_alias ?? null,
          input.auth_scheme ?? null,
          input.region ?? null,
          boolSql(input.zero_data_retention, null),
          input.openrouter_http_referer ?? null,
          input.openrouter_x_title ?? null,
          input.cloudflare_ai_gateway === undefined || input.cloudflare_ai_gateway === null
            ? null
            : JSON.stringify(input.cloudflare_ai_gateway),
          boolSql(input.enabled),
          now,
          now,
        ),
      true,
    );
    const stored = await this.getProvider(input.id);
    if (stored === null) throw new Error(`platform provider ${input.id} disappeared after create`);
    return stored;
  }

  async updateProvider(
    scope: CallerScope,
    id: string,
    input: Partial<ProviderChannelInput>,
    action: "replace" | "merge",
  ): Promise<CatalogRecord | null> {
    const current = await this.#providerRow(id);
    if (current === null) return null;
    const fields: UpdateField[] = [];
    if (action === "replace") {
      const name = this.#requiredText(input.name ?? current.name, "name");
      const kind = this.#requiredKind(input.kind ?? current.kind);
      const providerTypeId = this.#requiredProviderType(
        input.provider_type_id ?? current.provider_type_id,
        kind,
      );
      await this.#assertProviderTypeCompatibleWithGroups(id, providerTypeId);
      const baseUrl = this.#requiredText(input.base_url ?? current.base_url, "base_url");
      if (!urlIsValid(baseUrl)) throw new TenantCatalogValidationError("base_url must be a URL");
      fields.push(
        ["name", name],
        ["provider_type_id", providerTypeId],
        ["kind", kind],
        ["base_url", baseUrl],
      );
      fields.push(["api_key_var", input.api_key_var ?? null]);
      fields.push(["byok_alias", input.byok_alias ?? null]);
      fields.push(["auth_scheme", input.auth_scheme ?? null]);
      fields.push(["region", input.region ?? null]);
      fields.push(["zero_data_retention", boolSql(input.zero_data_retention, null)]);
      fields.push(["openrouter_http_referer", input.openrouter_http_referer ?? null]);
      fields.push(["openrouter_x_title", input.openrouter_x_title ?? null]);
      fields.push([
        "cloudflare_ai_gateway_json",
        input.cloudflare_ai_gateway === undefined || input.cloudflare_ai_gateway === null
          ? null
          : JSON.stringify(input.cloudflare_ai_gateway),
      ]);
      fields.push(["enabled", boolSql(input.enabled)]);
    } else {
      if (input.name !== undefined) fields.push(["name", this.#requiredText(input.name, "name")]);
      if (input.provider_type_id !== undefined) {
        const providerTypeId = this.#requiredProviderType(
          input.provider_type_id,
          input.kind ?? current.kind,
        );
        await this.#assertProviderTypeCompatibleWithGroups(id, providerTypeId);
        fields.push(["provider_type_id", providerTypeId]);
      }
      if (input.kind !== undefined) fields.push(["kind", this.#requiredKind(input.kind)]);
      if (input.base_url !== undefined) {
        const baseUrl = this.#requiredText(input.base_url, "base_url");
        if (!urlIsValid(baseUrl)) throw new TenantCatalogValidationError("base_url must be a URL");
        fields.push(["base_url", baseUrl]);
      }
      if (hasOwn(input, "api_key_var")) fields.push(["api_key_var", input.api_key_var ?? null]);
      if (hasOwn(input, "byok_alias")) fields.push(["byok_alias", input.byok_alias ?? null]);
      if (hasOwn(input, "auth_scheme")) fields.push(["auth_scheme", input.auth_scheme ?? null]);
      if (hasOwn(input, "region")) fields.push(["region", input.region ?? null]);
      if (hasOwn(input, "zero_data_retention")) {
        fields.push(["zero_data_retention", boolSql(input.zero_data_retention, null)]);
      }
      if (hasOwn(input, "openrouter_http_referer")) {
        fields.push(["openrouter_http_referer", input.openrouter_http_referer ?? null]);
      }
      if (hasOwn(input, "openrouter_x_title")) {
        fields.push(["openrouter_x_title", input.openrouter_x_title ?? null]);
      }
      if (hasOwn(input, "cloudflare_ai_gateway")) {
        fields.push([
          "cloudflare_ai_gateway_json",
          input.cloudflare_ai_gateway === undefined || input.cloudflare_ai_gateway === null
            ? null
            : JSON.stringify(input.cloudflare_ai_gateway),
        ]);
      }
      if (input.enabled !== undefined) fields.push(["enabled", boolSql(input.enabled)]);
    }
    if (fields.length === 0) fields.push(["name", current.name]);
    const changed = await this.#commit(
      scope,
      action,
      PROVIDER_COLLECTION,
      { id, scope: PLATFORM_SCOPE },
      updateStatement(
        this.#db,
        PLATFORM_PROVIDER_TABLE,
        fields,
        id,
        Math.floor(Date.now() / 1000),
        true,
      ),
      true,
    );
    return changed ? this.getProvider(id) : null;
  }

  async deleteProvider(scope: CallerScope, id: string): Promise<boolean> {
    if ((await this.#providerRow(id)) === null) return false;
    if (await this.#providerHasOfferings(id)) {
      throw new TenantCatalogConflictError(`platform provider ${id} has live offerings`);
    }
    const deleted = await this.#commit(
      scope,
      "remove",
      PROVIDER_COLLECTION,
      { id, scope: PLATFORM_SCOPE },
      this.#db
        .prepare(
          `DELETE FROM ${PLATFORM_PROVIDER_TABLE}
            WHERE id = ?
              AND NOT EXISTS (
                SELECT 1 FROM ${PLATFORM_OFFERING_TABLE} WHERE provider_id = ?
              )`,
        )
        .bind(id, id),
    );
    if (deleted) return true;

    // Same two-phase read as the tenant store: the preflight and the guarded
    // DELETE bracket one atomic batch, so an offering created in that window
    // turns the DELETE into a no-op that must still report the conflict rather
    // than a bare 404. `ON DELETE RESTRICT` alone would surface as an opaque
    // constraint error with no way to tell the two cases apart.
    if ((await this.#providerRow(id)) === null) return false;
    throw new TenantCatalogConflictError(
      (await this.#providerHasOfferings(id))
        ? `platform provider ${id} has live offerings`
        : `platform provider ${id} could not be deleted`,
    );
  }

  async #providerHasOfferings(id: string): Promise<boolean> {
    const live = await this.#db
      .prepare(`SELECT 1 AS present FROM ${PLATFORM_OFFERING_TABLE} WHERE provider_id = ? LIMIT 1`)
      .bind(id)
      .first<{ present: number }>();
    return live !== null;
  }

  async #providerRow(id: string): Promise<ProviderRow | null> {
    return this.#db.prepare(`${PROVIDER_SELECT} WHERE id = ?`).bind(id).first<ProviderRow>();
  }

  #requiredText(value: string, field: string): string {
    if (typeof value !== "string" || value.trim() === "") {
      throw new TenantCatalogValidationError(`${field} is required`);
    }
    return value.trim();
  }

  /**
   * `kind` is validated by the SAME `canonicalProviderKind` the tenant store
   * uses, which is what rejects `"platform"` here: that kind is a tenant-side
   * indirection INTO this catalog, so a platform channel claiming it would
   * point the platform default at itself.
   */
  #requiredKind(kind: string): string {
    const canonical = canonicalProviderKind(kind);
    if (canonical === null) {
      throw new TenantCatalogValidationError(`unsupported provider kind: ${kind}`);
    }
    return canonical;
  }

  #requiredProviderType(value: unknown, kind: string): ProviderTypeId {
    const providerTypeId = value ?? inferProviderTypeIdFromKind(kind);
    if (!isProviderTypeId(providerTypeId)) {
      throw new TenantCatalogValidationError("provider_type_id is required and must be supported");
    }
    return providerTypeId;
  }

  async #assertProviderTypeCompatibleWithGroups(
    providerId: string,
    providerTypeId: ProviderTypeId,
  ): Promise<void> {
    const row = await this.#db
      .prepare(
        `SELECT COUNT(*) AS mismatches
           FROM platform_billing_group_providers AS edge
           JOIN platform_billing_groups AS billing_group ON billing_group.id = edge.group_id
          WHERE edge.provider_id = ?
            AND (billing_group.provider_type_id IS NULL OR billing_group.provider_type_id <> ?)`,
      )
      .bind(providerId, providerTypeId)
      .first<{ mismatches: number | string }>();
    if (Number(row?.mismatches ?? 0) > 0) {
      throw new TenantCatalogValidationError(
        `provider ${providerId} is bound to a billing group with a different provider type`,
      );
    }
  }

  #validateProvider(input: ProviderChannelInput): {
    name: string;
    provider_type_id: ProviderTypeId;
    kind: string;
    base_url: string;
  } {
    const name = this.#requiredText(input.name, "name");
    const kind = this.#requiredKind(input.kind);
    const baseUrl = this.#requiredText(input.base_url, "base_url");
    if (!urlIsValid(baseUrl)) throw new TenantCatalogValidationError("base_url must be a URL");
    return {
      name,
      provider_type_id: this.#requiredProviderType(input.provider_type_id, kind),
      kind,
      base_url: baseUrl,
    };
  }

  async listModels(): Promise<readonly CatalogRecord[]> {
    const [models, offerings] = await Promise.all([
      this.#db.prepare(`${MODEL_SELECT} ORDER BY created_at_unix ASC, id ASC`).all<ModelRow>(),
      this.#offeringRows(),
    ]);
    const byModel = new Map<string, OfferingRow[]>();
    for (const offering of offerings) {
      const group = byModel.get(offering.model_id);
      if (group === undefined) byModel.set(offering.model_id, [offering]);
      else group.push(offering);
    }
    return models.results.map((model) => modelRecord(model, byModel.get(model.id) ?? []));
  }

  async getModel(id: string): Promise<CatalogRecord | null> {
    const row = await this.#modelRow(id);
    return row === null ? null : modelRecord(row, await this.#offeringRows(id));
  }

  async createModel(scope: CallerScope, input: ModelCatalogInput): Promise<CatalogRecord> {
    const normalized = this.#validateModel(input);
    const now = Math.floor(Date.now() / 1000);
    await this.#commit(
      scope,
      "create",
      MODEL_COLLECTION,
      { id: input.id, scope: PLATFORM_SCOPE },
      this.#db
        .prepare(
          `INSERT OR IGNORE INTO ${PLATFORM_MODEL_TABLE}
             (id, name, family, owned_by, capabilities_json,
              context_window, routing_strategy, enabled, created_at_unix, updated_at_unix)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          input.id,
          normalized.name,
          input.family ?? null,
          input.owned_by ?? null,
          jsonArray(input.capabilities, "capabilities"),
          input.context_window ?? null,
          input.routing_strategy ?? "priority",
          boolSql(input.enabled),
          now,
          now,
        ),
      true,
    );
    const stored = await this.getModel(input.id);
    if (stored === null) throw new Error(`platform model ${input.id} disappeared after create`);
    return stored;
  }

  async updateModel(
    scope: CallerScope,
    id: string,
    input: Partial<ModelCatalogInput>,
    action: "replace" | "merge",
  ): Promise<CatalogRecord | null> {
    const current = await this.#modelRow(id);
    if (current === null) return null;
    const fields: UpdateField[] = [];
    if (action === "replace") {
      const contextWindow = input.context_window ?? null;
      this.#requireContextWindow(contextWindow);
      fields.push(
        ["name", this.#requiredText(input.name ?? current.name, "name")],
        ["family", input.family ?? null],
        ["owned_by", input.owned_by ?? null],
        ["capabilities_json", jsonArray(input.capabilities, "capabilities")],
        ["context_window", contextWindow],
        ["routing_strategy", input.routing_strategy ?? "priority"],
        ["enabled", boolSql(input.enabled)],
      );
    } else {
      if (input.name !== undefined) fields.push(["name", this.#requiredText(input.name, "name")]);
      if (input.family !== undefined) fields.push(["family", input.family ?? null]);
      if (input.owned_by !== undefined) fields.push(["owned_by", input.owned_by ?? null]);
      if (input.capabilities !== undefined) {
        fields.push(["capabilities_json", jsonArray(input.capabilities, "capabilities")]);
      }
      if (input.context_window !== undefined) {
        this.#requireContextWindow(input.context_window);
        fields.push(["context_window", input.context_window]);
      }
      if (input.routing_strategy !== undefined) {
        fields.push(["routing_strategy", input.routing_strategy]);
      }
      if (input.enabled !== undefined) fields.push(["enabled", boolSql(input.enabled)]);
    }
    if (fields.length === 0) fields.push(["name", current.name]);
    const changed = await this.#commit(
      scope,
      action,
      MODEL_COLLECTION,
      { id, scope: PLATFORM_SCOPE },
      updateStatement(
        this.#db,
        PLATFORM_MODEL_TABLE,
        fields,
        id,
        Math.floor(Date.now() / 1000),
        true,
      ),
      true,
    );
    return changed ? this.getModel(id) : null;
  }

  async deleteModel(scope: CallerScope, id: string): Promise<boolean> {
    if ((await this.#modelRow(id)) === null) return false;
    return this.#commit(
      scope,
      "remove",
      MODEL_COLLECTION,
      { id, scope: PLATFORM_SCOPE },
      this.#db.prepare(`DELETE FROM ${PLATFORM_MODEL_TABLE} WHERE id = ?`).bind(id),
    );
  }

  async #modelRow(id: string): Promise<ModelRow | null> {
    return this.#db.prepare(`${MODEL_SELECT} WHERE id = ?`).bind(id).first<ModelRow>();
  }

  #requireContextWindow(value: number | null | undefined): void {
    if (value !== null && value !== undefined && (!Number.isInteger(value) || value <= 0)) {
      throw new TenantCatalogValidationError("context_window must be a positive integer");
    }
  }

  #validateModel(input: ModelCatalogInput): { name: string } {
    const name = this.#requiredText(input.name, "name");
    this.#requireContextWindow(input.context_window);
    return { name };
  }

  async listOfferings(modelId: string): Promise<readonly CatalogRecord[]> {
    if ((await this.#modelRow(modelId)) === null) {
      throw new TenantCatalogNotFoundError(`model ${modelId} not found`);
    }
    return (await this.#offeringRows(modelId)).map(offeringRecord);
  }

  /**
   * For the given `modelIds`, the provider that currently owns each one's single
   * `primary` offering slot — the input the provider-sync path needs to decide
   * whether a second provider's model must be laid down as a `fallback` rather
   * than collide with an existing primary (#944). A model_id with no primary is
   * absent from the map. The `platform-default` rate-card provider IS reported
   * (the caller ignores it, because {@link importGraph} purges that stale primary
   * in favour of a real provider's offering).
   */
  async primaryOfferingOwners(modelIds: readonly string[]): Promise<ReadonlyMap<string, string>> {
    const unique = [...new Set(modelIds)];
    if (unique.length === 0) return new Map();
    const placeholders = unique.map(() => "?").join(", ");
    const rows = (
      await this.#db
        .prepare(
          `SELECT model_id, provider_id FROM ${PLATFORM_OFFERING_TABLE}
            WHERE role = 'primary' AND model_id IN (${placeholders})`,
        )
        .bind(...unique)
        .all<{ model_id: string; provider_id: string }>()
    ).results;
    const owners = new Map<string, string>();
    for (const row of rows) owners.set(row.model_id, row.provider_id);
    return owners;
  }

  async createOffering(
    scope: CallerScope,
    modelId: string,
    input: ModelOfferingInput,
  ): Promise<CatalogRecord> {
    await this.#requireModelAndProvider(modelId, input.provider_id);
    const values = this.#validatedOffering(input);
    const now = Math.floor(Date.now() / 1000);
    await this.#commit(
      scope,
      "create",
      OFFERING_COLLECTION,
      { id: input.id, scope: PLATFORM_SCOPE },
      this.#db
        .prepare(
          `INSERT OR IGNORE INTO ${PLATFORM_OFFERING_TABLE}
             (id, model_id, provider_id, upstream_model_id, role,
              priority, weight, canary_percent, shadow_percent, shadow_max_requests,
              capabilities_json, context_window, region, zero_data_retention,
              input_price_per_1m, output_price_per_1m, cached_input_price_per_1m,
              cache_write_price_per_1m, reasoning_price_per_1m,
              audio_second_price_per_1m, audio_character_price_per_1m,
              currency, source, enabled, created_at_unix, updated_at_unix)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          input.id,
          modelId,
          input.provider_id,
          input.upstream_model_id,
          values.role,
          values.priority,
          values.weight,
          values.canary_percent,
          values.shadow_percent,
          values.shadow_max_requests,
          input.capabilities === undefined || input.capabilities === null
            ? null
            : jsonArray(input.capabilities, "capabilities"),
          input.context_window ?? null,
          input.region ?? null,
          boolSql(input.zero_data_retention, null),
          input.input_price_per_1m ?? null,
          input.output_price_per_1m ?? null,
          input.cached_input_price_per_1m ?? null,
          input.cache_write_price_per_1m ?? null,
          input.reasoning_price_per_1m ?? null,
          input.audio_second_price_per_1m ?? null,
          input.audio_character_price_per_1m ?? null,
          input.currency ?? "USD",
          input.source ?? "admin",
          boolSql(input.enabled),
          now,
          now,
        ),
      true,
    );
    const stored = await this.#offeringRow(modelId, input.id);
    if (stored === null) throw new Error(`platform offering ${input.id} disappeared after create`);
    return offeringRecord(stored);
  }

  async updateOffering(
    scope: CallerScope,
    modelId: string,
    id: string,
    input: Partial<ModelOfferingInput>,
    action: "replace" | "merge",
  ): Promise<CatalogRecord | null> {
    const current = await this.#offeringRow(modelId, id);
    if (current === null) return null;
    const replacing = action === "replace";
    const role: NonNullable<ModelOfferingInput["role"]> =
      input.role ??
      (replacing ? "fallback" : (current.role as NonNullable<ModelOfferingInput["role"]>));
    const canaryPercent = hasOwn(input, "canary_percent")
      ? input.canary_percent
      : replacing
        ? null
        : current.canary_percent;
    const shadowPercent = hasOwn(input, "shadow_percent")
      ? input.shadow_percent
      : replacing
        ? null
        : current.shadow_percent;
    this.#validateOffering({
      role,
      canary_percent: canaryPercent,
      shadow_percent: shadowPercent,
    });
    if (input.provider_id !== undefined && (await this.#providerRow(input.provider_id)) === null) {
      throw new TenantCatalogNotFoundError(`provider ${input.provider_id} not found`);
    }
    const fields: UpdateField[] = [];
    if (replacing) {
      fields.push(
        ["provider_id", input.provider_id ?? current.provider_id],
        ["upstream_model_id", input.upstream_model_id ?? current.upstream_model_id],
        ["role", role],
        ["priority", input.priority ?? 100],
        ["weight", input.weight ?? 1],
        ["canary_percent", canaryPercent ?? null],
        ["shadow_percent", shadowPercent ?? null],
        ["shadow_max_requests", input.shadow_max_requests ?? null],
        [
          "capabilities_json",
          input.capabilities === undefined || input.capabilities === null
            ? null
            : jsonArray(input.capabilities, "capabilities"),
        ],
        ["context_window", input.context_window ?? null],
        ["region", input.region ?? null],
        ["zero_data_retention", boolSql(input.zero_data_retention, null)],
      );
      for (const column of PRICE_COLUMNS) {
        fields.push([column, input[column] ?? null]);
      }
      fields.push(["currency", input.currency ?? "USD"]);
      fields.push(["source", input.source ?? "admin"]);
      fields.push(["enabled", boolSql(input.enabled)]);
    }
    const push = (column: string, value: string | number | null | undefined): void => {
      if (!replacing && value !== undefined) fields.push([column, value]);
    };
    push("provider_id", input.provider_id);
    push("upstream_model_id", input.upstream_model_id);
    push("role", input.role);
    push("priority", input.priority);
    push("weight", input.weight);
    if (!replacing && hasOwn(input, "canary_percent")) push("canary_percent", input.canary_percent);
    if (!replacing && hasOwn(input, "shadow_percent")) push("shadow_percent", input.shadow_percent);
    if (!replacing && hasOwn(input, "shadow_max_requests")) {
      push("shadow_max_requests", input.shadow_max_requests);
    }
    if (!replacing && input.capabilities !== undefined) {
      fields.push([
        "capabilities_json",
        input.capabilities === null ? null : jsonArray(input.capabilities, "capabilities"),
      ]);
    }
    push("context_window", input.context_window);
    push("region", input.region);
    if (!replacing && hasOwn(input, "zero_data_retention")) {
      fields.push(["zero_data_retention", boolSql(input.zero_data_retention, null)]);
    }
    for (const column of PRICE_COLUMNS) {
      if (!replacing && hasOwn(input, column)) fields.push([column, input[column] ?? null]);
    }
    push("currency", input.currency);
    push("source", input.source);
    if (!replacing && input.enabled !== undefined) fields.push(["enabled", boolSql(input.enabled)]);
    if (fields.length === 0) fields.push(["upstream_model_id", current.upstream_model_id]);
    const changed = await this.#commit(
      scope,
      action,
      OFFERING_COLLECTION,
      { id, scope: PLATFORM_SCOPE },
      updateStatement(
        this.#db,
        PLATFORM_OFFERING_TABLE,
        fields,
        id,
        Math.floor(Date.now() / 1000),
        true,
      ),
      true,
    );
    return changed ? this.getOffering(modelId, id) : null;
  }

  async deleteOffering(scope: CallerScope, modelId: string, id: string): Promise<boolean> {
    if ((await this.#offeringRow(modelId, id)) === null) return false;
    return this.#commit(
      scope,
      "remove",
      OFFERING_COLLECTION,
      { id, scope: PLATFORM_SCOPE },
      this.#db
        .prepare(`DELETE FROM ${PLATFORM_OFFERING_TABLE} WHERE model_id = ? AND id = ?`)
        .bind(modelId, id),
    );
  }

  async getOffering(modelId: string, id: string): Promise<CatalogRecord | null> {
    const row = await this.#offeringRow(modelId, id);
    return row === null ? null : offeringRecord(row);
  }

  #validateOffering(
    input: Pick<ModelOfferingInput, "role" | "canary_percent" | "shadow_percent">,
  ): void {
    const role = input.role ?? "fallback";
    if (!["primary", "fallback", "canary", "shadow"].includes(role)) {
      throw new TenantCatalogValidationError(`unsupported offering role: ${role}`);
    }
    if (
      role === "canary" &&
      (input.canary_percent === undefined || input.canary_percent === null)
    ) {
      throw new TenantCatalogValidationError("canary_percent is required for canary offerings");
    }
    if (
      role === "shadow" &&
      (input.shadow_percent === undefined || input.shadow_percent === null)
    ) {
      throw new TenantCatalogValidationError("shadow_percent is required for shadow offerings");
    }
  }

  #validatedOffering(input: ModelOfferingInput): {
    role: string;
    priority: number;
    weight: number;
    canary_percent: number | null;
    shadow_percent: number | null;
    shadow_max_requests: number | null;
  } {
    this.#validateOffering(input);
    return {
      role: input.role ?? "fallback",
      priority: input.priority ?? 100,
      weight: input.weight ?? 1,
      canary_percent: input.canary_percent ?? null,
      shadow_percent: input.shadow_percent ?? null,
      shadow_max_requests: input.shadow_max_requests ?? null,
    };
  }

  async #offeringRows(modelId?: string): Promise<readonly OfferingRow[]> {
    const suffix = modelId === undefined ? "" : "WHERE o.model_id = ?";
    const statement = this.#db.prepare(
      `${OFFERING_SELECT} ${suffix} ORDER BY o.priority ASC, o.id ASC`,
    );
    return modelId === undefined
      ? (await statement.all<OfferingRow>()).results
      : (await statement.bind(modelId).all<OfferingRow>()).results;
  }

  async #offeringRow(modelId: string, id: string): Promise<OfferingRow | null> {
    return this.#db
      .prepare(`${OFFERING_SELECT} WHERE o.model_id = ? AND o.id = ?`)
      .bind(modelId, id)
      .first<OfferingRow>();
  }

  async #requireModelAndProvider(modelId: string, providerId: string): Promise<void> {
    if ((await this.#modelRow(modelId)) === null) {
      throw new TenantCatalogNotFoundError(`model ${modelId} not found`);
    }
    if ((await this.#providerRow(providerId)) === null) {
      throw new TenantCatalogNotFoundError(`provider ${providerId} not found`);
    }
  }

  /**
   * One mutation, one revision bump, one audit row — in ONE batch.
   *
   * The revision UPDATE is guarded by `changes() > 0` from the mutation that
   * precedes it in the SAME batch, and the audit INSERT is guarded by
   * `changes() = 1` from that revision UPDATE, so a no-op mutation (an
   * `OR IGNORE` that hit a unique index, a guarded DELETE that lost its race)
   * cannot advance the revision or produce audit evidence for a transition that
   * did not happen — and, the direction that matters, an audit row that cannot
   * be written takes the mutation and the revision bump down with it instead of
   * leaving a committed change with no audit trail and an advanced revision for
   * #890's seeder and #891's loader to act on.
   *
   * `revision` therefore has to be known BEFORE the batch, so it is read here
   * and the bump's `RETURNING revision` is checked against it afterwards. The
   * read is not a CAS and does not need to be: every writer that bumps this
   * counter also appends to the platform (null-tenant) audit chain, so a
   * concurrent bump necessarily collides with `ux_audit_events_chain_seq`,
   * rolls the whole batch back, and lands on the retry below with a fresh head
   * AND a fresh revision. The equality check is the backstop for a bump that
   * arrived some other way; it can only fire on a batch that already committed,
   * which is why it is an internal error and not a status code.
   */
  async #commit(
    scope: CallerScope,
    action: AuditAction,
    collection: string,
    record: StoreRecord,
    mutation: D1PreparedStatement,
    requireMutation = false,
  ): Promise<boolean> {
    let lastError: unknown;
    for (let attempt = 1; attempt <= PLATFORM_COMMIT_ATTEMPTS; attempt += 1) {
      const now = Math.floor(Date.now() / 1000);
      const revision = (await this.#revision()) + 1;
      let results: readonly D1Result<unknown>[];
      try {
        results = await this.#db.batch([
          this.#db
            .prepare(
              `INSERT OR IGNORE INTO ${PLATFORM_REVISION_TABLE} (id, revision, updated_at_unix)
               VALUES (1, 0, ?)`,
            )
            .bind(now),
          mutation,
          this.#db
            .prepare(
              `UPDATE ${PLATFORM_REVISION_TABLE}
                  SET revision = revision + 1, updated_at_unix = ?
                WHERE id = 1 AND changes() > 0
                RETURNING revision`,
            )
            .bind(now),
          await controlPlaneAuditStatement(this.#db, {
            action,
            collection,
            record,
            revision,
            scope,
            requestId: this.#requestId,
            auditJson: controlPlaneAuditJson({ action, collection, record, revision, scope }),
          }),
        ]);
      } catch (error) {
        lastError = error;
        continue;
      }
      const mutationResult = results[1];
      if (requireMutation && Number(mutationResult?.meta.changes ?? 0) === 0) {
        throw new TenantCatalogConflictError("platform model catalog constraint violated");
      }
      const bump = results[2];
      if (bump === undefined || Number(bump.meta.changes ?? 0) === 0) return false;
      const bumped = Number(
        (bump.results[0] as { revision?: number | string } | undefined)?.revision ?? 0,
      );
      if (bumped !== revision) {
        throw new Error(
          `platform model catalog revision bumped to ${bumped}, audited as ${revision}`,
        );
      }
      if (Number(results[3]?.meta.changes ?? 0) === 0) {
        throw new Error("platform model catalog audit row was not appended with the mutation");
      }
      return true;
    }
    if (isConstraintError(lastError) && !isAuditAppendError(lastError)) {
      throw new TenantCatalogConflictError("platform model catalog constraint violated");
    }
    throw new Error(
      `platform model catalog: ${action} ${collection}/${String(record.id)} failed after ${PLATFORM_COMMIT_ATTEMPTS} attempts`,
      { cause: lastError },
    );
  }

  /** The current catalog revision; `0` before the first mutation. */
  async #revision(): Promise<number> {
    const row = await this.#db
      .prepare(`SELECT revision FROM ${PLATFORM_REVISION_TABLE} WHERE id = 1`)
      .first<{ revision: number | string }>();
    return Number(row?.revision ?? 0);
  }
}
