import { controlDatabaseFrom } from "../control-data.js";
import { buildModelCatalog, cloudflareAccountFromEnv } from "./catalog.js";
import type { ModelCatalogInputs, ModelRecord, ProviderRecord } from "./catalog.js";
import { InMemoryModelResolver } from "./defaults.js";
import type {
  InferenceBindings,
  ModelResolver,
  PlatformModelCatalogLoadResult,
  PlatformModelCatalogSource,
} from "./ports.js";
import { type CatalogJoinRow, projectCatalog } from "./tenant-catalog.js";

/**
 * Platform-owned (control-object) model catalog loading for the inference data
 * plane (#890, epic #810).
 *
 * The platform catalog is the deployment-wide default: the providers, models and
 * rate card `GATEWAY_PROVIDERS`/`GATEWAY_MODELS` used to hold. #889 gave those
 * rows a home in the CONTROL database; this source is what makes them readable
 * by the data plane, so an operator's CRUD write is visible without a redeploy.
 *
 * The row shape and the projection are identical to the tenant catalog — only
 * the SQL differs (the three `platform_`-prefixed tables, no `tenant_id`
 * predicate). It therefore reuses {@link projectCatalog} and {@link CatalogJoinRow}
 * from `tenant-catalog.ts` rather than duplicating the graph read.
 *
 * Composition rule (`route-module.ts`): platform rows present ⇒ authoritative;
 * zero rows (or migration not yet applied, or no control database bound) ⇒
 * `modelsFromEnv`, the bootstrap posture — the same authoritative-when-present
 * rule the tenant loader uses, so no new posture var is needed and rollback is
 * "empty the table" plus the existing `GATEWAY_CONTROL_STORAGE` escape hatch.
 *
 * A genuine control-object READ FAILURE is never treated as an empty catalog:
 * it serves the last good catalog when one is cached, refuses otherwise, and is
 * never itself cached (a cached blip would extend a one-request failure into a
 * TTL-long one). This mirrors `residency/source.ts` and the tenant loader.
 */

/** Thirty seconds bounds staleness when an editor forgets to bump a revision. */
export const DEFAULT_PLATFORM_MODEL_CATALOG_CACHE_TTL_MS = 30_000;

export const PLATFORM_CATALOG_REVISION_SQL =
  "SELECT revision FROM platform_catalog_revisions WHERE id = 1";

/** One shared KV object, atomically replaced after a platform catalog commit. */
export const PLATFORM_CATALOG_SNAPSHOT_KEY = "platform-config:model-catalog:v1";

export interface PlatformCatalogSnapshot {
  readonly schema_version: 1;
  readonly revision: number;
  readonly published_at_unix: number;
  readonly rows: readonly CatalogJoinRow[];
}

/**
 * One graph read: platform models, offerings and provider channels joined,
 * ordered `(name, priority ASC, weight DESC)`. Same column aliases as the tenant
 * {@link CatalogJoinRow} so the shared projection consumes it unchanged.
 */
export const PLATFORM_CATALOG_ROWS_SQL = `
  SELECT
    m.id AS model_id,
    m.name AS model_name,
    m.owned_by AS model_owned_by,
    m.capabilities_json AS model_capabilities_json,
    m.context_window AS model_context_window,
    m.routing_strategy AS model_routing_strategy,
    m.enabled AS model_enabled,
    o.id AS offering_id,
    o.upstream_model_id AS upstream_model_id,
    o.pricing_model_id AS pricing_model_id,
    o.role AS offering_role,
    o.priority AS offering_priority,
    o.weight AS offering_weight,
    o.canary_percent AS canary_percent,
    o.shadow_percent AS shadow_percent,
    o.shadow_max_requests AS shadow_max_requests,
    o.capabilities_json AS offering_capabilities_json,
    o.context_window AS offering_context_window,
    o.region AS offering_region,
    o.zero_data_retention AS offering_zero_data_retention,
    CASE WHEN o.pricing_model_id IS NULL THEN o.input_price_per_1m
         WHEN price.enabled = 1 THEN price.input_price_per_1m * p.cost_multiplier END AS input_price_per_1m,
    CASE WHEN o.pricing_model_id IS NULL THEN o.output_price_per_1m
         WHEN price.enabled = 1 THEN price.output_price_per_1m * p.cost_multiplier END AS output_price_per_1m,
    CASE WHEN o.pricing_model_id IS NULL THEN o.cached_input_price_per_1m
         WHEN price.enabled = 1 THEN price.cached_input_price_per_1m * p.cost_multiplier END AS cached_input_price_per_1m,
    CASE WHEN o.pricing_model_id IS NULL THEN o.cache_write_price_per_1m
         WHEN price.enabled = 1 THEN price.cache_write_price_per_1m * p.cost_multiplier END AS cache_write_price_per_1m,
    CASE WHEN o.pricing_model_id IS NULL THEN o.reasoning_price_per_1m
         WHEN price.enabled = 1 THEN price.reasoning_price_per_1m * p.cost_multiplier END AS reasoning_price_per_1m,
    CASE WHEN o.pricing_model_id IS NULL THEN o.audio_second_price_per_1m
         WHEN price.enabled = 1 THEN price.audio_second_price_per_1m * p.cost_multiplier END AS audio_second_price_per_1m,
    CASE WHEN o.pricing_model_id IS NULL THEN o.audio_character_price_per_1m
         WHEN price.enabled = 1 THEN price.audio_character_price_per_1m * p.cost_multiplier END AS audio_character_price_per_1m,
    o.enabled AS offering_enabled,
    p.id AS provider_id,
    p.name AS provider_name,
    p.kind AS provider_kind,
    p.base_url AS provider_base_url,
    p.cost_multiplier AS provider_cost_multiplier,
    p.api_key_var AS provider_api_key_var,
    p.byok_alias AS provider_byok_alias,
    p.auth_scheme AS provider_auth_scheme,
    p.region AS provider_region,
    p.zero_data_retention AS provider_zero_data_retention,
    p.openrouter_http_referer AS provider_openrouter_http_referer,
    p.openrouter_x_title AS provider_openrouter_x_title,
    p.cloudflare_ai_gateway_json AS provider_cloudflare_ai_gateway_json,
    p.enabled AS provider_enabled
  FROM platform_catalog_models m
  JOIN platform_catalog_offerings o
    ON o.model_id = m.id
  JOIN platform_provider_channels p
    ON p.id = o.provider_id
  LEFT JOIN platform_model_prices price
    ON price.id = o.pricing_model_id
  ORDER BY m.name ASC, o.priority ASC, o.weight DESC, o.id ASC`;

/** The bootstrap registry: empty, so the tenant `platform` arm falls to env. */
const EMPTY_INPUTS: ModelCatalogInputs = { providers: [], models: [] };

/**
 * Drop the price-only `platform-default` rows (#892): a `kind = 'platform'`
 * channel carries the default rate card's PRICES but names no physical upstream,
 * so it can never yield a working route. The remaining rows are the routable set,
 * and the presence/empty decision MUST be made on THIS set — a catalog that holds
 * only rate-card rows is empty for routing, so it has to fall to env rather than
 * shadow it with an empty resolver (a deployment-wide 404, issue #892 review).
 */
function routableCatalogRows(rows: readonly CatalogJoinRow[]): CatalogJoinRow[] {
  return rows.filter((row) => row.provider_kind !== "platform");
}

interface CacheEntry {
  readonly revision: number;
  readonly resolver: ModelResolver;
  readonly inputs: ModelCatalogInputs;
  readonly expiresAt: number;
}

type PlatformCatalogBuildResult =
  | { readonly ok: true; readonly resolver: ModelResolver; readonly inputs: ModelCatalogInputs }
  | { readonly ok: false; readonly reason: string };

function errorDetail(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * A missing `platform_` table means the control database has migration `0025`
 * but not these tables yet — the deploy/migrate window `wrangler.toml`'s
 * `d1_compat` posture opens. That is "not adopted", a different thing from a
 * read failure: the catalog is simply absent and the deployment falls to env.
 *
 * Reimplemented here rather than imported from `apps/control-plane` to avoid a
 * reverse dependency (the store already imports FROM gateway); the predicate is
 * byte-identical to `PlatformModelCatalogStore.isMissingPlatformCatalogError`.
 */
function isMissingPlatformCatalogError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return (
    /no such table:\s*(main\.)?platform_/i.test(message) ||
    /no such column:\s*(o\.pricing_model_id|p\.cost_multiplier)/i.test(message)
  );
}

/**
 * Flatten the platform rows into a resolver AND the parsed registry.
 *
 * Platform rows are real physical legs, with ONE exception introduced by the
 * bootstrap import (#892): a `kind = 'platform'` channel (`platform-default`,
 * `platform://default`) is the managed record of the default rate card — it
 * carries PRICES but names no physical upstream, so it is a price row, not a
 * routable leg. Those rows are EXCLUDED by {@link routableCatalogRows} BEFORE the
 * caller decides presence and before this projection runs: they can never produce
 * a working route (there is nowhere to dispatch), and feeding one to the shared
 * projection's `provider_kind === "platform"` arm — which resolves a tenant-side
 * indirection against an env registry this loader deliberately runs empty
 * (`EMPTY_INPUTS`) — would fail the WHOLE platform build with a deployment-wide
 * 503. Excluding them keeps the platform catalog's route set to the real
 * providers the env pair (or an operator's CRUD) supplied, which is the parity
 * invariant #892 asserts. `#889`'s admin CRUD still rejects a `platform` kind at
 * the write edge; only the bulk import lays these price rows down.
 *
 * `env` is still passed to {@link buildModelCatalog} as `secrets` so a provider's
 * `api_key_var` resolves from Worker secrets and fails the route closed exactly
 * as `modelsFromEnv` does — the CONTROL_DATA facade holds no secrets.
 *
 * The account-level `[cloudflare]` block still lives in the deployment's
 * `GATEWAY_CLOUDFLARE` var (the CONTROL_DATA tables carry per-provider AI-Gateway
 * config but not the account id / base URLs). It is sourced from env and threaded
 * to {@link buildModelCatalog} exactly as the tenant loader does with
 * `inputs.cloudflare`; without it a platform provider that #889's CRUD legitimately
 * persisted with a `cloudflare_ai_gateway` block would fail the WHOLE platform
 * catalog build — a deployment-wide 503 — instead of routing through AI Gateway.
 */
function buildPlatformCatalog(
  routableRows: readonly CatalogJoinRow[],
  env: InferenceBindings,
): PlatformCatalogBuildResult {
  // `routableRows` has already had the price-only `platform-default` rows (#892)
  // excluded by the caller (see `routableCatalogRows` and the docblock) so the
  // presence/empty decision is made on the routable set, not the raw rows.
  const projected = projectCatalog(routableRows, EMPTY_INPUTS);
  if (!projected.ok) return projected;
  const cloudflare = cloudflareAccountFromEnv(
    typeof env.GATEWAY_CLOUDFLARE === "string" ? env.GATEWAY_CLOUDFLARE : undefined,
  );
  if (!cloudflare.ok) return cloudflare;
  const providers: ProviderRecord[] = [...projected.providers.values()];
  const models: ModelRecord[] = projected.models;
  const built = buildModelCatalog(providers, models, env, cloudflare.cloudflare);
  if (!built.ok) return built;
  return {
    ok: true,
    resolver: new InMemoryModelResolver(built.routes),
    inputs: { providers, models },
  };
}

function parsePlatformCatalogSnapshot(raw: string): PlatformCatalogSnapshot | null {
  try {
    const parsed = JSON.parse(raw) as Partial<PlatformCatalogSnapshot>;
    if (
      parsed.schema_version !== 1 ||
      !Number.isSafeInteger(parsed.revision) ||
      (parsed.revision ?? -1) < 0 ||
      !Number.isSafeInteger(parsed.published_at_unix) ||
      (parsed.published_at_unix ?? -1) < 0 ||
      !Array.isArray(parsed.rows)
    ) {
      return null;
    }
    return parsed as PlatformCatalogSnapshot;
  } catch {
    return null;
  }
}

/** Control-object-backed source with revision-aware, per-env caching. */
export class ControlDataPlatformModelCatalogSource implements PlatformModelCatalogSource {
  readonly #ttlMs: number;
  readonly #now: () => number;
  readonly #byEnv = new WeakMap<object, CacheEntry>();

  constructor(options: { ttlMs?: number; now?: () => number } = {}) {
    this.#ttlMs = options.ttlMs ?? DEFAULT_PLATFORM_MODEL_CATALOG_CACHE_TTL_MS;
    this.#now = options.now ?? Date.now;
  }

  async load(input: {
    env: InferenceBindings;
    fallback: ModelResolver;
  }): Promise<PlatformModelCatalogLoadResult> {
    // `controlDatabaseFrom` honours `GATEWAY_CONTROL_STORAGE` and THROWS
    // HttpError(503) on an unrecognized posture — that is the "refuses" path and
    // is left to propagate. `undefined` = no control database bound (a unit env,
    // or a Worker the stanza has not reached): bootstrap, env is authoritative.
    const db = controlDatabaseFrom(input.env);
    if (db === undefined) {
      return { ok: true, models: input.fallback, inputs: EMPTY_INPUTS };
    }

    const envKey = input.env as unknown as object;
    const cached = this.#byEnv.get(envKey);

    let revision: number;
    try {
      const row = await db
        .prepare(PLATFORM_CATALOG_REVISION_SQL)
        .first<{ revision: number | string | null }>();
      revision = row === null || row.revision === null ? 0 : Number(row.revision);
      if (!Number.isSafeInteger(revision) || revision < 0) {
        return this.#lastGoodOrRefuse(cached, "platform catalog revision is invalid");
      }
    } catch (error) {
      if (isMissingPlatformCatalogError(error)) {
        return { ok: true, models: input.fallback, inputs: EMPTY_INPUTS };
      }
      return this.#lastGoodOrRefuse(
        cached,
        `platform catalog revision read failed: ${errorDetail(error)}`,
      );
    }

    const now = this.#now();
    if (cached !== undefined && cached.revision === revision && cached.expiresAt > now) {
      return { ok: true, models: cached.resolver, inputs: cached.inputs, revision };
    }

    let rows: CatalogJoinRow[];
    try {
      const result = await db.prepare(PLATFORM_CATALOG_ROWS_SQL).all<CatalogJoinRow>();
      rows = result.results;
    } catch (error) {
      if (isMissingPlatformCatalogError(error)) {
        return { ok: true, models: input.fallback, inputs: EMPTY_INPUTS };
      }
      return this.#lastGoodOrRefuse(cached, `platform catalog read failed: ${errorDetail(error)}`);
    }

    // Zero ROUTABLE rows ⇒ the catalog is adopted but empty for routing: env is
    // authoritative. This must exclude the price-only `platform`-kind rate-card
    // rows (#892) FIRST — a rate-card-only catalog has `rows.length > 0` but no
    // routable leg, and treating it as authoritative would shadow env with an
    // empty resolver (a deployment-wide 404, issue #892 review). Cache the env
    // fallback under this revision so the steady state is O(revisions), not
    // O(requests). An empty registry is threaded to the tenant `platform` arm so
    // it falls to env too.
    const routableRows = routableCatalogRows(rows);
    if (routableRows.length === 0) {
      this.#byEnv.set(envKey, {
        revision,
        resolver: input.fallback,
        inputs: EMPTY_INPUTS,
        expiresAt: now + this.#ttlMs,
      });
      return { ok: true, models: input.fallback, inputs: EMPTY_INPUTS, revision };
    }

    const built = buildPlatformCatalog(routableRows, input.env);
    if (!built.ok) return built;
    this.#byEnv.set(envKey, {
      revision,
      resolver: built.resolver,
      inputs: built.inputs,
      expiresAt: now + this.#ttlMs,
    });
    return { ok: true, models: built.resolver, inputs: built.inputs, revision };
  }

  /**
   * A control-object read failed. Serve the last good catalog when one is
   * cached (never an empty one), refuse otherwise — and never re-cache: the
   * stale entry is left intact so the next request retries the read.
   */
  #lastGoodOrRefuse(
    cached: CacheEntry | undefined,
    reason: string,
  ): PlatformModelCatalogLoadResult {
    if (cached !== undefined) {
      return {
        ok: true,
        models: cached.resolver,
        inputs: cached.inputs,
        revision: cached.revision,
      };
    }
    return { ok: false, reason };
  }
}

/**
 * KV-first shared platform catalog. The control database remains authoritative
 * and is the fallback for an absent, malformed, or temporarily unavailable KV
 * projection. Only binding names such as `OPENAI_API_KEY` enter the snapshot;
 * resolved provider secret values remain Worker secrets on this env.
 */
export class KvFirstPlatformModelCatalogSource implements PlatformModelCatalogSource {
  readonly #fallback: PlatformModelCatalogSource;
  readonly #ttlMs: number;
  readonly #now: () => number;
  readonly #byEnv = new WeakMap<object, CacheEntry>();

  constructor(options: {
    fallback: PlatformModelCatalogSource;
    ttlMs?: number;
    now?: () => number;
  }) {
    this.#fallback = options.fallback;
    this.#ttlMs = options.ttlMs ?? DEFAULT_PLATFORM_MODEL_CATALOG_CACHE_TTL_MS;
    this.#now = options.now ?? Date.now;
  }

  async load(input: {
    env: InferenceBindings;
    fallback: ModelResolver;
  }): Promise<PlatformModelCatalogLoadResult> {
    const kv = input.env.PLATFORM_CONFIG as KVNamespace | undefined;
    if (kv === undefined) return this.#fallback.load(input);

    const envKey = input.env as unknown as object;
    const cached = this.#byEnv.get(envKey);
    const now = this.#now();
    if (cached !== undefined && cached.expiresAt > now) {
      return {
        ok: true,
        models: cached.resolver,
        inputs: cached.inputs,
        revision: cached.revision,
      };
    }

    let raw: string | null;
    try {
      raw = await kv.get(PLATFORM_CATALOG_SNAPSHOT_KEY, { cacheTtl: 30 });
    } catch {
      return this.#fallback.load(input);
    }
    if (raw === null) return this.#fallback.load(input);

    const snapshot = parsePlatformCatalogSnapshot(raw);
    if (snapshot === null) return this.#fallback.load(input);
    if (cached !== undefined && snapshot.revision < cached.revision) {
      return {
        ok: true,
        models: cached.resolver,
        inputs: cached.inputs,
        revision: cached.revision,
      };
    }

    const routableRows = routableCatalogRows(snapshot.rows);
    if (routableRows.length === 0) return this.#fallback.load(input);
    const built = buildPlatformCatalog(routableRows, input.env);
    if (!built.ok) return this.#fallback.load(input);

    const entry: CacheEntry = {
      revision: snapshot.revision,
      resolver: built.resolver,
      inputs: built.inputs,
      expiresAt: now + this.#ttlMs,
    };
    this.#byEnv.set(envKey, entry);
    return {
      ok: true,
      models: entry.resolver,
      inputs: entry.inputs,
      revision: entry.revision,
    };
  }
}

/** Construct the production source; the returned object owns isolate-local cache state. */
export function platformModelCatalogFromControlData(
  options: { ttlMs?: number; now?: () => number } = {},
): PlatformModelCatalogSource {
  return new ControlDataPlatformModelCatalogSource(options);
}

/** Production source: shared KV cache in front of the authoritative control DB. */
export function platformModelCatalogFromSharedConfig(
  options: { ttlMs?: number; now?: () => number } = {},
): PlatformModelCatalogSource {
  return new KvFirstPlatformModelCatalogSource({
    fallback: platformModelCatalogFromControlData(options),
    ...options,
  });
}
