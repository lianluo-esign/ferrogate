import { controlDatabaseFrom } from "../control-data.js";
import { buildModelCatalog } from "./catalog.js";
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

/** Five seconds bounds staleness when an editor forgets to bump a revision. */
export const DEFAULT_PLATFORM_MODEL_CATALOG_CACHE_TTL_MS = 5_000;

const REVISION_SQL = "SELECT revision FROM platform_catalog_revisions WHERE id = 1";

/**
 * One graph read: platform models, offerings and provider channels joined,
 * ordered `(name, priority ASC, weight DESC)`. Same column aliases as the tenant
 * {@link CatalogJoinRow} so the shared projection consumes it unchanged.
 */
const CATALOG_SQL = `
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
    o.input_price_per_1m AS input_price_per_1m,
    o.output_price_per_1m AS output_price_per_1m,
    o.cached_input_price_per_1m AS cached_input_price_per_1m,
    o.cache_write_price_per_1m AS cache_write_price_per_1m,
    o.reasoning_price_per_1m AS reasoning_price_per_1m,
    o.audio_second_price_per_1m AS audio_second_price_per_1m,
    o.audio_character_price_per_1m AS audio_character_price_per_1m,
    o.enabled AS offering_enabled,
    p.id AS provider_id,
    p.name AS provider_name,
    p.kind AS provider_kind,
    p.base_url AS provider_base_url,
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
  ORDER BY m.name ASC, o.priority ASC, o.weight DESC, o.id ASC`;

/** The bootstrap registry: empty, so the tenant `platform` arm falls to env. */
const EMPTY_INPUTS: ModelCatalogInputs = { providers: [], models: [] };

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
  return /no such table:\s*(main\.)?platform_/i.test(message);
}

/**
 * Flatten the platform rows into a resolver AND the parsed registry.
 *
 * Platform rows are real physical legs — `canonicalProviderKind` rejects a
 * `platform` kind at the write edge, so no row here carries the tenant-side
 * `platform` indirection and the shared projection never needs env inputs.
 * `env` is still passed to {@link buildModelCatalog} as `secrets` so a provider's
 * `api_key_var` resolves from Worker secrets and fails the route closed exactly
 * as `modelsFromEnv` does — the CONTROL_DATA facade holds no secrets.
 */
function buildPlatformCatalog(
  rows: readonly CatalogJoinRow[],
  env: InferenceBindings,
): PlatformCatalogBuildResult {
  const projected = projectCatalog(rows, EMPTY_INPUTS);
  if (!projected.ok) return projected;
  const providers: ProviderRecord[] = [...projected.providers.values()];
  const models: ModelRecord[] = projected.models;
  const built = buildModelCatalog(providers, models, env);
  if (!built.ok) return built;
  return {
    ok: true,
    resolver: new InMemoryModelResolver(built.routes),
    inputs: { providers, models },
  };
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
      const row = await db.prepare(REVISION_SQL).first<{ revision: number | string | null }>();
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
      const result = await db.prepare(CATALOG_SQL).all<CatalogJoinRow>();
      rows = result.results;
    } catch (error) {
      if (isMissingPlatformCatalogError(error)) {
        return { ok: true, models: input.fallback, inputs: EMPTY_INPUTS };
      }
      return this.#lastGoodOrRefuse(cached, `platform catalog read failed: ${errorDetail(error)}`);
    }

    // Zero rows ⇒ the catalog is adopted but empty: env is authoritative. Cache
    // the env fallback under this revision so the steady state is O(revisions),
    // not O(requests). An empty registry is threaded to the tenant `platform`
    // arm so it falls to env too.
    if (rows.length === 0) {
      this.#byEnv.set(envKey, {
        revision,
        resolver: input.fallback,
        inputs: EMPTY_INPUTS,
        expiresAt: now + this.#ttlMs,
      });
      return { ok: true, models: input.fallback, inputs: EMPTY_INPUTS, revision };
    }

    const built = buildPlatformCatalog(rows, input.env);
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

/** Construct the production source; the returned object owns isolate-local cache state. */
export function platformModelCatalogFromControlData(
  options: { ttlMs?: number; now?: () => number } = {},
): PlatformModelCatalogSource {
  return new ControlDataPlatformModelCatalogSource(options);
}
