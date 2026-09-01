import { controlDatabaseFrom } from "../control-data.js";
import {
  buildModelCatalog,
  modelCatalogInputsFromEnv,
  modelRecordSchema,
  providerRecordSchema,
} from "./catalog.js";
import type { ModelCatalogInputs, ModelRecord, ProviderRecord } from "./catalog.js";
import { InMemoryModelResolver } from "./defaults.js";
import type {
  InferenceBindings,
  ModelResolver,
  TenantModelCatalogLoadResult,
  TenantModelCatalogSource,
} from "./ports.js";
import {
  PLATFORM_PROVIDER_COST_SQL,
  PUBLIC_MODEL_PRICE_SQL,
  type PlatformProviderCostRow,
  type PublicModelPriceRow,
  platformProviderCostMap,
  readPublicPriceSnapshot,
} from "./public-price-snapshot.js";

/**
 * Tenant-owned model catalog loading for the inference data plane.
 *
 * The tenant database is the source of truth once it has catalog rows. The
 * env tables remain a compatibility fallback for platform-operator requests,
 * explicitly disabled tenant routing, and an as-yet unconfigured tenant. A
 * read failure is never treated as an empty catalog or as permission to use
 * the env registry.
 */

/** Thirty seconds bounds staleness when an editor forgets to bump a revision. */
export const DEFAULT_TENANT_MODEL_CATALOG_CACHE_TTL_MS = 30_000;

const REVISION_SQL = "SELECT revision FROM catalog_revisions WHERE tenant_id = ? AND id = 1";
const OFFERING_ROLES = new Set(["primary", "fallback", "canary", "shadow"]);

/** One graph read: models, offerings, and provider channels are joined together. */
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
    o.pricing_model_id AS pricing_model_id,
    o.source AS offering_source,
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
    NULL AS provider_upstream_protocol,
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
  FROM catalog_models m
  JOIN catalog_model_offerings o
    ON o.tenant_id = m.tenant_id AND o.model_id = m.id
  JOIN provider_channels p
    ON p.tenant_id = o.tenant_id AND p.id = o.provider_id
  WHERE m.tenant_id = ?
  ORDER BY m.name ASC, o.priority ASC, o.weight DESC, o.id ASC`;

export interface CatalogJoinRow {
  readonly model_id: string;
  readonly model_name: string;
  readonly model_owned_by: string | null;
  readonly model_capabilities_json: string | null;
  readonly model_context_window: number | null;
  readonly model_routing_strategy: string | null;
  readonly model_enabled: number | null;
  readonly offering_id: string;
  readonly upstream_model_id: string;
  readonly pricing_model_id?: string | null;
  readonly offering_source?: string;
  readonly offering_role: string;
  readonly offering_priority: number | null;
  readonly offering_weight: number | null;
  readonly canary_percent: number | null;
  readonly shadow_percent: number | null;
  readonly shadow_max_requests: number | null;
  readonly offering_capabilities_json: string | null;
  readonly offering_context_window: number | null;
  readonly offering_region: string | null;
  readonly offering_zero_data_retention: number | null;
  readonly input_price_per_1m: number | null;
  readonly output_price_per_1m: number | null;
  readonly cached_input_price_per_1m: number | null;
  readonly cache_write_price_per_1m: number | null;
  readonly reasoning_price_per_1m: number | null;
  readonly audio_second_price_per_1m: number | null;
  readonly audio_character_price_per_1m: number | null;
  readonly offering_enabled: number | null;
  readonly provider_id: string;
  readonly provider_name: string;
  readonly provider_kind: string;
  readonly provider_base_url: string;
  readonly provider_upstream_protocol?: string | null;
  readonly provider_cost_multiplier?: number | null;
  readonly provider_api_key_var: string | null;
  readonly provider_byok_alias: string | null;
  readonly provider_auth_scheme: string | null;
  readonly provider_region: string | null;
  readonly provider_zero_data_retention: number | null;
  readonly provider_openrouter_http_referer: string | null;
  readonly provider_openrouter_x_title: string | null;
  readonly provider_cloudflare_ai_gateway_json: string | null;
  readonly provider_enabled: number | null;
}

const PUBLIC_PRICE_FIELDS = [
  "input_price_per_1m",
  "output_price_per_1m",
  "cached_input_price_per_1m",
  "cache_write_price_per_1m",
  "reasoning_price_per_1m",
  "audio_second_price_per_1m",
  "audio_character_price_per_1m",
] as const;

function providerCostMultiplier(
  row: CatalogJoinRow,
  platformCosts: ReadonlyMap<string, number>,
  tenantId: string,
): number {
  if (row.offering_source === "platform_seed") {
    const tenantPrefix = `${tenantId}:`;
    const platformProviderId = row.provider_id.startsWith(tenantPrefix)
      ? row.provider_id.slice(tenantPrefix.length)
      : row.provider_id;
    const platformCost = platformCosts.get(platformProviderId);
    if (platformCost !== undefined) return platformCost;
  }
  const value = row.provider_cost_multiplier;
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : 1;
}

function withPublicModelPrices(
  rows: readonly CatalogJoinRow[],
  prices: readonly PublicModelPriceRow[],
  platformCosts: ReadonlyMap<string, number>,
  tenantId: string,
): CatalogJoinRow[] {
  const byId = new Map(prices.map((price) => [price.id, price]));
  const byModelKey = new Map<string, PublicModelPriceRow>();
  for (const price of prices) {
    byModelKey.set(price.model_key, price);
    const aliases = JSON.parse(price.aliases_json) as unknown;
    if (!Array.isArray(aliases) || aliases.some((alias) => typeof alias !== "string")) {
      throw new Error(`public model price ${price.id} has invalid aliases_json`);
    }
    for (const alias of aliases) byModelKey.set(alias, price);
  }
  return rows.map((row) => {
    const explicitId = row.pricing_model_id ?? null;
    const price =
      explicitId !== null
        ? byId.get(explicitId)
        : row.offering_source === "platform_seed"
          ? byModelKey.get(row.upstream_model_id)
          : undefined;
    if (price === undefined) {
      if (explicitId === null) return row;
      return Object.fromEntries(
        Object.entries(row).map(([key, value]) => [
          key,
          (PUBLIC_PRICE_FIELDS as readonly string[]).includes(key) ? null : value,
        ]),
      ) as unknown as CatalogJoinRow;
    }
    const multiplier = providerCostMultiplier(row, platformCosts, tenantId);
    const projected = { ...row } as Record<string, unknown>;
    projected.provider_cost_multiplier = multiplier;
    for (const field of PUBLIC_PRICE_FIELDS) {
      const value = price.enabled === 1 || price.enabled === "1" ? price[field] : null;
      projected[field] = value;
    }
    return projected as unknown as CatalogJoinRow;
  });
}

async function resolvePublicModelPrices(
  rows: readonly CatalogJoinRow[],
  env: InferenceBindings,
  tenantId: string,
): Promise<readonly CatalogJoinRow[]> {
  const needsPricing = rows.some(
    (row) => row.pricing_model_id != null || row.offering_source === "platform_seed",
  );
  if (!needsPricing) return rows;

  // KV fast path (#961 shape): the account-global snapshot the control plane
  // republishes every tick over the SAME `PLATFORM_CONFIG` KV the catalog,
  // billing-group and tenant-status projections ride. Present-and-well-formed →
  // fold prices colo-locally, removing the two per-request control reads the
  // singleton-DO cutover must shield. ANY miss (KV absent, never published,
  // malformed, or a read that throws) falls THROUGH to the control read below,
  // so this is a fast path and never a new authority. `withPublicModelPrices`
  // and `platformProviderCostMap` are the SAME derivation on both paths, so KV
  // and control produce byte-identical pricing.
  const kv = env.PLATFORM_CONFIG as KVNamespace | undefined;
  if (kv !== undefined) {
    const snapshot = await readPublicPriceSnapshot(kv);
    if (snapshot !== null) {
      return withPublicModelPrices(
        rows,
        snapshot.prices,
        platformProviderCostMap(snapshot.provider_costs),
        tenantId,
      );
    }
  }

  const control = controlDatabaseFrom(env);
  if (control === undefined) return rows;
  try {
    const [priceResult, providerResult] = await Promise.all([
      control.prepare(PUBLIC_MODEL_PRICE_SQL).all<PublicModelPriceRow>(),
      control.prepare(PLATFORM_PROVIDER_COST_SQL).all<PlatformProviderCostRow>(),
    ]);
    return withPublicModelPrices(
      rows,
      priceResult.results,
      platformProviderCostMap(providerResult.results),
      tenantId,
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (
      /no such table:\s*(main\.)?platform_model_prices/i.test(message) ||
      /no such column:\s*(cost_multiplier|pricing_model_id)/i.test(message)
    ) {
      return rows;
    }
    throw error;
  }
}

interface CacheEntry {
  readonly revision: number;
  readonly platformRevision: number | undefined;
  readonly resolver: ModelResolver;
  readonly expiresAt: number;
}

interface ProjectedOffering {
  readonly row: CatalogJoinRow;
  readonly providerName: string;
  readonly providerModel: string;
}

type ProviderIdProjection = (row: CatalogJoinRow) => string;

type CatalogBuildResult =
  | {
      readonly ok: true;
      readonly resolver: ModelResolver;
    }
  | { readonly ok: false; readonly reason: string };

function errorDetail(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function failure(label: string, error: unknown): { ok: false; reason: string } {
  return { ok: false, reason: `${label}: ${errorDetail(error)}` };
}

function enabled(value: number | null): boolean {
  return value !== 0;
}

function boolValue(value: number | null): boolean {
  return value !== 0;
}

function parsedJson(
  raw: string | null,
  label: string,
):
  | { readonly ok: true; readonly value: unknown }
  | { readonly ok: false; readonly reason: string } {
  if (raw === null) return { ok: true, value: undefined };
  try {
    return { ok: true, value: JSON.parse(raw) };
  } catch (error) {
    return failure(`${label} is not valid JSON`, error);
  }
}

function schemaFailure(
  label: string,
  result: {
    success: false;
    error: { issues: readonly { path: readonly (string | number)[]; message: string }[] };
  },
): {
  ok: false;
  reason: string;
} {
  const detail = result.error.issues
    .map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`)
    .join("; ");
  return { ok: false, reason: `${label} is invalid: ${detail}` };
}

function dbProvider(
  row: CatalogJoinRow,
  providerId: string,
): { ok: true; provider: ProviderRecord } | { ok: false; reason: string } {
  const cloudflare = parsedJson(
    row.provider_cloudflare_ai_gateway_json,
    `provider ${row.provider_name}.cloudflare_ai_gateway`,
  );
  if (!cloudflare.ok) return cloudflare;

  const candidate: Record<string, unknown> = {
    id: providerId,
    name: row.provider_name,
    kind: row.provider_kind,
    base_url: row.provider_base_url,
    ...(row.provider_cost_multiplier === null
      ? {}
      : { cost_multiplier: row.provider_cost_multiplier }),
    ...(row.provider_upstream_protocol === "openai.chat.completions" ||
    row.provider_upstream_protocol === "openai.responses"
      ? { upstream_protocol: row.provider_upstream_protocol }
      : {}),
    ...(row.provider_api_key_var === null ? {} : { api_key_var: row.provider_api_key_var }),
    ...(row.provider_byok_alias === null ? {} : { byok_alias: row.provider_byok_alias }),
    ...(row.provider_auth_scheme === null ? {} : { auth_scheme: row.provider_auth_scheme }),
    ...(row.provider_region === null ? {} : { region: row.provider_region }),
    ...(row.provider_zero_data_retention === null
      ? {}
      : { zero_data_retention: boolValue(row.provider_zero_data_retention) }),
    ...(row.provider_openrouter_http_referer === null
      ? {}
      : { openrouter_http_referer: row.provider_openrouter_http_referer }),
    ...(row.provider_openrouter_x_title === null
      ? {}
      : { openrouter_x_title: row.provider_openrouter_x_title }),
    ...(cloudflare.value === undefined ? {} : { cloudflare_ai_gateway: cloudflare.value }),
  };
  const result = providerRecordSchema.safeParse(candidate);
  return result.success
    ? { ok: true, provider: result.data }
    : schemaFailure(`provider ${row.provider_name}`, result);
}

function modelCapabilities(
  row: CatalogJoinRow,
): { ok: true; value: unknown } | { ok: false; reason: string } {
  return parsedJson(row.model_capabilities_json, `model ${row.model_name}.capabilities`);
}

function offeringCapabilities(
  row: CatalogJoinRow,
  fallback: unknown,
): { ok: true; value: unknown } | { ok: false; reason: string } {
  if (row.offering_capabilities_json === null) return { ok: true, value: fallback };
  return parsedJson(row.offering_capabilities_json, `offering ${row.offering_id}.capabilities`);
}

function routeFields(
  projected: ProjectedOffering,
  modelCapabilitiesValue: unknown,
  modelContextWindow: number | null,
): { ok: true; fields: Record<string, unknown> } | { ok: false; reason: string } {
  const { row } = projected;
  const capabilities = offeringCapabilities(row, modelCapabilitiesValue);
  if (!capabilities.ok) return capabilities;

  return {
    ok: true,
    fields: {
      provider: projected.providerName,
      provider_model: projected.providerModel,
      capabilities: capabilities.value,
      ...(row.offering_region === null ? {} : { region: row.offering_region }),
      ...(row.offering_zero_data_retention === null
        ? {}
        : { zero_data_retention: boolValue(row.offering_zero_data_retention) }),
      ...(row.offering_context_window === null
        ? modelContextWindow === null
          ? {}
          : { context_window: modelContextWindow }
        : { context_window: row.offering_context_window }),
      ...(row.offering_priority === null ? {} : { priority: row.offering_priority }),
      ...(row.offering_weight === null ? {} : { weight: row.offering_weight }),
      ...(row.input_price_per_1m === null ? {} : { input_price_per_1m: row.input_price_per_1m }),
      ...(row.output_price_per_1m === null ? {} : { output_price_per_1m: row.output_price_per_1m }),
      ...(row.cached_input_price_per_1m === null
        ? {}
        : { cached_input_price_per_1m: row.cached_input_price_per_1m }),
      ...(row.cache_write_price_per_1m === null
        ? {}
        : { cache_write_price_per_1m: row.cache_write_price_per_1m }),
      ...(row.reasoning_price_per_1m === null
        ? {}
        : { reasoning_price_per_1m: row.reasoning_price_per_1m }),
      ...(row.audio_second_price_per_1m === null
        ? {}
        : { audio_second_price_per_1m: row.audio_second_price_per_1m }),
      ...(row.audio_character_price_per_1m === null
        ? {}
        : { audio_character_price_per_1m: row.audio_character_price_per_1m }),
    },
  };
}

function rowOrder(a: CatalogJoinRow, b: CatalogJoinRow): number {
  const priority = (a.offering_priority ?? 100) - (b.offering_priority ?? 100);
  if (priority !== 0) return priority;
  const weight = (b.offering_weight ?? 1) - (a.offering_weight ?? 1);
  if (weight !== 0) return weight;
  return a.offering_id.localeCompare(b.offering_id);
}

function asModelRecord(
  rows: readonly CatalogJoinRow[],
  inputs: ModelCatalogInputs,
  providers: Map<string, ProviderRecord>,
  providerIdForRow: ProviderIdProjection,
): { ok: true; model: ModelRecord } | { ok: false; reason: string } {
  const first = rows[0];
  if (first === undefined) return { ok: false, reason: "model group is empty" };

  const modelCaps = modelCapabilities(first);
  if (!modelCaps.ok) return modelCaps;

  const envModels = new Map(inputs.models.map((model) => [model.name, model]));
  const projected: ProjectedOffering[] = [];
  const envProviders = new Map(inputs.providers.map((provider) => [provider.name, provider]));
  const activeRows = rows.filter(
    (row) =>
      enabled(row.model_enabled) && enabled(row.offering_enabled) && enabled(row.provider_enabled),
  );
  const selectedRows = (activeRows.length > 0 ? activeRows : [first]).slice().sort(rowOrder);

  for (const row of selectedRows) {
    if (row.provider_kind === "platform") {
      const envModel = envModels.get(row.model_name);
      if (envModel === undefined) {
        return {
          ok: false,
          reason: `tenant model ${row.model_name} uses platform-default but no env model supplies a physical provider`,
        };
      }
      const envProvider = envProviders.get(envModel.provider);
      if (envProvider === undefined) {
        return {
          ok: false,
          reason: `env model ${row.model_name} names unknown provider ${envModel.provider}`,
        };
      }
      const existing = providers.get(envProvider.name);
      if (existing !== undefined && JSON.stringify(existing) !== JSON.stringify(envProvider)) {
        return {
          ok: false,
          reason: `provider ${envProvider.name} is defined differently in tenant and env catalogs`,
        };
      }
      providers.set(envProvider.name, envProvider);
      projected.push({
        row,
        providerName: envProvider.name,
        providerModel: row.upstream_model_id || envModel.provider_model,
      });
      continue;
    }

    const provider = dbProvider(row, providerIdForRow(row));
    if (!provider.ok) return provider;
    const existing = providers.get(provider.provider.name);
    if (existing !== undefined && JSON.stringify(existing) !== JSON.stringify(provider.provider)) {
      return {
        ok: false,
        reason: `tenant provider ${provider.provider.name} is defined inconsistently`,
      };
    }
    providers.set(provider.provider.name, provider.provider);
    projected.push({
      row,
      providerName: provider.provider.name,
      providerModel: row.upstream_model_id,
    });
  }

  const primaryIndex = projected.findIndex(({ row }) => row.offering_role === "primary");
  const primary = projected[primaryIndex >= 0 ? primaryIndex : 0];
  if (primary === undefined)
    return { ok: false, reason: `model ${first.model_name} has no offering` };

  const fallbacks = projected.filter(
    (_, index) => index !== (primaryIndex >= 0 ? primaryIndex : 0),
  );
  const canaries = fallbacks.filter(({ row }) => row.offering_role === "canary");
  const shadows = fallbacks.filter(({ row }) => row.offering_role === "shadow");
  if (canaries.length > 1)
    return { ok: false, reason: `model ${first.model_name} has multiple canaries` };
  if (shadows.length > 1)
    return { ok: false, reason: `model ${first.model_name} has multiple shadows` };

  const primaryFields = routeFields(primary, modelCaps.value, first.model_context_window);
  if (!primaryFields.ok) return primaryFields;
  const fallbackRecords: Record<string, unknown>[] = [];
  for (const item of fallbacks) {
    if (item.row.offering_role === "canary" || item.row.offering_role === "shadow") continue;
    const fields = routeFields(item, modelCaps.value, first.model_context_window);
    if (!fields.ok) return fields;
    fallbackRecords.push(fields.fields);
  }

  const record: Record<string, unknown> = {
    name: first.model_name,
    ...primaryFields.fields,
    enabled: enabled(first.model_enabled) && activeRows.length > 0,
    ...(first.model_routing_strategy === null
      ? {}
      : { routing_strategy: first.model_routing_strategy }),
    ...(fallbackRecords.length === 0 ? {} : { fallbacks: fallbackRecords }),
    ...(first.model_owned_by === null ? {} : { owned_by: first.model_owned_by }),
  };

  const canary = canaries[0];
  if (canary !== undefined) {
    const fields = routeFields(canary, modelCaps.value, first.model_context_window);
    if (!fields.ok) return fields;
    if (canary.row.canary_percent === null) {
      return { ok: false, reason: `offering ${canary.row.offering_id} is missing canary_percent` };
    }
    record.canary = { ...fields.fields, percent: canary.row.canary_percent };
  }

  const shadow = shadows[0];
  if (shadow !== undefined) {
    const fields = routeFields(shadow, modelCaps.value, first.model_context_window);
    if (!fields.ok) return fields;
    if (shadow.row.shadow_percent === null) {
      return { ok: false, reason: `offering ${shadow.row.offering_id} is missing shadow_percent` };
    }
    record.shadow = {
      ...fields.fields,
      sample_percent: shadow.row.shadow_percent,
      ...(shadow.row.shadow_max_requests === null
        ? {}
        : { max_requests: shadow.row.shadow_max_requests }),
    };
  }

  const result = modelRecordSchema.safeParse(record);
  return result.success
    ? { ok: true, model: result.data }
    : schemaFailure(`model ${first.model_name}`, result);
}

/**
 * Group the join rows by model and project each group into a {@link ModelRecord}.
 *
 * Shared by the tenant loader and the platform loader (#890): the row shape and
 * the projection are identical between the two catalogs — only the SQL that
 * produced the rows differs. `inputs` supplies the env/platform registry the
 * `provider_kind === "platform"` arm of {@link asModelRecord} resolves against;
 * pass an empty registry when the rows carry no `platform` indirection (which is
 * always the case for the platform catalog itself — those rows are real physical
 * legs).
 */
export function projectCatalog(
  rows: readonly CatalogJoinRow[],
  inputs: ModelCatalogInputs,
  providerIdForRow: ProviderIdProjection = (row) => row.provider_id,
):
  | { ok: true; providers: Map<string, ProviderRecord>; models: ModelRecord[] }
  | { ok: false; reason: string } {
  const byModel = new Map<string, CatalogJoinRow[]>();
  for (const row of rows) {
    if (!OFFERING_ROLES.has(row.offering_role)) {
      return {
        ok: false,
        reason: `offering ${row.offering_id} has unsupported role ${row.offering_role}`,
      };
    }
    const group = byModel.get(row.model_name);
    if (group === undefined) byModel.set(row.model_name, [row]);
    else group.push(row);
  }

  const providers = new Map<string, ProviderRecord>();
  const models: ModelRecord[] = [];
  for (const group of byModel.values()) {
    const result = asModelRecord(group, inputs, providers, providerIdForRow);
    if (!result.ok) return result;
    models.push(result.model);
  }
  return { ok: true, providers, models };
}

function buildTenantCatalog(
  rows: readonly CatalogJoinRow[],
  env: InferenceBindings,
  tenantId: string,
  platformInputs?: ModelCatalogInputs,
): CatalogBuildResult {
  // A `platform`-kind row is an indirection into the platform catalog. #890:
  // resolve it against the platform catalog's inputs when they are non-empty,
  // falling back to the env registry only when the platform tables are empty
  // (the pre-#890 behavior, and the bootstrap posture).
  const needsEnv = rows.some((row) => row.provider_kind === "platform");
  let inputs: ModelCatalogInputs = { providers: [], models: [] };
  if (needsEnv) {
    if (platformInputs !== undefined && platformInputs.models.length > 0) {
      inputs = platformInputs;
    } else {
      const parsed = modelCatalogInputsFromEnv(env);
      if (!parsed.ok) return parsed;
      inputs = parsed.inputs;
    }
  }

  const tenantPrefix = `${tenantId}:`;
  const projected = projectCatalog(rows, inputs, (row) =>
    row.provider_id.startsWith(tenantPrefix)
      ? row.provider_id.slice(tenantPrefix.length)
      : row.provider_id,
  );
  if (!projected.ok) return projected;

  const built = buildModelCatalog(
    [...projected.providers.values()],
    projected.models,
    env,
    inputs.cloudflare,
  );
  if (!built.ok) return built;
  return { ok: true, resolver: new InMemoryModelResolver(built.routes) };
}

/** D1-backed source with revision-aware, per-env/per-tenant caching. */
export class D1TenantModelCatalogSource implements TenantModelCatalogSource {
  readonly #ttlMs: number;
  readonly #now: () => number;
  readonly #byEnv = new WeakMap<object, Map<string, CacheEntry>>();

  constructor(options: { ttlMs?: number; now?: () => number } = {}) {
    this.#ttlMs = options.ttlMs ?? DEFAULT_TENANT_MODEL_CATALOG_CACHE_TTL_MS;
    this.#now = options.now ?? Date.now;
  }

  async load(input: {
    tenantId: string;
    db: D1Database;
    env: InferenceBindings;
    fallback: ModelResolver;
    platformInputs?: ModelCatalogInputs;
    platformRevision?: number;
  }): Promise<TenantModelCatalogLoadResult> {
    let revision: number;
    try {
      const row = await input.db.prepare(REVISION_SQL).bind(input.tenantId).first<{
        revision: number | string | null;
      }>();
      revision = row === null || row.revision === null ? 0 : Number(row.revision);
      if (!Number.isSafeInteger(revision) || revision < 0) {
        return { ok: false, reason: `tenant ${input.tenantId} catalog revision is invalid` };
      }
    } catch (error) {
      return failure(`tenant ${input.tenantId} catalog revision read failed`, error);
    }

    const envKey = input.env as unknown as object;
    let entries = this.#byEnv.get(envKey);
    if (entries === undefined) {
      entries = new Map<string, CacheEntry>();
      this.#byEnv.set(envKey, entries);
    }
    const now = this.#now();
    const cached = entries.get(input.tenantId);
    // The cache key folds in the platform revision: a `platform`-kind leg is
    // resolved against `platformInputs`, so a platform-catalog edit (which bumps
    // the platform revision) must invalidate this entry even when the tenant's
    // own revision is unchanged — otherwise a tenant using a platform-default
    // model keeps routing to the old provider until the tenant's TTL expires
    // (#890 revision-gate: visible immediately on a revision bump).
    if (
      cached !== undefined &&
      cached.revision === revision &&
      cached.platformRevision === input.platformRevision &&
      cached.expiresAt > now
    ) {
      return { ok: true, models: cached.resolver, revision };
    }

    let rows: CatalogJoinRow[];
    try {
      const result = await input.db.prepare(CATALOG_SQL).bind(input.tenantId).all<CatalogJoinRow>();
      rows = result.results;
    } catch (error) {
      return failure(`tenant ${input.tenantId} catalog read failed`, error);
    }

    // A catalog copied from the platform at onboarding is a cache, not a tenant
    // override. Keeping that seed authoritative forever strands the tenant on
    // provider ids and model bindings that no longer exist after an operator
    // updates the live platform catalog. Only a catalog containing at least one
    // tenant-owned offering opts out of the live platform resolver.
    const platformSeedOnly =
      rows.length > 0 && rows.every((row) => row.offering_source === "platform_seed");
    if (rows.length === 0 || platformSeedOnly) {
      entries.set(input.tenantId, {
        revision,
        platformRevision: input.platformRevision,
        resolver: input.fallback,
        expiresAt: now + this.#ttlMs,
      });
      return { ok: true, models: input.fallback, revision };
    }

    let pricedRows: readonly CatalogJoinRow[];
    try {
      pricedRows = await resolvePublicModelPrices(rows, input.env, input.tenantId);
    } catch (error) {
      return failure(`tenant ${input.tenantId} public model price read failed`, error);
    }

    const built = buildTenantCatalog(pricedRows, input.env, input.tenantId, input.platformInputs);
    if (!built.ok) return built;
    entries.set(input.tenantId, {
      revision,
      platformRevision: input.platformRevision,
      resolver: built.resolver,
      expiresAt: now + this.#ttlMs,
    });
    return { ok: true, models: built.resolver, revision };
  }
}

/** Construct the production source; the returned object owns isolate-local cache state. */
export function tenantModelCatalogFromD1(
  options: { ttlMs?: number; now?: () => number } = {},
): TenantModelCatalogSource {
  return new D1TenantModelCatalogSource(options);
}
