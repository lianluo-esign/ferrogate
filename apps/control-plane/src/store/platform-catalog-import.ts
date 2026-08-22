/**
 * The bootstrap import (#892, epic #810): the deployed `GATEWAY_PROVIDERS` /
 * `GATEWAY_MODELS` env tables and the default rate card, turned into the row
 * graph {@link PlatformModelCatalogStore.importGraph} writes.
 *
 * ## Why this is the INVERSE of the gateway's projection
 *
 * `apps/gateway/src/inference/tenant-catalog.ts::projectCatalog` reads the three
 * catalog tables and rebuilds the `ProviderRecord` / `ModelRecord` pair that
 * `buildModelCatalog` flattens into `PhysicalRoute`s. This module goes the other
 * way: it takes that same parsed pair (via `modelCatalogInputsFromEnv`, so the
 * parse is byte-identical to what the data plane does) and lays the rows down so
 * that reading them back through the platform loader reproduces the routes the
 * env tables produced — the parity invariant #892's workerd test asserts.
 *
 * The mapping is FAITHFUL rather than lossy where the schemas overlap, and the
 * places they do NOT overlap are named honestly:
 *
 *  - a `bedrock`/`vertex` provider's `aws_*`/`gcp_*` credential fields have no
 *    column in `platform_provider_channels` (they never did — #889 modelled the
 *    common families), so those providers cannot round-trip and the import
 *    carries them WITHOUT those fields. An operator whose env catalog routes to
 *    Bedrock/Vertex keeps the env path for those until the columns land; this is
 *    a documented gap, not a silent drop into a broken route.
 *  - a model's `tenant_id`/`project_id` (a PRIVATE env model) has no home in the
 *    platform (deployment-wide) catalog and is dropped; the platform catalog is
 *    the default every tenant sees, not a store for one tenant's private models.
 *
 * ## The rate card becomes `platform`-kind price rows
 *
 * `PriceBook.withDefaultRateCard()` prices a MODEL, not a channel — its provider
 * is the wildcard `"*"`. The tenant migration `0009_model_catalog.sql` converts
 * exactly this shape into a single `platform-default` channel of kind
 * `'platform'` with one priced primary offering per model, and this mirrors that
 * conversion into the platform catalog. Those rows carry PRICES but NO physical
 * upstream, so the platform data-plane loader
 * (`apps/gateway/src/inference/platform-catalog.ts`) excludes `kind = 'platform'`
 * rows from the route build and `PlatformModelCatalogStore.exportForSeed` excludes
 * them from a tenant seed — they are a managed record of the default rate card,
 * not a routable leg. Cache rates are materialized from the multiplier form the
 * card states them in, exactly as `0009` does (`input * cached_input_multiplier`).
 */
import type { PriceBook } from "@ferrogate/billing";
import type {
  SeedCatalogModel,
  SeedCatalogOffering,
  SeedProviderChannel,
} from "@ferrogate/storage";
import type { ModelRecord, ProviderRecord } from "../../../gateway/src/inference/catalog.js";

/** The synthetic wildcard channel the rate card's `"*"` provider becomes (mirrors `0009`). */
export const PLATFORM_DEFAULT_PROVIDER_ID = "platform:provider:platform-default";
const PLATFORM_DEFAULT_PROVIDER_NAME = "platform-default";
const PLATFORM_DEFAULT_PROVIDER_KIND = "platform";
const PLATFORM_DEFAULT_PROVIDER_BASE_URL = "platform://default";

/** `source` stamped on offerings imported from the env tables. */
export const IMPORT_SOURCE_ENV = "env_import";
/** `source` stamped on offerings imported from `withDefaultRateCard()`. */
export const IMPORT_SOURCE_RATE_CARD = "default_rate_card";
/** `source` stamped on offerings synced from a provider's live `/v1/models` (#944). */
export const IMPORT_SOURCE_PROVIDER_SYNC = "provider_sync";

/**
 * One offering row for the import — the `platform_catalog_offerings` columns.
 *
 * {@link SeedCatalogOffering} is ALMOST this shape, but deliberately omits
 * `source` (the tenant seed forces `platform_seed`); the import wants to record
 * WHERE a row came from, so it carries `source` explicitly.
 */
export interface ImportOfferingRow extends SeedCatalogOffering {
  readonly source: string;
}

/** The three-entity graph {@link PlatformModelCatalogStore.importGraph} writes. */
export interface PlatformCatalogImportGraph {
  readonly providers: readonly SeedProviderChannel[];
  readonly models: readonly SeedCatalogModel[];
  readonly offerings: readonly ImportOfferingRow[];
}

/** Deterministic ids from natural keys, so a re-run is a row-for-row no-op. */
function providerId(name: string): string {
  return `platform:provider:${name}`;
}
function modelId(name: string): string {
  return `platform:model:${name}`;
}

/**
 * The deterministic `platform_catalog_models.id` an upstream model name maps to
 * (#944). Exported so the sync orchestration can compute the candidate model ids
 * — WITHOUT rebuilding the graph — to ask the store which of them already carry
 * a real primary offering (see {@link providerModelsToImportGraph}'s
 * `fallbackModelIds`).
 */
export function platformCatalogModelId(name: string): string {
  return modelId(name);
}
function offeringId(model: string, providerName: string, upstream: string): string {
  return `platform:offering:${model}:${providerName}:${upstream}`;
}

function boolToInt(value: boolean | undefined): number | null {
  return value === undefined ? null : value ? 1 : 0;
}

function capabilitiesJson(capabilities: readonly string[] | undefined): string | null {
  return capabilities === undefined ? null : JSON.stringify(capabilities);
}

/** One `ProviderRecord` → one channel row. `aws_*`/`gcp_*` have no column (see header). */
function providerRow(provider: ProviderRecord): SeedProviderChannel {
  return {
    id: providerId(provider.name),
    name: provider.name,
    kind: provider.kind,
    base_url: provider.base_url,
    api_key_var: provider.api_key_var ?? null,
    byok_alias: provider.byok_alias ?? null,
    auth_scheme: provider.auth_scheme ?? null,
    region: provider.region ?? null,
    zero_data_retention: boolToInt(provider.zero_data_retention),
    openrouter_http_referer: provider.openrouter_http_referer ?? null,
    openrouter_x_title: provider.openrouter_x_title ?? null,
    cloudflare_ai_gateway_json:
      provider.cloudflare_ai_gateway === undefined
        ? null
        : JSON.stringify(provider.cloudflare_ai_gateway),
    enabled: 1,
  };
}

/**
 * The route half of a model/leg → the price/binding half of an offering row.
 *
 * The leg's OWN region / zero_data_retention / context_window are stored (not the
 * provider-resolved value): `buildModelCatalog` re-applies the provider fallback
 * on read, so storing the resolved value here would double-apply it and a leg
 * that inherited its provider's region would round-trip to a leg that STATES it.
 */
function offeringPricing(leg: {
  readonly capabilities?: readonly string[];
  readonly region?: string;
  readonly zero_data_retention?: boolean;
  readonly context_window?: number;
  readonly input_price_per_1m?: number;
  readonly output_price_per_1m?: number;
  readonly cached_input_price_per_1m?: number;
  readonly cache_write_price_per_1m?: number;
  readonly reasoning_price_per_1m?: number;
  readonly audio_second_price_per_1m?: number;
  readonly audio_character_price_per_1m?: number;
}): Pick<
  ImportOfferingRow,
  | "capabilities_json"
  | "region"
  | "zero_data_retention"
  | "context_window"
  | "input_price_per_1m"
  | "output_price_per_1m"
  | "cached_input_price_per_1m"
  | "cache_write_price_per_1m"
  | "reasoning_price_per_1m"
  | "audio_second_price_per_1m"
  | "audio_character_price_per_1m"
  | "currency"
> {
  return {
    capabilities_json: capabilitiesJson(leg.capabilities),
    region: leg.region ?? null,
    zero_data_retention: boolToInt(leg.zero_data_retention),
    context_window: leg.context_window ?? null,
    input_price_per_1m: leg.input_price_per_1m ?? null,
    output_price_per_1m: leg.output_price_per_1m ?? null,
    cached_input_price_per_1m: leg.cached_input_price_per_1m ?? null,
    cache_write_price_per_1m: leg.cache_write_price_per_1m ?? null,
    reasoning_price_per_1m: leg.reasoning_price_per_1m ?? null,
    audio_second_price_per_1m: leg.audio_second_price_per_1m ?? null,
    audio_character_price_per_1m: leg.audio_character_price_per_1m ?? null,
    currency: "USD",
  };
}

/**
 * The env `[[providers]]`/`[[models]]` pair → the import graph.
 *
 * The caller is expected to have parsed the pair with `modelCatalogInputsFromEnv`
 * and validated it with `buildModelCatalog`, so a duplicate model or an unknown
 * provider reference has already been refused before a row is laid down here.
 */
export function envInputsToImportGraph(
  providers: readonly ProviderRecord[],
  models: readonly ModelRecord[],
): PlatformCatalogImportGraph {
  const providerRows = providers.map(providerRow);
  const modelRows: SeedCatalogModel[] = [];
  const offeringRows: ImportOfferingRow[] = [];

  for (const model of models) {
    modelRows.push({
      id: modelId(model.name),
      name: model.name,
      family: null,
      owned_by: model.owned_by ?? null,
      capabilities_json: JSON.stringify(model.capabilities ?? []),
      context_window: model.context_window ?? null,
      routing_strategy: model.routing_strategy ?? "priority",
      enabled: model.enabled === false ? 0 : 1,
    });

    // The primary leg's ordering defaults are `ModelRoute::new` (0/1); a
    // fallback/canary/shadow leg's are `unwrap_or(100)`/`unwrap_or(1)`. These are
    // materialized here so the stored priority/weight equal the route's — the
    // offering columns are NOT NULL and always read back, so a re-applied default
    // on read would otherwise disagree with the env route.
    offeringRows.push({
      id: offeringId(model.name, model.provider, model.provider_model),
      model_id: modelId(model.name),
      provider_id: providerId(model.provider),
      upstream_model_id: model.provider_model,
      role: "primary",
      priority: model.priority ?? 0,
      weight: model.weight ?? 1,
      canary_percent: null,
      shadow_percent: null,
      shadow_max_requests: null,
      ...offeringPricing(model),
      enabled: 1,
      source: IMPORT_SOURCE_ENV,
    });

    for (const fallback of model.fallbacks ?? []) {
      offeringRows.push({
        id: offeringId(model.name, fallback.provider, fallback.provider_model),
        model_id: modelId(model.name),
        provider_id: providerId(fallback.provider),
        upstream_model_id: fallback.provider_model,
        role: "fallback",
        priority: fallback.priority ?? 100,
        weight: fallback.weight ?? 1,
        canary_percent: null,
        shadow_percent: null,
        shadow_max_requests: null,
        ...offeringPricing(fallback),
        enabled: 1,
        source: IMPORT_SOURCE_ENV,
      });
    }

    if (model.canary !== undefined) {
      offeringRows.push({
        id: offeringId(model.name, model.canary.provider, model.canary.provider_model),
        model_id: modelId(model.name),
        provider_id: providerId(model.canary.provider),
        upstream_model_id: model.canary.provider_model,
        role: "canary",
        priority: model.canary.priority ?? 100,
        weight: model.canary.weight ?? 1,
        canary_percent: model.canary.percent,
        shadow_percent: null,
        shadow_max_requests: null,
        ...offeringPricing(model.canary),
        enabled: 1,
        source: IMPORT_SOURCE_ENV,
      });
    }

    if (model.shadow !== undefined) {
      offeringRows.push({
        id: offeringId(model.name, model.shadow.provider, model.shadow.provider_model),
        model_id: modelId(model.name),
        provider_id: providerId(model.shadow.provider),
        upstream_model_id: model.shadow.provider_model,
        role: "shadow",
        priority: model.shadow.priority ?? 100,
        weight: model.shadow.weight ?? 1,
        canary_percent: null,
        shadow_percent: model.shadow.sample_percent,
        shadow_max_requests: model.shadow.max_requests ?? null,
        ...offeringPricing(model.shadow),
        enabled: 1,
        source: IMPORT_SOURCE_ENV,
      });
    }
  }

  return { providers: providerRows, models: modelRows, offerings: offeringRows };
}

/**
 * `PriceBook.withDefaultRateCard()` → `platform`-kind priced offerings.
 *
 * One `platform-default` channel plus one priced primary offering per rate-card
 * model, mirroring `0009`'s wildcard conversion. Entries whose model name is
 * already an imported env model are SKIPPED (`excludeModelNames`): the env model
 * is the real routable one and its `platform_catalog_models` row already exists,
 * so a second `primary` offering on it would only lose the `ux_primary` race.
 */
export function rateCardToImportGraph(
  card: PriceBook,
  excludeModelNames: ReadonlySet<string>,
): PlatformCatalogImportGraph {
  const modelRows: SeedCatalogModel[] = [];
  const offeringRows: ImportOfferingRow[] = [];

  for (const entry of card.entries) {
    if (excludeModelNames.has(entry.model)) continue;
    // Every default-card entry is keyed on the wildcard provider; a hypothetical
    // concrete-provider entry would name a real channel this import does not
    // create, so it is skipped rather than dangled off `platform-default`.
    if (entry.provider !== "*") continue;

    modelRows.push({
      id: modelId(entry.model),
      name: entry.model,
      family: null,
      owned_by: null,
      capabilities_json: "[]",
      context_window: null,
      routing_strategy: "priority",
      enabled: 1,
    });
    offeringRows.push({
      id: offeringId(entry.model, PLATFORM_DEFAULT_PROVIDER_NAME, entry.model),
      model_id: modelId(entry.model),
      provider_id: PLATFORM_DEFAULT_PROVIDER_ID,
      upstream_model_id: entry.model,
      role: "primary",
      priority: 0,
      weight: 1,
      canary_percent: null,
      shadow_percent: null,
      shadow_max_requests: null,
      capabilities_json: null,
      context_window: null,
      region: null,
      zero_data_retention: null,
      input_price_per_1m: entry.price.input_price_per_1m,
      output_price_per_1m: entry.price.output_price_per_1m,
      // `withDefaultRateCard` states cache rates ABSOLUTELY (it pre-multiplies via
      // `withCacheMultipliers`), so they are copied straight — unlike `0009`, which
      // materializes them from the multiplier form the storage card carries.
      cached_input_price_per_1m: entry.price.cached_input_price_per_1m ?? null,
      cache_write_price_per_1m: entry.price.cache_write_price_per_1m ?? null,
      reasoning_price_per_1m: entry.price.reasoning_price_per_1m ?? null,
      audio_second_price_per_1m: entry.price.audio_second_price_per_1m ?? null,
      audio_character_price_per_1m: entry.price.audio_character_price_per_1m ?? null,
      currency: entry.price.currency ?? "USD",
      enabled: 1,
      source: IMPORT_SOURCE_RATE_CARD,
    });
  }

  const providers: SeedProviderChannel[] =
    modelRows.length === 0
      ? []
      : [
          {
            id: PLATFORM_DEFAULT_PROVIDER_ID,
            name: PLATFORM_DEFAULT_PROVIDER_NAME,
            kind: PLATFORM_DEFAULT_PROVIDER_KIND,
            base_url: PLATFORM_DEFAULT_PROVIDER_BASE_URL,
            api_key_var: null,
            byok_alias: null,
            auth_scheme: null,
            region: null,
            zero_data_retention: null,
            openrouter_http_referer: null,
            openrouter_x_title: null,
            cloudflare_ai_gateway_json: null,
            enabled: 1,
          },
        ];

  return { providers, models: modelRows, offerings: offeringRows };
}

/** One row of an upstream provider's `GET /v1/models` list (#944). */
export interface UpstreamModel {
  /** The upstream model id — the only field OpenAI's `/v1/models` guarantees. */
  readonly id: string;
  /** Upstream `owned_by`, when advertised; carried onto the catalog model row. */
  readonly owned_by?: string | null;
}

/**
 * A provider's live `GET /v1/models` list → the platform import graph (#944).
 *
 * The INVERSE end of {@link rateCardToImportGraph}: that turns a compiled-in
 * rate card into price-only `platform`-kind rows; this turns an upstream's real
 * model inventory into REAL offerings on the provider channel being synced. Each
 * upstream model becomes one `platform_catalog_models` row (name = the upstream
 * id, so the natural key is stable across re-syncs) and one primary
 * `platform_catalog_offerings` row whose `upstream_model_id` is that same id.
 *
 * `providers` is deliberately EMPTY: the channel already exists in the control
 * database — it is the row the operator pointed the sync at — so re-inserting it
 * would be redundant, and the offering's `provider_id` foreign key is satisfied
 * by the live row rather than by a member of this graph. The handler therefore
 * does NOT run {@link importGraphReferentialError} (which only knows the graph's
 * own providers) against a provider-sync graph.
 *
 * Provider discovery never manufactures a price. `importGraph` binds the new
 * offering to an exact `platform_model_prices.model_key` when one exists; no
 * match leaves the route unbound and all legacy price columns null. Duplicate
 * upstream ids are collapsed to the first, so a malformed upstream list cannot
 * fan out into a `ux_..._primary` collision.
 *
 * ## Two providers serving the same model → the later one is a FALLBACK, not a drop
 *
 * `model_id` is `platform:model:{name}` — keyed on the upstream name ALONE, so
 * two providers that both serve `gpt-4o` share one model row. The schema allows
 * exactly ONE `role = 'primary'` offering per model_id
 * (`ux_platform_catalog_offerings_primary`), and {@link importGraph} writes with
 * `INSERT OR IGNORE`; so a naive "everything is primary" would let the second
 * provider's offering collide with the first's primary and be SILENTLY DROPPED,
 * misreported as `skipped` behind a 200 (#944 review). `fallbackModelIds` names
 * the model_ids whose primary slot a DIFFERENT real provider already holds; this
 * provider's offering for those is laid down as a routable `fallback` (a legal
 * second leg, ordered after the primary) so it actually routes and is counted as
 * `added`. The orchestration derives the set from the live catalog, so the FIRST
 * provider synced for a model owns its primary and later ones become fallbacks.
 */
export function providerModelsToImportGraph(
  provider: Pick<SeedProviderChannel, "id" | "name">,
  upstreamModels: readonly UpstreamModel[],
  _priceBook: PriceBook,
  fallbackModelIds: ReadonlySet<string> = new Set(),
): PlatformCatalogImportGraph {
  const modelRows: SeedCatalogModel[] = [];
  const offeringRows: ImportOfferingRow[] = [];
  const seen = new Set<string>();

  for (const upstream of upstreamModels) {
    const name = upstream.id;
    if (seen.has(name)) continue;
    seen.add(name);

    modelRows.push({
      id: modelId(name),
      name,
      family: null,
      owned_by: upstream.owned_by ?? null,
      capabilities_json: "[]",
      context_window: null,
      routing_strategy: "priority",
      enabled: 1,
    });

    const asFallback = fallbackModelIds.has(modelId(name));
    offeringRows.push({
      id: offeringId(name, provider.name, name),
      model_id: modelId(name),
      provider_id: provider.id,
      upstream_model_id: name,
      // A model whose primary slot another real provider already holds gets a
      // `fallback` leg (priority 100, the env-fallback default) so it routes
      // rather than colliding with the primary and being dropped; otherwise this
      // provider owns the primary.
      role: asFallback ? "fallback" : "primary",
      priority: asFallback ? 100 : 0,
      weight: 1,
      canary_percent: null,
      shadow_percent: null,
      shadow_max_requests: null,
      capabilities_json: null,
      context_window: null,
      region: null,
      zero_data_retention: null,
      input_price_per_1m: null,
      output_price_per_1m: null,
      cached_input_price_per_1m: null,
      cache_write_price_per_1m: null,
      reasoning_price_per_1m: null,
      audio_second_price_per_1m: null,
      audio_character_price_per_1m: null,
      currency: "USD",
      enabled: 1,
      source: IMPORT_SOURCE_PROVIDER_SYNC,
    });
  }

  return { providers: [], models: modelRows, offerings: offeringRows };
}

/**
 * The first offering that references a provider or model NOT in the graph, or
 * `null` when the graph is internally consistent.
 *
 * An `INSERT OR IGNORE` on an offering whose foreign key is absent is silently
 * SKIPPED by SQLite rather than raised, so an env model naming an unknown
 * provider would otherwise vanish from the import with no diagnostic. Checked
 * here so the operator gets a `400` naming the offending reference instead — the
 * cheap referential check the store cannot make once the batch is in flight.
 * (Secret resolution, which `buildModelCatalog` also does, is deliberately NOT
 * checked: the import stores credential NAMES and this Worker holds no provider
 * secrets.)
 */
export function importGraphReferentialError(graph: PlatformCatalogImportGraph): string | null {
  const providerIds = new Set(graph.providers.map((provider) => provider.id));
  const modelIds = new Set(graph.models.map((model) => model.id));
  for (const offering of graph.offerings) {
    if (!modelIds.has(offering.model_id)) {
      return `offering ${offering.id} references unknown model ${offering.model_id}`;
    }
    if (!providerIds.has(offering.provider_id)) {
      return `offering ${offering.id} references unknown provider ${offering.provider_id}`;
    }
  }
  return null;
}

/**
 * Merge graphs, de-duplicating rows by their deterministic id.
 *
 * The env graph is laid down first and wins on a collision (a real routable row
 * is preferred over a rate-card price row), which is belt-and-braces alongside
 * `rateCardToImportGraph`'s own `excludeModelNames` skip.
 */
export function mergeImportGraphs(
  ...graphs: readonly PlatformCatalogImportGraph[]
): PlatformCatalogImportGraph {
  const providers = new Map<string, SeedProviderChannel>();
  const models = new Map<string, SeedCatalogModel>();
  const offerings = new Map<string, ImportOfferingRow>();
  for (const graph of graphs) {
    for (const provider of graph.providers)
      if (!providers.has(provider.id)) providers.set(provider.id, provider);
    for (const model of graph.models) if (!models.has(model.id)) models.set(model.id, model);
    for (const offering of graph.offerings)
      if (!offerings.has(offering.id)) offerings.set(offering.id, offering);
  }
  return {
    providers: [...providers.values()],
    models: [...models.values()],
    offerings: [...offerings.values()],
  };
}
