import { PriceBook } from "@ferrogate/billing";
/**
 * Bootstrap-import parity (#892): a platform catalog built from the IMPORTED env
 * pair must produce the SAME flattened `PhysicalRoute` set the env tables produce
 * directly — route for route, prices included — and the default-rate-card
 * `platform`-kind price rows must NOT leak into that set.
 *
 * This is the round trip the issue's "done when" names, end to end and hermetic:
 *
 *   GATEWAY_PROVIDERS/GATEWAY_MODELS
 *     -> `modelCatalogInputsFromEnv`         (the data plane's own parse)
 *     -> `envInputsToImportGraph`            (#892's REAL converter, under test)
 *     -> platform_catalog rows (as `CatalogJoinRow`s, the shape `CATALOG_SQL` emits)
 *     -> `ControlDataPlatformModelCatalogSource.load`  (the REAL #890 loader + #892 filter)
 *     -> flattened `PhysicalRoute`s
 *
 * compared against `modelCatalogFromEnv` over the identical env pair. The rate
 * card is merged into the graph too, so the `platform-default` (kind `platform`)
 * rows are present in what the loader reads — proving the loader EXCLUDES them
 * (otherwise the sets would differ, or the whole build would 503). The real SQL
 * write/read is covered separately by the control-plane
 * `admin-config-import-catalog` suite; here a fake control database feeds the
 * join rows so the assertion is deterministic and touches no shared state.
 */
import { describe, expect, it } from "vitest";
import {
  envInputsToImportGraph,
  mergeImportGraphs,
  rateCardToImportGraph,
} from "../../../control-plane/src/store/platform-catalog-import.js";
import { modelCatalogFromEnv, modelCatalogInputsFromEnv } from "../../src/inference/catalog.js";
import { emptyModelResolver } from "../../src/inference/defaults.js";
import { ControlDataPlatformModelCatalogSource } from "../../src/inference/platform-catalog.js";
import type { PhysicalRoute } from "../../src/inference/ports.js";
import type { CatalogJoinRow } from "../../src/inference/tenant-catalog.js";
import { controlNamespaceOverD1 } from "../support/control-namespace.js";

const PROVIDERS = [
  {
    name: "openai",
    kind: "openai-compatible",
    base_url: "https://api.openai.example/v1",
    api_key_var: "OPENAI_KEY",
  },
  {
    name: "anthropic",
    kind: "anthropic",
    base_url: "https://api.anthropic.example",
    api_key_var: "ANTHROPIC_KEY",
    auth_scheme: "x-api-key",
  },
];

const MODELS = [
  {
    name: "smart",
    provider: "openai",
    provider_model: "gpt-4o",
    capabilities: ["chat", "streaming"],
    routing_strategy: "priority",
    input_price_per_1m: 2.5,
    output_price_per_1m: 10,
    cached_input_price_per_1m: 1.25,
    fallbacks: [
      {
        provider: "anthropic",
        provider_model: "claude-sonnet-4",
        capabilities: ["chat"],
        input_price_per_1m: 3,
        output_price_per_1m: 15,
      },
    ],
  },
  {
    name: "fast",
    provider: "openai",
    provider_model: "gpt-4o-mini",
    capabilities: ["chat"],
    routing_strategy: "priority",
    input_price_per_1m: 0.15,
    output_price_per_1m: 0.6,
  },
];

function envPair(): Record<string, unknown> {
  return {
    GATEWAY_PROVIDERS: JSON.stringify(PROVIDERS),
    GATEWAY_MODELS: JSON.stringify(MODELS),
    OPENAI_KEY: "sk-openai-test",
    ANTHROPIC_KEY: "sk-anthropic-test",
  };
}

/**
 * One graph row set → the `CatalogJoinRow`s `CATALOG_SQL` would emit for it.
 *
 * Mechanical join glue, NOT the logic under test: the converter that produced
 * `graph` and the loader that consumes these rows are the real code; this only
 * stands in for the SQL join the control-plane suite exercises for real.
 */
function joinRows(graph: ReturnType<typeof envInputsToImportGraph>): CatalogJoinRow[] {
  const models = new Map(graph.models.map((model) => [model.id, model]));
  const providers = new Map(graph.providers.map((provider) => [provider.id, provider]));
  const rows: CatalogJoinRow[] = [];
  for (const offering of graph.offerings) {
    const model = models.get(offering.model_id);
    const provider = providers.get(offering.provider_id);
    if (model === undefined || provider === undefined) continue;
    rows.push({
      model_id: model.id,
      model_name: model.name,
      model_owned_by: model.owned_by,
      model_capabilities_json: model.capabilities_json,
      model_context_window: model.context_window,
      model_routing_strategy: model.routing_strategy,
      model_enabled: model.enabled,
      offering_id: offering.id,
      upstream_model_id: offering.upstream_model_id,
      offering_role: offering.role,
      offering_priority: offering.priority,
      offering_weight: offering.weight,
      canary_percent: offering.canary_percent,
      shadow_percent: offering.shadow_percent,
      shadow_max_requests: offering.shadow_max_requests,
      offering_capabilities_json: offering.capabilities_json,
      offering_context_window: offering.context_window,
      offering_region: offering.region,
      offering_zero_data_retention: offering.zero_data_retention,
      input_price_per_1m: offering.input_price_per_1m,
      output_price_per_1m: offering.output_price_per_1m,
      cached_input_price_per_1m: offering.cached_input_price_per_1m,
      cache_write_price_per_1m: offering.cache_write_price_per_1m,
      reasoning_price_per_1m: offering.reasoning_price_per_1m,
      audio_second_price_per_1m: offering.audio_second_price_per_1m,
      audio_character_price_per_1m: offering.audio_character_price_per_1m,
      offering_enabled: offering.enabled,
      provider_id: provider.id,
      provider_name: provider.name,
      provider_kind: provider.kind,
      provider_base_url: provider.base_url,
      provider_api_key_var: provider.api_key_var,
      provider_byok_alias: provider.byok_alias,
      provider_auth_scheme: provider.auth_scheme,
      provider_region: provider.region,
      provider_zero_data_retention: provider.zero_data_retention,
      provider_openrouter_http_referer: provider.openrouter_http_referer,
      provider_openrouter_x_title: provider.openrouter_x_title,
      provider_cloudflare_ai_gateway_json: provider.cloudflare_ai_gateway_json,
      provider_enabled: provider.enabled,
    });
  }
  // The order `CATALOG_SQL` produces: (model name, priority asc, weight desc, id).
  return rows.sort(
    (a, b) =>
      a.model_name.localeCompare(b.model_name) ||
      (a.offering_priority ?? 100) - (b.offering_priority ?? 100) ||
      (b.offering_weight ?? 1) - (a.offering_weight ?? 1) ||
      a.offering_id.localeCompare(b.offering_id),
  );
}

/** A fake control database returning a fixed revision and the join rows. */
function fakeControlDb(
  rows: CatalogJoinRow[],
  revision: number,
): { db: D1Database; revision: number } {
  const state = { revision };
  const chain = {
    bind() {
      return chain;
    },
    async first<T>() {
      return { revision: state.revision } as T;
    },
    async all<T>() {
      return { results: rows as T[] };
    },
  };
  const chainFor = (sql: string) => ({
    bind() {
      return chainFor(sql);
    },
    async first<T>() {
      return { revision: state.revision } as T;
    },
    async all<T>() {
      return {
        results: (sql.includes("platform_catalog_revisions")
          ? [{ revision: state.revision }]
          : rows) as T[],
      };
    },
  });
  void chain;
  return { db: { prepare: (sql: string) => chainFor(sql) } as unknown as D1Database, revision };
}

/** A route as a stable key so two flattened sets compare order-independently. */
function canonical(route: PhysicalRoute): string {
  const entries = Object.entries(route as unknown as Record<string, unknown>).sort(([a], [b]) =>
    a.localeCompare(b),
  );
  return JSON.stringify(entries);
}

function sortedCanonical(routes: readonly PhysicalRoute[]): string[] {
  return routes.map(canonical).sort();
}

describe("platform catalog bootstrap-import parity (#892)", () => {
  it("reproduces modelCatalogFromEnv's flattened routes and excludes rate-card rows", async () => {
    const env = envPair();
    const inputs = modelCatalogInputsFromEnv(env as never);
    expect(inputs.ok).toBe(true);
    if (!inputs.ok) return;

    // The REAL converter, plus the rate card merged in so the loader must filter
    // the `platform-default` (kind `platform`) price rows back out.
    const graph = mergeImportGraphs(
      envInputsToImportGraph(inputs.inputs.providers, inputs.inputs.models),
      rateCardToImportGraph(
        PriceBook.withDefaultRateCard(),
        new Set(inputs.inputs.models.map((model) => model.name)),
      ),
    );
    expect(graph.providers.some((provider) => provider.kind === "platform")).toBe(true);

    const control = fakeControlDb(joinRows(graph), 1);
    const loadEnv = { ...env, CONTROL_DATA: controlNamespaceOverD1(control.db) };
    const source = new ControlDataPlatformModelCatalogSource();
    const loaded = await source.load({
      env: loadEnv as never,
      fallback: emptyModelResolver,
    });
    expect(loaded.ok, loaded.ok ? "" : loaded.reason).toBe(true);
    if (!loaded.ok) return;

    const envRoutes = modelCatalogFromEnv(env as never);
    expect(envRoutes.ok).toBe(true);
    if (!envRoutes.ok) return;

    const logicalModels = new Set(envRoutes.routes.map((route) => route.logicalModel));
    const platformRoutes = [...logicalModels].flatMap((model) =>
      loaded.models.candidates ? loaded.models.candidates(model) : [],
    );

    // Route-for-route parity, prices included.
    expect(sortedCanonical(platformRoutes)).toEqual(sortedCanonical(envRoutes.routes));

    // The rate-card model rows are present in what the loader read, but produce
    // no routes: they hang off the excluded platform-default channel.
    expect(loaded.models.candidates?.("gpt-4o") ?? []).toEqual([]);
    expect(loaded.models.resolve("gpt-4o")).toBeNull();

    // Re-reading at a bumped revision yields the identical set — "running it
    // twice changes nothing but the revision".
    const reloadEnv = {
      ...loadEnv,
      CONTROL_DATA: controlNamespaceOverD1(fakeControlDb(joinRows(graph), 2).db),
    };
    const reloaded = await source.load({ env: reloadEnv as never, fallback: emptyModelResolver });
    expect(reloaded.ok).toBe(true);
    if (!reloaded.ok) return;
    const reloadedRoutes = [...logicalModels].flatMap((model) =>
      reloaded.models.candidates ? reloaded.models.candidates(model) : [],
    );
    expect(sortedCanonical(reloadedRoutes)).toEqual(sortedCanonical(platformRoutes));
    expect(reloaded.revision).toBe(2);
  });
});
