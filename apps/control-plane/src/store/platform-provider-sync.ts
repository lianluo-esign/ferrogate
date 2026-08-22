/**
 * Import an upstream provider's live model list into the platform catalog (#944,
 * epic #941 slice 3).
 *
 * `POST /admin/v1/providers/{id}/sync-models` resolves the platform provider
 * channel's `base_url` + credential, GETs its `/v1/models`, and lays each
 * returned model down as a `platform_catalog_models` row plus a primary
 * `platform_catalog_offerings` row on that channel. It is the DYNAMIC sibling of
 * the STATIC config bootstrap (#892): the bootstrap imports the operator's env
 * tables, this imports what the upstream actually serves.
 *
 * ## Idempotent, additive, and honest about `{ added, updated, skipped }`
 *
 * The write is {@link PlatformModelCatalogStore.importGraph} — deterministic
 * ids + `INSERT OR IGNORE` — so a re-sync inserts nothing and only advances the
 * revision. The three counts are therefore derived from what the write ACTUALLY
 * did rather than from an intention it did not carry out:
 *
 *  - `added`   — offerings this call INSERTED (models new to the catalog);
 *  - `skipped` — upstream models already present, left untouched;
 *  - `updated` — always `0`, and this is faithful, not a stub: `INSERT OR
 *    IGNORE` never mutates a live row, and `GET /v1/models` advertises only an
 *    id (and at most `owned_by`) — there is no price or capability on the wire
 *    to update an existing offering FROM. Re-pricing an offering is a separate
 *    admin edit (`PATCH /admin/v1/models/{id}/offerings/{id}`), and reporting a
 *    non-zero `updated` here would claim a change to disk that did not happen.
 *
 * A model the upstream DROPS between syncs is simply absent from the new graph:
 * it is neither counted nor deleted, so a transient upstream omission cannot
 * silently tear a model out of the catalog. Removal stays an explicit operator
 * action.
 */
import type { PriceBook } from "@ferrogate/billing";
import type { SeedProviderChannel } from "@ferrogate/storage";
import {
  canonicalProviderKind,
  defaultAuthScheme,
} from "../../../gateway/src/inference/adapters.js";
import type { CallerScope } from "../ports.js";
import {
  PLATFORM_DEFAULT_PROVIDER_ID,
  type UpstreamModel,
  platformCatalogModelId,
  providerModelsToImportGraph,
} from "./platform-catalog-import.js";
import type { PlatformModelCatalogStore } from "./platform-model-catalog.js";

/**
 * A resolution the sync could not complete because of the UPSTREAM, not the
 * caller's request. The handler maps `status` straight onto the HTTP response so
 * an operator sees `502 provider_models_unavailable` (the upstream answered
 * badly) rather than a bare `500` that reads as a control-plane bug.
 */
export class ProviderModelSyncError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ProviderModelSyncError";
    this.status = status;
    this.code = code;
  }
}

/** The counts `POST .../sync-models` returns, plus the audit revision it bumped. */
export interface ProviderModelSyncResult {
  readonly added: number;
  readonly updated: number;
  readonly skipped: number;
  /** Distinct upstream models the `/v1/models` list carried (post-dedup). */
  readonly upstreamCount: number;
  /** The platform catalog revision after this sync's single audited batch. */
  readonly revision: number;
}

/** `base.trim_end_matches('/') + path`, the same join the data-plane adapter uses. */
function joinUrl(baseUrl: string, path: string): string {
  return `${baseUrl.replace(/\/+$/, "")}${path}`;
}

const MAX_MODEL_LIST_PAGES = 100;

function modelListUrl(
  provider: Pick<SeedProviderChannel, "kind" | "base_url">,
  pageToken?: string,
): string {
  const url = new URL(joinUrl(provider.base_url, "/models"));
  if (canonicalProviderKind(provider.kind) === "gemini") {
    // Gemini defaults to only 50 models. Ask for the documented maximum and
    // still follow nextPageToken so a growing catalog is never silently cut.
    url.searchParams.set("pageSize", "1000");
    if (pageToken !== undefined) url.searchParams.set("pageToken", pageToken);
  }
  return url.toString();
}

function modelListHeaders(
  provider: Pick<SeedProviderChannel, "kind" | "auth_scheme">,
  apiKey?: string,
): Record<string, string> {
  const kind = canonicalProviderKind(provider.kind);
  const headers: Record<string, string> = { accept: "application/json" };
  if (kind === "anthropic") {
    headers["anthropic-version"] = "2023-06-01";
  }
  if (apiKey === undefined || apiKey.trim().length === 0) return headers;

  // Gemini's API-key protocol uses Google's dedicated header. The generation
  // adapter does the same; putting this key in a URL would leak it into logs.
  if (kind === "gemini") {
    headers["x-goog-api-key"] = apiKey;
    return headers;
  }
  const scheme = provider.auth_scheme ?? defaultAuthScheme(provider.kind);
  if (scheme === "x-api-key") headers["x-api-key"] = apiKey;
  else headers.authorization = `Bearer ${apiKey}`;
  return headers;
}

function nonEmptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : undefined;
}

function parseModelListPage(
  payload: unknown,
  kind: string | null,
  url: string,
): { readonly models: UpstreamModel[]; readonly nextPageToken?: string } {
  if (kind === "gemini") {
    const models =
      typeof payload === "object" &&
      payload !== null &&
      Array.isArray((payload as { models?: unknown }).models)
        ? (payload as { models: unknown[] }).models
        : null;
    if (models === null) {
      throw new ProviderModelSyncError(
        502,
        "provider_models_malformed",
        `upstream ${url} did not return a { models: [...] } model list`,
      );
    }
    const parsed: UpstreamModel[] = [];
    for (const entry of models) {
      if (typeof entry !== "object" || entry === null) continue;
      const record = entry as Record<string, unknown>;
      const id =
        nonEmptyString(record.baseModelId) ?? nonEmptyString(record.name)?.replace(/^models\//, "");
      if (id === undefined) continue;
      parsed.push({ id, owned_by: "google" });
    }
    const nextPageToken =
      typeof payload === "object" && payload !== null
        ? nonEmptyString((payload as { nextPageToken?: unknown }).nextPageToken)
        : undefined;
    return { models: parsed, ...(nextPageToken === undefined ? {} : { nextPageToken }) };
  }

  // OpenAI, Grok, DeepSeek, and Anthropic all expose the OpenAI-style `data`
  // list on their model-catalog endpoint. A bare array remains accepted for
  // compatible/self-hosted providers.
  const list =
    Array.isArray(payload) === true
      ? (payload as unknown[])
      : typeof payload === "object" &&
          payload !== null &&
          Array.isArray((payload as { data?: unknown }).data)
        ? (payload as { data: unknown[] }).data
        : null;
  if (list === null) {
    throw new ProviderModelSyncError(
      502,
      "provider_models_malformed",
      `upstream ${url} did not return a { data: [...] } model list`,
    );
  }

  const models: UpstreamModel[] = [];
  for (const entry of list) {
    if (typeof entry !== "object" || entry === null) continue;
    const id = nonEmptyString((entry as { id?: unknown }).id);
    if (id === undefined) continue;
    const ownedBy = nonEmptyString((entry as { owned_by?: unknown }).owned_by);
    models.push({ id, owned_by: ownedBy ?? null });
  }
  return { models };
}

/**
 * GET the provider's `/v1/models` and return its model list.
 *
 * The auth header matches the data-plane adapter: `x-api-key` for Anthropic,
 * `x-goog-api-key` for Gemini, and `Authorization: Bearer` for the compatible
 * families unless the channel pins another scheme. No credential means no auth
 * header. Gemini's `{ models, nextPageToken }` catalog is paged; the other
 * supported families use an OpenAI-style `{ data }` list.
 *
 * `fetchImpl` is injected so a workerd test can drive a STUB `/v1/models`
 * without a live upstream and without the (unavailable) pool-workers fetch mock;
 * it defaults to the global `fetch` in production.
 */
export async function fetchUpstreamModels(options: {
  readonly provider: Pick<SeedProviderChannel, "kind" | "base_url" | "auth_scheme">;
  readonly apiKey?: string;
  readonly fetchImpl?: typeof fetch;
}): Promise<readonly UpstreamModel[]> {
  const { provider, apiKey } = options;
  const fetchImpl = options.fetchImpl ?? fetch;
  const kind = canonicalProviderKind(provider.kind);
  const headers = modelListHeaders(provider, apiKey);
  const models: UpstreamModel[] = [];
  const seenPageTokens = new Set<string>();
  let pageToken: string | undefined;

  for (let page = 0; page < MAX_MODEL_LIST_PAGES; page += 1) {
    const url = modelListUrl(provider, pageToken);
    let response: Response;
    try {
      response = await fetchImpl(url, { method: "GET", headers });
    } catch (error) {
      throw new ProviderModelSyncError(
        502,
        "provider_unreachable",
        `could not reach upstream ${url}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    if (!response.ok) {
      throw new ProviderModelSyncError(
        502,
        "provider_models_unavailable",
        `upstream GET ${url} returned ${response.status}`,
      );
    }

    let payload: unknown;
    try {
      payload = await response.json();
    } catch (error) {
      throw new ProviderModelSyncError(
        502,
        "provider_models_malformed",
        `upstream ${url} did not return JSON: ${error instanceof Error ? error.message : String(error)}`,
      );
    }

    const parsed = parseModelListPage(payload, kind, url);
    models.push(...parsed.models);
    if (parsed.nextPageToken === undefined) return models;
    if (seenPageTokens.has(parsed.nextPageToken)) {
      throw new ProviderModelSyncError(
        502,
        "provider_models_malformed",
        `upstream ${url} repeated a model-list page token`,
      );
    }
    seenPageTokens.add(parsed.nextPageToken);
    pageToken = parsed.nextPageToken;
  }

  throw new ProviderModelSyncError(
    502,
    "provider_models_malformed",
    `upstream ${provider.base_url} exceeded ${MAX_MODEL_LIST_PAGES} model-list pages`,
  );
}

/**
 * Fetch the provider's live models and idempotently upsert them into the
 * platform catalog, returning the `{ added, updated, skipped }` verification
 * shape.
 *
 * `added` is read from the store's own `inserted.offerings` — the rows the
 * single audited batch actually wrote — so the count cannot drift from the
 * disk state the way a pre-count would. `skipped` is every distinct upstream
 * model that was NOT inserted (already present). See the module header for why
 * `updated` is `0`.
 */
export async function syncProviderModelsIntoCatalog(options: {
  readonly store: PlatformModelCatalogStore;
  readonly scope: CallerScope;
  readonly provider: SeedProviderChannel;
  readonly apiKey?: string;
  readonly priceBook: PriceBook;
  readonly fetchImpl?: typeof fetch;
}): Promise<ProviderModelSyncResult> {
  const upstreamModels = await fetchUpstreamModels({
    provider: options.provider,
    apiKey: options.apiKey,
    fetchImpl: options.fetchImpl,
  });

  // A model whose single primary slot a DIFFERENT real provider already owns
  // must be laid down as a `fallback`, or `INSERT OR IGNORE` collides it with
  // that primary and drops it silently behind a 200 (#944 review). A
  // `platform-default` rate-card primary is NOT a real owner — `importGraph`
  // purges it for a real offering — so it does not force a demotion.
  const candidateModelIds = [...new Set(upstreamModels.map((model) => model.id))].map(
    platformCatalogModelId,
  );
  const primaryOwners = await options.store.primaryOfferingOwners(candidateModelIds);
  const fallbackModelIds = new Set<string>();
  for (const [modelId, ownerProviderId] of primaryOwners) {
    if (
      ownerProviderId !== options.provider.id &&
      ownerProviderId !== PLATFORM_DEFAULT_PROVIDER_ID
    ) {
      fallbackModelIds.add(modelId);
    }
  }

  const graph = providerModelsToImportGraph(
    options.provider,
    upstreamModels,
    options.priceBook,
    fallbackModelIds,
  );
  const result = await options.store.importGraph(options.scope, graph);

  // `graph.offerings` is the deduped upstream list (one offering per distinct
  // model, primary or fallback), so its length is the true "how many distinct
  // models did the upstream offer".
  const upstreamCount = graph.offerings.length;
  const added = result.inserted.offerings;
  return {
    added,
    updated: 0,
    skipped: upstreamCount - added,
    upstreamCount,
    revision: result.revision,
  };
}
