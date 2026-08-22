import { PriceBook } from "@ferrogate/billing";
import { PROVIDER_TYPE_IDS } from "@ferrogate/provider-types";
import type { SeedProviderChannel } from "@ferrogate/storage";
import { z } from "zod";
import { providerSecretRefusal, resolveProviderSecret } from "../../../gateway/src/keys/index.js";
import { HttpError } from "../middleware/errors.js";
import type { StoreRecord } from "../ports.js";
import { adminDeleted, adminItem, listResponse, parseListQuery } from "../responses.js";
import {
  PlatformModelCatalogStore,
  isMissingPlatformCatalogError,
} from "../store/platform-model-catalog.js";
import {
  ProviderConnectivityError,
  listProviderConnectivityModels,
  testProviderConnectivity,
} from "../store/platform-provider-connectivity.js";
import {
  ProviderModelSyncError,
  syncProviderModelsIntoCatalog,
} from "../store/platform-provider-sync.js";
import { matchesFilters, matchesSearch } from "../store/query.js";
import { tenantDatabaseFor } from "../store/tenancy.js";
import {
  type ModelCatalogInput,
  type ModelOfferingInput,
  type ProviderChannelInput,
  TenantCatalogConflictError,
  TenantCatalogNotFoundError,
  TenantCatalogValidationError,
  TenantModelCatalogStore,
} from "../store/tenant-model-catalog.js";
import { type Handler, depsOf, json, pathParam, readJson, scopeOf } from "./resource.js";

const providerCreateSchema = z
  .object({
    id: z.string().trim().min(1).optional(),
    tenant_id: z.string().trim().min(1).optional(),
    name: z.string().trim().min(1),
    provider_type_id: z.enum(PROVIDER_TYPE_IDS).optional(),
    kind: z.string().trim().min(1),
    base_url: z.string().trim().url(),
    api_key_var: z.string().trim().min(1).nullable().optional(),
    byok_alias: z.string().trim().min(1).nullable().optional(),
    auth_scheme: z.enum(["bearer", "x-api-key"]).nullable().optional(),
    region: z.string().trim().min(1).nullable().optional(),
    zero_data_retention: z.boolean().nullable().optional(),
    openrouter_http_referer: z.string().trim().min(1).nullable().optional(),
    openrouter_x_title: z.string().trim().min(1).nullable().optional(),
    cloudflare_ai_gateway: z.unknown().nullable().optional(),
    enabled: z.boolean().optional(),
  })
  .strict();

const providerUpdateSchema = providerCreateSchema.partial();

const providerConnectivitySchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("models") }).strict(),
  z
    .object({
      action: z.literal("chat"),
      model: z.string().trim().min(1),
      protocol: z.enum(["responses", "chat.completions"]).default("chat.completions"),
    })
    .strict(),
]);

const modelCreateSchema = z
  .object({
    id: z.string().trim().min(1).optional(),
    tenant_id: z.string().trim().min(1).optional(),
    name: z.string().trim().min(1),
    family: z.string().trim().min(1).nullable().optional(),
    owned_by: z.string().trim().min(1).nullable().optional(),
    capabilities: z.array(z.string().trim().min(1)).optional(),
    context_window: z.number().int().positive().nullable().optional(),
    routing_strategy: z.enum(["priority", "lowest_cost", "lowest_latency", "balanced"]).optional(),
    enabled: z.boolean().optional(),
  })
  .strict();

const modelUpdateSchema = modelCreateSchema.partial();

const offeringCreateSchema = z
  .object({
    id: z.string().trim().min(1).optional(),
    tenant_id: z.string().trim().min(1).optional(),
    provider_id: z.string().trim().min(1),
    upstream_model_id: z.string().trim().min(1),
    role: z.enum(["primary", "fallback", "canary", "shadow"]).optional(),
    priority: z.number().int().min(0).optional(),
    weight: z.number().int().min(0).optional(),
    canary_percent: z.number().int().min(0).max(100).nullable().optional(),
    shadow_percent: z.number().int().min(0).max(100).nullable().optional(),
    shadow_max_requests: z.number().int().min(0).nullable().optional(),
    capabilities: z.array(z.string().trim().min(1)).nullable().optional(),
    context_window: z.number().int().positive().nullable().optional(),
    region: z.string().trim().min(1).nullable().optional(),
    zero_data_retention: z.boolean().nullable().optional(),
    input_price_per_1m: z.number().nonnegative().nullable().optional(),
    output_price_per_1m: z.number().nonnegative().nullable().optional(),
    cached_input_price_per_1m: z.number().nonnegative().nullable().optional(),
    cache_write_price_per_1m: z.number().nonnegative().nullable().optional(),
    reasoning_price_per_1m: z.number().nonnegative().nullable().optional(),
    audio_second_price_per_1m: z.number().nonnegative().nullable().optional(),
    audio_character_price_per_1m: z.number().nonnegative().nullable().optional(),
    currency: z.string().trim().min(1).optional(),
    source: z.string().trim().min(1).optional(),
    enabled: z.boolean().optional(),
  })
  .strict();

const offeringUpdateSchema = offeringCreateSchema.partial();

type Body = Record<string, unknown>;

function asBody(value: unknown): Body {
  return value as Body;
}

function inputTenant(body: Body): string | null {
  const value = body.tenant_id;
  return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
}

/**
 * Which catalog one request addresses (#889).
 *
 * The same operation ids serve two stores now, so every handler resolves this
 * first and every response carries `scope` — a 2xx whose meaning depends on
 * which credential asked is not a contract.
 */
type CatalogScope =
  | { readonly kind: "platform" }
  | { readonly kind: "tenant"; readonly tenantId: string };

/**
 * A tenant-scoped caller can NEVER reach the platform catalog: the fence below
 * returns before the platform branch is considered, and it returns 404 rather
 * than 403 for a foreign tenant id so a probe cannot distinguish "not yours"
 * from "does not exist". A platform operator that names no tenant used to get
 * `400 tenant_id is required`; that request now addresses the platform catalog
 * — but only once the deployment has adopted one, which is what
 * `platformCatalogAdopted` decides. This function reports the INTENT; it does
 * not know whether there is a platform catalog to serve it.
 */
function targetScope(c: Parameters<Handler>[0], body?: Body): CatalogScope {
  const scope = scopeOf(c);
  const queryTenant = new URL(c.req.url).searchParams.get("tenant_id")?.trim() ?? null;
  const bodyTenant = inputTenant(body ?? {});
  if (scope.kind === "tenant") {
    if (
      (bodyTenant !== null && bodyTenant !== scope.tenantId) ||
      (queryTenant !== null && queryTenant !== "" && queryTenant !== scope.tenantId)
    ) {
      throw new HttpError(404, "not_found", "catalog item not found");
    }
    return { kind: "tenant", tenantId: scope.tenantId };
  }
  if (
    bodyTenant !== null &&
    queryTenant !== null &&
    queryTenant !== "" &&
    bodyTenant !== queryTenant
  ) {
    throw new HttpError(400, "invalid_request", "tenant_id query and body values must match");
  }
  const selected = bodyTenant ?? (queryTenant ? queryTenant : null);
  return selected === null ? { kind: "platform" } : { kind: "tenant", tenantId: selected };
}

/** Attach the `scope` discriminator to any catalog response body. */
function scoped(body: object, target: CatalogScope): Record<string, unknown> {
  return { ...body, scope: target.kind };
}

async function listTenants(c: Parameters<Handler>[0]): Promise<readonly string[]> {
  const scope = scopeOf(c);
  const selected = new URL(c.req.url).searchParams.get("tenant_id")?.trim();
  if (scope.kind === "tenant") {
    if (selected !== undefined && selected !== "" && selected !== scope.tenantId) {
      throw new HttpError(404, "not_found", "catalog item not found");
    }
    return [scope.tenantId];
  }
  if (selected) return [selected];
  return depsOf(c).tenantDatabases.provisionedTenants();
}

async function legacyWhenNoCatalog(
  c: Parameters<Handler>[0],
  collection: string,
  scope = scopeOf(c),
): Promise<Response> {
  if ((await depsOf(c).tenantDatabases.provisionedTenants()).length === 0) {
    return legacyList(c, collection, scope);
  }
  throw new HttpError(
    503,
    "tenant_database_unavailable",
    "one or more requested tenants have no provisioned catalog database",
  );
}

async function catalogStore(
  c: Parameters<Handler>[0],
  tenantId: string,
): Promise<TenantModelCatalogStore> {
  const store = await optionalCatalogStore(c, tenantId);
  if (store !== null) return store;
  throw new HttpError(
    503,
    "tenant_database_unavailable",
    `tenant ${tenantId} has no provisioned catalog database`,
  );
}

/**
 * The platform catalog store, over the CONTROL_DATA facade.
 *
 * `deps.controlDatabase` IS that facade (`control-data.ts::controlDatabaseFrom`
 * resolves the Durable Object handle when the posture says so, the legacy D1
 * binding otherwise), so there is deliberately no second resolver here and no
 * reference to `env.DB`.
 */
function platformCatalogStore(c: Parameters<Handler>[0]): PlatformModelCatalogStore {
  const deps = depsOf(c);
  if (deps.controlDatabase === null) {
    throw new HttpError(
      503,
      "control_database_unavailable",
      "control database is required for the platform catalog",
    );
  }
  return new PlatformModelCatalogStore({
    db: deps.controlDatabase,
    requestId: c.get("requestId") ?? null,
  });
}

/**
 * Does a platform operator that named no tenant mean the platform catalog?
 *
 * ONE predicate for every catalog operation, LIST and item alike, because the
 * alternative is incoherent: decided per resource, a session can be shown the
 * platform provider list and the tenant-aggregate model list at the same time,
 * and posting an offering that binds one to the other 404s.
 *
 * The tie-break is `PlatformModelCatalogStore.isAdopted()` — has anything ever
 * been written to the platform catalog — and not "does it have rows right now",
 * so emptying the catalog on purpose does not silently revert the whole surface
 * to tenant semantics. What it buys is that a deployment which has NOT adopted
 * it behaves exactly as it did before #889:
 *
 *  - LIST keeps the per-tenant aggregate (or the legacy document collection),
 *    both of which an operator may depend on and neither of which is reachable
 *    any other way: `filterAndList` drops the `tenant_id` filter and there is
 *    no "all tenants" tenant id;
 *  - the 15 ITEM operations keep answering `400 tenant_id is required`. That
 *    400 matters more than it looks: `404` on a DELETE is the canonical
 *    "already gone", so redirecting an un-adopted deployment's item operations
 *    here would turn a cleanup script that forgot `tenant_id` from loudly
 *    broken into silently reporting every tenant provider as deleted.
 *
 * Once a deployment HAS adopted the catalog, an id with no `tenant_id` is a
 * platform id and `404` is the honest answer for one that is not there; that
 * residual change of meaning is the feature, and `scope` on every 2xx says
 * which store answered.
 */
async function platformCatalogAdopted(c: Parameters<Handler>[0]): Promise<boolean> {
  if (depsOf(c).controlDatabase === null) return false;
  return platformCatalogStore(c).isAdopted();
}

/** The platform rows a LIST should serve, or `null` to keep the pre-#889 answer. */
async function platformRowsForList(
  c: Parameters<Handler>[0],
  target: CatalogScope,
  read: (store: PlatformModelCatalogStore) => Promise<readonly StoreRecord[]>,
): Promise<readonly StoreRecord[] | null> {
  if (target.kind !== "platform" || !(await platformCatalogAdopted(c))) return null;
  return read(platformCatalogStore(c));
}

/**
 * The platform store for an ITEM operation, or the pre-#889 400.
 *
 * Creating the FIRST platform provider or model is what adoption IS, so those
 * two go straight to `platformCatalogStore`; everything else — including
 * creating an offering, which needs a platform model to hang off — is gated.
 */
async function platformItemStore(c: Parameters<Handler>[0]): Promise<PlatformModelCatalogStore> {
  if (!(await platformCatalogAdopted(c))) {
    throw new HttpError(400, "invalid_request", "tenant_id is required for a platform operator");
  }
  return platformCatalogStore(c);
}

async function optionalCatalogStore(
  c: Parameters<Handler>[0],
  tenantId: string,
): Promise<TenantModelCatalogStore | null> {
  const deps = depsOf(c);
  const handle = await tenantDatabaseFor(deps.tenantDatabases, tenantId);
  if (handle === null) return null;
  if (deps.controlDatabase === null) {
    throw new HttpError(
      503,
      "control_database_unavailable",
      "control database is required for catalog audit",
    );
  }
  return new TenantModelCatalogStore({
    db: handle.db,
    controlDatabase: deps.controlDatabase,
    requestId: c.get("requestId") ?? null,
  });
}

/**
 * The pre-catalog document collection.
 *
 * `scope` is taken from the scope the DOCUMENTS were read at, not stamped as a
 * constant: `deps.store.list` filters to one tenant for a tenant-scoped read,
 * but a platform operator's read is the un-attributed platform-wide view of the
 * collection, and labelling that `tenant` would attribute rows to a tenant the
 * response cannot name.
 */
async function legacyList(
  c: Parameters<Handler>[0],
  collection: string,
  scope = scopeOf(c),
): Promise<Response> {
  const deps = depsOf(c);
  const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
  const page = await deps.store.list(collection, scope, query);
  const target: CatalogScope =
    scope.kind === "tenant" ? { kind: "tenant", tenantId: scope.tenantId } : { kind: "platform" };
  return json(c, 200, scoped(listResponse(page, query), target));
}

function catalogHandler(handler: Handler): Handler {
  return async (c) => {
    try {
      return await handler(c);
    } catch (error) {
      // Migration 0025 not applied yet. Reads degrade to the pre-#889 answer in
      // `platformCatalogAdopted`; a WRITE cannot, and "not deployed yet" is a
      // 503 an operator can retry, not a 500 that reads as a bug.
      if (isMissingPlatformCatalogError(error)) {
        throw new HttpError(
          503,
          "control_database_unavailable",
          "the platform model catalog schema is not applied to the control database yet",
        );
      }
      if (error instanceof TenantCatalogNotFoundError) {
        throw new HttpError(404, "not_found", error.message);
      }
      if (error instanceof TenantCatalogConflictError) {
        throw new HttpError(409, "catalog_conflict", error.message);
      }
      if (error instanceof TenantCatalogValidationError) {
        throw new HttpError(400, "invalid_request_body", error.message);
      }
      throw error;
    }
  };
}

function filterAndList(
  c: Parameters<Handler>[0],
  records: readonly StoreRecord[],
  target: CatalogScope,
): Response {
  const query = parseListQuery(
    new URL(c.req.url),
    depsOf(c).listDefaultLimit,
    depsOf(c).listMaxLimit,
  );
  const { tenant_id: _tenantFilter, ...filters } = query.filters;
  const filtered = records.filter(
    (record) => matchesSearch(record, query.search) && matchesFilters(record, filters),
  );
  const page = query.paginate ? filtered.slice(query.offset, query.offset + query.limit) : filtered;
  return json(c, 200, scoped(listResponse({ items: page, total: filtered.length }, query), target));
}

function providerInput(body: Body, id: string): ProviderChannelInput {
  return {
    id,
    name: body.name as string,
    provider_type_id: body.provider_type_id as string | undefined,
    kind: body.kind as string,
    base_url: body.base_url as string,
    api_key_var: body.api_key_var as string | null | undefined,
    byok_alias: body.byok_alias as string | null | undefined,
    auth_scheme: body.auth_scheme as "bearer" | "x-api-key" | null | undefined,
    region: body.region as string | null | undefined,
    zero_data_retention: body.zero_data_retention as boolean | null | undefined,
    openrouter_http_referer: body.openrouter_http_referer as string | null | undefined,
    openrouter_x_title: body.openrouter_x_title as string | null | undefined,
    cloudflare_ai_gateway: body.cloudflare_ai_gateway,
    enabled: body.enabled as boolean | undefined,
  };
}

function modelInput(body: Body, id: string): ModelCatalogInput {
  return {
    id,
    name: body.name as string,
    family: body.family as string | null | undefined,
    owned_by: body.owned_by as string | null | undefined,
    capabilities: body.capabilities as readonly string[] | undefined,
    context_window: body.context_window as number | null | undefined,
    routing_strategy: body.routing_strategy as ModelCatalogInput["routing_strategy"],
    enabled: body.enabled as boolean | undefined,
  };
}

function offeringInput(body: Body, id: string): ModelOfferingInput {
  return {
    id,
    provider_id: body.provider_id as string,
    upstream_model_id: body.upstream_model_id as string,
    role: body.role as ModelOfferingInput["role"],
    priority: body.priority as number | undefined,
    weight: body.weight as number | undefined,
    canary_percent: body.canary_percent as number | null | undefined,
    shadow_percent: body.shadow_percent as number | null | undefined,
    shadow_max_requests: body.shadow_max_requests as number | null | undefined,
    capabilities: body.capabilities as readonly string[] | null | undefined,
    context_window: body.context_window as number | null | undefined,
    region: body.region as string | null | undefined,
    zero_data_retention: body.zero_data_retention as boolean | null | undefined,
    input_price_per_1m: body.input_price_per_1m as number | null | undefined,
    output_price_per_1m: body.output_price_per_1m as number | null | undefined,
    cached_input_price_per_1m: body.cached_input_price_per_1m as number | null | undefined,
    cache_write_price_per_1m: body.cache_write_price_per_1m as number | null | undefined,
    reasoning_price_per_1m: body.reasoning_price_per_1m as number | null | undefined,
    audio_second_price_per_1m: body.audio_second_price_per_1m as number | null | undefined,
    audio_character_price_per_1m: body.audio_character_price_per_1m as number | null | undefined,
    currency: body.currency as string | undefined,
    source: body.source as string | undefined,
    enabled: body.enabled as boolean | undefined,
  };
}

async function providerList(c: Parameters<Handler>[0]): Promise<Response> {
  const target = targetScope(c);
  const platformRows = await platformRowsForList(c, target, (store) => store.listProviders());
  if (platformRows !== null) return filterAndList(c, platformRows, target);
  const tenantIds = await listTenants(c);
  if (tenantIds.length === 0) return legacyList(c, "providers");
  const rows: StoreRecord[] = [];
  for (const tenantId of tenantIds) {
    const store = await optionalCatalogStore(c, tenantId);
    if (store === null) {
      return legacyWhenNoCatalog(c, "providers", { kind: "tenant", tenantId });
    }
    rows.push(...(await store.listProviders(tenantId)));
  }
  return filterAndList(c, rows, { kind: "tenant", tenantId: tenantIds[0] ?? "" });
}

async function providerCreate(c: Parameters<Handler>[0]): Promise<Response> {
  const body = asBody(await readJson(c, providerCreateSchema));
  const target = targetScope(c, body);
  const id = (body.id as string | undefined) ?? crypto.randomUUID();
  const record =
    target.kind === "platform"
      ? await platformCatalogStore(c).createProvider(scopeOf(c), providerInput(body, id))
      : await (await catalogStore(c, target.tenantId)).createProvider(
          target.tenantId,
          scopeOf(c),
          providerInput(body, id),
        );
  return json(c, 201, scoped(adminItem("provider", record), target));
}

async function providerRead(c: Parameters<Handler>[0]): Promise<Response> {
  const target = targetScope(c);
  const id = pathParam(c, "id");
  const record =
    target.kind === "platform"
      ? await (await platformItemStore(c)).getProvider(id)
      : await (await catalogStore(c, target.tenantId)).getProvider(target.tenantId, id);
  if (record === null) throw new TenantCatalogNotFoundError(`provider ${id} not found`);
  return json(c, 200, scoped(adminItem("provider", record), target));
}

async function providerUpdate(
  c: Parameters<Handler>[0],
  action: "replace" | "merge",
): Promise<Response> {
  const body = asBody(
    await readJson(c, action === "replace" ? providerCreateSchema : providerUpdateSchema),
  );
  const target = targetScope(c, body);
  const id = pathParam(c, "id");
  const input = body as Partial<ProviderChannelInput>;
  const record =
    target.kind === "platform"
      ? await (await platformItemStore(c)).updateProvider(scopeOf(c), id, input, action)
      : await (await catalogStore(c, target.tenantId)).updateProvider(
          target.tenantId,
          scopeOf(c),
          id,
          input,
          action,
        );
  if (record === null) throw new TenantCatalogNotFoundError(`provider ${id} not found`);
  return json(c, 200, scoped(adminItem("provider", record), target));
}

async function providerDelete(c: Parameters<Handler>[0]): Promise<Response> {
  const target = targetScope(c);
  const id = pathParam(c, "id");
  const deleted =
    target.kind === "platform"
      ? await (await platformItemStore(c)).deleteProvider(scopeOf(c), id)
      : await (await catalogStore(c, target.tenantId)).deleteProvider(
          target.tenantId,
          scopeOf(c),
          id,
        );
  if (!deleted) throw new TenantCatalogNotFoundError(`provider ${id} not found`);
  return json(c, 200, scoped(adminDeleted("provider", id), target));
}

async function modelList(c: Parameters<Handler>[0]): Promise<Response> {
  const target = targetScope(c);
  const platformRows = await platformRowsForList(c, target, (store) => store.listModels());
  if (platformRows !== null) return filterAndList(c, platformRows, target);
  const tenantIds = await listTenants(c);
  if (tenantIds.length === 0) return legacyList(c, "models");
  const rows: StoreRecord[] = [];
  for (const tenantId of tenantIds) {
    const store = await optionalCatalogStore(c, tenantId);
    if (store === null) {
      return legacyWhenNoCatalog(c, "models", { kind: "tenant", tenantId });
    }
    rows.push(...(await store.listModels(tenantId)));
  }
  return filterAndList(c, rows, { kind: "tenant", tenantId: tenantIds[0] ?? "" });
}

async function modelCreate(c: Parameters<Handler>[0]): Promise<Response> {
  const body = asBody(await readJson(c, modelCreateSchema));
  const target = targetScope(c, body);
  const id = (body.id as string | undefined) ?? crypto.randomUUID();
  const record =
    target.kind === "platform"
      ? await platformCatalogStore(c).createModel(scopeOf(c), modelInput(body, id))
      : await (await catalogStore(c, target.tenantId)).createModel(
          target.tenantId,
          scopeOf(c),
          modelInput(body, id),
        );
  return json(c, 201, scoped(adminItem("model", record), target));
}

async function modelRead(c: Parameters<Handler>[0]): Promise<Response> {
  const target = targetScope(c);
  const id = pathParam(c, "id");
  const record =
    target.kind === "platform"
      ? await (await platformItemStore(c)).getModel(id)
      : await (await catalogStore(c, target.tenantId)).getModel(target.tenantId, id);
  if (record === null) throw new TenantCatalogNotFoundError(`model ${id} not found`);
  return json(c, 200, scoped(adminItem("model", record), target));
}

async function modelUpdate(
  c: Parameters<Handler>[0],
  action: "replace" | "merge",
): Promise<Response> {
  const body = asBody(
    await readJson(c, action === "replace" ? modelCreateSchema : modelUpdateSchema),
  );
  const target = targetScope(c, body);
  const id = pathParam(c, "id");
  const input = body as Partial<ModelCatalogInput>;
  const record =
    target.kind === "platform"
      ? await (await platformItemStore(c)).updateModel(scopeOf(c), id, input, action)
      : await (await catalogStore(c, target.tenantId)).updateModel(
          target.tenantId,
          scopeOf(c),
          id,
          input,
          action,
        );
  if (record === null) throw new TenantCatalogNotFoundError(`model ${id} not found`);
  return json(c, 200, scoped(adminItem("model", record), target));
}

async function modelDelete(c: Parameters<Handler>[0]): Promise<Response> {
  const target = targetScope(c);
  const id = pathParam(c, "id");
  const deleted =
    target.kind === "platform"
      ? await (await platformItemStore(c)).deleteModel(scopeOf(c), id)
      : await (await catalogStore(c, target.tenantId)).deleteModel(target.tenantId, scopeOf(c), id);
  if (!deleted) throw new TenantCatalogNotFoundError(`model ${id} not found`);
  return json(c, 200, scoped(adminDeleted("model", id), target));
}

async function offeringList(c: Parameters<Handler>[0]): Promise<Response> {
  const target = targetScope(c);
  const modelId = pathParam(c, "model_id");
  const rows =
    target.kind === "platform"
      ? await (await platformItemStore(c)).listOfferings(modelId)
      : await (await catalogStore(c, target.tenantId)).listOfferings(target.tenantId, modelId);
  return filterAndList(c, rows, target);
}

async function offeringRead(c: Parameters<Handler>[0]): Promise<Response> {
  const target = targetScope(c);
  const modelId = pathParam(c, "model_id");
  const id = pathParam(c, "offering_id");
  const record =
    target.kind === "platform"
      ? await (await platformItemStore(c)).getOffering(modelId, id)
      : await (await catalogStore(c, target.tenantId)).getOffering(target.tenantId, modelId, id);
  if (record === null) throw new TenantCatalogNotFoundError(`offering ${id} not found`);
  return json(c, 200, scoped(adminItem("offering", record), target));
}

async function offeringCreate(c: Parameters<Handler>[0]): Promise<Response> {
  const body = asBody(await readJson(c, offeringCreateSchema));
  const target = targetScope(c, body);
  const modelId = pathParam(c, "model_id");
  const id = (body.id as string | undefined) ?? crypto.randomUUID();
  const record =
    target.kind === "platform"
      ? await (await platformItemStore(c)).createOffering(
          scopeOf(c),
          modelId,
          offeringInput(body, id),
        )
      : await (await catalogStore(c, target.tenantId)).createOffering(
          target.tenantId,
          scopeOf(c),
          modelId,
          offeringInput(body, id),
        );
  return json(c, 201, scoped(adminItem("offering", record), target));
}

async function offeringUpdate(
  c: Parameters<Handler>[0],
  action: "replace" | "merge",
): Promise<Response> {
  const body = asBody(
    await readJson(c, action === "replace" ? offeringCreateSchema : offeringUpdateSchema),
  );
  const target = targetScope(c, body);
  const modelId = pathParam(c, "model_id");
  const id = pathParam(c, "offering_id");
  const input = body as Partial<ModelOfferingInput>;
  const record =
    target.kind === "platform"
      ? await (await platformItemStore(c)).updateOffering(scopeOf(c), modelId, id, input, action)
      : await (await catalogStore(c, target.tenantId)).updateOffering(
          target.tenantId,
          scopeOf(c),
          modelId,
          id,
          input,
          action,
        );
  if (record === null) throw new TenantCatalogNotFoundError(`offering ${id} not found`);
  return json(c, 200, scoped(adminItem("offering", record), target));
}

async function offeringDelete(c: Parameters<Handler>[0]): Promise<Response> {
  const target = targetScope(c);
  const modelId = pathParam(c, "model_id");
  const id = pathParam(c, "offering_id");
  const deleted =
    target.kind === "platform"
      ? await (await platformItemStore(c)).deleteOffering(scopeOf(c), modelId, id)
      : await (await catalogStore(c, target.tenantId)).deleteOffering(
          target.tenantId,
          scopeOf(c),
          modelId,
          id,
        );
  if (!deleted) throw new TenantCatalogNotFoundError(`offering ${id} not found`);
  return json(c, 200, scoped(adminDeleted("offering", id), target));
}

/**
 * `POST /admin/v1/providers/{id}/sync-models` — import a platform provider's
 * live model list into the platform catalog (#944).
 *
 * PLATFORM-OPERATOR ONLY, on the same reasoning as {@link importModelCatalog}
 * and {@link setAdminDrain}: the platform catalog is deployment-wide state a
 * tenant credential must never write, so a non-platform caller is
 * `403 tenant_scope_denied` and never reaches the provider row, the upstream
 * fetch, or the store. The fence returns before {@link platformCatalogStore},
 * which is why the 403 probe writes nothing.
 *
 * The provider is read RAW ({@link PlatformModelCatalogStore.getProviderSeed})
 * so `api_key_var` survives the admin projection, then resolved through the SAME
 * outbound credential seam the data plane uses ({@link resolveProviderSecret});
 * a channel with no `api_key_var` syncs unauthenticated. A credential named but
 * unbound FAILS CLOSED (`502`) rather than syncing with an empty header — the
 * fail-closed rule `provider-secrets.ts` exists to hold.
 */
async function providerSyncModels(c: Parameters<Handler>[0]): Promise<Response> {
  const scope = scopeOf(c);
  if (scope.kind !== "platform_operator") {
    throw new HttpError(
      403,
      "tenant_scope_denied",
      "the platform model catalog is deployment-wide state; a tenant-scoped credential cannot sync a provider's models",
    );
  }
  const id = pathParam(c, "id");
  const store = platformCatalogStore(c);
  const provider = await store.getProviderSeed(id);
  if (provider === null) throw new TenantCatalogNotFoundError(`provider ${id} not found`);

  const apiKey = providerApiKey(c, provider);

  let result: Awaited<ReturnType<typeof syncProviderModelsIntoCatalog>>;
  try {
    result = await syncProviderModelsIntoCatalog({
      store,
      scope,
      provider,
      apiKey,
      priceBook: PriceBook.withDefaultRateCard(),
      fetchImpl: fetch,
    });
  } catch (error) {
    if (error instanceof ProviderModelSyncError) {
      throw new HttpError(error.status, error.code, error.message);
    }
    throw error;
  }

  return json(c, 200, {
    object: "provider_model_sync",
    scope: "platform",
    provider_id: id,
    added: result.added,
    updated: result.updated,
    skipped: result.skipped,
    upstream_count: result.upstreamCount,
    revision: result.revision,
  });
}

function providerApiKey(
  c: Parameters<Handler>[0],
  provider: SeedProviderChannel,
): string | undefined {
  if (provider.api_key_var === null || provider.api_key_var === undefined) return undefined;
  const resolution = resolveProviderSecret(
    c.env as unknown as Readonly<Record<string, unknown>>,
    provider.api_key_var,
  );
  if (!resolution.ok) {
    throw new HttpError(
      502,
      "provider_credential_unresolved",
      providerSecretRefusal(provider.name, "api_key_var", provider.api_key_var, resolution),
    );
  }
  return resolution.value;
}

/** List live models or send a fixed `hi` through one platform provider. */
async function providerConnectivity(c: Parameters<Handler>[0]): Promise<Response> {
  const scope = scopeOf(c);
  if (scope.kind !== "platform_operator") {
    throw new HttpError(
      403,
      "tenant_scope_denied",
      "provider connectivity tests require a platform operator",
    );
  }
  const body = await readJson(c, providerConnectivitySchema);
  const id = pathParam(c, "id");
  const provider = await platformCatalogStore(c).getProviderSeed(id);
  if (provider === null) throw new TenantCatalogNotFoundError(`provider ${id} not found`);
  const apiKey = providerApiKey(c, provider);

  try {
    if (body.action === "models") {
      const models = await listProviderConnectivityModels({ provider, apiKey, fetchImpl: fetch });
      return json(c, 200, {
        object: "provider_connectivity_models",
        scope: "platform",
        provider_id: id,
        models,
      });
    }
    const result = await testProviderConnectivity({
      provider,
      apiKey,
      model: body.model,
      protocol: body.protocol,
      fetchImpl: fetch,
    });
    return json(c, 200, {
      object: "provider_connectivity_test",
      scope: "platform",
      provider_id: id,
      ok: true,
      model: result.model,
      protocol: result.protocol,
      latency_ms: result.latencyMs,
      upstream_status: result.status,
      answer: result.answer,
      response: result.response,
    });
  } catch (error) {
    if (error instanceof ProviderConnectivityError || error instanceof ProviderModelSyncError) {
      throw new HttpError(error.status, error.code, error.message);
    }
    throw error;
  }
}

function wrapped(handler: Handler): Handler {
  return catalogHandler(handler);
}

export function providerCatalogOverrides(): Readonly<Record<string, Handler>> {
  return {
    listAdminProviders: wrapped(providerList),
    createAdminProvider: wrapped(providerCreate),
    getAdminProvider: wrapped(providerRead),
    replaceAdminProvider: wrapped((c) => providerUpdate(c, "replace")),
    patchAdminProvider: wrapped((c) => providerUpdate(c, "merge")),
    deleteAdminProvider: wrapped(providerDelete),
    syncProviderModels: wrapped(providerSyncModels),
    testProviderConnectivity: wrapped(providerConnectivity),
  };
}

export function modelCatalogOverrides(): Readonly<Record<string, Handler>> {
  return {
    listAdminModels: wrapped(modelList),
    createAdminModel: wrapped(modelCreate),
    getAdminModel: wrapped(modelRead),
    replaceAdminModel: wrapped((c) => modelUpdate(c, "replace")),
    patchAdminModel: wrapped((c) => modelUpdate(c, "merge")),
    deleteAdminModel: wrapped(modelDelete),
    listAdminModelOfferings: wrapped(offeringList),
    createAdminModelOffering: wrapped(offeringCreate),
    getAdminModelOffering: wrapped(offeringRead),
    replaceAdminModelOffering: wrapped((c) => offeringUpdate(c, "replace")),
    patchAdminModelOffering: wrapped((c) => offeringUpdate(c, "merge")),
    deleteAdminModelOffering: wrapped(offeringDelete),
  };
}
