import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import type { StoreRecord } from "../ports.js";
import { adminDeleted, adminItem, listResponse, parseListQuery } from "../responses.js";
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

function targetTenant(c: Parameters<Handler>[0], body?: Body): string {
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
    return scope.tenantId;
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
  if (selected === null) {
    throw new HttpError(400, "invalid_request", "tenant_id is required for a platform operator");
  }
  return selected;
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

async function legacyList(
  c: Parameters<Handler>[0],
  collection: string,
  scope = scopeOf(c),
): Promise<Response> {
  const deps = depsOf(c);
  const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
  const page = await deps.store.list(collection, scope, query);
  return json(c, 200, listResponse(page, query));
}

function catalogHandler(handler: Handler): Handler {
  return async (c) => {
    try {
      return await handler(c);
    } catch (error) {
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

function filterAndList(c: Parameters<Handler>[0], records: readonly StoreRecord[]): Response {
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
  return json(c, 200, listResponse({ items: page, total: filtered.length }, query));
}

function providerInput(body: Body, id: string): ProviderChannelInput {
  return {
    id,
    name: body.name as string,
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
  return filterAndList(c, rows);
}

async function providerCreate(c: Parameters<Handler>[0]): Promise<Response> {
  const body = asBody(await readJson(c, providerCreateSchema));
  const tenantId = targetTenant(c, body);
  const id = (body.id as string | undefined) ?? crypto.randomUUID();
  const record = await (await catalogStore(c, tenantId)).createProvider(
    tenantId,
    scopeOf(c),
    providerInput(body, id),
  );
  return json(c, 201, adminItem("provider", record));
}

async function providerRead(c: Parameters<Handler>[0]): Promise<Response> {
  const tenantId = targetTenant(c);
  const id = pathParam(c, "id");
  const record = await (await catalogStore(c, tenantId)).getProvider(tenantId, id);
  if (record === null) throw new TenantCatalogNotFoundError(`provider ${id} not found`);
  return json(c, 200, adminItem("provider", record));
}

async function providerUpdate(
  c: Parameters<Handler>[0],
  action: "replace" | "merge",
): Promise<Response> {
  const body = asBody(
    await readJson(c, action === "replace" ? providerCreateSchema : providerUpdateSchema),
  );
  const tenantId = targetTenant(c, body);
  const id = pathParam(c, "id");
  const record = await (await catalogStore(c, tenantId)).updateProvider(
    tenantId,
    scopeOf(c),
    id,
    body as Partial<ProviderChannelInput>,
    action,
  );
  if (record === null) throw new TenantCatalogNotFoundError(`provider ${id} not found`);
  return json(c, 200, adminItem("provider", record));
}

async function providerDelete(c: Parameters<Handler>[0]): Promise<Response> {
  const tenantId = targetTenant(c);
  const id = pathParam(c, "id");
  if (!(await (await catalogStore(c, tenantId)).deleteProvider(tenantId, scopeOf(c), id))) {
    throw new TenantCatalogNotFoundError(`provider ${id} not found`);
  }
  return json(c, 200, adminDeleted("provider", id));
}

async function modelList(c: Parameters<Handler>[0]): Promise<Response> {
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
  return filterAndList(c, rows);
}

async function modelCreate(c: Parameters<Handler>[0]): Promise<Response> {
  const body = asBody(await readJson(c, modelCreateSchema));
  const tenantId = targetTenant(c, body);
  const id = (body.id as string | undefined) ?? crypto.randomUUID();
  const record = await (await catalogStore(c, tenantId)).createModel(
    tenantId,
    scopeOf(c),
    modelInput(body, id),
  );
  return json(c, 201, adminItem("model", record));
}

async function modelRead(c: Parameters<Handler>[0]): Promise<Response> {
  const tenantId = targetTenant(c);
  const id = pathParam(c, "id");
  const record = await (await catalogStore(c, tenantId)).getModel(tenantId, id);
  if (record === null) throw new TenantCatalogNotFoundError(`model ${id} not found`);
  return json(c, 200, adminItem("model", record));
}

async function modelUpdate(
  c: Parameters<Handler>[0],
  action: "replace" | "merge",
): Promise<Response> {
  const body = asBody(
    await readJson(c, action === "replace" ? modelCreateSchema : modelUpdateSchema),
  );
  const tenantId = targetTenant(c, body);
  const id = pathParam(c, "id");
  const record = await (await catalogStore(c, tenantId)).updateModel(
    tenantId,
    scopeOf(c),
    id,
    body as Partial<ModelCatalogInput>,
    action,
  );
  if (record === null) throw new TenantCatalogNotFoundError(`model ${id} not found`);
  return json(c, 200, adminItem("model", record));
}

async function modelDelete(c: Parameters<Handler>[0]): Promise<Response> {
  const tenantId = targetTenant(c);
  const id = pathParam(c, "id");
  if (!(await (await catalogStore(c, tenantId)).deleteModel(tenantId, scopeOf(c), id))) {
    throw new TenantCatalogNotFoundError(`model ${id} not found`);
  }
  return json(c, 200, adminDeleted("model", id));
}

async function offeringList(c: Parameters<Handler>[0]): Promise<Response> {
  const tenantId = targetTenant(c);
  const modelId = pathParam(c, "model_id");
  const rows = await (await catalogStore(c, tenantId)).listOfferings(tenantId, modelId);
  return filterAndList(c, rows);
}

async function offeringRead(c: Parameters<Handler>[0]): Promise<Response> {
  const tenantId = targetTenant(c);
  const modelId = pathParam(c, "model_id");
  const id = pathParam(c, "offering_id");
  const record = await (await catalogStore(c, tenantId)).getOffering(tenantId, modelId, id);
  if (record === null) throw new TenantCatalogNotFoundError(`offering ${id} not found`);
  return json(c, 200, adminItem("offering", record));
}

async function offeringCreate(c: Parameters<Handler>[0]): Promise<Response> {
  const body = asBody(await readJson(c, offeringCreateSchema));
  const tenantId = targetTenant(c, body);
  const modelId = pathParam(c, "model_id");
  const id = (body.id as string | undefined) ?? crypto.randomUUID();
  const record = await (await catalogStore(c, tenantId)).createOffering(
    tenantId,
    scopeOf(c),
    modelId,
    offeringInput(body, id),
  );
  return json(c, 201, adminItem("offering", record));
}

async function offeringUpdate(
  c: Parameters<Handler>[0],
  action: "replace" | "merge",
): Promise<Response> {
  const body = asBody(
    await readJson(c, action === "replace" ? offeringCreateSchema : offeringUpdateSchema),
  );
  const tenantId = targetTenant(c, body);
  const modelId = pathParam(c, "model_id");
  const id = pathParam(c, "offering_id");
  const record = await (await catalogStore(c, tenantId)).updateOffering(
    tenantId,
    scopeOf(c),
    modelId,
    id,
    body as Partial<ModelOfferingInput>,
    action,
  );
  if (record === null) throw new TenantCatalogNotFoundError(`offering ${id} not found`);
  return json(c, 200, adminItem("offering", record));
}

async function offeringDelete(c: Parameters<Handler>[0]): Promise<Response> {
  const tenantId = targetTenant(c);
  const modelId = pathParam(c, "model_id");
  const id = pathParam(c, "offering_id");
  if (
    !(await (await catalogStore(c, tenantId)).deleteOffering(tenantId, scopeOf(c), modelId, id))
  ) {
    throw new TenantCatalogNotFoundError(`offering ${id} not found`);
  }
  return json(c, 200, adminDeleted("offering", id));
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
