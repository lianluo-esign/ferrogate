/**
 * Contract group `admin_billing_group` (7 operations) — platform billing groups
 * and their provider bindings (#943, epic #941).
 *
 * ```
 *   GET/POST  /admin/v1/billing-groups
 *   GET/PATCH/DELETE  /admin/v1/billing-groups/{id}
 *   PUT/DELETE  /admin/v1/billing-groups/{id}/providers/{providerId}
 * ```
 *
 * A billing group binds a set of platform provider channels and carries ONE
 * `multiplier`; a served request's consumed price is the provider's official
 * offering price times the multiplier of the group the request's API key is
 * bound to (`api_keys.billing_group_id`, written on the virtual-key path in
 * `admin_virtual_key.ts`). Group ↔ provider is many-to-many.
 *
 * This is a PLATFORM-ONLY surface, modelled on the platform half of
 * `admin_model_catalog.ts`: the store lives in the CONTROL database via
 * {@link PlatformBillingGroupStore} over `deps.controlDatabase`, so a deployment
 * running without a control database answers `503 control_database_unavailable`,
 * and a tenant-scoped caller is fenced with a leak-proof `404` — the same 404 a
 * foreign-tenant catalog id gets, so a probe cannot tell "not yours" from "does
 * not exist".
 *
 * Because billing groups are NOT `control_plane_resources` documents, this group
 * declares NO CRUD collections: all seven operations are explicit `overrides`
 * that talk to the platform store directly. The generic CRUD handlers would
 * write `deps.store` (the document store), which no billing reader consults.
 */
import { DEFAULT_PROVIDER_TYPE_ID, PROVIDER_TYPE_IDS } from "@ferrogate/provider-types";
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import type { CallerScope } from "../ports.js";
import { adminDeleted, adminItem, listResponse, parseListQuery } from "../responses.js";
import {
  type BillingGroupInput,
  type BillingGroupPatch,
  PlatformBillingGroupStore,
} from "../store/platform-billing-group.js";
import { publishPlatformBillingGroupsCache } from "../store/platform-billing-group-cache.js";
import { isMissingPlatformCatalogError } from "../store/platform-model-catalog.js";
import { matchesSearch } from "../store/query.js";
import {
  TenantCatalogConflictError,
  TenantCatalogNotFoundError,
  TenantCatalogValidationError,
} from "../store/tenant-model-catalog.js";
import {
  type GroupModule,
  type Handler,
  crudGroup,
  depsOf,
  json,
  pathParam,
  readJson,
  scopeOf,
} from "./resource.js";

const groupCreateSchema = z
  .object({
    id: z.string().trim().min(1).optional(),
    name: z.string().trim().min(1),
    provider_type_id: z.enum(PROVIDER_TYPE_IDS).default(DEFAULT_PROVIDER_TYPE_ID),
    multiplier: z.number().nonnegative(),
    description: z.string().nullable().optional(),
    enabled: z.boolean().optional(),
  })
  .strict();

const groupPatchSchema = z
  .object({
    name: z.string().trim().min(1).optional(),
    provider_type_id: z.enum(PROVIDER_TYPE_IDS).optional(),
    multiplier: z.number().nonnegative().optional(),
    description: z.string().nullable().optional(),
    enabled: z.boolean().optional(),
  })
  .strict();

/**
 * The platform billing-group store, over the CONTROL_DATA facade.
 *
 * MIRRORS `admin_model_catalog.ts::platformCatalogStore`: `deps.controlDatabase`
 * IS the facade (`control-data.ts::controlDatabaseFrom`), so there is no second
 * resolver and no reference to `env.DB`. `null` is a refusal, not a downgrade —
 * a billing group written only to the document store is a multiplier the gateway
 * settlement path never sees.
 */
function billingGroupStore(c: Parameters<Handler>[0]): PlatformBillingGroupStore {
  const deps = depsOf(c);
  if (deps.controlDatabase === null) {
    throw new HttpError(
      503,
      "control_database_unavailable",
      "control database is required for platform billing groups",
    );
  }
  return new PlatformBillingGroupStore({
    db: deps.controlDatabase,
    requestId: c.get("requestId") ?? null,
  });
}

/**
 * The leak-proof platform fence.
 *
 * A tenant-scoped caller can NEVER reach this surface: it returns `404` rather
 * than `403`, so a probe cannot distinguish "you may not" from "there is no such
 * group". A platform operator falls through and its {@link CallerScope} is handed
 * straight to the store's audit chain.
 */
function platformScope(c: Parameters<Handler>[0]): CallerScope {
  const scope = scopeOf(c);
  if (scope.kind === "tenant") {
    throw new HttpError(404, "not_found", "billing group not found");
  }
  return scope;
}

/**
 * Republish the account-global billing-group snapshot to `PLATFORM_CONFIG` after
 * a committed mutation (#961). This REPLACES the old per-tenant Durable Object
 * fan-out — which serialized an RPC per tenant on the operator's request path and
 * made creating a group slow — with one atomic KV overwrite the gateway money
 * path reads KV-first. Mirrors `admin_model_catalog.ts`'s post-write publish: the
 * D1 mutation is already authoritative, so a failed cache write is logged and
 * left for the scheduled publisher to repair, never surfaced to the operator.
 */
async function propagateBillingGroups(c: Parameters<Handler>[0]): Promise<void> {
  const controlDatabase = depsOf(c).controlDatabase;
  if (controlDatabase === null) return;
  try {
    await publishPlatformBillingGroupsCache({
      db: controlDatabase,
      kv: c.env.PLATFORM_CONFIG,
    });
  } catch (error) {
    console.warn("control-plane: billing-group cache publish failed", {
      request_id: c.get("requestId"),
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

/** Map the store's typed errors onto HTTP, exactly as the catalog handler does. */
function billingGroupHandler(handler: Handler): Handler {
  return async (c) => {
    try {
      return await handler(c);
    } catch (error) {
      // 0028 not applied yet: a WRITE cannot degrade, and "not deployed yet" is a
      // 503 an operator can retry, not a 500 that reads as a bug.
      if (isMissingPlatformCatalogError(error)) {
        throw new HttpError(
          503,
          "control_database_unavailable",
          "the platform billing-group schema is not applied to the control database yet",
        );
      }
      if (error instanceof TenantCatalogNotFoundError) {
        throw new HttpError(404, "not_found", error.message);
      }
      if (error instanceof TenantCatalogConflictError) {
        throw new HttpError(409, "billing_group_conflict", error.message);
      }
      if (error instanceof TenantCatalogValidationError) {
        throw new HttpError(400, "invalid_request_body", error.message);
      }
      throw error;
    }
  };
}

async function listBillingGroups(c: Parameters<Handler>[0]): Promise<Response> {
  platformScope(c);
  const deps = depsOf(c);
  const groups = await billingGroupStore(c).listGroups();
  const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
  // #963 — honor `?search=`/`?q=` like every `pageOf`-backed collection. This handler sliced the
  // raw list, so the parsed needle was silently dropped and a console could only filter by pulling
  // every group down. `matchesSearch` is the same predicate (id/name/description) the document
  // store applies, and the total is post-filter so the page count matches what the caller sees.
  const matched = groups.filter((group) => matchesSearch(group, query.search));
  const page = query.paginate ? matched.slice(query.offset, query.offset + query.limit) : matched;
  return json(c, 200, listResponse({ items: page, total: matched.length }, query));
}

async function createBillingGroup(c: Parameters<Handler>[0]): Promise<Response> {
  const scope = platformScope(c);
  const body = await readJson(c, groupCreateSchema);
  const input: BillingGroupInput = {
    id: body.id ?? crypto.randomUUID(),
    name: body.name,
    provider_type_id: body.provider_type_id,
    multiplier: body.multiplier,
    description: body.description ?? null,
    enabled: body.enabled,
  };
  const record = await billingGroupStore(c).createGroup(scope, input);
  await propagateBillingGroups(c);
  return json(c, 201, adminItem("billing_group", record));
}

async function getBillingGroup(c: Parameters<Handler>[0]): Promise<Response> {
  platformScope(c);
  const id = pathParam(c, "id");
  const record = await billingGroupStore(c).getGroup(id);
  if (record === null) throw new HttpError(404, "not_found", `billing group ${id} not found`);
  return json(c, 200, adminItem("billing_group", record));
}

async function patchBillingGroup(c: Parameters<Handler>[0]): Promise<Response> {
  const scope = platformScope(c);
  const id = pathParam(c, "id");
  const body = await readJson(c, groupPatchSchema);
  const patch: BillingGroupPatch = body;
  const record = await billingGroupStore(c).updateGroup(scope, id, patch);
  await propagateBillingGroups(c);
  return json(c, 200, adminItem("billing_group", record));
}

async function deleteBillingGroup(c: Parameters<Handler>[0]): Promise<Response> {
  const scope = platformScope(c);
  const id = pathParam(c, "id");
  const deleted = await billingGroupStore(c).deleteGroup(scope, id);
  if (!deleted) throw new HttpError(404, "not_found", `billing group ${id} not found`);
  await propagateBillingGroups(c);
  return json(c, 200, adminDeleted("billing_group", id));
}

async function bindBillingGroupProvider(c: Parameters<Handler>[0]): Promise<Response> {
  const scope = platformScope(c);
  const id = pathParam(c, "id");
  const providerId = pathParam(c, "providerId");
  const store = billingGroupStore(c);
  // Idempotent: re-binding an existing edge is a no-op. The store still throws
  // 404 when the group or the provider does not exist, so this cannot manufacture
  // a binding to a phantom provider.
  const changed = await store.bindProvider(scope, id, providerId);
  const record = await store.getGroup(id);
  if (record === null) throw new HttpError(404, "not_found", `billing group ${id} not found`);
  if (changed) await propagateBillingGroups(c);
  return json(c, 200, adminItem("billing_group", record));
}

async function unbindBillingGroupProvider(c: Parameters<Handler>[0]): Promise<Response> {
  const scope = platformScope(c);
  const id = pathParam(c, "id");
  const providerId = pathParam(c, "providerId");
  const store = billingGroupStore(c);
  const removed = await store.unbindProvider(scope, id, providerId);
  if (!removed) {
    throw new HttpError(404, "not_found", `binding ${id}:${providerId} not found`);
  }
  const record = await store.getGroup(id);
  if (record === null) throw new HttpError(404, "not_found", `billing group ${id} not found`);
  await propagateBillingGroups(c);
  return json(c, 200, adminItem("billing_group", record));
}

export const adminBillingGroupRoutes: GroupModule = crudGroup("admin_billing_group", [], {
  listBillingGroups: billingGroupHandler(listBillingGroups),
  createBillingGroup: billingGroupHandler(createBillingGroup),
  getBillingGroup: billingGroupHandler(getBillingGroup),
  patchBillingGroup: billingGroupHandler(patchBillingGroup),
  deleteBillingGroup: billingGroupHandler(deleteBillingGroup),
  bindBillingGroupProvider: billingGroupHandler(bindBillingGroupProvider),
  unbindBillingGroupProvider: billingGroupHandler(unbindBillingGroupProvider),
});
