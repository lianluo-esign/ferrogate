/**
 * Contract group `semantic_cache_policy` (6 operations) — issue #695.
 *
 * ```
 *   GET/POST                 /admin/v1/semantic-cache-policies
 *   GET/PUT/DELETE           /admin/v1/semantic-cache-policies/{scope_type}/{scope_id}
 *   POST                     /admin/v1/semantic-cache-policies/{scope_type}/{scope_id}/invalidate
 * ```
 *
 * The admin surface for the response cache. Before it, `[cache]` reached the
 * gateway only as Worker `[vars]`, so enabling semantic caching for one tenant,
 * tuning its similarity threshold, narrowing it to a model set or throwing away
 * what it held all required `wrangler deploy` — a deployment-wide operator
 * action, not a tenant control. `apps/gateway/src/cache/governance.ts` is the
 * reader; `../store/semantic_cache_registry.ts` is the projection.
 *
 * ## The item path is a two-segment composite key, exactly like `quota_policy`
 *
 * A cache policy is identified by what it governs, not by an opaque id, so the
 * shape and the `authorizeScopedResource` ladder are borrowed verbatim from
 * `./quota_policy.ts` — including its fail-closed rule: a scope that is not a
 * bare tenant id must be RESOLVED to its owning tenant before a tenant-scoped
 * caller may touch it, and resolution FAILURE denies. Today `tenant` is the
 * only scope kind, so resolution is the identity and an unknown kind is a 404;
 * the ladder is here because the day a `project` scope lands, forgetting it is
 * a cross-tenant write.
 *
 * ## `PATCH` is deliberately absent
 *
 * `quota_policy` has one and this does not, and the asymmetry is the point.
 * Every column here is a TRI-STATE — `null` means "inherit the deployment
 * value", which is a different thing from any concrete value — and a merge
 * patch has no way to express "set this field back to inherit": omitting a key
 * means "leave it alone" and sending `null` means "clear it", and no
 * JSON-merge-patch reader in this tree distinguishes those from each other
 * reliably. `PUT` states the whole governed policy, so what the operator sent
 * is what the tenant gets, and "unset" is expressible by omission. A `PATCH`
 * that silently could not clear a threshold would leave an operator convinced
 * they had reverted to the default while the old number kept applying.
 *
 * ## Invalidate is a POST that touches the typed row ONLY
 *
 * See `../store/semantic_cache_registry.ts` for why the document is not written
 * on this path. The response reports the epoch now in force, because that is
 * the number an operator needs in order to be able to say the purge landed:
 * every cache key is a function of it, so a bumped epoch IS the purge.
 */
import { z } from "zod";
import { backfillTenantConfigurationPolicy } from "@ferrogate/storage";
import { HttpError } from "../middleware/errors.js";
import { type CallerScope, type ControlPlaneStore, StoreConflictError } from "../ports.js";
import { adminDeleted, adminItem } from "../responses.js";
import {
  type SemanticCacheScopeKind,
  bumpSemanticCacheEpoch,
  deleteSemanticCachePolicyRow,
  projectSemanticCachePolicy,
} from "../store/semantic_cache_registry.js";
import {
  type GroupModule,
  type Handler,
  adminRecordSchema,
  crudGroup,
  depsOf,
  json,
  pathParam,
  readJson,
  scopeOf,
} from "./resource.js";

/** The scope kinds this surface accepts. Mirrors the gateway's reader. */
export const SEMANTIC_CACHE_SCOPE_KINDS = ["tenant"] as const;
export const semanticCacheScopeKindSchema = z.enum(SEMANTIC_CACHE_SCOPE_KINDS);

/**
 * The document body.
 *
 * `.nullish()` throughout rather than `.optional()`: an operator clearing a
 * field by sending `null` is the explicit spelling of "inherit", and refusing
 * it would force them to construct a body by omission, which is exactly the
 * ambiguity the missing `PATCH` avoids.
 */
export const semanticCachePolicySchema = adminRecordSchema.extend({
  scope_type: semanticCacheScopeKindSchema.optional(),
  scope_id: z.string().trim().min(1).optional(),
  enabled: z.boolean().nullish(),
  mode: z.enum(["exact_match", "semantic"]).nullish(),
  similarity_threshold: z.number().gt(0).lte(1).nullish(),
  ttl_seconds: z.number().int().positive().nullish(),
  scoped_models: z.array(z.string()).nullish(),
});

const SEMANTIC_CACHE_POLICIES = "semantic-cache-policies";

/** Composite `(scope_type, scope_id)` flattened to the store's string id. */
export function semanticCachePolicyId(scopeType: string, scopeId: string): string {
  return `${scopeType}:${scopeId}`;
}

/**
 * Collection each scope kind resolves its owning tenant from.
 *
 * `null` means "the scope id IS the tenant id". The table exists so that adding
 * `project` or `workspace` later is a row here plus a scope-kind enum entry,
 * rather than a new authorization path someone has to remember to write.
 */
const SCOPE_COLLECTION: Readonly<Record<SemanticCacheScopeKind, string | null>> = {
  tenant: null,
};

function readScope(c: Parameters<Handler>[0]): {
  scopeType: SemanticCacheScopeKind;
  scopeId: string;
} {
  const parsed = semanticCacheScopeKindSchema.safeParse(pathParam(c, "scope_type"));
  if (!parsed.success) {
    // An unknown scope kind names no resource — 404, like a route miss.
    throw new HttpError(404, "not_found", `no route for ${c.req.method} ${c.req.path}`);
  }
  return { scopeType: parsed.data, scopeId: pathParam(c, "scope_id") };
}

/**
 * Rust `authorize_scoped_resource`. Fails closed: a tenant-scoped caller is
 * denied both when the resolved tenant differs from its own AND when resolution
 * fails entirely. Lifted from `./quota_policy.ts`, which states the reasoning.
 */
async function authorizeScopedResource(
  store: ControlPlaneStore,
  scope: CallerScope,
  scopeType: SemanticCacheScopeKind,
  scopeId: string,
): Promise<void> {
  if (scope.kind === "platform_operator") return;

  let resolvedTenantId: string | null = null;
  const collection = SCOPE_COLLECTION[scopeType];
  if (collection === null) {
    resolvedTenantId = scopeId;
  } else {
    const owner = await store
      .get(collection, { kind: "platform_operator" }, scopeId)
      .catch(() => null);
    const tenantId = owner?.tenant_id;
    resolvedTenantId = typeof tenantId === "string" ? tenantId : null;
  }

  if (resolvedTenantId !== scope.tenantId) {
    throw new HttpError(
      403,
      "tenant_scope_denied",
      "API key is not authorized to access this tenant's resources",
    );
  }
}

/** Who to record on the row. Never a client-declared value. */
function actorOf(scope: CallerScope): string | null {
  return scope.kind === "platform_operator" ? "platform_operator" : (scope.tenantId ?? null);
}

async function project(
  c: Parameters<Handler>[0],
  record: Record<string, unknown>,
  scopeType: SemanticCacheScopeKind,
  scopeId: string,
): Promise<void> {
  const deps = depsOf(c);
  const control = deps.controlDatabase;
  if (control === null) {
    throw new HttpError(
      503,
      "storage_unavailable",
      "semantic cache policy persistence requires CONTROL_DB and tenant object storage",
    );
  }
  await backfillTenantConfigurationPolicy(control, deps.tenantDatabases, scopeId);
  const db = (await deps.tenantDatabases.forTenant(scopeId)).db;
  await projectSemanticCachePolicy(
    db,
    record as Parameters<typeof projectSemanticCachePolicy>[1],
    scopeType,
    scopeId,
    Math.floor(Date.now() / 1000),
    actorOf(scopeOf(c)),
  );
}

export const semanticCachePolicyRoutes: GroupModule = crudGroup(
  "semantic_cache_policy",
  [
    {
      segment: SEMANTIC_CACHE_POLICIES,
      object: "semantic_cache_policy",
      body: semanticCachePolicySchema,
    },
  ],
  {
    createSemanticCachePolicy: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const body = await readJson(c, semanticCachePolicySchema);
      const parsedType = semanticCacheScopeKindSchema.safeParse(body.scope_type);
      if (!parsedType.success || body.scope_id === undefined) {
        throw new HttpError(
          400,
          "invalid_request_body",
          "scope_type (tenant) and scope_id are required",
        );
      }
      await authorizeScopedResource(deps.store, scope, parsedType.data, body.scope_id);

      const id = semanticCachePolicyId(parsedType.data, body.scope_id);
      try {
        const stored = await deps.store.create(SEMANTIC_CACHE_POLICIES, scope, { ...body, id });
        await project(c, stored, parsedType.data, body.scope_id);
        return json(c, 201, adminItem("semantic_cache_policy", stored));
      } catch (error) {
        if (error instanceof StoreConflictError) {
          throw new HttpError(409, "conflict", `semantic cache policy ${id} already exists`);
        }
        throw error;
      }
    },

    getSemanticCachePolicy: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const { scopeType, scopeId } = readScope(c);
      await authorizeScopedResource(deps.store, scope, scopeType, scopeId);
      const id = semanticCachePolicyId(scopeType, scopeId);
      const record = await deps.store.get(SEMANTIC_CACHE_POLICIES, scope, id);
      if (record === null) {
        throw new HttpError(404, "not_found", `semantic cache policy ${id} not found`);
      }
      return json(c, 200, adminItem("semantic_cache_policy", record));
    },

    replaceSemanticCachePolicy: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const { scopeType, scopeId } = readScope(c);
      await authorizeScopedResource(deps.store, scope, scopeType, scopeId);
      const body = await readJson(c, semanticCachePolicySchema);
      const id = semanticCachePolicyId(scopeType, scopeId);
      const stored = await deps.store.replace(SEMANTIC_CACHE_POLICIES, scope, id, {
        ...body,
        scope_type: scopeType,
        scope_id: scopeId,
      });
      if (stored === null) {
        throw new HttpError(404, "not_found", `semantic cache policy ${id} not found`);
      }
      await project(c, stored, scopeType, scopeId);
      return json(c, 200, adminItem("semantic_cache_policy", stored));
    },

    deleteSemanticCachePolicy: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const { scopeType, scopeId } = readScope(c);
      await authorizeScopedResource(deps.store, scope, scopeType, scopeId);
      const id = semanticCachePolicyId(scopeType, scopeId);
      if (!(await deps.store.remove(SEMANTIC_CACHE_POLICIES, scope, id))) {
        throw new HttpError(404, "not_found", `semantic cache policy ${id} not found`);
      }
      // Document first, enforcement row second — the ordering table in
      // `../store/semantic_cache_registry.ts`.
      const control = deps.controlDatabase;
      if (control === null) {
        throw new HttpError(
          503,
          "storage_unavailable",
          "semantic cache policy deletion requires CONTROL_DB and tenant object storage",
        );
      }
      await backfillTenantConfigurationPolicy(control, deps.tenantDatabases, scopeId);
      const db = (await deps.tenantDatabases.forTenant(scopeId)).db;
      await deleteSemanticCachePolicyRow(db, scopeType, scopeId);
      return json(c, 200, adminDeleted("semantic_cache_policy", id));
    },

    invalidateSemanticCachePolicy: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const { scopeType, scopeId } = readScope(c);
      await authorizeScopedResource(deps.store, scope, scopeType, scopeId);

      const control = deps.controlDatabase;
      if (control === null) {
        // A purge that cannot reach the typed row has not happened, and
        // reporting 200 would tell an operator that bodies they are trying to
        // stop serving are gone. This is the one leg that must refuse rather
        // than degrade — the opposite call from `project()` above, because the
        // opposite thing is at stake.
        throw new HttpError(
          503,
          "control_database_unavailable",
          "semantic cache invalidation requires CONTROL_DB and tenant object storage",
        );
      }
      await backfillTenantConfigurationPolicy(control, deps.tenantDatabases, scopeId);
      const db = (await deps.tenantDatabases.forTenant(scopeId)).db;
      const epoch = await bumpSemanticCacheEpoch(
        db,
        scopeType,
        scopeId,
        Math.floor(Date.now() / 1000),
        actorOf(scope),
      );
      return json(c, 200, {
        object: "semantic_cache_invalidation",
        scope_type: scopeType,
        scope_id: scopeId,
        // The number that IS the purge: every cache key is a function of it, so
        // an operator can correlate a bumped epoch with the miss they expect.
        invalidation_epoch: epoch,
      });
    },
  },
);
