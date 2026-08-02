/**
 * Contract group `quota_policy` (6 operations).
 *
 * ```
 *   GET/POST                 /admin/v1/quota-policies
 *   GET/PUT/PATCH/DELETE     /admin/v1/quota-policies/{scope_type}/{scope_id}
 * ```
 *
 * The item path is a **two-segment composite key**, not an opaque id — a quota
 * policy is identified by what it applies to. `scope_type` is the Rust
 * `QuotaScopeKind` (`tenant` | `project` | `workspace` | `key`), and the
 * enum is validated at the route so an unknown scope kind is a 404 rather than
 * a lookup against a collection that cannot exist.
 *
 * The authorization here is the one Rust factored into
 * `auth::authorize_scoped_resource` (issue #185): a scope that is not already a
 * bare tenant id must be RESOLVED to its owning tenant before a tenant-scoped
 * caller may touch it, and **resolution failure denies**. Both "the row is
 * absent" and "the store is unavailable" collapse to `None` in Rust, and `None`
 * can never equal the caller's tenant — so a storage blip denies rather than
 * granting. "Nonexistent means safe to touch" is explicitly the wrong default,
 * and that is reproduced exactly below.
 */
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import { type CallerScope, type ControlPlaneStore, StoreConflictError } from "../ports.js";
import { adminDeleted, adminItem } from "../responses.js";
import { deleteQuotaPolicyRow, projectQuotaPolicy } from "../store/quota_registry.js";
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

/** Rust `QuotaScopeKind`. */
export const QUOTA_SCOPE_KINDS = ["tenant", "project", "workspace", "key"] as const;
export const quotaScopeKindSchema = z.enum(QUOTA_SCOPE_KINDS);
export type QuotaScopeKind = (typeof QUOTA_SCOPE_KINDS)[number];

/** Collection each scope kind resolves its owning tenant from. */
const SCOPE_COLLECTION: Readonly<Record<QuotaScopeKind, string | null>> = {
  tenant: null, // the scope id IS the tenant id
  project: "projects",
  workspace: "workspaces",
  key: "virtual-keys",
};

export const quotaPolicySchema = adminRecordSchema.extend({
  scope_type: quotaScopeKindSchema.optional(),
  scope_id: z.string().trim().min(1).optional(),
  rpm_limit: z.number().int().min(0).nullish(),
  monthly_token_budget: z.number().int().min(0).nullish(),
  enabled: z.boolean().optional(),
  /**
   * #678 — the `metadata` tag KEYS every request from this scope must carry,
   * and what to do when one is missing. Read by the gateway at the `tenant`
   * scope only (`apps/gateway/src/attribution/source.ts` states why).
   *
   * `on_missing_tags` has no default and is not inferred from
   * `required_tags`: the issue asks for the operator's choice to be EXPLICIT,
   * so a document that lists required tags without naming an action enforces
   * nothing. Both the projection and the gateway reader make that same
   * judgement, from opposite ends.
   */
  required_tags: z.array(z.string().trim().min(1)).optional(),
  on_missing_tags: z.enum(["reject", "default_from_key"]).nullish(),
});

const QUOTA_POLICIES = "quota-policies";

/** Composite `(scope_type, scope_id)` flattened to the store's string id. */
export function quotaPolicyId(scopeType: string, scopeId: string): string {
  return `${scopeType}:${scopeId}`;
}

/**
 * Project the committed policy document into the typed `quota_policies` row.
 *
 * Every leg of this group is an OVERRIDE, so the `CollectionSpec.project` hook
 * the generic handlers run never fires here — the projection has to be called
 * on each write explicitly, and forgetting one leg is a policy the operator
 * edited and the gateway kept enforcing at the old numbers.
 *
 * This is the row `apps/gateway`'s `d1QuotaPolicySource` matches with
 * `(scope_type = ? AND scope_id = ?)` on the admission path of every
 * authenticated request. Until it existed, `resolveEffectiveQuota` merged an
 * empty chain, which is not "the default limits" — it is NO rpm cap, NO tpm
 * cap, NO monthly budget and NO model allowlist.
 */
async function projectPolicy(
  c: Parameters<Handler>[0],
  record: Record<string, unknown>,
  scopeType: QuotaScopeKind,
  scopeId: string,
): Promise<void> {
  const db = depsOf(c).controlDatabase;
  if (db === null) return;
  await projectQuotaPolicy(
    db,
    record as Parameters<typeof projectQuotaPolicy>[1],
    scopeType,
    scopeId,
    Math.floor(Date.now() / 1000),
  );
}

function readScope(c: Parameters<Handler>[0]): { scopeType: QuotaScopeKind; scopeId: string } {
  const parsed = quotaScopeKindSchema.safeParse(pathParam(c, "scope_type"));
  if (!parsed.success) {
    // An unknown scope kind names no resource — 404, like Rust's route miss.
    throw new HttpError(404, "not_found", `no route for ${c.req.method} ${c.req.path}`);
  }
  return { scopeType: parsed.data, scopeId: pathParam(c, "scope_id") };
}

/**
 * Rust `authorize_scoped_resource`. Fails closed: a tenant-scoped caller is
 * denied both when the resolved tenant differs from its own AND when
 * resolution fails entirely.
 */
async function authorizeScopedResource(
  store: ControlPlaneStore,
  scope: CallerScope,
  scopeType: QuotaScopeKind,
  scopeId: string,
): Promise<void> {
  if (scope.kind === "platform_operator") return;

  let resolvedTenantId: string | null = null;
  const collection = SCOPE_COLLECTION[scopeType];
  if (collection === null) {
    resolvedTenantId = scopeId;
  } else {
    // Deliberately a platform-scoped read: the point is to learn who OWNS the
    // referenced row, which a tenant-filtered read could not tell us apart from
    // "absent". The answer is then compared to the caller's tenant below.
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

export const quotaPolicyRoutes: GroupModule = crudGroup(
  "quota_policy",
  [{ segment: QUOTA_POLICIES, object: "quota_policy", body: quotaPolicySchema }],
  {
    createQuotaPolicy: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const body = await readJson(c, quotaPolicySchema);
      const parsedType = quotaScopeKindSchema.safeParse(body.scope_type);
      if (!parsedType.success || body.scope_id === undefined) {
        throw new HttpError(
          400,
          "invalid_request_body",
          "scope_type (tenant|project|workspace|key) and scope_id are required",
        );
      }
      await authorizeScopedResource(deps.store, scope, parsedType.data, body.scope_id);

      const id = quotaPolicyId(parsedType.data, body.scope_id);
      try {
        const stored = await deps.store.create(QUOTA_POLICIES, scope, { ...body, id });
        await projectPolicy(c, stored, parsedType.data, body.scope_id);
        return json(c, 201, adminItem("quota_policy", stored));
      } catch (error) {
        if (error instanceof StoreConflictError) {
          throw new HttpError(409, "conflict", `quota policy ${id} already exists`);
        }
        throw error;
      }
    },

    getQuotaPolicy: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const { scopeType, scopeId } = readScope(c);
      await authorizeScopedResource(deps.store, scope, scopeType, scopeId);
      const id = quotaPolicyId(scopeType, scopeId);
      const record = await deps.store.get(QUOTA_POLICIES, scope, id);
      if (record === null) throw new HttpError(404, "not_found", `quota policy ${id} not found`);
      return json(c, 200, adminItem("quota_policy", record));
    },

    replaceQuotaPolicy: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const { scopeType, scopeId } = readScope(c);
      await authorizeScopedResource(deps.store, scope, scopeType, scopeId);
      const body = await readJson(c, quotaPolicySchema);
      const id = quotaPolicyId(scopeType, scopeId);
      const stored = await deps.store.replace(QUOTA_POLICIES, scope, id, {
        ...body,
        scope_type: scopeType,
        scope_id: scopeId,
      });
      if (stored === null) throw new HttpError(404, "not_found", `quota policy ${id} not found`);
      await projectPolicy(c, stored, scopeType, scopeId);
      return json(c, 200, adminItem("quota_policy", stored));
    },

    updateQuotaPolicy: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const { scopeType, scopeId } = readScope(c);
      await authorizeScopedResource(deps.store, scope, scopeType, scopeId);
      const body = await readJson(c, quotaPolicySchema);
      const id = quotaPolicyId(scopeType, scopeId);
      const stored = await deps.store.merge(QUOTA_POLICIES, scope, id, body);
      if (stored === null) throw new HttpError(404, "not_found", `quota policy ${id} not found`);
      await projectPolicy(c, stored, scopeType, scopeId);
      return json(c, 200, adminItem("quota_policy", stored));
    },

    deleteQuotaPolicy: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const { scopeType, scopeId } = readScope(c);
      await authorizeScopedResource(deps.store, scope, scopeType, scopeId);
      const id = quotaPolicyId(scopeType, scopeId);
      if (!(await deps.store.remove(QUOTA_POLICIES, scope, id))) {
        throw new HttpError(404, "not_found", `quota policy ${id} not found`);
      }
      // Document first, enforcement row second — see the ordering table in
      // `store/quota_registry.ts`. A crash between them leaves a limit that
      // still bites and that the operator can no longer see, which is the
      // direction a limiter must fail in; the inverse leaves a policy the
      // console lists and the gateway no longer applies.
      const db = deps.controlDatabase;
      if (db !== null) await deleteQuotaPolicyRow(db, scopeType, scopeId);
      return json(c, 200, adminDeleted("quota_policy", id));
    },
  },
);
