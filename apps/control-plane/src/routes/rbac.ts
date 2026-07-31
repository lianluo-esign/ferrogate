/**
 * Contract group `rbac` (11 operations) — permissions, roles, and the tenant↔role
 * bindings that connect them.
 *
 * ```
 *   GET/POST      /admin/v1/permissions
 *   GET/DELETE    /admin/v1/permissions/{permission_id}
 *   GET/POST      /admin/v1/roles
 *   GET/DELETE    /admin/v1/roles/{role_id}
 *   GET/POST      /admin/v1/tenant-roles/{tenant_id}        list / bind
 *   DELETE        /admin/v1/tenant-roles/{tenant_id}/{role_id}   unbind
 * ```
 *
 * Two things are load-bearing:
 *
 *  - **Neither permissions nor roles are PUT/PATCH-able.** The contract
 *    declares only create/read/delete. A mutable role is a privilege-escalation
 *    primitive (edit the role you are bound to), which is why Rust's
 *    `rbac.rs` replaces rather than edits. `crudGroup` derives only the
 *    declared shapes, so `PATCH /admin/v1/roles/{id}` is a 405, not a silent no-op.
 *  - **`tenant-roles` is addressed by the TENANT, not by a binding id.** The
 *    binding row's identity is the `(tenant_id, role_id)` pair, so bind/unbind
 *    are written against a composite key rather than the generic CRUD shapes.
 *    A tenant-scoped caller may only address its own tenant — checked here,
 *    because the tenant is a path parameter rather than a row attribute.
 */
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import { type CallerScope, StoreConflictError } from "../ports.js";
import { adminDeleted, listResponse, parseListQuery } from "../responses.js";
import {
  type GroupModule,
  adminRecordSchema,
  crudGroup,
  json,
  pathParam,
  readJson,
  scopeOf,
} from "./resource.js";

export const permissionSchema = adminRecordSchema.extend({
  /** e.g. `guardrails.policy.activate` — the same vocabulary as `rbac_action`. */
  action: z.string().trim().min(1).optional(),
  resource: z.string().trim().min(1).optional(),
});

export const roleSchema = adminRecordSchema.extend({
  name: z.string().trim().min(1).optional(),
  /** Permission ids granted by this role. */
  permissions: z.array(z.string().trim().min(1)).optional(),
  /** `null` = a global, read-only role (Rust `Role { tenant_id: None }`). */
  tenant_id: z.string().trim().min(1).nullish(),
});

export const tenantRoleBindingSchema = z.object({
  role_id: z.string().trim().min(1),
  /** Rust `PolicySubject` — User / ServiceAccount / ApiKey. */
  subject_kind: z.enum(["user", "service_account", "api_key"]).optional(),
  subject_id: z.string().trim().min(1).optional(),
});

const TENANT_ROLES_COLLECTION = "tenant-roles";

/**
 * A tenant-scoped caller may only address its own tenant. Rust
 * `authorize_tenant_scope`: a platform operator passes through, anyone else
 * must match, and a mismatch is `403 tenant_scope_denied` — a real
 * authorization failure, not a 404, because the caller named a tenant
 * explicitly rather than probing for a row.
 */
function authorizeTenantPath(scope: CallerScope, tenantId: string): void {
  if (scope.kind === "platform_operator") return;
  if (scope.tenantId === tenantId) return;
  throw new HttpError(
    403,
    "tenant_scope_denied",
    "API key is not authorized to access this tenant's resources",
  );
}

/** `(tenant_id, role_id)` composite key, flattened to the store's string id. */
function bindingId(tenantId: string, roleId: string): string {
  return `${tenantId}:${roleId}`;
}

export const rbacRoutes: GroupModule = crudGroup(
  "rbac",
  [
    { segment: "permissions", object: "permission", body: permissionSchema },
    { segment: "roles", object: "role", body: roleSchema },
  ],
  {
    listTenantRoles: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const tenantId = pathParam(c, "tenant_id");
      authorizeTenantPath(scope, tenantId);

      const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
      const scoped = { ...query, filters: { ...query.filters, tenant_id: tenantId } };
      const page = await deps.store.list(TENANT_ROLES_COLLECTION, scope, scoped);
      return json(c, 200, listResponse(page, scoped));
    },

    bindTenantRole: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const tenantId = pathParam(c, "tenant_id");
      authorizeTenantPath(scope, tenantId);

      const body = await readJson(c, tenantRoleBindingSchema);
      const id = bindingId(tenantId, body.role_id);
      try {
        const stored = await deps.store.create(TENANT_ROLES_COLLECTION, scope, {
          ...body,
          id,
          tenant_id: tenantId,
        });
        return json(c, 201, { object: "tenant_role", tenant_role: stored });
      } catch (error) {
        if (error instanceof StoreConflictError) {
          throw new HttpError(
            409,
            "conflict",
            `role ${body.role_id} is already bound to tenant ${tenantId}`,
          );
        }
        throw error;
      }
    },

    unbindTenantRole: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const tenantId = pathParam(c, "tenant_id");
      const roleId = pathParam(c, "role_id");
      authorizeTenantPath(scope, tenantId);

      const id = bindingId(tenantId, roleId);
      if (!(await deps.store.remove(TENANT_ROLES_COLLECTION, scope, id))) {
        throw new HttpError(404, "not_found", `role ${roleId} is not bound to tenant ${tenantId}`);
      }
      return json(c, 200, adminDeleted("tenant_role", id));
    },
  },
);
