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
 *  - **Reading RBAC is one authority; AUTHORING it is another (#791).** Every
 *    write in this group is operator-only, mounted by {@link authorizeRbacWrite}
 *    on every non-`GET` operation the contract declares. The reads are
 *    untouched. See that function for the three questions #791 asks and the
 *    answers this file gives.
 */
import { z } from "zod";
import type { ApiOperation } from "../contract.js";
import { HttpError } from "../middleware/errors.js";
import { type CallerScope, StoreConflictError } from "../ports.js";
import { adminDeleted, listResponse, parseListQuery } from "../responses.js";
import {
  projectPermission,
  projectRole,
  projectTenantRoleBinding,
  unprojectPermission,
  unprojectRole,
  unprojectTenantRoleBinding,
} from "../store/rbac_registry.js";
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
 *
 * **This is the fence for the READ leg** (`GET /admin/v1/tenant-roles/{t}`), and
 * as of #791 it is no longer the only fence on the writes: the question it asks
 * is "is this tenant MINE?", and for a write the answer being "yes" is the
 * escalation. See {@link authorizeRbacWrite}. It is still CALLED from bind and
 * unbind, deliberately — those handlers must remain correct on their own if the
 * write fence is ever narrowed, and a cross-tenant path parameter should not
 * depend on a wrapper mounted somewhere else in the file.
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

/**
 * The fence on every WRITE in this group: **operator only** (#791).
 *
 * `authorizeTenantPath` above admits a tenant-scoped caller for its OWN tenant,
 * which is the right question for a read and, for a write, is the escalation
 * itself. A tenant-scoped `admin.write` key could
 * `POST /admin/v1/roles {"permissions":["*"]}` — the store stamps the caller's
 * `tenant_id`, so the role is the tenant's — and then
 * `POST /admin/v1/tenant-roles/{its own id}`; `D1RbacAuthorizer` and its four
 * siblings then allow on `granted.has("*")` and the tenant holds every
 * RBAC-gated verb its operator withheld. Reproduced through the Worker in
 * `test/rbac-self-grant.test.ts`.
 *
 * ## The three questions #791 asks, and the answers
 *
 * **May a tenant author roles at all? No.** **May a role it authors carry a
 * permission its own grants do not contain (`"*"` in particular)? Not
 * applicable — it may not author one.** **May it bind an operator-authored
 * GLOBAL role? No.**
 *
 * That is the "operator only" answer, and it IS a trade: it removes
 * tenant-self-service RBAC, which #791 correctly calls a plausible product
 * intent. Here is why it is not a real capability on this surface today, and
 * what would have to change for the subset rule to become the right answer.
 *
 * ### 1. A binding is a TENANT-WIDE grant. There is no per-subject binding.
 *
 * `tenantRoleBindingSchema` accepts `subject_kind` and `subject_id`, so the API
 * looks like "bind this role to user `u1`". It is not.
 * `sql/d1-ts/control/0001_init_control.sql` declares
 * `tenant_role_bindings(id, tenant_id, role_id, created_at_unix)` — **there are
 * no subject columns** — and all five authorizers in the fleet
 * (`src/adapters.ts::D1RbacAuthorizer`, `apps/gateway/src/adapters.ts`,
 * `apps/gateway/src/assets/entitlements.ts`, `apps/mcp/src/auth.ts`,
 * `apps/agent-runtime/src/rbac.ts`) resolve
 * `tenant_role_bindings ⋈ roles WHERE tenant_role_bindings.tenant_id = ?` and
 * union the permission keys. The subject fields ride on the operator DOCUMENT
 * and are read by nothing. So "a tenant admin delegating to its own users" does
 * not exist here: every binding a tenant could make grants the whole tenant,
 * i.e. grants the caller.
 *
 * ### 2. A subset rule cannot be sound against THIS authorizer.
 *
 * The obvious middle path is `delegationScopeSubset`
 * (`packages/identity/src/delegation/sign.ts`) — let a tenant author and bind a
 * role whose permissions are a subset of what it already holds, refuse anything
 * wider, and `"*"` is only mintable by a holder that already has `"*"`. That
 * predicate is right and would be reused rather than reinvented. What defeats
 * it is not the predicate but the authorizer's shape: a tenant's authority is
 * the UNION of the roles bound to it, so a subset binding is never an
 * attenuation and never a delegation — it is a COPY the tenant controls.
 * Concretely: the operator binds `role_ops = ["guardrails.policy.activate"]`;
 * the tenant authors `role_mine` with the same subset and binds it (allowed —
 * it is a subset, and it grants nothing new today); the operator later unbinds
 * `role_ops` to revoke the verb, and the tenant keeps it via `role_mine`.
 * Subset-at-write-time is a time-of-check rule guarding a permission set that
 * is evaluated later, so it converts "the operator can revoke" into "the
 * operator cannot revoke", which is a worse property to lose than the one it
 * buys. Closing it means intersecting tenant-authored grants against
 * operator-authored ones at READ time, in five authorizers across four apps —
 * a different change, with a different blast radius, and not one to make while
 * the hole is open.
 *
 * Deletes are fenced for the same reason in the other direction: `DELETE
 * /admin/v1/roles/{id}` on an OPERATOR-authored role attributed to the tenant
 * passes the store's `writableBy` (`record.tenant_id === scope.tenantId`), and
 * dropping the `roles` row makes the join miss — the tenant editing the
 * operator's RBAC configuration, even though the direction happens to be
 * de-escalating for itself.
 *
 * ### 3. What would flip this decision
 *
 * If `tenant_role_bindings` grows real subject columns AND the authorizers
 * evaluate them against the calling credential, a tenant binding a role to
 * `user:u1` stops granting the caller, and the subset rule becomes the correct
 * fence for exactly that leg. Until then the honest fence is the verb.
 *
 * ## Mounting
 *
 * Mounted on every non-`GET` operation the contract declares for this group
 * rather than named one at a time, so an RBAC write ADDED later is fenced by
 * default and has to be opened deliberately. That is the fail-closed direction,
 * and it is why this is not simply four `authorizeRbacWrite(scope)` calls in
 * four handlers — the defect class this repository keeps paying for is a fence
 * wired onto one verb and forgotten on the next.
 *
 * It runs before the handler, therefore before any body parse and before any
 * store resolution: a caller this verb will never admit is not told which
 * fields its request was missing, and cannot use the refusal to probe which
 * role ids exist.
 */
function authorizeRbacWrite(scope: CallerScope, operation: ApiOperation): void {
  if (scope.kind === "platform_operator") return;
  const detail = `${operation.method} ${operation.path} is an operator action: this credential is scoped to tenant ${scope.tenantId}, which may read the roles and permissions it is subject to but may not author them — a grant the governed party can write is not a grant`;
  throw new HttpError(403, "rbac_write_operator_only", detail);
}

/** `(tenant_id, role_id)` composite key, flattened to the store's string id. */
function bindingId(tenantId: string, roleId: string): string {
  return `${tenantId}:${roleId}`;
}

/**
 * The typed-row projections, and why they are on the SPEC.
 *
 * Every RBAC reader in the fleet — `src/adapters.ts::D1RbacAuthorizer`,
 * `apps/gateway/src/adapters.ts`, `apps/gateway/src/assets/entitlements.ts`,
 * `apps/mcp/src/auth.ts` — authorizes on `tenant_role_bindings ⋈ roles` in the
 * control database, never on the `control_plane_resources` documents this group
 * used to write alone. While the write half was missing, `POST /roles` +
 * `POST /tenant-roles/{t}` granted nothing and
 * `DELETE /tenant-roles/{t}/{r}` answered `200 {"deleted": true}` and revoked
 * nothing; the authorizers saw `rows.length === 0`, fell back to the
 * declarative `TENANT_RBAC_ACTIONS`, and every suite stayed green.
 * `store/rbac_registry.ts` carries the statements and the ordering rule.
 *
 * `project` / `unproject` are declared on the collection rather than called
 * from a bespoke handler so they cannot be wired on POST and forgotten on
 * PUT/DELETE — which is the shape of the original defect.
 */
const rbacCrud: GroupModule = crudGroup(
  "rbac",
  [
    {
      segment: "permissions",
      object: "permission",
      body: permissionSchema,
      project: projectPermission,
      unproject: (db, id) => unprojectPermission(db, id),
    },
    {
      segment: "roles",
      object: "role",
      body: roleSchema,
      project: projectRole,
      unproject: (db, id) => unprojectRole(db, id),
    },
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
        // Document first, then the GRANT: a crash between them leaves a binding
        // the operator can see that does not yet authorize. The inverse would
        // publish an invisible grant. See `store/rbac_registry.ts`.
        const db = deps.controlDatabase;
        if (db !== null) {
          await projectTenantRoleBinding(
            db,
            deps.tenantDatabases,
            tenantId,
            body.role_id,
            Math.floor(Date.now() / 1000),
          );
        }
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
      const db = deps.controlDatabase;
      if (db !== null) {
        // Resolve the binding for THIS caller before anything is deleted, so a
        // binding the caller cannot see is a 404 that writes nothing; then the
        // GRANT goes before the document, because a residual grant is the one
        // residue that is not survivable — the operator has been told the role
        // is revoked. `store/rbac_registry.ts` has the ordering table.
        if ((await deps.store.get(TENANT_ROLES_COLLECTION, scope, id)) === null) {
          throw new HttpError(
            404,
            "not_found",
            `role ${roleId} is not bound to tenant ${tenantId}`,
          );
        }
        await unprojectTenantRoleBinding(deps.tenantDatabases, tenantId, roleId);
      }
      if (!(await deps.store.remove(TENANT_ROLES_COLLECTION, scope, id))) {
        throw new HttpError(404, "not_found", `role ${roleId} is not bound to tenant ${tenantId}`);
      }
      return json(c, 200, adminDeleted("tenant_role", id));
    },
  },
);

/**
 * The group, with {@link authorizeRbacWrite} in front of every write.
 *
 * Wrapping the built map rather than editing four handlers is what makes the
 * fence TOTAL over the group: the set of fenced operations is derived from the
 * contract, so `POST /admin/v1/permissions`, `DELETE /admin/v1/roles/{id}`,
 * bind, unbind — and anything an author adds to the `rbac` group tomorrow — are
 * all covered without anyone remembering to cover them.
 *
 * `GET` is the one method that passes through. That is the deliberate other
 * half of #791: a tenant may still LIST and READ the roles, permissions and
 * bindings it is subject to (`GET /admin/v1/tenant-roles/{its own id}` is still
 * fenced to its own tenant by {@link authorizeTenantPath}), because a tenant
 * that cannot see the grants it is held to cannot tell a `403` from a bug —
 * the same split #782 made on quota policies.
 */
export const rbacRoutes: GroupModule = {
  group: rbacCrud.group,
  build(operations) {
    const handlers = rbacCrud.build(operations);
    for (const operation of operations) {
      if (operation.method === "GET") continue;
      const inner = handlers.get(operation.operationId);
      if (inner === undefined) {
        // Unreachable: `crudGroup` throws at module load for an operation it
        // cannot serve. Fail the BUILD rather than mounting an unfenced write
        // if that ever stops being true.
        throw new Error(
          `control-plane group rbac: no handler to fence for ${operation.operationId}`,
        );
      }
      handlers.set(operation.operationId, (c) => {
        authorizeRbacWrite(scopeOf(c), operation);
        return inner(c);
      });
    }
    return handlers;
  },
};
