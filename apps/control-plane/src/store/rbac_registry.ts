/**
 * The WRITE half of RBAC — `roles`, `permissions` and `tenant_role_bindings` in
 * the CONTROL database.
 *
 * ## What this closes
 *
 * Every RBAC *reader* in the fleet authorizes on ONE join:
 *
 * ```sql
 * SELECT roles.permission_keys_json
 *   FROM tenant_role_bindings
 *   JOIN roles ON roles.id = tenant_role_bindings.role_id
 *  WHERE tenant_role_bindings.tenant_id = ?
 * ```
 *
 * — `src/adapters.ts::D1RbacAuthorizer`, `apps/gateway/src/adapters.ts`,
 * `apps/gateway/src/assets/entitlements.ts` and `apps/mcp/src/auth.ts`.
 *
 * **No TypeScript in this repo wrote any of those three tables.** All eleven
 * `rbac` operations stored a `control_plane_resources` DOCUMENT and stopped, so
 * the join returned zero rows on every deployment and each authorizer fell
 * through to its declarative `TENANT_RBAC_ACTIONS` fallback. The two visible
 * consequences are both operator-facing lies, in opposite directions:
 *
 *  - `POST /admin/v1/roles` + `POST /admin/v1/tenant-roles/{t}` answer `201` and
 *    **grant nothing** — the documented provisioning path produces a tenant that
 *    can do nothing, with no error anywhere to explain it;
 *  - `DELETE /admin/v1/tenant-roles/{t}/{r}` answers `200 {"deleted": true}` and
 *    **revokes nothing** — an operator believes they removed access and the
 *    credential keeps the permission on the very next request.
 *
 * Same defect class as the MCP server catalog, the self-hosted-worker registry,
 * the quota chain and the virtual-key credential: the reader mounted, the data
 * path into it absent, every suite green because each side was tested against
 * its own fixture. `test/rbac-d1.test.ts` proves the READER and provisions with
 * raw SQL, which is why it could not see this; `test/rbac-write-half.test.ts`
 * provisions ONLY through the admin API and asserts the effect.
 *
 * ## Ordering: which leg goes first, and why it is the OPPOSITE of quota
 *
 * The document and the typed row are two statements in the same database but on
 * two different code paths (the store's and the route's), so they are not one
 * `batch()`. The rule is *fail closed*, and what "closed" means depends on what
 * the row does:
 *
 * | family | the typed row | a residual typed row means | so the delete order is |
 * |---|---|---|---|
 * | `quota_policies` (`store/quota_registry.ts`) | a LIMIT | the limit still bites and the operator cannot see it — CLOSED | document first |
 * | `roles` / `tenant_role_bindings` (here) | a GRANT | the permission still applies and the operator believes it is gone — OPEN | **typed row first** |
 *
 * So an unbind deletes the binding row and only then the document: a crash
 * between them leaves a credential that has ALREADY lost the permission and a
 * document the operator can delete again. The inverse leaves a live grant the
 * operator has been told is revoked, which is the one outcome that is not
 * survivable. This is the same "tighten writes the authority row first" rule
 * `store/virtual_keys.ts` states for credentials.
 *
 * The fence, though, is in the STORE: `deps.store.get`/`remove` is what refuses
 * a cross-tenant id. So the callers here check visibility through the store (or,
 * for `tenant-roles`, through `authorizeTenantPath` on the path parameter)
 * BEFORE the typed row is touched — otherwise "delete the authority row first"
 * would itself become an unfenced cross-tenant write.
 *
 * ## Deletes do NOT cascade, deliberately
 *
 * `DELETE /admin/v1/roles/{id}` removes the `roles` row and leaves
 * `tenant_role_bindings` alone, so document and typed row stay in exact 1:1
 * correspondence — the join simply misses, which is the closed direction. The
 * binding documents that named the deleted role remain listed by
 * `GET /admin/v1/tenant-roles/{t}` because they remain the operator's stated
 * intent; re-creating the role id restores exactly the grants those documents
 * describe. A cascade would silently rewrite the operator's intent on their
 * behalf, and would then disagree with the documents the admin surface serves.
 */
import type { StoreRecord } from "../ports.js";

/** The three typed tables in `sql/d1-ts/control/0001_init_control.sql`. */
export const ROLES_TABLE = "roles";
export const PERMISSIONS_TABLE = "permissions";
export const TENANT_ROLE_BINDINGS_TABLE = "tenant_role_bindings";

function text(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : fallback;
}

/**
 * The permission keys a role grants, as the JSON array
 * `roles.permission_keys_json` holds and every authorizer parses.
 *
 * Non-string entries are dropped rather than stringified: the readers compare
 * with `granted.has(rbacAction)`, so a `42` could only ever be dead weight, and
 * a `{"action": …}` that stringified to `[object Object]` would be a grant key
 * no operator could ever have meant.
 */
function permissionKeys(value: unknown): string {
  if (!Array.isArray(value)) return "[]";
  return JSON.stringify(value.filter((entry): entry is string => typeof entry === "string"));
}

/**
 * Write (or overwrite) the `roles` row a document describes.
 *
 * `roles.slug` is `NOT NULL UNIQUE` and no reader consults it, so it is derived
 * from the id rather than taken from the document: an operator-supplied slug
 * could collide with another role's and turn a `201` into a `500` *after* the
 * document was already committed. The id is the primary key, so deriving from
 * it cannot collide with anything.
 */
export async function projectRole(
  db: D1Database,
  record: StoreRecord,
  nowUnix: number,
): Promise<void> {
  const id = String(record.id);
  await db
    .prepare(
      `INSERT INTO ${ROLES_TABLE}
         (id, name, slug, description, permission_keys_json, created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET
         name = excluded.name,
         description = excluded.description,
         permission_keys_json = excluded.permission_keys_json,
         updated_at_unix = excluded.updated_at_unix`,
    )
    .bind(
      id,
      text(record.name, id),
      id,
      text(record.description, ""),
      permissionKeys(record.permissions),
      nowUnix,
      nowUnix,
    )
    .run();
}

/** Drop the `roles` row. See the module docblock: this runs BEFORE the document. */
export async function unprojectRole(db: D1Database, id: string): Promise<void> {
  await db.prepare(`DELETE FROM ${ROLES_TABLE} WHERE id = ?`).bind(id).run();
}

/**
 * Write (or overwrite) the `permissions` row a document describes.
 *
 * `permissions.key` is the vocabulary `roles.permission_keys_json` draws from
 * (`guardrails.policy.read`, …), which the admin schema calls `action`. It is
 * `NOT NULL UNIQUE`, and unlike a role's slug it is MEANINGFUL, so it is taken
 * from the document — with any other row holding the same key removed in the
 * same batch. The document store arbitrates identity by `id`, so a second
 * document claiming an existing key must win the key rather than fail a
 * constraint after its document was already committed.
 */
export async function projectPermission(
  db: D1Database,
  record: StoreRecord,
  nowUnix: number,
): Promise<void> {
  const id = String(record.id);
  const key = text(record.key, text(record.action, id));
  await db.batch([
    db.prepare(`DELETE FROM ${PERMISSIONS_TABLE} WHERE key = ? AND id <> ?`).bind(key, id),
    db
      .prepare(
        `INSERT INTO ${PERMISSIONS_TABLE}
           (id, key, name, description, created_at_unix, updated_at_unix)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET
           key = excluded.key,
           name = excluded.name,
           description = excluded.description,
           updated_at_unix = excluded.updated_at_unix`,
      )
      .bind(id, key, text(record.name, id), text(record.description, ""), nowUnix, nowUnix),
  ]);
}

/** Drop the `permissions` row. */
export async function unprojectPermission(db: D1Database, id: string): Promise<void> {
  await db.prepare(`DELETE FROM ${PERMISSIONS_TABLE} WHERE id = ?`).bind(id).run();
}

/**
 * Write the `tenant_role_bindings` row — the GRANT itself.
 *
 * The row id is the same `${tenant_id}:${role_id}` composite the document uses,
 * so binding is idempotent and the two identities cannot drift; `UNIQUE
 * (tenant_id, role_id)` in the schema says the same thing a second way, and the
 * upsert on `id` satisfies both.
 */
export async function projectTenantRoleBinding(
  db: D1Database,
  tenantId: string,
  roleId: string,
  nowUnix: number,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO ${TENANT_ROLE_BINDINGS_TABLE} (id, tenant_id, role_id, created_at_unix)
       VALUES (?, ?, ?, ?)
       ON CONFLICT (id) DO NOTHING`,
    )
    .bind(`${tenantId}:${roleId}`, tenantId, roleId, nowUnix)
    .run();
}

/**
 * Revoke the grant.
 *
 * Addressed by `(tenant_id, role_id)` rather than by the composite id string so
 * a row written by any other writer — a migration, a console, an earlier
 * id-format — is revoked too. A revocation that missed because the id was
 * spelled differently is the exact failure this whole module exists to remove.
 */
export async function unprojectTenantRoleBinding(
  db: D1Database,
  tenantId: string,
  roleId: string,
): Promise<void> {
  await db
    .prepare(`DELETE FROM ${TENANT_ROLE_BINDINGS_TABLE} WHERE tenant_id = ? AND role_id = ?`)
    .bind(tenantId, roleId)
    .run();
}
