/**
 * The per-tenant D1 seam: where `@ferrogate/storage`'s tenant router and its
 * reference-guarded deletes actually get MOUNTED on this Worker.
 *
 * ## What was wrong before this module
 *
 * The user directive for this rewrite is **one D1 database per tenant** plus one
 * account-global control database, and `@ferrogate/storage` implements the whole
 * of it — `EnvBindingTenantDatabaseRouter`, `ControlDatabaseTenantRegistry`,
 * `D1ReferenceGuardedDeletes` — with 152 D1 tests behind them. Every one of those
 * classes had **zero importers under any app's `src`** (`packages/storage/src/index.ts`
 * says so in its own `PORT-TODO`, and `docs/rewrite/parity-audit-storage.md` §4.1
 * calls it the repo's recurring defect in its purest form). The consequence here
 * was concrete, not architectural: `sql/d1-ts/tenant/0001_init_tenant.sql`
 * creates `projects`, `workspaces` and `api_keys`, and **nothing wrote a single
 * row into any of them**, so the database-per-tenant topology was not in effect
 * on any deployed path and §1.5.7's guarded deletes guarded nothing.
 *
 * ## What it does now
 *
 * The control plane is where a tenant's hierarchy is minted, so it is where the
 * typed rows come from. `POST /admin/v1/projects` and `POST /admin/v1/workspaces`
 * now project into the owning tenant's database, and `DELETE` runs through
 * `D1ReferenceGuardedDeletes`, so deleting a project while a workspace or a
 * virtual API key still points at it is a **409** naming the blockers rather than
 * a silent orphaning.
 *
 * ## Two databases, no transaction across them — so ORDER is the contract
 *
 * The admin document lives in the CONTROL database and the typed row lives in a
 * TENANT database. D1 has no transaction spanning two databases (there is no
 * cross-database `BEGIN` and no two-phase commit), so the pair cannot be one
 * commit and the ordering is what decides how a crash between them reads:
 *
 * | path | order | a crash in between leaves |
 * |---|---|---|
 * | create | document first, then the tenant row | a document with no tenant row — invisible to the reference guard, so the next delete is *permitted*. Benign: the guard only ever refuses. |
 * | delete | guarded tenant row first, then the document | a tenant row already gone and a document still listed — the next DELETE finds no blockers and completes. Self-healing. |
 *
 * Both residual states fail in the direction that loses no operator data and
 * cannot fabricate a reference. The inverse orderings do not: creating the
 * tenant row first would leave an invisible row permanently blocking a project
 * id nobody can see, and deleting the document first would strand a `projects`
 * row that the data plane still reads.
 *
 * ## `not_found` vs `runtime` — the split that must not be collapsed
 *
 * `TenantDatabaseRouter.forTenant` never falls back; it distinguishes two
 * failures and this module gives them opposite answers, deliberately:
 *
 *  - **no registry row** (`StorageError` `not_found`) ⇒ this tenant has no
 *    provisioned database. That is the state of every deployment that has not
 *    onboarded a tenant database yet, including a fresh `wrangler dev --local`,
 *    and the honest reading is "there are no typed rows and therefore no
 *    references". {@link tenantDatabaseFor} answers `null` and the caller keeps
 *    the document-only behaviour it has always had.
 *  - **registered but unroutable** (`runtime`: `binding_name` is NULL, or names
 *    a binding this Worker does not have, or names something that is not a D1
 *    database) ⇒ an operator ASKED for per-tenant isolation and the deployment
 *    cannot deliver it. That is a **503**, never a silent downgrade: writing only
 *    the document there would leave the isolation claim true on paper and false
 *    in the database, which is the failure the whole topology exists to prevent.
 *
 * Collapsing those two into "just skip the tenant database" is the tempting
 * simplification and it is exactly wrong — it converts a misconfiguration an
 * operator can fix into data silently landing in one place instead of two.
 */
import {
  D1ReferenceGuardedDeletes,
  type DeleteProjectOutcome,
  type DeleteWorkspaceOutcome,
  StorageError,
  type TenantDatabaseHandle,
  type TenantDatabaseRouter,
} from "@ferrogate/storage";
import { HttpError } from "../middleware/errors.js";
import type { StoreRecord } from "../ports.js";

/**
 * Resolve the tenant's database, or `null` when that tenant has no provisioned
 * one. Throws `HttpError` 503 when it HAS one that this deployment cannot reach
 * — see the module docblock for why those two are not the same answer.
 */
export async function tenantDatabaseFor(
  router: TenantDatabaseRouter,
  tenantId: string | null,
): Promise<TenantDatabaseHandle | null> {
  // An un-attributed (platform-global) row has no tenant database by
  // definition. Routing on the empty string would be a `runtime` refusal that
  // read like a misconfiguration.
  if (tenantId === null || tenantId.trim() === "") return null;
  try {
    return await router.forTenant(tenantId.trim());
  } catch (error) {
    if (error instanceof StorageError && error.kind === "not_found") return null;
    throw new HttpError(
      503,
      "tenant_database_unavailable",
      `tenant ${tenantId} has a provisioned database that this deployment cannot reach: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

/**
 * The tenant a stored admin document belongs to.
 *
 * The row's own `tenant_id` is authoritative — the store stamps it on create and
 * refuses to let a PATCH move it — so a platform operator acting on a tenant's
 * project routes to THAT tenant's database, not to its own (absent) one.
 */
export function tenantOf(record: StoreRecord): string | null {
  return typeof record.tenant_id === "string" && record.tenant_id !== "" ? record.tenant_id : null;
}

function text(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : fallback;
}

/**
 * A URL-safe slug. `projects.slug` is `NOT NULL` with `UNIQUE (tenant_id, slug)`,
 * and the admin document carries no slug, so one is derived from the name and
 * SUFFIXED with the id. The suffix is not decoration: two projects legitimately
 * named "Staging" must both be creatable, and a bare `slugify(name)` would make
 * the second one a UNIQUE violation — i.e. an admin surface that rejects a name
 * it accepted yesterday, for a column the operator never sees.
 */
function slugFor(id: string, name: unknown): string {
  const base = text(name, id)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return base === "" ? id : `${base}-${id}`;
}

/**
 * Project a `projects` admin document into the tenant database.
 *
 * `INSERT … ON CONFLICT (id) DO UPDATE` rather than a plain INSERT because the
 * admin surface's PUT/PATCH must be able to carry `name`/`status` through to the
 * typed row, and because a retried create must not 409 on the leg the control
 * database already accepted.
 */
export async function projectTenantRow(
  handle: TenantDatabaseHandle,
  record: StoreRecord,
  nowUnix: number,
): Promise<void> {
  const id = String(record.id);
  await handle.db
    .prepare(
      `INSERT INTO projects (id, tenant_id, name, slug, status, created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET
         name = excluded.name,
         status = excluded.status,
         updated_at_unix = excluded.updated_at_unix`,
    )
    .bind(
      id,
      handle.tenantId,
      text(record.name, id),
      slugFor(id, record.name),
      text(record.status, "active"),
      nowUnix,
      nowUnix,
    )
    .run();
}

/** Project a `workspaces` admin document into the tenant database. */
export async function workspaceTenantRow(
  handle: TenantDatabaseHandle,
  record: StoreRecord,
  nowUnix: number,
): Promise<void> {
  const id = String(record.id);
  await handle.db
    .prepare(
      `INSERT INTO workspaces
         (id, project_id, tenant_id, name, slug, environment, status, created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET
         project_id = excluded.project_id,
         name = excluded.name,
         status = excluded.status,
         updated_at_unix = excluded.updated_at_unix`,
    )
    .bind(
      id,
      // `project_id` is NOT NULL. A workspace created without one is stored as
      // its own orphan rather than refused, because the admin document schema
      // makes `project_id` optional and tightening it here would reject a body
      // the surface has always accepted. Such a row references no project, so
      // it blocks no project delete — which is the truthful outcome.
      text(record.project_id, ""),
      handle.tenantId,
      text(record.name, id),
      slugFor(id, record.name),
      text(record.environment, "default"),
      text(record.status, "active"),
      nowUnix,
      nowUnix,
    )
    .run();
}

/**
 * `@ferrogate/storage`'s §1.5.7 guarded project delete, run on the routed
 * handle.
 *
 * The guard is a `NOT EXISTS` subquery INSIDE the DELETE, so a workspace created
 * a microsecond before this statement is seen by it — count-then-delete would
 * authorize the delete against a stale count and orphan that workspace.
 */
export function deleteProjectRow(
  handle: TenantDatabaseHandle,
  id: string,
): Promise<DeleteProjectOutcome> {
  return new D1ReferenceGuardedDeletes(handle).deleteProjectIfUnreferenced(id);
}

/** The same, for a workspace still referenced by a virtual API key. */
export function deleteWorkspaceRow(
  handle: TenantDatabaseHandle,
  id: string,
): Promise<DeleteWorkspaceOutcome> {
  return new D1ReferenceGuardedDeletes(handle).deleteWorkspaceIfUnreferenced(id);
}

/**
 * Turn a refusal into the 409 the admin surface reports.
 *
 * The counts are IN the message because "cannot delete" without "3 workspaces
 * and 1 key are in the way" leaves an operator with nothing to do next.
 */
export function referencedConflict(
  object: string,
  id: string,
  blockers: Readonly<Record<string, number>>,
): HttpError {
  const detail = Object.entries(blockers)
    .filter(([, count]) => count > 0)
    .map(([kind, count]) => `${count} ${kind}`)
    .join(", ");
  return new HttpError(
    409,
    "conflict",
    `${object} ${id} is still referenced by ${detail === "" ? "other rows" : detail}; delete them first`,
  );
}

/**
 * The router a deployment gets when it is running WITHOUT the control database
 * (`CONTROL_PLANE_STORE = "memory"`, or no `DB` binding at all).
 *
 * There is no registry to read, so no tenant is provisioned and every lookup is
 * `not_found` — which {@link tenantDatabaseFor} reads as "document-only", i.e.
 * exactly the behaviour this app had before the seam existed. It is a real
 * implementation of the port rather than an `undefined` dependency so no caller
 * has to null-check the router, and `control()` THROWS rather than returning a
 * fabricated handle: a caller reaching for the control database in a
 * database-less deployment has a bug, and hiding it would only move the failure.
 */
export class UnprovisionedTenantDatabaseRouter implements TenantDatabaseRouter {
  control(): D1Database {
    throw StorageError.runtime(
      "control-plane: no control database is bound; set the [[d1_databases]] DB binding or run with CONTROL_PLANE_STORE=memory and no tenant routing",
    );
  }

  forTenant(tenantId: string): Promise<TenantDatabaseHandle> {
    return Promise.reject(
      StorageError.notFound(
        `tenant ${tenantId} has no provisioned D1 database in the control registry`,
      ),
    );
  }

  provisionedTenants(): Promise<readonly string[]> {
    return Promise.resolve([]);
  }
}
