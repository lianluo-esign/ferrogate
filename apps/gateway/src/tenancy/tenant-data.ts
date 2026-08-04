/**
 * Addressing for `TenantDataObject` — the SQLite-backed Durable Object that IS
 * a tenant's database (issue #822,
 * `docs/design/per-tenant-durable-object-storage-2026-08.md`).
 *
 * ## What this module is, now that the router exists
 *
 * It is the ONE place `env.TENANT_DATA` is read. `createTenantDatabaseResolver`
 * calls {@link tenantDataNamespace} on its `durable_object` branch — the
 * default since #819 — so the binding, its 503 refusal, and the `env.X` token
 * `test/env-var-drift.test.ts` scans for all live here rather than being
 * spread across the directory.
 *
 * `storage = "sqlite"` / `new_sqlite_classes` is **immutable once a namespace
 * exists** — changing it later is `storage_type_mismatch`, and converting
 * requires a `deleted` tombstone and total data loss. That is why the
 * `TENANT_DATA` stanza in `wrangler.toml` landed a slice AHEAD of the routing
 * mode that now uses it, and why this file predates its own caller.
 *
 * It is still deliberately NOT a {@link TenantDatabaseRouter}.
 * `DurableObjectTenantDatabaseRouter` in `@ferrogate/storage` is, because
 * `forTenant()` has to return a `TenantDatabaseHandle` carrying a
 * `D1Database`-shaped facade — `prepare().bind().first()/all()/run()`, a
 * `meta.changes` measured as a `total_changes()` delta, and `batch()` forwarded
 * into one `transactionSync`. {@link tenantDataObjectFor} hands back the RAW
 * stub and is NOT what the request path takes; it exists for maintenance and
 * test paths that want the object itself.
 *
 * ## Why the tenant id is passed to the object as well as used to address it
 *
 * `idFromName` is one-way: an object cannot recover the name it was addressed
 * by. `TenantDataObject` therefore adopts the tenant id carried on its first
 * RPC and refuses every later RPC carrying a different one. Without that, a
 * resolver bug that computed the wrong name would read and write another
 * tenant's ledger and every row would look correct, because the physical
 * database really would be the one the id named.
 */
import type { TenantDataNamespace, TenantDataObject } from "@ferrogate/storage/durable-objects";
import { HttpError } from "../middleware/errors.js";
import { TENANT_DATABASE_ROUTING_MISCONFIGURED, TENANT_DATABASE_UNAVAILABLE } from "./ports.js";

/**
 * The binding this module reads.
 *
 * Optional, because a self-hosted deployment on `"off"`, `"binding"` or
 * `"shared_development"` legitimately declares no stanza. Absent while the mode
 * IS `durable_object` — the committed default — is a NAMED 503 below, never a
 * fallback to `env.DB`.
 */
export interface TenantDataBindings {
  readonly TENANT_DATA?: TenantDataNamespace;
}

/**
 * The `TENANT_DATA` namespace, or a 503 naming what is missing.
 *
 * The parameter is called `env` on purpose: `test/env-var-drift.test.ts`
 * anchors its "no dead binding stanza" scan on the literal token `env.X`, and a
 * binding declared in `wrangler.toml` that no `src/` file reads is dead config
 * by that gate's definition. Renaming this parameter would make the read
 * invisible to the gate and the stanza would read as dead.
 */
export function tenantDataNamespace(env: TenantDataBindings): TenantDataNamespace {
  const namespace = env.TENANT_DATA;
  if (namespace === undefined) {
    throw new HttpError(
      503,
      TENANT_DATABASE_ROUTING_MISCONFIGURED,
      [
        "per-tenant Durable Object storage is selected but this Worker has no TENANT_DATA",
        "namespace bound; declare the [[durable_objects.bindings]] stanza and redeploy.",
        "This request is refused rather than served from the shared database.",
      ].join(" "),
    );
  }
  return namespace;
}

/**
 * The Durable Object stub holding `tenantId`'s database.
 *
 * A blank tenant id is REFUSED, not addressed. `routableTenantId`
 * (`src/tenancy/middleware.ts`) returns `""` for an UNCLASSIFIED credential —
 * `callerScope` classes it as a tenant carrying the empty-string id, which is
 * unforgeable as a real tenant id and so matches no registry row. (It returns
 * `null` only for a platform operator, which `tenantDatabase()` turns into a
 * 403 `tenant_database_unscoped` before anything reaches here; an earlier
 * revision of this note said `""` was the only value, which the `null` arm at
 * `middleware.ts:110` falsifies.) `idFromName("")` is a
 * perfectly valid id, so without this check that unforgeable sentinel would
 * instead name one shared object that every unclassified caller lands in —
 * a fallback database by accident, which is the one thing this directory
 * exists to prevent.
 */
export function tenantDataObjectFor(
  env: TenantDataBindings,
  tenantId: string,
): DurableObjectStub<TenantDataObject> {
  if (tenantId.trim() === "") {
    throw new HttpError(
      503,
      TENANT_DATABASE_UNAVAILABLE,
      [
        "refusing to address a tenant data object for an empty tenant id;",
        "an unclassified credential has no tenant database.",
      ].join(" "),
    );
  }
  const namespace = tenantDataNamespace(env);
  return namespace.get(namespace.idFromName(tenantId));
}
