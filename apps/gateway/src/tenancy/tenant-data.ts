/**
 * Addressing for `TenantDataObject` — the SQLite-backed Durable Object that IS
 * a tenant's database (issue #822,
 * `docs/design/per-tenant-durable-object-storage-2026-08.md`).
 *
 * ## Why this module exists NOW, ahead of the router that will use it
 *
 * `storage = "sqlite"` / `new_sqlite_classes` is **immutable once a namespace
 * exists** — changing it later is `storage_type_mismatch`, and converting
 * requires a `deleted` tombstone and total data loss. So the `TENANT_DATA`
 * stanza in `wrangler.toml` has to be right in the FIRST deploy, before the
 * `D1Database`-shaped facade and the `durable_object` routing mode land. This
 * file is the half of that pairing that lives in source: the one place the
 * binding is read, and the one place a blank tenant id is refused.
 *
 * It is deliberately NOT a {@link TenantDatabaseRouter}. `forTenant()` must
 * return a `TenantDatabaseHandle` carrying a `D1Database`, and that facade —
 * `prepare().bind().first()/all()/run()`, a synthesized `meta.changes`, and
 * `batch()` forwarded into `transactionSync` — is the next slice. Shipping a
 * half-router that some call site could reach would be worse than shipping
 * none: the fail-closed rule in `./ports.ts` is that an unresolvable tenant is
 * an error, never a fallback, and a partially-wired mode is exactly how a
 * fallback gets added "temporarily".
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
 * Optional, because the committed `GATEWAY_TENANT_DB_ROUTING = "off"` means no
 * request reaches here yet and a self-hosted single-tenant deploy may never
 * declare it. Absent is a NAMED refusal below, never a fallback to `env.DB`.
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
 * A blank tenant id is REFUSED, not addressed. `src/tenancy/middleware.ts`
 * returns `""` (never `null`) for a credential it could not confine to a
 * tenant, precisely so that it matches no registry row; `idFromName("")` is a
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
