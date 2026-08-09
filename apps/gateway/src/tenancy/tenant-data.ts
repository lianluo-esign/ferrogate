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
 * `storage = "sqlite"` in `[exports.TenantDataObject]` is **immutable once a
 * namespace exists** — changing it later is `storage_type_mismatch`, and
 * converting requires a `deleted` tombstone and total data loss. That is why the
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
import {
  type TenantObjectAddress,
  type TenantObjectNamespaceLike,
  tenantObjectStubFor,
} from "@ferrogate/storage";
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
 * A stub facade that re-derives the REAL stub on every property access.
 *
 * A `DurableObjectStub` is a request-scoped I/O object: workerd refuses
 * "I/O on behalf of a different request" the moment a stub created inside one
 * request handler is used from another. Several consumers of
 * {@link tenantDataObjectFor} deliberately memoize what they build from it on
 * the ENV OBJECT — `MeteringUsageSink.#backends` caches a `D1LedgerStore`
 * wrapping this stub once per isolate — and that device is sound for D1 and
 * Queue bindings (env-scoped) but not for stubs. The second request's
 * `ctx.waitUntil` drain then flushed billing through the FIRST request's stub
 * and workerd rejected it after the response had been served, in the one place
 * nobody is watching.
 *
 * Re-deriving here is correct because the address is pure data:
 * `idFromName(tenantId)` is a pure function and `namespace.get(id)` is an
 * in-isolate allocation, so every property access hands back a stub born in
 * the CURRENT request context while still addressing exactly the same object.
 * The tenant id is captured once and cannot be re-pointed, which preserves the
 * facade property `DurableObjectD1Database` documents: a handle that could
 * re-address itself would be a handle that could address the wrong tenant.
 */
function requestSafeTenantDataStub(
  derive: () => DurableObjectStub<TenantDataObject>,
): DurableObjectStub<TenantDataObject> {
  return new Proxy({} as DurableObjectStub<TenantDataObject>, {
    get(_target, property) {
      const value = Reflect.get(derive() as object, property);
      if (typeof value !== "function") {
        return value;
      }
      // NOT `value.bind(stub)`: an RPC method property is itself a remote
      // proxy, so calling `.bind` on it is an RPC to a method named "bind".
      // The stub is re-derived AT INVOCATION time instead, so the I/O happens
      // on a stub born in the caller's own request context.
      return (...args: unknown[]) => {
        const stub = derive() as unknown as Record<
          string | symbol,
          (...forwarded: unknown[]) => unknown
        >;
        const method = stub[property];
        if (typeof method !== "function") {
          // Unreachable while namespaces answer the same shape for the same
          // address; refusing beats invoking undefined on a billing path.
          throw new TypeError(`tenant data object stub exposes no callable ${String(property)}`);
        }
        // Member-style invocation (receiver = the fresh stub), so an RPC
        // property proxy behaves exactly as `stub.method(...)` would.
        return Reflect.apply(method, stub, args);
      };
    },
    has(_target, property) {
      return Reflect.has(derive() as object, property);
    },
  });
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
  address?: TenantObjectAddress,
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
  return requestSafeTenantDataStub(() =>
    tenantObjectStubFor(
      namespace as unknown as TenantObjectNamespaceLike<
        DurableObjectStub<TenantDataObject>,
        DurableObjectId
      >,
      tenantId,
      address,
    ),
  );
}
