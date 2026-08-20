/**
 * Node-safe access to the control Durable Object (Zero-D1 S1, issue #877).
 *
 * The control twin of `tenant-do.ts`, and importable from plain node for the
 * same reason: every reference to `control-data-object.ts` (which imports
 * `cloudflare:workers`) is `import type`, so this module carries no runtime
 * dependency on the Worker runtime and stays reachable from the node-only
 * vitest suites and `apps/cli`.
 *
 * The facade itself is NOT duplicated: `DurableObjectD1Database` already
 * forwards `prepare/bind/first/all/run` and a whole `batch()` into one stub
 * RPC, and `ControlDataObject.query`/`batch` take the same request shapes with
 * the `tenantId` field carrying the fixed address `"control"`. What this
 * module adds is the addressing: ONE well-known instance,
 * `idFromName("control")`, and a constructor that can never be called with a
 * tenant id by mistake because it takes no id at all.
 */
import type { TenantDataBatchRequest, TenantDataQueryRequest } from "./tenant-data-object.js";
import type { TenantDataResult } from "./tenant-data-object.js";
import { DurableObjectD1Database } from "./tenant-do.js";

/**
 * The single well-known address of the control object. Re-declared here (and
 * pinned equal by `test/do/control-data-object.test.ts`, which runs under
 * workerd and can import both modules) rather than imported from
 * `control-data-object.ts`, because a VALUE import of that module would drag
 * `cloudflare:workers` into node-only consumers.
 */
export const CONTROL_DATA_ADDRESS = "control";

/**
 * The data RPCs the facade calls on a `ControlDataObject` stub. Structural,
 * for the same reason `TenantDataStub` is: `DurableObjectStub<…>` types would
 * import the workerd-only module.
 */
export interface ControlDataStub {
  query(request: TenantDataQueryRequest): Promise<TenantDataResult>;
  batch(request: TenantDataBatchRequest): Promise<TenantDataResult[]>;
}

/** The `env.CONTROL_DATA` namespace, structurally. */
export interface ControlDataNamespaceLike {
  idFromName(name: string): unknown;
  get(id: unknown, options?: { locationHint?: string }): ControlDataStub;
}

/**
 * The control database as a `D1Database`.
 *
 * This is the value a Zero-D1 seam (S2–S4) hands to code that used to hold
 * `env.CONTROL_DB` / `env.DB` / `env.BILLING_DB`: same interface, same atomic
 * `batch()` (one `transactionSync` inside the object), different backend.
 */
export function controlDataObjectDatabase(namespace: ControlDataNamespaceLike): D1Database {
  // Resolve a FRESH stub per top-level operation rather than capturing one at
  // construction. A `DurableObjectStub` is request-bound — its I/O objects
  // "cannot be accessed from a different request's handler" (workerd) — and the
  // control database, unlike a per-request tenant handle, is memoized across
  // requests by its consumers (the tenancy resolver, the site-domain directory,
  // the guardrail store, …). A single cached stub would therefore throw
  // "Cannot perform I/O on behalf of a different request" on the SECOND request
  // that reused the cached facade. Re-addressing `idFromName("control")` per
  // operation is cheap (it is a routing lookup, not a wake) and keeps every
  // query in the context of the request that issued it. The tenant path avoids
  // this by resolving a new handle per request via `forTenant`; the singleton
  // control facade has no such per-request resolution, so it lazies here.
  const fresh = (): D1Database => {
    // Hint is honored only on first creation. This fleet's control object is
    // Tokyo-homed so login and quota reads are in-region for APAC clients.
    const stub = namespace.get(namespace.idFromName(CONTROL_DATA_ADDRESS), {
      locationHint: "apac-ne",
    });
    return new DurableObjectD1Database(CONTROL_DATA_ADDRESS, stub).asD1Database();
  };
  return new Proxy({} as D1Database, {
    get(_target, prop) {
      const db = fresh() as unknown as Record<string | symbol, unknown>;
      const value = db[prop];
      return typeof value === "function"
        ? (value as (...args: unknown[]) => unknown).bind(db)
        : value;
    },
  });
}

/**
 * Wrap a real `CONTROL_D1` binding as the replica-reading handle for the
 * READ-ONLY control consumers (gateway/agent-runtime/mcp).
 *
 * `first-unconstrained` lets the first (and every) read land on ANY replica
 * consistent with the session bookmark, so a globally-distributed reader gets a
 * colo-local replica instead of a cross-region hop to the single Tokyo primary.
 * These consumers never write control rows, so eventual consistency with a
 * just-committed control-plane write is acceptable — the same posture the
 * per-colo `api_key_directory` KV projection (#882) already runs under.
 *
 * The single writer (control-plane) does NOT go through here: it holds the
 * plain `env.CONTROL_D1` binding, which routes to the primary, so it reads its
 * own writes unconditionally with no bookmark plumbing.
 *
 * A `D1DatabaseSession` exposes exactly the `prepare`/`batch` surface every
 * control consumer uses; `exec`/`dump`/`withSession` are never called on a
 * control handle (verified across `apps/*` and `packages/storage`), so
 * presenting the session as a `D1Database` is sound — mirroring how the DO
 * facade's own `exec`/`dump`/`withSession` throw rather than being reachable.
 */
export function controlD1ReplicaDatabase(db: D1Database): D1Database {
  return db.withSession("first-unconstrained") as unknown as D1Database;
}
