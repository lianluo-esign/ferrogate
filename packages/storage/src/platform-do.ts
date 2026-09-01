/**
 * Node-safe access to the platform Durable Object (Zero-D1 Plan B).
 *
 * The platform sibling of `control-do.ts` / `tenant-do.ts`, importable from
 * plain node for the same reason: every reference to `platform-data-object.ts`
 * (which imports `cloudflare:workers`) is `import type`, so this module carries
 * no runtime dependency on the Worker runtime and stays reachable from the
 * node-only vitest suites and `apps/cli`.
 *
 * The facade itself is NOT duplicated: `DurableObjectD1Database` already
 * forwards `prepare/bind/first/all/run` and a whole `batch()` into one stub
 * RPC, and `PlatformDataObject.query`/`batch` take the same request shapes with
 * the `tenantId` field carrying the fixed address `"platform"`. What this
 * module adds is the addressing: ONE well-known instance,
 * `idFromName("platform")`, and a constructor that can never be called with a
 * tenant id by mistake because it takes no id at all.
 *
 * Unlike `control-do.ts` there is NO replica-reading leg: the platform object
 * is pure-DO (there is no `PLATFORM_D1` binding to fall back to), so every
 * reader addresses the one object directly.
 */
import type { TenantDataBatchRequest, TenantDataQueryRequest } from "./tenant-data-object.js";
import type { TenantDataResult } from "./tenant-data-object.js";
import { DurableObjectD1Database } from "./tenant-do.js";

/**
 * The single well-known address of the platform object. Re-declared here (and
 * pinned equal by `test/do/platform-data-object.test.ts`, which runs under
 * workerd and can import both modules) rather than imported from
 * `platform-data-object.ts`, because a VALUE import of that module would drag
 * `cloudflare:workers` into node-only consumers.
 */
export const PLATFORM_DATA_ADDRESS = "platform";

/**
 * The data RPCs the facade calls on a `PlatformDataObject` stub. Structural,
 * for the same reason `TenantDataStub` is: `DurableObjectStub<…>` types would
 * import the workerd-only module.
 */
export interface PlatformDataStub {
  query(request: TenantDataQueryRequest): Promise<TenantDataResult>;
  batch(request: TenantDataBatchRequest): Promise<TenantDataResult[]>;
}

/** The `env.PLATFORM_DATA` namespace, structurally. */
export interface PlatformDataNamespaceLike {
  idFromName(name: string): unknown;
  get(id: unknown, options?: { locationHint?: string }): PlatformDataStub;
}

/**
 * The platform database as a `D1Database`.
 *
 * This is the value a Zero-D1 Plan B seam hands to code that used to read/write
 * the control projection's platform-scoped (`tenant IS NULL`) guardrail rows:
 * same interface, same atomic `batch()` (one `transactionSync` inside the
 * object), a dedicated singleton backend.
 */
export function platformDataObjectDatabase(namespace: PlatformDataNamespaceLike): D1Database {
  // Resolve a FRESH stub per top-level operation rather than capturing one at
  // construction — identical rationale to `controlDataObjectDatabase`. A
  // `DurableObjectStub` is request-bound ("cannot be accessed from a different
  // request's handler"), and the platform database, like the control one, is
  // memoized across requests by its consumers (the gateway evidence sink, the
  // operator fleet reader). A single cached stub would throw "Cannot perform
  // I/O on behalf of a different request" on the SECOND request that reused the
  // cached facade. Re-addressing `idFromName("platform")` per operation is
  // cheap (a routing lookup, not a wake) and keeps every query in the context
  // of the request that issued it.
  const fresh = (): D1Database => {
    // Hint is honored only on first creation, and takes effect just once per
    // address. "apac" is the valid CF region token for this APAC fleet; the
    // earlier "apac-ne" was not a valid hint and was ignored. This is a token
    // correctness fix — it re-homes only a future fresh platform object, not
    // the one already materialized at PLATFORM_DATA_ADDRESS.
    const stub = namespace.get(namespace.idFromName(PLATFORM_DATA_ADDRESS), {
      locationHint: "apac",
    });
    return new DurableObjectD1Database(PLATFORM_DATA_ADDRESS, stub).asD1Database();
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
