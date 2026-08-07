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
  const stub = namespace.get(namespace.idFromName(CONTROL_DATA_ADDRESS));
  return new DurableObjectD1Database(CONTROL_DATA_ADDRESS, stub).asD1Database();
}
