/**
 * The harness Worker the tenancy specs drive through `SELF`.
 *
 * ## Why this exists rather than driving `src/worker.ts`
 *
 * Two things this slice may not touch are required for a REAL per-tenant D1
 * topology: `[[d1_databases]]` stanzas for each tenant in
 * `apps/gateway/wrangler.toml`, and the `tenantDatabase()` entry in
 * `GATEWAY_MIDDLEWARE` in `apps/gateway/src/index.ts`. Both belong to the
 * integrate step (see the WIRING block in `src/tenancy/index.ts`).
 *
 * So this module is a SECOND ENTRY POINT over the SAME composition root, not a
 * second app — the shape `test/ratelimit/harness/worker.ts` established:
 *
 *  - it calls the real {@link createGatewayApp}, not a bespoke `new Hono()`, so
 *    the real `contractAuth` guard runs and `c.get("auth")` is the real
 *    `AuthContext` the deployed Worker would resolve;
 *  - it mounts the real `GATEWAY_ROUTE_MODULES` imported from `src/index.ts`,
 *    so the routes are the deployed ones and cannot drift;
 *  - it passes `middleware: [tenantDatabase()]`, which is the EXACT zero-edit
 *    line documented for the integrate step.
 *
 * That last point is what makes `mount.spec.ts` a real unmount gate: deleting
 * `tenantDatabase()` from the array below turns those assertions red and leaves
 * every other spec in the suite green.
 */
import { GATEWAY_ROUTE_MODULES } from "../../../src/index.js";
import { createGatewayApp } from "../../../src/routes/index.js";
import { tenantDatabase } from "../../../src/tenancy/index.js";

/**
 * workerd resolves a `[[durable_objects.bindings]]` `class_name` against the
 * ENTRY module's named exports — a class merely reachable through the import
 * graph is NOT found, and the isolate refuses to start. This line is the
 * harness's copy of `apps/gateway/src/worker.ts:140`; deleting it makes every
 * spec in this suite fail to boot, which is the correct (if blunt) signal.
 */
export { TenantDataObject } from "@ferrogate/storage/durable-objects";

/**
 * The `CONTROL_DATA` Durable Object class — the singleton `ControlDataObject`
 * that is the control database (Zero-D1 S5, #914). Same workerd startup rule as
 * `TenantDataObject` above: `class_name = "ControlDataObject"` in
 * `harness/wrangler.toml` resolves against THIS entry module, so without this
 * re-export the harness isolate refuses to boot. It is the harness's copy of
 * `apps/gateway/src/worker.ts`'s CONTROL_DATA export, and it is what makes
 * `controlDatabaseFrom(env)` resolve a real facade instead of the retired
 * `d1_compat` `CONTROL_DB` leg.
 */
export { ControlDataObject } from "@ferrogate/storage/durable-objects";

const { app } = createGatewayApp({
  modules: [...GATEWAY_ROUTE_MODULES],
  // THE MOUNT UNDER TEST. `harness/wrangler.toml` pins
  // `GATEWAY_TENANT_DB_ROUTING = "binding_strict"`, so every tenant-scoped
  // credential must resolve to a routable D1 database before its request is
  // served — which is what makes the mount observable over HTTP.
  middleware: [tenantDatabase()],
});

export default app;
