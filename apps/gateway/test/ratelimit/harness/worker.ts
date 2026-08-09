/**
 * The harness Worker the rate-limit suite drives through `SELF`.
 *
 * ## Why this exists rather than testing `src/worker.ts` directly
 *
 * A REAL Durable Object binding needs two things this slice is not allowed to
 * touch: a `[[durable_objects.bindings]]` + `[exports.RateLimiterDurableObject]`
 * block in
 * `apps/gateway/wrangler.toml`, and `export { RateLimiterDurableObject }` on
 * `apps/gateway/src/worker.ts`. Both are also present in the deployed Worker;
 * this harness keeps a separate entry point so the suite can provide its own
 * data and options without changing production configuration.
 *
 * So this module is a SECOND ENTRY POINT over the SAME composition root, not a
 * second app:
 *
 *  - it calls the real {@link createGatewayApp} — not a bespoke `new Hono()`;
 *  - it mounts the real `GATEWAY_ROUTE_MODULES` imported from `src/index.ts`,
 *    so the routes are the deployed ones and cannot drift;
 *  - it inserts `rateLimitRouteModule()`, which is the exact zero-edit wiring
 *    documented for the integrate step;
 *  - it re-exports the DO class from the ENTRY module, which is precisely the
 *    line `src/worker.ts` must gain. Booting this harness under a wrangler
 *    config that binds `RATE_LIMIT` to `RateLimiterDurableObject` is what
 *    proves that export resolves.
 *
 * `harness/wrangler.toml` supplies the binding, the migration, the API-key
 * table and the quota-policy table.
 */
import { GATEWAY_ROUTE_MODULES } from "../../../src/index.js";
import { quotaPolicySourceFromVars, rateLimitRouteModule } from "../../../src/ratelimit/index.js";
import { createGatewayApp } from "../../../src/routes/index.js";
import { tenantDatabase } from "../../../src/tenancy/index.js";

/**
 * Per-credential `request_limit_per_minute` (TOK-12), keyed by api key id.
 * In production this column rides on the API-key row; `AuthContext` in
 * `src/ports.ts` does not carry it yet, so the harness injects it.
 */
const PER_KEY_RPM: Record<string, number | undefined> = {
  key_perkey_rpm: 2,
};

const { app } = createGatewayApp({
  // `tenantDatabase()` — and ONLY it — from the deployed chain. Since #819 the
  // inference route module and the admission ladder read `tenantDatabaseOf(c)`,
  // which is a deliberate 500 on any Worker that mounts the routes without the
  // middleware; this harness was such a composition. The FULL deployed
  // `GATEWAY_MIDDLEWARE` cannot be reused here because it contains its own
  // `rateLimit()`, which would stack on `rateLimitRouteModule` below and
  // charge every request twice. The posture stays storage-free via
  // `GATEWAY_TENANT_DB_ROUTING = "off"` in `harness/wrangler.toml`: the
  // accessor exists, every wallet/budget/spend arm degrades to its documented
  // no-storage answer, and the RATE_LIMIT Durable Object stays the only
  // admission gate — which is what these specs exist to drive.
  middleware: [tenantDatabase()],
  modules: [
    // FIRST, so it precedes every module route — see `rateLimitRouteModule`.
    rateLimitRouteModule({
      perKeyRequestLimit: (auth) => PER_KEY_RPM[auth.subject ?? ""],
      // Settlement is opt-in and absent in Rust; the harness turns it on so the
      // reservation/settlement split is actually exercised.
      settleTokens: true,
      // This harness carries its quota policies + plans in `[vars]`
      // (`GATEWAY_QUOTA_POLICIES` / `GATEWAY_PLANS`), the posture the specs
      // assert against. The default `quotaPolicySourceFromEnv` would read the
      // CONTROL object's `quota_policies` table instead now that `CONTROL_DATA`
      // is bound (for tenancy resolution) — and that object is empty, which
      // would silence every window. Pin the var-based source explicitly.
      quotas: quotaPolicySourceFromVars,
    }),
    ...GATEWAY_ROUTE_MODULES,
  ],
});

export default app;

// The line `src/worker.ts` must gain. workerd resolves a DO binding's
// `class_name` against the ENTRY module, so without this the harness Worker
// fails to start with "Durable Object class RateLimiterDurableObject not found".
export { RateLimiterDurableObject } from "../../../src/ratelimit/index.js";

// Since #821 PR2-delete the storage-free `"off"` posture is retired: the ONLY
// tenant-data path is the per-tenant Durable Object, and `durable_object`
// (the default) NAMES a 503 when `TENANT_DATA` is absent. So the harness binds
// the same tenant + control objects the deployed Worker does — the model
// catalog and admission ladder resolve an (empty) tenant object and answer 200,
// leaving the RATE_LIMIT object the sole admission gate these specs drive.
// workerd resolves each `class_name` against this ENTRY module, so both are
// re-exported here exactly as `src/worker.ts` does.
export { ControlDataObject, TenantDataObject } from "@ferrogate/storage/durable-objects";
