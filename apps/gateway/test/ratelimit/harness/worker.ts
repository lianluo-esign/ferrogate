/**
 * The harness Worker the rate-limit suite drives through `SELF`.
 *
 * ## Why this exists rather than testing `src/worker.ts` directly
 *
 * A REAL Durable Object binding needs two things this slice is not allowed to
 * touch: a `[[durable_objects.bindings]]` + `[[migrations]]` block in
 * `apps/gateway/wrangler.toml`, and `export { RateLimiterDurableObject }` on
 * `apps/gateway/src/worker.ts`. Both belong to the integrate step (see the
 * WIRING block in `src/ratelimit/index.ts`). Until they land, the app the
 * deployed Worker exports has no `RATE_LIMIT` namespace and cannot exercise the
 * DO at all.
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
import { rateLimitRouteModule } from "../../../src/ratelimit/index.js";
import { createGatewayApp } from "../../../src/routes/index.js";

/**
 * Per-credential `request_limit_per_minute` (TOK-12), keyed by api key id.
 * In production this column rides on the API-key row; `AuthContext` in
 * `src/ports.ts` does not carry it yet, so the harness injects it.
 */
const PER_KEY_RPM: Record<string, number | undefined> = {
  key_perkey_rpm: 2,
};

const { app } = createGatewayApp({
  modules: [
    // FIRST, so it precedes every module route — see `rateLimitRouteModule`.
    rateLimitRouteModule({
      perKeyRequestLimit: (auth) => PER_KEY_RPM[auth.subject ?? ""],
      // Settlement is opt-in and absent in Rust; the harness turns it on so the
      // reservation/settlement split is actually exercised.
      settleTokens: true,
    }),
    ...GATEWAY_ROUTE_MODULES,
  ],
});

export default app;

// The line `src/worker.ts` must gain. workerd resolves a DO binding's
// `class_name` against the ENTRY module, so without this the harness Worker
// fails to start with "Durable Object class RateLimiterDurableObject not found".
export { RateLimiterDurableObject } from "../../../src/ratelimit/index.js";
