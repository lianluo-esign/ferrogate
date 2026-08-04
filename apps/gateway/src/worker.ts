/**
 * The deploy entrypoint — the module `wrangler.toml`'s `main` points at.
 *
 * ## Why this file exists rather than `main = "src/index.ts"`
 *
 * workerd treats EVERY named export of the entry module as a service
 * entrypoint, and rejects any whose value is not a function, an
 * `ExportedHandler`, or a `WorkerEntrypoint`/`DurableObject` class. `index.ts`
 * deliberately exports the anti-drift surface the gate inspects
 * (`GATEWAY_ROUTE_MODULES`, `gatewayRouter`, …), which are arrays and objects.
 * Pointing `main` there fails the Worker AT STARTUP:
 *
 *     service core:user:ferrogate-gateway: Uncaught TypeError: Incorrect type
 *     for map entry 'EXPECTED_OPERATION_COUNT': the provided value is not of
 *     type 'function or ExportedHandler'.
 *
 * `@cloudflare/vitest-pool-workers` does NOT reproduce this — it boots the
 * module without the entrypoint-shape check — so the whole suite stayed green
 * on a Worker that could not start under real `wrangler dev`. The E2E harness
 * is what surfaced it.
 *
 * So the composition root stays in `index.ts` (tests keep importing its named
 * exports, and the gate keeps asserting the registry of the app the Worker
 * really serves); this module re-exports ONLY the default handler, which is the
 * exact object `index.ts` built. Nothing is re-assembled here — adding a route
 * to this file instead of the composition root would be the drift the gate
 * exists to catch.
 */
import app, { gatewayQueue, gatewayScheduled } from "./index.js";
import type { RequestLogMessageBatch } from "./requestlog/index.js";

/**
 * The deployed handler.
 *
 * `fetch` is the Hono app `index.ts` built — nothing is re-assembled here, and
 * delegating through an arrow keeps the app's own `this` regardless of how Hono
 * binds it.
 *
 * `scheduled` is the `[triggers] crons` entry point. workerd only dispatches a
 * scheduled event to a handler found on the ENTRY module's default export, so a
 * named `export { gatewayScheduled }` here would be ignored (and, being a
 * function, silently accepted as a service entrypoint instead) — the Cron would
 * fire against a Worker with no handler and the billing-outbox recovery would
 * never run. That is why this file grew from a bare `export { default }` into an
 * explicit `ExportedHandler`.
 */
const handler: ExportedHandler<Record<string, unknown>> = {
  fetch: (request, env, ctx) => app.fetch(request, env, ctx),
  scheduled: (controller, env, ctx) => gatewayScheduled(controller, env, ctx),
  /**
   * `queue` is the `[[queues.consumers]]` entry point for the request-log
   * queue (#664), and it is here for exactly the reason `scheduled` is:
   * workerd only dispatches a queue event to a handler found on the ENTRY
   * module's DEFAULT export. A named `export { gatewayQueue }` would be
   * ignored — and, being a function, silently accepted as a service entrypoint
   * instead — so the queue would fill and dead-letter with nothing consuming
   * it, and every request log would be lost after the producer had already
   * reported success.
   */
  queue: (batch, env) => gatewayQueue(batch as unknown as RequestLogMessageBatch, env),
};

export default handler;

/**
 * The `RATE_LIMIT` Durable Object class.
 *
 * workerd resolves a `[[durable_objects.bindings]]` `class_name` against the
 * ENTRY module — this file — so without this line the Worker fails AT STARTUP
 * with "Durable Object class RateLimiterDurableObject not found", and
 * `@cloudflare/vitest-pool-workers` does not reproduce that check, so the whole
 * unit suite would stay green on an unbootable Worker. That is exactly the
 * defect the docblock above describes, in its second form.
 *
 * A DO class is a LEGAL named export of the entry module: the restriction
 * documented above is on non-handler, non-class VALUES (arrays, plain objects),
 * which is why `GATEWAY_ROUTE_MODULES` and friends stay in `index.ts`.
 *
 * `bunx wrangler dev --local` booting and answering `/healthz` is the proof;
 * see `test/ratelimit/harness/` for the same export under vitest.
 */
export { RateLimiterDurableObject } from "./ratelimit/index.js";

/**
 * The `PROVIDER_CIRCUIT` Durable Object class — the cross-isolate provider
 * circuit breaker (`src/inference/circuit-do.ts`).
 *
 * Same startup rule as `RateLimiterDurableObject` above: workerd resolves the
 * `[[durable_objects.bindings]]` `class_name` against THIS module, so without
 * this line `wrangler dev` fails with "Durable Object class
 * ProviderCircuitDurableObject not found" while the whole vitest suite stays
 * green (`@cloudflare/vitest-pool-workers` does not run the entrypoint-shape
 * check).
 *
 * One instance per provider NAME, so a wedged provider concentrates on one
 * object; provider names come from the operator's `GATEWAY_PROVIDERS` table,
 * never from a caller, so no request input can choose a DO id.
 */
export { ProviderCircuitDurableObject } from "./inference/index.js";

/**
 * The `SHADOW_BUDGET` Durable Object class — the cross-isolate spend cap on
 * shadow (mirror) traffic (`@ferrogate/routing/durable-objects`, reached from
 * `src/inference/shadow.ts::shadowBudgetFor`).
 *
 * Same startup rule as the two classes above: workerd resolves the
 * `[[durable_objects.bindings]]` `class_name` against THIS module, so without
 * this line `wrangler dev` fails with "Durable Object class
 * ShadowBudgetDurableObject not found" while the vitest suite stays green.
 *
 * Unbound, `shadowBudgetFor` degrades to a PER-ISOLATE ledger, which caps
 * shadow spend by a bounded factor rather than absolutely — deliberately not
 * "no cap". Bound, it is the only cross-isolate cap the platform offers.
 */
export { ShadowBudgetDurableObject } from "@ferrogate/routing/durable-objects";

/**
 * The `TENANT_DATA` Durable Object class — one SQLite-backed object per tenant,
 * which IS that tenant's database (#822,
 * `@ferrogate/storage/durable-objects`, addressed from
 * `src/tenancy/tenant-data.ts` as `env.TENANT_DATA.idFromName(tenantId)`).
 *
 * Same startup rule as the three classes above: workerd resolves the
 * `[[durable_objects.bindings]]` `class_name` against THIS module, so without
 * this line `wrangler dev` fails with "Durable Object class TenantDataObject
 * not found" while the vitest suite stays green.
 *
 * IT IS ALSO THE FOURTH CLASS AND THE FIRST THAT IS NOT DEGRADABLE. The other
 * three have a documented per-isolate fallback — a weaker limiter, a weaker
 * breaker, a weaker spend cap. This one holds the tenant's wallet, usage and
 * asset rows; there is no degraded mode, and `src/tenancy/ports.ts`'s
 * fail-closed rule means an unresolvable tenant is a 503, never the shared
 * database. Unbound, `tenantDataNamespace()` raises
 * `tenant_database_routing_misconfigured` rather than falling back.
 *
 * `apps/gateway/test/wrangler-bindings.test.ts` closes the loop from the CONFIG
 * side, and `packages/storage/test/mount-inventory.test.ts` from the library
 * side; deleting this line reddens both.
 */
export { TenantDataObject } from "@ferrogate/storage/durable-objects";
