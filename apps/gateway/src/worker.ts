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
import app, { gatewayScheduled } from "./index.js";

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
