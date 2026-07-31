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
export { default } from "./index.js";

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
