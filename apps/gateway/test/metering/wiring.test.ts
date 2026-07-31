/**
 * Anti-drift gate for the DURABLE METERING MOUNT.
 *
 * ## Why this file exists
 *
 * `meteringDrain` is the flush step: it awaits `next()`, then calls
 * `sink.flush(rc)` — on `ctx.waitUntil`, and for an SSE response only after
 * `observeBodyCompletion` settles. Without it, usage is still captured into the
 * sink by the inference layer but is NEVER written to D1 or enqueued to the
 * billing outbox. That is a total loss of billing data with no error anywhere.
 *
 * That regression was UNCAUGHT. Deleting `meteringDrain(usage)` from
 * `GATEWAY_MIDDLEWARE` in `src/index.ts` left all 794 gateway tests green,
 * because every durable-metering test calls `sink.flush()` directly (or drives
 * `app.fetch` with a hand-built app) instead of exercising the middleware chain
 * the deployed Worker actually composes. Same defect class as the composition
 * root that once mounted zero route modules while its suites passed.
 *
 * ## What this proves — and what it does not
 *
 * This is a STRUCTURAL assertion against the exported `GATEWAY_MIDDLEWARE`, not
 * a behavioural one. It fails if the drain is unmounted or reordered; it does
 * NOT prove a ledger row lands (`test/metering/durable.test.ts` covers the
 * persistence itself).
 *
 * A behavioural `SELF.fetch` proof is not available here: the test harness pins
 * the model registry EMPTY (so the suite is hermetic and never reaches an
 * upstream), so no request through `SELF` can produce a metered completion —
 * see the header of `test/metering/durable.test.ts`. Closing that gap needs a
 * harness that can serve a fake upstream through the composed app; until then
 * this gate is the honest half, and it is the half that catches the deletion.
 */

import { describe, expect, test } from "vitest";

import { GATEWAY_MIDDLEWARE } from "../../src/index.js";

/** Runtime names of the handlers `GATEWAY_MIDDLEWARE` is built from. */
const METERING_DRAIN = "meteringDrainMiddleware";
const RATE_LIMIT = "rateLimitMiddleware";

describe("composition root — durable metering is mounted", () => {
  const names = GATEWAY_MIDDLEWARE.map((handler) => handler.name);

  test("the drain the deployed Worker composes is present", () => {
    // Deleting `meteringDrain(usage)` from src/index.ts turns this red. Nothing
    // else in the suite does.
    expect(names).toContain(METERING_DRAIN);
  });

  test("the drain runs FIRST, so it wraps every later middleware's response", () => {
    // Order is load-bearing, not cosmetic: the drain is the only middleware
    // that does its work AFTER `next()` resolves. Registered after `rateLimit`
    // or `guardrails`, a response those two short-circuit (429 / 403) would
    // never reach it, and the usage captured for that request would be dropped.
    expect(names[0]).toBe(METERING_DRAIN);
    expect(names.indexOf(METERING_DRAIN)).toBeLessThan(names.indexOf(RATE_LIMIT));
  });

  test("every middleware in the production list is a real handler", () => {
    // A guard against an entry silently becoming `undefined` — e.g. an import
    // cycle resolving late — which would make the `toContain` above pass on a
    // list that cannot run.
    for (const handler of GATEWAY_MIDDLEWARE) {
      expect(typeof handler).toBe("function");
      // Hono middleware is `(c, next) => ...`; a zero-arity entry means a
      // factory was mounted instead of the handler it returns.
      expect(handler.length).toBeGreaterThan(0);
    }
  });
});
