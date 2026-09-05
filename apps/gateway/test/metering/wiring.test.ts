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
 * ## Two gates, two different failure modes
 *
 * 1. A STRUCTURAL assertion against the exported `GATEWAY_MIDDLEWARE`. It fails
 *    if the drain is unmounted OR REORDERED — order is something no behavioural
 *    test can see, because a correctly-ordered and a merely-present drain both
 *    bill the happy path identically.
 * 2. A BEHAVIOURAL assertion that drives a full authenticated completion through
 *    `SELF.fetch` — i.e. through `export default app` in `src/index.ts`, exactly
 *    what `wrangler deploy` ships — and reads the resulting row back out of the
 *    real `PLATFORM_DATA` object (Track A hard-cut: an unattributed `fg_root`
 *    charge now settles there, not into the removed control billing mirror). It
 *    fails if the drain is unmounted, if the sink is
 *    dropped from `GATEWAY_ROUTE_MODULES`, if `meteringBindingsFromEnv` stops
 *    resolving, or if the ledger SQL stops landing. The structural gate sees
 *    none of those last three.
 *
 * Neither subsumes the other, so both stay.
 *
 * ## How the behavioural gate got a completion to meter
 *
 * The blocker used to be that `vitest.config.ts` pins `GATEWAY_MODELS` /
 * `GATEWAY_PROVIDERS` EMPTY so the suite is hermetic — every `SELF` request
 * answered `400 model_not_found` and never reached the sink. Two things fix that
 * without giving up hermeticity, and neither is a substitute for production code:
 *
 *  - `@cloudflare/vitest-pool-workers` runs each TEST FILE in its own isolate and
 *    hands the tests the SAME `env` object the Worker receives, so a `beforeAll`
 *    in this file can populate the registry vars for this file only. That is the
 *    device `test/guardrails/wiring.test.ts` already uses for
 *    `GATEWAY_GUARDRAIL_POLICIES`.
 *  - the upstream is a FAKE served by `interceptProviderFetch`
 *    (`test/inference/provider-mock.ts`), which replaces `globalThis.fetch` —
 *    the exact seam `fetchDispatcher` reads at call time. The real relay is never
 *    contacted; an unexpected outbound request THROWS rather than escaping.
 *
 * Everything between the HTTP request and the SQLite row is the deployed
 * article: the deployed `contractAuth`, the deployed `GATEWAY_MIDDLEWARE`, the
 * deployed model catalog parser, the deployed dispatcher, the module-scoped
 * `createMeteringUsageSink({ bindings: meteringBindingsFromEnv })`, and the real
 * `env.PLATFORM_DATA` / `env.BILLING` bindings `wrangler.toml` declares (the
 * unattributed leg's authoritative store after the Track A billing hard-cut).
 */

import { SELF, env } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, test } from "vitest";

import { GATEWAY_MIDDLEWARE } from "../../src/index.js";
import {
  type ProviderInterceptor,
  interceptProviderFetch,
  providerJson,
} from "../inference/provider-mock.js";
import {
  platformBillingDb,
  platformRowCount,
  resetMeteringTables,
  resetPlatformBilling,
} from "./d1-harness.js";

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

// ---------------------------------------------------------------------------
// The behavioural gate
// ---------------------------------------------------------------------------

/** Logical model the fake registry publishes to clients. */
const LOGICAL_MODEL = "wiring-probe";
/**
 * PHYSICAL model put on the wire — and its served offering must carry a price.
 * `src/index.ts` settles production traffic from the route that actually
 * served it, so this row is deliberately priced here. A pair that is priced
 * NOWHERE still writes no LEDGER row, which would be indistinguishable from
 * an unmounted drain. Pricing the pair is what makes a missing row mean
 * exactly one thing — this file is a mount gate, not a pricing test.
 *
 * That unpriced case is NOT out of scope for the suite, it just belongs
 * elsewhere: `test/metering/unpriced.test.ts` drives this same deployed article
 * with a model outside the default card and asserts both #663 outcomes — a
 * registry-row-priced model lands a fully priced ledger row, and a model priced
 * nowhere lands a cost-less `billing_events` row instead of vanishing.
 */
const PROVIDER_MODEL = "gpt-4o-mini";
/** Name of the Worker secret binding the fake provider's credential lives in. */
const PROVIDER_KEY_VAR = "WIRING_PROBE_PROVIDER_KEY";
/** A host that exists nowhere. Reaching it for real is a test failure, not a bill. */
const UPSTREAM = "https://upstream.invalid/v1";

const bindings = env as unknown as Record<string, unknown>;

let provider: ProviderInterceptor | undefined;

/**
 * Publish a one-model registry onto the env the Worker reads.
 *
 * `beforeAll`, before the first `SELF.fetch` in this file, because the router
 * memoizes `modelsFromEnv(env)` per env object — a var written after the first
 * request would be invisible. Confined to this file's isolate, so
 * `test/contract.test.ts`'s empty-registry assertions are untouched.
 */
beforeAll(() => {
  bindings[PROVIDER_KEY_VAR] = "sk-wiring-probe";
  bindings.GATEWAY_PROVIDERS = JSON.stringify([
    {
      name: "wiring-probe-provider",
      kind: "openai",
      base_url: UPSTREAM,
      api_key_var: PROVIDER_KEY_VAR,
    },
  ]);
  bindings.GATEWAY_MODELS = JSON.stringify([
    {
      name: LOGICAL_MODEL,
      provider: "wiring-probe-provider",
      provider_model: PROVIDER_MODEL,
      capabilities: ["chat"],
      input_price_per_1m: 0.15,
      output_price_per_1m: 0.6,
    },
  ]);
});

beforeEach(async () => {
  await resetMeteringTables();
  // Track A hard-cut: the unattributed `fg_root` completion now settles into the
  // PLATFORM_DATA object, so the behavioural gate reads and resets it.
  await resetPlatformBilling();
});

afterEach(() => {
  provider?.restore();
  provider = undefined;
});

/** A canonical buffered chat completion, with the usage block the tap reads. */
const COMPLETION = {
  id: "chatcmpl-wiring",
  object: "chat.completion",
  model: PROVIDER_MODEL,
  choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
  usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
};

/**
 * Wait for the drain that `meteringDrain` handed to `ctx.waitUntil`.
 *
 * `SELF.fetch` resolves when the RESPONSE is flushed; the durable write is
 * deliberately after that (see `src/metering/middleware.ts`), and
 * `cloudflare:test` exposes no `waitOnExecutionContext` for a `SELF` call. So
 * the row is polled for, with a bounded budget: it appears in single-digit
 * milliseconds when the drain is mounted, and the budget expires — loudly —
 * when it is not.
 */
async function awaitLedgerRow(budgetMs = 2000): Promise<number> {
  const deadline = Date.now() + budgetMs;
  for (;;) {
    const rows = await platformRowCount("billing_ledger");
    if (rows > 0) {
      return rows;
    }
    if (Date.now() >= deadline) {
      return 0;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

describe("composition root — a completion through SELF lands a billing row in D1", () => {
  test("the app the Worker exports meters a real completion end to end", async () => {
    provider = interceptProviderFetch((request) =>
      request.url.startsWith(UPSTREAM) ? providerJson(COMPLETION) : undefined,
    );

    // Nothing is asserted about the ledger yet, so a row already present would
    // make the proof vacuous. Start from zero, explicitly.
    expect(await platformRowCount("billing_ledger")).toBe(0);

    const response = await SELF.fetch("https://gw.test/v1/chat/completions", {
      method: "POST",
      headers: { authorization: "Bearer fg_root", "content-type": "application/json" },
      body: JSON.stringify({ model: LOGICAL_MODEL, messages: [{ role: "user", content: "hi" }] }),
    });

    // The request really completed through the deployed pipeline — auth,
    // drain, rate limit, guardrails, Zod, registry resolve, dispatch.
    expect(response.status).toBe(200);
    expect(((await response.json()) as { id: string }).id).toBe("chatcmpl-wiring");

    // …and the LOGICAL name was translated to the physical one before egress,
    // which is what proves the fake upstream was reached through the registry
    // rather than by accident.
    expect(provider.lastRequest().url).toBe(`${UPSTREAM}/chat/completions`);
    expect((provider.lastRequest().body as { model: string }).model).toBe(PROVIDER_MODEL);

    // THE ASSERTION. Deleting `meteringDrain(usage)` from `GATEWAY_MIDDLEWARE`
    // in src/index.ts leaves everything above green and turns this line red:
    // the sink is built with a `bindings` resolver, so `record()` captures into
    // the outbox and deliberately schedules no drain of its own.
    expect(await awaitLedgerRow()).toBe(1);

    // The row is a real, priced settlement of THIS request, not an empty
    // placeholder: the billing event row is committed in the same D1 `batch()`
    // (#150) and the outbox intent is reaped once the Queue accepted it.
    expect(await platformRowCount("billing_events")).toBe(1);

    const ledger = await platformBillingDb()
      .prepare(
        "SELECT billing_ledger.id AS id, entry_json, billing_events.request_id AS request_id " +
          "FROM billing_ledger " +
          "JOIN billing_events ON billing_events.billing_event_id = billing_ledger.id",
      )
      .all();
    const row = ledger.results?.[0] as
      | { id: string; request_id: string; entry_json: string }
      | undefined;
    const entry = JSON.parse(row?.entry_json ?? "{}") as {
      request_id: string;
      logical_model: string;
      provider: string;
      provider_model: string;
      cost: { total_cost: number };
    };
    // The two rows are the SAME settlement, keyed on the ledger entry id — the
    // property the single-`batch()` commit (#150) exists to guarantee.
    expect(row?.request_id).toBe(entry.request_id);
    // …and it is THIS request's settlement, correlated by the id the gateway
    // put on the response.
    expect(entry.request_id).toBe(response.headers.get("x-request-id"));
    // The registry indirection survives all the way into the ledger: the
    // tenant is billed against the physical model, labelled by the logical one.
    expect(entry.logical_model).toBe(LOGICAL_MODEL);
    expect(entry.provider_model).toBe(PROVIDER_MODEL);
    // 11 prompt @ $0.15/1M + 4 completion @ $0.60/1M = $4.05e-6. A zero here
    // would be the "billed at zero" failure #129 exists to prevent.
    expect(entry.cost.total_cost).toBeCloseTo(4.05e-6, 12);
  });

  test("a request that never reaches an upstream bills nothing", async () => {
    // The complement, and the reason the test above is not trivially true: the
    // drain runs on EVERY request, so "a row exists" must not be something the
    // middleware can produce on its own.
    provider = interceptProviderFetch(() => undefined);

    const response = await SELF.fetch("https://gw.test/v1/chat/completions", {
      method: "POST",
      headers: { authorization: "Bearer fg_root", "content-type": "application/json" },
      body: JSON.stringify({ model: "no-such-model", messages: [{ role: "user", content: "hi" }] }),
    });

    expect(response.status).toBe(400);
    expect(provider.requests).toHaveLength(0);
    expect(await platformRowCount("billing_ledger")).toBe(0);
  });
});
