/**
 * Issue #663 — a billable request whose model is not in the DEFAULT RATE CARD
 * must still be recorded.
 *
 * ## What this file pins, and why the rest of the suite could not see it
 *
 * The live cloud verification served a real `POST /v1/chat/completions` (200,
 * 377 prompt + 12 completion tokens) against a model absent from
 * `PriceBook.withDefaultRateCard()`, and `billing_ledger`, `billing_events` and
 * `billing_report_outbox` all stayed at ZERO rows. The customer was served, the
 * provider was paid, and FerroGate kept no record of it at all.
 *
 * The suite was green because both existing tests steer around exactly this
 * input: `test/metering/wiring.test.ts` deliberately pins a PRICED physical
 * model (see its `PROVIDER_MODEL` note), and `test/metering/gateway.test.ts`
 * asserted the zero-row outcome as correct. So this file drives the SAME
 * deployed article `wiring.test.ts` does — `SELF.fetch` into `export default
 * app` from `src/index.ts`, the real `env.BILLING_DB` — and changes exactly one
 * variable: the physical model the registry publishes is one the default card
 * has never heard of.
 *
 * Two models, because the defect has two halves and they have DIFFERENT correct
 * outcomes:
 *
 *  1. `ROW_PRICED_MODEL` carries `input_price_per_1m` / `output_price_per_1m` on
 *     its `[[models]]` row. Those numbers were parsed by `inference/catalog.ts`
 *     and read ONLY by cost-based routing; nothing carried them into metering.
 *     The correct outcome is a fully priced ledger row at the row's own prices.
 *  2. `NO_PRICE_MODEL` carries no prices anywhere. `charge()` fails closed and
 *     must NOT invent a $0 bill (#129) — but the usage still happened, so the
 *     correct outcome is Rust's: a `billing_events` row with a null `cost_usd`,
 *     recoverable and re-priceable, rather than silence.
 *
 * Both assertions are red on the pre-fix tree.
 */

import { SELF, env } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, test } from "vitest";

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

/** Logical names the fake registry publishes. */
const ROW_PRICED_LOGICAL = "unpriced-probe-row-priced";
const NO_PRICE_LOGICAL = "unpriced-probe-no-price";

/**
 * PHYSICAL models put on the wire. Neither appears in
 * `PriceBook.withDefaultRateCard()` — that is the whole point, and
 * `the default rate card really does not know these models` below asserts it
 * rather than trusting the name.
 */
const ROW_PRICED_MODEL = "gate-663-row-priced";
const NO_PRICE_MODEL = "gate-663-no-price";

/** Row prices for `ROW_PRICED_MODEL`, in USD per 1M tokens. */
const INPUT_PRICE_PER_1M = 3.0;
const OUTPUT_PRICE_PER_1M = 15.0;

/** The token counts the live verification observed, reused verbatim. */
const PROMPT_TOKENS = 377;
const COMPLETION_TOKENS = 12;

/**
 * The exact settled cost the row prices imply:
 * 377/1e6 × $3.00 + 12/1e6 × $15.00 = $0.001131 + $0.00018 = $0.001311.
 */
const EXPECTED_COST_USD =
  (PROMPT_TOKENS / 1_000_000) * INPUT_PRICE_PER_1M +
  (COMPLETION_TOKENS / 1_000_000) * OUTPUT_PRICE_PER_1M;

const PROVIDER_KEY_VAR = "UNPRICED_PROBE_PROVIDER_KEY";
/** A host that exists nowhere. Reaching it for real is a test failure, not a bill. */
const UPSTREAM = "https://unpriced-upstream.invalid/v1";

const bindings = env as unknown as Record<string, unknown>;

let provider: ProviderInterceptor | undefined;

/**
 * Publish the two-model registry onto the env the Worker reads.
 *
 * `beforeAll`, before the first `SELF.fetch` in this file, because the router
 * memoizes `modelsFromEnv(env)` per env object. `@cloudflare/vitest-pool-workers`
 * gives each test FILE its own isolate, so this is confined here.
 */
beforeAll(() => {
  bindings[PROVIDER_KEY_VAR] = "sk-unpriced-probe";
  bindings.GATEWAY_PROVIDERS = JSON.stringify([
    {
      name: "unpriced-probe-provider",
      kind: "openai",
      base_url: UPSTREAM,
      api_key_var: PROVIDER_KEY_VAR,
    },
  ]);
  bindings.GATEWAY_MODELS = JSON.stringify([
    {
      name: ROW_PRICED_LOGICAL,
      provider: "unpriced-probe-provider",
      provider_model: ROW_PRICED_MODEL,
      capabilities: ["chat"],
      input_price_per_1m: INPUT_PRICE_PER_1M,
      output_price_per_1m: OUTPUT_PRICE_PER_1M,
    },
    {
      name: NO_PRICE_LOGICAL,
      provider: "unpriced-probe-provider",
      provider_model: NO_PRICE_MODEL,
      capabilities: ["chat"],
    },
  ]);
});

beforeEach(async () => {
  await resetMeteringTables();
  // Track A hard-cut: the unattributed `fg_root` path now settles into the
  // PLATFORM_DATA object, so this suite reads and resets the platform tables.
  await resetPlatformBilling();
});

afterEach(() => {
  provider?.restore();
  provider = undefined;
});

/** A buffered completion carrying the usage block the tap reads. */
function completion(model: string): Record<string, unknown> {
  return {
    id: `chatcmpl-${model}`,
    object: "chat.completion",
    model,
    choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
    usage: {
      prompt_tokens: PROMPT_TOKENS,
      completion_tokens: COMPLETION_TOKENS,
      total_tokens: PROMPT_TOKENS + COMPLETION_TOKENS,
    },
  };
}

/**
 * Wait for a durable row, with a bounded budget — the drain runs on
 * `ctx.waitUntil` after `SELF.fetch` has already resolved, and `cloudflare:test`
 * exposes no `waitOnExecutionContext` for a `SELF` call. Same device
 * `wiring.test.ts` uses.
 */
async function awaitRow(
  table: "billing_ledger" | "billing_events",
  budgetMs = 2000,
): Promise<number> {
  const deadline = Date.now() + budgetMs;
  for (;;) {
    const rows = await platformRowCount(table);
    if (rows > 0) return rows;
    if (Date.now() >= deadline) return 0;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

/** Drive one authenticated completion through the deployed Worker. */
async function complete(logicalModel: string, physicalModel: string): Promise<Response> {
  provider = interceptProviderFetch((request) =>
    request.url.startsWith(UPSTREAM) ? providerJson(completion(physicalModel)) : undefined,
  );
  const response = await SELF.fetch("https://gw.test/v1/chat/completions", {
    method: "POST",
    headers: { authorization: "Bearer fg_root", "content-type": "application/json" },
    body: JSON.stringify({ model: logicalModel, messages: [{ role: "user", content: "hi" }] }),
  });
  expect(response.status).toBe(200);
  return response;
}

describe("#663 — an unpriced model is still recorded", () => {
  test("the default rate card really does not know either probe model", async () => {
    // The negative control for both tests below. If some future edit seeds
    // these ids into `withDefaultRateCard()`, the two tests would pass through
    // the rate-card branch and prove nothing about the registry prices — this
    // says so out loud instead.
    const { PriceBook } = await import("@ferrogate/billing");
    const card = PriceBook.withDefaultRateCard();
    expect(card.priceFor("unpriced-probe-provider", ROW_PRICED_MODEL)).toBeUndefined();
    expect(card.priceFor("unpriced-probe-provider", NO_PRICE_MODEL)).toBeUndefined();
  });

  test("a model priced only by its registry row lands a fully priced ledger row", async () => {
    expect(await platformRowCount("billing_ledger")).toBe(0);

    const response = await complete(ROW_PRICED_LOGICAL, ROW_PRICED_MODEL);

    // The physical model really went on the wire, so the registry indirection
    // (and its prices) is the thing under test.
    expect((provider?.lastRequest().body as { model: string }).model).toBe(ROW_PRICED_MODEL);

    // THE ASSERTION (#663). Before the fix this is 0: `#price` threw
    // `price_not_found` and returned upstream of every durable write.
    expect(await awaitRow("billing_ledger")).toBe(1);
    expect(await platformRowCount("billing_events")).toBe(1);

    const result = await platformBillingDb().prepare("SELECT id, entry_json FROM billing_ledger").all();
    const row = result.results?.[0] as { id: string; entry_json: string } | undefined;
    const entry = JSON.parse(row?.entry_json ?? "{}") as {
      request_id: string;
      provider_model: string;
      cost: { total_cost: number };
      cost_source: string;
      usage: { prompt_tokens: number; completion_tokens: number };
    };
    expect(entry.request_id).toBe(response.headers.get("x-request-id"));
    expect(entry.provider_model).toBe(ROW_PRICED_MODEL);
    expect(entry.usage.prompt_tokens).toBe(PROMPT_TOKENS);
    expect(entry.usage.completion_tokens).toBe(COMPLETION_TOKENS);
    // The EXACT cost the registry row implies — not zero, and not some other
    // model's card price.
    expect(entry.cost.total_cost).toBeCloseTo(EXPECTED_COST_USD, 12);
    // …and it is labelled as gateway-settled, because the data plane priced it.
    expect(entry.cost_source).toBe("gateway_settled");
  });

  test("a model priced NOWHERE still leaves a durable, re-priceable trace", async () => {
    expect(await platformRowCount("billing_events")).toBe(0);

    const response = await complete(NO_PRICE_LOGICAL, NO_PRICE_MODEL);

    // THE ASSERTION (#663). Before the fix this is 0 — the usage vanished.
    // Rust's `append_billing_event_with_outbox_enqueue` ran regardless of
    // whether a `cost_usd` was settled; only the wallet debit was skipped.
    expect(await awaitRow("billing_events")).toBe(1);

    const result = await platformBillingDb()
      .prepare("SELECT billing_event_id, request_id, event_json FROM billing_events")
      .all();
    const row = result.results?.[0] as
      | { billing_event_id: string; request_id: string; event_json: string }
      | undefined;
    const event = JSON.parse(row?.event_json ?? "{}") as {
      provider_model: string;
      cost_usd?: number | null;
      usage: { prompt_tokens: number; completion_tokens: number };
    };
    expect(row?.request_id).toBe(response.headers.get("x-request-id"));
    expect(event.provider_model).toBe(NO_PRICE_MODEL);
    // The tokens are what makes it RE-PRICEABLE once the operator adds a rule.
    expect(event.usage.prompt_tokens).toBe(PROMPT_TOKENS);
    expect(event.usage.completion_tokens).toBe(COMPLETION_TOKENS);
    // NULL cost, never 0 — a $0 bill for a real call is the free-inference bug
    // #129 exists to prevent, and this row must not be mistaken for one.
    expect(event.cost_usd ?? null).toBeNull();

    // And it is NOT a charge: nothing was billed, nothing was reported.
    expect(await platformRowCount("billing_ledger")).toBe(0);
    expect(await platformRowCount("billing_report_outbox")).toBe(0);
  });
});
