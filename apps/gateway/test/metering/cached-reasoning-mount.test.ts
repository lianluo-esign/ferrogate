/**
 * ANTI-UNMOUNT for #667 — the cached / cache-write / reasoning counters, from a
 * real provider frame to the row that is really stored, through the DEPLOYED
 * Worker.
 *
 * ## Why this file exists alongside `cached-reasoning-tokens.test.ts`
 *
 * That file is a UNIT suite. It proves `usageFromResponseBody` normalizes each
 * family, that `billingEventFromUsage` copies the three counters off a `Usage`,
 * and that `charge()` prices them. Every one of those tests builds the `Usage`
 * it feeds with its own `usageFor()` helper — a helper that duplicates, spread
 * for spread, the join `src/inference/handlers.ts::recordUsage` performs. So the
 * suite held on a hand-made object and said nothing about whether the gateway
 * ever hands `billingEventFromUsage` one. Deleting the `#667` block of
 * `recordUsage` left the whole gateway suite green, and zeroing the rollup write
 * in `src/metering/usage-ledger.ts::usageWriteFor` left it green too.
 *
 * This file closes both. **Nothing here constructs a `Usage`, a `BillingEvent`
 * or a `UsageAggregateWrite`.** The only inputs are an HTTP request and the
 * bytes a stubbed upstream returns; the only outputs read are rows in real D1:
 *
 *   SELF.fetch                                (src/worker.ts → src/index.ts)
 *     → contract router → auth → meteringDrain → dispatch
 *     → usageFromResponseBody / sseUsageTap    (capture)
 *     → recordUsage                            <-- THE JOIN UNDER TEST
 *     → MeteringUsageSink.record → charge()
 *     → ctx.waitUntil(drain)
 *     → billing_events.event_json              (env.BILLING_DB — control)
 *       billing_ledger.entry_json
 *     → usage_aggregate_rollups                (env.DB — tenant)
 *       usage_monthly_rollups
 *
 * ## Why `SELF` and not `app.fetch(request, env, ctx)`
 *
 * The sibling metering suites build their own app because `src/worker.ts` runs
 * with `GATEWAY_MODELS` pinned EMPTY by `vitest.config.ts`, so every request
 * would answer `400 model_not_found`. `test/inference/shadow-mount.test.ts`
 * shows the way around that without giving up the deployed entrypoint: override
 * the `[vars]` on `env` for the duration of the file, exactly as a real
 * deployment's `[env.<name>.vars]` does. Everything else — the module-scope
 * `createMeteringUsageSink`, the middleware order, the price book, the
 * `BILLING_DB` / `DB` bindings — is the deployed composition, untouched.
 *
 * ## The rule every case obeys
 *
 * Nothing here seeds `billing_events`, `billing_ledger`, `usage_aggregate_rollups`
 * or `usage_monthly_rollups`. Every number an assertion reads was put in D1 by a
 * request that went through the production join.
 */
import { SELF, env } from "cloudflare:test";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { billingDb, resetMeteringTables } from "./d1-harness.js";

const BASE = "https://gw.test";

const ANTHROPIC_HOST = "api.anthropic-probe.example";
const OPENAI_HOST = "api.openai-probe.example";

/**
 * Two probe providers. `api_key_var` is deliberately absent — it names a SECRET
 * binding and the upstream here is a stub, so there is no credential to carry.
 */
const PROVIDERS = JSON.stringify([
  { name: "anthropic-probe", kind: "anthropic", base_url: `https://${ANTHROPIC_HOST}/v1` },
  { name: "openai-probe", kind: "openai", base_url: `https://${OPENAI_HOST}/v1` },
]);

/**
 * Two logical models, each with the serving offering prices used by the
 * assertions below. The values mirror the former default card entries, but
 * they are stated on the route so this production test does not depend on a
 * wildcard rate card:
 *
 *  - `claude-sonnet-4` — $3.00 / $15.00, cache read 0.1x, cache write 1.25x;
 *  - `gpt-4o`          — $2.50 / $10.00, cache read 0.5x.
 *
 * The cache/read, cache/write and reasoning prices are explicit too; otherwise
 * the serving route would conservatively use its ordinary input/output rate.
 */
const MODELS = JSON.stringify([
  {
    name: "cache-probe",
    provider: "anthropic-probe",
    provider_model: "claude-sonnet-4",
    input_price_per_1m: 3.0,
    output_price_per_1m: 15.0,
    cached_input_price_per_1m: 0.3,
    cache_write_price_per_1m: 3.75,
  },
  {
    name: "reasoning-probe",
    provider: "openai-probe",
    provider_model: "gpt-4o",
    input_price_per_1m: 2.5,
    output_price_per_1m: 10.0,
    cached_input_price_per_1m: 1.25,
    reasoning_price_per_1m: 10.0,
  },
]);

/**
 * The credential every request below authenticates with.
 *
 * It carries a `project_id` because `usage_aggregate_rollups` is joined to
 * `tenant_contexts`, and the api-key id is what `meteringDrain` puts on the
 * attribution — i.e. the rollup assertions are only meaningful with a
 * tenant-scoped native key, not the operator root key.
 */
const KEY_ID = "key_cache_probe";
const NATIVE_KEYS = JSON.stringify([
  {
    key: "fg_cache_probe",
    id: KEY_ID,
    tenant_id: "tenant_a",
    project_id: "project_cache",
    scopes: [],
  },
]);

const OVERRIDES: Record<string, string> = {
  GATEWAY_PROVIDERS: PROVIDERS,
  GATEWAY_MODELS: MODELS,
  GATEWAY_NATIVE_API_KEYS: NATIVE_KEYS,
};

const ORIGINAL: Record<string, unknown> = {};
const mutable = env as unknown as Record<string, unknown>;

beforeAll(() => {
  for (const [name, value] of Object.entries(OVERRIDES)) {
    ORIGINAL[name] = mutable[name];
    mutable[name] = value;
  }
});

afterAll(() => {
  for (const [name, value] of Object.entries(ORIGINAL)) {
    mutable[name] = value;
  }
});

// ---------------------------------------------------------------------------
// Provider payloads — the shapes the vendors document, verbatim.
// ---------------------------------------------------------------------------

/**
 * Anthropic `/v1/messages`, buffered. `input_tokens` is the FRESH input only,
 * so the normalized prompt total is 1 000 + 5 000 + 20 000 = 26 000.
 */
const ANTHROPIC_MESSAGE = {
  id: "msg_667",
  type: "message",
  role: "assistant",
  model: "claude-sonnet-4",
  content: [{ type: "text", text: "hello" }],
  stop_reason: "end_turn",
  usage: {
    input_tokens: 1_000,
    cache_creation_input_tokens: 5_000,
    cache_read_input_tokens: 20_000,
    output_tokens: 500,
  },
};

/**
 * The same request STREAMED. Anthropic reports the cache counters ONCE, on
 * `message_start`; the terminal `message_delta` carries only `output_tokens`.
 * That split is the whole reason the merge rule is prefer-new-fall-back-to-old,
 * and it is why the streaming leg needs its own end-to-end case: a
 * newer-absence-wins merge would store 0 cached tokens here and 20 000 above,
 * from one identical request.
 */
const ANTHROPIC_STREAM_FRAMES: readonly string[] = [
  'data: {"type":"message_start","message":{"id":"msg_667s","type":"message","role":"assistant",' +
    '"model":"claude-sonnet-4","content":[],"usage":{"input_tokens":1000,' +
    '"cache_creation_input_tokens":5000,"cache_read_input_tokens":20000,"output_tokens":0}}}',
  'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}',
  'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":500}}',
  'data: {"type":"message_stop"}',
];

/**
 * OpenAI chat completions. `prompt_tokens` INCLUDES the cached subset and
 * `completion_tokens` INCLUDES the reasoning subset — the opposite convention
 * to Anthropic's, which is why the reasoning counter needs its own case.
 */
const OPENAI_COMPLETION = {
  id: "chatcmpl-667",
  object: "chat.completion",
  model: "gpt-4o",
  choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
  usage: {
    prompt_tokens: 10_000,
    completion_tokens: 2_000,
    total_tokens: 12_000,
    prompt_tokens_details: { cached_tokens: 8_000 },
    completion_tokens_details: { reasoning_tokens: 1_500 },
  },
};

/** One SSE frame, framed the way a provider frames it. */
function frame(payload: unknown): string {
  return `data: ${JSON.stringify(payload)}`;
}

/**
 * The same, streamed: OpenAI puts the whole usage object on ONE terminal frame,
 * and it is the SAME object the buffered response carries — so the two OpenAI
 * cases below differ only in how the bytes arrived.
 */
const OPENAI_STREAM_FRAMES: readonly string[] = [
  frame({
    id: "chatcmpl-667s",
    object: "chat.completion.chunk",
    model: "gpt-4o",
    choices: [{ index: 0, delta: { role: "assistant", content: "ok" }, finish_reason: null }],
  }),
  frame({
    id: "chatcmpl-667s",
    object: "chat.completion.chunk",
    model: "gpt-4o",
    choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
  }),
  frame({
    id: "chatcmpl-667s",
    object: "chat.completion.chunk",
    model: "gpt-4o",
    choices: [],
    usage: OPENAI_COMPLETION.usage,
  }),
  "data: [DONE]",
];

// ---------------------------------------------------------------------------
// Upstream stub. Only the two probe hosts are intercepted.
// ---------------------------------------------------------------------------

interface Upstream {
  restore(): void;
}

function stubUpstream(respond: (host: string) => Response): Upstream {
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const host = new URL(url).hostname;
    if (host !== ANTHROPIC_HOST && host !== OPENAI_HOST) {
      return await original(input as RequestInfo, init);
    }
    return respond(host);
  }) as typeof fetch;
  return {
    restore(): void {
      globalThis.fetch = original;
    },
  };
}

function json(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function sse(frames: readonly string[]): Response {
  const encoder = new TextEncoder();
  return new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        for (const frame of frames) controller.enqueue(encoder.encode(`${frame}\n\n`));
        controller.close();
      },
    }),
    { status: 200, headers: { "content-type": "text/event-stream" } },
  );
}

// ---------------------------------------------------------------------------
// The stored rows.
// ---------------------------------------------------------------------------

const tenantDb = (env as unknown as { DB: D1Database }).DB;

/** The three counters as `billing_events.event_json` really holds them. */
interface StoredUsage {
  readonly prompt_tokens: number;
  readonly completion_tokens: number;
  readonly total_tokens: number;
  readonly cached_input_tokens: number;
  readonly cache_write_tokens: number;
  readonly reasoning_tokens: number;
}

/**
 * Poll `billing_events` until the drain has landed a row.
 *
 * The drain runs on `ctx.waitUntil`, which by construction outlives the
 * response `SELF.fetch` resolves with, and `SELF` gives no handle on it — so a
 * bounded poll is the honest way to wait. It never invents a row: the timeout
 * throws.
 */
async function storedEvent(): Promise<{ usage: StoredUsage; model: string; source: string }> {
  for (let attempt = 0; attempt < 400; attempt += 1) {
    const row = await billingDb()
      .prepare("SELECT event_json FROM billing_events LIMIT 1")
      .first<{ event_json: string }>();
    if (row !== null && row !== undefined) {
      const event = JSON.parse(row.event_json) as {
        usage: StoredUsage;
        provider_model: string;
        usage_source: string;
      };
      return { usage: event.usage, model: event.provider_model, source: event.usage_source };
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("timed out waiting for the deployed Worker to store a billing_events row");
}

/** The settled cost, as `billing_ledger.entry_json` really holds it. */
async function storedCostUsd(): Promise<number> {
  const row = await billingDb()
    .prepare("SELECT entry_json FROM billing_ledger LIMIT 1")
    .first<{ entry_json: string }>();
  if (row === null || row === undefined) throw new Error("no billing_ledger row was stored");
  return (JSON.parse(row.entry_json) as { cost: { total_cost: number } }).cost.total_cost;
}

interface StoredRollup {
  readonly prompt_tokens: number;
  readonly completion_tokens: number;
  readonly total_tokens: number;
  readonly cached_input_tokens: number;
  readonly cache_write_tokens: number;
  readonly reasoning_tokens: number;
  readonly api_key_id: string | null;
}

/** Poll `usage_aggregate_rollups`, joined to the context it is filed under. */
async function storedRollup(): Promise<StoredRollup> {
  for (let attempt = 0; attempt < 400; attempt += 1) {
    const row = await tenantDb
      .prepare(
        "SELECT r.prompt_tokens, r.completion_tokens, r.total_tokens, r.cached_input_tokens, " +
          "r.cache_write_tokens, r.reasoning_tokens, c.api_key_id " +
          "FROM usage_aggregate_rollups r JOIN tenant_contexts c ON c.id = r.tenant_context_id",
      )
      .first<StoredRollup>();
    if (row !== null && row !== undefined) return row;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("timed out waiting for the deployed Worker to accumulate a rollup row");
}

// ---------------------------------------------------------------------------

let upstream: Upstream | undefined;

beforeEach(async () => {
  await resetMeteringTables();
  await tenantDb.prepare("DELETE FROM usage_aggregate_rollups").run();
  await tenantDb.prepare("DELETE FROM usage_monthly_rollups").run();
  await tenantDb.prepare("DELETE FROM tenant_contexts").run();
});

afterEach(() => {
  upstream?.restore();
  upstream = undefined;
});

async function call(path: string, body: unknown): Promise<Response> {
  return await SELF.fetch(`${BASE}${path}`, {
    method: "POST",
    headers: {
      authorization: "Bearer fg_cache_probe",
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

/** Drain a streamed response so the tap's `flush()` runs, as a client would. */
async function drain(response: Response): Promise<void> {
  await response.text();
}

// ---------------------------------------------------------------------------
// 1. The join: capture → billing event → the row that is stored.
// ---------------------------------------------------------------------------

describe("a served request stores its cached/cache-write/reasoning counters (#667)", () => {
  it("BUFFERED Anthropic: the stored billing event carries all three", async () => {
    upstream = stubUpstream(() => json(ANTHROPIC_MESSAGE));

    const response = await call("/v1/messages", {
      model: "cache-probe",
      max_tokens: 64,
      messages: [{ role: "user", content: "does the join exist in production" }],
    });
    expect(response.status).toBe(200);

    const stored = await storedEvent();
    expect(stored.model).toBe("claude-sonnet-4");
    // 1 000 fresh + 5 000 cache-write + 20 000 cache-read. The pre-#667 answer
    // was 1 000 — this number alone proves the capture reached the store.
    expect(stored.usage.prompt_tokens).toBe(26_000);
    expect(stored.usage.cached_input_tokens).toBe(20_000);
    expect(stored.usage.cache_write_tokens).toBe(5_000);
    expect(stored.usage.completion_tokens).toBe(500);
    // Anthropic folds extended thinking into `output_tokens` and reports no
    // separate counter, so the stored value is the wire default, not a claim.
    expect(stored.usage.reasoning_tokens).toBe(0);
  });

  it("BUFFERED Anthropic: and the ledger row is priced on them", async () => {
    upstream = stubUpstream(() => json(ANTHROPIC_MESSAGE));

    await call("/v1/messages", {
      model: "cache-probe",
      max_tokens: 64,
      messages: [{ role: "user", content: "price it" }],
    });
    await storedEvent();

    //   fresh       1 000 / 1e6 * 3.00  = 0.003
    //   cache read 20 000 / 1e6 * 0.30  = 0.006      (the card's 0.1x)
    //   cache write 5 000 / 1e6 * 3.75  = 0.01875    (the card's 1.25x)
    //   output        500 / 1e6 * 15.00 = 0.0075
    //                                     ---------
    //                                     0.03525
    expect(await storedCostUsd()).toBeCloseTo(0.03525, 12);
  });

  it("STREAMED Anthropic: the counters from message_start survive to the row", async () => {
    upstream = stubUpstream(() => sse(ANTHROPIC_STREAM_FRAMES));

    const response = await call("/v1/messages", {
      model: "cache-probe",
      max_tokens: 64,
      stream: true,
      messages: [{ role: "user", content: "stream it" }],
    });
    expect(response.status).toBe(200);
    // The client really was served a stream — so the row below came off the SSE
    // tap, not the buffered handler.
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    await drain(response);

    const stored = await storedEvent();
    // Not a `gateway_estimate`: the counters were SCRAPED off the frames.
    expect(stored.source).toBe("provider_usage");
    expect(stored.usage.prompt_tokens).toBe(26_000);
    expect(stored.usage.cached_input_tokens).toBe(20_000);
    expect(stored.usage.cache_write_tokens).toBe(5_000);
    expect(stored.usage.completion_tokens).toBe(500);
    // The buffered case above stored 0.03525 for the same numbers; a streamed
    // request that lost `message_start` would settle at 0.0105 instead.
    expect(await storedCostUsd()).toBeCloseTo(0.03525, 12);
  });

  it("BUFFERED OpenAI: the reasoning and cached SUBSETS reach the row", async () => {
    upstream = stubUpstream(() => json(OPENAI_COMPLETION));

    const response = await call("/v1/chat/completions", {
      model: "reasoning-probe",
      messages: [{ role: "user", content: "think" }],
    });
    expect(response.status).toBe(200);

    const stored = await storedEvent();
    // OpenAI's totals already INCLUDE the subsets, so these two stay as reported
    // while the subsets appear beside them.
    expect(stored.usage.prompt_tokens).toBe(10_000);
    expect(stored.usage.completion_tokens).toBe(2_000);
    expect(stored.usage.cached_input_tokens).toBe(8_000);
    expect(stored.usage.reasoning_tokens).toBe(1_500);
    // OpenAI's automatic caching carries no cache-WRITE charge.
    expect(stored.usage.cache_write_tokens).toBe(0);

    //   fresh      2 000 / 1e6 * 2.50  = 0.005
    //   cache read 8 000 / 1e6 * 1.25  = 0.010   (the card's 0.5x)
    //   output     2 000 / 1e6 * 10.00 = 0.020   (reasoning bills as output)
    //                                    ---------
    //                                    0.035
    expect(await storedCostUsd()).toBeCloseTo(0.035, 12);
  });

  it("STREAMED OpenAI: the terminal usage frame's subsets reach the row", async () => {
    upstream = stubUpstream(() => sse(OPENAI_STREAM_FRAMES));

    const response = await call("/v1/chat/completions", {
      model: "reasoning-probe",
      stream: true,
      messages: [{ role: "user", content: "think out loud" }],
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    await drain(response);

    const stored = await storedEvent();
    expect(stored.source).toBe("provider_usage");
    expect(stored.usage.cached_input_tokens).toBe(8_000);
    expect(stored.usage.reasoning_tokens).toBe(1_500);
    expect(await storedCostUsd()).toBeCloseTo(0.035, 12);
  });
});

// ---------------------------------------------------------------------------
// 2. The rollup write.
// ---------------------------------------------------------------------------

/**
 * `usage_aggregate_rollups` is what the report API reads to EXPLAIN a bill —
 * which portion of a charge was a cache read, which was reasoning. Before this
 * file the gateway-side write of those three columns
 * (`src/metering/usage-ledger.ts::usageWriteFor`) had no test at all: the only
 * coverage was `packages/storage`'s, through a `persistUsageAggregate` call the
 * test supplied the arguments to, which cannot notice that nothing in `apps/`
 * ever supplies them.
 */
describe("a served request accumulates the same counters into the rollup (#667)", () => {
  it("BUFFERED Anthropic: the persisted aggregate carries the three subsets", async () => {
    upstream = stubUpstream(() => json(ANTHROPIC_MESSAGE));

    await call("/v1/messages", {
      model: "cache-probe",
      max_tokens: 64,
      messages: [{ role: "user", content: "roll it up" }],
    });

    const rollup = await storedRollup();
    expect(rollup.api_key_id).toBe(KEY_ID);
    expect(rollup.prompt_tokens).toBe(26_000);
    expect(rollup.completion_tokens).toBe(500);
    expect(rollup.cached_input_tokens).toBe(20_000);
    expect(rollup.cache_write_tokens).toBe(5_000);
    expect(rollup.reasoning_tokens).toBe(0);
  });

  it("BUFFERED OpenAI: reasoning tokens land in the rollup as their own column", async () => {
    upstream = stubUpstream(() => json(OPENAI_COMPLETION));

    await call("/v1/chat/completions", {
      model: "reasoning-probe",
      messages: [{ role: "user", content: "roll up the thinking" }],
    });

    const rollup = await storedRollup();
    expect(rollup.cached_input_tokens).toBe(8_000);
    expect(rollup.reasoning_tokens).toBe(1_500);
    expect(rollup.cache_write_tokens).toBe(0);
    // The subsets do not disturb the totals the budgets read.
    expect(rollup.prompt_tokens).toBe(10_000);
    expect(rollup.total_tokens).toBe(12_000);
  });

  it("STREAMED Anthropic: the rollup agrees with the buffered leg", async () => {
    upstream = stubUpstream(() => sse(ANTHROPIC_STREAM_FRAMES));

    const response = await call("/v1/messages", {
      model: "cache-probe",
      max_tokens: 64,
      stream: true,
      messages: [{ role: "user", content: "roll up the stream" }],
    });
    await drain(response);

    const rollup = await storedRollup();
    expect(rollup.cached_input_tokens).toBe(20_000);
    expect(rollup.cache_write_tokens).toBe(5_000);
    expect(rollup.prompt_tokens).toBe(26_000);
  });
});
