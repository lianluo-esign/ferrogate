/**
 * Metering through the app the Worker actually serves.
 *
 * `sink.test.ts` drives `MeteringUsageSink` directly. This file drives it the
 * only way that proves the SEAM is real: `createGatewayApp({ modules: [
 * inferenceRouteModule({ usage: sink }) ] })` — the exact composition, and the
 * exact one-line wiring, `src/index.ts` will use. Everything between the HTTP
 * request and `sink.record()` is production code: the contract router, the auth
 * guard, the Zod validation, the adapter, the SSE relay and the usage tap.
 * Only the OUTBOUND provider `fetch` is intercepted.
 *
 * The two timing shapes are what this file exists for. A streamed response has
 * already started — headers flushed, bytes on the wire — by the time the usage
 * frame arrives, so metering must happen after the response and must not delay
 * it; and a client that hangs up mid-stream must still be billed for what it
 * consumed.
 */
import { PriceBook, modelPriceUsd, priceEntry } from "@ferrogate/billing";
import { afterEach, describe, expect, it } from "vitest";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import type { PhysicalRoute, RequestIdFactory } from "../../src/inference/index.js";
import {
  InMemoryLedgerStore,
  InMemoryMeteringOutbox,
  type LedgerStore,
  type LedgerWriteOutcome,
  type MeteredCharge,
  MeteringUsageSink,
  TrackingScheduler,
  routePriceSettledCostUsd,
} from "../../src/metering/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { OPENAI_ROUTE } from "../inference/fixtures.js";
import {
  type ProviderInterceptor,
  interceptProviderFetch,
  providerJson,
  providerSse,
  readBody,
} from "../inference/provider-mock.js";
import { FIXTURE_CREDITS, PRICED_PROVIDER, pricedBook } from "./fixtures.js";

const BASE = "https://gw.test";
const ENV = {
  GATEWAY_STATIC_API_KEYS: JSON.stringify([
    { key: "fg_root", id: "key_root", platform_operator: true },
  ]),
};
const AUTHED = { authorization: "Bearer fg_root", "content-type": "application/json" };

/** Distinct request ids, so two calls are two charges and not one replay. */
function incrementingRequestIds(): RequestIdFactory {
  let next = 0;
  return {
    next: (): string => {
      next += 1;
      return `fg-${next.toString(16).padStart(16, "0")}`;
    },
  };
}

interface Harness {
  readonly sink: MeteringUsageSink;
  readonly ledger: InMemoryLedgerStore;
  readonly outbox: InMemoryMeteringOutbox;
  readonly scheduler: TrackingScheduler;
  call(path: string, init?: RequestInit): Promise<Response>;
}

function gateway(
  options: {
    ledger?: LedgerStore;
    routes?: readonly PhysicalRoute[];
    priceBook?: PriceBook;
    settlementMode?: "rate_card" | "serving_offering";
  } = {},
): Harness {
  const ledger = new InMemoryLedgerStore();
  const outbox = new InMemoryMeteringOutbox();
  const scheduler = new TrackingScheduler();
  const sink = new MeteringUsageSink({
    priceBook: options.priceBook ?? pricedBook(),
    ...(options.settlementMode === undefined ? {} : { settlementMode: options.settlementMode }),
    ...(options.settlementMode === "serving_offering"
      ? { settledCostUsd: routePriceSettledCostUsd }
      : {}),
    ledger: options.ledger ?? ledger,
    outbox,
    scheduler,
  });

  // THE WIRING LINE. `usage` is the only new argument the composition root needs.
  const { app } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: new InMemoryModelResolver(options.routes ?? [OPENAI_ROUTE]),
        requestIds: incrementingRequestIds(),
        usage: sink,
      }),
    ],
  });

  return {
    sink,
    ledger,
    outbox,
    scheduler,
    call: async (path, init) => app.request(`${BASE}${path}`, init, ENV),
  };
}

function chatBody(stream: boolean): string {
  return JSON.stringify({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "hi" }],
    ...(stream ? { stream: true } : {}),
  });
}

/**
 * A usage frame LANDS EARLY, then more content follows, then a LARGER usage
 * frame closes the stream.
 *
 * The two different usage reports are what makes the disconnect test
 * falsifiable: a run that consumed the whole stream reports 40 completion
 * tokens, a run that was cut after the early frame reports 2. Filler frames
 * keep the pipe from buffering the whole body before the client reads.
 */
const EARLY_USAGE_FRAMES: readonly string[] = [
  'data: {"id":"c","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":"He"},"finish_reason":null}]}',
  'data: {"id":"c","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":"llo"},"finish_reason":null}],"usage":{"prompt_tokens":11,"completion_tokens":2,"total_tokens":13}}',
  ...Array.from(
    { length: 40 },
    (_unused, index) =>
      `data: {"id":"c","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":" ${index}"},"finish_reason":null}]}`,
  ),
  'data: {"id":"c","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[],"usage":{"prompt_tokens":11,"completion_tokens":40,"total_tokens":51}}',
  "data: [DONE]",
];

let provider: ProviderInterceptor | undefined;
afterEach(() => {
  provider?.restore();
  provider = undefined;
});

describe("metering through the composed gateway — non-streaming", () => {
  it("meters a buffered chat completion", async () => {
    provider = interceptProviderFetch(() =>
      providerJson({
        id: "chatcmpl-1",
        object: "chat.completion",
        model: "gpt-4o-mini",
        choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
        usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
      }),
    );
    const h = gateway();

    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(false),
    });
    expect(response.status).toBe(200);
    await h.scheduler.idle();

    expect(h.ledger.size).toBe(1);
    const [charge] = h.ledger.charges;
    expect(charge?.credits).toBe(FIXTURE_CREDITS);
    expect(charge?.entry.usage).toEqual({
      prompt_tokens: 11,
      completion_tokens: 4,
      total_tokens: 15,
      // #667 — this fixture's provider reports no cached or reasoning
      // tokens, and the equality stays EXACT so a change that started
      // inventing cached tokens on an uncached request would fail here.
      cached_input_tokens: 0,
      cache_write_tokens: 0,
      reasoning_tokens: 0,
    });
    expect(charge?.entry.logical_model).toBe("gpt-4o-mini");
    expect(charge?.entry.provider_model).toBe("gpt-4o-mini-2024-07-18");
    expect(charge?.requestId).toBe(response.headers.get("x-request-id"));
  });

  it("meters an upstream failure too, so a 502 is not free", async () => {
    provider = interceptProviderFetch(() =>
      providerJson({ error: { message: "upstream boom" } }, 500),
    );
    const h = gateway();

    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(false),
    });
    expect(response.status).toBe(500);
    await h.scheduler.idle();

    expect(h.ledger.size).toBe(1);
    expect(h.ledger.charges[0]?.entry.status_code).toBe(500);
    expect(h.ledger.charges[0]?.entry.usage_source).toBe("gateway_estimate");
    expect(h.ledger.charges[0]?.credits).toBe(0n);
  });

  it("charges each distinct request separately", async () => {
    provider = interceptProviderFetch(() =>
      providerJson({
        id: "chatcmpl-1",
        object: "chat.completion",
        model: "gpt-4o-mini",
        choices: [],
        usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
      }),
    );
    const h = gateway();

    for (let call = 0; call < 3; call += 1) {
      await h.call("/v1/chat/completions", {
        method: "POST",
        headers: AUTHED,
        body: chatBody(false),
      });
    }
    await h.scheduler.idle();

    expect(h.ledger.size).toBe(3);
    expect((await h.ledger.totals()).credits).toBe(FIXTURE_CREDITS * 3n);
  });
});

describe("metering through the composed gateway — streaming", () => {
  it("meters AFTER the response has started, from the trailing usage frame", async () => {
    provider = interceptProviderFetch(() => providerSse(EARLY_USAGE_FRAMES));
    const h = gateway();

    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(true),
    });

    // The response is already the client's — headers out, body streaming.
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    // …and nothing has been metered yet, because the usage frame has not been
    // read. Metering CANNOT have delayed these headers.
    expect(h.ledger.size).toBe(0);

    const body = await readBody(response);
    expect(body).toContain("[DONE]");
    await h.scheduler.idle();

    expect(h.ledger.size).toBe(1);
    // The FINAL usage frame wins, not the early partial one.
    expect(h.ledger.charges[0]?.entry.usage).toEqual({
      prompt_tokens: 11,
      completion_tokens: 40,
      total_tokens: 51,
      // #667 — this fixture's provider reports no cached or reasoning
      // tokens, and the equality stays EXACT so a change that started
      // inventing cached tokens on an uncached request would fail here.
      cached_input_tokens: 0,
      cache_write_tokens: 0,
      reasoning_tokens: 0,
    });
    // 11 * 0.15/1e6 + 40 * 0.6/1e6 = 2.565e-5 USD ⇒ 26 credits (25.65, rounded).
    expect(h.ledger.charges[0]?.credits).toBe(26n);
  });

  it("does not make the client wait on the durable write", async () => {
    provider = interceptProviderFetch(() => providerSse(EARLY_USAGE_FRAMES));

    // A ledger that will not complete until the test says so. If metering were
    // inline, the response body could not finish before `release()` is called.
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const inner = new InMemoryLedgerStore();
    const slow: LedgerStore = {
      record: async (charge: MeteredCharge): Promise<LedgerWriteOutcome> => {
        await gate;
        return inner.record(charge);
      },
      get: (id) => inner.get(id),
      list: (filter, offset, limit) => inner.list(filter, offset, limit),
      totals: (filter) => inner.totals(filter),
    };
    const h = gateway({ ledger: slow });

    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(true),
    });
    const body = await readBody(response);

    // The whole body reached the client while the metering write was blocked.
    expect(body).toContain("[DONE]");
    expect(inner.size).toBe(0);
    expect(h.outbox.size).toBe(1); // captured, durable-intent recorded

    release?.();
    await h.scheduler.idle();
    expect(inner.size).toBe(1);
    expect(h.outbox.size).toBe(0);
  });

  it("still meters what was consumed when the client disconnects mid-stream", async () => {
    provider = interceptProviderFetch(() => providerSse(EARLY_USAGE_FRAMES));
    const h = gateway();

    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(true),
    });
    const stream = response.body;
    expect(stream).not.toBeNull();

    // Consume up to and including the EARLY usage report, then hang up.
    const reader = (stream as ReadableStream<Uint8Array>).getReader();
    const decoder = new TextDecoder();
    let seen = "";
    while (!seen.includes('"completion_tokens":2')) {
      const chunk = await reader.read();
      expect(chunk.done, "the early usage frame must arrive before the stream ends").toBe(false);
      seen += decoder.decode(chunk.value, { stream: true });
    }
    // The trailing 40-token usage frame has NOT been delivered yet.
    expect(seen).not.toContain('"completion_tokens":40');
    await reader.cancel("client went away");

    await h.scheduler.idle();

    expect(h.ledger.size).toBe(1);
    const charge = h.ledger.charges[0];
    // What was consumed is what is billed. Billing the trailing frame would be
    // billing tokens nobody received; billing nothing would be the cost leak
    // `abort.ts` and the tap's `cancel()` exist to close.
    expect(charge?.entry.usage).toEqual({
      prompt_tokens: 11,
      completion_tokens: 2,
      total_tokens: 13,
      // #667 — this fixture's provider reports no cached or reasoning
      // tokens, and the equality stays EXACT so a change that started
      // inventing cached tokens on an uncached request would fail here.
      cached_input_tokens: 0,
      cache_write_tokens: 0,
      reasoning_tokens: 0,
    });
    // 11 * 0.15/1e6 + 2 * 0.6/1e6 = 2.85e-6 USD ⇒ 3 credits.
    expect(charge?.credits).toBe(3n);
    expect(charge?.entry.usage_source).toBe("provider_usage");
  });

  it("meters a disconnect that beat the first usage frame, rather than losing it", async () => {
    provider = interceptProviderFetch(() => providerSse(EARLY_USAGE_FRAMES));
    const h = gateway();

    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(true),
    });
    const reader = (response.body as ReadableStream<Uint8Array>).getReader();
    await reader.read();
    await reader.cancel("client went away");
    await h.scheduler.idle();

    // A metering EVENT still exists — the request happened and is attributable
    // — with no provider-reported tokens, so it settles at zero rather than
    // silently disappearing from the ledger.
    expect(h.ledger.size).toBe(1);
    expect(h.ledger.charges[0]?.entry.usage_source).toBe("gateway_estimate");
    expect(h.ledger.charges[0]?.credits).toBe(0n);
  });

  it("does not double-charge a stream that both flushes and cancels", async () => {
    provider = interceptProviderFetch(() => providerSse(EARLY_USAGE_FRAMES));
    const h = gateway();

    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(true),
    });
    await readBody(response);
    await h.scheduler.idle();

    expect(h.ledger.size).toBe(1);
    expect(h.sink.stats.recorded).toBe(1);
    expect(h.sink.stats.duplicates).toBe(0);
  });
});

describe("metering through the composed gateway — fail closed", () => {
  /**
   * CHANGED FOR #663. The old assertions (`ledger.size === 0`, zero credits)
   * are all still here and still correct — nothing may be BILLED for a model
   * nothing can price. What they did not say, and what let the defect hide, is
   * what happens to the USAGE: this test passed identically whether the sink
   * kept a recoverable record of the request or forgot it completely, and the
   * shipped behaviour was the second one. The `ledger.events` assertion below
   * is the observation that distinguishes them.
   */
  it("bills NOTHING for a model with no rate-card rule, but records the usage", async () => {
    provider = interceptProviderFetch(() =>
      providerJson({
        id: "chatcmpl-1",
        object: "chat.completion",
        model: "unpriced",
        choices: [],
        usage: { prompt_tokens: 100, completion_tokens: 100, total_tokens: 200 },
      }),
    );
    // A route that resolves and dispatches fine, but is absent from the card.
    const ledger = new InMemoryLedgerStore();
    const scheduler = new TrackingScheduler();
    const sink = new MeteringUsageSink({ priceBook: pricedBook(), ledger, scheduler });
    const { app } = createGatewayApp({
      modules: [
        inferenceRouteModule({
          models: new InMemoryModelResolver([
            { ...OPENAI_ROUTE, providerModel: "unpriced-model-9000" },
          ]),
          requestIds: incrementingRequestIds(),
          usage: sink,
        }),
      ],
    });

    const response = await app.request(
      `${BASE}/v1/chat/completions`,
      { method: "POST", headers: AUTHED, body: chatBody(false) },
      ENV,
    );
    // The CLIENT is served normally — fail-closed is a billing refusal, not a
    // request refusal; the Rust gateway also served the response.
    expect(response.status).toBe(200);
    await scheduler.idle();

    // Nothing billed — #129, unchanged.
    expect(ledger.size).toBe(0);
    expect((await ledger.totals()).credits).toBe(0n);
    expect(sink.stats.priceNotFound).toBe(1);
    expect(sink.unpriced[0]?.providerModel).toBe("unpriced-model-9000");

    // …and the usage is still on record, with a null cost (#663).
    expect(ledger.events).toHaveLength(1);
    expect(ledger.events[0]?.event.provider_model).toBe("unpriced-model-9000");
    expect(ledger.events[0]?.event.cost_usd).toBeUndefined();
    expect(ledger.events[0]?.event.usage.total_tokens).toBe(200);
    expect(sink.stats.unpricedRecorded).toBe(1);
  });
});

/**
 * The provider-attempt index, end to end.
 *
 * `metering/event.ts` folds `Usage.providerAttemptIndex` into the
 * `ledgerEntryId` / `provider_attempt` key because ONE logical request can fan
 * out into several provider dispatches (issue #213). The marker on
 * `SINGLE_PROVIDER_ATTEMPT_INDEX` used to say nothing SET that field — that
 * changed when the inference slice landed `dispatchWithFailover`, and this is
 * the test that keeps the closure honest across the ownership boundary.
 *
 * It is a REAL gate, not a restatement: the fallback in
 * `providerAttemptIndexFor` is `0`, and `0` is exactly what a request with no
 * failover produces, so the only way to observe the threading is a request that
 * was actually served by attempt 1. Drop `providerAttemptIndex: attemptIndex`
 * from `src/inference/handlers.ts::recordUsage`'s `base` and this goes red with
 * `provider-attempt:0` — which is the under-bill the marker warned about.
 */
describe("the provider-attempt index reaches the ledger key", () => {
  // `priority` ASC decides the order, so the failing route is unambiguously
  // attempt 0 — without it `orderCandidates` falls back to a name tiebreak and
  // the "backup" would be tried first, making the assertion below vacuous.
  const PRIMARY: PhysicalRoute = { ...OPENAI_ROUTE, provider: "openai-primary", priority: 0 };
  const BACKUP: PhysicalRoute = {
    ...OPENAI_ROUTE,
    provider: PRICED_PROVIDER,
    baseUrl: "https://api.openai-backup.example/v1/",
    priority: 1,
  };

  it("keys the charge on attempt 1 when the FIRST candidate failed over", async () => {
    provider = interceptProviderFetch((request) =>
      request.url.includes("openai-backup")
        ? providerJson({
            id: "chatcmpl-1",
            object: "chat.completion",
            model: "gpt-4o-mini",
            choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
            usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
          })
        : providerJson({ error: "overloaded" }, 503),
    );
    const h = gateway({ routes: [PRIMARY, BACKUP] });

    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(false),
    });
    expect(response.status).toBe(200);
    // The ladder really did walk two candidates — otherwise "attempt 1" below
    // would be provable without any failover having happened.
    expect(provider.requests).toHaveLength(2);
    await h.scheduler.idle();

    expect(h.ledger.size).toBe(1);
    const charge = h.ledger.charges[0];
    if (charge === undefined) throw new Error("expected a recorded charge");
    // The key that partitions a retried request from its first attempt.
    expect(charge.entry.provider_attempt).toEqual({
      provider_attempt_id: "fg-0000000000000001:provider-attempt:1",
      provider_attempt_index: 1,
    });
    expect(charge.id.endsWith(":provider-attempt:1")).toBe(true);
    // Attributed to the provider that actually served it.
    expect(charge.entry.provider).toBe(PRICED_PROVIDER);
    expect(charge.credits).toBe(FIXTURE_CREDITS);
  });

  it("keys an unfailed request on attempt 0 — the negative control", async () => {
    provider = interceptProviderFetch(() =>
      providerJson({
        id: "chatcmpl-1",
        object: "chat.completion",
        model: "gpt-4o-mini",
        choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
        usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
      }),
    );
    const h = gateway();

    expect(
      (
        await h.call("/v1/chat/completions", {
          method: "POST",
          headers: AUTHED,
          body: chatBody(false),
        })
      ).status,
    ).toBe(200);
    await h.scheduler.idle();

    expect(h.ledger.charges[0]?.entry.provider_attempt).toEqual({
      provider_attempt_id: "fg-0000000000000001:provider-attempt:0",
      provider_attempt_index: 0,
    });
  });
});

describe("serving offering settlement (#814)", () => {
  const MODEL = "offering-priced-model";
  const PRIMARY: PhysicalRoute = {
    ...OPENAI_ROUTE,
    logicalModel: MODEL,
    provider: "primary-channel",
    providerModel: "primary-upstream",
    baseUrl: "https://api.primary-offering.example/v1/",
    priority: 0,
    inputPricePer1m: 1,
    outputPricePer1m: 2,
  };
  const FALLBACK: PhysicalRoute = {
    ...OPENAI_ROUTE,
    logicalModel: MODEL,
    provider: "fallback-channel",
    providerModel: "fallback-upstream",
    baseUrl: "https://api.fallback-offering.example/v1/",
    priority: 1,
    inputPricePer1m: 10,
    outputPricePer1m: 20,
  };
  const CANARY: PhysicalRoute = {
    ...OPENAI_ROUTE,
    logicalModel: MODEL,
    provider: "canary-channel",
    providerModel: "canary-upstream",
    baseUrl: "https://api.canary-offering.example/v1/",
    priority: 5,
    canaryPercent: 100,
    inputPricePer1m: 7,
    outputPricePer1m: 11,
  };
  const WILDCARD_CARD = PriceBook.new([priceEntry("*", "*", modelPriceUsd(99, 99))]);

  it("settles a fallback response from the fallback offering, then moves on input-price mutation", async () => {
    provider = interceptProviderFetch((request) =>
      request.url.includes("fallback-offering")
        ? providerJson({
            id: "chatcmpl-fallback",
            object: "chat.completion",
            model: FALLBACK.providerModel,
            choices: [{ index: 0, message: { role: "assistant", content: "ok" } }],
            usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
          })
        : providerJson({ error: "primary unavailable" }, 503),
    );
    const h = gateway({
      routes: [PRIMARY, FALLBACK],
      priceBook: WILDCARD_CARD,
      settlementMode: "serving_offering",
    });

    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: JSON.stringify({
        model: MODEL,
        messages: [{ role: "user", content: "hi" }],
      }),
    });
    expect(response.status).toBe(200);
    expect(provider.requests.map((request) => request.url)).toEqual([
      `${PRIMARY.baseUrl}chat/completions`,
      `${FALLBACK.baseUrl}chat/completions`,
    ]);
    await h.scheduler.idle();

    const settled = (11 / 1_000_000) * 10 + (4 / 1_000_000) * 20;
    expect(h.ledger.charges[0]?.entry.provider).toBe("fallback-channel");
    expect(h.ledger.charges[0]?.entry.provider_model).toBe("fallback-upstream");
    expect(h.ledger.charges[0]?.entry.cost.total_cost).toBeCloseTo(settled, 12);
    expect(h.sink.stats.divergences).toBe(0);

    const mutatedFallback = { ...FALLBACK, inputPricePer1m: 20 };
    const mutated = gateway({
      routes: [PRIMARY, mutatedFallback],
      priceBook: WILDCARD_CARD,
      settlementMode: "serving_offering",
    });
    const mutatedResponse = await mutated.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: JSON.stringify({
        model: MODEL,
        messages: [{ role: "user", content: "hi" }],
      }),
    });
    expect(mutatedResponse.status).toBe(200);
    await mutated.scheduler.idle();
    const mutatedCost = mutated.ledger.charges[0]?.entry.cost.total_cost ?? 0;
    expect(mutatedCost - settled).toBeCloseTo((11 / 1_000_000) * 10, 12);
  });

  it("settles a canary response from the canary offering and identifies its channel", async () => {
    provider = interceptProviderFetch((request) =>
      request.url.includes("canary-offering")
        ? providerJson({
            id: "chatcmpl-canary",
            object: "chat.completion",
            model: CANARY.providerModel,
            choices: [{ index: 0, message: { role: "assistant", content: "ok" } }],
            usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
          })
        : providerJson({ error: "unexpected stable route" }, 503),
    );
    const h = gateway({
      routes: [PRIMARY, CANARY],
      priceBook: WILDCARD_CARD,
      settlementMode: "serving_offering",
    });

    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: JSON.stringify({
        model: MODEL,
        messages: [{ role: "user", content: "hi" }],
      }),
    });
    expect(response.status).toBe(200);
    expect(provider.requests).toHaveLength(1);
    expect(provider.requests[0]?.url).toContain("canary-offering");
    await h.scheduler.idle();

    expect(h.ledger.charges[0]?.entry.provider).toBe("canary-channel");
    expect(h.ledger.charges[0]?.entry.provider_model).toBe("canary-upstream");
    expect(h.ledger.charges[0]?.entry.cost.total_cost).toBeCloseTo(
      (11 / 1_000_000) * 7 + (4 / 1_000_000) * 11,
      12,
    );
  });
});
