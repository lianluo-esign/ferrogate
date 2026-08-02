/**
 * Cached / cache-write / reasoning token accounting, end to end (issue #667).
 *
 * ## What was broken
 *
 * A tenant using Anthropic prompt caching or a reasoning model was billed on the
 * wrong quantities. `apps/gateway/src/streaming/usage.ts` said so out loud —
 * "`cache_read_input_tokens` counters are not read here" — and treated it as a
 * deliberate parity boundary with the Rust tree. Nothing downstream read them
 * either, so the omission travelled all the way to the invoice:
 *
 *  - **Anthropic** reports `input_tokens` EXCLUDING both cache counters, so a
 *    request that read 20 000 tokens out of the cache was billed for the 1 000
 *    fresh ones and the other 25 000 were invisible. An under-bill.
 *  - **OpenAI** reports `prompt_tokens` INCLUDING `cached_tokens`, so the cached
 *    subset was billed at the full fresh-input rate — roughly ten times its
 *    price. An over-bill.
 *  - **Gemini** reports `candidatesTokenCount` EXCLUDING `thoughtsTokenCount`,
 *    so reasoning tokens were billed at nothing at all while
 *    `cachedContentTokenCount` was billed at full price.
 *
 * Three different wrong answers, which is exactly why the fix is a
 * NORMALIZATION and not three pricing rules: at capture time every family is
 * converted to one invariant —
 *
 *     cached_input_tokens ⊆ prompt_tokens
 *     cache_write_tokens  ⊆ prompt_tokens   (disjoint from cached_input_tokens)
 *     reasoning_tokens    ⊆ completion_tokens
 *
 * — and `@ferrogate/billing` prices that one shape.
 *
 * ## Why the assertions are literal
 *
 * Every expected USD figure below is derived by hand in the comment above it.
 * A cached-token discount that is silently wrong looks entirely reasonable on
 * an invoice, so a test that recomputed the expectation the way the code does
 * would confirm nothing at all.
 */
import {
  PriceBook,
  charge,
  priceEntry,
  type ModelPrice,
} from "@ferrogate/billing";
import { describe, expect, it } from "vitest";

import type { Usage } from "../../src/inference/ports.js";
import {
  extractLastStreamUsage,
  sseUsageTap,
  usageFromResponseBody,
  type ProviderUsage,
} from "../../src/inference/usage.js";
import { billingEventFromUsage } from "../../src/metering/event.js";
import { routePriceSettledCostUsd } from "../../src/metering/route-price.js";
import {
  extractLastStreamUsage as extractLastStreamUsageFrames,
  type NormalizedUsage,
} from "../../src/streaming/usage.js";

// ---------------------------------------------------------------------------
// Provider payloads. Each is the shape the vendor documents, verbatim.
// ---------------------------------------------------------------------------

/**
 * Anthropic `/v1/messages`, non-streaming. `input_tokens` is the FRESH input
 * only; the two cache counters are additional to it.
 */
const ANTHROPIC_BODY = {
  type: "message",
  usage: {
    input_tokens: 1_000,
    cache_creation_input_tokens: 5_000,
    cache_read_input_tokens: 20_000,
    output_tokens: 500,
  },
};

/**
 * OpenAI chat completions. `prompt_tokens` INCLUDES
 * `prompt_tokens_details.cached_tokens`, and `completion_tokens` INCLUDES
 * `completion_tokens_details.reasoning_tokens`.
 */
const OPENAI_BODY = {
  usage: {
    prompt_tokens: 10_000,
    completion_tokens: 2_000,
    total_tokens: 12_000,
    prompt_tokens_details: { cached_tokens: 8_000 },
    completion_tokens_details: { reasoning_tokens: 1_500 },
  },
};

/**
 * Gemini. `promptTokenCount` INCLUDES `cachedContentTokenCount`, but
 * `candidatesTokenCount` EXCLUDES `thoughtsTokenCount` — `totalTokenCount`
 * counts the thoughts.
 */
const GEMINI_BODY = {
  usageMetadata: {
    promptTokenCount: 30_000,
    candidatesTokenCount: 800,
    thoughtsTokenCount: 1_200,
    cachedContentTokenCount: 24_000,
    totalTokenCount: 32_000,
  },
};

// ---------------------------------------------------------------------------
// Capture — the BUFFERED leg.
// ---------------------------------------------------------------------------

describe("buffered capture normalizes each family onto the subset invariant", () => {
  it("Anthropic: the two cache counters are ADDED to the fresh input tokens", () => {
    const usage = usageFromResponseBody("anthropic", ANTHROPIC_BODY);
    // 1 000 fresh + 5 000 cache-write + 20 000 cache-read
    expect(usage?.promptTokens).toBe(26_000);
    expect(usage?.cachedInputTokens).toBe(20_000);
    expect(usage?.cacheWriteTokens).toBe(5_000);
    expect(usage?.completionTokens).toBe(500);
    expect(usage?.totalTokens).toBe(26_500);
    // Anthropic folds extended-thinking tokens into `output_tokens` and reports
    // no separate counter, so claiming one would be an invention.
    expect(usage?.reasoningTokens).toBeUndefined();
  });

  it("OpenAI: the cached and reasoning details are read as SUBSETS", () => {
    const usage = usageFromResponseBody("openai", OPENAI_BODY);
    expect(usage?.promptTokens).toBe(10_000);
    expect(usage?.cachedInputTokens).toBe(8_000);
    expect(usage?.completionTokens).toBe(2_000);
    expect(usage?.reasoningTokens).toBe(1_500);
    // OpenAI's automatic prompt caching carries no cache-WRITE charge.
    expect(usage?.cacheWriteTokens).toBeUndefined();
  });

  it("OpenAI Responses: the `input_tokens_details` spelling is read too", () => {
    const usage = usageFromResponseBody("openai", {
      usage: {
        prompt_tokens: 500,
        completion_tokens: 100,
        total_tokens: 600,
        input_tokens_details: { cached_tokens: 400 },
        output_tokens_details: { reasoning_tokens: 60 },
      },
    });
    expect(usage?.cachedInputTokens).toBe(400);
    expect(usage?.reasoningTokens).toBe(60);
  });

  it("Gemini: thoughts are ADDED to the visible completion tokens", () => {
    const usage = usageFromResponseBody("gemini", GEMINI_BODY);
    expect(usage?.promptTokens).toBe(30_000);
    expect(usage?.cachedInputTokens).toBe(24_000);
    // 800 visible + 1 200 thoughts — which is what `totalTokenCount` already
    // counted, so 30 000 + 2 000 == 32 000 stays consistent.
    expect(usage?.completionTokens).toBe(2_000);
    expect(usage?.reasoningTokens).toBe(1_200);
    expect(usage?.totalTokens).toBe(32_000);
  });

  it("leaves the counters absent when the provider reports none", () => {
    const usage = usageFromResponseBody("openai", {
      usage: { prompt_tokens: 10, completion_tokens: 2, total_tokens: 12 },
    });
    expect(usage?.cachedInputTokens).toBeUndefined();
    expect(usage?.cacheWriteTokens).toBeUndefined();
    expect(usage?.reasoningTokens).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Capture — the STREAMING leg.
// ---------------------------------------------------------------------------

/** Serialize payloads as an SSE body the way a provider would. */
function sse(...payloads: unknown[]): string {
  return `${payloads.map((p) => `data: ${JSON.stringify(p)}`).join("\n\n")}\n\ndata: [DONE]\n\n`;
}

/**
 * Anthropic's stream splits the usage across two frames, and the cache counters
 * arrive on `message_start` — the frame the tap must not lose.
 */
const ANTHROPIC_STREAM = sse(
  {
    type: "message_start",
    message: {
      usage: {
        input_tokens: 1_000,
        cache_creation_input_tokens: 5_000,
        cache_read_input_tokens: 20_000,
        output_tokens: 0,
      },
    },
  },
  { type: "content_block_delta" },
  { type: "message_delta", usage: { output_tokens: 500 } },
);

describe("streaming capture", () => {
  it("merges Anthropic's cache counters from message_start across the stream", () => {
    const usage = extractLastStreamUsage(ANTHROPIC_STREAM, "anthropic");
    expect(usage?.promptTokens).toBe(26_000);
    expect(usage?.cachedInputTokens).toBe(20_000);
    expect(usage?.cacheWriteTokens).toBe(5_000);
    expect(usage?.completionTokens).toBe(500);
  });

  it("scrapes OpenAI's cached/reasoning details off the terminal usage frame", () => {
    const usage = extractLastStreamUsage(sse({ choices: [] }, OPENAI_BODY), "openai");
    expect(usage?.cachedInputTokens).toBe(8_000);
    expect(usage?.reasoningTokens).toBe(1_500);
  });

  it("scrapes Gemini's cached-content and thoughts counters", () => {
    const usage = extractLastStreamUsage(sse(GEMINI_BODY), "gemini");
    expect(usage?.cachedInputTokens).toBe(24_000);
    expect(usage?.reasoningTokens).toBe(1_200);
    expect(usage?.completionTokens).toBe(2_000);
  });

  it("keeps the client-visible bytes byte-identical while scraping them", async () => {
    // The raw-byte tap's whole reason for existing (`sseUsageTap`'s doc): the
    // passthrough leg re-enqueues the UPSTREAM chunks untouched, so adding new
    // counters must not turn it into parse → capture → re-serialize.
    const bytes = new TextEncoder().encode(ANTHROPIC_STREAM);
    // Split mid-frame, and inside a multi-byte-safe boundary, so a tap that
    // buffered or re-framed would be caught.
    const chunks = [bytes.subarray(0, 37), bytes.subarray(37, 400), bytes.subarray(400)];

    let observed: ProviderUsage | undefined;
    const tap = sseUsageTap("anthropic", (u) => {
      observed = u;
    });
    const source = new ReadableStream<Uint8Array>({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(chunk);
        controller.close();
      },
    });
    const out = new Uint8Array(
      await new Response(source.pipeThrough(tap)).arrayBuffer(),
    );

    expect(new TextDecoder().decode(out)).toBe(ANTHROPIC_STREAM);
    expect(observed?.cachedInputTokens).toBe(20_000);
    expect(observed?.cacheWriteTokens).toBe(5_000);
    expect(observed?.promptTokens).toBe(26_000);
  });

  it("the parsed-frame capture in src/streaming agrees with the raw-byte one", () => {
    // Two independent scrapers exist (one over parsed `SseFrame`s for the
    // re-serializing ingresses, one over raw bytes for the passthrough leg).
    // They must not drift, or the same request bills differently depending on
    // which ingress it arrived through.
    const frames: NormalizedUsage | undefined = extractLastStreamUsageFrames(
      ANTHROPIC_STREAM,
      "anthropic",
    );
    const raw = extractLastStreamUsage(ANTHROPIC_STREAM, "anthropic");
    expect(frames?.promptTokens).toBe(raw?.promptTokens);
    expect(frames?.cachedInputTokens).toBe(raw?.cachedInputTokens);
    expect(frames?.cacheWriteTokens).toBe(raw?.cacheWriteTokens);
    expect(frames?.completionTokens).toBe(raw?.completionTokens);
  });
});

// ---------------------------------------------------------------------------
// The metering event.
// ---------------------------------------------------------------------------

function usageFor(provider: string, model: string, observed: ProviderUsage | undefined): Usage {
  return {
    requestId: "req_667",
    route: "openai.chat.completions",
    logicalModel: model,
    provider,
    providerModel: model,
    stream: false,
    status: 200,
    tenantId: "tenant_a",
    ...(observed?.promptTokens !== undefined ? { promptTokens: observed.promptTokens } : {}),
    ...(observed?.completionTokens !== undefined
      ? { completionTokens: observed.completionTokens }
      : {}),
    ...(observed?.totalTokens !== undefined ? { totalTokens: observed.totalTokens } : {}),
    ...(observed?.cachedInputTokens !== undefined
      ? { cachedInputTokens: observed.cachedInputTokens }
      : {}),
    ...(observed?.cacheWriteTokens !== undefined
      ? { cacheWriteTokens: observed.cacheWriteTokens }
      : {}),
    ...(observed?.reasoningTokens !== undefined
      ? { reasoningTokens: observed.reasoningTokens }
      : {}),
  };
}

describe("the metering event carries the new counters", () => {
  it("copies all three onto BillingEvent.usage", () => {
    const event = billingEventFromUsage(
      usageFor("anthropic", "claude-sonnet-4", usageFromResponseBody("anthropic", ANTHROPIC_BODY)),
      { nowUnixSeconds: 1_784_073_600 },
    );
    expect(event.usage.prompt_tokens).toBe(26_000);
    expect(event.usage.cached_input_tokens).toBe(20_000);
    expect(event.usage.cache_write_tokens).toBe(5_000);
    expect(event.usage.reasoning_tokens).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// GOLDEN COSTS, per provider family.
// ---------------------------------------------------------------------------

/** Anthropic's published cache structure: read 0.1x input, 5-minute write 1.25x. */
const CLAUDE_SONNET_4: ModelPrice = {
  input_price_per_1m: 3.0,
  output_price_per_1m: 15.0,
  cached_input_price_per_1m: 0.3,
  cache_write_price_per_1m: 3.75,
  currency: "USD",
};

/** gpt-4o: $2.50 input, $1.25 cached input (0.5x), $10.00 output. */
const GPT_4O: ModelPrice = {
  input_price_per_1m: 2.5,
  output_price_per_1m: 10.0,
  cached_input_price_per_1m: 1.25,
  currency: "USD",
};

/** gemini-2.5-pro: $1.25 input, cached content at 0.25x, $10.00 output. */
const GEMINI_25_PRO: ModelPrice = {
  input_price_per_1m: 1.25,
  output_price_per_1m: 10.0,
  cached_input_price_per_1m: 0.3125,
  currency: "USD",
};

function bookFor(provider: string, model: string, price: ModelPrice): PriceBook {
  return PriceBook.new([priceEntry(provider, model, price)]);
}

function settle(provider: string, model: string, price: ModelPrice, usage: Usage): number {
  const event = billingEventFromUsage(usage, { nowUnixSeconds: 1_784_073_600 });
  return charge(bookFor(provider, model, price), event).cost.total_cost;
}

describe("golden settled costs", () => {
  it("Anthropic prompt caching", () => {
    //   fresh      1 000 / 1e6 * 3.00  = 0.003
    //   cache read 20 000 / 1e6 * 0.30 = 0.006
    //   cache write 5 000 / 1e6 * 3.75 = 0.01875
    //   output        500 / 1e6 * 15.0 = 0.0075
    //                                    ---------
    //                                    0.03525
    const usage = usageFor(
      "anthropic",
      "claude-sonnet-4",
      usageFromResponseBody("anthropic", ANTHROPIC_BODY),
    );
    expect(settle("anthropic", "claude-sonnet-4", CLAUDE_SONNET_4, usage)).toBeCloseTo(
      0.03525,
      12,
    );
    // The pre-#667 answer, for contrast: only `input_tokens` was seen, so
    // 1 000/1e6*3 + 500/1e6*15 = 0.0105 — a 3.4x under-bill.
    expect(settle("anthropic", "claude-sonnet-4", CLAUDE_SONNET_4, usage)).not.toBeCloseTo(
      0.0105,
      6,
    );
  });

  it("OpenAI cached prompt + reasoning", () => {
    //   fresh      2 000 / 1e6 * 2.50  = 0.005
    //   cache read 8 000 / 1e6 * 1.25  = 0.010
    //   output     2 000 / 1e6 * 10.0  = 0.020   (reasoning bills as output)
    //                                    ---------
    //                                    0.035
    const usage = usageFor("openai", "gpt-4o", usageFromResponseBody("openai", OPENAI_BODY));
    expect(settle("openai", "gpt-4o", GPT_4O, usage)).toBeCloseTo(0.035, 12);
    // Pre-#667: the whole 10 000 prompt tokens at $2.50 = 0.025, plus 0.020
    // output = 0.045 — a 28% OVER-bill on the cached half.
    expect(settle("openai", "gpt-4o", GPT_4O, usage)).not.toBeCloseTo(0.045, 6);
  });

  it("Gemini cached content + thoughts", () => {
    //   fresh      6 000 / 1e6 * 1.2500 = 0.0075
    //   cache read 24 000/ 1e6 * 0.3125 = 0.0075
    //   output     2 000 / 1e6 * 10.00  = 0.020   (800 visible + 1 200 thoughts)
    //                                     ---------
    //                                     0.035
    const usage = usageFor(
      "gemini",
      "gemini-2.5-pro",
      usageFromResponseBody("gemini", GEMINI_BODY),
    );
    expect(settle("gemini", "gemini-2.5-pro", GEMINI_25_PRO, usage)).toBeCloseTo(0.035, 12);
    // Pre-#667: 30 000/1e6*1.25 + 800/1e6*10 = 0.0455 — the thoughts billed at
    // nothing and the cached content billed at full price.
    expect(settle("gemini", "gemini-2.5-pro", GEMINI_25_PRO, usage)).not.toBeCloseTo(0.0455, 6);
  });

  it("a rate card with no cached rates prices exactly as it did before #667", () => {
    // Backward compatibility, stated as a number rather than as a promise:
    //   26 000 / 1e6 * 3.00 + 500 / 1e6 * 15.00 = 0.078 + 0.0075 = 0.0855
    const usage = usageFor(
      "anthropic",
      "claude-sonnet-4",
      usageFromResponseBody("anthropic", ANTHROPIC_BODY),
    );
    const legacy: ModelPrice = {
      input_price_per_1m: 3.0,
      output_price_per_1m: 15.0,
      currency: "USD",
    };
    expect(settle("anthropic", "claude-sonnet-4", legacy, usage)).toBeCloseTo(0.0855, 12);
  });
});

// ---------------------------------------------------------------------------
// The model-registry settlement leg (#663) must agree with the rate card.
// ---------------------------------------------------------------------------

describe("routePriceSettledCostUsd honours the route's own cached rates", () => {
  it("prices the cached subset at the route's cached rate", () => {
    //   fresh      1 000 / 1e6 * 3.00  = 0.003
    //   cache read 20 000 / 1e6 * 0.30 = 0.006
    //   cache write 5 000 / 1e6 * 3.75 = 0.01875
    //   output        500 / 1e6 * 15.0 = 0.0075
    const usage = usageFor(
      "anthropic",
      "claude-sonnet-4",
      usageFromResponseBody("anthropic", ANTHROPIC_BODY),
    );
    expect(
      routePriceSettledCostUsd({
        ...usage,
        inputPricePer1m: 3.0,
        outputPricePer1m: 15.0,
        cachedInputPricePer1m: 0.3,
        cacheWritePricePer1m: 3.75,
      }),
    ).toBeCloseTo(0.03525, 12);
  });

  it("falls back to the fresh-input rate when the route states no cached rate", () => {
    //   26 000 / 1e6 * 3.00 + 500 / 1e6 * 15.00 = 0.0855
    const usage = usageFor(
      "anthropic",
      "claude-sonnet-4",
      usageFromResponseBody("anthropic", ANTHROPIC_BODY),
    );
    expect(
      routePriceSettledCostUsd({ ...usage, inputPricePer1m: 3.0, outputPricePer1m: 15.0 }),
    ).toBeCloseTo(0.0855, 12);
  });
});
