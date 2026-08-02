/**
 * Token-usage capture, for both the buffered and the streaming response paths.
 *
 * Clean-room port of:
 *  - `ProviderAdapter::extract_usage` for the OpenAI-compatible family
 *    (`openai.rs`) and the Anthropic family (`anthropic.rs`);
 *  - `chat.rs::extract_last_provider_stream_usage` — the SSE scraper that pulls
 *    the FINAL reported usage out of a provider stream, merging partial reports
 *    across frames;
 *  - `chat.rs::StreamingUsageCapturingReader` / `StreamingUsageCapture` — the
 *    bounded tee that scrapes usage WITHOUT buffering the whole stream.
 *
 * Why this matters (inventory-request-path §1.5): a streamed request is metered
 * from the last SSE `usage` frame. If that scrape fails the Rust tree fell back
 * to a 512-token estimate — which was a real bypass class (see the comment at
 * `chat.rs:1012`: parsing a normalized stream with the ORIGIN provider's native
 * extractor found nothing and let a tenant stream unbounded tokens billed as
 * ~512). Hence `usageProviderKindFor` below: the extractor is chosen from the
 * dialect the bytes are actually IN, not from the upstream that produced them.
 *
 * Relationship to `../streaming/` (which also ports `UsageCapture`): that
 * module's `usageCaptureStream()` operates on a PARSED `SseFrame` stream, so
 * using it on the proxy path would mean parse → capture → re-serialize, and a
 * re-serialized stream is no longer byte-identical to the upstream. The
 * cross-dialect legs (`/v1/messages`, `/v1/responses`) are re-serialized anyway
 * and could use either; the pure-passthrough leg (`/v1/chat/completions`)
 * cannot. {@link sseUsageTap} therefore tees the RAW bytes — it enqueues the
 * upstream `Uint8Array` untouched and scrapes a separate decode — which keeps
 * one tap correct for all three ingresses. The merge semantics in
 * {@link mergeUsage} are the Rust ones and must not drift.
 */
import { canonicalProviderKind } from "./adapters.js";
import type { ProviderUsageWire } from "./schemas.js";

/**
 * `ferrogate_providers::ProviderUsage`, extended with the cached/reasoning
 * counters (issue #667).
 *
 * ## The normalization, and why it lives HERE and not in the billing package
 *
 * The three new counters are SUBSETS of the two headline counts:
 *
 *     cachedInputTokens ⊆ promptTokens
 *     cacheWriteTokens  ⊆ promptTokens   (disjoint from cachedInputTokens)
 *     reasoningTokens   ⊆ completionTokens
 *
 * The vendors do NOT agree on that, which is the whole reason the conversion is
 * a capture-time concern:
 *
 *  - OpenAI's `prompt_tokens` already INCLUDES `prompt_tokens_details.
 *    cached_tokens`, and `completion_tokens` already INCLUDES
 *    `completion_tokens_details.reasoning_tokens`. Nothing to adjust.
 *  - Anthropic's `input_tokens` EXCLUDES both `cache_read_input_tokens` and
 *    `cache_creation_input_tokens`, so {@link extractAnthropicUsage} ADDS them
 *    in. Before #667 those tokens were invisible to metering entirely — the
 *    under-bill the deferral comment in `../streaming/usage.ts` described.
 *  - Gemini's `promptTokenCount` INCLUDES `cachedContentTokenCount` but its
 *    `candidatesTokenCount` EXCLUDES `thoughtsTokenCount`, so
 *    {@link extractGeminiUsage} adds thoughts into the completion count — which
 *    is what `totalTokenCount` already assumed, so the identity
 *    `prompt + completion == total` survives.
 *
 * Normalizing here means `@ferrogate/billing` holds ONE pricing rule
 * (`estimateCost`) instead of one per family, and a new provider family is a
 * change to one extractor rather than to the money path.
 *
 * A counter the provider did not report stays `undefined` — NOT `0`. "No cached
 * tokens" and "this response predates the counter" price the same, but the
 * distinction is what keeps {@link mergeUsage} from letting a later frame that
 * omits the field erase an earlier frame that reported it.
 */
export interface ProviderUsage {
  readonly promptTokens?: number | undefined;
  readonly completionTokens?: number | undefined;
  readonly totalTokens?: number | undefined;
  /** Prompt tokens served from a prompt cache — a SUBSET of `promptTokens`. */
  readonly cachedInputTokens?: number | undefined;
  /** Prompt tokens written INTO a prompt cache — a SUBSET of `promptTokens`. */
  readonly cacheWriteTokens?: number | undefined;
  /** Reasoning/thinking tokens — a SUBSET of `completionTokens`. */
  readonly reasoningTokens?: number | undefined;
}

function asUint(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0
    ? value
    : undefined;
}

function member(value: unknown, key: string): unknown {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)[key]
    : undefined;
}

/**
 * True when at least one count was reported (`then_some` guard in Rust).
 *
 * The cached/reasoning counters are deliberately NOT part of the guard: they
 * are subsets, so a payload carrying `cached_tokens` and nothing else is a
 * malformed usage object, not a usage report, and treating it as one would let
 * it clobber a real earlier reading in {@link mergeUsage}.
 */
function nonEmpty(usage: ProviderUsage): ProviderUsage | undefined {
  return usage.promptTokens !== undefined ||
    usage.completionTokens !== undefined ||
    usage.totalTokens !== undefined
    ? usage
    : undefined;
}

/** Drop the `undefined`-valued keys so an absent counter stays ABSENT. */
function withCounters(
  base: ProviderUsage,
  counters: {
    cachedInputTokens?: number | undefined;
    cacheWriteTokens?: number | undefined;
    reasoningTokens?: number | undefined;
  },
): ProviderUsage {
  return {
    ...base,
    ...(counters.cachedInputTokens !== undefined
      ? { cachedInputTokens: counters.cachedInputTokens }
      : {}),
    ...(counters.cacheWriteTokens !== undefined
      ? { cacheWriteTokens: counters.cacheWriteTokens }
      : {}),
    ...(counters.reasoningTokens !== undefined
      ? { reasoningTokens: counters.reasoningTokens }
      : {}),
  };
}

/**
 * `OpenAiCompatibleAdapter::extract_usage` — top-level
 * `usage.{prompt,completion,total}_tokens`, plus the cached/reasoning details
 * (issue #667).
 *
 * BOTH detail spellings are read. Chat Completions nests them under
 * `prompt_tokens_details` / `completion_tokens_details`; the Responses API uses
 * `input_tokens_details` / `output_tokens_details`, and `/v1/responses` streams
 * are metered with THIS extractor by `usageProviderKindFor` (they are normalized
 * to the OpenAI shape before metering sees them). Reading only one spelling
 * would therefore silently drop the discount on exactly one of the two
 * ingresses, which is the shape of bug this issue is about.
 *
 * Both counts are already SUBSETS of `prompt_tokens` / `completion_tokens` in
 * OpenAI's own accounting, so nothing is added in. There is no cache-WRITE
 * counter: OpenAI's automatic prompt caching charges nothing to populate the
 * cache, so claiming one would be an invention.
 */
export function extractOpenAiUsage(payload: unknown): ProviderUsage | undefined {
  const usage = member(payload, "usage");
  if (usage === undefined) {
    return undefined;
  }
  const promptDetails =
    member(usage, "prompt_tokens_details") ?? member(usage, "input_tokens_details");
  const completionDetails =
    member(usage, "completion_tokens_details") ?? member(usage, "output_tokens_details");
  return nonEmpty(
    withCounters(
      {
        promptTokens: asUint(member(usage, "prompt_tokens")),
        completionTokens: asUint(member(usage, "completion_tokens")),
        totalTokens: asUint(member(usage, "total_tokens")),
      },
      {
        cachedInputTokens: asUint(member(promptDetails, "cached_tokens")),
        reasoningTokens: asUint(member(completionDetails, "reasoning_tokens")),
      },
    ),
  );
}

/**
 * `AnthropicAdapter::extract_usage` — `usage.{input,output}_tokens`, falling
 * back to `message.usage` (the `message_start` SSE frame nests it there).
 * `total_tokens` is derived only when BOTH halves are present, as in Rust.
 *
 * ## The cache counters are ADDED to `input_tokens` (issue #667)
 *
 * This is the one family where the subset normalization costs an addition, and
 * it is the defect this issue names. Anthropic reports `input_tokens` as the
 * FRESH input only: a request that read 20 000 tokens out of the prompt cache
 * and wrote 5 000 into it reports `input_tokens: 1000`, and every one of the
 * other 25 000 tokens is billable. Summing them into `promptTokens` is what
 * makes them visible at all; carrying them ALSO as their own counters is what
 * lets `estimateCost` bill them at the cache rates instead of at the fresh rate
 * (Anthropic prices a cache read at 0.1x and a 5-minute cache write at 1.25x,
 * so folding them in without the split would be a different wrong answer — the
 * exact objection the deferral comment in `../streaming/usage.ts` raised).
 *
 * `output_tokens` needs no such treatment: Anthropic counts extended-thinking
 * tokens INSIDE `output_tokens` and publishes no separate counter, so
 * `reasoningTokens` is left absent rather than invented. Thinking already bills
 * at the output rate, which is what the absent counter produces.
 */
export function extractAnthropicUsage(payload: unknown): ProviderUsage | undefined {
  const usage = member(payload, "usage") ?? member(member(payload, "message"), "usage");
  if (usage === undefined) {
    return undefined;
  }
  const freshInput = asUint(member(usage, "input_tokens"));
  const cachedInputTokens = asUint(member(usage, "cache_read_input_tokens"));
  const cacheWriteTokens = asUint(member(usage, "cache_creation_input_tokens"));
  const completionTokens = asUint(member(usage, "output_tokens"));
  // Only widen a reported `input_tokens`; a frame that carries cache counters
  // and no `input_tokens` at all must not manufacture a prompt count out of
  // them, because `mergeUsage` would then let it overwrite the real one.
  const promptTokens =
    freshInput === undefined
      ? undefined
      : freshInput + (cachedInputTokens ?? 0) + (cacheWriteTokens ?? 0);
  return nonEmpty(
    withCounters(
      {
        promptTokens,
        completionTokens,
        totalTokens:
          promptTokens !== undefined && completionTokens !== undefined
            ? promptTokens + completionTokens
            : undefined,
      },
      { cachedInputTokens, cacheWriteTokens },
    ),
  );
}

/**
 * `GeminiAdapter::extract_usage` — `usageMetadata.{promptTokenCount,
 * candidatesTokenCount, totalTokenCount}`.
 *
 * Gemini reports a `totalTokenCount` of its own; unlike the Anthropic
 * extractor, the TOTAL is not derived here, because `gemini.rs` derives none.
 *
 * ## Thoughts are ADDED to the visible completion count (issue #667)
 *
 * `candidatesTokenCount` EXCLUDES `thoughtsTokenCount`, while `totalTokenCount`
 * INCLUDES it. So before #667 a thinking model's reasoning tokens were billed
 * at nothing at all, and `prompt + completion` silently disagreed with the
 * `total` the same object reported. Adding thoughts into `completionTokens`
 * fixes both at once and restores `prompt + completion == total`.
 *
 * `cachedContentTokenCount` needs no addition — it is already inside
 * `promptTokenCount` — and there is no token-denominated cache-WRITE counter:
 * Gemini's explicit caching bills storage by the hour, which is a different
 * meter and is deliberately not modelled as a token count.
 */
export function extractGeminiUsage(payload: unknown): ProviderUsage | undefined {
  const usage = member(payload, "usageMetadata");
  if (usage === undefined) {
    return undefined;
  }
  const visible = asUint(member(usage, "candidatesTokenCount"));
  const reasoningTokens = asUint(member(usage, "thoughtsTokenCount"));
  return nonEmpty(
    withCounters(
      {
        promptTokens: asUint(member(usage, "promptTokenCount")),
        completionTokens:
          visible === undefined ? undefined : visible + (reasoningTokens ?? 0),
        totalTokens: asUint(member(usage, "totalTokenCount")),
      },
      {
        cachedInputTokens: asUint(member(usage, "cachedContentTokenCount")),
        reasoningTokens,
      },
    ),
  );
}

/** Extractor selection by the dialect the payload is written in. */
export type UsageDialect = "openai" | "anthropic" | "gemini";

/** `state.extract_provider_usage(kind, payload)`. */
export function extractUsage(dialect: UsageDialect, payload: unknown): ProviderUsage | undefined {
  switch (dialect) {
    case "anthropic":
      return extractAnthropicUsage(payload);
    case "gemini":
      return extractGeminiUsage(payload);
    case "openai":
      return extractOpenAiUsage(payload);
  }
}

/**
 * Which extractor a stream needs.
 *
 * `/v1/responses` streams are normalized to the OpenAI/Responses shape BEFORE
 * metering sees them, so they are always read with the OpenAI extractor
 * regardless of upstream family. Chat-completions streams the raw native SSE,
 * so the upstream family decides. This mirrors the `usage_provider_kind` branch
 * at `chat.rs:1022` verbatim — it is a security control, not a nicety.
 */
export function usageProviderKindFor(
  operation: "chat.completions" | "responses" | "messages",
  providerKind: string,
): UsageDialect {
  if (operation === "responses") {
    return "openai";
  }
  if (operation === "messages") {
    // The client is served Anthropic SSE; whatever the upstream was, the frames
    // metering sees at this point carry Anthropic-shaped usage.
    return "anthropic";
  }
  // Rust reads `provider.kind` and dispatches to THAT adapter's `extract_usage`
  // (`chat.rs:1026` → `AppState::extract_provider_usage`), so every family with
  // its own usage envelope needs its own arm here. A family that fell through to
  // the OpenAI extractor would scrape nothing and meter the call at the fallback
  // estimate — the token-budget/TPM/wallet bypass this function's doc names.
  switch (canonicalProviderKind(providerKind)) {
    case "anthropic":
      return "anthropic";
    case "gemini":
      return "gemini";
    default:
      return "openai";
  }
}

/**
 * Merge a newly observed usage report over the running one.
 *
 * Rust semantics, preserved exactly: each field prefers the NEW report and
 * falls back to the previous; `total_tokens` prefers the new report, then the
 * sum of the merged prompt+completion (saturating), then the previous total.
 * That last chain is why a stream that reports `input_tokens` on
 * `message_start` and `output_tokens` on `message_delta` still yields a
 * complete total.
 */
export function mergeUsage(
  previous: ProviderUsage | undefined,
  next: ProviderUsage,
): ProviderUsage {
  const prior = previous ?? {};
  const promptTokens = next.promptTokens ?? prior.promptTokens;
  const completionTokens = next.completionTokens ?? prior.completionTokens;
  const derivedTotal =
    promptTokens !== undefined && completionTokens !== undefined
      ? promptTokens + completionTokens
      : undefined;
  // The cached/reasoning counters follow the SAME prefer-new-fall-back-to-old
  // rule (#667), and that is load-bearing on the Anthropic stream: the cache
  // counters arrive once, on `message_start`, and the terminal `message_delta`
  // frame reports only `output_tokens`. A merge that let the newer frame's
  // absence win would erase them at the last possible moment — the whole
  // request's cache discount, lost on the final frame.
  return withCounters(
    {
      promptTokens,
      completionTokens,
      totalTokens: next.totalTokens ?? derivedTotal ?? prior.totalTokens,
    },
    {
      cachedInputTokens: next.cachedInputTokens ?? prior.cachedInputTokens,
      cacheWriteTokens: next.cacheWriteTokens ?? prior.cacheWriteTokens,
      reasoningTokens: next.reasoningTokens ?? prior.reasoningTokens,
    },
  );
}

/** The `[DONE]` sentinel, which carries no usage and must not be JSON-parsed. */
const DONE_SENTINEL = "[DONE]";

/**
 * `extract_last_provider_stream_usage` over a complete SSE body.
 *
 * Line grammar, byte-for-byte from the Rust loop: split on `\n`, strip a
 * trailing `\r`, a blank line dispatches the accumulated event, any line not
 * starting with `data:` is skipped, and exactly one leading space after the
 * colon is stripped. Multiple `data:` lines in one frame are joined with `\n`.
 */
export function extractLastStreamUsage(
  body: string,
  dialect: UsageDialect,
): ProviderUsage | undefined {
  const tap = new SseUsageScraper(dialect);
  tap.push(body);
  return tap.finish();
}

/**
 * Incremental form of {@link extractLastStreamUsage}: fed chunk by chunk as a
 * stream flows past, so nothing beyond one frame is ever retained.
 *
 * This is the bounded-memory property `StreamingUsageCapture` bought in Rust
 * with an 8 KiB prefix + 56 KiB tail ring buffer. The incremental parser here
 * is strictly better: it holds at most the current partial frame.
 */
export class SseUsageScraper {
  readonly #dialect: UsageDialect;
  #pending = "";
  #eventData = "";
  #sawData = false;
  #usage: ProviderUsage | undefined;

  constructor(dialect: UsageDialect) {
    this.#dialect = dialect;
  }

  /** Feed decoded text. Chunk boundaries may fall anywhere. */
  push(text: string): void {
    this.#pending += text;
    let start = 0;
    for (;;) {
      const newline = this.#pending.indexOf("\n", start);
      if (newline < 0) {
        break;
      }
      this.#line(this.#pending.slice(start, newline));
      start = newline + 1;
    }
    this.#pending = this.#pending.slice(start);
  }

  /** Dispatch whatever is left (an upstream may omit the final newline). */
  finish(): ProviderUsage | undefined {
    if (this.#pending.length > 0) {
      this.#line(this.#pending);
      this.#pending = "";
    }
    this.#dispatch();
    return this.#usage;
  }

  /** Usage observed so far, without ending the scrape. */
  get current(): ProviderUsage | undefined {
    return this.#usage;
  }

  #line(rawLine: string): void {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    if (line.length === 0) {
      this.#dispatch();
      return;
    }
    if (!line.startsWith("data:")) {
      return;
    }
    let data = line.slice("data:".length);
    if (data.startsWith(" ")) {
      data = data.slice(1);
    }
    if (this.#sawData) {
      this.#eventData += "\n";
    }
    this.#eventData += data;
    this.#sawData = true;
  }

  #dispatch(): void {
    if (this.#sawData && this.#eventData !== DONE_SENTINEL) {
      let payload: unknown;
      try {
        payload = JSON.parse(this.#eventData);
      } catch {
        payload = undefined;
      }
      if (payload !== undefined) {
        const observed = extractUsage(this.#dialect, payload);
        if (observed !== undefined) {
          this.#usage = mergeUsage(this.#usage, observed);
        }
      }
    }
    this.#eventData = "";
    this.#sawData = false;
  }
}

/**
 * A byte-for-byte passthrough `TransformStream` that tees the bytes into an
 * {@link SseUsageScraper} and reports the final usage on flush.
 *
 * The client-visible bytes are the upstream chunks re-enqueued UNCHANGED (the
 * same `Uint8Array` references), which is the "preserve upstream SSE framing
 * byte-for-byte" invariant from ROUTE-MAP. The decoder used for scraping is a
 * separate, streaming `TextDecoder`, so a multi-byte character split across a
 * chunk boundary cannot corrupt either path.
 */
export function sseUsageTap(
  dialect: UsageDialect,
  onUsage: (usage: ProviderUsage | undefined) => void,
): TransformStream<Uint8Array, Uint8Array> {
  const scraper = new SseUsageScraper(dialect);
  const decoder = new TextDecoder("utf-8");
  let reported = false;
  const report = (): void => {
    if (!reported) {
      reported = true;
      onUsage(scraper.finish());
    }
  };
  return new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      controller.enqueue(chunk);
      scraper.push(decoder.decode(chunk, { stream: true }));
    },
    flush() {
      scraper.push(decoder.decode());
      report();
    },
    // A client disconnect aborts the stream; the Rust pump propagated that to
    // the provider and metered whatever had been observed. Same here.
    cancel() {
      report();
    },
  });
}

/** Read the usage object off a buffered (non-streaming) provider response. */
export function usageFromResponseBody(
  dialect: UsageDialect,
  body: unknown,
): ProviderUsage | undefined {
  return extractUsage(dialect, body);
}

/** Narrow a `ProviderUsage` to the wire shape used in tests and logs. */
export function usageToWire(usage: ProviderUsage | undefined): ProviderUsageWire {
  return {
    ...(usage?.promptTokens !== undefined ? { prompt_tokens: usage.promptTokens } : {}),
    ...(usage?.completionTokens !== undefined ? { completion_tokens: usage.completionTokens } : {}),
    ...(usage?.totalTokens !== undefined ? { total_tokens: usage.totalTokens } : {}),
  };
}
