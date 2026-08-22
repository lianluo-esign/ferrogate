/**
 * Incremental usage / token capture for streamed provider responses.
 *
 * Clean-room port of the Rust streaming metering path in
 * `ferrogate-gateway/src/server/chat.rs`:
 *  - `extract_last_provider_stream_usage` — walk the SSE body, run each frame's
 *    data payload through the provider adapter's `extract_usage`, and merge
 *    field-by-field so a late frame that reports only `completion_tokens` does
 *    not erase the `prompt_tokens` an earlier frame reported;
 *  - `StreamingUsageCapture` / `StreamingUsageCapturingReader` — a bounded
 *    64 KiB prefix+tail window over the raw body kept alongside the live stream;
 *  - the per-provider `extract_usage` implementations in `ferrogate-providers`
 *    (`openai.rs`, `anthropic.rs`, `gemini.rs`) — reproduced here behind
 *    {@link extractUsage} as a NARROW LOCAL INTERFACE, because
 *    `@ferrogate/providers` is a wave-2 stub still being written concurrently.
 *
 * Metering must not block first-byte delivery, so the capture sits *inline* on
 * the stream (it observes, never buffers the whole body) and publishes the
 * result through {@link UsageCapture.completed} — a promise the billing layer
 * awaits AFTER the response stream has been handed to the client.
 */
import { type SseFrame, frameJson, isDoneFrame, parseSse } from "./sse.js";
import { asUint, get, getUint, nonNull } from "./values.js";

/** Which wire dialect the usage frame is written in. */
export type UsageProviderKind = "openai_compatible" | "anthropic" | "gemini" | "other";

/**
 * Normalized token counts — the TS twin of `ferrogate_providers::ProviderUsage`
 * (`prompt_tokens` / `completion_tokens` / `total_tokens`, each `Option<u64>`),
 * extended with the cached/reasoning counters (issue #667).
 *
 * The subset invariant and the per-family conversion that establishes it are
 * documented once, on `../inference/usage.ts::ProviderUsage`. This module is the
 * PARSED-FRAME twin of that scraper (see the module doc there for why two
 * exist), and the two must agree field for field — a request that billed
 * differently depending on which ingress it arrived through would be worse than
 * either answer alone. `test/metering/cached-reasoning-tokens.test.ts` asserts
 * the agreement directly rather than trusting the comment.
 */
export interface NormalizedUsage {
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

/** True when no field of the usage record is populated. */
export function isUsageEmpty(usage: NormalizedUsage | undefined): boolean {
  return (
    usage === undefined ||
    (usage.promptTokens === undefined &&
      usage.completionTokens === undefined &&
      usage.totalTokens === undefined)
  );
}

/** Render as the OpenAI `usage` object (used by the Responses normalizer). */
export function usageToOpenAiJson(usage: NormalizedUsage): {
  prompt_tokens: number | null;
  completion_tokens: number | null;
  total_tokens: number | null;
} {
  return {
    prompt_tokens: usage.promptTokens ?? null,
    completion_tokens: usage.completionTokens ?? null,
    total_tokens: usage.totalTokens ?? null,
  };
}

/**
 * Extract usage from one decoded frame payload.
 *
 * Returns `undefined` when the payload reports nothing — mirroring the Rust
 * adapters, which return `None` unless at least one of the three counters is
 * present, so a usage-less chunk never clobbers an earlier reading.
 */
export function extractUsage(
  payload: unknown,
  kind: UsageProviderKind = "openai_compatible",
): NormalizedUsage | undefined {
  switch (kind) {
    case "anthropic":
      return extractAnthropicUsage(payload);
    case "gemini":
      return extractGeminiUsage(payload);
    case "openai_compatible":
    case "other":
      return extractOpenAiUsage(payload);
    default:
      return extractOpenAiUsage(payload);
  }
}

function finish(usage: NormalizedUsage): NormalizedUsage | undefined {
  return isUsageEmpty(usage) ? undefined : usage;
}

/**
 * Drop `undefined`-valued cached/reasoning keys so an absent counter stays
 * ABSENT — the property {@link mergeUsage} relies on to keep a later frame from
 * erasing an earlier frame's reading.
 */
function withCounters(
  base: NormalizedUsage,
  counters: {
    cachedInputTokens?: number | undefined;
    cacheWriteTokens?: number | undefined;
    reasoningTokens?: number | undefined;
  },
): NormalizedUsage {
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
 * `ferrogate-providers/src/openai.rs::extract_usage`, plus the cached/reasoning
 * details (#667).
 *
 * Both detail spellings are read — `prompt_tokens_details` /
 * `completion_tokens_details` (Chat Completions) and `input_tokens_details` /
 * `output_tokens_details` (Responses). Both counts are already subsets of the
 * headline counts in OpenAI's accounting, so nothing is added in.
 */
function extractOpenAiUsage(payload: unknown): NormalizedUsage | undefined {
  const usage = nonNull(get(payload, "usage")) ?? nonNull(get(get(payload, "response"), "usage"));
  if (usage === undefined) {
    return undefined;
  }
  const promptDetails =
    nonNull(get(usage, "prompt_tokens_details")) ?? nonNull(get(usage, "input_tokens_details"));
  const completionDetails =
    nonNull(get(usage, "completion_tokens_details")) ??
    nonNull(get(usage, "output_tokens_details"));
  return finish(
    withCounters(
      {
        promptTokens: getUint(usage, "prompt_tokens") ?? getUint(usage, "input_tokens"),
        completionTokens: getUint(usage, "completion_tokens") ?? getUint(usage, "output_tokens"),
        totalTokens: getUint(usage, "total_tokens"),
      },
      {
        cachedInputTokens:
          promptDetails === undefined ? undefined : getUint(promptDetails, "cached_tokens"),
        reasoningTokens:
          completionDetails === undefined
            ? undefined
            : getUint(completionDetails, "reasoning_tokens"),
      },
    ),
  );
}

/**
 * `ferrogate-providers/src/anthropic.rs::extract_usage`.
 *
 * Handles both Anthropic streaming carriers: `message_start` nests the counts
 * under `message.usage` (input tokens, `output_tokens: 0`), while
 * `message_delta` reports the final `usage.output_tokens` at the tail of the
 * stream. `total_tokens` is only synthesized when both halves are known.
 *
 * ## The parity boundary that stood here is CLOSED (issue #667)
 *
 * It read: "Anthropic's newer `cache_creation_input_tokens` /
 * `cache_read_input_tokens` counters are not read here", correctly noted that
 * the Rust tree read neither (`crates/ferrogate-providers/src/anthropic.rs`
 * `extract_usage` reads `input_tokens` and `output_tokens` and nothing else),
 * and just as correctly refused to smuggle a fix in as a port — because summing
 * the two counters into `promptTokens` would be *a different wrong answer*: they
 * bill at different rates from ordinary input tokens (Anthropic prices a cache
 * read at 0.1x and a 5-minute cache write at 1.25x), so folding them in without
 * a split would over-bill the read side roughly tenfold.
 *
 * That objection is what the fix is BUILT ON rather than around. The counters
 * are summed into `promptTokens` — which is what makes the 25 000 previously
 * invisible tokens billable at all — AND carried separately, so
 * `@ferrogate/billing`'s `estimateCost` can subtract them back out and price
 * each at its own rate. The rate card gained the three rates in the same change
 * (`ModelPrice.cached_input_price_per_1m` and siblings), so this is no longer a
 * capture that outruns its pricing.
 *
 * `output_tokens` is left alone: Anthropic counts extended-thinking tokens
 * inside it and publishes no separate counter, so `reasoningTokens` stays absent
 * rather than invented — which prices thinking at the output rate, which is
 * correct.
 */
function extractAnthropicUsage(payload: unknown): NormalizedUsage | undefined {
  const usage = nonNull(get(payload, "usage")) ?? nonNull(get(get(payload, "message"), "usage"));
  if (usage === undefined) {
    return undefined;
  }
  const freshInput = getUint(usage, "input_tokens");
  const cachedInputTokens = getUint(usage, "cache_read_input_tokens");
  const cacheWriteTokens = getUint(usage, "cache_creation_input_tokens");
  const completionTokens = getUint(usage, "output_tokens");
  // Only widen a REPORTED `input_tokens`. A frame carrying cache counters and no
  // `input_tokens` must not manufacture a prompt count, or `mergeUsage` would
  // let it overwrite the real one.
  const promptTokens =
    freshInput === undefined
      ? undefined
      : freshInput + (cachedInputTokens ?? 0) + (cacheWriteTokens ?? 0);
  const totalTokens =
    promptTokens !== undefined && completionTokens !== undefined
      ? promptTokens + completionTokens
      : undefined;
  return finish(
    withCounters(
      { promptTokens, completionTokens, totalTokens },
      { cachedInputTokens, cacheWriteTokens },
    ),
  );
}

/**
 * `ferrogate-providers/src/gemini.rs::extract_usage`, plus the cached-content
 * and thoughts counters (#667).
 *
 * `candidatesTokenCount` EXCLUDES `thoughtsTokenCount` while `totalTokenCount`
 * INCLUDES it, so thoughts are added into the completion count: that both makes
 * reasoning tokens billable and restores `prompt + completion == total`.
 * `cachedContentTokenCount` is already inside `promptTokenCount` and needs no
 * addition.
 */
function extractGeminiUsage(payload: unknown): NormalizedUsage | undefined {
  const usage = nonNull(get(payload, "usageMetadata"));
  if (usage === undefined) {
    return undefined;
  }
  const visible = getUint(usage, "candidatesTokenCount");
  const reasoningTokens = getUint(usage, "thoughtsTokenCount");
  return finish(
    withCounters(
      {
        promptTokens: getUint(usage, "promptTokenCount"),
        completionTokens:
          visible === undefined ? reasoningTokens : visible + (reasoningTokens ?? 0),
        totalTokens: getUint(usage, "totalTokenCount"),
      },
      { cachedInputTokens: getUint(usage, "cachedContentTokenCount"), reasoningTokens },
    ),
  );
}

/**
 * Field-wise merge, exactly as `extract_last_provider_stream_usage` folds each
 * frame into the running total: a field reported by the newer frame wins, an
 * unreported field falls back to the previous reading, and `total_tokens` is
 * synthesized from prompt+completion when the provider omits it.
 */
export function mergeUsage(
  previous: NormalizedUsage | undefined,
  next: NormalizedUsage | undefined,
): NormalizedUsage | undefined {
  if (next === undefined) {
    return previous;
  }
  const base = previous ?? {};
  const promptTokens = next.promptTokens ?? base.promptTokens;
  const completionTokens = next.completionTokens ?? base.completionTokens;
  const derivedTotal =
    promptTokens !== undefined && completionTokens !== undefined
      ? promptTokens + completionTokens
      : undefined;
  const totalTokens = next.totalTokens ?? derivedTotal ?? base.totalTokens;
  // Same prefer-new-fall-back-to-old rule for the #667 counters, and it is
  // load-bearing on the Anthropic stream: the cache counters arrive ONCE, on
  // `message_start`, while the terminal `message_delta` reports only
  // `output_tokens`. Letting the newer frame's absence win would drop the whole
  // request's cache discount on the very last frame.
  return withCounters(
    { promptTokens, completionTokens, totalTokens },
    {
      cachedInputTokens: next.cachedInputTokens ?? base.cachedInputTokens,
      cacheWriteTokens: next.cacheWriteTokens ?? base.cacheWriteTokens,
      reasoningTokens: next.reasoningTokens ?? base.reasoningTokens,
    },
  );
}

/**
 * Whole-body scrape — the buffered/governed path's entry point, equivalent to
 * `extract_last_provider_stream_usage(body, adapter.extract_usage)`.
 */
export function extractLastStreamUsage(
  body: Uint8Array | ArrayBuffer | string,
  kind: UsageProviderKind = "openai_compatible",
): NormalizedUsage | undefined {
  const capture = new UsageCapture({ kind });
  for (const frame of parseSse(body)) {
    capture.observe(frame);
  }
  return capture.usage;
}

/** Options for {@link UsageCapture}. */
export interface UsageCaptureOptions {
  /** Wire dialect of the *upstream* frames being observed. */
  readonly kind?: UsageProviderKind;
  /** Invoked once, after the stream ends, with the final merged usage. */
  readonly onUsage?: (usage: NormalizedUsage | undefined) => void;
}

/**
 * Live, allocation-free usage scraper.
 *
 * Feed it every upstream frame with {@link observe}; call {@link complete} when
 * the stream ends. {@link usage} is readable at any point (a partial reading
 * mid-stream), and {@link completed} resolves once — that promise is what the
 * metering layer awaits so billing runs strictly AFTER the client has been
 * served.
 */
export class UsageCapture {
  readonly #kind: UsageProviderKind;
  readonly #onUsage: ((usage: NormalizedUsage | undefined) => void) | undefined;
  readonly #completed: Promise<NormalizedUsage | undefined>;
  #resolve!: (usage: NormalizedUsage | undefined) => void;
  #usage: NormalizedUsage | undefined;
  #done = false;

  constructor(options: UsageCaptureOptions = {}) {
    this.#kind = options.kind ?? "openai_compatible";
    this.#onUsage = options.onUsage;
    this.#completed = new Promise<NormalizedUsage | undefined>((resolve) => {
      this.#resolve = resolve;
    });
  }

  /** Usage merged from every frame observed so far. */
  get usage(): NormalizedUsage | undefined {
    return this.#usage;
  }

  /** Resolves with the final usage once the stream has ended. */
  get completed(): Promise<NormalizedUsage | undefined> {
    return this.#completed;
  }

  /** True once {@link complete} has run. */
  get isComplete(): boolean {
    return this.#done;
  }

  /** Observe one upstream frame. The `[DONE]` sentinel carries no usage. */
  observe(frame: SseFrame): void {
    if (isDoneFrame(frame)) {
      return;
    }
    this.observePayload(frameJson(frame));
  }

  /** Observe an already-decoded payload. */
  observePayload(payload: unknown): void {
    if (payload === undefined) {
      return;
    }
    const extracted = extractUsage(payload, this.#kind);
    if (extracted === undefined) {
      return;
    }
    this.#usage = mergeUsage(this.#usage, extracted);
  }

  /** End the capture and publish the result. Idempotent. */
  complete(): NormalizedUsage | undefined {
    if (this.#done) {
      return this.#usage;
    }
    this.#done = true;
    this.#onUsage?.(this.#usage);
    this.#resolve(this.#usage);
    return this.#usage;
  }
}

/** A usage-capturing frame tap plus the handle the metering layer consumes. */
export interface UsageCaptureStream {
  /** Pass-through transform: every frame in is the same frame out. */
  readonly stream: TransformStream<SseFrame, SseFrame>;
  /** The live capture (readable mid-stream). */
  readonly capture: UsageCapture;
  /** Resolves with the final usage once the stream ends. */
  readonly usage: Promise<NormalizedUsage | undefined>;
}

/**
 * Inline usage tap. Frames flow through untouched — the framing the client sees
 * is byte-identical to the upstream's — while the usage frame is scraped on the
 * way past.
 */
export function usageCaptureStream(options: UsageCaptureOptions = {}): UsageCaptureStream {
  const capture = new UsageCapture(options);
  const stream = new TransformStream<SseFrame, SseFrame>({
    transform(frame, controller) {
      capture.observe(frame);
      controller.enqueue(frame);
    },
    flush() {
      capture.complete();
    },
  });
  return { stream, capture, usage: capture.completed };
}

// ---------------------------------------------------------------------------
// Bounded raw-body capture (`chat.rs::StreamingUsageCapture`).
// ---------------------------------------------------------------------------

/** `STREAMING_USAGE_CAPTURE_MAX_BYTES`. */
export const STREAMING_CAPTURE_MAX_BYTES = 64 * 1024;
/** `STREAMING_USAGE_CAPTURE_PREFIX_MAX_BYTES`. */
export const STREAMING_CAPTURE_PREFIX_MAX_BYTES = 8 * 1024;
const CAPTURE_SEPARATOR = new TextEncoder().encode("\n\n");
/** `STREAMING_USAGE_CAPTURE_TAIL_MAX_BYTES`. */
export const STREAMING_CAPTURE_TAIL_MAX_BYTES =
  STREAMING_CAPTURE_MAX_BYTES - STREAMING_CAPTURE_PREFIX_MAX_BYTES - CAPTURE_SEPARATOR.length;

/**
 * Bounded prefix+tail window over a streamed body — the port of
 * `chat.rs::StreamingUsageCapture`.
 *
 * A stream can be arbitrarily long, so the capture keeps the first 8 KiB (which
 * carries the model/id header frames) and the trailing window (which carries
 * the usage frame), joined by a blank line so the reconstructed body is still
 * parseable SSE. Under the 64 KiB cap the body is retained verbatim.
 */
export class StreamingBodyCapture {
  #prefix = new Uint8Array(STREAMING_CAPTURE_PREFIX_MAX_BYTES);
  #prefixLength = 0;
  #tail = new Uint8Array(0);
  #totalBytes = 0;

  /** Total bytes fed in, including bytes evicted from the window. */
  get totalBytes(): number {
    return this.#totalBytes;
  }

  /** True once the body exceeded the cap and the middle was dropped. */
  get truncated(): boolean {
    return this.#totalBytes > STREAMING_CAPTURE_MAX_BYTES;
  }

  /** Append the next raw chunk. */
  append(bytes: Uint8Array): void {
    if (bytes.length === 0) {
      return;
    }
    const prefixRemaining = STREAMING_CAPTURE_PREFIX_MAX_BYTES - this.#prefixLength;
    if (prefixRemaining > 0) {
      const take = Math.min(prefixRemaining, bytes.length);
      this.#prefix.set(bytes.subarray(0, take), this.#prefixLength);
      this.#prefixLength += take;
    }
    this.#totalBytes += bytes.length;

    const bodyLimit =
      this.#totalBytes > STREAMING_CAPTURE_MAX_BYTES
        ? STREAMING_CAPTURE_TAIL_MAX_BYTES
        : STREAMING_CAPTURE_MAX_BYTES;

    if (bytes.length >= bodyLimit) {
      this.#tail = bytes.slice(bytes.length - bodyLimit);
      return;
    }
    const combined = new Uint8Array(this.#tail.length + bytes.length);
    combined.set(this.#tail, 0);
    combined.set(bytes, this.#tail.length);
    this.#tail =
      combined.length > bodyLimit ? combined.subarray(combined.length - bodyLimit) : combined;
  }

  /** The captured body: verbatim under the cap, prefix + `\n\n` + tail over it. */
  body(): Uint8Array {
    if (this.#totalBytes <= STREAMING_CAPTURE_MAX_BYTES) {
      return this.#tail.slice();
    }
    const prefix = this.#prefix.subarray(0, this.#prefixLength);
    const out = new Uint8Array(prefix.length + CAPTURE_SEPARATOR.length + this.#tail.length);
    out.set(prefix, 0);
    out.set(CAPTURE_SEPARATOR, prefix.length);
    out.set(this.#tail, prefix.length + CAPTURE_SEPARATOR.length);
    return out;
  }
}

/** A byte tap plus the bounded capture it fills (`StreamingUsageCapturingReader`). */
export interface BodyCaptureStream {
  readonly stream: TransformStream<Uint8Array, Uint8Array>;
  readonly capture: StreamingBodyCapture;
  readonly completed: Promise<Uint8Array>;
}

/** Byte-level pass-through that fills a bounded {@link StreamingBodyCapture}. */
export function bodyCaptureStream(initialBody?: Uint8Array): BodyCaptureStream {
  const capture = new StreamingBodyCapture();
  if (initialBody !== undefined) {
    capture.append(initialBody);
  }
  let resolve!: (body: Uint8Array) => void;
  const completed = new Promise<Uint8Array>((r) => {
    resolve = r;
  });
  const stream = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      capture.append(chunk);
      controller.enqueue(chunk);
    },
    flush() {
      resolve(capture.body());
    },
  });
  return { stream, capture, completed };
}

/** Re-exported for callers that only need the numeric guard. */
export { asUint as asTokenCount };
