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
import type { ProviderUsageWire } from "./schemas.js";

/** `ferrogate_providers::ProviderUsage`. */
export interface ProviderUsage {
  readonly promptTokens?: number | undefined;
  readonly completionTokens?: number | undefined;
  readonly totalTokens?: number | undefined;
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

/** True when at least one count was reported (`then_some` guard in Rust). */
function nonEmpty(usage: ProviderUsage): ProviderUsage | undefined {
  return usage.promptTokens !== undefined ||
    usage.completionTokens !== undefined ||
    usage.totalTokens !== undefined
    ? usage
    : undefined;
}

/** `OpenAiCompatibleAdapter::extract_usage` — top-level `usage.{prompt,completion,total}_tokens`. */
export function extractOpenAiUsage(payload: unknown): ProviderUsage | undefined {
  const usage = member(payload, "usage");
  if (usage === undefined) {
    return undefined;
  }
  return nonEmpty({
    promptTokens: asUint(member(usage, "prompt_tokens")),
    completionTokens: asUint(member(usage, "completion_tokens")),
    totalTokens: asUint(member(usage, "total_tokens")),
  });
}

/**
 * `AnthropicAdapter::extract_usage` — `usage.{input,output}_tokens`, falling
 * back to `message.usage` (the `message_start` SSE frame nests it there).
 * `total_tokens` is derived only when BOTH halves are present, as in Rust.
 */
export function extractAnthropicUsage(payload: unknown): ProviderUsage | undefined {
  const usage = member(payload, "usage") ?? member(member(payload, "message"), "usage");
  if (usage === undefined) {
    return undefined;
  }
  const promptTokens = asUint(member(usage, "input_tokens"));
  const completionTokens = asUint(member(usage, "output_tokens"));
  return nonEmpty({
    promptTokens,
    completionTokens,
    totalTokens:
      promptTokens !== undefined && completionTokens !== undefined
        ? promptTokens + completionTokens
        : undefined,
  });
}

/** Extractor selection by the dialect the payload is written in. */
export type UsageDialect = "openai" | "anthropic";

/** `state.extract_provider_usage(kind, payload)`. */
export function extractUsage(dialect: UsageDialect, payload: unknown): ProviderUsage | undefined {
  return dialect === "anthropic" ? extractAnthropicUsage(payload) : extractOpenAiUsage(payload);
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
  return providerKind === "anthropic" ? "anthropic" : "openai";
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
  return {
    promptTokens,
    completionTokens,
    totalTokens: next.totalTokens ?? derivedTotal ?? prior.totalTokens,
  };
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
