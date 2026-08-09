/**
 * Capturing the assistant turn off a STREAMED `/v1/responses` answer (#689).
 *
 * ============================================================================
 * WHY A STREAM NEEDS ITS OWN CAPTURE AT ALL
 * ============================================================================
 *
 * On the buffered path the served body IS the turn: it has an `id`, an `output`
 * array, and `handlers.ts` stores it. A stream has neither. Worse, the two
 * streaming sub-paths disagree about what flows:
 *
 *  - when the upstream dialect differs from the ingress one,
 *    `streaming/responses.ts::ResponsesStreamNormalizer` SYNTHESIZES the whole
 *    `response.*` sequence, and that sequence carries no response id and no
 *    output items — only `response.output_text.delta` frames and a terminal
 *    `response.completed` holding usage;
 *  - when the upstream already speaks `openai.responses`, the provider's own
 *    frames are relayed byte for byte, and those DO carry a `response.completed`
 *    event with the complete `response` object in it.
 *
 * So refusing `store: true` on a stream would have been the easy answer and the
 * wrong one — agents stream, and "conversation state works unless you stream"
 * is not conversation state. This tap handles both shapes: it prefers the
 * provider's own completed `response.output` when one arrives, and falls back
 * to assembling the text deltas into a single output message when it does not.
 *
 * ============================================================================
 * IT NEVER TOUCHES THE CLIENT'S BYTES
 * ============================================================================
 *
 * Same construction as `usage.ts::sseUsageTap`, and for the same reason: the
 * chunks are re-enqueued as the SAME `Uint8Array` references and the scrape
 * runs off a separate streaming `TextDecoder`, so a multi-byte character split
 * across a chunk boundary cannot corrupt either path and first-token latency is
 * unchanged. Unlike that tap this one must read the `event:` line too — our
 * synthesized text deltas and function-call-argument deltas both carry a
 * `delta` member and are told apart only by their event name.
 */

/** What one streamed turn produced, as `output` items. */
export interface CapturedResponseOutput {
  /** The `output` array to store, possibly empty. */
  readonly output: readonly unknown[];
  /** The provider's own response id, when the stream carried one. */
  readonly upstreamResponseId: string | undefined;
}

/**
 * Assemble accumulated text into the one output item the Responses API defines
 * for an assistant message.
 *
 * Shaped as a real `message` item rather than a bare string because the whole
 * point of storing output items is that they are replayable AS INPUT on the
 * next turn — `conversation.ts::conversationInput` pushes them straight back —
 * and a bare string would be replayed as an unlabelled item of unknown role.
 */
export function assistantMessageItem(text: string): Record<string, unknown> {
  return {
    type: "message",
    role: "assistant",
    status: "completed",
    content: [{ type: "output_text", text }],
  };
}

/**
 * A pass-through `TransformStream` that reports the assistant turn on flush.
 *
 * `onOutput` is called EXACTLY once — on flush, or on cancel when the client
 * hangs up mid-stream. The cancel arm is deliberate and matches `sseUsageTap`'s:
 * a disconnected client still consumed (and is still billed for) what arrived,
 * and a conversation that silently lost its last turn because the reader went
 * away would be the same context loss this issue is about.
 */
export function responsesOutputTap(
  onOutput: (captured: CapturedResponseOutput) => void,
): TransformStream<Uint8Array, Uint8Array> {
  const scraper = new ResponsesOutputScraper();
  const decoder = new TextDecoder("utf-8");
  let reported = false;
  const report = (): void => {
    if (reported) return;
    reported = true;
    onOutput(scraper.finish());
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
    cancel() {
      report();
    },
  });
}

/**
 * The incremental SSE reader behind {@link responsesOutputTap}.
 *
 * Holds at most one frame plus the accumulated text — the same bounded-memory
 * property `SseUsageScraper` has. The accumulated text is capped
 * ({@link MAX_CAPTURED_TEXT}) so a runaway upstream cannot make a streamed
 * response cost unbounded isolate memory; hitting the cap marks the capture
 * TRUNCATED, and `handlers.ts` declines to store a truncated turn rather than
 * persisting a conversation that is quietly missing its tail.
 */
const MAX_CAPTURED_TEXT = 1_000_000;

export class ResponsesOutputScraper {
  #pending = "";
  #eventName: string | undefined;
  #data = "";
  #sawData = false;
  #text = "";
  #truncated = false;
  #completedOutput: unknown[] | undefined;
  #upstreamResponseId: string | undefined;

  /** Feed decoded text; chunk boundaries may fall anywhere. */
  push(text: string): void {
    this.#pending += text;
    let start = 0;
    for (;;) {
      const newline = this.#pending.indexOf("\n", start);
      if (newline < 0) break;
      this.#line(this.#pending.slice(start, newline));
      start = newline + 1;
    }
    this.#pending = this.#pending.slice(start);
  }

  finish(): CapturedResponseOutput {
    if (this.#pending.length > 0) {
      this.#line(this.#pending);
      this.#pending = "";
    }
    this.#dispatch();
    // The provider's own completed `response.output` WINS over the assembled
    // text: it carries reasoning items and tool calls the deltas never showed.
    const output =
      this.#completedOutput ?? (this.#text === "" ? [] : [assistantMessageItem(this.#text)]);
    return {
      output,
      ...(this.#upstreamResponseId !== undefined
        ? { upstreamResponseId: this.#upstreamResponseId }
        : { upstreamResponseId: undefined }),
    };
  }

  /** True when the text cap was hit, so the capture is incomplete. */
  get truncated(): boolean {
    return this.#truncated;
  }

  #line(rawLine: string): void {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    if (line.length === 0) {
      this.#dispatch();
      return;
    }
    if (line.startsWith("event:")) {
      this.#eventName = line.slice("event:".length).trim();
      return;
    }
    if (!line.startsWith("data:")) return;
    let data = line.slice("data:".length);
    if (data.startsWith(" ")) data = data.slice(1);
    if (this.#sawData) this.#data += "\n";
    this.#data += data;
    this.#sawData = true;
  }

  #dispatch(): void {
    if (this.#sawData && this.#data !== "[DONE]") {
      let payload: unknown;
      try {
        payload = JSON.parse(this.#data);
      } catch {
        payload = undefined;
      }
      if (payload !== undefined) this.#frame(payload);
    }
    this.#eventName = undefined;
    this.#data = "";
    this.#sawData = false;
  }

  #frame(payload: unknown): void {
    const record =
      typeof payload === "object" && payload !== null && !Array.isArray(payload)
        ? (payload as Record<string, unknown>)
        : undefined;
    if (record === undefined) return;
    // The event name may arrive on the `event:` line (our normalizer, and the
    // OpenAI wire format) or as the payload's own `type` (some relays send only
    // `data:`). Both are accepted; neither is required to be present.
    const type = this.#eventName ?? (typeof record.type === "string" ? record.type : undefined);

    if (type === "response.output_text.delta") {
      const delta = record.delta;
      if (typeof delta === "string" && !this.#truncated) {
        if (this.#text.length + delta.length > MAX_CAPTURED_TEXT) {
          this.#truncated = true;
        } else {
          this.#text += delta;
        }
      }
      return;
    }

    if (type === "response.completed" || type === "response.incomplete") {
      const response = record.response;
      if (typeof response === "object" && response !== null && !Array.isArray(response)) {
        const body = response as Record<string, unknown>;
        const output = body.output;
        if (Array.isArray(output)) this.#completedOutput = [...output];
        const id = body.id;
        if (typeof id === "string" && id !== "") this.#upstreamResponseId = id;
      }
    }
  }
}
