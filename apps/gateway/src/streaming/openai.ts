/**
 * OpenAI `chat.completions` streaming chunk format.
 *
 * Clean-room port of `ferrogate-gateway/src/messages_stream.rs::chat_sse_to_completion`
 * — the buffered leg of the streaming tower. The gateway runs this whenever a
 * `BufferAndEnforce` response guardrail must inspect a whole stream before
 * first-byte release: the OpenAI SSE chunks are folded back into a single
 * `chat.completion` object so streaming requests get *identical* governance
 * (block/redact, metering) to non-streaming ones, and only then is the result
 * re-serialized into whatever dialect the client asked for.
 *
 * The fold is deliberately lenient, exactly as the Rust is: an unparsable
 * payload, a payload without `choices`, or a `[DONE]` sentinel is skipped
 * rather than failing the request.
 */
import { type SseFrame, frameJson, isDoneFrame, parseSse } from "./sse.js";
import { ToolCallAccumulator } from "./toolcalls.js";
import { asArray, asString, get, getString, nonNull } from "./values.js";

/** Default id used when no upstream chunk carried one (Rust literal). */
export const FALLBACK_COMPLETION_ID = "chatcmpl-ferrogate";

/** The aggregated `chat.completion` object produced by the buffered path. */
export interface AggregatedChatCompletion {
  id: string;
  object: "chat.completion";
  choices: {
    index: number;
    message: Record<string, unknown>;
    finish_reason: string | null;
  }[];
  model?: string;
  usage?: unknown;
}

/**
 * Incremental fold of OpenAI chat chunks into one completion object.
 *
 * Exposed as a class (the Rust is a single function over the whole body) so the
 * same fold can run inline on a live stream — the governed path needs the
 * aggregate at end-of-stream, not a second pass over a buffered body.
 */
export class OpenAiCompletionAggregator {
  #id: string | undefined;
  #model: string | undefined;
  #content = "";
  #sawContent = false;
  #finishReason: string | undefined;
  #usage: unknown;
  readonly #toolCalls = new ToolCallAccumulator();

  /** Fold one frame (the `[DONE]` sentinel is skipped). */
  observe(frame: SseFrame): void {
    if (isDoneFrame(frame)) {
      return;
    }
    this.observePayload(frameJson(frame));
  }

  /** Fold one already-decoded chunk payload. */
  observePayload(payload: unknown): void {
    if (payload === undefined) {
      return;
    }
    this.#id ??= getString(payload, "id");
    this.#model ??= getString(payload, "model");

    const usage = nonNull(get(payload, "usage"));
    if (usage !== undefined) {
      this.#usage = usage;
    }

    const choice = asArray(get(payload, "choices"))?.[0];
    if (choice === undefined) {
      return;
    }
    const finishReason = getString(choice, "finish_reason");
    if (finishReason !== undefined) {
      this.#finishReason = finishReason;
    }
    const delta = get(choice, "delta");
    if (delta === undefined) {
      return;
    }
    const text = asString(get(delta, "content"));
    if (text !== undefined) {
      this.#content += text;
      this.#sawContent = true;
    }
    this.#toolCalls.applyToolCallDeltas(get(delta, "tool_calls"));
  }

  /** Accumulated tool calls (index-ordered). */
  get toolCalls(): ToolCallAccumulator {
    return this.#toolCalls;
  }

  /** The reported `finish_reason`, if any chunk carried one. */
  get finishReason(): string | undefined {
    return this.#finishReason;
  }

  /**
   * Render the aggregate.
   *
   * `message.content` is `null` — not `""` — when no chunk carried text, which
   * is what a tool-call-only completion looks like on the wire and what the
   * Anthropic translation keys off.
   */
  result(): AggregatedChatCompletion {
    const message: Record<string, unknown> = { role: "assistant" };
    message.content = this.#sawContent ? this.#content : null;
    if (!this.#toolCalls.isEmpty) {
      message.tool_calls = this.#toolCalls.toOpenAiToolCalls();
    }
    const completion: AggregatedChatCompletion = {
      id: this.#id ?? FALLBACK_COMPLETION_ID,
      object: "chat.completion",
      choices: [
        {
          index: 0,
          message,
          finish_reason: this.#finishReason ?? null,
        },
      ],
    };
    if (this.#model !== undefined) {
      completion.model = this.#model;
    }
    if (this.#usage !== undefined) {
      completion.usage = this.#usage;
    }
    return completion;
  }
}

/**
 * `chat_sse_to_completion` — aggregate a buffered OpenAI chat SSE body into a
 * single chat-completion object.
 */
export function chatSseToCompletion(
  body: Uint8Array | ArrayBuffer | string | readonly SseFrame[],
): AggregatedChatCompletion {
  const aggregator = new OpenAiCompletionAggregator();
  const frames = Array.isArray(body)
    ? (body as readonly SseFrame[])
    : parseSse(body as Uint8Array | ArrayBuffer | string);
  for (const frame of frames) {
    aggregator.observe(frame);
  }
  return aggregator.result();
}

/**
 * Fold a live frame stream into a completion object without disturbing it: the
 * frames pass through untouched and the aggregate resolves at end-of-stream.
 */
export function chatAggregateStream(): {
  stream: TransformStream<SseFrame, SseFrame>;
  completion: Promise<AggregatedChatCompletion>;
} {
  const aggregator = new OpenAiCompletionAggregator();
  let resolve!: (completion: AggregatedChatCompletion) => void;
  const completion = new Promise<AggregatedChatCompletion>((r) => {
    resolve = r;
  });
  const stream = new TransformStream<SseFrame, SseFrame>({
    transform(frame, controller) {
      aggregator.observe(frame);
      controller.enqueue(frame);
    },
    flush() {
      resolve(aggregator.result());
    },
  });
  return { stream, completion };
}

/** The text carried by one OpenAI chunk's first choice, if any. */
export function chunkText(payload: unknown): string | undefined {
  const delta = get(asArray(get(payload, "choices"))?.[0], "delta");
  return asString(get(delta, "content"));
}

/**
 * PORT_TODO(inventory-request-path §1.5) — **KEPT AS A PARITY BOUNDARY, NOT A
 * GAP.** There is deliberately no Anthropic-events → OpenAI-chunks normalizer
 * here, because there is none in the Rust tree either.
 *
 * Re-verified for this pass, against `crates/`: the tower wires exactly three
 * conversions — OpenAI → Anthropic (`MessagesStreamNormalizer`),
 * OpenAI/Anthropic/Gemini → Responses (`ResponsesStreamNormalizer`), and
 * Anthropic-object → Anthropic-SSE (`message_to_anthropic_sse`). The reverse
 * direction is absent because an Anthropic upstream answering a
 * `/v1/chat/completions` request is translated by the PROVIDER ADAPTER on the
 * non-streaming path before it ever reaches the tower;
 * `defaults.ts::defaultStreamNormalizers` reproduces that by returning `null`
 * (passthrough) for the `openai.chat` dialect, exactly as Rust does.
 *
 * So this marker does not track missing work. It exists so that the NEXT reader
 * who notices the asymmetry does not "fix" it: writing this normalizer would be
 * inventing behavior the tree being ported never had, and a streaming
 * `/v1/chat/completions` against an Anthropic upstream would start emitting a
 * chunk shape no Rust deployment ever emitted. If that conversion is genuinely
 * wanted it is a FEATURE, it belongs with the adapters in
 * `@ferrogate/providers` beside the non-streaming translation it mirrors, and
 * it needs its own acceptance criteria — not a silent addition inside a port.
 */
export const OPENAI_REVERSE_NORMALIZER_UNPORTED = true;
