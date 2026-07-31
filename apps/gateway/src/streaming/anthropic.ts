/**
 * Anthropic Messages event-frame format, and the OpenAI -> Anthropic streaming
 * normalizer.
 *
 * Clean-room port of `ferrogate-gateway/src/messages_stream.rs`:
 *  - {@link messageToAnthropicFrames} / {@link messageToAnthropicSse} —
 *    `message_to_anthropic_sse`: serialize a *complete* Anthropic Messages
 *    object into the `message_start` / `content_block_start` /
 *    `content_block_delta` / `content_block_stop` / `message_delta` /
 *    `message_stop` sequence. This is the buffered leg, used when a
 *    `BufferAndEnforce` response guardrail has to see the whole stream before
 *    first-byte release.
 *  - {@link OpenAiToAnthropicNormalizer} — `MessagesStreamNormalizer`: the
 *    incremental leg (issue #310). Every provider frame is re-emitted the
 *    moment it is read, so token-by-token delivery survives the translation:
 *    `message_start` on the provider's first chunk, a `content_block_delta` per
 *    token or per tool-argument fragment, and the `message_delta`/`message_stop`
 *    tail once the provider signals completion. Its terminal `stop_reason` and
 *    `usage` are required to match what the buffered pipeline would produce for
 *    the same stream.
 *  - {@link errorSseFrame} — `error_sse`.
 *
 * The Rust version was a synchronous `Read` adapter because Pingora's transform
 * tower is synchronous; on Workers this is a `TransformStream` over the decoded
 * frame stream (`docs/legacy/inventory-request-path.md` §1.5).
 */
import {
  type AnthropicMessagesPort,
  localAnthropicMessagesPort,
} from "./ports.js";
import {
  type SseFrame,
  bytesThroughFrames,
  frameJson,
  isDoneFrame,
  jsonSseFrame,
  serializeSseFrames,
} from "./sse.js";
import { ToolCallAccumulator } from "./toolcalls.js";
import { chatSseToCompletion } from "./openai.js";
import {
  asArray,
  asString,
  get,
  getString,
  getUint,
  nonNull,
} from "./values.js";

/** Fallback message id when the upstream chunk carried none (Rust literal). */
export const FALLBACK_MESSAGE_ID = "msg_ferrogate";
/** Fallback error code for a provider stream failure (Rust literal). */
export const PROVIDER_STREAM_ERROR_CODE = "provider_stream_error";
/** Fallback error message for a provider stream failure (Rust literal). */
export const PROVIDER_STREAM_ERROR_MESSAGE =
  "provider returned a streaming error";

const encoder = new TextEncoder();

/** `error_sse` — an Anthropic-shaped error as a single `event: error` frame. */
export function errorSseFrame(code: string, message: string): SseFrame {
  return jsonSseFrame("error", {
    type: "error",
    error: { type: code, message },
  });
}

/** `error_sse`, as bytes. */
export function errorSse(code: string, message: string): Uint8Array {
  return encoder.encode(serializeSseFrames([errorSseFrame(code, message)]));
}

/**
 * `message_to_anthropic_sse` — a complete Anthropic Messages object rendered as
 * the Anthropic event-frame sequence.
 *
 * `message_start` deliberately carries `output_tokens: 0` (the message has
 * produced nothing yet at that point in the stream) and the real output count
 * only appears on the trailing `message_delta`, which is where Anthropic
 * clients read it from.
 */
export function messageToAnthropicFrames(message: unknown): SseFrame[] {
  const usage = get(message, "usage");
  const inputTokens = getUint(usage, "input_tokens") ?? 0;
  const outputTokens = getUint(usage, "output_tokens") ?? 0;

  const frames: SseFrame[] = [
    jsonSseFrame("message_start", {
      type: "message_start",
      message: {
        id: get(message, "id") ?? FALLBACK_MESSAGE_ID,
        type: "message",
        role: "assistant",
        model: get(message, "model") ?? null,
        content: [],
        stop_reason: null,
        stop_sequence: null,
        usage: { input_tokens: inputTokens, output_tokens: 0 },
      },
    }),
  ];

  const blocks = asArray(get(message, "content")) ?? [];
  for (let index = 0; index < blocks.length; index += 1) {
    frames.push(...contentBlockFrames(index, blocks[index]));
  }

  frames.push(
    jsonSseFrame("message_delta", {
      type: "message_delta",
      delta: {
        stop_reason: get(message, "stop_reason") ?? null,
        stop_sequence: get(message, "stop_sequence") ?? null,
      },
      usage: { output_tokens: outputTokens },
    }),
    jsonSseFrame("message_stop", { type: "message_stop" }),
  );
  return frames;
}

/** `message_to_anthropic_sse`, as bytes. */
export function messageToAnthropicSse(message: unknown): Uint8Array {
  return encoder.encode(serializeSseFrames(messageToAnthropicFrames(message)));
}

/** `emit_content_block` — one `start` / `delta` / `stop` triple. */
function contentBlockFrames(index: number, block: unknown): SseFrame[] {
  if (getString(block, "type") === "tool_use") {
    const input = get(block, "input");
    return [
      jsonSseFrame("content_block_start", {
        type: "content_block_start",
        index,
        content_block: {
          type: "tool_use",
          id: get(block, "id") ?? null,
          name: get(block, "name") ?? null,
          input: {},
        },
      }),
      jsonSseFrame("content_block_delta", {
        type: "content_block_delta",
        index,
        delta: {
          type: "input_json_delta",
          partial_json: input === undefined ? "{}" : JSON.stringify(input),
        },
      }),
      jsonSseFrame("content_block_stop", { type: "content_block_stop", index }),
    ];
  }
  return [
    jsonSseFrame("content_block_start", {
      type: "content_block_start",
      index,
      content_block: { type: "text", text: "" },
    }),
    jsonSseFrame("content_block_delta", {
      type: "content_block_delta",
      index,
      delta: { type: "text_delta", text: asString(get(block, "text")) ?? "" },
    }),
    jsonSseFrame("content_block_stop", { type: "content_block_stop", index }),
  ];
}

/** Options for the OpenAI -> Anthropic normalizer. */
export interface OpenAiToAnthropicOptions {
  /** Model reported on `message_start` when no chunk names one. */
  readonly fallbackModel: string;
  /** Injection seam for the provider-side pure helpers (see `ports.ts`). */
  readonly port?: AnthropicMessagesPort;
}

type OpenBlock =
  | { readonly kind: "text" }
  | { readonly kind: "tool_use"; readonly toolIndex: number };

/**
 * `MessagesStreamNormalizer` — incremental OpenAI chat SSE -> Anthropic events.
 *
 * Drive it frame by frame with {@link push} and finish with {@link flush}. Once
 * {@link completed} is true (a `[DONE]` sentinel, a provider error frame, or
 * end-of-stream) every further frame is dropped, matching the Rust reader,
 * which returns `Ok(0)` forever after the terminal frames are drained.
 */
export class OpenAiToAnthropicNormalizer {
  readonly #fallbackModel: string;
  readonly #port: AnthropicMessagesPort;
  readonly #toolCalls = new ToolCallAccumulator();
  #started = false;
  #completed = false;
  #messageId: string | undefined;
  #model: string | undefined;
  #openBlock: OpenBlock | undefined;
  #currentBlockIndex = 0;
  #nextBlockIndex = 0;
  #finishReason: string | undefined;
  #sawToolUse = false;
  #promptTokens: number | undefined;
  #completionTokens: number | undefined;

  constructor(options: OpenAiToAnthropicOptions) {
    this.#fallbackModel = options.fallbackModel;
    this.#port = options.port ?? localAnthropicMessagesPort;
  }

  /** True once the terminal (or error) frames have been produced. */
  get completed(): boolean {
    return this.#completed;
  }

  /** Translate one upstream frame into zero or more Anthropic frames. */
  push(frame: SseFrame): SseFrame[] {
    if (this.#completed) {
      return [];
    }
    // `drain_frame`: a frame with neither an event name nor data (a provider
    // keep-alive comment) is inert.
    if ((frame.data ?? "") === "" && frame.event === undefined) {
      return [];
    }
    if (isDoneFrame(frame)) {
      // The Anthropic dialect has no `[DONE]` sentinel — it is swallowed and
      // replaced by the `message_delta`/`message_stop` tail.
      return this.finish();
    }
    const payload = frameJson(frame);
    if (payload === undefined) {
      return [];
    }

    // Header fields are latched from the first chunk that carries them.
    this.#messageId ??= getString(payload, "id")?.replaceAll("chatcmpl", "msg");
    this.#model ??= getString(payload, "model");

    const usage = nonNull(get(payload, "usage"));
    if (usage !== undefined) {
      this.#promptTokens = getUint(usage, "prompt_tokens") ?? this.#promptTokens;
      this.#completionTokens =
        getUint(usage, "completion_tokens") ?? this.#completionTokens;
    }

    if (frame.event === "error" || get(payload, "error") !== undefined) {
      return this.#emitError(payload);
    }

    const choice = asArray(get(payload, "choices"))?.[0];
    if (choice === undefined) {
      return [];
    }

    const out: SseFrame[] = [];
    // A chat chunk is flowing: open the Anthropic message immediately so the
    // client sees `message_start` on the provider's very first frame.
    this.#ensureStarted(out);

    const finishReason = getString(choice, "finish_reason");
    if (finishReason !== undefined) {
      this.#finishReason = finishReason;
    }

    const delta = get(choice, "delta");
    if (delta === undefined) {
      return out;
    }

    const text = asString(get(delta, "content"));
    if (text !== undefined && text.length > 0) {
      const index = this.#ensureTextBlock(out);
      out.push(
        jsonSseFrame("content_block_delta", {
          type: "content_block_delta",
          index,
          delta: { type: "text_delta", text },
        }),
      );
    }

    const toolCalls = get(delta, "tool_calls");
    if (toolCalls !== undefined) {
      for (const update of this.#toolCalls.applyToolCallDeltas(toolCalls)) {
        this.#sawToolUse = true;
        const index = this.#ensureToolBlock(out, update.index);
        if (update.argumentsDelta.length > 0) {
          out.push(
            jsonSseFrame("content_block_delta", {
              type: "content_block_delta",
              index,
              delta: {
                type: "input_json_delta",
                partial_json: update.argumentsDelta,
              },
            }),
          );
        }
      }
    }
    return out;
  }

  /** End-of-stream: emit the terminal frames if the stream is still open. */
  flush(): SseFrame[] {
    return this.finish();
  }

  /** `finish_stream` — idempotent terminal `message_delta` + `message_stop`. */
  finish(): SseFrame[] {
    if (this.#completed) {
      return [];
    }
    const out: SseFrame[] = [];
    this.#ensureStarted(out);
    this.#closeOpenBlock(out);
    const stopReason = this.#port.finishReasonToStopReason(
      this.#finishReason,
      this.#sawToolUse,
    );
    const usage: Record<string, number> = {
      output_tokens: this.#completionTokens ?? 0,
    };
    if (this.#promptTokens !== undefined) {
      usage["input_tokens"] = this.#promptTokens;
    }
    out.push(
      jsonSseFrame("message_delta", {
        type: "message_delta",
        delta: { stop_reason: stopReason, stop_sequence: null },
        usage,
      }),
      jsonSseFrame("message_stop", { type: "message_stop" }),
    );
    this.#completed = true;
    return out;
  }

  #emitError(payload: unknown): SseFrame[] {
    const error = get(payload, "error");
    const message =
      asString(get(error, "message")) ?? PROVIDER_STREAM_ERROR_MESSAGE;
    const code =
      asString(get(error, "code")) ??
      asString(get(error, "type")) ??
      PROVIDER_STREAM_ERROR_CODE;
    this.#completed = true;
    return [errorSseFrame(code, message)];
  }

  #ensureStarted(out: SseFrame[]): void {
    if (this.#started) {
      return;
    }
    this.#started = true;
    out.push(
      jsonSseFrame("message_start", {
        type: "message_start",
        message: {
          id: this.#messageId ?? FALLBACK_MESSAGE_ID,
          type: "message",
          role: "assistant",
          model: this.#model ?? this.#fallbackModel,
          content: [],
          stop_reason: null,
          stop_sequence: null,
          usage: { input_tokens: 0, output_tokens: 0 },
        },
      }),
    );
  }

  #closeOpenBlock(out: SseFrame[]): void {
    if (this.#openBlock === undefined) {
      return;
    }
    this.#openBlock = undefined;
    out.push(
      jsonSseFrame("content_block_stop", {
        type: "content_block_stop",
        index: this.#currentBlockIndex,
      }),
    );
  }

  #ensureTextBlock(out: SseFrame[]): number {
    if (this.#openBlock?.kind === "text") {
      return this.#currentBlockIndex;
    }
    this.#closeOpenBlock(out);
    const index = this.#nextBlockIndex;
    this.#nextBlockIndex += 1;
    this.#currentBlockIndex = index;
    this.#openBlock = { kind: "text" };
    out.push(
      jsonSseFrame("content_block_start", {
        type: "content_block_start",
        index,
        content_block: { type: "text", text: "" },
      }),
    );
    return index;
  }

  #ensureToolBlock(out: SseFrame[], toolIndex: number): number {
    const open = this.#openBlock;
    if (open?.kind === "tool_use" && open.toolIndex === toolIndex) {
      return this.#currentBlockIndex;
    }
    this.#closeOpenBlock(out);
    const state = this.#toolCalls.get(toolIndex);
    const index = this.#nextBlockIndex;
    this.#nextBlockIndex += 1;
    this.#currentBlockIndex = index;
    this.#openBlock = { kind: "tool_use", toolIndex };
    out.push(
      jsonSseFrame("content_block_start", {
        type: "content_block_start",
        index,
        content_block: {
          type: "tool_use",
          id: state?.id ?? "",
          name: state?.name ?? "",
          input: {},
        },
      }),
    );
    return index;
  }
}

/** OpenAI chat frames -> Anthropic Messages frames. */
export function openAiToAnthropicFrameStream(
  options: OpenAiToAnthropicOptions,
): TransformStream<SseFrame, SseFrame> {
  const normalizer = new OpenAiToAnthropicNormalizer(options);
  return new TransformStream<SseFrame, SseFrame>({
    transform(frame, controller) {
      for (const out of normalizer.push(frame)) {
        controller.enqueue(out);
      }
    },
    flush(controller) {
      for (const out of normalizer.flush()) {
        controller.enqueue(out);
      }
    },
  });
}

/** OpenAI chat SSE bytes -> Anthropic Messages SSE bytes. */
export function openAiToAnthropicStream(
  options: OpenAiToAnthropicOptions,
): TransformStream<Uint8Array, Uint8Array> {
  return bytesThroughFrames(openAiToAnthropicFrameStream(options), {
    preferRaw: false,
  });
}

/**
 * The buffered/governed leg: aggregate the whole OpenAI stream, translate it to
 * an Anthropic Messages object, then re-serialize the event sequence. This is
 * `chat_sse_to_completion` -> `chat_completion_to_message` ->
 * `message_to_anthropic_sse`, and the incremental normalizer's terminal
 * `stop_reason` / `usage` must agree with it for the same input.
 */
export function bufferedOpenAiToAnthropicSse(
  body: Uint8Array | ArrayBuffer | string,
  fallbackModel: string,
  port: AnthropicMessagesPort = localAnthropicMessagesPort,
): Uint8Array {
  const completion = chatSseToCompletion(body);
  const message = port.chatCompletionToMessage(completion, fallbackModel);
  return messageToAnthropicSse(message);
}
