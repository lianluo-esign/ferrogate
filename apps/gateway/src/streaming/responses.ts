/**
 * OpenAI **Responses** (`response.*`) streaming format.
 *
 * Clean-room port of `ferrogate-gateway/src/responses_stream.rs`
 * (`ResponsesStreamNormalizer`, `ResponsesStreamProviderKind`,
 * `ProviderUsageState`, `FunctionCallState`). This is the normalizer behind
 * `POST /v1/responses`: whatever dialect the selected upstream speaks
 * (OpenAI-compatible, Anthropic, Gemini, or an unclassified "other"), the
 * client always sees the same `response.*` event sequence:
 *
 * ```
 * event: response.output_text.delta               (per text token)
 * event: response.function_call_arguments.delta   (per tool-argument fragment)
 * event: response.output_text.done                (once, if any text flowed)
 * event: response.function_call_arguments.done    (once per accumulated call)
 * event: response.completed                       (carries the merged usage)
 * data: [DONE]
 * ```
 *
 * A provider error short-circuits to `response.failed` + `[DONE]`, and nothing
 * further is emitted.
 */
import {
  DONE_SENTINEL,
  type SseFrame,
  bytesThroughFrames,
  frameJson,
  isDoneFrame,
  jsonSseFrame,
  sseFrame,
} from "./sse.js";
import { ToolCallAccumulator, type ToolCallUpdate } from "./toolcalls.js";
import { asArray, asRecord, asString, asUint, get, getString, getUint } from "./values.js";

/** `ResponsesStreamProviderKind`. */
export type ResponsesStreamProviderKind = "openai_compatible" | "anthropic" | "gemini" | "other";

/** Fallback error code for a provider stream failure (Rust literal). */
export const RESPONSES_STREAM_ERROR_CODE = "provider_stream_error";
/** Fallback error message for a provider stream failure (Rust literal). */
export const RESPONSES_STREAM_ERROR_MESSAGE = "provider returned a streaming error";

/**
 * `ProviderUsageState`.
 *
 * Usage is merged field by field because Anthropic splits input/cache counts
 * onto `message_start` and output counts onto `message_delta`. Gemini thinking
 * tokens are folded into output, matching the billing extractor.
 */
class ProviderUsageState {
  promptTokens: number | null = null;
  completionTokens: number | null = null;
  totalTokens: number | null = null;

  updateFromValue(value: unknown, kind: ResponsesStreamProviderKind): void {
    if (kind === "anthropic") {
      const usage = get(value, "usage") ?? get(get(value, "message"), "usage");
      if (usage === undefined) return;
      const fresh = getUint(usage, "input_tokens");
      const cacheRead = getUint(usage, "cache_read_input_tokens") ?? 0;
      const cacheWrite = getUint(usage, "cache_creation_input_tokens") ?? 0;
      if (fresh !== undefined) this.promptTokens = fresh + cacheRead + cacheWrite;
      this.completionTokens = getUint(usage, "output_tokens") ?? this.completionTokens;
      this.totalTokens =
        this.promptTokens !== null && this.completionTokens !== null
          ? this.promptTokens + this.completionTokens
          : null;
      return;
    }
    if (kind === "gemini") {
      const usage = get(value, "usageMetadata");
      if (usage === undefined) {
        return;
      }
      this.promptTokens = getUint(usage, "promptTokenCount") ?? this.promptTokens;
      const visible = getUint(usage, "candidatesTokenCount");
      const thinking = getUint(usage, "thoughtsTokenCount");
      if (visible !== undefined || thinking !== undefined) {
        this.completionTokens = (visible ?? 0) + (thinking ?? 0);
      }
      this.totalTokens =
        getUint(usage, "totalTokenCount") ??
        (this.promptTokens !== null && this.completionTokens !== null
          ? this.promptTokens + this.completionTokens
          : this.totalTokens);
      return;
    }
    const usage = get(value, "usage") ?? get(get(value, "response"), "usage");
    if (usage === undefined) {
      return;
    }
    this.promptTokens =
      getUint(usage, "prompt_tokens") ?? getUint(usage, "input_tokens") ?? this.promptTokens;
    this.completionTokens =
      getUint(usage, "completion_tokens") ??
      getUint(usage, "output_tokens") ??
      this.completionTokens;
    this.totalTokens =
      getUint(usage, "total_tokens") ??
      (this.promptTokens !== null && this.completionTokens !== null
        ? this.promptTokens + this.completionTokens
        : this.totalTokens);
  }

  toJson(): {
    prompt_tokens: number | null;
    completion_tokens: number | null;
    total_tokens: number | null;
  } {
    return {
      prompt_tokens: this.promptTokens,
      completion_tokens: this.completionTokens,
      total_tokens: this.totalTokens,
    };
  }
}

/** Options for {@link ResponsesStreamNormalizer}. */
export interface ResponsesStreamOptions {
  /** Which dialect the upstream speaks. */
  readonly providerKind: ResponsesStreamProviderKind;
  /** Echoed into every emitted event as `request_id`. */
  readonly requestId: string;
  /** Echoed into `response.completed` as `content_type`. */
  readonly contentType?: string;
}

/** `ResponsesStreamNormalizer`. */
export class ResponsesStreamNormalizer {
  readonly #kind: ResponsesStreamProviderKind;
  readonly #requestId: string;
  readonly #contentType: string;
  readonly #usage = new ProviderUsageState();
  readonly #functionCalls = new ToolCallAccumulator();
  #completed = false;
  #sawTextDelta = false;
  #sawFunctionCallDelta = false;

  constructor(options: ResponsesStreamOptions) {
    this.#kind = options.providerKind;
    this.#requestId = options.requestId;
    this.#contentType = options.contentType ?? "text/event-stream";
  }

  /** True once the terminal (or failure) frames have been produced. */
  get completed(): boolean {
    return this.#completed;
  }

  /** Merged usage observed so far (`null` fields = not reported). */
  get usage(): {
    prompt_tokens: number | null;
    completion_tokens: number | null;
    total_tokens: number | null;
  } {
    return this.#usage.toJson();
  }

  /** `drain_frame` — translate one upstream frame. */
  push(frame: SseFrame): SseFrame[] {
    if (this.#completed) {
      return [];
    }
    if ((frame.data ?? "") === "" && frame.event === undefined) {
      return [];
    }
    if (isDoneFrame(frame)) {
      return this.finish();
    }

    const eventName = frame.event;
    const parsed = frameJson(frame);
    if (parsed !== undefined) {
      this.#usage.updateFromValue(parsed, this.#kind);
    }

    const failure = this.#emitError(eventName, parsed);
    if (failure !== undefined) {
      this.#completed = true;
      return failure;
    }

    const out: SseFrame[] = [];
    for (const delta of extractTextDeltas(this.#kind, eventName, parsed)) {
      this.#sawTextDelta = true;
      out.push(
        jsonSseFrame("response.output_text.delta", {
          request_id: this.#requestId,
          delta,
        }),
      );
    }

    for (const update of extractFunctionCallDeltas(
      this.#kind,
      eventName,
      parsed,
      this.#functionCalls,
    )) {
      this.#sawFunctionCallDelta = true;
      out.push(
        jsonSseFrame("response.function_call_arguments.delta", {
          request_id: this.#requestId,
          index: update.index,
          call_id: update.state.id ?? null,
          name: update.state.name ?? null,
          delta: update.argumentsDelta,
        }),
      );
    }

    if (isDoneEvent(eventName, parsed)) {
      // The Rust reader sets `eof` here and runs `finish_stream` once the
      // current read buffer has drained; frame-at-a-time we finish immediately,
      // which is the same sequence for every real provider (the done marker is
      // the last frame) and strictly more deterministic.
      out.push(...this.finish());
    }
    return out;
  }

  /** End-of-stream. */
  flush(): SseFrame[] {
    return this.finish();
  }

  /** `finish_stream` — idempotent `*.done` + `response.completed` + `[DONE]`. */
  finish(): SseFrame[] {
    if (this.#completed) {
      return [];
    }
    const out: SseFrame[] = [];
    if (this.#sawTextDelta) {
      out.push(sseFrame({ event: "response.output_text.done", data: "{}" }));
    }
    if (this.#sawFunctionCallDelta) {
      for (const call of this.#functionCalls.snapshot()) {
        out.push(
          jsonSseFrame("response.function_call_arguments.done", {
            request_id: this.#requestId,
            index: call.index,
            call_id: call.id ?? null,
            name: call.name ?? null,
            arguments: call.arguments,
          }),
        );
      }
    }
    out.push(
      jsonSseFrame("response.completed", {
        request_id: this.#requestId,
        content_type: this.#contentType,
        usage: this.#usage.toJson(),
      }),
      sseFrame({ data: DONE_SENTINEL }),
    );
    this.#completed = true;
    return out;
  }

  /** `emit_error` — `response.failed` + `[DONE]`, or `undefined` if not an error. */
  #emitError(eventName: string | undefined, parsed: unknown): SseFrame[] | undefined {
    const error = get(parsed, "error");
    if (eventName !== "error" && error === undefined) {
      return undefined;
    }
    const message =
      asString(get(error, "message")) ?? asString(parsed) ?? RESPONSES_STREAM_ERROR_MESSAGE;
    const code =
      asString(get(error, "code")) ?? asString(get(error, "type")) ?? RESPONSES_STREAM_ERROR_CODE;
    return [
      jsonSseFrame("response.failed", {
        request_id: this.#requestId,
        error: { message, type: "ferrogate_error", code },
      }),
      sseFrame({ data: DONE_SENTINEL }),
    ];
  }
}

/** `is_done_frame`. */
export function isDoneEvent(eventName: string | undefined, parsed: unknown): boolean {
  if (eventName === "response.completed" || eventName === "message_stop") {
    return true;
  }
  if (getString(parsed, "type") === "response.completed") {
    return true;
  }
  if (getString(parsed, "finish_reason") !== undefined) return true;
  return (asArray(get(parsed, "choices")) ?? []).some(
    (choice) => getString(choice, "finish_reason") !== undefined,
  );
}

/** `extract_text_deltas`. */
export function extractTextDeltas(
  kind: ResponsesStreamProviderKind,
  eventName: string | undefined,
  parsed: unknown,
): string[] {
  if (parsed === undefined) {
    return [];
  }
  if (kind === "anthropic") {
    if (eventName !== "content_block_delta" && eventName !== "response.output_text.delta") {
      return [];
    }
    const text = asString(get(get(parsed, "delta"), "text"));
    return text !== undefined && text.length > 0 ? [text] : [];
  }
  if (kind === "gemini") {
    const out: string[] = [];
    for (const candidate of asArray(get(parsed, "candidates")) ?? []) {
      for (const part of asArray(get(get(candidate, "content"), "parts")) ?? []) {
        const text = asString(get(part, "text"));
        if (get(part, "thought") !== true && text !== undefined && text.length > 0) {
          out.push(text);
        }
      }
    }
    return out;
  }

  if (
    eventName === "response.output_text.delta" ||
    getString(parsed, "type") === "response.output_text.delta"
  ) {
    const delta = asString(get(parsed, "delta"));
    return delta !== undefined && delta.length > 0 ? [delta] : [];
  }
  const outputText = asString(get(parsed, "output_text"));
  if (outputText !== undefined) {
    return outputText.length > 0 ? [outputText] : [];
  }
  const out: string[] = [];
  for (const choice of asArray(get(parsed, "choices")) ?? []) {
    const delta = get(choice, "delta");
    if (delta === undefined) {
      continue;
    }
    const text =
      asString(get(delta, "content")) ??
      asString(get(delta, "text")) ??
      asString(get(delta, "output_text"));
    if (text !== undefined && text.length > 0) {
      out.push(text);
    }
  }
  return out;
}

/** Extract provider-native function calls as Responses argument deltas. */
export function extractFunctionCallDeltas(
  kind: ResponsesStreamProviderKind,
  eventName: string | undefined,
  parsed: unknown,
  accumulator: ToolCallAccumulator,
): ToolCallUpdate[] {
  if (parsed === undefined) {
    return [];
  }

  if (kind === "anthropic") {
    if (eventName === "content_block_start") {
      const block = get(parsed, "content_block");
      if (getString(block, "type") !== "tool_use") return [];
      const index = getUint(parsed, "index") ?? 0;
      const input = get(block, "input");
      const inputRecord = asRecord(input);
      const initialArguments =
        inputRecord !== undefined && Object.keys(inputRecord).length === 0
          ? undefined
          : input === undefined
            ? undefined
            : JSON.stringify(input);
      const update = accumulator.applyFragment({
        index,
        id: getString(block, "id"),
        name: getString(block, "name"),
        argumentsDelta: initialArguments,
      });
      return [update];
    }
    if (eventName !== "content_block_delta" && eventName !== "response.output_item.delta") {
      return [];
    }
    const delta = get(parsed, "delta");
    if (delta === undefined || getString(delta, "type") !== "input_json_delta") {
      return [];
    }
    const index = getUint(parsed, "index") ?? 0;
    const fragment = asString(get(delta, "partial_json"));
    const update = accumulator.applyFragment({
      index,
      id: getString(parsed, "id"),
      name: getString(delta, "name") ?? getString(parsed, "name"),
      argumentsDelta: fragment,
    });
    return update.argumentsDelta.length > 0 ? [update] : [];
  }

  if (kind === "gemini") {
    if (
      eventName !== undefined &&
      eventName !== "data" &&
      eventName !== "message" &&
      eventName !== "response.output_item.delta"
    ) {
      return [];
    }
    const updates: ToolCallUpdate[] = [];
    const candidates = asArray(get(parsed, "candidates")) ?? [];
    for (let candidateIndex = 0; candidateIndex < candidates.length; candidateIndex += 1) {
      const parts = asArray(get(get(candidates[candidateIndex], "content"), "parts")) ?? [];
      for (let partIndex = 0; partIndex < parts.length; partIndex += 1) {
        const call = get(parts[partIndex], "functionCall");
        if (call === undefined) continue;
        const index = candidateIndex * 1_000_000 + partIndex;
        const rawArgs = get(call, "args") ?? get(call, "arguments");
        const args =
          asString(rawArgs) ?? (rawArgs === undefined ? undefined : JSON.stringify(rawArgs));
        const update = accumulator.applyFragment({
          index,
          id: asString(get(call, "id")),
          name: asString(get(call, "name")),
          argumentsDelta: args,
        });
        if (update.argumentsDelta.length > 0) {
          updates.push(update);
        }
      }
    }
    return updates;
  }

  // openai_compatible | other
  const updates: ToolCallUpdate[] = [];
  const choices = asArray(get(parsed, "choices")) ?? [];
  for (let choiceIndex = 0; choiceIndex < choices.length; choiceIndex += 1) {
    const delta = get(choices[choiceIndex], "delta");
    if (delta === undefined) {
      continue;
    }
    const functionCall = get(delta, "function_call");
    if (functionCall !== undefined) {
      const update = accumulator.applyFunctionCallDelta(functionCall, choiceIndex);
      if (update !== undefined && update.argumentsDelta.length > 0) {
        updates.push(update);
      }
    }
    for (const update of accumulator.applyToolCallDeltas(get(delta, "tool_calls"), choiceIndex)) {
      if (update.argumentsDelta.length > 0) {
        updates.push(update);
      }
    }
  }
  return updates;
}

/** Upstream frames -> `response.*` frames. */
export function responsesNormalizeFrameStream(
  options: ResponsesStreamOptions,
): TransformStream<SseFrame, SseFrame> {
  const normalizer = new ResponsesStreamNormalizer(options);
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

/** Upstream SSE bytes -> `response.*` SSE bytes. */
export function responsesNormalizeStream(
  options: ResponsesStreamOptions,
): TransformStream<Uint8Array, Uint8Array> {
  return bytesThroughFrames(responsesNormalizeFrameStream(options), {
    preferRaw: false,
  });
}

/** Re-exported so callers can classify an upstream without importing values.ts. */
export { asUint as asResponsesIndex };
