/** Native Anthropic/Gemini SSE -> OpenAI Chat Completions SSE. */
import {
  type SseFrame,
  bytesThroughFrames,
  doneSseFrame,
  frameJson,
  isDoneFrame,
  jsonSseFrame,
} from "./sse.js";
import { asArray, asRecord, get, getString, getUint } from "./values.js";

export type ChatStreamProviderKind = "anthropic" | "gemini";

export interface ChatStreamOptions {
  readonly providerKind: ChatStreamProviderKind;
  readonly requestId: string;
  readonly fallbackModel: string;
}

export interface ResponsesChatStreamOptions {
  readonly requestId: string;
  readonly fallbackModel: string;
}

interface AnthropicUsageState {
  freshInput?: number;
  cacheRead?: number;
  cacheWrite?: number;
  output?: number;
}

function finishReasonFromAnthropic(value: string | undefined): string | null {
  switch (value) {
    case undefined:
      return null;
    case "tool_use":
      return "tool_calls";
    case "max_tokens":
      return "length";
    case "refusal":
      return "content_filter";
    default:
      return "stop";
  }
}

function finishReasonFromGemini(value: string | undefined, sawToolCall: boolean): string | null {
  if (sawToolCall) return "tool_calls";
  switch (value) {
    case undefined:
    case "FINISH_REASON_UNSPECIFIED":
      return null;
    case "MAX_TOKENS":
      return "length";
    case "SAFETY":
    case "RECITATION":
    case "PROHIBITED_CONTENT":
    case "BLOCKLIST":
    case "SPII":
    case "IMAGE_SAFETY":
      return "content_filter";
    default:
      return "stop";
  }
}

function errorEnvelope(value: unknown): Record<string, unknown> {
  const error = get(value, "error");
  return {
    error: {
      message: getString(error, "message") ?? "provider returned a streaming error",
      type: "provider_error",
      code: getString(error, "code") ?? getString(error, "type") ?? "provider_stream_error",
    },
  };
}

/** Stateful converter because both native protocols split metadata, usage, and tool calls. */
export class OpenAiChatStreamNormalizer {
  readonly #kind: ChatStreamProviderKind;
  readonly #fallbackId: string;
  readonly #fallbackModel: string;
  readonly #created = Math.floor(Date.now() / 1000);
  readonly #startedChoices = new Set<number>();
  readonly #finishedChoices = new Set<number>();
  readonly #toolCallsByBlock = new Map<number, number>();
  readonly #geminiToolCounts = new Map<number, number>();
  readonly #geminiToolIds = new Set<string>();
  readonly #geminiSawToolCall = new Set<number>();
  readonly #anthropicUsage: AnthropicUsageState = {};
  #id: string | undefined;
  #model: string | undefined;
  #completed = false;

  constructor(options: ChatStreamOptions) {
    this.#kind = options.providerKind;
    this.#fallbackId = `chatcmpl_${options.requestId}`;
    this.#fallbackModel = options.fallbackModel;
  }

  push(frame: SseFrame): SseFrame[] {
    if (this.#completed) return [];
    if (isDoneFrame(frame)) return this.finish();
    const parsed = frameJson(frame);
    if (parsed === undefined) return [];
    if (frame.event === "error" || get(parsed, "error") !== undefined) {
      this.#completed = true;
      return [jsonSseFrame(undefined, errorEnvelope(parsed)), doneSseFrame()];
    }
    return this.#kind === "anthropic"
      ? this.#pushAnthropic(frame.event ?? getString(parsed, "type"), parsed)
      : this.#pushGemini(parsed);
  }

  flush(): SseFrame[] {
    return this.finish();
  }

  finish(): SseFrame[] {
    if (this.#completed) return [];
    const out: SseFrame[] = [];
    for (const index of this.#startedChoices) {
      if (!this.#finishedChoices.has(index)) {
        out.push(this.#chunk(index, {}, "stop"));
        this.#finishedChoices.add(index);
      }
    }
    out.push(doneSseFrame());
    this.#completed = true;
    return out;
  }

  #chunk(
    index: number | null,
    delta: Record<string, unknown>,
    finishReason: string | null = null,
    usage?: Record<string, unknown>,
  ): SseFrame {
    return jsonSseFrame(undefined, {
      id: this.#id ?? this.#fallbackId,
      object: "chat.completion.chunk",
      created: this.#created,
      model: this.#model ?? this.#fallbackModel,
      choices: index === null ? [] : [{ index, delta, finish_reason: finishReason }],
      ...(usage === undefined ? {} : { usage }),
    });
  }

  #startChoice(index: number): SseFrame[] {
    if (this.#startedChoices.has(index)) return [];
    this.#startedChoices.add(index);
    return [this.#chunk(index, { role: "assistant", content: "" })];
  }

  #observeAnthropicUsage(value: unknown): void {
    const usage = get(value, "usage") ?? get(get(value, "message"), "usage");
    const freshInput = getUint(usage, "input_tokens");
    const cacheRead = getUint(usage, "cache_read_input_tokens");
    const cacheWrite = getUint(usage, "cache_creation_input_tokens");
    const output = getUint(usage, "output_tokens");
    if (freshInput !== undefined) this.#anthropicUsage.freshInput = freshInput;
    if (cacheRead !== undefined) this.#anthropicUsage.cacheRead = cacheRead;
    if (cacheWrite !== undefined) this.#anthropicUsage.cacheWrite = cacheWrite;
    if (output !== undefined) this.#anthropicUsage.output = output;
  }

  #anthropicUsageJson(): Record<string, unknown> | undefined {
    const { freshInput, cacheRead, cacheWrite, output } = this.#anthropicUsage;
    if (freshInput === undefined && output === undefined) return undefined;
    const prompt =
      freshInput === undefined ? undefined : freshInput + (cacheRead ?? 0) + (cacheWrite ?? 0);
    return {
      ...(prompt === undefined ? {} : { prompt_tokens: prompt }),
      ...(output === undefined ? {} : { completion_tokens: output }),
      ...(prompt === undefined || output === undefined ? {} : { total_tokens: prompt + output }),
      ...(cacheRead === undefined
        ? {}
        : {
            prompt_tokens_details: { cached_tokens: cacheRead },
            cache_read_input_tokens: cacheRead,
          }),
      ...(cacheWrite === undefined ? {} : { cache_creation_input_tokens: cacheWrite }),
    };
  }

  #pushAnthropic(event: string | undefined, parsed: unknown): SseFrame[] {
    this.#observeAnthropicUsage(parsed);
    if (event === "message_start") {
      const message = get(parsed, "message");
      this.#id = getString(message, "id")?.replace(/^msg/, "chatcmpl");
      this.#model = getString(message, "model");
      return this.#startChoice(0);
    }
    if (event === "content_block_start") {
      const out = this.#startChoice(0);
      const blockIndex = getUint(parsed, "index") ?? 0;
      const block = get(parsed, "content_block");
      const type = getString(block, "type");
      if (type === "text") {
        const text = getString(block, "text");
        if (text) out.push(this.#chunk(0, { content: text }));
      } else if (type === "thinking") {
        const thinking = getString(block, "thinking");
        if (thinking) out.push(this.#chunk(0, { reasoning_content: thinking }));
        const signature = getString(block, "signature");
        if (signature) out.push(this.#chunk(0, { reasoning_signature: signature }));
      } else if (type === "tool_use") {
        const toolIndex = this.#toolCallsByBlock.size;
        this.#toolCallsByBlock.set(blockIndex, toolIndex);
        const input = get(block, "input");
        const inputRecord = asRecord(input);
        const initialArguments =
          inputRecord !== undefined && Object.keys(inputRecord).length === 0
            ? ""
            : input === undefined
              ? ""
              : JSON.stringify(input);
        out.push(
          this.#chunk(0, {
            tool_calls: [
              {
                index: toolIndex,
                id: getString(block, "id") ?? `call_${toolIndex}`,
                type: "function",
                function: {
                  name: getString(block, "name") ?? "",
                  arguments: initialArguments,
                },
              },
            ],
          }),
        );
      }
      return out;
    }
    if (event === "content_block_delta") {
      const out = this.#startChoice(0);
      const delta = get(parsed, "delta");
      const type = getString(delta, "type");
      if (type === "text_delta") {
        const text = getString(delta, "text");
        if (text) out.push(this.#chunk(0, { content: text }));
      } else if (type === "thinking_delta") {
        const thinking = getString(delta, "thinking");
        if (thinking) out.push(this.#chunk(0, { reasoning_content: thinking }));
      } else if (type === "signature_delta") {
        const signature = getString(delta, "signature");
        if (signature) out.push(this.#chunk(0, { reasoning_signature: signature }));
      } else if (type === "input_json_delta") {
        const blockIndex = getUint(parsed, "index") ?? 0;
        const toolIndex = this.#toolCallsByBlock.get(blockIndex) ?? this.#toolCallsByBlock.size;
        this.#toolCallsByBlock.set(blockIndex, toolIndex);
        const argumentsDelta = getString(delta, "partial_json");
        if (argumentsDelta) {
          out.push(
            this.#chunk(0, {
              tool_calls: [{ index: toolIndex, function: { arguments: argumentsDelta } }],
            }),
          );
        }
      }
      return out;
    }
    if (event === "message_delta") {
      const out = this.#startChoice(0);
      const reason = finishReasonFromAnthropic(getString(get(parsed, "delta"), "stop_reason"));
      out.push(this.#chunk(0, {}, reason, this.#anthropicUsageJson()));
      if (reason !== null) this.#finishedChoices.add(0);
      return out;
    }
    if (event === "message_stop") return this.finish();
    return [];
  }

  #geminiUsageJson(value: unknown): Record<string, unknown> | undefined {
    const usage = get(value, "usageMetadata");
    if (usage === undefined) return undefined;
    const prompt = getUint(usage, "promptTokenCount");
    const visibleOutput = getUint(usage, "candidatesTokenCount");
    const reasoning = getUint(usage, "thoughtsTokenCount");
    const completion = visibleOutput === undefined ? reasoning : visibleOutput + (reasoning ?? 0);
    const total =
      getUint(usage, "totalTokenCount") ??
      (prompt !== undefined && completion !== undefined ? prompt + completion : undefined);
    const cached = getUint(usage, "cachedContentTokenCount");
    return {
      ...(prompt === undefined ? {} : { prompt_tokens: prompt }),
      ...(completion === undefined ? {} : { completion_tokens: completion }),
      ...(total === undefined ? {} : { total_tokens: total }),
      ...(cached === undefined ? {} : { prompt_tokens_details: { cached_tokens: cached } }),
      ...(reasoning === undefined
        ? {}
        : { completion_tokens_details: { reasoning_tokens: reasoning } }),
    };
  }

  #pushGemini(parsed: unknown): SseFrame[] {
    this.#id ??= getString(parsed, "responseId");
    this.#model ??= getString(parsed, "modelVersion");
    const usage = this.#geminiUsageJson(parsed);
    const out: SseFrame[] = [];
    const candidates = asArray(get(parsed, "candidates")) ?? [];
    for (let candidateIndex = 0; candidateIndex < candidates.length; candidateIndex += 1) {
      const candidate = candidates[candidateIndex];
      const parts = asArray(get(get(candidate, "content"), "parts")) ?? [];
      if (parts.length > 0 || getString(candidate, "finishReason") !== undefined) {
        out.push(...this.#startChoice(candidateIndex));
      }
      for (const part of parts) {
        const text = getString(part, "text");
        const thought = get(part, "thought") === true;
        const signature = getString(part, "thoughtSignature");
        const call = get(part, "functionCall");
        if (text || (signature && call === undefined)) {
          out.push(
            this.#chunk(
              candidateIndex,
              thought
                ? {
                    ...(text === undefined ? {} : { reasoning_content: text }),
                    ...(signature === undefined ? {} : { reasoning_signature: signature }),
                  }
                : {
                    ...(text === undefined ? {} : { content: text }),
                    ...(signature === undefined ? {} : { text_signature: signature }),
                  },
            ),
          );
        }
        const name = getString(call, "name");
        if (name !== undefined) {
          const toolIndex = this.#geminiToolCounts.get(candidateIndex) ?? 0;
          this.#geminiToolCounts.set(candidateIndex, toolIndex + 1);
          this.#geminiSawToolCall.add(candidateIndex);
          const providedId = getString(call, "id");
          const fallbackId = `call_${candidateIndex}_${toolIndex}`;
          let toolId =
            providedId !== undefined && !this.#geminiToolIds.has(providedId)
              ? providedId
              : fallbackId;
          let suffix = 1;
          while (this.#geminiToolIds.has(toolId)) {
            toolId = `${fallbackId}_${suffix}`;
            suffix += 1;
          }
          this.#geminiToolIds.add(toolId);
          const signature = getString(part, "thoughtSignature");
          out.push(
            this.#chunk(candidateIndex, {
              tool_calls: [
                {
                  index: toolIndex,
                  id: toolId,
                  type: "function",
                  function: { name, arguments: JSON.stringify(get(call, "args") ?? {}) },
                  ...(signature === undefined ? {} : { thought_signature: signature }),
                },
              ],
            }),
          );
        }
      }
      const finishReason = finishReasonFromGemini(
        getString(candidate, "finishReason"),
        this.#geminiSawToolCall.has(candidateIndex),
      );
      if (finishReason !== null) {
        out.push(this.#chunk(candidateIndex, {}, finishReason, usage));
        this.#finishedChoices.add(candidateIndex);
      }
    }
    if (usage !== undefined && !out.some((frame) => frame.data?.includes('"usage"'))) {
      out.push(this.#chunk(null, {}, null, usage));
    }
    return out;
  }
}

export function nativeToOpenAiChatFrameStream(
  options: ChatStreamOptions,
): TransformStream<SseFrame, SseFrame> {
  const normalizer = new OpenAiChatStreamNormalizer(options);
  return new TransformStream<SseFrame, SseFrame>({
    transform(frame, controller) {
      for (const output of normalizer.push(frame)) controller.enqueue(output);
    },
    flush(controller) {
      for (const output of normalizer.flush()) controller.enqueue(output);
    },
  });
}

export function nativeToOpenAiChatStream(
  options: ChatStreamOptions,
): TransformStream<Uint8Array, Uint8Array> {
  return bytesThroughFrames(nativeToOpenAiChatFrameStream(options), { preferRaw: false });
}

/** OpenAI Responses SSE -> OpenAI Chat Completions SSE. */
export function responsesToOpenAiChatStream(
  options: ResponsesChatStreamOptions,
): TransformStream<Uint8Array, Uint8Array> {
  const id = `chatcmpl_${options.requestId}`;
  const created = Math.floor(Date.now() / 1000);
  let model = options.fallbackModel;
  let started = false;
  let completed = false;
  let sawToolCall = false;
  const toolIndexes = new Map<string, number>();
  const toolCallIds = new Map<string, string>();

  const chunk = (
    delta: Record<string, unknown>,
    finishReason: string | null = null,
    usage?: Record<string, unknown>,
  ): SseFrame =>
    jsonSseFrame(undefined, {
      id,
      object: "chat.completion.chunk",
      created,
      model,
      choices:
        usage === undefined || Object.keys(delta).length > 0 || finishReason !== null
          ? [{ index: 0, delta, finish_reason: finishReason }]
          : [],
      ...(usage === undefined ? {} : { usage }),
    });

  const start = (): SseFrame[] => {
    if (started) return [];
    started = true;
    return [chunk({ role: "assistant", content: "" })];
  };

  const finish = (usage?: Record<string, unknown>): SseFrame[] => {
    if (completed) return [];
    completed = true;
    return [...start(), chunk({}, sawToolCall ? "tool_calls" : "stop", usage), doneSseFrame()];
  };

  const frames = new TransformStream<SseFrame, SseFrame>({
    transform(frame, controller) {
      if (completed) return;
      if (isDoneFrame(frame)) {
        for (const output of finish()) controller.enqueue(output);
        return;
      }
      const parsed = frameJson(frame);
      if (parsed === undefined) return;
      const event = frame.event ?? getString(parsed, "type");
      const response = get(parsed, "response");
      const responseModel = getString(response, "model") ?? getString(parsed, "model");
      if (responseModel !== undefined) model = responseModel;
      if (event === "error" || event === "response.failed" || get(parsed, "error") !== undefined) {
        completed = true;
        controller.enqueue(jsonSseFrame(undefined, errorEnvelope(parsed)));
        controller.enqueue(doneSseFrame());
        return;
      }
      if (event === "response.output_text.delta") {
        for (const output of start()) controller.enqueue(output);
        const delta = getString(parsed, "delta");
        if (delta !== undefined) controller.enqueue(chunk({ content: delta }));
        return;
      }
      if (event === "response.output_item.added") {
        const item = get(parsed, "item");
        if (getString(item, "type") !== "function_call") return;
        for (const output of start()) controller.enqueue(output);
        const callId =
          getString(item, "call_id") ?? getString(item, "id") ?? `call_${toolIndexes.size}`;
        const itemId = getString(item, "id");
        const index = getUint(parsed, "output_index") ?? toolIndexes.size;
        toolIndexes.set(callId, index);
        if (itemId !== undefined) {
          toolIndexes.set(itemId, index);
          toolCallIds.set(itemId, callId);
        }
        sawToolCall = true;
        controller.enqueue(
          chunk({
            tool_calls: [
              {
                index,
                id: callId,
                type: "function",
                function: { name: getString(item, "name") ?? "", arguments: "" },
              },
            ],
          }),
        );
        return;
      }
      if (event === "response.function_call_arguments.delta") {
        for (const output of start()) controller.enqueue(output);
        const itemId = getString(parsed, "item_id");
        const callId =
          getString(parsed, "call_id") ??
          (itemId === undefined ? undefined : toolCallIds.get(itemId)) ??
          itemId ??
          "call_0";
        const index =
          getUint(parsed, "output_index") ??
          toolIndexes.get(callId) ??
          (itemId === undefined ? undefined : toolIndexes.get(itemId)) ??
          0;
        toolIndexes.set(callId, index);
        sawToolCall = true;
        controller.enqueue(
          chunk({
            tool_calls: [
              {
                index,
                function: { arguments: getString(parsed, "delta") ?? "" },
              },
            ],
          }),
        );
        return;
      }
      if (event === "response.completed") {
        const usageValue = get(response, "usage") ?? get(parsed, "usage");
        const usage =
          usageValue === undefined
            ? undefined
            : {
                prompt_tokens: getUint(usageValue, "input_tokens") ?? 0,
                completion_tokens: getUint(usageValue, "output_tokens") ?? 0,
                total_tokens: getUint(usageValue, "total_tokens") ?? 0,
              };
        for (const output of finish(usage)) controller.enqueue(output);
      }
    },
    flush(controller) {
      for (const output of finish()) controller.enqueue(output);
    },
  });
  return bytesThroughFrames(frames, { preferRaw: false });
}
