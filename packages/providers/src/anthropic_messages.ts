/**
 * Anthropic Messages ⇄ OpenAI chat-completions translation — port of
 * `anthropic_messages.rs` (issue #272). Backs the `/v1/messages` ingress: a
 * Claude-native request is translated to OpenAI chat-completions, dispatched
 * through the shared governed path, then translated back on the way out. Pure
 * JSON ⇄ JSON, no I/O.
 */
import { AdapterError } from "./types.js";
import { PROMPT_CACHE_MEMBER } from "./caching.js";
import { asStr, asU64, getField, isArray, isObject, parseJson } from "./json.js";
import type { Json, JsonObject } from "./json.js";

/** Anthropic Messages request → OpenAI chat-completions request. */
export function toChatCompletions(body: Json): Json {
  const object = isObject(body) ? body : undefined;
  if (!object) {
    throw AdapterError.invalidRequest("Anthropic messages request body must be a JSON object");
  }

  const out: JsonObject = {};
  for (const key of ["model", "max_tokens", "temperature", "top_p", "stream"]) {
    if (object[key] !== undefined) out[key] = object[key]!;
  }
  if (object["stop_sequences"] !== undefined) out["stop"] = object["stop_sequences"];

  const messages: Json[] = [];
  const system = object["system"];
  if (system !== undefined) {
    const text = anthropicSystemToText(system);
    if (text !== undefined) messages.push({ role: "system", content: text });
  }

  const items = object["messages"];
  if (isArray(items)) {
    for (const message of items) anthropicMessageToChat(message, messages);
  }
  out["messages"] = messages;

  const tools = object["tools"];
  if (isArray(tools)) {
    const converted = tools.map(anthropicToolToOpenai);
    if (converted.length > 0) out["tools"] = converted;
  }
  const toolChoice = object["tool_choice"];
  if (toolChoice !== undefined) {
    const converted = anthropicToolChoiceToOpenai(toolChoice);
    if (converted !== undefined) out["tool_choice"] = converted;
  }

  // Every conversion above rebuilds its blocks, so a native `cache_control`
  // marker was dropped on the floor here and an Anthropic-native caller lost
  // its prefix discount on its OWN protocol. The intent (not the placement,
  // which the OpenAI grammar cannot hold) is carried forward as the canonical
  // directive, which then re-emits per family — issue #690, and see the twin of
  // this function in `apps/gateway/src/inference/anthropic.ts`.
  //
  // A STATED `prompt_cache` beats an INFERRED marker. `/v1/messages` is served
  // by the same ladder as every other ingress, so a directive this translation
  // dropped would be one the route silently declined to honour while answering
  // 200 — and for `mode: "off"`, a retention control, that 200 would mean the
  // opposite of what was asked. Reading it here is what puts this ingress under
  // #674's refuse-rather-than-degrade rule. It is passed through unvalidated
  // because `promptCacheFromBody` is the one canonical parser.
  const promptCache = object[PROMPT_CACHE_MEMBER] ?? promptCacheFromCacheControl(object);
  if (promptCache !== undefined) out[PROMPT_CACHE_MEMBER] = promptCache;

  return out;
}

function promptCacheFromCacheControl(body: Json): Json | undefined {
  const marker = findCacheControl(body);
  if (marker === undefined) return undefined;
  const ttl = asStr(getField(marker, "ttl"));
  return { mode: "explicit", ...(ttl === "1h" ? { ttl } : {}) };
}

function findCacheControl(value: Json | undefined): Json | undefined {
  if (isArray(value)) {
    for (const entry of value) {
      const found = findCacheControl(entry);
      if (found !== undefined) return found;
    }
    return undefined;
  }
  if (!isObject(value)) return undefined;
  if (value["cache_control"] !== undefined) return value["cache_control"];
  for (const entry of Object.values(value)) {
    const found = findCacheControl(entry);
    if (found !== undefined) return found;
  }
  return undefined;
}

function anthropicSystemToText(system: Json): string | undefined {
  if (typeof system === "string") return system.length > 0 ? system : undefined;
  if (isArray(system)) {
    const text = system
      .map((block) => asStr(getField(block, "text")))
      .filter((value): value is string => value !== undefined)
      .join("\n");
    return text.length > 0 ? text : undefined;
  }
  return undefined;
}

function anthropicMessageToChat(message: Json, out: Json[]): void {
  const role = asStr(getField(message, "role")) ?? "user";
  const content = getField(message, "content") ?? null;

  if (typeof content === "string") {
    out.push({ role, content });
    return;
  }
  if (!isArray(content)) {
    out.push({ role, content: "" });
    return;
  }

  const contentParts: Json[] = [];
  const toolCalls: Json[] = [];
  const toolMessages: Json[] = [];

  for (const block of content) {
    switch (asStr(getField(block, "type"))) {
      case "text":
        contentParts.push({ type: "text", text: asStr(getField(block, "text")) ?? "" });
        break;
      case "image": {
        const url = anthropicImageToDataUrl(block);
        if (url !== undefined) contentParts.push({ type: "image_url", image_url: { url } });
        break;
      }
      case "tool_use":
        toolCalls.push({
          id: asStr(getField(block, "id")) ?? "",
          type: "function",
          function: {
            name: asStr(getField(block, "name")) ?? "",
            arguments: stringifyArguments(getField(block, "input")),
          },
        });
        break;
      case "tool_result":
        toolMessages.push({
          role: "tool",
          tool_call_id: asStr(getField(block, "tool_use_id")) ?? "",
          content: toolResultToText(getField(block, "content")),
        });
        break;
      default:
        break;
    }
  }

  out.push(...toolMessages);

  if (toolCalls.length > 0) {
    out.push({ role: "assistant", content: collapseContent(contentParts), tool_calls: toolCalls });
  } else if (contentParts.length > 0) {
    out.push({ role, content: collapseContent(contentParts) });
  }
}

function collapseContent(parts: Json[]): Json {
  if (parts.length === 0) return null;
  if (parts.length === 1) {
    const single = parts[0]!;
    if (asStr(getField(single, "type")) === "text") return getField(single, "text") ?? "";
  }
  return [...parts];
}

function anthropicImageToDataUrl(block: Json): string | undefined {
  const source = getField(block, "source");
  if (source === undefined) return undefined;
  switch (asStr(getField(source, "type"))) {
    case "base64": {
      const mediaType = asStr(getField(source, "media_type")) ?? "image/png";
      const data = asStr(getField(source, "data"));
      if (data === undefined) return undefined;
      return `data:${mediaType};base64,${data}`;
    }
    case "url":
      return asStr(getField(source, "url"));
    default:
      return undefined;
  }
}

function toolResultToText(content: Json | undefined): string {
  if (typeof content === "string") return content;
  if (isArray(content)) {
    return content
      .map((block) => asStr(getField(block, "text")) ?? JSON.stringify(block))
      .join("\n");
  }
  if (content === undefined) return "";
  return JSON.stringify(content);
}

function stringifyArguments(input: Json | undefined): string {
  if (typeof input === "string") return input;
  if (input === undefined) return "{}";
  return JSON.stringify(input);
}

function anthropicToolToOpenai(tool: Json): Json {
  const fn: JsonObject = { name: getField(tool, "name") ?? null };
  const description = getField(tool, "description");
  if (description !== undefined) fn["description"] = description;
  fn["parameters"] = getField(tool, "input_schema") ?? { type: "object" };
  return { type: "function", function: fn };
}

function anthropicToolChoiceToOpenai(choice: Json): Json | undefined {
  switch (asStr(getField(choice, "type"))) {
    case "auto":
      return "auto";
    case "none":
      return "none";
    case "any":
      return "required";
    case "tool": {
      const name = asStr(getField(choice, "name"));
      return name !== undefined ? { type: "function", function: { name } } : undefined;
    }
    default:
      return undefined;
  }
}

/**
 * Upstream chat-completion response → Anthropic Messages object. An
 * already-Anthropic-shaped body is passed through unchanged.
 */
export function chatCompletionToMessage(chat: Json, fallbackModel: string): Json {
  if (isAnthropicMessage(chat)) return chat;

  const chatId = asStr(getField(chat, "id"));
  const id = chatId !== undefined ? chatId.replaceAll("chatcmpl", "msg") : "msg_ferrogate";
  const model = asStr(getField(chat, "model")) ?? fallbackModel;

  const choices = getField(chat, "choices");
  const choice = isArray(choices) ? choices[0] : undefined;
  const message = getField(choice, "message");
  const finishReason = asStr(getField(choice, "finish_reason"));

  const content: Json[] = [];
  const text = asStr(getField(message, "content"));
  if (text !== undefined && text.length > 0) content.push({ type: "text", text });

  let sawToolUse = false;
  const toolCalls = getField(message, "tool_calls");
  if (isArray(toolCalls)) {
    for (const toolCall of toolCalls) {
      sawToolUse = true;
      const fn = getField(toolCall, "function");
      content.push({
        type: "tool_use",
        id: asStr(getField(toolCall, "id")) ?? "",
        name: asStr(getField(fn, "name")) ?? "",
        input: parseArguments(getField(fn, "arguments")),
      });
    }
  }

  const usage = getField(chat, "usage");
  const outputTokens = asU64(getField(usage, "completion_tokens")) ?? 0;

  return {
    id,
    type: "message",
    role: "assistant",
    model,
    content,
    stop_reason: finishReasonToStopReason(finishReason, sawToolUse),
    stop_sequence: null,
    usage: { ...anthropicUsageCounters(usage), output_tokens: outputTokens },
  };
}

/**
 * The OpenAI input counters in Anthropic's vocabulary, cache split kept (#690).
 *
 * OpenAI's `prompt_tokens` INCLUDES `prompt_tokens_details.cached_tokens`;
 * Anthropic's `input_tokens` EXCLUDES `cache_read_input_tokens`. The fresh
 * count is therefore the difference — emitting both unreduced would make a
 * native client double-count the prompt. A response with no cached tokens
 * reported emits exactly the counter it always did.
 */
function anthropicUsageCounters(usage: Json | undefined): JsonObject {
  const promptTokens = asU64(getField(usage, "prompt_tokens")) ?? 0;
  const details =
    getField(usage, "prompt_tokens_details") ?? getField(usage, "input_tokens_details");
  const cached = asU64(getField(details, "cached_tokens"));
  if (cached === undefined) return { input_tokens: promptTokens };
  return {
    input_tokens: Math.max(promptTokens - cached, 0),
    cache_read_input_tokens: cached,
  };
}

export function isAnthropicMessage(value: Json): boolean {
  return asStr(getField(value, "type")) === "message" && isArray(getField(value, "content"));
}

/** Map an OpenAI `finish_reason` to the Anthropic `stop_reason` vocabulary. */
export function finishReasonToStopReason(
  finishReason: string | undefined,
  sawToolUse: boolean,
): string {
  if (sawToolUse) return "tool_use";
  switch (finishReason) {
    case "length":
      return "max_tokens";
    case "tool_calls":
      return "tool_use";
    case "stop":
      return "end_turn";
    default:
      return "end_turn";
  }
}

export function parseArguments(argumentsValue: Json | undefined): Json {
  if (typeof argumentsValue === "string") {
    const parsed = parseJson(argumentsValue);
    return parsed !== undefined ? parsed : {};
  }
  if (argumentsValue === undefined) return {};
  return argumentsValue;
}
