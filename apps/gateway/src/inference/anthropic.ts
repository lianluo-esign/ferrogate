/**
 * Anthropic Messages ⇄ OpenAI chat-completions translation.
 *
 * Clean-room port of `ferrogate-providers/src/anthropic_messages.rs` (issue
 * #272). Pure JSON⇄JSON: no I/O, no governance, no state — the Rust module made
 * the same promise so it stayed unit-testable in isolation, and this one keeps
 * it.
 *
 * Why it exists at all: `/v1/messages` is a Claude-protocol-native ingress, but
 * FerroGate routes it through the SAME governed chokepoint the OpenAI ingress
 * uses so every adapter family is reachable as an upstream. The request is
 * translated into an OpenAI chat body on the way in, and the provider's
 * chat-completion is translated back into an Anthropic Message on the way out.
 * An Anthropic upstream round-trips: the adapter converts the OpenAI body back
 * to Anthropic shape, and `chatCompletionToMessage` detects an already-Anthropic
 * response and passes it through untouched.
 *
 * This is the default implementation of the `AnthropicTranslator` port; it moves
 * to `@ferrogate/providers` when that package is ported.
 */
import type { AnthropicTranslator, TranslationResult } from "./ports.js";

type Json = Record<string, unknown>;

function asRecord(value: unknown): Json | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Json)
    : undefined;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function asArray(value: unknown): unknown[] | undefined {
  return Array.isArray(value) ? value : undefined;
}

function asUint(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0
    ? value
    : undefined;
}

function get(value: unknown, key: string): unknown {
  return asRecord(value)?.[key];
}

/**
 * Rust `Value::to_string()` on a non-string value — compact JSON, no spaces.
 * `JSON.stringify` produces the same text for every JSON value serde_json can
 * hold, which is what the `stringify_arguments` / `tool_result_to_text`
 * fallbacks rely on.
 */
function valueToString(value: unknown): string {
  return JSON.stringify(value) ?? "null";
}

// ---------------------------------------------------------------------------
// Request direction — `to_chat_completions`
// ---------------------------------------------------------------------------

/**
 * Scalar members that map 1:1 onto the OpenAI request.
 *
 * `system` is deliberately NOT in this list: Rust folds the Anthropic top-level
 * system prompt into `messages[0]` as a `system`-role turn.
 *
 * // PORT_TODO(inventory-request-path §3, issue #272): that means a
 * // `/v1/messages` request routed to an ANTHROPIC upstream reaches the provider
 * // with `messages[0].role === "system"` and NO top-level `system` field,
 * // because `AnthropicAdapter::prepare_chat_completions` only lifts a `system`
 * // member that was already on the OpenAI-shaped body. Anthropic's Messages API
 * // does not accept a `system` role inside `messages`. The Rust tree pins this
 * // behavior in `server/messages_test.rs:139`, so it is reproduced verbatim
 * // rather than silently "fixed" here — changing it is a behavior change that
 * // belongs with the `@ferrogate/providers` port, where the Rust test moves too.
 */
const SCALAR_PASSTHROUGH = ["model", "max_tokens", "temperature", "top_p", "stream"] as const;

/**
 * `anthropic_system_to_text` — Anthropic carries the system prompt as a
 * top-level field (a string, or an array of text blocks joined with `\n`).
 * Returns `undefined` for an empty result so no empty system turn is emitted.
 */
function systemToText(system: unknown): string | undefined {
  const text = asString(system);
  if (text !== undefined) {
    return text.length > 0 ? text : undefined;
  }
  const blocks = asArray(system);
  if (blocks !== undefined) {
    const joined = blocks
      .map((block) => asString(get(block, "text")))
      .filter((value): value is string => value !== undefined)
      .join("\n");
    return joined.length > 0 ? joined : undefined;
  }
  return undefined;
}

/**
 * `collapse_content` — a lone text block collapses to a plain string (the shape
 * most upstreams prefer); anything richer stays an OpenAI content-part array.
 * An empty part list becomes `null`, matching `Value::Null`.
 */
function collapseContent(parts: readonly Json[]): unknown {
  if (parts.length === 0) {
    return null;
  }
  const [single] = parts;
  if (parts.length === 1 && single !== undefined && single["type"] === "text") {
    return single["text"] ?? "";
  }
  return [...parts];
}

/** `anthropic_image_to_data_url`. */
function imageBlockToUrl(block: unknown): string | undefined {
  const source = get(block, "source");
  if (source === undefined) {
    return undefined;
  }
  switch (asString(get(source, "type"))) {
    case "base64": {
      const mediaType = asString(get(source, "media_type")) ?? "image/png";
      const data = asString(get(source, "data"));
      return data === undefined ? undefined : `data:${mediaType};base64,${data}`;
    }
    case "url":
      return asString(get(source, "url"));
    default:
      return undefined;
  }
}

/** `tool_result_to_text`. */
function toolResultToText(content: unknown): string {
  if (content === undefined) {
    return "";
  }
  const text = asString(content);
  if (text !== undefined) {
    return text;
  }
  const blocks = asArray(content);
  if (blocks !== undefined) {
    return blocks
      .map((block) => asString(get(block, "text")) ?? valueToString(block))
      .join("\n");
  }
  return valueToString(content);
}

/** `stringify_arguments` — OpenAI wants `function.arguments` as a JSON string. */
function stringifyArguments(input: unknown): string {
  if (input === undefined) {
    return "{}";
  }
  return asString(input) ?? valueToString(input);
}

/** `parse_arguments` — and back again; an unparseable string degrades to `{}`. */
export function parseArguments(argumentsValue: unknown): unknown {
  if (argumentsValue === undefined) {
    return {};
  }
  const text = asString(argumentsValue);
  if (text === undefined) {
    return argumentsValue;
  }
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}

/** `anthropic_tool_to_openai`. */
function toolToOpenAi(tool: unknown): Json {
  const fn: Json = { name: get(tool, "name") ?? null };
  const description = get(tool, "description");
  if (description !== undefined) {
    fn["description"] = description;
  }
  fn["parameters"] = get(tool, "input_schema") ?? { type: "object" };
  return { type: "function", function: fn };
}

/** `anthropic_tool_choice_to_openai`. */
function toolChoiceToOpenAi(choice: unknown): unknown {
  switch (asString(get(choice, "type"))) {
    case "auto":
      return "auto";
    case "none":
      return "none";
    case "any":
      return "required";
    case "tool": {
      const name = asString(get(choice, "name"));
      return name === undefined ? undefined : { type: "function", function: { name } };
    }
    default:
      return undefined;
  }
}

/** `anthropic_message_to_chat` — appends 0..n OpenAI messages for one turn. */
function messageToChat(message: unknown, out: Json[]): void {
  const role = asString(get(message, "role")) ?? "user";
  const content = get(message, "content") ?? null;

  const text = asString(content);
  if (text !== undefined) {
    out.push({ role, content: text });
    return;
  }

  const blocks = asArray(content);
  if (blocks === undefined) {
    // Null / absent content -> empty assistant/user turn.
    out.push({ role, content: "" });
    return;
  }

  const contentParts: Json[] = [];
  const toolCalls: Json[] = [];
  const toolMessages: Json[] = [];

  for (const block of blocks) {
    switch (asString(get(block, "type"))) {
      case "text":
        contentParts.push({ type: "text", text: asString(get(block, "text")) ?? "" });
        break;
      case "image": {
        const url = imageBlockToUrl(block);
        if (url !== undefined) {
          contentParts.push({ type: "image_url", image_url: { url } });
        }
        break;
      }
      case "tool_use":
        toolCalls.push({
          id: asString(get(block, "id")) ?? "",
          type: "function",
          function: {
            name: asString(get(block, "name")) ?? "",
            arguments: stringifyArguments(get(block, "input")),
          },
        });
        break;
      case "tool_result":
        toolMessages.push({
          role: "tool",
          tool_call_id: asString(get(block, "tool_use_id")) ?? "",
          content: toolResultToText(get(block, "content")),
        });
        break;
      default:
        break;
    }
  }

  // OpenAI requires tool result messages to appear before the next user text in
  // the same logical turn.
  out.push(...toolMessages);

  if (toolCalls.length > 0) {
    out.push({
      role: "assistant",
      content: collapseContent(contentParts),
      tool_calls: toolCalls,
    });
  } else if (contentParts.length > 0) {
    out.push({ role, content: collapseContent(contentParts) });
  }
}

/**
 * `to_chat_completions`. Text content is preserved verbatim so request-stage
 * guardrails see identical text under either ingress protocol.
 */
export function toChatCompletions(body: Json): TranslationResult {
  if (asRecord(body) === undefined) {
    return {
      ok: false,
      error: {
        kind: "invalid_request",
        message: "Anthropic messages request body must be a JSON object",
      },
    };
  }

  const out: Json = {};
  for (const key of SCALAR_PASSTHROUGH) {
    if (key in body) {
      out[key] = body[key];
    }
  }
  if ("stop_sequences" in body) {
    out["stop"] = body["stop_sequences"];
  }

  const messages: Json[] = [];
  const system = systemToText(body["system"]);
  if (system !== undefined) {
    messages.push({ role: "system", content: system });
  }
  for (const message of asArray(body["messages"]) ?? []) {
    messageToChat(message, messages);
  }
  out["messages"] = messages;

  const tools = asArray(body["tools"]);
  if (tools !== undefined) {
    const converted = tools.map(toolToOpenAi);
    if (converted.length > 0) {
      out["tools"] = converted;
    }
  }
  if ("tool_choice" in body) {
    const converted = toolChoiceToOpenAi(body["tool_choice"]);
    if (converted !== undefined) {
      out["tool_choice"] = converted;
    }
  }

  return { ok: true, body: out };
}

// ---------------------------------------------------------------------------
// Response direction — `chat_completion_to_message`
// ---------------------------------------------------------------------------

/** `is_anthropic_message` — an already-native response is passed straight back. */
export function isAnthropicMessage(value: unknown): boolean {
  return asString(get(value, "type")) === "message" && asArray(get(value, "content")) !== undefined;
}

/** `finish_reason_to_stop_reason`. */
export function finishReasonToStopReason(
  finishReason: string | undefined,
  sawToolUse: boolean,
): string {
  if (sawToolUse) {
    return "tool_use";
  }
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

/** `chat_completion_to_message`. */
export function chatCompletionToMessage(chat: unknown, fallbackModel: string): unknown {
  if (isAnthropicMessage(chat)) {
    return chat;
  }

  const rawId = asString(get(chat, "id"));
  const id = rawId === undefined ? "msg_ferrogate" : rawId.replaceAll("chatcmpl", "msg");
  const model = asString(get(chat, "model")) ?? fallbackModel;

  const choice = asArray(get(chat, "choices"))?.[0];
  const message = choice === undefined ? undefined : get(choice, "message");
  const finishReason = choice === undefined ? undefined : asString(get(choice, "finish_reason"));

  const content: Json[] = [];
  const text = asString(get(message, "content"));
  if (text !== undefined && text.length > 0) {
    content.push({ type: "text", text });
  }

  let sawToolUse = false;
  for (const toolCall of asArray(get(message, "tool_calls")) ?? []) {
    sawToolUse = true;
    const fn = get(toolCall, "function");
    content.push({
      type: "tool_use",
      id: asString(get(toolCall, "id")) ?? "",
      name: asString(get(fn, "name")) ?? "",
      input: parseArguments(get(fn, "arguments")),
    });
  }

  const usage = get(chat, "usage");
  const inputTokens = asUint(get(usage, "prompt_tokens")) ?? 0;
  const outputTokens = asUint(get(usage, "completion_tokens")) ?? 0;

  return {
    id,
    type: "message",
    role: "assistant",
    model,
    content,
    stop_reason: finishReasonToStopReason(finishReason, sawToolUse),
    stop_sequence: null,
    usage: { input_tokens: inputTokens, output_tokens: outputTokens },
  };
}

/** Default {@link AnthropicTranslator} wired into `defaults.ts`. */
export const defaultAnthropicTranslator: AnthropicTranslator = {
  toChatCompletions,
  chatCompletionToMessage,
};
