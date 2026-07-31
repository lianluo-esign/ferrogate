/**
 * NARROW LOCAL INTERFACES for the streaming tower (dependency inversion).
 *
 * The Rust streaming normalizers call two pure helpers that live in a *sibling
 * crate*, `ferrogate_providers::anthropic_messages`:
 *   - `finish_reason_to_stop_reason(finish_reason, saw_tool_use)`
 *   - `chat_completion_to_message(chat, fallback_model)`
 *
 * `@ferrogate/providers` is a wave-2 package still being written concurrently,
 * so per the port rules this module declares the interface the streaming tower
 * needs and ships a local implementation of it. Both are pure functions over
 * JSON with no I/O, so the local copy is a faithful clean-room re-write rather
 * than a stand-in.
 *
 * PORT-TODO(inventory-request-path §3.3 / §1.5): once `@ferrogate/providers`
 * exposes `anthropicMessages`, inject it as an {@link AnthropicMessagesPort}
 * and delete {@link localAnthropicMessagesPort} — the normalizers already take
 * the port as a parameter, so that is a one-line change at the call sites.
 */
import { asArray, asString, get, getString, getUint } from "./values.js";

/** Anthropic terminal `stop_reason` vocabulary. */
export type AnthropicStopReason = "end_turn" | "max_tokens" | "tool_use";

/** The provider-side pure helpers the streaming tower depends on. */
export interface AnthropicMessagesPort {
  /** `finish_reason_to_stop_reason`. */
  finishReasonToStopReason(
    finishReason: string | undefined,
    sawToolUse: boolean,
  ): AnthropicStopReason;
  /** `chat_completion_to_message`. */
  chatCompletionToMessage(chat: unknown, fallbackModel: string): Record<string, unknown>;
}

/**
 * `finish_reason_to_stop_reason`.
 *
 * Note the ordering: an observed tool call wins over the reported
 * `finish_reason`, and any unrecognized reason (including a provider that
 * reports none at all) falls back to `end_turn`.
 */
export function finishReasonToStopReason(
  finishReason: string | undefined,
  sawToolUse: boolean,
): AnthropicStopReason {
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

/** `is_anthropic_message` — an already-Anthropic body passes through unchanged. */
export function isAnthropicMessage(value: unknown): boolean {
  return getString(value, "type") === "message" && Array.isArray(get(value, "content"));
}

/** `parse_arguments` — a JSON-encoded argument string is re-parsed to an object. */
export function parseToolArguments(argumentsValue: unknown): unknown {
  if (typeof argumentsValue === "string") {
    try {
      return JSON.parse(argumentsValue) as unknown;
    } catch {
      return {};
    }
  }
  if (argumentsValue === undefined) {
    return {};
  }
  return argumentsValue;
}

/**
 * `chat_completion_to_message` — translate an OpenAI chat completion into an
 * Anthropic Messages object. An already-Anthropic body is returned unchanged so
 * a Claude-native client sees a native response either way.
 */
export function chatCompletionToMessage(
  chat: unknown,
  fallbackModel: string,
): Record<string, unknown> {
  if (isAnthropicMessage(chat)) {
    return { ...(chat as Record<string, unknown>) };
  }

  const id = getString(chat, "id")?.replaceAll("chatcmpl", "msg") ?? "msg_ferrogate";
  const model = getString(chat, "model") ?? fallbackModel;

  const choice = asArray(get(chat, "choices"))?.[0];
  const message = get(choice, "message");
  const finishReason = getString(choice, "finish_reason");

  const content: Record<string, unknown>[] = [];
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
      id: getString(toolCall, "id") ?? "",
      name: getString(fn, "name") ?? "",
      input: parseToolArguments(get(fn, "arguments")),
    });
  }

  const usage = get(chat, "usage");
  return {
    id,
    type: "message",
    role: "assistant",
    model,
    content,
    stop_reason: finishReasonToStopReason(finishReason, sawToolUse),
    stop_sequence: null,
    usage: {
      input_tokens: getUint(usage, "prompt_tokens") ?? 0,
      output_tokens: getUint(usage, "completion_tokens") ?? 0,
    },
  };
}

/** The local (default) implementation of {@link AnthropicMessagesPort}. */
export const localAnthropicMessagesPort: AnthropicMessagesPort = {
  finishReasonToStopReason,
  chatCompletionToMessage,
};
