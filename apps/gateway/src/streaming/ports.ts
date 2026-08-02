/**
 * NARROW LOCAL INTERFACES for the streaming tower (dependency inversion).
 *
 * The Rust streaming normalizers call two pure helpers that live in a *sibling
 * crate*, `ferrogate_providers::anthropic_messages`:
 *   - `finish_reason_to_stop_reason(finish_reason, saw_tool_use)`
 *   - `chat_completion_to_message(chat, fallback_model)`
 *
 * Both now exist in `@ferrogate/providers` (`src/anthropic_messages.ts`), which
 * is the crate boundary the Rust has, so this module no longer carries its own
 * copy of either function: {@link defaultAnthropicMessagesPort} adapts the
 * package exports to the narrow port the tower depends on. The interface stays
 * because it is the dependency-inversion seam the normalizers take as a
 * parameter — it is what lets a test drive the tower without the package.
 *
 * The adapter is not a re-implementation. It does exactly two things the
 * package's signatures leave to the caller:
 *   - narrows `finishReasonToStopReason`'s `string` return to the
 *     {@link AnthropicStopReason} vocabulary it actually produces, and
 *   - copies `chatCompletionToMessage`'s result, because for an
 *     ALREADY-Anthropic body the package returns the caller's own object
 *     (`if (isAnthropicMessage(chat)) return chat`) and the tower must not hand
 *     a borrowed object to `messageToAnthropicSse`.
 */
import {
  chatCompletionToMessage as providersChatCompletionToMessage,
  finishReasonToStopReason as providersFinishReasonToStopReason,
} from "@ferrogate/providers";
import type { Json } from "@ferrogate/providers";

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
 * `finish_reason_to_stop_reason`, from `@ferrogate/providers`.
 *
 * The package function is typed `-> string` because the Rust returns a
 * `&'static str`; every arm it can take (`tool_use` / `max_tokens` /
 * `end_turn`) is in {@link AnthropicStopReason}, and
 * `test/streaming/ports.test.ts` holds that exhaustively rather than trusting
 * the cast.
 */
export function finishReasonToStopReason(
  finishReason: string | undefined,
  sawToolUse: boolean,
): AnthropicStopReason {
  return providersFinishReasonToStopReason(finishReason, sawToolUse) as AnthropicStopReason;
}

/**
 * `chat_completion_to_message`, from `@ferrogate/providers`.
 *
 * The copy is the one thing added on top of the package call: for an
 * already-Anthropic body the package returns the argument itself, and the
 * tower's callers (`bufferedOpenAiToAnthropicSse` → `messageToAnthropicSse`)
 * take ownership of what they get back.
 */
export function chatCompletionToMessage(
  chat: unknown,
  fallbackModel: string,
): Record<string, unknown> {
  const message = providersChatCompletionToMessage(chat as Json, fallbackModel);
  return { ...(message as Record<string, unknown>) };
}

/** The default {@link AnthropicMessagesPort}: `@ferrogate/providers`, adapted. */
export const defaultAnthropicMessagesPort: AnthropicMessagesPort = {
  finishReasonToStopReason,
  chatCompletionToMessage,
};
