import {
  chatCompletionToMessage as providersChatCompletionToMessage,
  finishReasonToStopReason as providersFinishReasonToStopReason,
} from "@ferrogate/providers";
import { describe, expect, test } from "vitest";

import { bufferedOpenAiToAnthropicSse } from "../../src/streaming/anthropic.js";
import {
  type AnthropicStopReason,
  chatCompletionToMessage,
  defaultAnthropicMessagesPort,
  finishReasonToStopReason,
} from "../../src/streaming/ports.js";

/**
 * The streaming tower's `AnthropicMessagesPort` is now satisfied by
 * `@ferrogate/providers` (the crate boundary the Rust has:
 * `ferrogate_providers::anthropic_messages`) instead of a second copy of the
 * two helpers inside `src/streaming/`.
 *
 * These tests hold the two things the adapter is allowed to add on top of the
 * package call — the narrowed `AnthropicStopReason` return and the defensive
 * copy — plus the delegation itself, so a future edit that quietly reinstates a
 * local re-implementation (or lets the two drift) goes red.
 */

const STOP_REASONS: readonly AnthropicStopReason[] = ["end_turn", "max_tokens", "tool_use"];

describe("finishReasonToStopReason delegates to @ferrogate/providers", () => {
  // Every arm the Rust `finish_reason_to_stop_reason` match can take, plus
  // inputs no provider should send, so the `as AnthropicStopReason` narrowing
  // is PROVEN rather than asserted by the cast.
  const inputs: readonly (string | undefined)[] = [
    "stop",
    "length",
    "tool_calls",
    "content_filter",
    "function_call",
    "",
    "STOP",
    undefined,
  ];

  test("agrees with the package on every reason x sawToolUse", () => {
    for (const reason of inputs) {
      for (const sawToolUse of [false, true]) {
        expect(finishReasonToStopReason(reason, sawToolUse)).toBe(
          providersFinishReasonToStopReason(reason, sawToolUse),
        );
      }
    }
  });

  test("never returns a value outside the Anthropic stop_reason vocabulary", () => {
    for (const reason of inputs) {
      for (const sawToolUse of [false, true]) {
        expect(STOP_REASONS).toContain(finishReasonToStopReason(reason, sawToolUse));
      }
    }
  });

  test("an observed tool call still wins over the reported finish_reason", () => {
    expect(finishReasonToStopReason("length", true)).toBe("tool_use");
    expect(finishReasonToStopReason("length", false)).toBe("max_tokens");
  });
});

describe("chatCompletionToMessage delegates to @ferrogate/providers", () => {
  const completion = {
    id: "chatcmpl-77",
    model: "gpt-4o-mini",
    choices: [
      {
        finish_reason: "tool_calls",
        message: {
          content: "partial",
          tool_calls: [{ id: "call_1", function: { name: "lookup", arguments: '{"q":"a"}' } }],
        },
      },
    ],
    usage: { prompt_tokens: 11, completion_tokens: 5 },
  };

  test("produces exactly what the package produces", () => {
    expect(chatCompletionToMessage(completion, "fallback")).toStrictEqual(
      providersChatCompletionToMessage(completion, "fallback"),
    );
  });

  test("carries the Rust field shape through the port", () => {
    const message = chatCompletionToMessage(completion, "fallback");
    expect(message.id).toBe("msg-77");
    expect(message.type).toBe("message");
    expect(message.role).toBe("assistant");
    expect(message.model).toBe("gpt-4o-mini");
    expect(message.stop_reason).toBe("tool_use");
    expect(message.stop_sequence).toBeNull();
    expect(message.usage).toStrictEqual({ input_tokens: 11, output_tokens: 5 });
    expect(message.content).toStrictEqual([
      { type: "text", text: "partial" },
      { type: "tool_use", id: "call_1", name: "lookup", input: { q: "a" } },
    ]);
  });

  test("an already-Anthropic body is NOT handed back by reference", () => {
    // The package returns the caller's own object for this arm
    // (`if (isAnthropicMessage(chat)) return chat`). The tower's callers take
    // ownership of the result, so the port must copy.
    const anthropic = { type: "message", content: [{ type: "text", text: "hi" }] };
    const returned = chatCompletionToMessage(anthropic, "fallback");
    expect(returned).toStrictEqual(anthropic);
    expect(returned).not.toBe(anthropic);
    expect(providersChatCompletionToMessage(anthropic, "fallback")).toBe(anthropic);
  });
});

describe("defaultAnthropicMessagesPort is what the tower runs on", () => {
  test("the port object exposes the two adapted helpers", () => {
    expect(defaultAnthropicMessagesPort.finishReasonToStopReason).toBe(finishReasonToStopReason);
    expect(defaultAnthropicMessagesPort.chatCompletionToMessage).toBe(chatCompletionToMessage);
  });

  test("bufferedOpenAiToAnthropicSse uses it by default", () => {
    const sse = [
      'data: {"id":"chatcmpl-1","model":"m","choices":[{"delta":{"content":"hi"}}]}\n\n',
      'data: {"choices":[{"finish_reason":"length"}],"usage":{"prompt_tokens":3,"completion_tokens":1}}\n\n',
      "data: [DONE]\n\n",
    ].join("");
    const text = new TextDecoder().decode(bufferedOpenAiToAnthropicSse(sse, "claude-logical"));
    // `stop_reason` here can only come from the injected port.
    expect(text).toContain('"stop_reason":"max_tokens"');
    expect(text).toContain('"input_tokens":3');
  });
});
