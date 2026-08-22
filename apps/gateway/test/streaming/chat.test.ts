import { describe, expect, test } from "vitest";

import { nativeToOpenAiChatStream } from "../../src/streaming/chat.js";
import { frameJson, isDoneFrame, parseSse } from "../../src/streaming/sse.js";
import { bytes, chunkBytes, drainText, streamOf } from "./helpers.js";

function payloads(body: string): Record<string, unknown>[] {
  return parseSse(body)
    .filter((frame) => !isDoneFrame(frame))
    .map((frame) => frameJson(frame))
    .filter(
      (value): value is Record<string, unknown> =>
        typeof value === "object" && value !== null && !Array.isArray(value),
    );
}

describe("native provider -> OpenAI chat stream", () => {
  test("Anthropic preserves text, tool JSON fragments, finish reason, and usage", async () => {
    const source =
      'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_1","model":"claude-test","usage":{"input_tokens":5,"cache_read_input_tokens":7,"cache_creation_input_tokens":2,"output_tokens":0}}}\n\n' +
      'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n' +
      'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}\n\n' +
      'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"anthropic-signature"}}\n\n' +
      'event: content_block_start\ndata: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"tool_1","name":"lookup","input":{}}}\n\n' +
      'event: content_block_delta\ndata: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\\"q\\":\\"x\\"}"}}\n\n' +
      'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":4}}\n\n' +
      'event: message_stop\ndata: {"type":"message_stop"}\n\n';
    const output = await drainText(
      streamOf(chunkBytes(bytes(source), 7)).pipeThrough(
        nativeToOpenAiChatStream({
          providerKind: "anthropic",
          requestId: "req-1",
          fallbackModel: "claude-logical",
        }),
      ),
    );

    expect(output).not.toContain("message_start");
    expect(output).toContain('"object":"chat.completion.chunk"');
    expect(output).toContain('"content":"hello"');
    expect(output).toContain('"reasoning_signature":"anthropic-signature"');
    expect(output).toContain('"name":"lookup"');
    expect(output).toContain('"arguments":"{\\"q\\":\\"x\\"}"');
    expect(output).toContain('"finish_reason":"tool_calls"');
    expect(output).toContain('"prompt_tokens":14');
    expect(output).toContain('"total_tokens":18');
    expect(output).toContain('"cache_creation_input_tokens":2');
    expect(output.endsWith("data: [DONE]\n\n")).toBe(true);
  });

  test("Gemini separates thought text, text, function calls, and usage", async () => {
    const source =
      'data: {"responseId":"gemini-1","modelVersion":"gemini-test","candidates":[{"content":{"parts":[{"thought":true,"text":"reason","thoughtSignature":"reason-signature"},{"text":"answer","thoughtSignature":"text-signature"},{"thoughtSignature":"tool-signature","functionCall":{"id":"duplicate","name":"lookup","args":{"q":"x"}}},{"functionCall":{"id":"duplicate","name":"lookup-again","args":{}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"cachedContentTokenCount":3,"candidatesTokenCount":4,"thoughtsTokenCount":2,"totalTokenCount":16}}\n\n';
    const output = await drainText(
      streamOf([source]).pipeThrough(
        nativeToOpenAiChatStream({
          providerKind: "gemini",
          requestId: "req-2",
          fallbackModel: "gemini-logical",
        }),
      ),
    );
    const chunks = payloads(output);

    expect(output).toContain('"reasoning_content":"reason"');
    expect(output).toContain('"content":"answer"');
    expect(output).toContain('"reasoning_signature":"reason-signature"');
    expect(output).toContain('"text_signature":"text-signature"');
    expect(output).toContain('"id":"duplicate"');
    expect(output).toContain('"id":"call_0_1"');
    expect(output).toContain('"thought_signature":"tool-signature"');
    expect(output).toContain('"arguments":"{\\"q\\":\\"x\\"}"');
    expect(output).toContain('"completion_tokens":6');
    expect(output).toContain('"reasoning_tokens":2');
    expect(chunks.some((chunk) => chunk.object === "chat.completion.chunk")).toBe(true);
    expect(output.endsWith("data: [DONE]\n\n")).toBe(true);
  });

  test("Gemini meters thought-only usage as completion tokens", async () => {
    const source =
      'data: {"candidates":[],"usageMetadata":{"promptTokenCount":3,"thoughtsTokenCount":5,"totalTokenCount":8}}\n\n';
    const output = await drainText(
      streamOf([source]).pipeThrough(
        nativeToOpenAiChatStream({
          providerKind: "gemini",
          requestId: "req-3",
          fallbackModel: "gemini-logical",
        }),
      ),
    );

    expect(output).toContain('"completion_tokens":5');
    expect(output).toContain('"reasoning_tokens":5');
  });
});
