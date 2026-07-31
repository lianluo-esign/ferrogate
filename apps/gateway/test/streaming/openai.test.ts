import { describe, expect, test } from "vitest";

import {
  FALLBACK_COMPLETION_ID,
  chatAggregateStream,
  chatSseToCompletion,
} from "../../src/streaming/openai.js";
import { sseParseStream } from "../../src/streaming/sse.js";
import {
  OPENAI_TEXT_STREAM,
  OPENAI_TOOL_STREAM,
  chunkBytes,
  bytes,
  drainFrames,
  streamOf,
} from "./helpers.js";

describe("chatSseToCompletion (buffered/governed leg)", () => {
  test("accumulates an OpenAI chat SSE stream into one completion", () => {
    const completion = chatSseToCompletion(OPENAI_TEXT_STREAM);
    expect(completion.id).toBe("chatcmpl-1");
    expect(completion.model).toBe("gpt-4o");
    expect(completion.object).toBe("chat.completion");
    expect(completion.choices[0]!.message["content"]).toBe("Hello");
    expect(completion.choices[0]!.finish_reason).toBe("stop");
    expect(completion.usage).toEqual({
      prompt_tokens: 5,
      completion_tokens: 2,
      total_tokens: 7,
    });
  });

  test("accumulates streamed tool calls into a single arguments string", () => {
    const completion = chatSseToCompletion(OPENAI_TOOL_STREAM);
    const toolCalls = completion.choices[0]!.message["tool_calls"] as {
      id: string;
      function: { name: string; arguments: string };
    }[];
    expect(toolCalls).toHaveLength(1);
    expect(toolCalls[0]!.id).toBe("call_1");
    expect(toolCalls[0]!.function.name).toBe("lookup");
    expect(toolCalls[0]!.function.arguments).toBe('{"q":"x"}');
    expect(completion.choices[0]!.finish_reason).toBe("tool_calls");
  });

  test("content is null (not empty string) when no chunk carried text", () => {
    const completion = chatSseToCompletion(
      'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c","function":{"name":"n","arguments":"{}"}}]}}]}\n\n',
    );
    expect(completion.choices[0]!.message["content"]).toBeNull();
  });

  test("the [DONE] sentinel and unparsable frames are skipped, not fatal", () => {
    const completion = chatSseToCompletion(
      "data: [DONE]\n\ndata: not json at all\n\n" +
        'data: {"choices":[{"delta":{"content":"ok"}}]}\n\n',
    );
    expect(completion.choices[0]!.message["content"]).toBe("ok");
  });

  test("falls back to the Rust literal id when no chunk carries one", () => {
    const completion = chatSseToCompletion(
      'data: {"choices":[{"delta":{"content":"x"}}]}\n\n',
    );
    expect(completion.id).toBe(FALLBACK_COMPLETION_ID);
    expect(completion.model).toBeUndefined();
    expect(completion.choices[0]!.finish_reason).toBeNull();
  });

  test("a later usage frame replaces an earlier one; nulls do not clobber", () => {
    const completion = chatSseToCompletion(
      'data: {"choices":[{"delta":{"content":"a"}}],"usage":null}\n\n' +
        'data: {"choices":[{"delta":{}}],"usage":{"prompt_tokens":1}}\n\n' +
        'data: {"choices":[{"delta":{}}],"usage":{"prompt_tokens":9,"completion_tokens":3}}\n\n',
    );
    expect(completion.usage).toEqual({ prompt_tokens: 9, completion_tokens: 3 });
  });
});

describe("chatAggregateStream (live fold)", () => {
  test("frames pass through untouched while the aggregate is built", async () => {
    const { stream, completion } = chatAggregateStream();
    const frames = await drainFrames(
      streamOf(chunkBytes(bytes(OPENAI_TEXT_STREAM), 5))
        .pipeThrough(sseParseStream())
        .pipeThrough(stream),
    );
    expect(frames).toHaveLength(4);
    expect(frames[3]!.data).toBe("[DONE]");
    const aggregate = await completion;
    expect(aggregate.choices[0]!.message["content"]).toBe("Hello");
    expect(aggregate.id).toBe("chatcmpl-1");
  });
});
