import { describe, expect, test } from "vitest";

import {
  ResponsesStreamNormalizer,
  type ResponsesStreamProviderKind,
  isDoneEvent,
  responsesNormalizeStream,
} from "../../src/streaming/responses.js";
import {
  bytes,
  chunkBytes,
  drainText,
  eventNames,
  jsonEvents,
  splitBytes,
  streamOf,
} from "./helpers.js";

function normalize(
  source: string | Uint8Array[],
  providerKind: ResponsesStreamProviderKind = "openai_compatible",
  requestId = "fg-test",
): Promise<string> {
  const chunks = typeof source === "string" ? [bytes(source)] : source;
  return drainText(
    streamOf(chunks).pipeThrough(
      responsesNormalizeStream({
        providerKind,
        requestId,
        contentType: "text/event-stream",
      }),
    ),
  );
}

describe("Responses normalizer — OpenAI-compatible upstream", () => {
  test("renders text deltas, the usage tail and the [DONE] terminator", async () => {
    const sse = await normalize(
      'data: {"choices":[{"delta":{"content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}\n\n' +
        "data: [DONE]\n\n",
    );
    expect(sse).toContain("event: response.output_text.delta");
    expect(sse).toContain('"delta":"ok"');
    expect(sse).toContain('"request_id":"fg-test"');
    expect(sse).toContain("event: response.output_text.done");
    expect(sse).toContain("event: response.completed");
    expect(sse).toContain('"prompt_tokens":3');
    expect(sse).toContain('"completion_tokens":5');
    expect(sse).toContain('"total_tokens":8');
    expect(sse.endsWith("data: [DONE]\n\n")).toBe(true);
  });

  test("response.completed carries content_type and null-filled usage", async () => {
    const sse = await normalize('data: {"choices":[{"delta":{"content":"x"}}]}\n\n');
    const completed = jsonEvents(sse, "response.completed")[0] as {
      content_type: string;
      usage: Record<string, number | null>;
    };
    expect(completed.content_type).toBe("text/event-stream");
    expect(completed.usage).toEqual({
      prompt_tokens: null,
      completion_tokens: null,
      total_tokens: null,
    });
  });

  test("tool-call fragments become argument deltas plus one done event", async () => {
    const sse = await normalize(
      'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"lookup","arguments":"{\\"query\\":\\""}}]}}]}\n\n' +
        'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"ferrogate\\"}"}}]}}]}\n\n' +
        "data: [DONE]\n\n",
    );
    const deltas = jsonEvents(sse, "response.function_call_arguments.delta") as {
      name: string;
      call_id: string;
      delta: string;
    }[];
    expect(deltas).toHaveLength(2);
    expect((deltas[0] as NonNullable<(typeof deltas)[0]>).name).toBe("lookup");
    expect((deltas[0] as NonNullable<(typeof deltas)[0]>).call_id).toBe("call_1");
    expect((deltas[0] as NonNullable<(typeof deltas)[0]>).delta).toBe('{"query":"');
    expect((deltas[1] as NonNullable<(typeof deltas)[1]>).delta).toBe('ferrogate"}');

    const done = jsonEvents(sse, "response.function_call_arguments.done") as {
      name: string;
      call_id: string;
      arguments: string;
    }[];
    expect(done).toHaveLength(1);
    expect((done[0] as NonNullable<(typeof done)[0]>).arguments).toBe('{"query":"ferrogate"}');
    expect((done[0] as NonNullable<(typeof done)[0]>).call_id).toBe("call_1");
  });

  test("the deprecated function_call shape is accumulated too", async () => {
    const sse = await normalize(
      'data: {"choices":[{"delta":{"function_call":{"name":"legacy","arguments":"{\\"a"}}}]}\n\n' +
        'data: {"choices":[{"delta":{"function_call":{"arguments":"\\":1}"}}}]}\n\n' +
        "data: [DONE]\n\n",
    );
    const done = jsonEvents(sse, "response.function_call_arguments.done") as {
      arguments: string;
      name: string;
    }[];
    expect((done[0] as NonNullable<(typeof done)[0]>).arguments).toBe('{"a":1}');
    expect((done[0] as NonNullable<(typeof done)[0]>).name).toBe("legacy");
  });

  test("output_text and delta.text are accepted as text carriers", async () => {
    expect(await normalize('data: {"output_text":"whole"}\n\n')).toContain('"delta":"whole"');
    expect(await normalize('data: {"choices":[{"delta":{"text":"alt"}}]}\n\n')).toContain(
      '"delta":"alt"',
    );
  });

  test("no output_text.done is emitted when no text ever flowed", async () => {
    const sse = await normalize("data: [DONE]\n\n");
    expect(eventNames(sse)).toEqual(["response.completed"]);
  });
});

describe("Responses normalizer — Anthropic upstream", () => {
  test("content_block_delta becomes an output_text delta and message_stop ends it", async () => {
    const sse = await normalize(
      'event: content_block_delta\ndata: {"delta":{"text":"ok"}}\n\n' +
        "event: message_stop\ndata: {}\n\n",
      "anthropic",
    );
    expect(sse).toContain("event: response.output_text.delta");
    expect(sse).toContain('"delta":"ok"');
    expect(sse).toContain("event: response.completed");
  });

  test("Anthropic text deltas do not create spurious function calls", async () => {
    const sse = await normalize(
      'event: content_block_delta\ndata: {"index":0,"delta":{"text":"ok"}}\n\n' +
        "event: message_stop\ndata: {}\n\n",
      "anthropic",
    );
    expect(jsonEvents(sse, "response.output_text.delta")).toHaveLength(1);
    expect(jsonEvents(sse, "response.function_call_arguments.delta")).toHaveLength(0);
  });

  test("Anthropic tool metadata and partial_json are accumulated", async () => {
    const sse = await normalize(
      'event: content_block_start\ndata: {"index":1,"content_block":{"type":"tool_use","id":"tool_1","name":"lookup","input":{}}}\n\n' +
        'event: content_block_delta\ndata: {"index":1,"delta":{"type":"input_json_delta","partial_json":"{\\"q\\":\\"x\\"}"}}\n\n' +
        "event: message_stop\ndata: {}\n\n",
      "anthropic",
    );
    const done = jsonEvents(sse, "response.function_call_arguments.done") as Array<{
      call_id: string;
      name: string;
      arguments: string;
    }>;
    expect(done).toEqual([
      expect.objectContaining({ call_id: "tool_1", name: "lookup", arguments: '{"q":"x"}' }),
    ]);
  });

  test("message_start input tokens and message_delta output tokens are reported", async () => {
    const sse = await normalize(
      'event: message_start\ndata: {"message":{"usage":{"input_tokens":11,"output_tokens":0}}}\n\n' +
        'event: message_delta\ndata: {"delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":11,"output_tokens":4}}\n\n' +
        "event: message_stop\ndata: {}\n\n",
      "anthropic",
    );
    const completed = jsonEvents(sse, "response.completed")[0] as {
      usage: Record<string, number | null>;
    };
    expect(completed.usage).toEqual({
      prompt_tokens: 11,
      completion_tokens: 4,
      total_tokens: 15,
    });
  });
});

describe("Responses normalizer — Gemini upstream", () => {
  test("candidate parts become text deltas and usageMetadata is mapped", async () => {
    const sse = await normalize(
      'data: {"candidates":[{"content":{"parts":[{"text":"ok"}]}}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":5,"totalTokenCount":8}}\n\n',
      "gemini",
    );
    expect(sse).toContain("event: response.output_text.delta");
    expect(sse).toContain('"prompt_tokens":3');
    expect(sse).toContain('"completion_tokens":5');
    expect(sse).toContain('"total_tokens":8');
  });

  test("multiple parts emit one delta each, in order", async () => {
    const sse = await normalize(
      'data: {"candidates":[{"content":{"parts":[{"text":"a"},{"text":"b"}]}}]}\n\n',
      "gemini",
    );
    const deltas = jsonEvents(sse, "response.output_text.delta") as {
      delta: string;
    }[];
    expect(deltas.map((delta) => delta.delta)).toEqual(["a", "b"]);
  });

  test("functionCall args objects are serialized as JSON", async () => {
    const sse = await normalize(
      'data: {"candidates":[{"content":{"parts":[{"text":"answer"},{"functionCall":{"name":"lookup","args":{"q":"x"}}}]}}]}\n\n',
      "gemini",
    );
    const done = jsonEvents(sse, "response.function_call_arguments.done") as Array<{
      name: string;
      arguments: string;
    }>;
    expect(done).toEqual([expect.objectContaining({ name: "lookup", arguments: '{"q":"x"}' })]);
  });

  test("thought summaries are not emitted as visible response text", async () => {
    const sse = await normalize(
      'data: {"candidates":[{"content":{"parts":[{"thought":true,"text":"hidden"},{"text":"visible"}]}}]}\n\n',
      "gemini",
    );
    const deltas = jsonEvents(sse, "response.output_text.delta") as Array<{ delta: string }>;
    expect(deltas.map((event) => event.delta)).toEqual(["visible"]);
  });
});

describe("Responses normalizer — failures and terminators", () => {
  test("a provider error becomes response.failed + [DONE] and stops the stream", async () => {
    const sse = await normalize(
      'event: error\ndata: {"error":{"message":"stream exploded","type":"rate_limit_exceeded","code":"rate_limit_exceeded"}}\n\n' +
        'data: {"choices":[{"delta":{"content":"never"}}]}\n\n',
    );
    expect(eventNames(sse)).toEqual(["response.failed"]);
    expect(sse).toContain('"message":"stream exploded"');
    expect(sse).toContain('"code":"rate_limit_exceeded"');
    expect(sse).toContain('"type":"ferrogate_error"');
    expect(sse).toContain("data: [DONE]");
    expect(sse).not.toContain("never");
    expect(sse).not.toContain("response.completed");
  });

  test("isDoneEvent waits for a real terminal reason", () => {
    expect(isDoneEvent("response.completed", undefined)).toBe(true);
    expect(isDoneEvent("message_stop", undefined)).toBe(true);
    expect(isDoneEvent(undefined, { type: "response.completed" })).toBe(true);
    expect(isDoneEvent(undefined, { finish_reason: null })).toBe(false);
    expect(isDoneEvent(undefined, { choices: [{ finish_reason: null }] })).toBe(false);
    expect(isDoneEvent(undefined, { choices: [{ finish_reason: "stop" }] })).toBe(true);
    expect(isDoneEvent("content_block_delta", { delta: {} })).toBe(false);
  });

  test("a top-level finish_reason terminates the stream immediately", async () => {
    const sse = await normalize(
      'data: {"choices":[{"delta":{"content":"x"}}],"finish_reason":"stop"}\n\n' +
        'data: {"choices":[{"delta":{"content":"after"}}]}\n\n',
    );
    expect(sse).toContain('"delta":"x"');
    expect(sse).not.toContain("after");
    expect(sse).toContain("event: response.completed");
  });

  test("[DONE] closes the stream: later upstream frames are dropped", async () => {
    const sse = await normalize(
      'data: {"choices":[{"delta":{"content":"before"}}]}\n\n' +
        "data: [DONE]\n\n" +
        'data: {"choices":[{"delta":{"content":"after"}}],"usage":{"prompt_tokens":99}}\n\n',
    );
    expect(sse).toContain('"delta":"before"');
    expect(sse).not.toContain("after");
    expect(sse).not.toContain("99");
    // Exactly one terminator, and it is the last thing on the wire.
    expect(sse.split("data: [DONE]")).toHaveLength(2);
    expect(eventNames(sse)).toEqual([
      "response.output_text.delta",
      "response.output_text.done",
      "response.completed",
    ]);
  });

  test("an upstream that just ends still gets completed + [DONE]", async () => {
    const sse = await normalize("");
    expect(eventNames(sse)).toEqual(["response.completed"]);
    expect(sse).toContain("data: [DONE]");
  });

  test("usage is merged across partial frames", () => {
    const normalizer = new ResponsesStreamNormalizer({
      providerKind: "openai_compatible",
      requestId: "fg-test",
    });
    normalizer.push({
      data: '{"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}',
      comments: [],
      raw: "",
    });
    expect(normalizer.usage.prompt_tokens).toBe(10);
    normalizer.push({ data: '{"usage":{"completion_tokens":9}}', comments: [], raw: "" });
    expect(normalizer.usage).toEqual({
      prompt_tokens: 10,
      completion_tokens: 9,
      total_tokens: 19,
    });
  });
});

describe("Responses normalizer — chunking robustness", () => {
  const source =
    'data: {"choices":[{"delta":{"content":"héllo \u{1F680}"}}]}\n\n' +
    'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"n","arguments":"{\\"k\\":1}"}}]}}]}\n\n' +
    'data: {"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}\n\n' +
    "data: [DONE]\n\n";

  test("output is identical for every chunk size", async () => {
    const reference = await normalize(source);
    const body = bytes(source);
    for (const size of [1, 2, 5, 17, 1024]) {
      expect(await normalize(chunkBytes(body, size))).toBe(reference);
    }
  });

  test("a split inside a multi-byte character does not corrupt the delta", async () => {
    const body = bytes(source);
    const emoji = body.indexOf(0xf0);
    const accent = body.indexOf(0xc3);
    const sse = await normalize(splitBytes(body, [accent + 1, emoji + 3]));
    const deltas = jsonEvents(sse, "response.output_text.delta") as {
      delta: string;
    }[];
    expect((deltas[0] as NonNullable<(typeof deltas)[0]>).delta).toBe("héllo \u{1F680}");
    expect(sse).not.toContain("�");
  });
});
