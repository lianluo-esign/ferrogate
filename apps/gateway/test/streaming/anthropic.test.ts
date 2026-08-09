import { describe, expect, test } from "vitest";

import {
  FALLBACK_MESSAGE_ID,
  OpenAiToAnthropicNormalizer,
  bufferedOpenAiToAnthropicSse,
  errorSse,
  messageToAnthropicSse,
  openAiToAnthropicFrameStream,
  openAiToAnthropicStream,
} from "../../src/streaming/anthropic.js";
import { parseSse, serializeSseFrames } from "../../src/streaming/sse.js";
import {
  OPENAI_TEXT_STREAM,
  OPENAI_TOOL_STREAM,
  bytes,
  chunkBytes,
  drainText,
  eventNames,
  jsonEvents,
  splitBytes,
  streamOf,
} from "./helpers.js";

const decoder = new TextDecoder();

function normalize(
  source: string | Uint8Array[],
  fallbackModel = "claude-logical",
): Promise<string> {
  const chunks = typeof source === "string" ? [bytes(source)] : source;
  return drainText(streamOf(chunks).pipeThrough(openAiToAnthropicStream({ fallbackModel })));
}

describe("messageToAnthropicSse (buffered serialization)", () => {
  const message = {
    id: "msg-1",
    type: "message",
    role: "assistant",
    model: "claude-logical",
    content: [
      { type: "text", text: "hi" },
      { type: "tool_use", id: "call_1", name: "lookup", input: { q: "x" } },
    ],
    stop_reason: "tool_use",
    stop_sequence: null,
    usage: { input_tokens: 5, output_tokens: 3 },
  };

  test("emits the Anthropic frame sequence in order", () => {
    const sse = decoder.decode(messageToAnthropicSse(message));
    expect(eventNames(sse)).toEqual([
      "message_start",
      "content_block_start",
      "content_block_delta",
      "content_block_stop",
      "content_block_start",
      "content_block_delta",
      "content_block_stop",
      "message_delta",
      "message_stop",
    ]);
  });

  test("renders text and tool_use blocks with their Anthropic delta types", () => {
    const sse = decoder.decode(messageToAnthropicSse(message));
    expect(sse).toContain('"type":"text_delta"');
    expect(sse).toContain('"text":"hi"');
    expect(sse).toContain('"type":"input_json_delta"');
    expect(sse).toContain('"partial_json":"{\\"q\\":\\"x\\"}"');
    expect(sse).toContain('"stop_reason":"tool_use"');
    expect(sse).toContain('"output_tokens":3');
  });

  test("message_start reports output_tokens 0; the tail reports the real count", () => {
    const frames = parseSse(messageToAnthropicSse(message));
    const start = JSON.parse((frames[0] as NonNullable<(typeof frames)[0]>).data!) as {
      message: { usage: { input_tokens: number; output_tokens: number } };
    };
    expect(start.message.usage).toEqual({ input_tokens: 5, output_tokens: 0 });
    const delta = jsonEvents(
      decoder.decode(messageToAnthropicSse(message)),
      "message_delta",
    )[0] as { usage: { output_tokens: number } };
    expect(delta.usage.output_tokens).toBe(3);
  });

  test("a tool_use block with no input still emits {} partial_json", () => {
    const sse = decoder.decode(
      messageToAnthropicSse({
        content: [{ type: "tool_use", id: "c", name: "n" }],
      }),
    );
    expect(sse).toContain('"partial_json":"{}"');
  });

  test("missing id/model fall back to the Rust literals", () => {
    const sse = decoder.decode(messageToAnthropicSse({ content: [] }));
    expect(sse).toContain(`"id":"${FALLBACK_MESSAGE_ID}"`);
    expect(sse).toContain('"model":null');
  });
});

describe("OpenAI -> Anthropic incremental normalizer", () => {
  test("translates a text stream into the Anthropic frame sequence", async () => {
    const sse = await normalize(OPENAI_TEXT_STREAM);
    expect(eventNames(sse)).toEqual([
      "message_start",
      "content_block_start",
      "content_block_delta",
      "content_block_delta",
      "content_block_stop",
      "message_delta",
      "message_stop",
    ]);
    // Two separate deltas -- the stream is NOT coalesced.
    expect(sse).toContain('"text":"Hel"');
    expect(sse).toContain('"text":"lo"');
    expect(sse).toContain('"id":"msg-1"');
    expect(sse).toContain('"model":"gpt-4o"');
    expect(sse).toContain('"stop_reason":"end_turn"');
    expect(sse).toContain('"output_tokens":2');
    expect(sse).toContain('"input_tokens":5');
    // The Anthropic dialect has no [DONE] sentinel.
    expect(sse).not.toContain("[DONE]");
  });

  test("terminal stop_reason/usage match the buffered pipeline exactly", async () => {
    const incremental = await normalize(OPENAI_TEXT_STREAM);
    const buffered = decoder.decode(
      bufferedOpenAiToAnthropicSse(OPENAI_TEXT_STREAM, "claude-logical"),
    );
    const incrementalDelta = jsonEvents(incremental, "message_delta")[0] as {
      delta: { stop_reason: string };
      usage: { output_tokens: number };
    };
    const bufferedDelta = jsonEvents(buffered, "message_delta")[0] as {
      delta: { stop_reason: string };
      usage: { output_tokens: number };
    };
    expect(incrementalDelta.delta.stop_reason).toBe("end_turn");
    expect(bufferedDelta.delta.stop_reason).toBe("end_turn");
    expect(incrementalDelta.usage.output_tokens).toBe(2);
    expect(bufferedDelta.usage.output_tokens).toBe(2);
  });

  test("interleaved tool calls open a second content block", async () => {
    const sse = await normalize(OPENAI_TOOL_STREAM);
    expect(eventNames(sse)).toEqual([
      "message_start",
      "content_block_start",
      "content_block_delta",
      "content_block_stop",
      "content_block_start",
      "content_block_delta",
      "content_block_delta",
      "content_block_stop",
      "message_delta",
      "message_stop",
    ]);
    expect(sse).toContain('"type":"tool_use"');
    expect(sse).toContain('"id":"call_1"');
    expect(sse).toContain('"name":"lookup"');
    expect(sse).toContain('"partial_json":"{\\"q\\":"');
    expect(sse).toContain('"partial_json":"\\"x\\"}"');
    expect(sse).toContain('"stop_reason":"tool_use"');
  });

  test("two parallel tool calls get two blocks with ascending indices", async () => {
    const sse = await normalize(
      'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"a","function":{"name":"alpha","arguments":"A"}}]}}]}\n\n' +
        'data: {"choices":[{"delta":{"tool_calls":[{"index":1,"id":"b","function":{"name":"beta","arguments":"B"}}]}}]}\n\n' +
        "data: [DONE]\n\n",
    );
    const starts = jsonEvents(sse, "content_block_start") as {
      index: number;
      content_block: { id: string; name: string };
    }[];
    expect(starts.map((start) => start.index)).toEqual([0, 1]);
    expect(starts.map((start) => start.content_block.name)).toEqual(["alpha", "beta"]);
    const stops = jsonEvents(sse, "content_block_stop") as { index: number }[];
    expect(stops.map((stop) => stop.index)).toEqual([0, 1]);
  });

  test("a provider error frame becomes an Anthropic error frame and stops the stream", async () => {
    const sse = await normalize(
      'data: {"error":{"message":"stream exploded","code":"rate_limit_exceeded"}}\n\n' +
        'data: {"choices":[{"delta":{"content":"never"}}]}\n\n',
    );
    expect(eventNames(sse)).toEqual(["error"]);
    expect(sse).toContain('"type":"rate_limit_exceeded"');
    expect(sse).toContain('"message":"stream exploded"');
    expect(sse).not.toContain("never");
    expect(sse).not.toContain("message_stop");
  });

  test("an error frame without code falls back to type, then to the literal", async () => {
    expect(await normalize('data: {"error":{"type":"overloaded"}}\n\n')).toContain(
      '"type":"overloaded"',
    );
    expect(await normalize('data: {"error":{}}\n\n')).toContain('"type":"provider_stream_error"');
    expect(await normalize('data: {"error":{}}\n\n')).toContain(
      "provider returned a streaming error",
    );
  });

  test("an empty upstream still produces a well-formed Anthropic stream", async () => {
    const sse = await normalize("");
    expect(eventNames(sse)).toEqual(["message_start", "message_delta", "message_stop"]);
    expect(sse).toContain('"model":"claude-logical"');
    expect(sse).toContain('"output_tokens":0');
  });

  test("[DONE] closes the stream: later upstream frames are dropped", async () => {
    const sse = await normalize(
      'data: {"choices":[{"delta":{"content":"before"}}]}\n\n' +
        "data: [DONE]\n\n" +
        'data: {"choices":[{"delta":{"content":"after"}}],"usage":{"completion_tokens":99}}\n\n',
    );
    expect(sse).toContain('"text":"before"');
    expect(sse).not.toContain("after");
    expect(sse).not.toContain('"output_tokens":99');
    expect(eventNames(sse)).toEqual([
      "message_start",
      "content_block_start",
      "content_block_delta",
      "content_block_stop",
      "message_delta",
      "message_stop",
    ]);
  });

  test("a stream that ends without [DONE] still gets its terminal frames", async () => {
    const sse = await normalize('data: {"choices":[{"delta":{"content":"x"}}]}\n\n');
    expect(eventNames(sse).at(-1)).toBe("message_stop");
  });

  test("provider keep-alive comments are inert", async () => {
    const sse = await normalize(
      ': ping\n\ndata: {"choices":[{"delta":{"content":"x"}}]}\n\ndata: [DONE]\n\n',
    );
    expect(eventNames(sse)[0]).toBe("message_start");
    expect(sse).not.toContain("ping");
  });

  test("output is identical regardless of how the input bytes are chunked", async () => {
    const reference = await normalize(OPENAI_TOOL_STREAM);
    const body = bytes(OPENAI_TOOL_STREAM);
    for (const size of [1, 3, 7, 64, 4096]) {
      expect(await normalize(chunkBytes(body, size))).toBe(reference);
    }
  });

  test("a chunk split inside a multi-byte character does not corrupt a delta", async () => {
    const source =
      'data: {"choices":[{"delta":{"content":"héllo \u{1F680}"}}]}\n\ndata: [DONE]\n\n';
    const body = bytes(source);
    const emojiStart = body.indexOf(0xf0);
    const accentStart = body.indexOf(0xc3);
    const sse = await normalize(splitBytes(body, [accentStart + 1, emojiStart + 2]));
    const deltas = jsonEvents(sse, "content_block_delta") as {
      delta: { text: string };
    }[];
    expect(deltas).toHaveLength(1);
    expect((deltas[0] as NonNullable<(typeof deltas)[0]>).delta.text).toBe("héllo \u{1F680}");
    expect(sse).not.toContain("�");
  });

  test("emits frames incrementally, not buffered until the stream ends", async () => {
    const transform = openAiToAnthropicFrameStream({
      fallbackModel: "claude-logical",
    });
    const writer = transform.writable.getWriter();
    const reader = transform.readable.getReader();
    // Not awaited: `write` only settles once the readable side drains, which is
    // itself the proof that the normalizer emits before the stream is closed.
    const firstWrite = writer.write(
      parseSse('data: {"id":"chatcmpl-1","choices":[{"delta":{"content":"first"}}]}\n\n')[0]!,
    );

    const early: string[] = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      early.push(serializeSseFrames([value]));
      if (early.join("").includes('"text":"first"')) {
        break;
      }
    }
    await firstWrite;
    const earlyText = early.join("");
    // The first token reached the client while the provider had sent exactly
    // one frame, and the stream is still open.
    expect(earlyText).toContain("event: message_start");
    expect(earlyText).toContain("event: content_block_delta");
    expect(earlyText).not.toContain("event: message_stop");

    await writer.close();
    const rest: string[] = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      rest.push(serializeSseFrames([value]));
    }
    expect(rest.join("")).toContain("event: message_delta");
    expect(rest.join("")).toContain("event: message_stop");
  });

  test("the normalizer class is idempotent once completed", () => {
    const normalizer = new OpenAiToAnthropicNormalizer({
      fallbackModel: "claude-logical",
    });
    // An untouched stream still gets a full, well-formed Anthropic envelope.
    expect(normalizer.finish().map((frame) => frame.event)).toEqual([
      "message_start",
      "message_delta",
      "message_stop",
    ]);
    expect(normalizer.completed).toBe(true);
    expect(normalizer.finish()).toEqual([]);
    expect(normalizer.push(parseSse('data: {"choices":[{"delta":{}}]}\n\n')[0]!)).toEqual([]);
  });
});

describe("errorSse", () => {
  test("renders a single Anthropic error frame", () => {
    expect(decoder.decode(errorSse("bad_request", "nope"))).toBe(
      'event: error\ndata: {"type":"error","error":{"type":"bad_request","message":"nope"}}\n\n',
    );
  });
});
