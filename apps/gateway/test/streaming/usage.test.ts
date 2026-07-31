import { describe, expect, test } from "vitest";

import {
  STREAMING_CAPTURE_MAX_BYTES,
  STREAMING_CAPTURE_PREFIX_MAX_BYTES,
  StreamingBodyCapture,
  UsageCapture,
  bodyCaptureStream,
  extractLastStreamUsage,
  extractUsage,
  mergeUsage,
  usageCaptureStream,
  usageToOpenAiJson,
} from "../../src/streaming/usage.js";
import { sseParseStream, sseSerializeStream } from "../../src/streaming/sse.js";
import {
  OPENAI_TEXT_STREAM,
  bytes,
  chunkBytes,
  drainFrames,
  drainText,
  streamOf,
} from "./helpers.js";

describe("extractUsage", () => {
  test("OpenAI usage frame", () => {
    expect(
      extractUsage(
        { usage: { prompt_tokens: 5, completion_tokens: 2, total_tokens: 7 } },
        "openai_compatible",
      ),
    ).toEqual({ promptTokens: 5, completionTokens: 2, totalTokens: 7 });
  });

  test("Anthropic message_start nests usage under message", () => {
    expect(
      extractUsage(
        {
          type: "message_start",
          message: { usage: { input_tokens: 11, output_tokens: 0 } },
        },
        "anthropic",
      ),
    ).toEqual({ promptTokens: 11, completionTokens: 0, totalTokens: 11 });
  });

  test("Anthropic message_delta reports only output_tokens", () => {
    expect(
      extractUsage(
        { type: "message_delta", delta: {}, usage: { output_tokens: 17 } },
        "anthropic",
      ),
    ).toEqual({
      promptTokens: undefined,
      completionTokens: 17,
      totalTokens: undefined,
    });
  });

  test("Gemini usageMetadata", () => {
    expect(
      extractUsage(
        {
          usageMetadata: {
            promptTokenCount: 3,
            candidatesTokenCount: 5,
            totalTokenCount: 8,
          },
        },
        "gemini",
      ),
    ).toEqual({ promptTokens: 3, completionTokens: 5, totalTokens: 8 });
  });

  test("a frame with no usage, or a null usage, reports nothing", () => {
    expect(extractUsage({ choices: [] })).toBeUndefined();
    expect(extractUsage({ usage: null })).toBeUndefined();
    expect(extractUsage({ usage: {} })).toBeUndefined();
  });

  test("non-integer or negative counters are rejected, not metered", () => {
    expect(extractUsage({ usage: { prompt_tokens: 1.5 } })).toBeUndefined();
    expect(extractUsage({ usage: { prompt_tokens: -3 } })).toBeUndefined();
    expect(extractUsage({ usage: { prompt_tokens: "12" } })).toBeUndefined();
  });
});

describe("mergeUsage", () => {
  test("a later partial reading does not erase an earlier field", () => {
    const merged = mergeUsage(
      { promptTokens: 11, completionTokens: 0, totalTokens: 11 },
      { completionTokens: 17 },
    );
    expect(merged).toEqual({
      promptTokens: 11,
      completionTokens: 17,
      totalTokens: 28,
    });
  });

  test("total_tokens is synthesized when the provider omits it", () => {
    expect(mergeUsage(undefined, { promptTokens: 2, completionTokens: 3 })).toEqual(
      { promptTokens: 2, completionTokens: 3, totalTokens: 5 },
    );
  });

  test("a reported total wins over the synthesized one", () => {
    expect(
      mergeUsage(undefined, {
        promptTokens: 2,
        completionTokens: 3,
        totalTokens: 99,
      })?.totalTokens,
    ).toBe(99);
  });

  test("merging nothing keeps the previous reading", () => {
    const previous = { promptTokens: 1, completionTokens: 1, totalTokens: 2 };
    expect(mergeUsage(previous, undefined)).toBe(previous);
  });
});

describe("UsageCapture over a live stream", () => {
  test("scrapes the trailing usage frame and publishes it after the stream", async () => {
    const capture = usageCaptureStream({ kind: "openai_compatible" });
    let resolved = false;
    void capture.usage.then(() => {
      resolved = true;
    });

    const stream = streamOf(chunkBytes(bytes(OPENAI_TEXT_STREAM), 9))
      .pipeThrough(sseParseStream())
      .pipeThrough(capture.stream);
    const reader = stream.getReader();
    // First frame delivered: metering must NOT have fired yet.
    await reader.read();
    expect(resolved).toBe(false);
    for (;;) {
      const { done } = await reader.read();
      if (done) {
        break;
      }
    }

    await expect(capture.usage).resolves.toEqual({
      promptTokens: 5,
      completionTokens: 2,
      totalTokens: 7,
    });
    expect(capture.capture.isComplete).toBe(true);
  });

  test("frames pass through byte-for-byte while being scraped", async () => {
    const capture = usageCaptureStream({ kind: "openai_compatible" });
    const out = await drainText(
      streamOf(chunkBytes(bytes(OPENAI_TEXT_STREAM), 4))
        .pipeThrough(sseParseStream())
        .pipeThrough(capture.stream)
        .pipeThrough(sseSerializeStream()),
    );
    expect(out).toBe(OPENAI_TEXT_STREAM);
    await expect(capture.usage).resolves.toEqual({
      promptTokens: 5,
      completionTokens: 2,
      totalTokens: 7,
    });
  });

  test("the onUsage callback fires exactly once, at completion", async () => {
    const seen: unknown[] = [];
    const capture = usageCaptureStream({
      kind: "anthropic",
      onUsage: (usage) => seen.push(usage),
    });
    const frames = await drainFrames(
      streamOf([
        'event: message_start\ndata: {"message":{"usage":{"input_tokens":11,"output_tokens":0}}}\n\n',
        'event: message_delta\ndata: {"usage":{"output_tokens":17}}\n\n',
        "event: message_stop\ndata: {}\n\n",
      ])
        .pipeThrough(sseParseStream())
        .pipeThrough(capture.stream),
    );
    expect(frames).toHaveLength(3);
    expect(seen).toEqual([
      { promptTokens: 11, completionTokens: 17, totalTokens: 28 },
    ]);
  });

  test("a stream that never reports usage resolves to undefined", async () => {
    const capture = usageCaptureStream();
    await drainFrames(
      streamOf(['data: {"choices":[{"delta":{"content":"x"}}]}\n\n'])
        .pipeThrough(sseParseStream())
        .pipeThrough(capture.stream),
    );
    await expect(capture.usage).resolves.toBeUndefined();
  });

  test("the [DONE] sentinel is not mistaken for a payload", () => {
    const capture = new UsageCapture();
    capture.observe({ data: "[DONE]", comments: [], raw: "" });
    expect(capture.complete()).toBeUndefined();
  });

  test("complete() is idempotent", () => {
    const capture = new UsageCapture();
    capture.observePayload({ usage: { prompt_tokens: 1 } });
    expect(capture.complete()).toEqual(capture.complete());
  });
});

describe("extractLastStreamUsage (buffered scrape)", () => {
  test("merges across frames like the Rust fold", () => {
    expect(extractLastStreamUsage(OPENAI_TEXT_STREAM)).toEqual({
      promptTokens: 5,
      completionTokens: 2,
      totalTokens: 7,
    });
  });

  test("an Anthropic stream's split input/output counts are recombined", () => {
    const body =
      'event: message_start\ndata: {"message":{"usage":{"input_tokens":11,"output_tokens":0}}}\n\n' +
      'event: content_block_delta\ndata: {"delta":{"text":"x"}}\n\n' +
      'event: message_delta\ndata: {"usage":{"output_tokens":17}}\n\n' +
      "event: message_stop\ndata: {}\n\n";
    expect(extractLastStreamUsage(body, "anthropic")).toEqual({
      promptTokens: 11,
      completionTokens: 17,
      totalTokens: 28,
    });
  });

  test("usageToOpenAiJson renders nulls for unreported counters", () => {
    expect(usageToOpenAiJson({ promptTokens: 4 })).toEqual({
      prompt_tokens: 4,
      completion_tokens: null,
      total_tokens: null,
    });
  });
});

describe("StreamingBodyCapture (bounded prefix+tail window)", () => {
  test("a body under the cap is retained verbatim", () => {
    const capture = new StreamingBodyCapture();
    capture.append(bytes("data: a\n\n"));
    capture.append(bytes("data: b\n\n"));
    expect(new TextDecoder().decode(capture.body())).toBe(
      "data: a\n\ndata: b\n\n",
    );
    expect(capture.truncated).toBe(false);
  });

  test("an oversized body keeps the head, a separator, and the tail", () => {
    const capture = new StreamingBodyCapture();
    capture.append(bytes("HEAD-MARKER\n\n"));
    capture.append(new Uint8Array(STREAMING_CAPTURE_MAX_BYTES * 2).fill(0x2e));
    capture.append(bytes('\n\ndata: {"usage":{"prompt_tokens":9}}\n\n'));

    const body = new TextDecoder().decode(capture.body());
    expect(capture.truncated).toBe(true);
    expect(body.startsWith("HEAD-MARKER")).toBe(true);
    expect(body.endsWith('data: {"usage":{"prompt_tokens":9}}\n\n')).toBe(true);
    expect(capture.body().length).toBeLessThanOrEqual(
      STREAMING_CAPTURE_MAX_BYTES,
    );
    // The usage frame at the tail is still scrapeable after truncation.
    expect(extractLastStreamUsage(capture.body())?.promptTokens).toBe(9);
  });

  test("the prefix window never exceeds its cap", () => {
    const capture = new StreamingBodyCapture();
    capture.append(new Uint8Array(STREAMING_CAPTURE_PREFIX_MAX_BYTES * 3).fill(0x61));
    capture.append(new Uint8Array(STREAMING_CAPTURE_MAX_BYTES).fill(0x62));
    expect(capture.body().length).toBeLessThanOrEqual(
      STREAMING_CAPTURE_MAX_BYTES,
    );
  });

  test("bodyCaptureStream taps bytes without altering them", async () => {
    const tap = bodyCaptureStream();
    const out = await drainText(
      streamOf(chunkBytes(bytes(OPENAI_TEXT_STREAM), 6)).pipeThrough(tap.stream),
    );
    expect(out).toBe(OPENAI_TEXT_STREAM);
    const captured = await tap.completed;
    expect(new TextDecoder().decode(captured)).toBe(OPENAI_TEXT_STREAM);
    expect(tap.capture.totalBytes).toBe(bytes(OPENAI_TEXT_STREAM).length);
  });
});
