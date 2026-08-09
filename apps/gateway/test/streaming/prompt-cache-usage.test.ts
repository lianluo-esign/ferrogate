/**
 * The cache hit/miss split survives the OpenAI → Anthropic STREAM (issue #690).
 *
 * The buffered leg is pinned in `test/inference/prompt-caching.test.ts`. A
 * streamed `/v1/messages` request served by an OpenAI-family route is
 * re-serialized frame by frame instead, and its terminal `message_delta` is the
 * only place the caller ever sees a token count — so a split dropped here is a
 * split the caller cannot see at all, on exactly the requests (long cached
 * prefixes) where it matters most.
 */
import { describe, expect, test } from "vitest";

import { openAiToAnthropicStream } from "../../src/streaming/anthropic.js";
import { bytes, drainText, jsonEvents, streamOf } from "./helpers.js";

/** An OpenAI stream whose final usage frame reports a large cache hit. */
const CACHED_STREAM =
  'data: {"id":"chatcmpl-1","model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant","content":"covered"}}]}\n\n' +
  'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],' +
  '"usage":{"prompt_tokens":9012,"completion_tokens":3,"total_tokens":9015,' +
  '"prompt_tokens_details":{"cached_tokens":9000}}}\n\n' +
  "data: [DONE]\n\n";

const normalize = (source: string): Promise<string> =>
  drainText(
    streamOf([bytes(source)]).pipeThrough(
      openAiToAnthropicStream({ fallbackModel: "claude-logical" }),
    ),
  );

describe("streamed /v1/messages usage carries the cache split", () => {
  test("the terminal message_delta reports fresh and cached input separately", async () => {
    const sse = await normalize(CACHED_STREAM);
    const [delta] = jsonEvents(sse, "message_delta") as Array<{
      usage: Record<string, number>;
    }>;
    // OpenAI's `prompt_tokens` INCLUDES the cached tokens; Anthropic's
    // `input_tokens` excludes them. Emitting 9012 alongside a 9000 cache read
    // would make an Anthropic-native client bill ~18000 input tokens for a
    // 9012-token prompt.
    expect((delta as NonNullable<typeof delta>).usage).toEqual({
      input_tokens: 12,
      output_tokens: 3,
      cache_read_input_tokens: 9_000,
    });
  });

  test("a stream with no cached tokens reports exactly the two counters it always did", async () => {
    const sse = await normalize(
      'data: {"choices":[{"index":0,"delta":{"content":"hi"}}]}\n\n' +
        'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],' +
        '"usage":{"prompt_tokens":5,"completion_tokens":2}}\n\n' +
        "data: [DONE]\n\n",
    );
    const [delta] = jsonEvents(sse, "message_delta") as Array<{
      usage: Record<string, number>;
    }>;
    // An absent counter stays ABSENT rather than becoming a zero — the same
    // rule #667 applies on the metering side, and what keeps a pre-cache-era
    // provider response indistinguishable from what it was before.
    expect((delta as NonNullable<typeof delta>).usage).toEqual({
      input_tokens: 5,
      output_tokens: 2,
    });
  });
});
