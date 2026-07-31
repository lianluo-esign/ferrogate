/**
 * Streaming (`stream: true`) — a real SSE chat completion end to end.
 *
 * The provider returns a canned SSE stream chunk-by-chunk; the gateway relays
 * it while a `TransformStream` scrapes the final usage frame. The two invariants
 * under test are the two the Rust tree treated as load-bearing:
 *
 *  1. **byte-for-byte framing** (`ROUTE-MAP` "must preserve upstream SSE framing
 *     byte-for-byte"): the client sees exactly the provider's bytes.
 *  2. **usage is scraped from the LAST usage frame** (`chat.rs:1012`): failing
 *     this silently fell back to a 512-token estimate, which let a tenant stream
 *     unbounded real tokens billed as ~512.
 */
import { describe, expect, it } from "vitest";
import { harness } from "./fixtures.js";
import {
  OPENAI_CHAT_STREAM_FRAMES,
  interceptProviderFetch,
  providerSse,
  readBody,
  sseBytes,
} from "./provider-mock.js";

describe("POST /v1/chat/completions (stream: true)", () => {
  it("returns a correctly framed SSE response", async () => {
    const provider = interceptProviderFetch(() => providerSse(OPENAI_CHAT_STREAM_FRAMES));
    try {
      const h = harness();
      const res = await h.post("/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi" }],
        stream: true,
      });

      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toBe("text/event-stream");
      expect(res.headers.get("cache-control")).toBe("no-cache");

      const text = await readBody(res);
      // Byte-for-byte: every frame, every terminator, in order.
      expect(text).toBe(sseBytes(OPENAI_CHAT_STREAM_FRAMES));
      // And it really is SSE-shaped, not a JSON blob relabelled.
      expect(text.endsWith("data: [DONE]\n\n")).toBe(true);
      expect(text.split("\n\n").filter((frame) => frame.length > 0)).toHaveLength(
        OPENAI_CHAT_STREAM_FRAMES.length,
      );
    } finally {
      provider.restore();
    }
  });

  it("preserves CRLF framing and provider keep-alive comments verbatim", async () => {
    // "Byte-for-byte" has to mean the BYTES. A relay that decoded to text and
    // re-encoded would silently normalize `\r\n` to `\n` and drop `:`-comment
    // keep-alive lines, and an `\n`-only fixture would never notice.
    const raw =
      'data: {"choices":[{"delta":{"content":"a"}}]}\r\n\r\n' +
      ": keep-alive\r\n\r\n" +
      'data: {"choices":[],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}\r\n\r\n' +
      "data: [DONE]\r\n\r\n";
    const provider = interceptProviderFetch(
      () =>
        new Response(new TextEncoder().encode(raw), {
          headers: { "content-type": "text/event-stream" },
        }),
    );

    try {
      const h = harness();
      const res = await h.post("/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [],
        stream: true,
      });
      const text = await readBody(res);

      expect(text).toBe(raw);
      expect(text).toContain("\r\n");
      expect(text).toContain(": keep-alive");
      // …and the CRLF grammar is still parsed for metering.
      expect(h.usage.last).toMatchObject({ promptTokens: 2, completionTokens: 1, totalTokens: 3 });
    } finally {
      provider.restore();
    }
  });

  it("streams incrementally rather than buffering the whole body", async () => {
    // The provider stalls after the first frame until the test releases it. If
    // the gateway buffered, the first read below would never resolve.
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const encoder = new TextEncoder();
    const provider = interceptProviderFetch(
      () =>
        new Response(
          new ReadableStream<Uint8Array>({
            async start(controller) {
              controller.enqueue(encoder.encode(`${OPENAI_CHAT_STREAM_FRAMES[0]}\n\n`));
              await gate;
              controller.enqueue(encoder.encode("data: [DONE]\n\n"));
              controller.close();
            },
          }),
          { headers: { "content-type": "text/event-stream" } },
        ),
    );

    try {
      const h = harness();
      const res = await h.post("/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi" }],
        stream: true,
      });

      const reader = (res.body as ReadableStream<Uint8Array>).getReader();
      const first = await reader.read();
      expect(new TextDecoder().decode(first.value)).toBe(`${OPENAI_CHAT_STREAM_FRAMES[0]}\n\n`);

      release();
      const second = await reader.read();
      expect(new TextDecoder().decode(second.value)).toBe("data: [DONE]\n\n");
      await reader.read();
    } finally {
      release();
      provider.restore();
    }
  });

  it("records the usage carried by the final SSE frame", async () => {
    const provider = interceptProviderFetch(() => providerSse(OPENAI_CHAT_STREAM_FRAMES));
    try {
      const h = harness();
      const res = await h.post("/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi" }],
        stream: true,
      });
      await readBody(res);

      expect(h.usage.records).toHaveLength(1);
      expect(h.usage.last).toMatchObject({
        route: "openai.chat.completions",
        stream: true,
        promptTokens: 11,
        completionTokens: 4,
        totalTokens: 15,
      });
    } finally {
      provider.restore();
    }
  });

  it("does not meter until the stream has actually been consumed", async () => {
    const provider = interceptProviderFetch(() => providerSse(OPENAI_CHAT_STREAM_FRAMES));
    try {
      const h = harness();
      const res = await h.post("/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi" }],
        stream: true,
      });

      // The response headers are out, but no token has crossed the wire yet.
      expect(h.usage.records).toHaveLength(0);
      await readBody(res);
      expect(h.usage.records).toHaveLength(1);
    } finally {
      provider.restore();
    }
  });

  it("asks the provider for stream usage so the final frame exists at all", async () => {
    const provider = interceptProviderFetch(() => providerSse(OPENAI_CHAT_STREAM_FRAMES));
    try {
      const h = harness();
      const res = await h.post("/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi" }],
        stream: true,
      });
      await readBody(res);

      const body = provider.lastRequest().body as Record<string, unknown>;
      expect(body["stream"]).toBe(true);
      // Without `include_usage` OpenAI omits the terminal usage frame entirely
      // and metering falls back to an estimate.
      expect(body["stream_options"]).toEqual({ include_usage: true });
    } finally {
      provider.restore();
    }
  });

  it("overwrites a caller-supplied non-object stream_options", async () => {
    const provider = interceptProviderFetch(() => providerSse(OPENAI_CHAT_STREAM_FRAMES));
    try {
      const h = harness();
      const res = await h.post("/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [],
        stream: true,
        stream_options: "not-an-object",
      });
      await readBody(res);

      expect((provider.lastRequest().body as Record<string, unknown>)["stream_options"]).toEqual({
        include_usage: true,
      });
    } finally {
      provider.restore();
    }
  });

  it("survives a usage frame split across chunk boundaries", async () => {
    // The scraper decodes with a streaming TextDecoder and buffers partial
    // lines, so a frame torn mid-JSON (or mid-UTF-8) must still be read.
    const whole = sseBytes(OPENAI_CHAT_STREAM_FRAMES);
    const encoder = new TextEncoder();
    const bytes = encoder.encode(whole);
    const provider = interceptProviderFetch(
      () =>
        new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              // 7-byte chunks: every frame is torn in several places.
              for (let offset = 0; offset < bytes.length; offset += 7) {
                controller.enqueue(bytes.slice(offset, offset + 7));
              }
              controller.close();
            },
          }),
          { headers: { "content-type": "text/event-stream" } },
        ),
    );

    try {
      const h = harness();
      const res = await h.post("/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [],
        stream: true,
      });
      const text = await readBody(res);

      expect(text).toBe(whole);
      expect(h.usage.last).toMatchObject({ promptTokens: 11, completionTokens: 4, totalTokens: 15 });
    } finally {
      provider.restore();
    }
  });

  it("meters a stream that reports usage across two frames", async () => {
    // `merge_usage` semantics: prompt on one frame, completion on another, and
    // the total derived from the merge — the Anthropic `message_start` /
    // `message_delta` split relies on exactly this.
    const provider = interceptProviderFetch(() =>
      providerSse([
        'data: {"choices":[],"usage":{"prompt_tokens":100}}',
        'data: {"choices":[],"usage":{"completion_tokens":25}}',
        "data: [DONE]",
      ]),
    );
    try {
      const h = harness();
      const res = await h.post("/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [],
        stream: true,
      });
      await readBody(res);

      expect(h.usage.last).toMatchObject({
        promptTokens: 100,
        completionTokens: 25,
        totalTokens: 125,
      });
    } finally {
      provider.restore();
    }
  });

  it("falls back to the buffered path when the provider ignores stream:true", async () => {
    const provider = interceptProviderFetch(
      () =>
        new Response(JSON.stringify({ id: "chatcmpl-x", choices: [], usage: { total_tokens: 9 } }), {
          headers: { "content-type": "application/json" },
        }),
    );
    try {
      const h = harness();
      const res = await h.post("/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [],
        stream: true,
      });

      expect(res.headers.get("content-type")).toBe("application/json");
      expect(h.usage.last).toMatchObject({ stream: true, totalTokens: 9 });
    } finally {
      provider.restore();
    }
  });

});

describe("cross-dialect stream normalization", () => {
  it("translates an OpenAI upstream stream into Anthropic events for /v1/messages", async () => {
    // `gpt-4o-mini` resolves to an OpenAI route, so `MessagesStreamNormalizer`
    // has to rewrite the dialect the Claude-native client was promised.
    const provider = interceptProviderFetch(() => providerSse(OPENAI_CHAT_STREAM_FRAMES));
    try {
      const h = harness();
      const res = await h.post("/v1/messages", {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi" }],
        stream: true,
      });
      const text = await readBody(res);

      expect(res.headers.get("content-type")).toBe("text/event-stream");
      // The Anthropic event grammar, in order.
      expect(text).toContain("event: message_start");
      expect(text).toContain("event: content_block_start");
      expect(text).toContain("event: content_block_delta");
      expect(text).toContain("event: content_block_stop");
      expect(text).toContain("event: message_delta");
      expect(text).toContain("event: message_stop");
      expect(text.indexOf("event: message_start")).toBeLessThan(
        text.indexOf("event: content_block_delta"),
      );
      expect(text.indexOf("event: content_block_delta")).toBeLessThan(
        text.indexOf("event: message_stop"),
      );
      // The OpenAI dialect must be gone: no chat.completion.chunk, no [DONE].
      expect(text).not.toContain("chat.completion.chunk");
      // The assistant text survived the translation.
      expect(text).toContain("Hel");
      expect(text).toContain("lo");
    } finally {
      provider.restore();
    }
  });

  it("meters a normalized /v1/messages stream from the Anthropic frames", async () => {
    const provider = interceptProviderFetch(() => providerSse(OPENAI_CHAT_STREAM_FRAMES));
    try {
      const h = harness();
      const res = await h.post("/v1/messages", {
        model: "gpt-4o-mini",
        messages: [],
        stream: true,
      });
      await readBody(res);

      // The tap runs AFTER the normalizer, so it must read the OpenAI usage that
      // the normalizer re-expressed as Anthropic `input_tokens`/`output_tokens`.
      // Reading it with the ORIGIN provider's extractor would find nothing and
      // silently fall back to an estimate (`chat.rs:1012`).
      expect(h.usage.last).toMatchObject({
        route: "anthropic.messages",
        stream: true,
        promptTokens: 11,
        completionTokens: 4,
      });
    } finally {
      provider.restore();
    }
  });

  it("normalizes /v1/responses into the response.* event sequence", async () => {
    const provider = interceptProviderFetch(() => providerSse(OPENAI_CHAT_STREAM_FRAMES));
    try {
      const h = harness();
      const res = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "hi",
        stream: true,
      });
      const text = await readBody(res);

      expect(res.headers.get("content-type")).toBe("text/event-stream");
      // Rust normalizes the Responses stream UNCONDITIONALLY — the branch is
      // `if endpoint == AiEndpoint::Responses`, not "if the upstream differs".
      expect(text).toContain("response.");
      expect(text).toContain("response.completed");
      expect(text).not.toContain("chat.completion.chunk");
    } finally {
      provider.restore();
    }
  });
});
