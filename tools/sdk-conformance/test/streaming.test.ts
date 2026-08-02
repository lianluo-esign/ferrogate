/**
 * Streaming — the leg the issue calls "the most likely place to diverge", and
 * it is, because a stream is the one response an SDK cannot re-read. A buffered
 * body that is subtly wrong produces a wrong field; a stream that is subtly
 * wrong produces a hang, a truncated message, or a parser exception halfway
 * through a token.
 *
 * Everything below is decoded by the SDK's OWN SSE reader
 * (`openai/core/streaming`), not by a hand-rolled `split("\n\n")` in a test —
 * that is the whole difference between proving the wire and proving the client.
 *
 * Both entry points are covered because they fail differently:
 *  - `create({stream:true})` — the raw async iterator most application code uses;
 *  - `.stream()` — the `ChatCompletionStream` helper, which ACCUMULATES chunks
 *    into a final `ChatCompletion` and therefore rejects a stream whose chunk
 *    shape is wrong even when iteration would have survived it.
 */
import { describe, expect, it } from "vitest";
import {
  DONE_FRAME,
  dataFrame,
  interceptUpstream,
  openaiClient,
  upstreamSse,
} from "./harness.js";

const CHUNK_BASE = {
  id: "chatcmpl-stream",
  object: "chat.completion.chunk",
  created: 1_700_000_000,
  model: "gpt-4o-mini-2024-07-18",
};

/** A provider stream: role, three content deltas, a finish, then usage. */
const TEXT_STREAM = [
  dataFrame({ ...CHUNK_BASE, choices: [{ index: 0, delta: { role: "assistant" } }] }),
  dataFrame({ ...CHUNK_BASE, choices: [{ index: 0, delta: { content: "Ferro" } }] }),
  dataFrame({ ...CHUNK_BASE, choices: [{ index: 0, delta: { content: "Gate" } }] }),
  dataFrame({ ...CHUNK_BASE, choices: [{ index: 0, delta: { content: " streams" } }] }),
  dataFrame({ ...CHUNK_BASE, choices: [{ index: 0, delta: {}, finish_reason: "stop" }] }),
  dataFrame({
    ...CHUNK_BASE,
    choices: [],
    usage: { prompt_tokens: 9, completion_tokens: 3, total_tokens: 12 },
  }),
  DONE_FRAME,
];

describe("openai SDK — streaming chat completions", () => {
  it("iterates chunks the SDK decoded from the gateway's SSE", async () => {
    const upstream = interceptUpstream(() => upstreamSse(TEXT_STREAM));
    try {
      const stream = await openaiClient().chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "stream please" }],
        stream: true,
      });

      const text: string[] = [];
      let finish: string | null | undefined;
      for await (const chunk of stream) {
        const delta = chunk.choices[0]?.delta.content;
        if (delta != null) text.push(delta);
        if (chunk.choices[0]?.finish_reason != null) finish = chunk.choices[0].finish_reason;
      }

      expect(text.join("")).toBe("FerroGate streams");
      expect(finish).toBe("stop");
      // The gateway asked the upstream to stream too — not "buffer, then fake
      // a stream", which would pass an iteration test while destroying latency.
      expect((upstream.last().body as { stream: boolean }).stream).toBe(true);
    } finally {
      upstream.restore();
    }
  });

  it("terminates on `[DONE]` instead of hanging", async () => {
    const upstream = interceptUpstream(() => upstreamSse(TEXT_STREAM));
    try {
      const stream = await openaiClient().chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi" }],
        stream: true,
      });

      // Draining to completion IS the assertion: the SDK stops only when it
      // reads `data: [DONE]`. A gateway that swallowed the sentinel would leave
      // this `for await` waiting until the vitest timeout.
      let chunks = 0;
      for await (const _chunk of stream) chunks += 1;
      expect(chunks).toBe(TEXT_STREAM.length - 1); // every frame but `[DONE]`
    } finally {
      upstream.restore();
    }
  });

  it("accumulates into a final ChatCompletion through the .stream() helper", async () => {
    const upstream = interceptUpstream(() => upstreamSse(TEXT_STREAM));
    try {
      const runner = openaiClient().chat.completions.stream({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi" }],
      });

      const completion = await runner.finalChatCompletion();
      expect(completion.choices[0]?.message.content).toBe("FerroGate streams");
      expect(completion.choices[0]?.finish_reason).toBe("stop");
      expect(completion.id).toBe("chatcmpl-stream");
    } finally {
      upstream.restore();
    }
  });

  it("surfaces the usage frame when the caller asks for it", async () => {
    const upstream = interceptUpstream(() => upstreamSse(TEXT_STREAM));
    try {
      const stream = await openaiClient().chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi" }],
        stream: true,
        stream_options: { include_usage: true },
      });

      let usage: { total_tokens: number } | null | undefined;
      for await (const chunk of stream) {
        if (chunk.usage != null) usage = chunk.usage;
      }

      expect(usage?.total_tokens).toBe(12);
      // `stream_options` is a caller parameter FerroGate does not own; it must
      // reach the provider untouched or the client's usage accounting silently
      // stops working behind the gateway.
      expect((upstream.last().body as { stream_options?: unknown }).stream_options).toEqual({
        include_usage: true,
      });
    } finally {
      upstream.restore();
    }
  });

  it("delivers incrementally rather than after the upstream completes", async () => {
    // The provider stalls after the first content delta until the SDK has
    // already yielded it. If the gateway buffered the whole stream this would
    // deadlock — and it is the failure a "collect everything then compare"
    // test can never see.
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });

    const upstream = interceptUpstream(
      () =>
        new Response(
          new ReadableStream<Uint8Array>({
            async start(controller) {
              const encoder = new TextEncoder();
              controller.enqueue(encoder.encode(TEXT_STREAM[0] as string));
              controller.enqueue(encoder.encode(TEXT_STREAM[1] as string));
              await gate;
              for (const frame of TEXT_STREAM.slice(2)) controller.enqueue(encoder.encode(frame));
              controller.close();
            },
          }),
          { headers: { "content-type": "text/event-stream" } },
        ),
    );

    try {
      const stream = await openaiClient().chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi" }],
        stream: true,
      });

      const iterator = stream[Symbol.asyncIterator]();
      // Two reads that must resolve BEFORE the upstream is released.
      await iterator.next();
      const second = await iterator.next();
      expect(second.value?.choices[0]?.delta.content).toBe("Ferro");

      release?.();
      // Same iterator, not a second `for await`: the SDK's `Stream` is
      // single-consumption and would throw "Cannot iterate over a consumed
      // stream" — which is itself part of the contract this suite honours.
      const rest: string[] = [];
      for (let next = await iterator.next(); next.done !== true; next = await iterator.next()) {
        const delta = next.value?.choices[0]?.delta.content;
        if (delta != null) rest.push(delta);
      }
      expect(rest.join("")).toBe("Gate streams");
    } finally {
      release?.();
      upstream.restore();
    }
  });
});
