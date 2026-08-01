/**
 * SSE streaming normalization tower for `apps/gateway`.
 *
 * Clean-room port of the Rust gateway's async-pump -> synchronous-`Read`
 * transform tower (`messages_stream.rs`, `responses_stream.rs`, and the usage
 * capture in `server/chat.rs`) onto Cloudflare Workers `TransformStream`s. See
 * `docs/legacy/inventory-request-path.md` §1.5.
 *
 * Typical wiring for a streaming `/v1/messages` request served by an
 * OpenAI-compatible upstream:
 *
 * ```ts
 * const upstream = await dispatchStreamingUpstream({ url, init, clientSignal: c.req.raw.signal });
 * const usage = usageCaptureStream({ kind: "openai_compatible" });
 * const body = upstream.body!
 *   .pipeThrough(sseParseStream())          // bytes  -> frames (UTF-8 safe)
 *   .pipeThrough(usage.stream)              // scrape the trailing usage frame
 *   .pipeThrough(openAiToAnthropicFrameStream({ fallbackModel }))
 *   .pipeThrough(sseSerializeStream({ preferRaw: false }));
 * c.executionCtx.waitUntil(usage.usage.then(meter));   // meter AFTER the stream
 * return new Response(body, { headers: { "content-type": "text/event-stream" } });
 * ```
 *
 * For a pure proxy (no dialect change) use {@link passthroughStream} so the
 * upstream framing reaches the client byte for byte.
 *
 * ## THE POINT OF NO RETURN
 *
 * The first byte enqueued onto the response body is irrevocable. HTTP offers no
 * way to un-send it or to revise a status line already on the wire, so:
 *
 *  - **every decision that can change the answer must be made before it.**
 *    Retry, failover and the circuit breaker all run in
 *    `inference/reliability.ts::dispatchWithFailover`, which decides on the
 *    upstream *headers* and returns a `Response`;
 *    `inference/handlers.ts::streamResponse` only then builds the client body.
 *    There is deliberately no retry anywhere downstream of this module — a
 *    second attempt after a partial answer would concatenate two generations.
 *  - **after it, a failure must stay a failure.** The two ways a stream can end
 *    are NOT interchangeable:
 *      · a CLEAN close (upstream finished, or closed early without `[DONE]`)
 *        runs the transform's `flush()`, which synthesizes the dialect's
 *        terminal frames. That reproduces Rust `messages_stream.rs:636`, where
 *        `read() == 0` sets `eof` and calls `finish_stream()`;
 *      · a TRANSPORT failure errors the stream. `flush()` is then never invoked
 *        — WHATWG only runs it on normal close — so no terminal frame is
 *        forged and the client's body breaks. That reproduces Rust
 *        `messages_stream.rs:646`, which returns `IoError::other(...)` WITHOUT
 *        setting `eof`.
 *
 * Do NOT "harden" these transforms by catching an upstream error and closing
 * normally, with or without terminal frames. Doing so converts a provider that
 * died mid-sentence into a well-formed, apparently complete answer: the client
 * cannot tell it was truncated, and the usage tap reports the partial token
 * counts as final, so the tenant is billed for a successful-looking fragment.
 * `test/streaming/point-of-no-return.test.ts` fails if anyone does.
 */

export * from "./sse.js";
export * from "./values.js";
export * from "./ports.js";
export * from "./toolcalls.js";
export * from "./usage.js";
export * from "./openai.js";
export * from "./anthropic.js";
export * from "./responses.js";
export * from "./abort.js";
