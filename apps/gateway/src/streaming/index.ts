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
