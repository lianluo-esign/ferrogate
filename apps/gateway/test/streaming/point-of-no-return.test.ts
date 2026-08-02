/**
 * The POINT OF NO RETURN on a streamed response.
 *
 * Once the first byte of a streamed answer has been flushed to the client the
 * gateway can no longer retry, fail over, or change its mind: HTTP gives it no
 * way to un-send a byte or to revise a status line that is already on the wire.
 * Everything that can still be decided must therefore be decided BEFORE the
 * body starts moving, and everything after it must be honest about failure
 * rather than tidy about it.
 *
 * Three separate properties make that safe, and each is pinned below because
 * each can be broken independently while the other two keep passing:
 *
 *  1. **Retry/failover happens on headers only.** `dispatchWithFailover`
 *     returns a `Response` and only THEN does `handlers.ts::streamResponse`
 *     build the client body, so no attempt is ever abandoned after it has
 *     emitted bytes. Pinned in `test/inference/reliability.test.ts`; the
 *     structural half is restated here as the reason the rest matters.
 *  2. **A clean early EOF still terminates the dialect.** An upstream that
 *     closes without `[DONE]` and without a `finish_reason` gets the terminal
 *     frames synthesized, because the Rust tree does exactly that:
 *     `messages_stream.rs:653` sets `eof` on `read() == 0` and line 636 then
 *     calls `finish_stream()`. Reproduced, and already pinned by
 *     `anthropic.test.ts` "a stream that ends without [DONE] still gets its
 *     terminal frames".
 *  3. **A TRANSPORT failure is NOT laundered into a clean ending.** This is the
 *     one that had no test, and it is the dangerous one. Rust's
 *     `MessagesStreamNormalizer::read` returns `IoError::other("reading
 *     provider streaming response: …")` (`messages_stream.rs:646`) — it does
 *     NOT set `eof`, so `finish_stream()` never runs and the client's body
 *     breaks. The TS port inherits that from `TransformStream` semantics: a
 *     `flush()` is only invoked on normal close, never on an errored writable.
 *
 * Property 3 is worth a test of its own because the two failure modes are
 * ONE LINE apart and produce byte streams that differ only in their tail. A
 * well-meant `try { … } catch { controller.enqueue(...normalizer.finish()) }`
 * around either transform — the "make the stream robust" change any reader
 * might reach for — turns a provider that died mid-sentence into a perfectly
 * well-formed `message_delta` + `message_stop` (or `response.completed` +
 * `[DONE]`). The client then believes it received the complete answer, the
 * usage tap reports the partial token counts as final, and the tenant is
 * billed for a truncated generation that reads as a successful one. Nothing in
 * the suite noticed, because every other streaming test drives a stream that
 * ends cleanly.
 */
import { describe, expect, test } from "vitest";

import { openAiToAnthropicStream } from "../../src/streaming/anthropic.js";
import { responsesNormalizeStream } from "../../src/streaming/responses.js";
import { passthroughStream } from "../../src/streaming/sse.js";
import { bytes, drainText, eventNames, streamOf } from "./helpers.js";

/** The transport failure workerd surfaces when a provider socket dies. */
const UPSTREAM_RESET = "upstream connection reset";

/**
 * A byte stream that delivers `chunks` and then ERRORS instead of closing.
 *
 * Deliberately not `controller.close()`: a closed stream is case 2 above and a
 * normalizer is supposed to terminate it. This is case 3.
 */
function erroringStreamOf(chunks: readonly string[]): ReadableStream<Uint8Array> {
  let index = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (index >= chunks.length) {
        controller.error(new Error(UPSTREAM_RESET));
        return;
      }
      controller.enqueue(bytes(chunks[index] as string));
      index += 1;
    },
  });
}

/** What the client actually received, and how the body ended. */
interface Delivered {
  /** Bytes that reached the client before the failure. */
  readonly text: string;
  /** The error the client's reader rejected with, or `undefined` if it closed. */
  readonly error: string | undefined;
}

/** Read a stream the way a real client does: incrementally, until it stops. */
async function deliver(stream: ReadableStream<Uint8Array>): Promise<Delivered> {
  const reader = stream.getReader();
  const decoder = new TextDecoder("utf-8");
  let text = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      text += decoder.decode(value, { stream: true });
    }
  } catch (error) {
    return { text: text + decoder.decode(), error: String(error) };
  }
  return { text: text + decoder.decode(), error: undefined };
}

/** One OpenAI text delta — enough to force the normalizer to open a block. */
const FIRST_DELTA = 'data: {"choices":[{"delta":{"content":"Hel"}}]}\n\n';

describe("a transport failure after the first byte is not laundered into a clean ending", () => {
  test("the Anthropic normalizer surfaces the failure and forges no terminal frames", async () => {
    const delivered = await deliver(
      erroringStreamOf([FIRST_DELTA]).pipeThrough(
        openAiToAnthropicStream({ fallbackModel: "claude-logical" }),
      ),
    );

    // The client's body BREAKS. It must not look like a normal end of stream:
    // a client that cannot tell the two apart has no way to know its answer is
    // incomplete, which is the entire point of this file. Asserted as two
    // steps so that a stream which was silently truncated into a CLEAN close
    // reports itself as exactly that rather than as an argument-type error.
    expect(delivered.error, "upstream failure was silently swallowed").toBeDefined();
    expect(delivered.error).toContain(UPSTREAM_RESET);

    // Bytes really were flushed first — otherwise this test would be asserting
    // the absence of terminal frames on a stream that produced nothing at all,
    // which is trivially true and would hold even if the normalizer were gone.
    expect(delivered.text.length).toBeGreaterThan(0);
    expect(eventNames(delivered.text)).toContain("message_start");

    // ...and the terminal sequence `finish()` would have written is ABSENT.
    // These two are the assertions that fail the moment anyone "hardens" the
    // transform by catching the error and flushing.
    expect(eventNames(delivered.text)).not.toContain("message_delta");
    expect(eventNames(delivered.text)).not.toContain("message_stop");
  });

  test("the Responses normalizer surfaces the failure and forges no completion", async () => {
    const delivered = await deliver(
      erroringStreamOf([FIRST_DELTA]).pipeThrough(
        responsesNormalizeStream({
          providerKind: "openai_compatible",
          requestId: "fg-deadbeefdeadbeef",
        }),
      ),
    );

    expect(delivered.error, "upstream failure was silently swallowed").toBeDefined();
    expect(delivered.error).toContain(UPSTREAM_RESET);
    expect(delivered.text.length).toBeGreaterThan(0);

    // `response.completed` claims a finished generation and `[DONE]` claims a
    // finished STREAM; neither may be synthesized out of a dead socket.
    expect(eventNames(delivered.text)).not.toContain("response.completed");
    expect(delivered.text).not.toContain("[DONE]");

    // `response.failed` is equally wrong here, and for a subtler reason: it is
    // the in-band arm (`#emitError`), it is followed by `[DONE]`, and it
    // therefore ends the stream NORMALLY. Converting a transport failure into
    // it would hand the client a well-formed, cleanly-terminated body — the
    // same laundering as `response.completed`, just wearing an error label.
    expect(eventNames(delivered.text)).not.toContain("response.failed");
  });

  test("the passthrough (no dialect change) leg propagates the failure too", async () => {
    // A same-dialect stream has no normalizer, so nothing is in a position to
    // synthesize a tail — but the failure must still reach the client rather
    // than being swallowed into a silent, successful-looking short read.
    const delivered = await deliver(
      erroringStreamOf([FIRST_DELTA]).pipeThrough(passthroughStream()),
    );

    expect(delivered.error, "upstream failure was silently swallowed").toBeDefined();
    expect(delivered.error).toContain(UPSTREAM_RESET);
    expect(delivered.text).toContain('"content":"Hel"');
  });
});

describe("the two endings are distinguishable, and flushed bytes are never revised", () => {
  test("a CLEAN early close does get the terminal frames the failure does not", async () => {
    // The contrast that gives the assertions above their meaning. Same input
    // bytes; the only difference is `close()` vs `error()`. If this test and
    // the Anthropic test above ever agree, one of them has stopped testing
    // anything: `message_stop` would be either always present or always absent.
    const clean = await deliver(
      streamOf([FIRST_DELTA]).pipeThrough(
        openAiToAnthropicStream({ fallbackModel: "claude-logical" }),
      ),
    );

    expect(clean.error).toBeUndefined();
    expect(eventNames(clean.text)).toContain("message_stop");
    expect(eventNames(clean.text)).toContain("message_delta");
  });

  test("what was flushed before the failure is a byte-exact prefix of the clean stream", async () => {
    // The other half of "no return": the gateway may STOP, but it may never
    // rewrite or reorder what the client already holds. A buffering or
    // re-framing regression that changed the delivered prefix — say, holding
    // `message_start` back until the usage frame arrived — would break this
    // even though every whole-stream comparison test still passed.
    const failed = await deliver(
      erroringStreamOf([FIRST_DELTA]).pipeThrough(
        openAiToAnthropicStream({ fallbackModel: "claude-logical" }),
      ),
    );
    const clean = await drainText(
      streamOf([FIRST_DELTA]).pipeThrough(
        openAiToAnthropicStream({ fallbackModel: "claude-logical" }),
      ),
    );

    expect(failed.text.length).toBeGreaterThan(0);
    expect(clean.startsWith(failed.text)).toBe(true);
    // Strict prefix: the clean stream must carry MORE than the failed one, or
    // "is a prefix of" is satisfied by the two being equal and the assertion
    // says nothing about the failure having stopped early.
    expect(clean.length).toBeGreaterThan(failed.text.length);
  });
});
