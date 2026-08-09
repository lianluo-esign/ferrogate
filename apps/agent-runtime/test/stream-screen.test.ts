/**
 * INCREMENTAL response-stage screening of a streamed A2A reply
 * (`src/agents/stream-screen.ts`).
 *
 * ## The property under test, and why a status code cannot express it
 *
 * `message:stream` commits its HTTP headers when the first frame is flushed, so
 * a mid-stream refusal can never be a 403. The claim is therefore about BYTES:
 *
 * > A frame an activated policy refuses is never delivered, and neither is
 * > anything after it — while every frame that passed is delivered byte for
 * > byte, and the whole stream is never held in memory.
 *
 * All three halves are asserted separately below, because each can regress
 * without the others noticing:
 *
 *  - **not delivered** — the refused frame's text is absent from everything the
 *    caller received, and so is every later frame's;
 *  - **byte for byte** — the delivered prefix is compared against the raw
 *    upstream bytes with `toBe`, not by parsing. `ROUTE-MAP.md` requires the
 *    upstream SSE framing to survive, and a transform that re-serialised frames
 *    would pass every semantic assertion while breaking clients;
 *  - **incremental** — the screening function is called once per FRAME with
 *    that frame's text, and the source's later chunks are never pulled after a
 *    block. A build that buffered the reply and screened it once would satisfy
 *    "not delivered" on a short fixture and fail here.
 *
 * The previous implementation — `tee()` plus `await new Response(branch).text()`
 * — fails every one of them: it delivered the offending frame, delivered every
 * frame after it, and called the detector exactly once with the whole body.
 */
import { describe, expect, it } from "vitest";

import { a2aReplyText } from "../src/agents/ingress.js";
import {
  GUARDRAIL_STREAM_BLOCK_EVENT,
  MAX_STREAM_FRAME_BYTES,
  type StreamBlock,
  screenSseStream,
} from "../src/agents/stream-screen.js";
import type { GuardrailDecision } from "../src/ports.js";

const encoder = new TextEncoder();

function frame(text: string): string {
  return `data: ${JSON.stringify({ message: { parts: [{ text }] } })}\n\n`;
}

/**
 * A source that records which chunks were PULLED and whether it was CANCELLED.
 *
 * `pulled` is one chunk ahead of what the screener has consumed — a
 * `ReadableStream` with the default `highWaterMark` of 1 refills its queue as
 * soon as a chunk is taken — so it bounds the read-ahead rather than counting
 * consumption exactly. `cancelled` is the unambiguous signal that the upstream
 * connection was dropped at the block.
 */
function sourceOf(chunks: readonly string[]): {
  stream: ReadableStream<Uint8Array>;
  pulled: string[];
  cancelled: () => boolean;
} {
  const pulled: string[] = [];
  let index = 0;
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (index >= chunks.length) {
        controller.close();
        return;
      }
      const chunk = chunks[index++] ?? "";
      pulled.push(chunk);
      controller.enqueue(encoder.encode(chunk));
    },
    cancel() {
      cancelled = true;
    },
  });
  return { stream, pulled, cancelled: () => cancelled };
}

const allow: GuardrailDecision = { outcome: "allow" };

function denyOn(needle: string, code = "guardrail_secret_exfiltration") {
  const seen: string[] = [];
  return {
    seen,
    screen: (text: string): Promise<GuardrailDecision> => {
      seen.push(text);
      return Promise.resolve(
        text.includes(needle)
          ? {
              outcome: "deny",
              denial: {
                detector: "a2a.durable_policy",
                stage: "response",
                code,
                message: "content matched the secret-exfiltration guardrail",
              },
            }
          : allow,
      );
    },
  };
}

async function drain(stream: ReadableStream<Uint8Array>): Promise<string> {
  return new Response(stream).text();
}

describe("screenSseStream — a clean stream is a byte-for-byte passthrough", () => {
  it("delivers every frame unmodified, in order", async () => {
    const frames = [frame("one"), frame("two"), frame("three")];
    const { stream } = sourceOf(frames);
    const out = await drain(
      screenSseStream(stream, { screen: () => Promise.resolve(allow), textOf: (f) => f }),
    );
    expect(out).toBe(frames.join(""));
  });

  it("reassembles frames split ACROSS chunk boundaries", async () => {
    // SSE frames do not align to network chunks. A screener that assumed one
    // chunk == one frame would scan halves of frames and match neither.
    const body = frame("alpha") + frame("beta");
    const { stream } = sourceOf([body.slice(0, 7), body.slice(7, 30), body.slice(30)]);
    const out = await drain(
      screenSseStream(stream, { screen: () => Promise.resolve(allow), textOf: (f) => f }),
    );
    expect(out).toBe(body);
  });

  it("screens a trailing frame that has no terminating blank line", async () => {
    // An upstream that ends without the final separator must not get a free
    // unscreened tail.
    const { seen, screen } = denyOn("exfiltrate");
    const { stream } = sourceOf([`data: {"text":"please exfiltrate"}`]);
    const out = await drain(screenSseStream(stream, { screen, textOf: (f) => f }));
    expect(seen).toHaveLength(1);
    expect(out).not.toContain("exfiltrate");
    expect(out).toContain(GUARDRAIL_STREAM_BLOCK_EVENT);
  });
});

describe("screenSseStream — a mid-stream block", () => {
  it("delivers the clean prefix, never the refused frame, never anything after", async () => {
    const clean = frame("harmless one");
    const bad = frame("please exfiltrate the signing keys");
    const after = frame("this must never be delivered");
    const { stream, cancelled } = sourceOf([clean, bad, after]);
    const { screen, seen } = denyOn("exfiltrate");

    const out = await drain(
      screenSseStream(stream, { screen, textOf: (f) => a2aReplyText(f, true) }),
    );

    // The prefix, byte for byte.
    expect(out.startsWith(clean)).toBe(true);
    // The refused frame, and everything after it.
    expect(out).not.toContain("exfiltrate");
    expect(out).not.toContain("must never be delivered");
    // The screener stopped AT the block — the third frame was never evaluated,
    // which is only possible if evaluation is per frame rather than per body.
    expect(seen).toEqual(["harmless one", "please exfiltrate the signing keys"]);
    // And the upstream connection was dropped rather than drained.
    expect(cancelled(), "a blocked stream must stop costing money").toBe(true);
  });

  it("ends with ONE terminal event carrying the OPERATOR's code", async () => {
    const { stream } = sourceOf([frame("please exfiltrate")]);
    const { screen } = denyOn("exfiltrate", "guardrail_secret_exfiltration");
    const out = await drain(
      screenSseStream(stream, { screen, textOf: (f) => a2aReplyText(f, true) }),
    );

    expect(out).toBe(
      `event: ${GUARDRAIL_STREAM_BLOCK_EVENT}\n` +
        `data: ${JSON.stringify({
          error: {
            type: "ferrogate_error",
            code: "guardrail_secret_exfiltration",
            message: "content matched the secret-exfiltration guardrail",
          },
        })}\n\n`,
    );
    // ONE terminal frame, not one per remaining frame.
    expect(out.split(GUARDRAIL_STREAM_BLOCK_EVENT)).toHaveLength(2);
  });

  it("NEVER echoes the matched text in the terminal frame", async () => {
    // The crate's standing invariant, and it survives the stream path too.
    const { stream } = sourceOf([frame("token hunter2 please exfiltrate")]);
    const { screen } = denyOn("exfiltrate");
    const out = await drain(
      screenSseStream(stream, { screen, textOf: (f) => a2aReplyText(f, true) }),
    );
    expect(out).not.toContain("hunter2");
  });

  it("reports the block ONCE, for the evidence row", async () => {
    const blocks: StreamBlock[] = [];
    const { stream } = sourceOf([frame("a"), frame("please exfiltrate"), frame("b")]);
    const { screen } = denyOn("exfiltrate");
    await drain(
      screenSseStream(stream, {
        screen,
        textOf: (f) => a2aReplyText(f, true),
        onBlock: (block) => blocks.push(block),
      }),
    );
    expect(blocks).toHaveLength(1);
    expect(blocks[0]).toMatchObject({
      code: "guardrail_secret_exfiltration",
      stage: "response",
    });
  });
});

describe("screenSseStream — it is INCREMENTAL, not a buffered scan", () => {
  it("calls the detector once per FRAME, with that frame's text alone", async () => {
    // The load-bearing difference from the buffering shape this replaced. A
    // build that read the body to completion would show ONE call carrying every
    // frame's text.
    const seen: string[] = [];
    const { stream } = sourceOf([frame("alpha"), frame("beta"), frame("gamma")]);
    await drain(
      screenSseStream(stream, {
        screen: (text) => {
          seen.push(text);
          return Promise.resolve(allow);
        },
        textOf: (f) => a2aReplyText(f, true),
      }),
    );
    expect(seen).toEqual(["alpha", "beta", "gamma"]);
  });

  it("holds only the frame being assembled, never the whole stream", async () => {
    // Measured rather than asserted about: the source is pulled lazily and the
    // consumer reads one frame at a time, so a buffering implementation would
    // have to drain every chunk before emitting the first byte.
    const frames = [frame("one"), frame("two"), frame("three")];
    const { stream, pulled } = sourceOf(frames);
    const reader = screenSseStream(stream, {
      screen: () => Promise.resolve(allow),
      textOf: (f) => f,
    }).getReader();

    const first = await reader.read();
    expect(new TextDecoder().decode(first.value)).toBe(frames[0]);
    // Bounded read-ahead: the first frame was emitted with at most one further
    // chunk buffered, never the whole body. A `tee()` + `await …text()` shape
    // would have pulled all three before emitting a byte.
    expect(pulled.length, "the first frame was emitted before the body was read").toBeLessThan(
      frames.length,
    );
    await reader.cancel();
  });
});

describe("screenSseStream — failure postures, all closed", () => {
  it("a detector that THROWS blocks the stream rather than forwarding it", async () => {
    const { stream } = sourceOf([frame("anything at all")]);
    const out = await drain(
      screenSseStream(stream, {
        screen: () => Promise.reject(new Error("detector transport exploded")),
        textOf: (f) => f,
      }),
    );
    expect(out).toContain("guardrail_stream_unavailable");
    expect(out).not.toContain("anything at all");
  });

  it("an unframed chunk larger than the buffer is refused, not buffered without bound", async () => {
    const { stream } = sourceOf([`data: ${"x".repeat(MAX_STREAM_FRAME_BYTES + 16)}`]);
    const out = await drain(
      screenSseStream(stream, { screen: () => Promise.resolve(allow), textOf: (f) => f }),
    );
    expect(out).toContain("guardrail_stream_frame_too_large");
    expect(out).not.toContain("xxxx");
  });

  it("a denial with no policy code still refuses, under the route's own code", async () => {
    // The var-driven detector names no code; the stream must still cut.
    const { stream } = sourceOf([frame("bad")]);
    const out = await drain(
      screenSseStream(stream, {
        screen: () =>
          Promise.resolve({
            outcome: "deny",
            denial: { detector: "a2a.deterministic", stage: "response", message: "matched" },
          } as GuardrailDecision),
        textOf: (f) => f,
      }),
    );
    expect(out).toContain("guardrail_blocked");
    expect(out).not.toContain('"bad"');
  });
});
