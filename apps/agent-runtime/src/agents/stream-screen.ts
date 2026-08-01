/**
 * INCREMENTAL response-stage screening for a streamed A2A reply.
 *
 * ## What this replaces, and why buffering was not acceptable
 *
 * The previous shape `tee()`d the upstream body, handed one branch to the
 * client untouched, and read the OTHER branch to completion
 * (`await new Response(branch).text()`) before evaluating it. Two consequences,
 * and the second is the one that matters:
 *
 *  1. the whole reply was held in memory, so a long stream's peak footprint was
 *     the length of the stream rather than the length of a frame;
 *  2. the evaluation finished AFTER the last byte had already been flushed to
 *     the caller, so a match could only be RECORDED. Content the operator's
 *     activated policy forbids left the Worker, in full, every time.
 *
 * That is a guardrail that observes rather than one that guards, and on the
 * response leg — the direction an exfiltration payload travels — it is the leg
 * that matters. `docs/rewrite/FLEET-CONSISTENCY.md` FC-3 is about an activated
 * policy reaching every door; a door that only takes notes is not reached.
 *
 * ## What this does instead
 *
 * The upstream body is consumed FRAME BY FRAME. Only the bytes of the frame
 * currently being assembled are held — the SSE event separator (a blank line)
 * is the boundary — and each complete frame is screened before ANY of its bytes
 * are handed on. A frame that passes is enqueued **byte for byte, unmodified**,
 * so `docs/rewrite/ROUTE-MAP.md`'s requirement that `message:stream` preserve
 * upstream SSE framing exactly still holds for everything the caller receives.
 *
 * ## WHAT A MID-STREAM BLOCK LOOKS LIKE TO THE CALLER
 *
 * This is the part a client author has to be able to rely on, so it is stated
 * precisely rather than left to be discovered:
 *
 *  - **The HTTP status is 200 and stays 200.** The response headers were
 *    committed when the first frame was flushed; HTTP cannot retract them. A
 *    caller that only checks `response.ok` will believe it received a complete
 *    reply, so the terminal frame below is the ONLY in-band signal and clients
 *    must handle it.
 *  - **Every frame the caller has already received is valid and final.** They
 *    passed screening. Nothing is rewritten retroactively.
 *  - **The offending frame is never delivered.** Not truncated, not redacted —
 *    not sent at all. Neither is anything after it.
 *  - **One terminal event is appended, then the stream closes cleanly:**
 *
 *    ```
 *    event: ferrogate.guardrail_blocked
 *    data: {"error":{"type":"ferrogate_error","code":"<policy code>","message":"<policy message>"}}
 *
 *    ```
 *
 *    The `code` is the OPERATOR's own `PolicyAction.code` — the same code the
 *    gateway and MCP refuse with for the same activation — so a client can
 *    branch on it identically wherever it met the policy. The `message` is the
 *    operator's message and never the matched text.
 *  - **The upstream connection is cancelled**, so a blocked stream stops
 *    costing money at the point of the block rather than at the point the
 *    upstream finishes.
 *
 * ## Failure postures, all closed
 *
 *  - the screening function THROWS: treated as a block with
 *    `guardrail_stream_unavailable`. A detector that could not run has cleared
 *    nothing, and the bytes it did not clear are not sent.
 *  - the upstream errors mid-stream: the error propagates to the caller; no
 *    unscreened bytes are emitted.
 *  - a single frame exceeds {@link MAX_STREAM_FRAME_BYTES} with no boundary in
 *    sight: the stream is blocked with `guardrail_stream_frame_too_large`
 *    rather than buffered without bound. Refusing is the only option that is
 *    neither "hold the whole stream in memory" nor "forward unscreened bytes".
 */
import type { GuardrailDecision, GuardrailStage } from "../ports.js";

/** The terminal SSE event name a blocked stream ends with. */
export const GUARDRAIL_STREAM_BLOCK_EVENT = "ferrogate.guardrail_blocked";

/**
 * The largest partially-assembled frame held before refusing.
 *
 * Generous relative to any real SSE frame and small relative to a whole stream,
 * which is the entire point: the bound is per FRAME, not per RESPONSE.
 */
export const MAX_STREAM_FRAME_BYTES = 1_048_576;

/** What a blocked stream carries to the caller, and to the run timeline. */
export interface StreamBlock {
  readonly code: string;
  readonly message: string;
  readonly stage: GuardrailStage;
}

export interface StreamScreenOptions {
  /** Screen one frame's extracted text. MUST NOT be given the whole stream. */
  readonly screen: (text: string) => Promise<GuardrailDecision>;
  /** Pull the scannable text out of one raw SSE frame. */
  readonly textOf: (frame: string) => string;
  /** Called once, when a frame is refused. Evidence; never blocks the cut. */
  readonly onBlock?: ((block: StreamBlock) => void) | undefined;
}

function terminalFrame(block: StreamBlock): Uint8Array {
  const body = JSON.stringify({
    error: { type: "ferrogate_error", code: block.code, message: block.message },
  });
  return new TextEncoder().encode(
    `event: ${GUARDRAIL_STREAM_BLOCK_EVENT}\ndata: ${body}\n\n`,
  );
}

function blockOf(decision: GuardrailDecision, stage: GuardrailStage): StreamBlock | undefined {
  if (decision.outcome === "allow") return undefined;
  return {
    code: decision.denial.code ?? "guardrail_blocked",
    message: decision.denial.message,
    stage,
  };
}

/**
 * Wrap a streamed upstream body in a screening transform.
 *
 * The returned stream emits the SAME BYTES the source emitted, one frame later,
 * up to the first frame a policy refuses.
 */
export function screenSseStream(
  source: ReadableStream<Uint8Array>,
  options: StreamScreenOptions,
): ReadableStream<Uint8Array> {
  const reader = source.getReader();
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  // Only ever the frame being assembled. Never the stream.
  let pending = "";
  let blocked = false;

  return new ReadableStream<Uint8Array>({
    async pull(controller): Promise<void> {
      if (blocked) {
        controller.close();
        return;
      }

      const cut = async (block: StreamBlock): Promise<void> => {
        blocked = true;
        options.onBlock?.(block);
        controller.enqueue(terminalFrame(block));
        controller.close();
        // Stop paying for bytes nobody will receive.
        await reader.cancel().catch(() => undefined);
      };

      /** Screen one raw frame; enqueue it verbatim, or cut. Returns `true` if cut. */
      const forward = async (frame: string): Promise<boolean> => {
        if (frame.length === 0) return false;
        let decision: GuardrailDecision;
        try {
          decision = await options.screen(options.textOf(frame));
        } catch (error) {
          await cut({
            code: "guardrail_stream_unavailable",
            message: `response-stage guardrail could not be evaluated: ${
              error instanceof Error ? error.message : "detector error"
            }`,
            stage: "response",
          });
          return true;
        }
        const block = blockOf(decision, "response");
        if (block !== undefined) {
          await cut(block);
          return true;
        }
        // Byte for byte, framing intact — the ROUTE-MAP requirement.
        controller.enqueue(encoder.encode(frame));
        return false;
      };

      for (;;) {
        // Emit every WHOLE frame already assembled, then RETURN rather than
        // reading further. Returning is what keeps this lazy: the source is
        // pulled only when the consumer has taken what is already screened, so
        // the upstream is never drained ahead of the client and a block stops
        // it at the offending frame instead of after the last one.
        let boundary = pending.indexOf("\n\n");
        let emitted = false;
        while (boundary !== -1) {
          const frame = pending.slice(0, boundary + 2);
          pending = pending.slice(boundary + 2);
          if (await forward(frame)) return;
          emitted = true;
          boundary = pending.indexOf("\n\n");
        }
        if (emitted) return;

        if (pending.length > MAX_STREAM_FRAME_BYTES) {
          await cut({
            code: "guardrail_stream_frame_too_large",
            message:
              "an unframed upstream chunk exceeded the response-stage screening buffer; " +
              "the stream was terminated rather than forwarded unscreened",
            stage: "response",
          });
          return;
        }

        const { done, value } = await reader.read();
        if (done) {
          // The trailing bytes are a frame too — an upstream that omits the
          // final blank line must not get a free unscreened tail.
          const tail = pending + decoder.decode();
          pending = "";
          if (tail.length > 0 && (await forward(tail))) return;
          controller.close();
          return;
        }
        pending += decoder.decode(value, { stream: true });
      }
    },
    async cancel(reason): Promise<void> {
      await reader.cancel(reason).catch(() => undefined);
    },
  });
}
