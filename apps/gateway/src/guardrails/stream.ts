/**
 * INCREMENTAL output screening over an SSE `TransformStream`.
 *
 * ## Why this is not a transcription of the Rust
 *
 * The Rust had three streaming postures (`PolicyStreamingMode`), and its
 * enforcing one — `BufferAndEnforce`, the serde default — literally buffered the
 * ENTIRE provider stream before releasing a single byte
 * (`server/chat.rs:1101-1140`: `read_provider_streaming_body(...)` then
 * `match_guardrail(Response, ...)`). That is safe and simple, and it destroys
 * the streaming UX: time-to-first-token becomes time-to-LAST-token.
 *
 * This port keeps the POLICY vocabulary verbatim and changes only the
 * mechanism:
 *
 * | `PolicyStreamingMode`   | Rust                              | here |
 * |-------------------------|-----------------------------------|------|
 * | `reject_streaming`      | 403 before dispatch               | identical (`engine.ts`) |
 * | `buffer_and_enforce`    | buffer whole body, then evaluate  | **incremental**: evaluate each frame as it passes; a failing frame is never forwarded |
 * | `shadow_after_complete` | pass through, evaluate after      | identical (pass-through + one post-hoc evaluation) |
 *
 * The safety property that matters is preserved: **a frame that trips the
 * policy is never delivered.** What changes is the frames BEFORE it — they have
 * already reached the client, so the block arrives mid-stream instead of as a
 * 403. That is documented below and asserted by the suite.
 *
 * ## Catching a marker split across frames
 *
 * A token can straddle a frame boundary (`sk-pro` | `j-AAAA...`). Screening each
 * frame in isolation would miss it, so each evaluation runs over TWO segments:
 * a bounded `carry` (the trailing {@link ScreenSseOptions.overlapBytes} of the
 * already-forwarded text) and the new `delta`. Both carry `source: "assistant"`,
 * which makes the deterministic detector's **coalesced-group scan** — described
 * in `inventory-policy-core.md` §3.4(a) as existing precisely "so a token split
 * across adjacent parts is caught" — do the joining, and map the match offsets
 * back to per-segment sub-ranges for redaction. No detector logic is
 * re-implemented here.
 *
 * Memory is bounded by `overlapBytes + one frame`. The whole stream is never
 * held.
 *
 * ## What a mid-stream BLOCK looks like to the client
 *
 * Response status and headers are long gone (200 / `text/event-stream`), so the
 * block is delivered IN BAND, in the dialect the client was promised, and the
 * upstream is aborted:
 *
 * - `openai.chat` — one `data:` frame carrying the FerroGate error envelope
 *   (the exact body the buffered 403 would have had), then `data: [DONE]`:
 *   ```
 *   data: {"error":{"message":"…","type":"ferrogate_error","code":"guardrail_blocked","request_id":"fg-…"}}
 *
 *   data: [DONE]
 *   ```
 * - `openai.responses` — `event: response.failed` with the same error object,
 *   then `data: [DONE]`. Byte-shape ported from
 *   `crates/ferrogate-gateway/src/responses_stream.rs:260-275`.
 * - `anthropic.messages` — `event: error` with
 *   `{"type":"error","error":{"type":<code>,"message":<message>}}`. Byte-shape
 *   ported from `crates/ferrogate-gateway/src/messages_stream.rs:287-298`
 *   (`error_sse`), which is the framing `write_messages_error` already used for
 *   a guardrail denial on a streaming `/v1/messages` request.
 *
 * A mid-stream REDACT rewrites the offending frame's text delta in place using
 * the detector's own `ContentPatch`es and forwards the rewritten frame; the
 * stream continues.
 */
import {
  type ContentPatch,
  type ContentSegment,
  type GuardrailEnvelope,
  type GuardrailProtocol,
  byteLen,
  byteSlice,
  contentFingerprint,
} from "@ferrogate/guardrails";
import {
  type SseFrame,
  frameJson,
  isDoneFrame,
  jsonSseFrame,
  sseFrame,
  sseParseStream,
  sseSerializeStream,
} from "../streaming/sse.js";
import type { GuardrailEngine } from "./engine.js";
import { evidenceTarget } from "./engine.js";
import type { GuardrailEvaluationContext, GuardrailMatch } from "./ports.js";

/** Which SSE dialect the CLIENT was promised (mirrors `inference/ports.ts`). */
export type StreamDialect = "openai.chat" | "openai.responses" | "anthropic.messages";

/** How the screened stream ended. */
export type StreamScreenOutcome =
  | { readonly kind: "clean" }
  | { readonly kind: "blocked"; readonly match: GuardrailMatch; readonly frameIndex: number }
  | { readonly kind: "redacted"; readonly match: GuardrailMatch; readonly frameCount: number };

export interface ScreenSseOptions {
  readonly engine: GuardrailEngine;
  /**
   * The evaluation context. Its `envelope` is REPLACED per frame with the
   * carry+delta window; every other field (tenant, model, provider, streaming)
   * is used as given.
   */
  readonly context: GuardrailEvaluationContext;
  readonly dialect: StreamDialect;
  readonly protocol: GuardrailProtocol;
  readonly requestId: string;
  /** Trailing bytes of already-forwarded text replayed as the carry segment. */
  readonly overlapBytes?: number | undefined;
  /** Called once when the stream settles. */
  readonly onOutcome?: ((outcome: StreamScreenOutcome) => void) | undefined;
  /** Aborts the upstream fetch when a block fires. */
  readonly abort?: (() => void) | undefined;
}

const DEFAULT_OVERLAP_BYTES = 256;

/**
 * Wrap a provider SSE body in incremental response screening.
 *
 * Compose it AFTER any dialect normalizer, so the frames it sees are the ones
 * the client will actually receive.
 */
export function screenSseStream(
  options: ScreenSseOptions,
): TransformStream<Uint8Array, Uint8Array> {
  const parse = sseParseStream();
  const screen = screenSseFrames(options);
  return {
    writable: parse.writable,
    readable: parse.readable.pipeThrough(screen).pipeThrough(sseSerializeStream()),
  };
}

/**
 * Screen a provider response body. **This is the entry point callers should
 * use** — `screenSseStream` alone cannot stop the upstream on a block, because
 * a `TransformStream` has no handle on the source that feeds it.
 *
 * On a block the screener latches and drops every later frame, then calls back
 * here; this function aborts the pipe, which CANCELS the provider body (a
 * blocked stream must stop costing tokens) while `preventAbort`/`preventClose`
 * keep the abort from tearing down the transform before the terminal error
 * frames have drained. The writable is then closed explicitly, so the reader
 * always sees a clean end-of-stream rather than an error.
 */
export function screenSseBody(
  body: ReadableStream<Uint8Array>,
  options: ScreenSseOptions,
): ReadableStream<Uint8Array> {
  let blocked = false;
  const transform = screenSseStream({
    ...options,
    abort: () => {
      blocked = true;
      options.abort?.();
    },
  });

  // A manual read/write pump rather than `pipeTo`/`pipeThrough`. Both of those
  // hand ownership of the source to the stream machinery, and every way of
  // getting it back to stop early (`controller.terminate()`, an abort
  // `signal`) surfaces as an unhandled rejection in workerd that no `.catch()`
  // on the pipe promise absorbs. The pump keeps every await inside one
  // try/catch, so a block ends the stream with a clean close and a cancelled
  // provider body — no stray rejection, no leaked upstream.
  void (async () => {
    const reader = body.getReader();
    const writer = transform.writable.getWriter();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done || value === undefined) {
          break;
        }
        await writer.write(value);
        if (blocked) {
          break;
        }
      }
    } catch {
      /* provider stream failed; the close below still ends the client stream */
    } finally {
      void writer.close().catch(() => {
        /* already closed or errored */
      });
      try {
        reader.releaseLock();
        void body.cancel().catch(() => {
          /* already cancelled */
        });
      } catch {
        /* nothing to release */
      }
    }
  })();

  return transform.readable;
}

/** Frame-level screener — the testable core of {@link screenSseStream}. */
export function screenSseFrames(options: ScreenSseOptions): TransformStream<SseFrame, SseFrame> {
  const overlapBytes = options.overlapBytes ?? DEFAULT_OVERLAP_BYTES;
  let carry = "";
  let frameIndex = -1;
  let settled = false;
  let redactedMatch: GuardrailMatch | undefined;
  let redactedFrames = 0;

  const settle = (outcome: StreamScreenOutcome): void => {
    if (settled) {
      return;
    }
    settled = true;
    options.onOutcome?.(outcome);
  };

  return new TransformStream<SseFrame, SseFrame>({
    async transform(frame, controller) {
      frameIndex += 1;
      if (settled) {
        // Already blocked: swallow anything still in flight.
        return;
      }

      const delta = frameText(options.dialect, frame);
      if (delta.length === 0) {
        controller.enqueue(frame);
        return;
      }

      const envelope = windowEnvelope(options.protocol, carry, delta);
      const match = await options.engine.matchGuardrail("response", {
        ...options.context,
        envelope,
      });

      if (match === null) {
        carry = tailBytes(carry + delta, overlapBytes);
        controller.enqueue(frame);
        return;
      }

      if (match.effect === "deny") {
        // The offending frame is NEVER forwarded.
        for (const terminal of terminalErrorFrames(options.dialect, match, options.requestId)) {
          controller.enqueue(terminal);
        }
        settle({ kind: "blocked", match, frameIndex });
        // NOT `controller.terminate()`. In workerd, terminating a transform
        // mid-pipeline errors its writable side and produces an UNHANDLED
        // rejection that no `.catch()` on the surrounding `pipeTo` promises can
        // absorb (reproduced: two `TypeError: The readable side of this
        // TransformStream is no longer readable.` per block). Instead the
        // screener latches `settled` — every later frame is silently dropped —
        // and asks the OWNER of the source body to abort it, which is what
        // `screenSseBody` wires up. The stream then closes cleanly.
        options.abort?.();
        return;
      }

      const patched = applyDeltaPatches(delta, match.contentPatches);
      const rewritten = withFrameText(options.dialect, frame, patched);
      redactedMatch = match;
      redactedFrames += 1;
      carry = tailBytes(carry + patched, overlapBytes);
      controller.enqueue(rewritten);
    },
    flush() {
      if (redactedMatch !== undefined) {
        settle({ kind: "redacted", match: redactedMatch, frameCount: redactedFrames });
        return;
      }
      settle({ kind: "clean" });
    },
  });
}

// ---------------------------------------------------------------------------
// Window envelope
// ---------------------------------------------------------------------------

const CARRY_LOCATION = "response.stream.carry";
const DELTA_LOCATION = "response.stream.delta";
const DELTA_SEGMENT_ID = "stream:delta";

function segment(id: string, location: string, text: string): ContentSegment {
  return {
    segment_id: id,
    source: "assistant",
    protocol_location: location,
    content_type: "text",
    text,
    fingerprint: contentFingerprint(text),
  };
}

/**
 * Two ADJACENT `assistant` segments so the deterministic detector's
 * coalesced-group scan joins them; the per-segment re-scan then keeps
 * `\b`-anchored patterns honest inside each part.
 */
function windowEnvelope(
  protocol: GuardrailProtocol,
  carry: string,
  delta: string,
): GuardrailEnvelope {
  const segments: ContentSegment[] = [];
  if (carry.length > 0) {
    segments.push(segment("stream:carry", CARRY_LOCATION, carry));
  }
  segments.push(segment(DELTA_SEGMENT_ID, DELTA_LOCATION, delta));
  return { protocol, stage: "response", segments };
}

/** Keep at most `max` trailing UTF-8 bytes, cut on a character boundary. */
function tailBytes(text: string, max: number): string {
  const length = byteLen(text);
  if (length <= max) {
    return text;
  }
  for (let start = length - max; start <= length; start += 1) {
    const slice = byteSlice(text, start, length);
    if (slice !== undefined) {
      return slice;
    }
  }
  return "";
}

/**
 * Apply the patches that target the DELTA segment, right-to-left so earlier
 * offsets stay valid. Patches arrive validated (non-overlapping, on UTF-8
 * character boundaries) from `validateContentPatchesForSegments`.
 */
function applyDeltaPatches(delta: string, patches: readonly ContentPatch[]): string {
  const applicable = patches
    .filter((patch) => patch.segment_id === DELTA_SEGMENT_ID)
    .sort((a, b) => b.byte_start - a.byte_start);
  if (applicable.length === 0) {
    // The finding sat entirely in the carry (already-delivered) text. There is
    // nothing left to scrub in THIS frame; the redaction that mattered was
    // applied when the carry itself was the delta.
    return delta;
  }
  let out = delta;
  for (const patch of applicable) {
    const head = byteSlice(out, 0, patch.byte_start);
    const tail = byteSlice(out, patch.byte_end, byteLen(out));
    if (head === undefined || tail === undefined) {
      return "[REDACTED]";
    }
    out = `${head}${patch.replacement}${tail}`;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Dialect frame vocabulary
// ---------------------------------------------------------------------------

/**
 * The model-generated text this frame carries, or `""` for a frame that carries
 * none (role chunks, ping, usage, `[DONE]`).
 *
 * Deliberately narrow: guardrails screen MODEL CONTENT, so SSE plumbing must
 * never reach a detector — a `data: [DONE]` scanned as text would be a false
 * positive surface and a needless evidence row.
 */
export function frameText(dialect: StreamDialect, frame: SseFrame): string {
  if (isDoneFrame(frame)) {
    return "";
  }
  const value = frameJson(frame);
  if (value === undefined || value === null || typeof value !== "object") {
    return "";
  }
  const json = value as Record<string, unknown>;
  switch (dialect) {
    case "openai.chat": {
      const choices = json.choices;
      if (!Array.isArray(choices)) {
        return "";
      }
      let out = "";
      for (const choice of choices) {
        const delta = (choice as Record<string, unknown> | null)?.delta;
        if (delta === null || typeof delta !== "object") {
          continue;
        }
        const content = (delta as Record<string, unknown>).content;
        if (typeof content === "string") {
          out += content;
        }
        const toolCalls = (delta as Record<string, unknown>).tool_calls;
        if (Array.isArray(toolCalls)) {
          for (const call of toolCalls) {
            const fn = (call as Record<string, unknown> | null)?.function;
            const args = (fn as Record<string, unknown> | null)?.arguments;
            if (typeof args === "string") {
              out += args;
            }
          }
        }
      }
      return out;
    }
    case "openai.responses": {
      if (frame.event !== "response.output_text.delta") {
        return "";
      }
      const delta = json.delta;
      return typeof delta === "string" ? delta : "";
    }
    case "anthropic.messages": {
      if (frame.event !== "content_block_delta") {
        return "";
      }
      const delta = json.delta;
      if (delta === null || typeof delta !== "object") {
        return "";
      }
      const record = delta as Record<string, unknown>;
      if (typeof record.text === "string") {
        return record.text;
      }
      return typeof record.partial_json === "string" ? record.partial_json : "";
    }
  }
}

/** Rebuild a frame with its text delta replaced (redaction). */
export function withFrameText(dialect: StreamDialect, frame: SseFrame, text: string): SseFrame {
  const value = frameJson(frame);
  if (value === undefined || value === null || typeof value !== "object") {
    return frame;
  }
  const json = structuredClone(value) as Record<string, unknown>;
  switch (dialect) {
    case "openai.chat": {
      const choices = json.choices;
      if (Array.isArray(choices)) {
        let first = true;
        for (const choice of choices) {
          const delta = (choice as Record<string, unknown> | null)?.delta;
          if (delta === null || typeof delta !== "object") {
            continue;
          }
          const record = delta as Record<string, unknown>;
          if (typeof record.content === "string") {
            record.content = first ? text : "";
            first = false;
          }
          const toolCalls = record.tool_calls;
          if (Array.isArray(toolCalls)) {
            for (const call of toolCalls) {
              const fn = (call as Record<string, unknown> | null)?.function;
              if (fn !== null && typeof fn === "object") {
                const fnRecord = fn as Record<string, unknown>;
                if (typeof fnRecord.arguments === "string") {
                  fnRecord.arguments = first ? text : "";
                  first = false;
                }
              }
            }
          }
        }
      }
      break;
    }
    case "openai.responses": {
      json.delta = text;
      break;
    }
    case "anthropic.messages": {
      const delta = json.delta;
      if (delta !== null && typeof delta === "object") {
        const record = delta as Record<string, unknown>;
        if (typeof record.text === "string") {
          record.text = text;
        } else if (typeof record.partial_json === "string") {
          record.partial_json = text;
        }
      }
      break;
    }
  }
  return jsonSseFrame(frame.event, json);
}

/** The in-band terminal frames a mid-stream block delivers. */
export function terminalErrorFrames(
  dialect: StreamDialect,
  match: GuardrailMatch,
  requestId: string,
): SseFrame[] {
  switch (dialect) {
    case "anthropic.messages":
      // `messages_stream.rs:287-298 error_sse`.
      return [
        jsonSseFrame("error", {
          type: "error",
          error: { type: match.code, message: match.message },
        }),
      ];
    case "openai.responses":
      // `responses_stream.rs:260-275 emit_error`.
      return [
        jsonSseFrame("response.failed", {
          request_id: requestId,
          error: { message: match.message, type: "ferrogate_error", code: match.code },
        }),
        sseFrame({ data: "[DONE]" }),
      ];
    case "openai.chat":
      // PORT-TODO(L: inventory-request-path §1.6): NO RUST BYTE-SHAPE EXISTS to
      // port. The Rust chat path evaluated the response guardrail only after
      // buffering, so a chat denial was always a BUFFERED 403 body and a
      // mid-stream chat block was unreachable. This port screens INCREMENTALLY
      // (that is the whole point — it never buffers an SSE body), which makes
      // the case reachable and therefore makes some frame necessary.
      // The approximation, stated exactly: the frame below carries the
      // IDENTICAL `ErrorBody` the buffered 403 would have carried — same
      // `message`/`type`/`code`/`request_id` — as an unnamed `data:` event,
      // which is what an OpenAI-compatible client already parses out of a
      // stream error frame, followed by `[DONE]`. The two sibling dialects need
      // no approximation: `anthropic.messages` and `openai.responses` both have
      // real Rust mid-stream error shapes (`messages_stream.rs:287`,
      // `responses_stream.rs:260`) and are ported verbatim above.
      // `test/guardrails/stream.test.ts` pins this frame, so it is a decision
      // on record rather than an accident.
      return [
        jsonSseFrame(undefined, {
          error: {
            message: match.message,
            type: "ferrogate_error",
            code: match.code,
            request_id: requestId,
          },
        }),
        sseFrame({ data: "[DONE]" }),
      ];
  }
}

/** Audit target for a stream decision (re-exported for the middleware). */
export { evidenceTarget };
