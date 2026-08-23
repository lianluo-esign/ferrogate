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
 *
 * ## EVERY frame that carries model text is screened, not just the deltas
 *
 * Issue #778. This screener used to read exactly ONE event per dialect on the
 * Responses surface — `response.output_text.delta` — which meant a
 * provider-relayed `response.completed`, whose `response.output` holds the FULL
 * assembled answer, went past the response-stage policy untouched. #689's
 * "stored == delivered" invariant still HELD there (the stored bytes were the
 * delivered bytes); it simply was not protection, because the delivered bytes
 * were themselves unscreened.
 *
 * The vocabulary below is therefore expressed as TEXT SLOTS — every position in
 * a frame's payload that holds model-generated text — rather than as one delta
 * field. On `openai.responses` that is `delta`, `text`, `arguments`, `refusal`,
 * `part.*`, `item.*` and `response.output[].*`, which between them cover
 * `response.output_text.delta|done`, `response.function_call_arguments.
 * delta|done`, `response.refusal.delta|done`,
 * `response.reasoning_summary_text.delta|done`,
 * `response.output_item.added|done`, `response.content_part.added|done` and
 * `response.completed|incomplete`. Patching the terminal frame and leaving a
 * sibling is how a third instance of this bug survives, so the coverage is
 * structural rather than a list of event names.
 *
 * Frames that carry NO model text — a usage-only terminal frame, `[DONE]`,
 * `response.created`, a keep-alive — still yield no slots, so they never reach a
 * detector and never produce an evidence row. That property is pinned in
 * `test/guardrails/responses-stream.test.ts`.
 *
 * ## What a DENY on the TERMINAL frame does (issue #778)
 *
 * By the time `response.completed` arrives every delta is already on the wire,
 * so "emit the envelope" is not available and neither is a status line. #733
 * settled this for the general case of a failure after the headers are flushed:
 * **fault the stream so the truncation is visible**, rather than ending it
 * cleanly and pretending it completed. The same answer applies here, and it
 * falls out of the existing block path unchanged:
 *
 *  - the offending `response.completed` is NEVER forwarded, and
 *  - `response.failed` (carrying `guardrail_blocked`) plus `[DONE]` takes its
 *    place.
 *
 * So the terminal EVENT NAME is what tells a caller "truncated by policy" from
 * "complete" — a client that waits for `response.completed` sees
 * `response.failed` instead and cannot mistake a policy truncation for a finished
 * answer. Deleting `response.completed` outright was rejected for the same
 * reason: a stream that just stops is a silent failure, and one that ends with a
 * synthesized `response.completed` after a denial would be a lie.
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
export type StreamDialect =
  | "openai.chat"
  | "openai.responses"
  | "anthropic.messages"
  | "gemini";

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

      // ALL of this frame's model text, every slot joined in wire order — not
      // just a `delta` field. See the module header (#778).
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

      const rewritten = withFramePatches(options.dialect, frame, match.contentPatches);
      redactedMatch = match;
      redactedFrames += 1;
      carry = tailBytes(carry + rewritten.text, overlapBytes);
      controller.enqueue(rewritten.frame);
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
 * Apply the patches that target the DELTA segment across the frame's text
 * slots, right-to-left so earlier offsets stay valid.
 *
 * The detector sees ONE segment — the joined text of every slot — so its offsets
 * are global to that join and have to be mapped back onto the slot they landed
 * in. That is the same offset-mapping the carry/delta window already does, one
 * level down: a slot boundary is always a character boundary (each slot holds a
 * whole string), so an intersection with a slot is always on a character
 * boundary too.
 *
 * A patch that STRADDLES two slots — possible only because the join is what the
 * detector matched over — puts its replacement in the first slot it touches and
 * deletes the touched range from the rest. That keeps the replacement text
 * exactly once rather than once per slot.
 *
 * Patches arrive validated (non-overlapping, on UTF-8 character boundaries) from
 * `validateContentPatchesForSegments`.
 */
function applyPatchesAcrossSlots(
  slots: readonly TextSlot[],
  patches: readonly ContentPatch[],
): string {
  const texts = slots.map((slot) => slot.read());
  const lengths = texts.map((text) => byteLen(text));
  const starts: number[] = [];
  let offset = 0;
  for (const length of lengths) {
    starts.push(offset);
    offset += length;
  }

  const applicable = patches
    .filter((patch) => patch.segment_id === DELTA_SEGMENT_ID)
    .sort((a, b) => b.byte_start - a.byte_start);
  if (applicable.length === 0) {
    // The finding sat entirely in the carry (already-delivered) text. There is
    // nothing left to scrub in THIS frame; the redaction that mattered was
    // applied when the carry itself was the delta.
    return texts.join("");
  }

  // A slot whose offsets we could not trust is scrubbed wholesale and then left
  // alone: after a wholesale replacement the remaining offsets into it are
  // meaningless, and re-slicing on them could re-expose the very bytes the
  // fallback removed.
  const scrubbed = new Set<number>();

  for (const patch of applicable) {
    const touched: number[] = [];
    for (let index = 0; index < texts.length; index += 1) {
      const start = starts[index] ?? 0;
      const end = start + (lengths[index] ?? 0);
      const overlaps =
        patch.byte_end > patch.byte_start
          ? patch.byte_end > start && patch.byte_start < end
          : // A zero-length patch is an INSERT; it belongs to whichever slot
            // contains its position (both, at a boundary — the extra one takes
            // an empty edit and is unchanged).
            patch.byte_start >= start && patch.byte_start <= end;
      if (overlaps) {
        touched.push(index);
      }
    }
    const first = touched[0];
    if (first === undefined) {
      continue;
    }
    // Descending, so a lower slot's offsets are still valid when we reach it.
    for (let cursor = touched.length - 1; cursor >= 0; cursor -= 1) {
      const index = touched[cursor] ?? 0;
      if (scrubbed.has(index)) {
        continue;
      }
      const start = starts[index] ?? 0;
      const localStart = Math.max(patch.byte_start - start, 0);
      const localEnd = Math.min(patch.byte_end - start, lengths[index] ?? 0);
      const current = texts[index] ?? "";
      const head = byteSlice(current, 0, localStart);
      const tail = byteSlice(current, localEnd, byteLen(current));
      if (head === undefined || tail === undefined) {
        texts[index] = FALLBACK_REDACTION;
        scrubbed.add(index);
        continue;
      }
      texts[index] = `${head}${index === first ? patch.replacement : ""}${tail}`;
    }
  }

  for (let index = 0; index < slots.length; index += 1) {
    slots[index]?.write(texts[index] ?? "");
  }
  return texts.join("");
}

/** Used only when a patch offset does not land on a character boundary. */
const FALLBACK_REDACTION = "[REDACTED]";

// ---------------------------------------------------------------------------
// Dialect frame vocabulary
// ---------------------------------------------------------------------------

/**
 * One rewritable position holding model-generated text inside a frame payload.
 *
 * A slot is bound to the object it was collected from, so collecting over a
 * CLONE and writing through the slots rewrites the clone — which is how
 * {@link withFramePatches} redacts without touching the frame the client may
 * already have been handed.
 */
interface TextSlot {
  read(): string;
  write(text: string): void;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

/** Push a slot for `container[key]` when it holds a string. */
function pushStringSlot(slots: TextSlot[], container: Record<string, unknown>, key: string): void {
  if (typeof container[key] !== "string") {
    return;
  }
  slots.push({
    read: () => (typeof container[key] === "string" ? (container[key] as string) : ""),
    write: (text) => {
      container[key] = text;
    },
  });
}

/**
 * Every position in this frame that carries model-generated text, in wire order.
 *
 * Deliberately narrow: guardrails screen MODEL CONTENT, so SSE plumbing must
 * never reach a detector — a `data: [DONE]`, a usage object or a `request_id`
 * scanned as text would be a false-positive surface and a needless evidence row.
 * Every arm below therefore names the fields it reads; nothing walks the payload
 * generically.
 */
function frameTextSlots(dialect: StreamDialect, json: Record<string, unknown>): TextSlot[] {
  const slots: TextSlot[] = [];
  switch (dialect) {
    case "openai.chat": {
      const choices = json.choices;
      if (!Array.isArray(choices)) {
        return slots;
      }
      for (const choice of choices) {
        const delta = asRecord(asRecord(choice)?.delta);
        if (delta === undefined) {
          continue;
        }
        pushStringSlot(slots, delta, "content");
        const toolCalls = delta.tool_calls;
        if (Array.isArray(toolCalls)) {
          for (const call of toolCalls) {
            const fn = asRecord(asRecord(call)?.function);
            if (fn !== undefined) {
              pushStringSlot(slots, fn, "arguments");
            }
          }
        }
      }
      return slots;
    }
    case "openai.responses": {
      // Structural, NOT keyed on the event name (#778): naming the events is
      // exactly how `response.completed` was missed, and a fourth event would be
      // missed the same way. Every field below is model output on this protocol
      // whatever frame it arrives in.
      //
      //   delta      — output_text.delta, function_call_arguments.delta,
      //                refusal.delta, reasoning_summary_text.delta
      //   text       — output_text.done, reasoning_summary_text.done
      //   arguments  — function_call_arguments.done
      //   refusal    — refusal.done
      //   part       — content_part.added|done
      //   item       — output_item.added|done
      //   response   — completed|incomplete: the FULL assembled output
      pushStringSlot(slots, json, "delta");
      pushStringSlot(slots, json, "text");
      pushStringSlot(slots, json, "arguments");
      pushStringSlot(slots, json, "refusal");
      pushResponsesPartSlots(slots, json.part);
      pushResponsesItemSlots(slots, json.item);
      const response = asRecord(json.response);
      if (response !== undefined) {
        const output = response.output;
        if (Array.isArray(output)) {
          for (const item of output) {
            pushResponsesItemSlots(slots, item);
          }
        }
      }
      return slots;
    }
    case "anthropic.messages": {
      // The FIELDS are unchanged by #778 — on this dialect the only model text
      // is a `content_block_delta`'s `delta.text` / `delta.partial_json`.
      // `message_start` carries usage and a role, `content_block_start` opens an
      // EMPTY block, `message_delta` carries a stop reason (its `delta` holds no
      // string field, so it yields no slot), `message_stop` carries nothing.
      // There is no assembled-output frame on this protocol — which is exactly
      // why Responses had one to miss and this one did not.
      //
      // What did change: the gate is the SHAPE rather than the `event:` name, so
      // a relay that sends the payload's own `type` without an `event:` line is
      // screened too. Same fields, one less way to slip past.
      const delta = asRecord(json.delta);
      if (delta === undefined) {
        return slots;
      }
      if (typeof delta.text === "string") {
        pushStringSlot(slots, delta, "text");
      } else {
        pushStringSlot(slots, delta, "partial_json");
      }
      return slots;
    }
    case "gemini": {
      // `streamGenerateContent?alt=sse` — each frame is a partial
      // `GenerateContentResponse`. The only model TEXT is
      // `candidates[].content.parts[].text`. A `functionCall` part carries its
      // `args` as an OBJECT on this protocol (not a stringified `arguments`
      // field), so there is no string slot to rewrite in place — detection over
      // it lives in the buffered/whole-body path (`envelope.ts`), and the live
      // screener stays narrow, exactly as it is for every other dialect.
      // `usageMetadata`, `promptFeedback` and a `finishReason`-only terminal
      // frame carry no model text and yield no slot.
      const candidates = json.candidates;
      if (!Array.isArray(candidates)) {
        return slots;
      }
      for (const candidate of candidates) {
        const content = asRecord(asRecord(candidate)?.content);
        const parts = content?.parts;
        if (!Array.isArray(parts)) {
          continue;
        }
        for (const part of parts) {
          const partRecord = asRecord(part);
          if (partRecord !== undefined) {
            pushStringSlot(slots, partRecord, "text");
          }
        }
      }
      return slots;
    }
  }
}

/** `content_part.*` — one part of an assistant message. */
function pushResponsesPartSlots(slots: TextSlot[], value: unknown): void {
  const part = asRecord(value);
  if (part === undefined) {
    return;
  }
  pushStringSlot(slots, part, "text");
  pushStringSlot(slots, part, "refusal");
}

/**
 * `output_item.*` and each entry of `response.output` — a message, a function
 * call or a reasoning item.
 */
function pushResponsesItemSlots(slots: TextSlot[], value: unknown): void {
  const item = asRecord(value);
  if (item === undefined) {
    return;
  }
  pushStringSlot(slots, item, "text");
  // A `function_call` item's assembled arguments: model-authored, and the same
  // bytes `openai.chat` screens out of `tool_calls[].function.arguments`.
  pushStringSlot(slots, item, "arguments");
  pushStringSlot(slots, item, "refusal");
  const content = item.content;
  if (Array.isArray(content)) {
    for (const part of content) {
      pushResponsesPartSlots(slots, part);
    }
  }
  // A reasoning item's summary parts.
  const summary = item.summary;
  if (Array.isArray(summary)) {
    for (const part of summary) {
      pushResponsesPartSlots(slots, part);
    }
  }
}

/**
 * The model-generated text this frame carries, or `""` for a frame that carries
 * none (role chunks, ping, usage, `response.created`, `[DONE]`).
 *
 * Frames with several slots are joined in wire order and screened as ONE
 * segment, so a marker split across two of them — an answer whose halves land in
 * two content parts — is caught, exactly as the carry window catches one split
 * across two frames.
 */
export function frameText(dialect: StreamDialect, frame: SseFrame): string {
  if (isDoneFrame(frame)) {
    return "";
  }
  const json = asRecord(frameJson(frame));
  if (json === undefined) {
    return "";
  }
  let out = "";
  for (const slot of frameTextSlots(dialect, json)) {
    out += slot.read();
  }
  return out;
}

/**
 * Rebuild a frame with the detector's patches applied to its text (redaction).
 *
 * Returns the rewritten frame AND the patched text, which is what the carry
 * window is advanced with — the client-visible bytes, not the provider's.
 */
export function withFramePatches(
  dialect: StreamDialect,
  frame: SseFrame,
  patches: readonly ContentPatch[],
): { readonly frame: SseFrame; readonly text: string } {
  const value = frameJson(frame);
  if (asRecord(value) === undefined) {
    return { frame, text: "" };
  }
  // Clone first, then collect the slots over the CLONE: a frame is not owned by
  // this transform and the parsed payload may be shared with a tap.
  const json = structuredClone(value) as Record<string, unknown>;
  const text = applyPatchesAcrossSlots(frameTextSlots(dialect, json), patches);
  return { frame: jsonSseFrame(frame.event, json), text };
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
    case "gemini":
      // NO native byte-shape exists to port: Gemini-native ingress is new to
      // this gateway, and Gemini's `alt=sse` transport defines no mid-stream
      // error frame. The approximation, stated exactly: the frame carries the
      // IDENTICAL FerroGate `ErrorBody` the buffered 403 would have carried —
      // same `message`/`type`/`code`/`request_id` — as an unnamed `data:`
      // event. A Gemini SSE client parses each frame as a
      // `GenerateContentResponse`-shaped object and finds an `error` member in
      // place of `candidates`, which is the same place Gemini's OWN transport
      // reports a request error. NO `[DONE]` follows: unlike the two OpenAI
      // dialects the Gemini SSE transport has no such sentinel, so synthesizing
      // one would be a second fabrication. The `"gemini native streaming is
      // screened"` block in `test/guardrails/stream.test.ts` pins this frame
      // (unnamed `data:` error, no `[DONE]`), so it is a decision on record
      // rather than an accident.
      return [
        jsonSseFrame(undefined, {
          error: {
            message: match.message,
            type: "ferrogate_error",
            code: match.code,
            request_id: requestId,
          },
        }),
      ];
  }
}

/** Audit target for a stream decision (re-exported for the middleware). */
export { evidenceTarget };
