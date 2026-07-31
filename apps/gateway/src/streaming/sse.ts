/**
 * Rigorous Server-Sent Events parser / serializer built on `TransformStream`.
 *
 * Clean-room port of the SSE framing layer that the Rust gateway open-coded in
 * `ferrogate-gateway/src/messages_stream.rs` (`sse_data_payloads`, `drain_frame`,
 * `write_event`) and `responses_stream.rs` (`queue_event`). In the Rust tree the
 * framing lived inside an async-pump -> synchronous `Read` transform tower
 * (Pingora's tower is synchronous); on Workers we compose `TransformStream`s
 * directly, per `docs/legacy/inventory-request-path.md` §1.5.
 *
 * Differences from the Rust open-coding are deliberate *widenings* toward the
 * WHATWG SSE grammar, never narrowings:
 *  - all three line terminators (`\n`, `\r\n`, bare `\r`) end a line, and a `\r`
 *    landing on a chunk boundary is held back until the next chunk proves
 *    whether it was a bare `\r` or the first half of a `\r\n`;
 *  - `id:` and `retry:` fields are parsed (the Rust normalizers only read
 *    `event:`/`data:`, but the passthrough path must not lose them);
 *  - `:`-prefixed comment lines (provider keep-alives) are retained on the frame
 *    so byte-for-byte passthrough can re-emit them.
 *
 * BYTE-FOR-BYTE PASSTHROUGH: `SseFrame.raw` holds the exact source text of the
 * frame, terminators included, so a passthrough re-serialization is
 * byte-identical for any valid-UTF-8 upstream. When no rewriting at all is
 * required, prefer {@link passthroughStream}, which never decodes the bytes.
 */

/** The `[DONE]` sentinel OpenAI-compatible providers close a stream with. */
export const DONE_SENTINEL = "[DONE]";

/** One dispatched SSE frame (a run of field lines ended by a blank line). */
export interface SseFrame {
  /** `event:` field value, or `undefined` when the frame carried none. */
  readonly event?: string | undefined;
  /**
   * `data:` field values joined with `\n`. `undefined` means the frame had no
   * `data:` line at all (distinct from a present-but-empty `data:` line, which
   * yields `""`).
   */
  readonly data?: string | undefined;
  /** `id:` field value. */
  readonly id?: string | undefined;
  /** `retry:` field value, parsed as an integer number of milliseconds. */
  readonly retry?: number | undefined;
  /** `:`-prefixed comment lines, in order, without the leading colon. */
  readonly comments: readonly string[];
  /**
   * Exact source text of this frame including every line terminator and the
   * terminating blank line. Empty for frames synthesized by a normalizer.
   */
  readonly raw: string;
}

/** Options for {@link serializeSseFrame}. */
export interface SseSerializeOptions {
  /**
   * When true (the default) a frame that carries `raw` source text is re-emitted
   * verbatim — this is what makes proxy passthrough byte-for-byte exact.
   */
  readonly preferRaw?: boolean;
}

const CR = "\r";
const LF = "\n";

interface FramePartial {
  event: string | undefined;
  data: string[] | undefined;
  id: string | undefined;
  retry: number | undefined;
  comments: string[];
  raw: string;
  lineCount: number;
}

function emptyPartial(): FramePartial {
  return {
    event: undefined,
    data: undefined,
    id: undefined,
    retry: undefined,
    comments: [],
    raw: "",
    lineCount: 0,
  };
}

/**
 * Incremental, allocation-frugal SSE parser.
 *
 * Feed it decoded text with {@link push} (any chunking — mid-line, mid-frame —
 * is fine) and call {@link flush} at end-of-stream. `flush` dispatches a
 * trailing unterminated frame if one is buffered, matching the Rust
 * normalizers, which drained the leftover buffer through `drain_frame` when the
 * upstream reader hit EOF. (The WHATWG spec discards that trailing block; the
 * Rust gateway did not, and providers that omit the final blank line would
 * otherwise lose their last frame — including the usage frame.)
 */
export class SseParser {
  #buffer = "";
  #partial: FramePartial = emptyPartial();

  /** Feed decoded text; returns every frame completed by this input. */
  push(text: string): SseFrame[] {
    if (text.length === 0) {
      return [];
    }
    this.#buffer += text;
    return this.#drain(false);
  }

  /** End the stream: dispatches any buffered partial line / partial frame. */
  flush(): SseFrame[] {
    return this.#drain(true);
  }

  /** True when neither a partial line nor a partial frame is buffered. */
  get idle(): boolean {
    return this.#buffer.length === 0 && this.#partial.lineCount === 0;
  }

  #drain(final: boolean): SseFrame[] {
    const frames: SseFrame[] = [];
    for (;;) {
      const index = findLineBreak(this.#buffer);
      if (index < 0) {
        break;
      }
      const char = this.#buffer[index];
      // A trailing bare `\r` may still turn into `\r\n` once the next chunk
      // lands, so hold it back unless the stream is over.
      if (char === CR && index === this.#buffer.length - 1 && !final) {
        break;
      }
      const terminatorLength =
        char === CR && this.#buffer[index + 1] === LF ? 2 : 1;
      const line = this.#buffer.slice(0, index);
      const terminator = this.#buffer.slice(index, index + terminatorLength);
      this.#buffer = this.#buffer.slice(index + terminatorLength);
      const frame = this.#consumeLine(line, terminator);
      if (frame) {
        frames.push(frame);
      }
    }

    if (final) {
      if (this.#buffer.length > 0) {
        const line = this.#buffer;
        this.#buffer = "";
        this.#consumeLine(line, "");
      }
      const trailing = this.#dispatch("");
      if (trailing) {
        frames.push(trailing);
      }
    }
    return frames;
  }

  #consumeLine(line: string, terminator: string): SseFrame | undefined {
    if (line.length === 0) {
      return this.#dispatch(terminator);
    }
    this.#partial.raw += line + terminator;
    this.#partial.lineCount += 1;

    if (line.startsWith(":")) {
      this.#partial.comments.push(line.slice(1));
      return undefined;
    }

    const colon = line.indexOf(":");
    const field = colon < 0 ? line : line.slice(0, colon);
    let value = colon < 0 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) {
      value = value.slice(1);
    }

    switch (field) {
      case "event":
        this.#partial.event = value;
        break;
      case "data":
        (this.#partial.data ??= []).push(value);
        break;
      case "id":
        // Per spec an id containing U+0000 is ignored.
        if (!value.includes("\u0000")) {
          this.#partial.id = value;
        }
        break;
      case "retry":
        if (value.length > 0 && /^\d+$/.test(value)) {
          this.#partial.retry = Number.parseInt(value, 10);
        }
        break;
      default:
        // Unknown field: ignored per spec, but still preserved in `raw`.
        break;
    }
    return undefined;
  }

  #dispatch(terminator: string): SseFrame | undefined {
    const partial = this.#partial;
    if (partial.lineCount === 0) {
      // Blank line with no preceding fields dispatches nothing (and carries no
      // information), so it is not surfaced. Its bytes are dropped from `raw`
      // — passthrough callers should use `passthroughStream()`.
      return undefined;
    }
    this.#partial = emptyPartial();
    return {
      event: partial.event,
      data: partial.data?.join(LF),
      id: partial.id,
      retry: partial.retry,
      comments: partial.comments,
      raw: partial.raw + terminator,
    };
  }
}

function findLineBreak(text: string): number {
  const lf = text.indexOf(LF);
  const cr = text.indexOf(CR);
  if (lf < 0) {
    return cr;
  }
  if (cr < 0) {
    return lf;
  }
  return Math.min(lf, cr);
}

/** True when the frame is the OpenAI-style `data: [DONE]` terminator. */
export function isDoneFrame(frame: SseFrame): boolean {
  return frame.data !== undefined && frame.data.trim() === DONE_SENTINEL;
}

/** True when the frame carries neither an event name nor data (keep-alive). */
export function isEmptyFrame(frame: SseFrame): boolean {
  return (frame.data === undefined || frame.data.length === 0) && frame.event === undefined;
}

/** Parse the frame's `data:` payload as JSON, or `undefined` when unparsable. */
export function frameJson(frame: SseFrame): unknown {
  if (frame.data === undefined) {
    return undefined;
  }
  try {
    return JSON.parse(frame.data) as unknown;
  } catch {
    return undefined;
  }
}

/** Build a synthesized frame (no `raw`; it will be serialized field by field). */
export function sseFrame(init: {
  event?: string | undefined;
  data?: string | undefined;
  id?: string | undefined;
  retry?: number | undefined;
  comments?: readonly string[];
}): SseFrame {
  return {
    event: init.event,
    data: init.data,
    id: init.id,
    retry: init.retry,
    comments: init.comments ?? [],
    raw: "",
  };
}

/** Build a synthesized `event: <name>` / `data: <json>` frame. */
export function jsonSseFrame(event: string | undefined, value: unknown): SseFrame {
  return sseFrame({ event, data: JSON.stringify(value) });
}

/** The terminating `data: [DONE]` frame. */
export function doneSseFrame(): SseFrame {
  return sseFrame({ data: DONE_SENTINEL });
}

/**
 * Serialize a frame back to SSE wire text.
 *
 * Field order mirrors the Rust `write_event` / `queue_event`: comments, then
 * `event:`, then `id:`/`retry:`, then one `data:` line per line of the payload,
 * then the blank line. Multi-line data therefore round-trips exactly.
 */
export function serializeSseFrame(
  frame: SseFrame,
  options: SseSerializeOptions = {},
): string {
  const preferRaw = options.preferRaw ?? true;
  if (preferRaw && frame.raw.length > 0) {
    return frame.raw;
  }
  let out = "";
  for (const comment of frame.comments) {
    out += `:${comment}${LF}`;
  }
  if (frame.event !== undefined) {
    out += `event: ${frame.event}${LF}`;
  }
  if (frame.id !== undefined) {
    out += `id: ${frame.id}${LF}`;
  }
  if (frame.retry !== undefined) {
    out += `retry: ${frame.retry}${LF}`;
  }
  if (frame.data !== undefined) {
    for (const line of frame.data.split(LF)) {
      out += `data: ${line}${LF}`;
    }
  }
  return `${out}${LF}`;
}

/** Serialize a whole sequence of frames. */
export function serializeSseFrames(
  frames: Iterable<SseFrame>,
  options?: SseSerializeOptions,
): string {
  let out = "";
  for (const frame of frames) {
    out += serializeSseFrame(frame, options);
  }
  return out;
}

/**
 * Byte stream -> frame stream.
 *
 * The `TextDecoder` runs in streaming mode, so a chunk boundary that lands in
 * the middle of a multi-byte UTF-8 sequence is held until the continuation
 * bytes arrive instead of producing U+FFFD. (The Rust tower used
 * `String::from_utf8_lossy` per 8 KiB read, which *did* corrupt a code point
 * split across reads; this port fixes that rather than replicating the bug.)
 */
export function sseParseStream(): TransformStream<Uint8Array, SseFrame> {
  const parser = new SseParser();
  const decoder = new TextDecoder("utf-8");
  return new TransformStream<Uint8Array, SseFrame>({
    transform(chunk, controller) {
      for (const frame of parser.push(decoder.decode(chunk, { stream: true }))) {
        controller.enqueue(frame);
      }
    },
    flush(controller) {
      const tail = decoder.decode();
      for (const frame of parser.push(tail)) {
        controller.enqueue(frame);
      }
      for (const frame of parser.flush()) {
        controller.enqueue(frame);
      }
    },
  });
}

/** Frame stream -> byte stream. */
export function sseSerializeStream(
  options?: SseSerializeOptions,
): TransformStream<SseFrame, Uint8Array> {
  const encoder = new TextEncoder();
  return new TransformStream<SseFrame, Uint8Array>({
    transform(frame, controller) {
      controller.enqueue(encoder.encode(serializeSseFrame(frame, options)));
    },
  });
}

/**
 * Identity byte transform. The only 100 %-safe passthrough: no decode, no
 * re-encode, so even invalid UTF-8 from the upstream survives untouched.
 */
export function passthroughStream(): TransformStream<Uint8Array, Uint8Array> {
  return new TransformStream<Uint8Array, Uint8Array>();
}

/** Parse a complete SSE body (bytes or text) into frames — sync, for tests and
 * for the buffered/governed path where the whole stream is inspected first. */
export function parseSse(body: Uint8Array | ArrayBuffer | string): SseFrame[] {
  const text =
    typeof body === "string"
      ? body
      : new TextDecoder("utf-8").decode(
          body instanceof Uint8Array ? body : new Uint8Array(body),
        );
  const parser = new SseParser();
  return [...parser.push(text), ...parser.flush()];
}

/**
 * Compose transforms into a single `TransformStream`-shaped pair. Lets a
 * caller hand one object to `body.pipeThrough(...)` while the implementation
 * stays a pipeline of small, individually testable transforms.
 */
export function composeTransforms<A, B>(
  first: TransformStream<A, B>,
): TransformStream<A, B>;
export function composeTransforms<A, B, C>(
  first: TransformStream<A, B>,
  second: TransformStream<B, C>,
): TransformStream<A, C>;
export function composeTransforms<A, B, C, D>(
  first: TransformStream<A, B>,
  second: TransformStream<B, C>,
  third: TransformStream<C, D>,
): TransformStream<A, D>;
export function composeTransforms(
  ...stages: TransformStream<unknown, unknown>[]
): TransformStream<unknown, unknown> {
  const first = stages[0];
  if (first === undefined) {
    throw new TypeError("composeTransforms requires at least one stage");
  }
  let readable: ReadableStream<unknown> = first.readable;
  for (let index = 1; index < stages.length; index += 1) {
    const stage = stages[index];
    if (stage === undefined) {
      continue;
    }
    readable = readable.pipeThrough(stage);
  }
  return { writable: first.writable, readable } as TransformStream<
    unknown,
    unknown
  >;
}

/** Wrap a frame->frame transform as a byte->byte transform. */
export function bytesThroughFrames(
  frames: TransformStream<SseFrame, SseFrame>,
  options?: SseSerializeOptions,
): TransformStream<Uint8Array, Uint8Array> {
  return composeTransforms(
    sseParseStream(),
    frames,
    sseSerializeStream(options),
  );
}

/** Build a `ReadableStream<Uint8Array>` from literal chunks (test fixtures). */
export function byteStreamFrom(
  chunks: readonly (Uint8Array | string)[],
): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  let index = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      const chunk = chunks[index];
      if (index >= chunks.length || chunk === undefined) {
        controller.close();
        return;
      }
      index += 1;
      controller.enqueue(typeof chunk === "string" ? encoder.encode(chunk) : chunk);
    },
  });
}

/** Drain a byte stream to a string (test/aggregation helper). */
export async function readAllText(stream: ReadableStream<Uint8Array>): Promise<string> {
  const decoder = new TextDecoder("utf-8");
  const reader = stream.getReader();
  let out = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      out += decoder.decode(value, { stream: true });
    }
  } finally {
    reader.releaseLock();
  }
  return out + decoder.decode();
}

/** Drain a frame stream to an array (test helper). */
export async function readAllFrames(
  stream: ReadableStream<SseFrame>,
): Promise<SseFrame[]> {
  const frames: SseFrame[] = [];
  const reader = stream.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      frames.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return frames;
}
