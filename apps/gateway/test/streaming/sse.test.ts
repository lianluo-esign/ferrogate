import { describe, expect, test } from "vitest";

import {
  DONE_SENTINEL,
  SseParser,
  isDoneFrame,
  jsonSseFrame,
  parseSse,
  passthroughStream,
  serializeSseFrame,
  serializeSseFrames,
  sseFrame,
  sseParseStream,
  sseSerializeStream,
} from "../../src/streaming/sse.js";
import {
  bytes,
  chunkBytes,
  drainBytes,
  drainFrames,
  splitBytes,
  streamOf,
} from "./helpers.js";

describe("SSE field grammar", () => {
  test("parses event / data / id / retry and strips exactly one space", () => {
    const frames = parseSse(
      "event: message\ndata: hello\nid: 42\nretry: 2500\n\n",
    );
    expect(frames).toHaveLength(1);
    const frame = frames[0]!;
    expect(frame.event).toBe("message");
    expect(frame.data).toBe("hello");
    expect(frame.id).toBe("42");
    expect(frame.retry).toBe(2500);
  });

  test("a colon with no space is still a field separator", () => {
    const frame = parseSse("event:ping\ndata:{\"a\":1}\n\n")[0]!;
    expect(frame.event).toBe("ping");
    expect(frame.data).toBe('{"a":1}');
  });

  test("only ONE leading space is stripped from a value", () => {
    const frame = parseSse("data:  two-spaces\n\n")[0]!;
    expect(frame.data).toBe(" two-spaces");
  });

  test("multi-line data joins with \\n and round-trips", () => {
    const frame = parseSse("data: line one\ndata: line two\ndata: \n\n")[0]!;
    expect(frame.data).toBe("line one\nline two\n");
    const reserialized = serializeSseFrame(
      sseFrame({ data: frame.data }),
      { preferRaw: false },
    );
    expect(reserialized).toBe("data: line one\ndata: line two\ndata: \n\n");
  });

  test("a present-but-empty data field is distinct from an absent one", () => {
    expect(parseSse("data:\n\n")[0]!.data).toBe("");
    expect(parseSse("event: ping\n\n")[0]!.data).toBeUndefined();
  });

  test("comment lines are retained, not silently dropped", () => {
    const frame = parseSse(": keep-alive\ndata: x\n\n")[0]!;
    expect(frame.comments).toEqual([" keep-alive"]);
    expect(frame.data).toBe("x");
  });

  test("a field with no colon is a field with an empty value", () => {
    const frame = parseSse("data\n\n")[0]!;
    expect(frame.data).toBe("");
  });

  test("a non-numeric retry is ignored", () => {
    expect(parseSse("retry: soon\ndata: x\n\n")[0]!.retry).toBeUndefined();
  });

  test("unknown fields are ignored but preserved in raw", () => {
    const frame = parseSse("weird: value\ndata: x\n\n")[0]!;
    expect(frame.data).toBe("x");
    expect(frame.raw).toBe("weird: value\ndata: x\n\n");
  });

  test("[DONE] sentinel is recognized with or without padding", () => {
    expect(isDoneFrame(parseSse("data: [DONE]\n\n")[0]!)).toBe(true);
    expect(isDoneFrame(parseSse("data:[DONE]\n\n")[0]!)).toBe(true);
    expect(isDoneFrame(parseSse("data: [DONE] \n\n")[0]!)).toBe(true);
    expect(isDoneFrame(parseSse("data: not-done\n\n")[0]!)).toBe(false);
    expect(DONE_SENTINEL).toBe("[DONE]");
  });
});

describe("SSE line terminators", () => {
  test("LF, CRLF and bare CR all terminate a line", () => {
    expect(parseSse("data: a\n\n")[0]!.data).toBe("a");
    expect(parseSse("data: b\r\n\r\n")[0]!.data).toBe("b");
    expect(parseSse("data: c\r\r")[0]!.data).toBe("c");
  });

  test("a CRLF split across chunks is NOT read as a bare CR", () => {
    const parser = new SseParser();
    expect(parser.push("data: a\r")).toEqual([]);
    const frames = [...parser.push("\ndata: b\r\n\r\n"), ...parser.flush()];
    expect(frames).toHaveLength(1);
    expect(frames[0]!.data).toBe("a\nb");
  });

  test("a trailing bare CR at true end-of-stream still terminates", () => {
    const parser = new SseParser();
    parser.push("data: a\r");
    const frames = parser.flush();
    expect(frames).toHaveLength(1);
    expect(frames[0]!.data).toBe("a");
  });
});

describe("SSE framing across chunk boundaries", () => {
  const body = bytes(
    'data: {"n":1}\n\nevent: tick\ndata: {"n":2}\n\ndata: [DONE]\n\n',
  );

  test("split mid-event yields the same frames as an unsplit body", async () => {
    const expected = parseSse(body).map((frame) => ({
      event: frame.event,
      data: frame.data,
    }));
    // Cut inside the JSON payload, inside a field name, and on the blank line.
    for (const cut of [1, 7, 13, 14, 15, 22, 33, 40, body.length - 1]) {
      const frames = await drainFrames(
        streamOf(splitBytes(body, [cut])).pipeThrough(sseParseStream()),
      );
      expect(frames.map((f) => ({ event: f.event, data: f.data }))).toEqual(
        expected,
      );
    }
  });

  test("one byte at a time yields the same frames", async () => {
    const frames = await drainFrames(
      streamOf(chunkBytes(body, 1)).pipeThrough(sseParseStream()),
    );
    expect(frames.map((f) => f.data)).toEqual([
      '{"n":1}',
      '{"n":2}',
      "[DONE]",
    ]);
    expect(frames[1]!.event).toBe("tick");
  });

  test("splitting at EVERY byte offset is stable", async () => {
    const expected = parseSse(body).map((frame) => frame.data);
    for (let cut = 1; cut < body.length; cut += 1) {
      const frames = await drainFrames(
        streamOf(splitBytes(body, [cut])).pipeThrough(sseParseStream()),
      );
      expect(frames.map((frame) => frame.data)).toEqual(expected);
    }
  });

  test("a final frame with no terminating blank line is still dispatched", async () => {
    const frames = await drainFrames(
      streamOf(['data: {"tail":true}']).pipeThrough(sseParseStream()),
    );
    expect(frames).toHaveLength(1);
    expect(frames[0]!.data).toBe('{"tail":true}');
  });

  test("blank lines with no fields dispatch nothing", () => {
    expect(parseSse("\n\n\n\n")).toEqual([]);
  });
});

describe("SSE UTF-8 safety", () => {
  test("a 2-byte code point split across chunks is not corrupted", async () => {
    const body = bytes("data: café\n\n");
    // "é" is 0xC3 0xA9; cut between its two bytes.
    const eAcute = body.indexOf(0xc3);
    expect(eAcute).toBeGreaterThan(0);
    const frames = await drainFrames(
      streamOf(splitBytes(body, [eAcute + 1])).pipeThrough(sseParseStream()),
    );
    expect(frames[0]!.data).toBe("café");
    expect(frames[0]!.data).not.toContain("�");
  });

  test("a 4-byte emoji split at every internal offset survives", async () => {
    const body = bytes('data: {"t":"\u{1F680}"}\n\n');
    const start = body.indexOf(0xf0);
    expect(start).toBeGreaterThan(0);
    for (const cut of [start + 1, start + 2, start + 3]) {
      const frames = await drainFrames(
        streamOf(splitBytes(body, [cut])).pipeThrough(sseParseStream()),
      );
      expect(frames).toHaveLength(1);
      expect(frames[0]!.data).toBe('{"t":"\u{1F680}"}');
      expect(JSON.parse(frames[0]!.data!)).toEqual({ t: "\u{1F680}" });
    }
  });

  test("byte-at-a-time delivery of mixed-width text is exact", async () => {
    const payload = "aé中\u{1F680}z";
    const body = bytes(`data: ${payload}\n\n`);
    const frames = await drainFrames(
      streamOf(chunkBytes(body, 1)).pipeThrough(sseParseStream()),
    );
    expect(frames[0]!.data).toBe(payload);
  });
});

describe("SSE serialization", () => {
  test("jsonSseFrame renders the Rust write_event shape", () => {
    expect(
      serializeSseFrame(jsonSseFrame("message_stop", { type: "message_stop" }), {
        preferRaw: false,
      }),
    ).toBe('event: message_stop\ndata: {"type":"message_stop"}\n\n');
  });

  test("a frame with no event name emits only data lines", () => {
    expect(
      serializeSseFrame(sseFrame({ data: "[DONE]" }), { preferRaw: false }),
    ).toBe("data: [DONE]\n\n");
  });

  test("comments, id and retry survive a serialize round-trip", () => {
    const original = ": ping\nevent: tick\nid: 7\nretry: 1000\ndata: x\n\n";
    const frame = parseSse(original)[0]!;
    expect(serializeSseFrame(frame, { preferRaw: false })).toBe(original);
  });
});

describe("byte-for-byte passthrough", () => {
  const upstream =
    ": keep-alive\n\n" +
    'event: message\nid: 1\ndata: {"a":"é"}\n\n' +
    "retry: 3000\ndata: line one\ndata: line two\n\n" +
    "data: [DONE]\n\n";

  test("parse -> serialize with raw reproduces the upstream bytes", async () => {
    const round = await drainBytes(
      streamOf(chunkBytes(bytes(upstream), 3))
        .pipeThrough(sseParseStream())
        .pipeThrough(sseSerializeStream()),
    );
    expect(new TextDecoder().decode(round)).toBe(upstream);
  });

  test("serializeSseFrames(parseSse(x)) === x", () => {
    expect(serializeSseFrames(parseSse(upstream))).toBe(upstream);
  });

  test("framing that field-by-field serialization could NOT reproduce survives", () => {
    // Deliberately quirky upstream framing: no space after the colon, `data`
    // BEFORE `event`, an unknown field, and CRLF terminators. Only verbatim
    // `raw` re-emission reproduces these bytes.
    const quirky = 'data:{"a":1}\r\nevent:message\r\nx-vendor: 7\r\n\r\n';
    const frames = parseSse(quirky);
    expect(frames).toHaveLength(1);
    expect(serializeSseFrames(frames)).toBe(quirky);
    // ...and the normalized re-serialization really is different, so the test
    // above is not passing by coincidence.
    expect(serializeSseFrames(frames, { preferRaw: false })).not.toBe(quirky);
  });

  test("passthroughStream never decodes, so arbitrary bytes survive", async () => {
    // A lone 0xFF is not valid UTF-8; the identity transform must not mangle it.
    const raw = new Uint8Array([0x64, 0x61, 0x74, 0x61, 0x3a, 0xff, 0x0a, 0x0a]);
    const out = await drainBytes(
      streamOf([raw]).pipeThrough(passthroughStream()),
    );
    expect([...out]).toEqual([...raw]);
  });
});
