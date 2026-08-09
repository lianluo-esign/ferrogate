/**
 * SSE transport framing tests — both directions.
 *
 * Server side: a JSON-RPC response framed as `text/event-stream` must be a
 * spec-legal frame (multi-line payloads split across repeated `data:` fields,
 * terminated by the blank line that dispatches the event), because a raw
 * newline inside `data` would silently truncate the message.
 *
 * Client side: {@link readSseJsonResponse} must return on the FIRST complete
 * JSON value rather than blocking until the peer closes — a real SSE stream may
 * never close promptly.
 */
import { describe, expect, it } from "vitest";

import {
  MAX_MCP_RESPONSE_BYTES,
  encodeSseEvent,
  parseSseEvents,
  prefersEventStream,
  readSseJsonResponse,
  sseJsonRpcResponse,
} from "../src/transport.js";

function streamOf(...chunks: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      controller.close();
    },
  });
}

/** A stream that emits its chunks and then NEVER closes. */
function neverClosingStream(...chunks: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      // deliberately no controller.close()
    },
  });
}

describe("SSE frame encoding", () => {
  it("terminates a frame with the dispatching blank line", () => {
    expect(encodeSseEvent({ event: "message", data: "hello" })).toBe(
      "event: message\ndata: hello\n\n",
    );
  });

  it("splits a multi-line payload across repeated data fields", () => {
    const frame = encodeSseEvent({ data: "line one\nline two" });
    expect(frame).toBe("data: line one\ndata: line two\n\n");
    // Round-trips back to the original payload, newline intact.
    expect(parseSseEvents(frame)[0]?.data).toBe("line one\nline two");
  });

  it("emits id and retry fields when present", () => {
    expect(encodeSseEvent({ data: "x", id: "7", retry: 1500 })).toBe(
      "id: 7\nretry: 1500\ndata: x\n\n",
    );
  });
});

describe("SSE frame parsing", () => {
  it("ignores comment / keep-alive lines", () => {
    const events = parseSseEvents(': keep-alive\n\nevent: message\ndata: {"a":1}\n\n');
    expect(events).toHaveLength(1);
    expect(events[0]).toEqual({ event: "message", data: '{"a":1}' });
  });

  it("strips exactly one leading space from a field value", () => {
    expect(parseSseEvents("data:  two-spaces\n\n")[0]?.data).toBe(" two-spaces");
  });
});

describe("sseJsonRpcResponse", () => {
  it("frames one JSON-RPC message and closes", async () => {
    const response = sseJsonRpcResponse({ jsonrpc: "2.0", id: 1, result: { ok: true } });
    expect(response.headers.get("content-type")).toBe("text/event-stream; charset=utf-8");
    expect(response.headers.get("cache-control")).toContain("no-cache");
    const events = parseSseEvents(await response.text());
    expect(events).toHaveLength(1);
    expect(events[0]?.event).toBe("message");
    expect(JSON.parse(events[0]?.data ?? "null")).toEqual({
      jsonrpc: "2.0",
      id: 1,
      result: { ok: true },
    });
  });
});

describe("upstream SSE reading", () => {
  it("returns the first complete JSON value", async () => {
    const value = await readSseJsonResponse(
      streamOf('event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n\n'),
    );
    expect(value).toEqual({ jsonrpc: "2.0", id: 1, result: { ok: true } });
  });

  it("does NOT block waiting for the stream to close", async () => {
    // The peer emits a complete event and then holds the connection open
    // forever. Returning here is the whole point of the incremental parse.
    const value = await readSseJsonResponse(
      neverClosingStream('data: {"jsonrpc":"2.0","id":2,"result":7}\n\n'),
    );
    expect(value).toEqual({ jsonrpc: "2.0", id: 2, result: 7 });
  });

  it("reassembles a payload split across data fields and network chunks", async () => {
    const value = await readSseJsonResponse(
      streamOf('data: {"jsonrpc":"2.0",\n', 'data: "id":3,"result":{"a":1}}\n', "\n"),
    );
    expect(value).toEqual({ jsonrpc: "2.0", id: 3, result: { a: 1 } });
  });

  it("skips a non-JSON event and keeps reading", async () => {
    const value = await readSseJsonResponse(
      streamOf("event: ping\ndata: not-json\n\n", 'data: {"jsonrpc":"2.0","id":4,"result":1}\n\n'),
    );
    expect(value).toEqual({ jsonrpc: "2.0", id: 4, result: 1 });
  });

  it("fails rather than hanging when the stream closes with no response", async () => {
    await expect(readSseJsonResponse(streamOf("event: ping\n\n"))).rejects.toThrow(
      /closed before a JSON-RPC response arrived/,
    );
  });

  it("caps the response so a lying peer cannot grow the buffer without bound", async () => {
    // One oversized `data:` line, never terminated.
    const oversized = `data: ${"x".repeat(MAX_MCP_RESPONSE_BYTES + 1)}`;
    await expect(readSseJsonResponse(streamOf(oversized))).rejects.toThrow(/maximum/);
  });
});

describe("Streamable HTTP response-shape negotiation", () => {
  it("stays on JSON when the caller advertises both (the SDK's default)", () => {
    expect(prefersEventStream("application/json, text/event-stream")).toBe(false);
  });

  it("streams when the caller asks only for the event stream", () => {
    expect(prefersEventStream("text/event-stream")).toBe(true);
  });

  it("honours an explicit q-value preference for the stream", () => {
    expect(prefersEventStream("application/json;q=0.1, text/event-stream;q=0.9")).toBe(true);
  });

  it("stays on JSON when no Accept header is present", () => {
    expect(prefersEventStream(null)).toBe(false);
  });
});
