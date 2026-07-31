/**
 * Shared fixtures/utilities for the streaming-tower unit tests.
 *
 * These tests are plain vitest unit tests over the `TransformStream`s — no
 * `SELF`, no bindings — driven with synthetic SSE byte chunks, including chunks
 * split mid-event and mid-UTF-8-sequence.
 */
import type { SseFrame } from "../../src/streaming/sse.js";

export const encoder = new TextEncoder();
export const decoder = new TextDecoder("utf-8");

/** Encode text to bytes. */
export function bytes(text: string): Uint8Array {
  return encoder.encode(text);
}

/** Split a byte array at the given absolute offsets. */
export function splitBytes(
  input: Uint8Array,
  offsets: readonly number[],
): Uint8Array[] {
  const cuts = [...new Set([0, ...offsets, input.length])].sort((a, b) => a - b);
  const out: Uint8Array[] = [];
  for (let index = 1; index < cuts.length; index += 1) {
    const start = cuts[index - 1] ?? 0;
    const end = cuts[index] ?? input.length;
    if (end > start) {
      out.push(input.subarray(start, end));
    }
  }
  return out;
}

/** Split a byte array into fixed-size chunks (1 = one byte at a time). */
export function chunkBytes(input: Uint8Array, size: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let offset = 0; offset < input.length; offset += size) {
    out.push(input.subarray(offset, Math.min(offset + size, input.length)));
  }
  return out;
}

/** A `ReadableStream<Uint8Array>` over literal chunks. */
export function streamOf(
  chunks: readonly (Uint8Array | string)[],
): ReadableStream<Uint8Array> {
  let index = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (index >= chunks.length) {
        controller.close();
        return;
      }
      const chunk = chunks[index];
      index += 1;
      controller.enqueue(typeof chunk === "string" ? bytes(chunk) : (chunk as Uint8Array));
    },
  });
}

/** Drain a byte stream into a single decoded string. */
export async function drainText(stream: ReadableStream<Uint8Array>): Promise<string> {
  const streaming = new TextDecoder("utf-8");
  const reader = stream.getReader();
  let out = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    out += streaming.decode(value, { stream: true });
  }
  return out + streaming.decode();
}

/** Drain a byte stream into the concatenated raw bytes. */
export async function drainBytes(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  const reader = stream.getReader();
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    parts.push(value);
    total += value.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Drain a frame stream into an array. */
export async function drainFrames(
  stream: ReadableStream<SseFrame>,
): Promise<SseFrame[]> {
  const out: SseFrame[] = [];
  const reader = stream.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    out.push(value);
  }
  return out;
}

/** The ordered `event:` names in a serialized SSE body (Rust `sse_event_names`). */
export function eventNames(body: string): string[] {
  return body
    .split("\n")
    .filter((line) => line.startsWith("event: "))
    .map((line) => line.slice("event: ".length));
}

/** Every JSON payload emitted under a given event name. */
export function jsonEvents(body: string, event: string): unknown[] {
  return body
    .split("\n\n")
    .map((frame) => {
      let name: string | undefined;
      const data: string[] = [];
      for (const line of frame.split("\n")) {
        if (line.startsWith("event:")) {
          name = line.slice("event:".length).trim();
        } else if (line.startsWith("data:")) {
          const value = line.slice("data:".length);
          data.push(value.startsWith(" ") ? value.slice(1) : value);
        }
      }
      if (name !== event || data.length === 0) {
        return undefined;
      }
      try {
        return JSON.parse(data.join("\n")) as unknown;
      } catch {
        return undefined;
      }
    })
    .filter((value): value is unknown => value !== undefined);
}

/** A canonical OpenAI chat-completions SSE stream (text only + usage + DONE). */
export const OPENAI_TEXT_STREAM =
  'data: {"id":"chatcmpl-1","model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant","content":"Hel"}}]}\n\n' +
  'data: {"choices":[{"index":0,"delta":{"content":"lo"}}]}\n\n' +
  'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}\n\n' +
  "data: [DONE]\n\n";

/** A canonical OpenAI stream carrying an interleaved tool call. */
export const OPENAI_TOOL_STREAM =
  'data: {"choices":[{"index":0,"delta":{"content":"calling"}}]}\n\n' +
  'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"lookup","arguments":"{\\"q\\":"}}]}}]}\n\n' +
  'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\\"x\\"}"}}]}}]}\n\n' +
  'data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}\n\n' +
  "data: [DONE]\n\n";
