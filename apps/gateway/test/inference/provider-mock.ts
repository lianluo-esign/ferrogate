/**
 * Outbound-provider interception for the inference tests.
 *
 * `docs/rewrite/TESTING.md` §2 prescribes MSW for this. **MSW is not installed
 * in this workspace** (`node_modules/msw` is absent and this agent must not run
 * `bun install`), so the same interception is implemented with a
 * `globalThis.fetch` stub. The seam is identical either way: the gateway's
 * `fetchDispatcher` reads `globalThis.fetch` at CALL time (never captures it at
 * module load) precisely so it can be intercepted, and the handlers are
 * exercised through their real dispatch path — no dependency injection
 * shortcut, no mocked adapter.
 *
 * // PORT-TODO(docs/rewrite/TESTING.md §2): swap `interceptProviderFetch` for
 * // `setupServer(...)` + `http.post(...)` once `msw` is a devDependency. Only
 * // this file changes; the tests call the same helpers.
 */
import { expect } from "vitest";

/** One intercepted outbound call. */
export interface RecordedRequest {
  readonly url: string;
  readonly method: string;
  readonly headers: Record<string, string>;
  readonly body: unknown;
}

/** Handler signature: return a `Response`, or `undefined` to fall through. */
export type ProviderHandler = (request: RecordedRequest) => Response | undefined;

export interface ProviderInterceptor {
  /** Every outbound request seen, in order. */
  readonly requests: readonly RecordedRequest[];
  /** The most recent outbound request (throws when there was none). */
  lastRequest(): RecordedRequest;
  /** Restore the real `fetch`. */
  restore(): void;
}

/**
 * Install a `globalThis.fetch` stub for the duration of a test.
 *
 * `vi.stubGlobal` is deliberately NOT used: it is unreliable for `fetch` in
 * workerd, where the global is an own accessor on the module scope. A plain
 * assignment + restore is both sufficient and precise.
 */
export function interceptProviderFetch(handler: ProviderHandler): ProviderInterceptor {
  const original = globalThis.fetch;
  const requests: RecordedRequest[] = [];

  const stub = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const method = init?.method ?? (input instanceof Request ? input.method : "GET");
    const headers: Record<string, string> = {};
    new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined)).forEach(
      (value, key) => {
        headers[key.toLowerCase()] = value;
      },
    );
    let body: unknown;
    const rawBody = init?.body;
    if (typeof rawBody === "string") {
      try {
        body = JSON.parse(rawBody);
      } catch {
        body = rawBody;
      }
    } else if (rawBody instanceof Uint8Array) {
      body = new TextDecoder().decode(rawBody);
    }

    const recorded: RecordedRequest = { url, method, headers, body };
    requests.push(recorded);

    const response = handler(recorded);
    if (response === undefined) {
      throw new Error(`unhandled outbound request: ${method} ${url}`);
    }
    return response;
  }) as typeof globalThis.fetch;

  globalThis.fetch = stub;

  return {
    requests,
    lastRequest(): RecordedRequest {
      const last = requests.at(-1);
      expect(last, "expected the gateway to have dispatched an upstream request").toBeDefined();
      return last as RecordedRequest;
    },
    restore(): void {
      globalThis.fetch = original;
    },
  };
}

/** A JSON provider response. */
export function providerJson(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * A canned SSE provider response.
 *
 * `frames` are raw SSE frame bodies WITHOUT the trailing blank line; the
 * separator is added here so a test declares intent, not framing. The stream is
 * emitted one chunk per frame so the gateway's `TransformStream` chain is
 * exercised across real chunk boundaries (a single-chunk body would not prove
 * incremental parsing).
 */
export function providerSse(frames: readonly string[], status = 200): Response {
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const frame of frames) {
        controller.enqueue(encoder.encode(`${frame}\n\n`));
      }
      controller.close();
    },
  });
  return new Response(stream, {
    status,
    headers: { "content-type": "text/event-stream" },
  });
}

/**
 * An SSE response whose headers are a clean `200` and whose BODY then faults.
 *
 * This is the shape the failover ladder must never retry: the status said
 * success, the gateway committed to the stream and handed the client a piped
 * body, and only then did the upstream break. `frames` are delivered first so
 * the fault lands strictly AFTER bytes have been flushed — a stream that errors
 * before its first chunk would not test the point of no return.
 */
export function providerSseThatFaults(
  frames: readonly string[],
  reason = "upstream connection reset",
): Response {
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const frame of frames) {
        controller.enqueue(encoder.encode(`${frame}\n\n`));
      }
      controller.error(new Error(reason));
    },
  });
  return new Response(stream, {
    status: 200,
    headers: { "content-type": "text/event-stream" },
  });
}

/** Build the exact bytes {@link providerSse} would emit, for byte-for-byte asserts. */
export function sseBytes(frames: readonly string[]): string {
  return frames.map((frame) => `${frame}\n\n`).join("");
}

/** A canonical OpenAI chat-completion SSE stream ending with a usage frame. */
export const OPENAI_CHAT_STREAM_FRAMES: readonly string[] = [
  'data: {"id":"chatcmpl-test","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":"Hel"},"finish_reason":null}]}',
  'data: {"id":"chatcmpl-test","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":"lo"},"finish_reason":null}]}',
  'data: {"id":"chatcmpl-test","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}',
  'data: {"id":"chatcmpl-test","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[],"usage":{"prompt_tokens":11,"completion_tokens":4,"total_tokens":15}}',
  "data: [DONE]",
];

/** Read a `Response` body to a string without losing the exact bytes. */
export async function readBody(response: Response): Promise<string> {
  const body = response.body;
  if (body === null) {
    return "";
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    chunks.push(value);
    total += value.byteLength;
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
}
