/**
 * The seam that makes this suite meaningful: OFFICIAL SDK -> FerroGate.
 *
 * Both clients take a `fetch` override, and both are given `SELF.fetch`, i.e.
 * the deployed Worker running in `workerd`. Nothing between the client's
 * `.create()` call and the gateway's router is replaced — the SDK builds the
 * request (headers, JSON body, `Accept`), and the SDK parses the response
 * (streaming decode, error classification, pagination). That is the entire
 * point: a hand-rolled `fetch` in a test proves the WIRE, not the CLIENT, and
 * "change your base_url and nothing else" is a claim about the client.
 *
 * The only stub is the OUTBOUND provider `fetch`, so no test needs a real
 * OpenAI/Anthropic account or a network.
 */
import { SELF } from "cloudflare:test";
import Anthropic from "@anthropic-ai/sdk";
import OpenAI from "openai";

/** The origin the Worker is addressed on; any host works, `SELF` routes it. */
export const GATEWAY_ORIGIN = "https://gateway.conformance.test";

/** The healthy data-plane credential (see `vitest.config.ts`). */
export const CONFORMANCE_KEY = "fg_conformance";

/**
 * `SELF.fetch` as a plain `fetch`, which is what both SDKs expect.
 *
 * `SELF.fetch` must be called with `SELF` as the receiver, and the SDKs call
 * their `fetch` option unbound, hence the wrapper rather than a bare reference.
 */
const gatewayFetch = ((input: RequestInfo | URL, init?: RequestInit) =>
  SELF.fetch(input as RequestInfo, init)) as unknown as typeof fetch;

export interface ClientOptions {
  /** The bearer credential. Defaults to the healthy key. */
  readonly apiKey?: string;
  /**
   * SDK retries. Defaults to 0.
   *
   * Both SDKs retry 408/409/429/5xx twice by default with exponential backoff.
   * For a status assertion that is noise (and seconds of sleeping), so the
   * error-taxonomy cases pin it to 0 and `test/retries.test.ts` is the one file
   * that deliberately turns it back on.
   */
  readonly maxRetries?: number;
}

/** The official `openai` client, pointed at FerroGate and nothing else. */
export function openaiClient(options: ClientOptions = {}): OpenAI {
  return new OpenAI({
    apiKey: options.apiKey ?? CONFORMANCE_KEY,
    baseURL: `${GATEWAY_ORIGIN}/v1`,
    maxRetries: options.maxRetries ?? 0,
    fetch: gatewayFetch,
  });
}

/** The official `@anthropic-ai/sdk` client, pointed at FerroGate. */
export function anthropicClient(options: ClientOptions = {}): Anthropic {
  return new Anthropic({
    apiKey: options.apiKey ?? CONFORMANCE_KEY,
    baseURL: GATEWAY_ORIGIN,
    maxRetries: options.maxRetries ?? 0,
    fetch: gatewayFetch,
  });
}

/** One intercepted OUTBOUND (gateway -> provider) request. */
export interface UpstreamRequest {
  readonly url: string;
  readonly method: string;
  readonly headers: Record<string, string>;
  readonly body: unknown;
}

export interface UpstreamStub {
  readonly requests: readonly UpstreamRequest[];
  last(): UpstreamRequest;
  restore(): void;
}

/**
 * Intercept the gateway's outbound provider calls.
 *
 * `vi.stubGlobal` is deliberately not used — in workerd the `fetch` global is an
 * own accessor on the module scope and a plain assignment + restore is both
 * sufficient and precise. Requests to anything OTHER than a `.conformance.test`
 * upstream fall through to the real `fetch` so `SELF` still works.
 */
export function interceptUpstream(
  handler: (request: UpstreamRequest) => Response | Promise<Response>,
): UpstreamStub {
  const original = globalThis.fetch;
  const requests: UpstreamRequest[] = [];

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (!url.includes(".conformance.test")) {
      return await original(input as RequestInfo, init);
    }
    const headers: Record<string, string> = {};
    new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined)).forEach(
      (value, key) => {
        headers[key] = value;
      },
    );
    const rawBody = init?.body;
    let body: unknown;
    if (typeof rawBody === "string") {
      try {
        body = JSON.parse(rawBody);
      } catch {
        body = rawBody;
      }
    }
    const request: UpstreamRequest = {
      url,
      method: init?.method ?? "GET",
      headers,
      body,
    };
    requests.push(request);
    return await handler(request);
  }) as typeof fetch;

  return {
    requests,
    last(): UpstreamRequest {
      const last = requests.at(-1);
      if (last === undefined) throw new Error("no upstream request was made");
      return last;
    },
    restore(): void {
      globalThis.fetch = original;
    },
  };
}

/** A JSON provider response. */
export function upstreamJson(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** A provider SSE response built from already-serialized frames. */
export function upstreamSse(frames: readonly string[]): Response {
  return new Response(frames.join(""), {
    status: 200,
    headers: { "content-type": "text/event-stream" },
  });
}

/** `data: <json>\n\n`, the frame shape every OpenAI-dialect provider emits. */
export function dataFrame(payload: unknown): string {
  return `data: ${JSON.stringify(payload)}\n\n`;
}

/** The terminal frame of an OpenAI stream. */
export const DONE_FRAME = "data: [DONE]\n\n";
