/**
 * THE STREAMED `/v1/responses` ANSWER IS SCREENED CONTENT — every frame of it
 * (issue #778).
 *
 * ## Why this file goes through `SELF.fetch` rather than the screener
 *
 * `test/guardrails/responses-stream.test.ts` drives `screenSseFrames` directly
 * and pins the frame vocabulary. It cannot answer the question that decides
 * whether #778 is a real leak or a hypothetical one: are those frames REACHABLE
 * on the deployed wiring? They are, and the demonstration needs the whole tower
 * — `src/worker.ts` → `GATEWAY_MIDDLEWARE` → `guardrails()` → the inner
 * inference router → `streaming/responses.ts::ResponsesStreamNormalizer` — with
 * only the outbound provider `fetch` stood in for.
 *
 * The leg below is the one that needed no exotic deployment at all. An
 * OpenAI-compatible upstream streams a TOOL CALL; the Responses normalizer turns
 * it into `response.function_call_arguments.delta` frames and one accumulated
 * `response.function_call_arguments.done`. Before #778 the response-stage
 * screener read `response.output_text.delta` and nothing else, so both frames
 * went to the client verbatim — while the SAME model output through
 * `/v1/chat/completions` was screened, because that dialect's arm has always
 * folded `tool_calls[].function.arguments` into the screened text. One gateway,
 * one policy, two answers, decided by which ingress dialect the caller picked.
 *
 * ## What each assertion states
 *
 * The surviving text, not just the absence of the marker. A screener that
 * dropped the tool call entirely would also make the secret vanish, and that is
 * a protocol break rather than a redaction.
 */
import { SELF, env } from "cloudflare:test";
import { PROBE_SECRET } from "@ferrogate/guardrails";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { FINGERPRINT_SECRET_REF, secretScanPolicy } from "../guardrails/fixtures.js";

const BASE = "https://gw.test";
const PROVIDER_HOST = "api.responses-stream-guard.example";

/** Response stage, enforce mode, REDACT — so the stream survives the finding. */
const REDACT_POLICY = secretScanPolicy({
  policyId: "responses-stream-redact-e2e",
  stage: "response",
  onFail: [{ kind: "redact", code: "guardrail_redacted", message: "secret redacted" }],
});

const OVERRIDES: Record<string, string> = {
  GATEWAY_PROVIDERS: JSON.stringify([
    { name: "probe", kind: "openai", base_url: `https://${PROVIDER_HOST}/v1` },
  ]),
  GATEWAY_MODELS: JSON.stringify([
    { name: "guard-probe", provider: "probe", provider_model: "guard-probe-physical" },
  ]),
  GATEWAY_NATIVE_API_KEYS: JSON.stringify([
    { key: "fg_stream_guard", id: "key_stream_guard", tenant_id: "tenant_a", scopes: [] },
  ]),
  // Must be on `env` before the FIRST request in this file: `guardrails()`
  // memoizes the compiled engine per `env` object.
  GATEWAY_GUARDRAIL_POLICIES: JSON.stringify([REDACT_POLICY]),
  [FINGERPRINT_SECRET_REF]: "test-fingerprint-key",
};

const ORIGINAL: Record<string, unknown> = {};
const mutable = env as unknown as Record<string, unknown>;

beforeAll(() => {
  for (const [name, value] of Object.entries(OVERRIDES)) {
    ORIGINAL[name] = mutable[name];
    mutable[name] = value;
  }
});

afterAll(() => {
  for (const [name, value] of Object.entries(ORIGINAL)) {
    mutable[name] = value;
  }
});

interface Upstream {
  restore(): void;
}

/** Stream `sse` back from the probe provider; anything else falls through. */
function stubUpstreamSse(sse: string): Upstream {
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (new URL(url).hostname !== PROVIDER_HOST) {
      return await original(input as RequestInfo, init);
    }
    return new Response(sse, {
      status: 200,
      headers: { "content-type": "text/event-stream" },
    });
  }) as typeof fetch;
  return { restore: () => void (globalThis.fetch = original) };
}

let upstream: Upstream | undefined;

afterEach(() => {
  upstream?.restore();
  upstream = undefined;
});

function streamResponses(body: unknown): Promise<Response> {
  return SELF.fetch(`${BASE}/v1/responses`, {
    method: "POST",
    headers: {
      authorization: "Bearer fg_stream_guard",
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

/** The `delta`/`arguments` payloads of every frame with this event name. */
function fieldOf(sse: string, event: string, field: string): string[] {
  const out: string[] = [];
  let current: string | undefined;
  for (const block of sse.split("\n\n")) {
    current = undefined;
    let data: string | undefined;
    for (const line of block.split("\n")) {
      if (line.startsWith("event:")) current = line.slice("event:".length).trim();
      if (line.startsWith("data:")) data = line.slice("data:".length).trim();
    }
    if (current !== event || data === undefined || data === "[DONE]") continue;
    const value = (JSON.parse(data) as Record<string, unknown>)[field];
    if (typeof value === "string") out.push(value);
  }
  return out;
}

describe("a streamed /v1/responses tool call is screened (#778)", () => {
  it("redacts the argument deltas AND the accumulated arguments frame", async () => {
    // A chat-dialect upstream streaming one tool call in two fragments. The
    // secret straddles the fragment boundary, so this also exercises the carry
    // window on a frame type that never reached it before.
    const head = PROBE_SECRET.slice(0, 8);
    const tail = PROBE_SECRET.slice(8);
    upstream = stubUpstreamSse(
      `data: ${JSON.stringify({
        choices: [
          {
            delta: {
              tool_calls: [
                {
                  index: 0,
                  id: "call_1",
                  function: { name: "store", arguments: `{"key":"${head}` },
                },
              ],
            },
          },
        ],
      })}\n\n` +
        `data: ${JSON.stringify({
          choices: [
            {
              delta: {
                tool_calls: [{ index: 0, function: { arguments: `${tail}"}` } }],
              },
            },
          ],
        })}\n\n` +
        "data: [DONE]\n\n",
    );

    const res = await streamResponses({
      model: "guard-probe",
      input: "store my key",
      stream: true,
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/event-stream");
    const sse = await res.text();

    // THE ASSERTION. Before #778 both of these frames carried the key verbatim.
    expect(sse).not.toContain(PROBE_SECRET);

    // The tool call is still a tool call: the frames arrive, the accumulated
    // arguments frame arrives, and only the secret span is gone.
    const done = fieldOf(sse, "response.function_call_arguments.done", "arguments");
    expect(done).toHaveLength(1);
    expect(done[0]).toContain('"key"');
    expect(done[0]).not.toContain(tail);
    expect(fieldOf(sse, "response.function_call_arguments.delta", "delta").length).toBeGreaterThan(
      0,
    );
    // ...and the stream still ends the way a client expects.
    expect(sse).toContain("event: response.completed");
    expect(sse.trimEnd().endsWith("data: [DONE]")).toBe(true);
  });

  it("a clean tool call is relayed unchanged — no over-redaction", async () => {
    upstream = stubUpstreamSse(
      `data: ${JSON.stringify({
        choices: [
          {
            delta: {
              tool_calls: [
                {
                  index: 0,
                  id: "call_2",
                  function: { name: "lookup", arguments: '{"city":"Berlin"}' },
                },
              ],
            },
          },
        ],
      })}\n\n` + "data: [DONE]\n\n",
    );

    const res = await streamResponses({
      model: "guard-probe",
      input: "weather",
      stream: true,
    });
    const sse = await res.text();
    expect(fieldOf(sse, "response.function_call_arguments.done", "arguments")).toEqual([
      '{"city":"Berlin"}',
    ]);
  });
});
