/**
 * `WorkersAiAdapter` — the ninth family's REQUEST half (issue #673).
 *
 * The reachability of the family is proved elsewhere and deliberately so:
 * `apps/gateway/test/inference/workers-ai.test.ts` drives the deployed Worker
 * through `SELF.fetch`, because `ProviderAdapterRegistry` is not the registry
 * the data plane resolves against and a unit test here could be green while
 * every real request answered `model_not_found`.
 *
 * What THIS file owns is the part that test cannot see with a recording double:
 * the exact bytes the adapter would put on the wire, the error/usage/tool
 * grammars it reads back, and the two envelopes (binding-unwrapped vs REST
 * `{ result, success }`) it has to tolerate.
 */
import { describe, expect, test } from "vitest";

import { AdapterError, WorkersAiAdapter } from "../src/index.js";
import type { ProviderConfig, ProviderHeader } from "../src/index.js";

const bytes = (value: string): Uint8Array => new TextEncoder().encode(value);
const headerValue = (headers: ProviderHeader[], name: string): string | undefined =>
  headers.find((header) => header.name === name)?.value.exposeSecret();

const BASE = "https://api.cloudflare.com/client/v4/accounts/acct_1/ai";

function provider(apiKey?: string): ProviderConfig {
  return { name: "cf-ai", kind: "workers-ai", baseUrl: `${BASE}/`, apiKey };
}

const adapter = new WorkersAiAdapter();

describe("WorkersAiAdapter — chat completions", () => {
  test("addresses the model in the PATH and never copies it into the body", () => {
    const prepared = adapter.prepareChatCompletions(provider(), {
      logicalModel: "edge-chat",
      providerModel: "@cf/meta/llama-3.1-8b-instruct",
      stream: false,
      body: { model: "edge-chat", messages: [{ role: "user", content: "hi" }] },
    });

    // The `@` and the slashes are NOT percent-encoded: Cloudflare's own URLs
    // carry them raw, and encoding them 404s against the real API.
    expect(prepared.endpoint).toBe(`${BASE}/run/@cf/meta/llama-3.1-8b-instruct`);
    const body = prepared.body as Record<string, unknown>;
    expect(body["messages"]).toEqual([{ role: "user", content: "hi" }]);
    expect(body["stream"]).toBe(false);
    // A stray `model` would read, in a request log, as the thing being invoked
    // while the PATH decided otherwise. Same reason `azure.rs` deletes it.
    expect("model" in body).toBe(false);
  });

  test("forwards only the generation knobs the caller actually set", () => {
    const prepared = adapter.prepareChatCompletions(provider(), {
      logicalModel: "edge-chat",
      providerModel: "@cf/meta/llama-3.1-8b-instruct",
      stream: true,
      body: { messages: [], max_tokens: 256, temperature: 0.2 },
    });
    const body = prepared.body as Record<string, unknown>;
    expect(body).toEqual({ messages: [], stream: true, max_tokens: 256, temperature: 0.2 });
    // No invented defaults: Workers AI's own per-model defaults must apply.
    expect("top_p" in body).toBe(false);
    expect(prepared.stream).toBe(true);
  });

  test("no api key ⇒ NO authorization header — the binding needs no credential", () => {
    const prepared = adapter.prepareChatCompletions(provider(), {
      logicalModel: "m",
      providerModel: "@cf/x",
      stream: false,
      body: { messages: [] },
    });
    expect(headerValue(prepared.headers, "content-type")).toBe("application/json");
    expect(headerValue(prepared.headers, "authorization")).toBeUndefined();
  });

  test("an api key becomes a Bearer header, redacted in inspection", () => {
    const prepared = adapter.prepareChatCompletions(provider("cf-token"), {
      logicalModel: "m",
      providerModel: "@cf/x",
      stream: false,
      body: { messages: [] },
    });
    expect(headerValue(prepared.headers, "authorization")).toBe("Bearer cf-token");
    expect(JSON.stringify(prepared.headers)).not.toContain("cf-token");
  });

  test("refuses a body with no messages, and a foreign provider kind", () => {
    expect(() =>
      adapter.prepareChatCompletions(provider(), {
        logicalModel: "m",
        providerModel: "@cf/x",
        stream: false,
        body: { prompt: "hi" },
      }),
    ).toThrow(AdapterError);
    expect(() =>
      adapter.prepareChatCompletions(
        { ...provider(), kind: "openai" },
        { logicalModel: "m", providerModel: "@cf/x", stream: false, body: { messages: [] } },
      ),
    ).toThrow(/unsupported provider kind openai/);
  });

  test("refuses a model id that could climb out of the path or inject a query", () => {
    for (const providerModel of ["../../secrets", "@cf/x?token=1", "@cf/x#frag", "@cf/ x"]) {
      expect(
        () =>
          adapter.prepareChatCompletions(provider(), {
            logicalModel: "m",
            providerModel,
            stream: false,
            body: { messages: [] },
          }),
        providerModel,
      ).toThrow(AdapterError);
    }
  });
});

describe("WorkersAiAdapter — responses", () => {
  test("folds `instructions` into a leading system MESSAGE, not a `system` field", () => {
    const prepared = adapter.prepareResponses(provider(), {
      logicalModel: "edge-chat",
      providerModel: "@cf/meta/llama-3.1-8b-instruct",
      stream: false,
      body: { input: "hello", instructions: "be terse" },
    });
    const body = prepared.body as Record<string, unknown>;
    // Workers AI has no top-level `system` key; a `system` FIELD would be
    // silently dropped and the instruction would never reach the model.
    expect("system" in body).toBe(false);
    expect(body["messages"]).toEqual([
      { role: "system", content: "be terse" },
      { role: "user", content: "hello" },
    ]);
  });
});

describe("WorkersAiAdapter — embeddings", () => {
  test("sends `{ text }`, not OpenAI's `{ input }`", () => {
    const prepared = adapter.prepareEmbeddings(provider(), {
      logicalModel: "edge-embed",
      providerModel: "@cf/baai/bge-base-en-v1.5",
      body: { model: "edge-embed", input: ["a", "b"] },
    });
    expect(prepared.endpoint).toBe(`${BASE}/run/@cf/baai/bge-base-en-v1.5`);
    expect(prepared.body).toEqual({ text: ["a", "b"] });
    expect(prepared.stream).toBe(false);
  });

  test("translates the native answer to the OpenAI list, from BOTH envelopes", () => {
    const native = '{"shape":[1,2],"data":[[0.5,0.25]]}';
    const rest = `{"success":true,"errors":[],"result":${native}}`;
    const expected = {
      object: "list",
      data: [{ object: "embedding", index: 0, embedding: [0.5, 0.25] }],
      model: "edge-embed",
    };
    expect(adapter.translateEmbeddingsResponse(bytes(native), "edge-embed")).toEqual(expected);
    expect(adapter.translateEmbeddingsResponse(bytes(rest), "edge-embed")).toEqual(expected);
  });

  test("reports NO usage for embeddings rather than a fabricated zero", () => {
    const translated = adapter.translateEmbeddingsResponse(
      bytes('{"data":[[1]]}'),
      "edge-embed",
    ) as Record<string, unknown>;
    // A zero would be metered as a real reading of "this cost nothing".
    expect("usage" in translated).toBe(false);
  });

  test("refuses a response with no data array instead of inventing an empty list", () => {
    expect(() => adapter.translateEmbeddingsResponse(bytes('{"shape":[1]}'), "m")).toThrow(
      /missing a data array/,
    );
  });
});

describe("WorkersAiAdapter — usage extraction", () => {
  test("reads the OpenAI-named counters at the top level and under `result`", () => {
    const usage = '{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}';
    const expected = { promptTokens: 3, completionTokens: 5, totalTokens: 8 };
    expect(adapter.extractUsage(bytes(`{"response":"hi","usage":${usage}}`))).toEqual(expected);
    expect(adapter.extractUsage(bytes(`{"success":true,"result":{"usage":${usage}}}`))).toEqual(
      expected,
    );
  });

  test("returns undefined when nothing was reported", () => {
    // Not cosmetic: a partial reading that clobbered an earlier one would
    // under-meter, which is what `hasAnyUsage` guards in every family.
    expect(adapter.extractUsage(bytes('{"response":"hi"}'))).toBeUndefined();
    expect(adapter.extractUsage(bytes("not json"))).toBeUndefined();
  });
});

describe("WorkersAiAdapter — errors", () => {
  test("reads Cloudflare's `{ errors: [...] }` envelope, not OpenAI's `{ error }`", () => {
    const normalized = adapter.normalizeErrorResponse(
      400,
      "application/json",
      bytes('{"success":false,"errors":[{"code":7003,"message":"no route for that URI"}]}'),
      "req-1",
    );
    expect(normalized.status).toBe(400);
    const error = (normalized.body as Record<string, Record<string, unknown>>)["error"] as Record<
      string,
      unknown
    >;
    expect(error["message"]).toBe("no route for that URI");
    // Cloudflare codes are integers; the client-visible `code` stays a string,
    // as it is for every other family.
    expect(error["code"]).toBe("cloudflare_7003");
    expect(error["request_id"]).toBe("req-1");
  });

  test("falls back sanely when the body is not a Cloudflare envelope at all", () => {
    const normalized = adapter.normalizeErrorResponse(502, "text/html", bytes("<h1>bad</h1>"), "r");
    const error = (normalized.body as Record<string, Record<string, unknown>>)["error"] as Record<
      string,
      unknown
    >;
    expect(error["code"]).toBe("provider_error");
    expect(typeof error["message"]).toBe("string");
  });
});

describe("WorkersAiAdapter — tools", () => {
  test("injects OpenAI-shaped tool definitions, which Workers AI takes verbatim", () => {
    const injected = adapter.injectTools({ messages: [] }, [
      { name: "lookup", description: "find", input_schema: { type: "object" } },
    ]) as Record<string, unknown>;
    expect(injected["tools"]).toEqual([
      {
        type: "function",
        function: { name: "lookup", parameters: { type: "object" }, description: "find" },
      },
    ]);
  });

  test("extracts TOP-LEVEL `tool_calls` and synthesizes positional ids", () => {
    const calls = adapter.extractToolCalls(
      bytes('{"tool_calls":[{"name":"a","arguments":{"x":1}},{"name":"b","arguments":{}}]}'),
    );
    // Workers AI's run surface has no per-call id; an empty one would collide
    // across two calls in the same turn and `appendToolResults` could not
    // address either.
    expect(calls).toEqual([
      { id: "workers_ai_tool_0", name: "a", arguments: { x: 1 } },
      { id: "workers_ai_tool_1", name: "b", arguments: {} },
    ]);
    expect(calls[0]?.id).not.toBe(calls[1]?.id);
  });

  test("appends results as OpenAI `role: tool` messages", () => {
    const appended = adapter.appendToolResults({ messages: [{ role: "user", content: "hi" }] }, [
      { tool_call_id: "workers_ai_tool_0", content: { ok: true }, is_error: false },
    ]) as Record<string, unknown>;
    expect((appended["messages"] as unknown[])[1]).toEqual({
      role: "tool",
      tool_call_id: "workers_ai_tool_0",
      content: '{"ok":true}',
    });
  });
});
