/**
 * The four non-chat inference operations: `listModels`, `createMessage`,
 * `createEmbedding`, `createImage`.
 */
import { describe, expect, it } from "vitest";
import { harness, tenantCaller } from "./fixtures.js";
import { interceptProviderFetch, providerJson, providerSse, readBody } from "./provider-mock.js";

// ---------------------------------------------------------------------------
// GET /v1/models — `listModels`
// ---------------------------------------------------------------------------

describe("GET /v1/models", () => {
  it("lists every enabled model in the OpenAI catalog shape", async () => {
    const res = await harness().get("/v1/models");
    expect(res.status).toBe(200);

    const body = (await res.json()) as {
      object: string;
      data: Array<{ id: string; object: string; created: number; owned_by: string }>;
    };
    expect(body.object).toBe("list");
    expect(body.data.map((model) => model.id)).toEqual([
      "gpt-4o-mini",
      "claude-logical",
      "text-embed",
      "image-model",
      "acme-private",
    ]);
    // CHANGED DELIBERATELY (issue #670). This assertion used to be the exact
    // four-key OpenAI object, which is now the PREFIX of the answer: the
    // listing additionally carries `capabilities`, `context_window`,
    // `modalities` and `pricing` so a client can discover what a model does and
    // what it costs (`src/inference/model-metadata.ts`). The four original keys
    // are asserted unchanged, byte for byte; the metadata for THESE fixtures is
    // the capability-neutral/unpriced case, which
    // `test/inference/model-discovery.test.ts` covers in full alongside the
    // declared ones.
    expect(body.data[0]).toEqual({
      id: "gpt-4o-mini",
      object: "model",
      created: 0,
      owned_by: "openai-main",
      capabilities: [],
      context_window: null,
      modalities: { input: ["text"], output: ["text"] },
      pricing: { currency: "USD", unit: "per_1m_tokens", input: null, output: null },
    });
  });

  it("omits disabled models", async () => {
    const res = await harness().get("/v1/models");
    const body = (await res.json()) as { data: Array<{ id: string }> };
    expect(body.data.map((model) => model.id)).not.toContain("retired-model");
  });

  it("hides another tenant's private model from the listing", async () => {
    // The listing filter and the invocation gate must agree; when they drifted,
    // the listing leaked other tenants' logical names and their provider
    // mapping even though invocation was blocked downstream (issue #515).
    const res = await harness({ caller: tenantCaller("globex") }).get("/v1/models");
    const body = (await res.json()) as { data: Array<{ id: string }> };
    expect(body.data.map((model) => model.id)).not.toContain("acme-private");
    expect(body.data.map((model) => model.id)).toContain("gpt-4o-mini");
  });

  it("shows the owning tenant its own private model", async () => {
    const res = await harness({ caller: tenantCaller("acme") }).get("/v1/models");
    const body = (await res.json()) as { data: Array<{ id: string }> };
    expect(body.data.map((model) => model.id)).toContain("acme-private");
  });

  it("carries the gateway response headers", async () => {
    const res = await harness().get("/v1/models");
    expect(res.headers.get("x-request-id")).toBe("fg-000000000000002a");
    expect(res.headers.get("x-ferrogate-runtime")).toBe("workers");
  });

  it("carries the request-id header the Anthropic SDK reads", async () => {
    const res = await harness().get("/v1/models");
    expect(res.headers.get("request-id")).toBe("fg-000000000000002a");
  });

  it("answers in the Anthropic dialect when the Anthropic SDK sends anthropic-version", async () => {
    const res = await harness().get("/v1/models", {
      headers: { "anthropic-version": "2023-06-01" },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: Array<Record<string, unknown>> };
    expect(body.data[0]).toMatchObject({
      id: expect.any(String),
      type: "model",
      display_name: expect.any(String),
      created_at: expect.any(String),
    });
    // The OpenAI-specific fields should NOT be present on the Anthropic ingress.
    expect((body.data[0] as Record<string, unknown>)["object"]).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// POST /v1/messages — `createMessage`
// ---------------------------------------------------------------------------

const ANTHROPIC_MESSAGE = {
  id: "msg_01",
  type: "message",
  role: "assistant",
  model: "claude-3-5-sonnet-20241022",
  content: [{ type: "text", text: "hello" }],
  stop_reason: "end_turn",
  usage: { input_tokens: 7, output_tokens: 3 },
};

describe("POST /v1/messages", () => {
  it("dispatches to an Anthropic upstream with the native headers", async () => {
    const provider = interceptProviderFetch(() => providerJson(ANTHROPIC_MESSAGE));
    try {
      const h = harness();
      const res = await h.post("/v1/messages", {
        model: "claude-logical",
        max_tokens: 256,
        system: "be concise",
        messages: [{ role: "user", content: "hi" }],
      });

      expect(res.status).toBe(200);
      const upstream = provider.lastRequest();
      expect(upstream.url).toBe("https://api.anthropic.example/v1/messages");
      expect(upstream.headers["x-api-key"]).toBe("sk-test-anthropic");
      expect(upstream.headers["anthropic-version"]).toBe("2023-06-01");
      expect(upstream.headers["authorization"]).toBeUndefined();

      const body = upstream.body as Record<string, unknown>;
      expect(body["model"]).toBe("claude-3-5-sonnet-20241022");
      expect(body["max_tokens"]).toBe(256);
      // The system prompt is the TOP-LEVEL parameter. `to_chat_completions`
      // folds it into `messages[0]` as a `system`-role turn on the way in
      // because that is the shape the OpenAI-side estimator and adapters read,
      // and the Anthropic adapter lifts it back out on the way to the wire —
      // the Messages API accepts only `user` and `assistant` turns, so the old
      // body was one a real upstream would have rejected outright (issue #725).
      expect(body["system"]).toBe("be concise");
      expect(body["messages"]).toEqual([{ role: "user", content: "hi" }]);
    } finally {
      provider.restore();
    }
  });

  it("defaults max_tokens when the caller omits it (Anthropic requires it)", async () => {
    const provider = interceptProviderFetch(() => providerJson(ANTHROPIC_MESSAGE));
    try {
      await harness().post("/v1/messages", {
        model: "claude-logical",
        messages: [{ role: "user", content: "hi" }],
      });
      expect((provider.lastRequest().body as Record<string, unknown>)["max_tokens"]).toBe(1024);
    } finally {
      provider.restore();
    }
  });

  it("passes an Anthropic-shaped response straight back", async () => {
    const provider = interceptProviderFetch(() => providerJson(ANTHROPIC_MESSAGE));
    try {
      const res = await harness().post("/v1/messages", {
        model: "claude-logical",
        messages: [{ role: "user", content: "hi" }],
      });
      expect(await res.json()).toEqual(ANTHROPIC_MESSAGE);
    } finally {
      provider.restore();
    }
  });

  it("reshapes an OpenAI-family completion into a native Anthropic Message", async () => {
    const provider = interceptProviderFetch(() =>
      providerJson({
        id: "chatcmpl-42",
        model: "gpt-4o-mini-2024-07-18",
        choices: [
          { index: 0, message: { role: "assistant", content: "hey" }, finish_reason: "stop" },
        ],
        usage: { prompt_tokens: 5, completion_tokens: 2, total_tokens: 7 },
      }),
    );
    try {
      // `gpt-4o-mini` resolves to an OpenAI route, so the Anthropic ingress has
      // to translate both directions.
      const res = await harness().post("/v1/messages", {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi" }],
      });

      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({
        id: "msg-42",
        type: "message",
        role: "assistant",
        model: "gpt-4o-mini-2024-07-18",
        content: [{ type: "text", text: "hey" }],
        stop_reason: "end_turn",
        stop_sequence: null,
        usage: { input_tokens: 5, output_tokens: 2 },
      });
    } finally {
      provider.restore();
    }
  });

  it("translates tool_use / tool_result blocks into the OpenAI wire shape", async () => {
    const provider = interceptProviderFetch(() =>
      providerJson({ id: "chatcmpl-1", choices: [], usage: {} }),
    );
    try {
      await harness().post("/v1/messages", {
        model: "gpt-4o-mini",
        messages: [
          {
            role: "assistant",
            content: [{ type: "tool_use", id: "toolu_1", name: "lookup", input: { q: "x" } }],
          },
          {
            role: "user",
            content: [{ type: "tool_result", tool_use_id: "toolu_1", content: "42" }],
          },
        ],
        tools: [{ name: "lookup", description: "d", input_schema: { type: "object" } }],
        tool_choice: { type: "any" },
      });

      const body = provider.lastRequest().body as Record<string, unknown>;
      const messages = body["messages"] as Array<Record<string, unknown>>;
      expect(messages[0]).toMatchObject({
        role: "assistant",
        tool_calls: [
          { id: "toolu_1", type: "function", function: { name: "lookup", arguments: '{"q":"x"}' } },
        ],
      });
      expect(messages[1]).toEqual({ role: "tool", tool_call_id: "toolu_1", content: "42" });
      expect(body["tools"]).toEqual([
        {
          type: "function",
          function: { name: "lookup", description: "d", parameters: { type: "object" } },
        },
      ]);
      // Anthropic `any` maps to OpenAI `required`.
      expect(body["tool_choice"]).toBe("required");
    } finally {
      provider.restore();
    }
  });

  it("streams and meters with the Anthropic usage extractor", async () => {
    const provider = interceptProviderFetch(() =>
      providerSse([
        'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":12}}}',
        'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"text":"hi"}}',
        'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":6}}',
        'event: message_stop\ndata: {"type":"message_stop"}',
      ]),
    );
    try {
      const h = harness();
      const res = await h.post("/v1/messages", {
        model: "claude-logical",
        messages: [{ role: "user", content: "hi" }],
        stream: true,
      });
      const text = await readBody(res);

      expect(res.headers.get("content-type")).toBe("text/event-stream");
      expect(text).toContain("event: message_start");
      expect(text).toContain("event: message_stop");
      // input_tokens on `message_start`, output_tokens on `message_delta` —
      // merged, with the total derived.
      expect(h.usage.last).toMatchObject({
        route: "anthropic.messages",
        stream: true,
        promptTokens: 12,
        completionTokens: 6,
        totalTokens: 18,
      });
    } finally {
      provider.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// POST /v1/embeddings — `createEmbedding`
// ---------------------------------------------------------------------------

describe("POST /v1/embeddings", () => {
  const EMBEDDING_RESPONSE = {
    object: "list",
    data: [{ object: "embedding", index: 0, embedding: [0.1, 0.2] }],
    model: "text-embedding-3-small",
    usage: { prompt_tokens: 6, total_tokens: 6 },
  };

  it("returns 200 and never sets stream on the upstream", async () => {
    const provider = interceptProviderFetch(() => providerJson(EMBEDDING_RESPONSE));
    try {
      const h = harness();
      const res = await h.post("/v1/embeddings", { model: "text-embed", input: "hello" });

      expect(res.status).toBe(200);
      expect(await res.json()).toEqual(EMBEDDING_RESPONSE);
      const upstream = provider.lastRequest();
      expect(upstream.url).toBe("https://api.openai.example/v1/embeddings");
      // `EmbeddingsPlan` has no `stream` field at all — the adapter must not
      // invent one.
      expect((upstream.body as Record<string, unknown>)["stream"]).toBeUndefined();
      expect(h.usage.last).toMatchObject({ route: "openai.embeddings", promptTokens: 6 });
    } finally {
      provider.restore();
    }
  });

  it("accepts an array input", async () => {
    const provider = interceptProviderFetch(() => providerJson(EMBEDDING_RESPONSE));
    try {
      const res = await harness().post("/v1/embeddings", {
        model: "text-embed",
        input: ["a", "b"],
      });
      expect(res.status).toBe(200);
    } finally {
      provider.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// POST /v1/images/generations — `createImage`
// ---------------------------------------------------------------------------

describe("POST /v1/images/generations", () => {
  it("returns 200 and meters the count the provider actually returned", async () => {
    const provider = interceptProviderFetch(() =>
      providerJson({
        created: 1,
        data: [{ url: "https://cdn.example/a.png" }, { url: "https://cdn.example/b.png" }],
      }),
    );
    try {
      const h = harness();
      const res = await h.post("/v1/images/generations", {
        model: "image-model",
        prompt: "a cat",
        n: 99,
      });

      expect(res.status).toBe(200);
      expect(provider.lastRequest().url).toBe("https://api.openai.example/v1/images/generations");
      // The AUTHORITATIVE count is the response's, never the caller's `n` —
      // otherwise a hostile `n` bills for images that were never generated.
      expect(h.usage.last).toMatchObject({ route: "openai.images.generations", imageCount: 2 });
    } finally {
      provider.restore();
    }
  });
});
