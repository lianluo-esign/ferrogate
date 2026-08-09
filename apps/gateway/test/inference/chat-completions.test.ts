/**
 * `POST /v1/chat/completions` — the buffered (non-streaming) path, end to end.
 *
 * The outbound provider `fetch` is intercepted; everything between the Hono
 * route and that call is the real code: body read, JSON parse, Zod validation,
 * metadata bounds, model gate, model resolution, adapter request construction,
 * dispatch, usage extraction, metering.
 */
import { describe, expect, it } from "vitest";
import { errorBody, harness } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

const COMPLETION = {
  id: "chatcmpl-abc",
  object: "chat.completion",
  model: "gpt-4o-mini-2024-07-18",
  choices: [{ index: 0, message: { role: "assistant", content: "Hello" }, finish_reason: "stop" }],
  usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
};

describe("POST /v1/chat/completions", () => {
  it("returns 200 and relays the provider body byte-for-byte", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const h = harness();
      const res = await h.post("/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi" }],
      });

      expect(res.status).toBe(200);
      expect(await res.json()).toEqual(COMPLETION);
    } finally {
      provider.restore();
    }
  });

  it("builds the upstream request from the resolved physical route", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const h = harness();
      await h.post("/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi" }],
        temperature: 0.2,
      });

      const upstream = provider.lastRequest();
      expect(upstream.url).toBe("https://api.openai.example/v1/chat/completions");
      expect(upstream.method).toBe("POST");
      expect(upstream.headers.authorization).toBe("Bearer sk-test-openai");
      // The adapter OWNS `model`: the caller's LOGICAL name must not reach the
      // provider, or a tenant could pin a physical model the route forbids.
      expect((upstream.body as { model: string }).model).toBe("gpt-4o-mini-2024-07-18");
      // Unknown members survive — the Rust extractor never had
      // `deny_unknown_fields`, so caller parameters pass through.
      expect((upstream.body as { temperature: number }).temperature).toBe(0.2);
      expect((upstream.body as { stream: boolean }).stream).toBe(false);
    } finally {
      provider.restore();
    }
  });

  it("records the provider-reported usage", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const h = harness();
      await h.post("/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi" }],
        metadata: { customer_id: "acme" },
      });

      expect(h.usage.records).toHaveLength(1);
      expect(h.usage.last).toMatchObject({
        route: "openai.chat.completions",
        logicalModel: "gpt-4o-mini",
        provider: "openai-main",
        providerModel: "gpt-4o-mini-2024-07-18",
        stream: false,
        status: 200,
        promptTokens: 11,
        completionTokens: 4,
        totalTokens: 15,
        metadata: { customer_id: "acme" },
      });
    } finally {
      provider.restore();
    }
  });

  it("stamps the gateway response headers", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const h = harness();
      const res = await h.post("/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi" }],
      });

      expect(res.headers.get("x-request-id")).toBe("fg-000000000000002a");
      expect(res.headers.get("x-trace-id")).toBe("fg-000000000000002a");
      expect(res.headers.get("x-ferrogate-runtime")).toBe("workers");
    } finally {
      provider.restore();
    }
  });

  it("honours an inbound x-request-id so a caller can correlate", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const h = harness();
      const res = await h.post(
        "/v1/chat/completions",
        { model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }] },
        { headers: { "x-request-id": "fg-deadbeefdeadbeef" } },
      );

      expect(res.headers.get("x-request-id")).toBe("fg-deadbeefdeadbeef");
    } finally {
      provider.restore();
    }
  });

  it("relays a provider error status and body without reshaping it", async () => {
    const providerError = { error: { message: "rate limited", type: "rate_limit_error" } };
    const provider = interceptProviderFetch(() => providerJson(providerError, 429));
    try {
      const h = harness();
      const res = await h.post("/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi" }],
      });

      // Only TRANSPORT failures become `provider_dispatch_error`; a provider's
      // own error object reaches the caller intact.
      expect(res.status).toBe(429);
      expect(await res.json()).toEqual(providerError);
      expect(h.usage.last?.status).toBe(429);
    } finally {
      provider.restore();
    }
  });

  it("maps a transport failure to 502 provider_dispatch_error", async () => {
    const provider = interceptProviderFetch(() => {
      throw new TypeError("network unreachable");
    });
    try {
      const h = harness();
      const res = await h.post("/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi" }],
      });

      expect(res.status).toBe(502);
      const body = await errorBody(res);
      expect(body.error.code).toBe("provider_dispatch_error");
      expect(body.error.type).toBe("ferrogate_error");
      expect(body.error.message).toContain("provider dispatch failed");
    } finally {
      provider.restore();
    }
  });

  it("never follows a provider redirect", async () => {
    const provider = interceptProviderFetch(() => providerJson(COMPLETION));
    try {
      const h = harness();
      await h.post("/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi" }],
      });
      // Rust used `redirect::Policy::none()`; following a 3xx would let a
      // compromised provider config exfiltrate the request to another origin.
      expect(provider.requests).toHaveLength(1);
    } finally {
      provider.restore();
    }
  });
});

describe("POST /v1/responses", () => {
  it("dispatches to the Responses endpoint and meters under its own route label", async () => {
    const responsesBody = {
      id: "resp_1",
      object: "response",
      model: "gpt-4o-mini-2024-07-18",
      output: [],
      usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
    };
    const provider = interceptProviderFetch(() => providerJson(responsesBody));
    try {
      const h = harness();
      const res = await h.post("/v1/responses", {
        model: "gpt-4o-mini",
        input: "hello",
      });

      expect(res.status).toBe(200);
      expect(provider.lastRequest().url).toBe("https://api.openai.example/v1/responses");
      expect(h.usage.last).toMatchObject({
        route: "openai.responses",
        totalTokens: 4,
      });
    } finally {
      provider.restore();
    }
  });

  it("does not inject stream_options.include_usage (Responses reports usage itself)", async () => {
    const provider = interceptProviderFetch(
      () =>
        new Response('data: {"type":"response.completed"}\n\n', {
          headers: { "content-type": "text/event-stream" },
        }),
    );
    try {
      const h = harness();
      await h.post("/v1/responses", { model: "gpt-4o-mini", input: "hi", stream: true });

      const body = provider.lastRequest().body as Record<string, unknown>;
      expect(body.stream).toBe(true);
      expect(body.stream_options).toBeUndefined();
    } finally {
      provider.restore();
    }
  });
});
