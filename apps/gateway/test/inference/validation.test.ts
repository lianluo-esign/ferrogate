/**
 * Request-validation and admission rejections for every inference operation.
 *
 * Each assertion pins BOTH the HTTP status and the machine-readable `code`,
 * because the Rust tree gave distinct codes to failures that share a status
 * (`invalid_json` vs `invalid_request` vs `invalid_request_metadata`, all 400;
 * `model_disabled` vs `model_not_found`, both 400) and clients switch on them.
 */
import { describe, expect, it } from "vitest";
import { callerDenying, errorBody, harness } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

const OK = { id: "chatcmpl-x", choices: [], usage: { total_tokens: 1 } };

/** Run a request with the provider stubbed out; most of these never reach it. */
async function post(path: string, body: unknown, deps = {}): Promise<Response> {
  const provider = interceptProviderFetch(() => providerJson(OK));
  try {
    return await harness(deps).post(path, body);
  } finally {
    provider.restore();
  }
}

describe("body parsing", () => {
  it("rejects a non-JSON body with invalid_json, not invalid_request", async () => {
    const provider = interceptProviderFetch(() => providerJson(OK));
    try {
      const res = await harness().post("/v1/chat/completions", "{not json");
      expect(res.status).toBe(400);
      const body = await errorBody(res);
      expect(body.error.code).toBe("invalid_json");
      expect(body.error.message).toContain("invalid JSON body");
      expect(body.error.type).toBe("ferrogate_error");
      expect(body.error.request_id).toBe("fg-000000000000002a");
    } finally {
      provider.restore();
    }
  });

  it("accepts a JSON body sent without a JSON content-type", async () => {
    // Rust parsed the bytes regardless of `Content-Type`; Hono's own validator
    // would silently substitute `{}` and produce a spurious `invalid_request`.
    const provider = interceptProviderFetch(() => providerJson(OK));
    try {
      const h = harness();
      const res = await h.router.request("https://gw.test/v1/chat/completions", {
        method: "POST",
        body: JSON.stringify({ model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }] }),
      });
      expect(res.status).toBe(200);
    } finally {
      provider.restore();
    }
  });

  it("rejects an oversized body with payload_too_large before parsing it", async () => {
    const provider = interceptProviderFetch(() => providerJson(OK));
    try {
      const h = harness({ limits: { inferenceBodyMaxBytes: 64 } });
      const res = await h.post("/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "x".repeat(512) }],
      });

      expect(res.status).toBe(413);
      const body = await errorBody(res);
      expect(body.error.code).toBe("payload_too_large");
      expect(body.error.message).toBe("request body exceeds maximum size of 64 bytes");
      // Nothing was dispatched upstream.
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });
});

describe("Zod violations → 400 invalid_request", () => {
  it("rejects messages sent as a string", async () => {
    const res = await post("/v1/chat/completions", {
      model: "gpt-4o",
      messages: "not-an-array",
    });

    expect(res.status).toBe(400);
    const body = await errorBody(res);
    expect(body.error.code).toBe("invalid_request");
    expect(body.error.type).toBe("ferrogate_error");
    expect(body.error.message).toContain("invalid chat completion request");
    expect(body.error.message).toContain('must include a "messages" array');
  });

  it("rejects a missing model", async () => {
    const res = await post("/v1/chat/completions", { messages: [{ role: "user", content: "hi" }] });
    expect(res.status).toBe(400);
    expect((await errorBody(res)).error.code).toBe("invalid_request");
  });

  it("rejects a non-boolean stream", async () => {
    const res = await post("/v1/chat/completions", {
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "hi" }],
      stream: "true",
    });
    expect(res.status).toBe(400);
    expect((await errorBody(res)).error.code).toBe("invalid_request");
  });

  it("rejects a message element that is not an object", async () => {
    const res = await post("/v1/chat/completions", {
      model: "gpt-4o-mini",
      messages: ["hello"],
    });
    expect(res.status).toBe(400);
    expect((await errorBody(res)).error.code).toBe("invalid_request");
  });

  it("accepts the multimodal content-part array form", async () => {
    const res = await post("/v1/chat/completions", {
      model: "gpt-4o-mini",
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: "what is this" },
            { type: "image_url", image_url: { url: "https://img.example/a.png" } },
          ],
        },
      ],
    });
    expect(res.status).toBe(200);
  });

  it("accepts a role the schema never enumerated", async () => {
    // `role` is a free string in Rust; enumerating it here would reject
    // `developer` and every future role OpenAI adds.
    const res = await post("/v1/chat/completions", {
      model: "gpt-4o-mini",
      messages: [{ role: "developer", content: "be terse" }],
    });
    expect(res.status).toBe(200);
  });

  it("rejects a non-array messages on /v1/messages with the Anthropic wording", async () => {
    const res = await post("/v1/messages", { model: "claude-logical", messages: {} });
    expect(res.status).toBe(400);
    const body = await errorBody(res);
    expect(body.error.code).toBe("invalid_request");
    expect(body.error.message).toContain(
      'Anthropic messages request must include a "messages" array',
    );
  });

  it("rejects embeddings without a string-or-array input", async () => {
    const res = await post("/v1/embeddings", { model: "text-embed", input: 42 });
    expect(res.status).toBe(400);
    const body = await errorBody(res);
    expect(body.error.code).toBe("invalid_request");
    expect(body.error.message).toContain(
      'embeddings request must include a string or array "input" field',
    );
  });

  it("rejects an image generation with a blank prompt", async () => {
    const res = await post("/v1/images/generations", { model: "image-model", prompt: "   " });
    expect(res.status).toBe(400);
    const body = await errorBody(res);
    expect(body.error.code).toBe("invalid_request");
    expect(body.error.message).toContain(
      'image generation request must include a non-empty string "prompt" field',
    );
  });
});

describe("request metadata bounds (issue #171)", () => {
  it("rejects more than 8 entries with invalid_request_metadata", async () => {
    const metadata = Object.fromEntries(
      Array.from({ length: 9 }, (_unused, index) => [`key-${index}`, "value"]),
    );
    const res = await post("/v1/chat/completions", {
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "hi" }],
      metadata,
    });

    expect(res.status).toBe(400);
    const body = await errorBody(res);
    // Distinct from `invalid_request`: the SHAPE was fine, the BOUNDS were not.
    expect(body.error.code).toBe("invalid_request_metadata");
    expect(body.error.message).toBe("metadata supports at most 8 entries, got 9");
  });

  it("rejects an over-long key", async () => {
    const res = await post("/v1/chat/completions", {
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "hi" }],
      metadata: { ["k".repeat(65)]: "v" },
    });
    const body = await errorBody(res);
    expect(body.error.code).toBe("invalid_request_metadata");
    expect(body.error.message).toContain("exceeds the 64-byte limit");
  });

  it("rejects an over-long value", async () => {
    const res = await post("/v1/chat/completions", {
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "hi" }],
      metadata: { customer_id: "v".repeat(257) },
    });
    const body = await errorBody(res);
    expect(body.error.code).toBe("invalid_request_metadata");
    expect(body.error.message).toContain("exceeds the 256-byte limit");
  });

  it("measures the limits in UTF-8 bytes, not characters", async () => {
    // 100 × 3-byte characters = 300 bytes > 256, but only 100 JS characters.
    const res = await post("/v1/chat/completions", {
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "hi" }],
      metadata: { customer_id: "あ".repeat(100) },
    });
    expect((await errorBody(res)).error.code).toBe("invalid_request_metadata");
  });

  it("rejects non-string metadata values as invalid_request", async () => {
    const res = await post("/v1/chat/completions", {
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "hi" }],
      metadata: { count: 3 },
    });
    expect((await errorBody(res)).error.code).toBe("invalid_request");
  });

  it("accepts a map within every bound", async () => {
    const res = await post("/v1/chat/completions", {
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "hi" }],
      metadata: { customer_id: "acme" },
    });
    expect(res.status).toBe(200);
  });
});

describe("model admission", () => {
  it("returns 400 model_not_found for an unknown model", async () => {
    const res = await post("/v1/chat/completions", {
      model: "nope",
      messages: [{ role: "user", content: "hi" }],
    });
    expect(res.status).toBe(400);
    const body = await errorBody(res);
    expect(body.error.code).toBe("model_not_found");
    expect(body.error.message).toBe("unknown model nope");
  });

  it("returns 400 model_disabled for a configured-but-disabled model", async () => {
    const res = await post("/v1/chat/completions", {
      model: "retired-model",
      messages: [{ role: "user", content: "hi" }],
    });
    expect(res.status).toBe(400);
    const body = await errorBody(res);
    expect(body.error.code).toBe("model_disabled");
    expect(body.error.message).toBe("model retired-model is disabled");
  });

  it("returns 403 model_not_allowed when the key denies the model", async () => {
    const res = await post(
      "/v1/chat/completions",
      { model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }] },
      { caller: callerDenying("gpt-4o-mini") },
    );
    expect(res.status).toBe(403);
    const body = await errorBody(res);
    expect(body.error.code).toBe("model_not_allowed");
    expect(body.error.message).toBe("API key is not allowed to use model gpt-4o-mini");
  });

  it("checks the key's model gate BEFORE resolution so it cannot probe the catalog", async () => {
    // A denied key asking for a model that does not exist must still get the
    // 403, otherwise the 400/403 split leaks which logical names are configured.
    const res = await post(
      "/v1/chat/completions",
      { model: "does-not-exist", messages: [{ role: "user", content: "hi" }] },
      { caller: callerDenying("does-not-exist") },
    );
    expect(res.status).toBe(403);
    expect((await errorBody(res)).error.code).toBe("model_not_allowed");
  });

  it("hides another tenant's private model behind model_not_found", async () => {
    const res = await post(
      "/v1/chat/completions",
      { model: "acme-private", messages: [{ role: "user", content: "hi" }] },
      { caller: () => ({ scope: { kind: "tenant" as const, tenantId: "globex" } }) },
    );
    expect(res.status).toBe(400);
    // Not 403: a tenant must not be able to distinguish "exists but is not
    // mine" from "does not exist" (issue #515).
    expect((await errorBody(res)).error.code).toBe("model_not_found");
  });

  it("lets the owning tenant invoke its private model", async () => {
    const res = await post(
      "/v1/chat/completions",
      { model: "acme-private", messages: [{ role: "user", content: "hi" }] },
      { caller: () => ({ scope: { kind: "tenant" as const, tenantId: "acme" } }) },
    );
    expect(res.status).toBe(200);
  });
});

describe("capability gating (issue #275)", () => {
  it("rejects image generation on an Anthropic route with a precise capability error", async () => {
    const res = await post("/v1/images/generations", {
      model: "claude-logical",
      prompt: "a cat",
    });

    expect(res.status).toBe(400);
    const body = await errorBody(res);
    // Distinct from "unknown provider", which would be misleading here.
    expect(body.error.code).toBe("model_capability_unsupported");
    expect(body.error.message).toBe("provider kind anthropic does not support image generation");
  });

  it("rejects embeddings on an Anthropic route", async () => {
    const res = await post("/v1/embeddings", { model: "claude-logical", input: "hi" });
    expect(res.status).toBe(502);
    expect((await errorBody(res)).error.code).toBe("provider_adapter_error");
  });

  it("fails closed on a provider family that does not exist", async () => {
    const provider = interceptProviderFetch(() => providerJson(OK));
    try {
      const h = harness({}, [
        {
          logicalModel: "mystery-model",
          provider: "mystery-main",
          providerModel: "mystery-1",
          // Not in `PROVIDER_ADAPTER_FAMILIES`: `canonicalProviderKind` returns
          // `null` and the registry has no adapter to hand back.
          providerKind: "mystery-cloud",
          baseUrl: "https://mystery.example",
          enabled: true,
        },
      ]);
      const res = await h.post("/v1/chat/completions", {
        model: "mystery-model",
        messages: [{ role: "user", content: "hi" }],
      });

      // An unknown family is operator misconfiguration: refuse rather than
      // guess a wire grammar, and above all dispatch nothing.
      expect(res.status).toBe(502);
      expect((await errorBody(res)).error.code).toBe("provider_adapter_error");
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });

  it("a bedrock route with no SigV4 credential fails closed too", async () => {
    const provider = interceptProviderFetch(() => providerJson(OK));
    try {
      const h = harness({}, [
        {
          logicalModel: "bedrock-model",
          provider: "bedrock-main",
          providerModel: "anthropic.claude-v2",
          providerKind: "bedrock",
          baseUrl: "https://bedrock.example",
          enabled: true,
        },
      ]);
      const res = await h.post("/v1/chat/completions", {
        model: "bedrock-model",
        messages: [{ role: "user", content: "hi" }],
      });

      // Bedrock is ported now, but it requires byte-exact SigV4: dispatching an
      // UNSIGNED request would be worse than refusing, so the adapter refuses.
      // The status is 400 `invalid_request` rather than 502 because this is the
      // adapter's `AdapterError::InvalidRequest`, exactly as in Rust.
      expect(res.status).toBe(400);
      expect((await errorBody(res)).error.code).toBe("invalid_request");
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });
});
