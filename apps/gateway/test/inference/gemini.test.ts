/**
 * The `gemini` provider family, reached through `@ferrogate/providers`'
 * `GeminiAdapter` (the port of `gemini.rs`) via `packageProviderAdapter`.
 *
 * Gemini used to resolve to `null` and answer `unsupported provider kind`.
 * These assertions are the places where wiring it as an ALIAS of the OpenAI
 * adapter — the shortcut the old marker refused — would have been wrong: a
 * different endpoint grammar (`:generateContent` / `:streamGenerateContent`,
 * model in the PATH), a different body (`contents`/`parts`/`systemInstruction`,
 * no `model` field), a different credential header (`x-goog-api-key`), a
 * different embeddings envelope (`batchEmbedContents` → translated back to the
 * OpenAI shape), and Rust's two refusals (images, model catalog) preserved.
 *
 * Driven through the real router + registry + dispatch path; only the outbound
 * provider `fetch` is stubbed.
 */
import { describe, expect, it } from "vitest";

import { defaultAdapterRegistry } from "../../src/inference/index.js";
import type { PhysicalRoute } from "../../src/inference/index.js";
import { errorBody, harness } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

const GEMINI_ROUTE: PhysicalRoute = {
  logicalModel: "gemini-chat",
  provider: "google",
  providerModel: "gemini-2.0-flash",
  providerKind: "gemini",
  baseUrl: "https://generativelanguage.googleapis.com/v1beta/",
  apiKey: "provider-secret",
  enabled: true,
};

const GEMINI_EMBEDDINGS_ROUTE: PhysicalRoute = {
  ...GEMINI_ROUTE,
  logicalModel: "gemini-embed",
  providerModel: "text-embedding-004",
};

const ROUTES = [GEMINI_ROUTE, GEMINI_EMBEDDINGS_ROUTE];

const GEMINI_COMPLETION = {
  candidates: [{ content: { parts: [{ text: "hello" }], role: "model" } }],
  usageMetadata: { promptTokenCount: 7, candidatesTokenCount: 2, totalTokenCount: 9 },
};

describe("gemini chat completions", () => {
  it("builds the Gemini generateContent request, not an OpenAI one", async () => {
    const provider = interceptProviderFetch(() => providerJson(GEMINI_COMPLETION));
    try {
      const h = harness({}, ROUTES);
      const res = await h.post("/v1/chat/completions", {
        model: "gemini-chat",
        messages: [
          { role: "system", content: "be terse" },
          { role: "user", content: "hi" },
        ],
        temperature: 0.25,
      });

      expect(res.status).toBe(200);
      const sent = provider.lastRequest();

      // Model lives in the PATH, and the physical id is used — never the
      // caller's logical name.
      expect(sent.url).toBe(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent",
      );
      // Credential header is Google's, NOT `Authorization: Bearer`.
      expect(sent.headers["x-goog-api-key"]).toBe("provider-secret");
      expect(sent.headers.authorization).toBeUndefined();

      const body = sent.body as Record<string, unknown>;
      // Gemini grammar: `contents`/`parts`, system prompt lifted out of
      // `messages`, generation knobs renamed. No OpenAI leftovers.
      expect(body.contents).toStrictEqual([{ role: "user", parts: [{ text: "hi" }] }]);
      expect(body.systemInstruction).toStrictEqual({
        role: "system",
        parts: [{ text: "be terse" }],
      });
      expect(body.generationConfig).toStrictEqual({ temperature: 0.25 });
      expect(body.model).toBeUndefined();
      expect(body.messages).toBeUndefined();
    } finally {
      provider.restore();
    }
  });

  it("addresses the streaming endpoint when the caller asks to stream", async () => {
    const provider = interceptProviderFetch(() => providerJson({ ...GEMINI_COMPLETION }));
    try {
      const h = harness({}, ROUTES);
      await h.post("/v1/chat/completions", {
        model: "gemini-chat",
        messages: [{ role: "user", content: "hi" }],
        stream: true,
      });
      expect(provider.lastRequest().url).toBe(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:streamGenerateContent?alt=sse",
      );
    } finally {
      provider.restore();
    }
  });

  it("meters the call from Gemini's own usage envelope", async () => {
    const provider = interceptProviderFetch(() => providerJson(GEMINI_COMPLETION));
    try {
      const h = harness({}, ROUTES);
      await h.post("/v1/chat/completions", {
        model: "gemini-chat",
        messages: [{ role: "user", content: "hi" }],
      });
      const [usage] = h.usage.records;
      expect(usage?.promptTokens).toBe(7);
      expect(usage?.completionTokens).toBe(2);
      expect(usage?.totalTokens).toBe(9);
    } finally {
      provider.restore();
    }
  });
});

describe("gemini embeddings", () => {
  it("posts batchEmbedContents and translates the response to the OpenAI envelope", async () => {
    const provider = interceptProviderFetch(() =>
      providerJson({ embeddings: [{ values: [0.5, 0.25] }, { values: [0.125] }] }),
    );
    try {
      const h = harness({}, ROUTES);
      const res = await h.post("/v1/embeddings", {
        model: "gemini-embed",
        input: ["one", "two"],
      });

      const sent = provider.lastRequest();
      expect(sent.url).toBe(
        "https://generativelanguage.googleapis.com/v1beta/models/text-embedding-004:batchEmbedContents",
      );
      expect(sent.body).toStrictEqual({
        requests: [
          { model: "models/text-embedding-004", content: { parts: [{ text: "one" }] } },
          { model: "models/text-embedding-004", content: { parts: [{ text: "two" }] } },
        ],
      });

      // The CLIENT still sees OpenAI shape — that translation is the adapter's,
      // and a pass-through would fail this.
      expect(res.status).toBe(200);
      const body = (await res.json()) as Record<string, unknown>;
      expect(body.object).toBe("list");
      expect(body.model).toBe("gemini-embed");
      expect(body.data).toStrictEqual([
        { object: "embedding", index: 0, embedding: [0.5, 0.25] },
        { object: "embedding", index: 1, embedding: [0.125] },
      ]);
    } finally {
      provider.restore();
    }
  });
});

describe("gemini refusals are the Rust trait defaults, not new behavior", () => {
  it("refuses image generation with the capability message (issue #275)", async () => {
    const provider = interceptProviderFetch(() => providerJson({}));
    try {
      const h = harness({}, ROUTES);
      const res = await h.post("/v1/images/generations", {
        model: "gemini-chat",
        prompt: "a cat",
      });
      expect((await errorBody(res)).error.message).toBe(
        "provider kind gemini does not support image generation",
      );
      // Nothing was dispatched: the refusal happens before the socket.
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });
});

describe("registry resolution", () => {
  it("resolves gemini, bedrock and vertex through the package adapters", () => {
    expect(defaultAdapterRegistry.adapterFor("gemini")?.kind).toBe("gemini");
    // Bedrock and Vertex used to resolve to `null` for want of a credential
    // shape on `PhysicalRoute` (SigV4 needs four fields, Vertex three). They are
    // ported now — `awsCredentials`/`gcpCredentials` on the route — and the
    // fail-closed guarantee moved INTO the adapters: a route with no credential
    // still dispatches nothing. See `bedrock-vertex.test.ts`, which pins both
    // the signed request and the credential-less refusal.
    expect(defaultAdapterRegistry.adapterFor("bedrock")?.kind).toBe("bedrock");
    expect(defaultAdapterRegistry.adapterFor("aws-bedrock")?.kind).toBe("bedrock");
    expect(defaultAdapterRegistry.adapterFor("vertex")?.kind).toBe("vertex");
    expect(defaultAdapterRegistry.adapterFor("vertex-ai")?.kind).toBe("vertex");
    // A family that is not in `PROVIDER_ADAPTER_FAMILIES` at all still fails
    // closed, which is the assertion this test was really protecting.
    expect(defaultAdapterRegistry.adapterFor("not-a-provider")).toBeNull();
  });

  it("a gemini adapter handed a non-gemini route refuses it", () => {
    const gemini = defaultAdapterRegistry.adapterFor("gemini");
    const result = gemini?.buildUpstreamRequest({
      operation: "chat.completions",
      route: { ...GEMINI_ROUTE, providerKind: " OpenAI " },
      logicalModel: "gemini-chat",
      providerModel: "gemini-2.0-flash",
      stream: false,
      body: {},
    });
    expect(result?.ok).toBe(false);
  });
});
