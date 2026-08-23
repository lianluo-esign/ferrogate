/**
 * The Gemini-NATIVE ingress (`POST /v1beta/models/{model}:generateContent` and
 * `:streamGenerateContent`), reached through `handleGeminiGenerateContent`.
 *
 * `gemini.test.ts` pins the OpenAI→Gemini TRANSLATION path (a caller posts an
 * OpenAI `/v1/chat/completions` body and the adapter rewrites it into Gemini
 * grammar). THIS file pins the opposite direction: a caller who already speaks
 * Gemini, whose body must reach a Gemini supplier BYTE-FOR-BYTE while FerroGate
 * still owns auth, routing, metering and the credential swap.
 *
 * The doctrine under test: preserve the protocol when client and supplier match
 * (`nativeBody` forwarded unchanged, native SSE relayed unchanged), translate
 * only at the adapter boundary, and never fabricate a Gemini answer from a
 * supplier that cannot produce one (a non-Gemini route is refused, not
 * mis-served).
 *
 * Driven through the real router + registry + dispatch path; only the outbound
 * provider `fetch` is stubbed.
 */
import { describe, expect, it } from "vitest";

import type { PhysicalRoute } from "../../src/inference/index.js";
import { errorBody, harness } from "./fixtures.js";
import {
  interceptProviderFetch,
  providerJson,
  providerSse,
  readBody,
  sseBytes,
} from "./provider-mock.js";

const GEMINI_ROUTE: PhysicalRoute = {
  logicalModel: "gemini-chat",
  provider: "google",
  providerModel: "gemini-2.0-flash",
  providerKind: "gemini",
  baseUrl: "https://generativelanguage.googleapis.com/v1beta/",
  apiKey: "provider-secret",
  enabled: true,
};

/** Same logical surface, but the ladder resolves it to a NON-Gemini supplier. */
const MISMATCH_ROUTE: PhysicalRoute = {
  logicalModel: "gemini-mismatch",
  provider: "openai-main",
  providerModel: "gpt-4o-mini",
  providerKind: "openai",
  baseUrl: "https://api.openai.example/v1",
  apiKey: "sk-provider-openai",
  enabled: true,
};

const ROUTES = [GEMINI_ROUTE, MISMATCH_ROUTE];

/** A minimal, valid `generateContent` request in Gemini's own grammar. */
const NATIVE_REQUEST = {
  systemInstruction: { parts: [{ text: "be terse" }] },
  contents: [{ role: "user", parts: [{ text: "hi" }] }],
  generationConfig: { temperature: 0.25, thinkingConfig: { thinkingBudget: 128 } },
  safetySettings: [{ category: "HARM_CATEGORY_HATE_SPEECH", threshold: "BLOCK_NONE" }],
};

const NATIVE_COMPLETION = {
  candidates: [{ content: { role: "model", parts: [{ text: "ok" }] }, finishReason: "STOP" }],
  usageMetadata: {
    promptTokenCount: 10,
    cachedContentTokenCount: 4,
    candidatesTokenCount: 6,
    thoughtsTokenCount: 3,
    totalTokenCount: 19,
  },
};

describe("gemini native generateContent (buffered)", () => {
  it("forwards the caller's body byte-for-byte to the Gemini supplier", async () => {
    const provider = interceptProviderFetch(() => providerJson(NATIVE_COMPLETION));
    try {
      const h = harness({}, ROUTES);
      const res = await h.post("/v1beta/models/gemini-chat:generateContent", NATIVE_REQUEST);

      expect(res.status).toBe(200);
      const sent = provider.lastRequest();

      // Model + buffered/stream choice come from the PATH, never the body — the
      // physical id is used, and `:generateContent` addresses the non-stream leg.
      expect(sent.method).toBe("POST");
      expect(sent.url).toBe(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent",
      );

      // The body is the ORIGINAL, unchanged: no injected `model`/`stream`, and
      // every vendor field (safetySettings, thinkingConfig) preserved. A
      // translation pass or a mutation of the plan body would fail this.
      expect(sent.body).toStrictEqual(NATIVE_REQUEST);
    } finally {
      provider.restore();
    }
  });

  it("swaps the tenant credential for the supplier's and never leaks inbound creds", async () => {
    const provider = interceptProviderFetch(() => providerJson(NATIVE_COMPLETION));
    try {
      const h = harness({}, ROUTES);
      await h.post("/v1beta/models/gemini-chat:generateContent", NATIVE_REQUEST, {
        headers: {
          // What a Gemini SDK would put on the wire toward FerroGate — none of it
          // is a provider credential and none of it may reach the supplier.
          "x-goog-api-key": "tenant-virtual-key",
          authorization: "Bearer fg_tenant_token",
          // A pure capability hint (SDK version) IS forwarded.
          "x-goog-api-client": "genai-js/0.21.0",
        },
      });

      const sent = provider.lastRequest();
      // The upstream key is the ROUTE's provider secret, not the caller's key.
      expect(sent.headers["x-goog-api-key"]).toBe("provider-secret");
      expect(sent.headers["x-goog-api-key"]).not.toBe("tenant-virtual-key");
      // No bearer token crosses to the supplier.
      expect(sent.headers.authorization).toBeUndefined();
      // The capability header is allow-listed through.
      expect(sent.headers["x-goog-api-client"]).toBe("genai-js/0.21.0");
    } finally {
      provider.restore();
    }
  });

  it("returns the upstream Gemini bytes unchanged", async () => {
    const provider = interceptProviderFetch(() => providerJson(NATIVE_COMPLETION));
    try {
      const h = harness({}, ROUTES);
      const res = await h.post("/v1beta/models/gemini-chat:generateContent", NATIVE_REQUEST);
      expect(res.status).toBe(200);
      // The client is served the supplier's own envelope, not a re-encoded copy.
      expect(await res.json()).toStrictEqual(NATIVE_COMPLETION);
    } finally {
      provider.restore();
    }
  });

  it("meters from Gemini's usageMetadata, folding cached and thinking tokens", async () => {
    const provider = interceptProviderFetch(() => providerJson(NATIVE_COMPLETION));
    try {
      const h = harness({}, ROUTES);
      await h.post("/v1beta/models/gemini-chat:generateContent", NATIVE_REQUEST);

      const [usage] = h.usage.records;
      expect(usage?.promptTokens).toBe(10);
      // Gemini's `candidatesTokenCount` EXCLUDES `thoughtsTokenCount`, so the
      // billed completion is visible(6) + thinking(3).
      expect(usage?.completionTokens).toBe(9);
      expect(usage?.totalTokens).toBe(19);
      expect(usage?.cachedInputTokens).toBe(4);
      expect(usage?.reasoningTokens).toBe(3);
    } finally {
      provider.restore();
    }
  });
});

describe("gemini native streamGenerateContent (SSE)", () => {
  const STREAM_FRAMES: readonly string[] = [
    'data: {"candidates":[{"content":{"role":"model","parts":[{"text":"Hel"}]}}]}',
    'data: {"candidates":[{"content":{"role":"model","parts":[{"text":"lo"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":7,"candidatesTokenCount":2,"totalTokenCount":9}}',
  ];

  it("addresses the streaming endpoint and relays the frames byte-for-byte", async () => {
    const provider = interceptProviderFetch(() => providerSse(STREAM_FRAMES));
    try {
      const h = harness({}, ROUTES);
      const res = await h.post("/v1beta/models/gemini-chat:streamGenerateContent", NATIVE_REQUEST);

      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toBe("text/event-stream");
      expect(provider.lastRequest().url).toBe(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:streamGenerateContent?alt=sse",
      );
      // A null normalizer means the client sees the supplier's exact SSE bytes.
      expect(await readBody(res)).toBe(sseBytes(STREAM_FRAMES));
    } finally {
      provider.restore();
    }
  });

  it("meters the stream off the trailing usageMetadata frame", async () => {
    const provider = interceptProviderFetch(() => providerSse(STREAM_FRAMES));
    try {
      const h = harness({}, ROUTES);
      const res = await h.post("/v1beta/models/gemini-chat:streamGenerateContent", NATIVE_REQUEST);
      // Drain the stream so the usage tap runs to completion.
      await readBody(res);

      const [usage] = h.usage.records;
      expect(usage?.promptTokens).toBe(7);
      expect(usage?.completionTokens).toBe(2);
      expect(usage?.totalTokens).toBe(9);
    } finally {
      provider.restore();
    }
  });
});

describe("gemini native ingress refusals", () => {
  it("rejects an action suffix that is neither generateContent nor streamGenerateContent", async () => {
    const provider = interceptProviderFetch(() => providerJson(NATIVE_COMPLETION));
    try {
      const h = harness({}, ROUTES);
      const res = await h.post("/v1beta/models/gemini-chat:embedContent", {
        contents: [{ role: "user", parts: [{ text: "hi" }] }],
      });

      expect(res.status).toBe(404);
      expect((await errorBody(res)).error.code).toBe("invalid_request");
      // The refusal is before the socket — nothing was dispatched upstream.
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });

  it("refuses a non-Gemini supplier rather than fabricate a Gemini response", async () => {
    // The supplier is reached (the attempt happened and is metered), but it does
    // not speak Gemini, so there is no honest native answer to relay.
    const provider = interceptProviderFetch(() =>
      providerJson({ choices: [{ message: { role: "assistant", content: "hi" } }] }),
    );
    try {
      const h = harness({}, ROUTES);
      const res = await h.post("/v1beta/models/gemini-mismatch:generateContent", NATIVE_REQUEST);

      expect(res.status).toBe(502);
      expect((await errorBody(res)).error.code).toBe("provider_protocol_mismatch");
    } finally {
      provider.restore();
    }
  });
});
