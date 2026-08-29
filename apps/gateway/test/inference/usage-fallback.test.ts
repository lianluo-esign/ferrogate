/**
 * #976 Phase B1 — buffered local-tokenizer fallback, end to end.
 *
 * The three buffered success sites (chat/responses, `/v1/messages`, Gemini
 * `:generateContent`) are driven through the real router → registry → adapter →
 * dispatch path; only the outbound provider `fetch` is stubbed. Each site is
 * pinned twice:
 *
 *   - upstream success WITHOUT a usage object → the call is metered on the LOCAL
 *     token count (never $0) and tagged `local_tokenizer`;
 *   - upstream success WITH a usage object → the provider count wins and the
 *     fallback stays out (`usageSource` unset → `provider_usage`).
 *
 * The completion text on every no-usage stub is "hello world" (2 tokens on
 * o200k_base), so `completionTokens` is asserted exactly; the prompt count is
 * asserted `> 0` because request framing/roles make its exact value an
 * implementation detail of the harvester, pinned in `fallback-usage.test.ts`.
 */
import { describe, expect, it } from "vitest";

import type { PhysicalRoute } from "../../src/inference/index.js";
import { ANTHROPIC_ROUTE, OPENAI_ROUTE, harness } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

const GEMINI_ROUTE: PhysicalRoute = {
  logicalModel: "gemini-native",
  provider: "google",
  providerModel: "gemini-2.0-flash",
  providerKind: "gemini",
  baseUrl: "https://generativelanguage.googleapis.com/v1beta/",
  apiKey: "provider-secret",
  enabled: true,
};

const ROUTES: readonly PhysicalRoute[] = [OPENAI_ROUTE, ANTHROPIC_ROUTE, GEMINI_ROUTE];

// A well-formed chat.completion body that OMITS `usage`.
const OPENAI_NO_USAGE = {
  id: "chatcmpl-x",
  object: "chat.completion",
  created: 0,
  model: "gpt-4o-mini",
  choices: [{ index: 0, message: { role: "assistant", content: "hello world" }, finish_reason: "stop" }],
};

// A native Anthropic message body that OMITS `usage`.
const ANTHROPIC_NO_USAGE = {
  id: "msg_x",
  type: "message",
  role: "assistant",
  model: "claude-3-5-sonnet-20241022",
  content: [{ type: "text", text: "hello world" }],
  stop_reason: "end_turn",
};

// A native Gemini body that OMITS `usageMetadata`.
const GEMINI_NO_USAGE = {
  candidates: [{ content: { role: "model", parts: [{ text: "hello world" }] } }],
};

describe("#976 B1: chat/completions buffered fallback", () => {
  it("meters on the local count when the upstream omits usage", async () => {
    const intercept = interceptProviderFetch(() => providerJson(OPENAI_NO_USAGE));
    try {
      const h = harness({}, ROUTES);
      const res = await h.post("/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi there" }],
      });
      expect(res.status).toBe(200);
      expect(h.usage.last?.completionTokens).toBe(2); // "hello world"
      expect(h.usage.last?.promptTokens ?? 0).toBeGreaterThan(0);
      expect(h.usage.last?.totalTokens).toBe(
        (h.usage.last?.promptTokens ?? 0) + (h.usage.last?.completionTokens ?? 0),
      );
      expect(h.usage.last?.usageSource).toBe("local_tokenizer");
    } finally {
      intercept.restore();
    }
  });

  it("keeps the provider count (fallback out) when the upstream reports usage", async () => {
    const intercept = interceptProviderFetch(() =>
      providerJson({
        ...OPENAI_NO_USAGE,
        usage: { prompt_tokens: 11, completion_tokens: 5, total_tokens: 16 },
      }),
    );
    try {
      const h = harness({}, ROUTES);
      await h.post("/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi there" }],
      });
      expect(h.usage.last?.promptTokens).toBe(11);
      expect(h.usage.last?.completionTokens).toBe(5);
      expect(h.usage.last?.totalTokens).toBe(16);
      expect(h.usage.last?.usageSource).toBeUndefined(); // → provider_usage
    } finally {
      intercept.restore();
    }
  });
});

describe("#976 B1: /v1/messages buffered fallback", () => {
  it("meters on the local count when the native Anthropic body omits usage", async () => {
    const intercept = interceptProviderFetch(() => providerJson(ANTHROPIC_NO_USAGE));
    try {
      const h = harness({}, ROUTES);
      const res = await h.post("/v1/messages", {
        model: "claude-logical",
        max_tokens: 64,
        messages: [{ role: "user", content: "hi there" }],
      });
      expect(res.status).toBe(200);
      expect(h.usage.last?.completionTokens).toBe(2); // "hello world"
      expect(h.usage.last?.promptTokens ?? 0).toBeGreaterThan(0);
      expect(h.usage.last?.usageSource).toBe("local_tokenizer");
    } finally {
      intercept.restore();
    }
  });

  it("keeps the provider count when the Anthropic body reports usage", async () => {
    const intercept = interceptProviderFetch(() =>
      providerJson({
        ...ANTHROPIC_NO_USAGE,
        usage: { input_tokens: 9, output_tokens: 4 },
      }),
    );
    try {
      const h = harness({}, ROUTES);
      await h.post("/v1/messages", {
        model: "claude-logical",
        max_tokens: 64,
        messages: [{ role: "user", content: "hi there" }],
      });
      expect(h.usage.last?.promptTokens).toBe(9);
      expect(h.usage.last?.completionTokens).toBe(4);
      expect(h.usage.last?.usageSource).toBeUndefined();
    } finally {
      intercept.restore();
    }
  });
});

describe("#976 B1: Gemini generateContent buffered fallback", () => {
  it("meters on the local count when the native Gemini body omits usageMetadata", async () => {
    const intercept = interceptProviderFetch(() => providerJson(GEMINI_NO_USAGE));
    try {
      const h = harness({}, ROUTES);
      const res = await h.post("/v1beta/models/gemini-native:generateContent", {
        contents: [{ role: "user", parts: [{ text: "hi there" }] }],
      });
      expect(res.status).toBe(200);
      expect(h.usage.last?.completionTokens).toBe(2); // "hello world"
      expect(h.usage.last?.promptTokens ?? 0).toBeGreaterThan(0);
      expect(h.usage.last?.usageSource).toBe("local_tokenizer");
    } finally {
      intercept.restore();
    }
  });

  it("keeps the provider count when Gemini reports usageMetadata", async () => {
    const intercept = interceptProviderFetch(() =>
      providerJson({
        ...GEMINI_NO_USAGE,
        usageMetadata: { promptTokenCount: 7, candidatesTokenCount: 2, totalTokenCount: 9 },
      }),
    );
    try {
      const h = harness({}, ROUTES);
      await h.post("/v1beta/models/gemini-native:generateContent", {
        contents: [{ role: "user", parts: [{ text: "hi there" }] }],
      });
      expect(h.usage.last?.promptTokens).toBe(7);
      expect(h.usage.last?.completionTokens).toBe(2);
      expect(h.usage.last?.totalTokens).toBe(9);
      expect(h.usage.last?.usageSource).toBeUndefined();
    } finally {
      intercept.restore();
    }
  });

  it("does NOT synthesize a count on an unparseable success body", async () => {
    // Gemini's buffered path has no invalid-body 502 guard, so the fallback is
    // gated on a structurally valid record. A garbage 200 must meter nothing
    // (prompt is counted from the REQUEST — synthesizing here would mislabel it).
    const intercept = interceptProviderFetch(
      () => new Response("not json", { status: 200, headers: { "content-type": "application/json" } }),
    );
    try {
      const h = harness({}, ROUTES);
      await h.post("/v1beta/models/gemini-native:generateContent", {
        contents: [{ role: "user", parts: [{ text: "hi there" }] }],
      });
      expect(h.usage.last?.usageSource).toBeUndefined();
      expect(h.usage.last?.promptTokens).toBeUndefined();
      expect(h.usage.last?.totalTokens).toBeUndefined();
    } finally {
      intercept.restore();
    }
  });
});
