/**
 * Structured outputs through the REAL request path (issue #674).
 *
 * `packages/providers/test/structured-outputs.test.ts` pins the translation at
 * the adapter boundary. This file pins the seam: that a `response_format` on a
 * `/v1/chat/completions` body actually reaches the wire in each family's dialect
 * through the router → eligibility → adapter → dispatch chain, and that a family
 * which refuses the requirement is DROPPED FROM THE LADDER rather than allowed
 * to answer with unconstrained text.
 *
 * Only the outbound provider `fetch` is stubbed.
 */
import { describe, expect, it } from "vitest";

import type { PhysicalRoute } from "../../src/inference/index.js";
import { ANTHROPIC_ROUTE, OPENAI_ROUTE, errorBody, harness } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

const SCHEMA = {
  type: "object",
  properties: { total: { type: "number" } },
  required: ["total"],
};

const JSON_SCHEMA_FORMAT = {
  type: "json_schema",
  json_schema: { name: "invoice", strict: true, schema: SCHEMA },
};

const GEMINI_ROUTE: PhysicalRoute = {
  logicalModel: "gemini-structured",
  provider: "google",
  providerModel: "gemini-2.0-flash",
  providerKind: "gemini",
  baseUrl: "https://generativelanguage.googleapis.example/v1beta/",
  apiKey: "provider-secret",
  enabled: true,
};

/**
 * One logical model with an Anthropic PRIMARY (priority 0) and an OpenAI
 * fallback (priority 1) — the failover pair the issue is about.
 */
const FAILOVER_ANTHROPIC: PhysicalRoute = {
  ...ANTHROPIC_ROUTE,
  logicalModel: "failover-model",
  priority: 0,
};
const FAILOVER_OPENAI: PhysicalRoute = {
  ...OPENAI_ROUTE,
  logicalModel: "failover-model",
  priority: 1,
};

const ROUTES = [ANTHROPIC_ROUTE, OPENAI_ROUTE, GEMINI_ROUTE, FAILOVER_ANTHROPIC, FAILOVER_OPENAI];

const ANTHROPIC_MESSAGE = {
  id: "msg_1",
  content: [{ type: "tool_use", id: "toolu_1", name: "invoice", input: { total: 12 } }],
  usage: { input_tokens: 5, output_tokens: 3 },
};
const OPENAI_COMPLETION = {
  id: "chatcmpl-1",
  choices: [{ index: 0, message: { role: "assistant", content: '{"total":12}' } }],
  usage: { prompt_tokens: 5, completion_tokens: 3, total_tokens: 8 },
};
const GEMINI_COMPLETION = {
  candidates: [{ content: { parts: [{ text: '{"total":12}' }], role: "model" } }],
  usageMetadata: { promptTokenCount: 5, candidatesTokenCount: 3, totalTokenCount: 8 },
};

describe("the requested schema reaches every family's wire", () => {
  it("an anthropic route receives a forced coercion tool, not a bare prompt", async () => {
    const provider = interceptProviderFetch(() => providerJson(ANTHROPIC_MESSAGE));
    try {
      const res = await harness({}, ROUTES).post("/v1/chat/completions", {
        model: "claude-logical",
        messages: [{ role: "user", content: "parse it" }],
        response_format: JSON_SCHEMA_FORMAT,
      });
      expect(res.status).toBe(200);
      const body = provider.lastRequest().body as Record<string, any>;
      expect(body.tools).toEqual([{ name: "invoice", input_schema: SCHEMA }]);
      expect(body.tool_choice).toEqual({ type: "tool", name: "invoice" });
    } finally {
      provider.restore();
    }
  });

  it("a gemini route receives responseSchema + the JSON mime type", async () => {
    const provider = interceptProviderFetch(() => providerJson(GEMINI_COMPLETION));
    try {
      const res = await harness({}, ROUTES).post("/v1/chat/completions", {
        model: "gemini-structured",
        messages: [{ role: "user", content: "parse it" }],
        response_format: JSON_SCHEMA_FORMAT,
      });
      expect(res.status).toBe(200);
      const config = (provider.lastRequest().body as Record<string, any>).generationConfig;
      expect(config.responseMimeType).toBe("application/json");
      expect(config.responseSchema).toEqual(SCHEMA);
    } finally {
      provider.restore();
    }
  });

  it("an openai route keeps the native field (the leg that always worked)", async () => {
    const provider = interceptProviderFetch(() => providerJson(OPENAI_COMPLETION));
    try {
      await harness({}, ROUTES).post("/v1/chat/completions", {
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "parse it" }],
        response_format: JSON_SCHEMA_FORMAT,
      });
      expect((provider.lastRequest().body as Record<string, any>).response_format).toEqual(
        JSON_SCHEMA_FORMAT,
      );
    } finally {
      provider.restore();
    }
  });
});

describe("a family that cannot honour the contract is dropped from the ladder", () => {
  it("failover skips the refusing primary instead of degrading on it", async () => {
    // `json_object` has no Anthropic equivalent. The primary must not be
    // dispatched to at all — an unconstrained Anthropic answer is precisely the
    // silent contract change this issue is about.
    const provider = interceptProviderFetch(() => providerJson(OPENAI_COMPLETION));
    try {
      const res = await harness({}, ROUTES).post("/v1/chat/completions", {
        model: "failover-model",
        messages: [{ role: "user", content: "parse it" }],
        response_format: { type: "json_object" },
      });
      expect(res.status).toBe(200);
      expect(provider.requests).toHaveLength(1);
      expect(provider.lastRequest().url).toContain("api.openai.example");
      expect((provider.lastRequest().body as Record<string, any>).response_format).toEqual({
        type: "json_object",
      });
    } finally {
      provider.restore();
    }
  });

  it("with nothing able to honour it, the caller gets a refusal and no upstream call", async () => {
    const provider = interceptProviderFetch(() => providerJson(ANTHROPIC_MESSAGE));
    try {
      const res = await harness({}, ROUTES).post("/v1/chat/completions", {
        model: "claude-logical",
        messages: [{ role: "user", content: "parse it" }],
        response_format: { type: "json_object" },
      });
      expect(res.status).toBe(400);
      expect((await errorBody(res)).error.code).toBe("model_capability_unsupported");
      // The decisive assertion: nothing was sent upstream, so no token was ever
      // spent producing an answer that would have broken the caller's contract.
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });
});
