/**
 * The caching directive through the REAL request path (issue #690).
 *
 * `packages/providers/test/prompt-caching.test.ts` pins the translation at the
 * adapter boundary. This file pins the seam: that a `prompt_cache` on a
 * `/v1/chat/completions` body actually reaches the wire as the selected
 * family's own mechanism through the router → eligibility → adapter → dispatch
 * chain, that a family which cannot honour the directive is DROPPED FROM THE
 * LADDER instead of serving the request under different economics, and that a
 * `/v1/messages` caller's native `cache_control` is not erased on the way in.
 *
 * Only the outbound provider `fetch` is stubbed.
 */
import { describe, expect, it } from "vitest";

import type { PhysicalRoute } from "../../src/inference/index.js";
import { ANTHROPIC_ROUTE, OPENAI_ROUTE, errorBody, harness } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

const GEMINI_ROUTE: PhysicalRoute = {
  logicalModel: "gemini-cached",
  provider: "google",
  providerModel: "gemini-2.0-flash",
  providerKind: "gemini",
  baseUrl: "https://generativelanguage.googleapis.example/v1beta/",
  apiKey: "provider-secret",
  enabled: true,
};

/**
 * One logical model with an OPENAI primary and an Anthropic fallback — the
 * order that matters for `mode: "off"`, which OpenAI cannot honour and
 * Anthropic can.
 */
const FAILOVER_OPENAI: PhysicalRoute = {
  ...OPENAI_ROUTE,
  logicalModel: "failover-cached",
  priority: 0,
};
const FAILOVER_ANTHROPIC: PhysicalRoute = {
  ...ANTHROPIC_ROUTE,
  logicalModel: "failover-cached",
  priority: 1,
};

const ROUTES = [
  ANTHROPIC_ROUTE,
  OPENAI_ROUTE,
  GEMINI_ROUTE,
  FAILOVER_OPENAI,
  FAILOVER_ANTHROPIC,
];

const SYSTEM_PROMPT = "You are a claims adjuster. <10k tokens of policy text>";

const ANTHROPIC_MESSAGE = {
  id: "msg_1",
  type: "message",
  role: "assistant",
  model: "claude-3-5-sonnet-20241022",
  content: [{ type: "text", text: "covered" }],
  stop_reason: "end_turn",
  usage: {
    input_tokens: 12,
    output_tokens: 3,
    cache_read_input_tokens: 9_000,
    cache_creation_input_tokens: 0,
  },
};

const OPENAI_COMPLETION = {
  id: "chatcmpl-1",
  choices: [{ index: 0, message: { role: "assistant", content: "covered" }, finish_reason: "stop" }],
  usage: {
    prompt_tokens: 9_012,
    completion_tokens: 3,
    total_tokens: 9_015,
    prompt_tokens_details: { cached_tokens: 9_000 },
  },
};

const chatRequest = (model: string, promptCache: unknown) => ({
  model,
  messages: [
    { role: "system", content: SYSTEM_PROMPT },
    { role: "user", content: "is claim 91 covered?" },
  ],
  prompt_cache: promptCache,
});

describe("the directive reaches the selected family's mechanism", () => {
  it("an anthropic route receives a cache_control breakpoint with the requested ttl", async () => {
    const provider = interceptProviderFetch(() => providerJson(ANTHROPIC_MESSAGE));
    try {
      const res = await harness({}, ROUTES).post(
        "/v1/chat/completions",
        chatRequest("claude-logical", { mode: "explicit", ttl: "1h" }),
      );
      expect(res.status).toBe(200);
      const body = provider.lastRequest().body as Record<string, any>;
      expect(body["messages"][0]).toEqual({
        role: "system",
        content: [
          { type: "text", text: SYSTEM_PROMPT, cache_control: { type: "ephemeral", ttl: "1h" } },
        ],
      });
      // The volatile turn stays OUTSIDE the cached prefix, or the cache would
      // be rewritten on every request and never read.
      expect(JSON.stringify(body["messages"][1])).not.toContain("cache_control");
    } finally {
      provider.restore();
    }
  });

  it("an openai route relies on automatic caching and never sees the directive", async () => {
    const provider = interceptProviderFetch(() => providerJson(OPENAI_COMPLETION));
    try {
      const res = await harness({}, ROUTES).post(
        "/v1/chat/completions",
        chatRequest("gpt-4o-mini", { mode: "auto" }),
      );
      expect(res.status).toBe(200);
      // `prompt_cache` is FerroGate's member on a body OpenAI copies wholesale;
      // leaving it there turns a caching hint into an upstream 400.
      expect(provider.lastRequest().body).not.toHaveProperty("prompt_cache");
    } finally {
      provider.restore();
    }
  });
});

describe("a family that cannot honour the directive is dropped from the ladder", () => {
  it("`off` skips the OpenAI primary and is served by the Anthropic fallback", async () => {
    // OpenAI's automatic prompt caching cannot be disabled per request, so a
    // caller that requires the prompt NOT be cached must not be served there —
    // answering 200 off the primary would be the opposite of what was asked.
    const provider = interceptProviderFetch(() => providerJson(ANTHROPIC_MESSAGE));
    try {
      const res = await harness({}, ROUTES).post(
        "/v1/chat/completions",
        chatRequest("failover-cached", { mode: "off" }),
      );
      expect(res.status).toBe(200);
      expect(provider.requests).toHaveLength(1);
      expect(provider.lastRequest().url).toContain("api.anthropic.example");
      expect(JSON.stringify(provider.lastRequest().body)).not.toContain("cache_control");
    } finally {
      provider.restore();
    }
  });

  it("with nothing able to honour it, the caller gets a refusal and no upstream call", async () => {
    const provider = interceptProviderFetch(() => providerJson(OPENAI_COMPLETION));
    try {
      const res = await harness({}, ROUTES).post(
        "/v1/chat/completions",
        chatRequest("gemini-cached", { mode: "explicit", ttl: "5m" }),
      );
      expect(res.status).toBe(400);
      expect((await errorBody(res)).error.code).toBe("model_capability_unsupported");
      // Nothing was dispatched, so no token was spent on a request whose cache
      // economics would not have been the ones the caller asked for.
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });
});

describe("the /v1/messages ingress keeps the caller's caching intent", () => {
  it("a native cache_control survives the OpenAI-shaped translation", async () => {
    const provider = interceptProviderFetch(() => providerJson(ANTHROPIC_MESSAGE));
    try {
      const res = await harness({}, ROUTES).post("/v1/messages", {
        model: "claude-logical",
        max_tokens: 256,
        system: [
          { type: "text", text: SYSTEM_PROMPT, cache_control: { type: "ephemeral", ttl: "1h" } },
        ],
        messages: [{ role: "user", content: "is claim 91 covered?" }],
      });
      expect(res.status).toBe(200);
      // The ingress translates the Anthropic body into the OpenAI grammar
      // before routing, and that translation rebuilds every content block —
      // which used to drop the markers on the floor and cost the caller the
      // whole discount, silently, on its OWN protocol.
      const body = provider.lastRequest().body as Record<string, any>;
      expect(JSON.stringify(body)).toContain("cache_control");
      expect(JSON.stringify(body)).not.toContain("prompt_cache");
    } finally {
      provider.restore();
    }
  });

  it("reports the cache hit/miss split back to the caller after a translation", async () => {
    // A `/v1/messages` request served by an OPENAI route comes back as a chat
    // completion and is translated into an Anthropic Message. #667 made the
    // split visible to metering; this is the same split made visible to the
    // caller, in the envelope its own protocol defines.
    const provider = interceptProviderFetch(() => providerJson(OPENAI_COMPLETION));
    try {
      const res = await harness({}, ROUTES).post("/v1/messages", {
        model: "gpt-4o-mini",
        max_tokens: 256,
        messages: [{ role: "user", content: "is claim 91 covered?" }],
      });
      expect(res.status).toBe(200);
      const message = (await res.json()) as Record<string, any>;
      expect(message["usage"]).toEqual({
        // Anthropic's `input_tokens` EXCLUDES cache reads, where OpenAI's
        // `prompt_tokens` includes them — so the fresh count is the difference.
        // Reporting 9012 fresh AND 9000 cached would double-count the prompt.
        input_tokens: 12,
        output_tokens: 3,
        cache_read_input_tokens: 9_000,
      });
    } finally {
      provider.restore();
    }
  });
});
