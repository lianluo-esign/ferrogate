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

import { defaultAdapterRegistry } from "../../src/inference/index.js";
import type { GatewayProviderFamily, PhysicalRoute } from "../../src/inference/index.js";
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

/**
 * The other order: an ANTHROPIC primary with an OpenAI fallback.
 *
 * This is the ladder that reaches two families with ONE caller body — the
 * Anthropic candidate is prepared and dispatched first, and when it fails the
 * OpenAI candidate is prepared from the same `plan.body`. Any write-through an
 * adapter performed while preparing the first candidate is visible on the
 * second candidate's wire body.
 */
const ISOLATION_ANTHROPIC: PhysicalRoute = {
  ...ANTHROPIC_ROUTE,
  logicalModel: "isolation-cached",
  priority: 0,
};
const ISOLATION_OPENAI: PhysicalRoute = {
  ...OPENAI_ROUTE,
  logicalModel: "isolation-cached",
  priority: 1,
};

/**
 * Azure is the ninth family and the one that does NOT delegate to the
 * OpenAI-compatible adapter — it builds its own body, because the model is a
 * deployment in the path rather than a member. That difference is how it came
 * to skip the caching adjudication entirely.
 */
const AZURE_ROUTE: PhysicalRoute = {
  logicalModel: "azure-cached",
  provider: "azure-eastus",
  providerModel: "gpt-4o-mini",
  providerKind: "azure-openai",
  baseUrl: "https://example.openai.azure.example/?api-version=2024-02-15-preview",
  apiKey: "provider-secret",
  enabled: true,
};

const ROUTES = [
  ANTHROPIC_ROUTE,
  OPENAI_ROUTE,
  GEMINI_ROUTE,
  AZURE_ROUTE,
  FAILOVER_OPENAI,
  FAILOVER_ANTHROPIC,
  ISOLATION_ANTHROPIC,
  ISOLATION_OPENAI,
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
      // The breakpoint lands on the top-level `system` parameter, which is
      // where Anthropic's static prefix actually lives — #725 lifted the
      // system-role turn out of `messages`, so the prefix and the breakpoint
      // are now the same object rather than a role the API does not accept.
      expect(body["system"]).toEqual([
        { type: "text", text: SYSTEM_PROMPT, cache_control: { type: "ephemeral", ttl: "1h" } },
      ]);
      // The volatile turn stays OUTSIDE the cached prefix, or the cache would
      // be rewritten on every request and never read.
      expect(body["messages"]).toEqual([{ role: "user", content: "is claim 91 covered?" }]);
      expect(JSON.stringify(body["messages"])).not.toContain("cache_control");
    } finally {
      provider.restore();
    }
  });

  it("an azure route adjudicates the directive like any other automatic family", async () => {
    // Azure builds its upstream body BY HAND — the model is a deployment in
    // the path, so it cannot delegate to the OpenAI-compatible adapter the way
    // grok and openrouter do. That is exactly how it came to skip adjudication:
    // `{"mode":"off"}` answered 200 and `prompt_cache` reached the upstream
    // verbatim, which is both a broken retention promise and a live 400 (Azure
    // rejects unknown members).
    const provider = interceptProviderFetch(() => providerJson(OPENAI_COMPLETION));
    try {
      const app = harness({}, ROUTES);
      const refused = await app.post(
        "/v1/chat/completions",
        chatRequest("azure-cached", { mode: "off" }),
      );
      expect(refused.status).toBe(400);
      expect((await errorBody(refused)).error.code).toBe("model_capability_unsupported");
      expect(provider.requests).toHaveLength(0);

      const served = await app.post(
        "/v1/chat/completions",
        chatRequest("azure-cached", { mode: "auto" }),
      );
      expect(served.status).toBe(200);
      expect(provider.lastRequest().url).toContain("openai.azure.example");
      expect(provider.lastRequest().body).not.toHaveProperty("prompt_cache");
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

describe("preparing one family never rewrites what another family sends", () => {
  /**
   * The candidates on a ladder share ONE caller body. An adapter that applies
   * its family's mechanism by writing through to that shared object does not
   * merely add a field — it decides what every LATER candidate sends. Here the
   * Anthropic primary is prepared first and fails, and the OpenAI fallback must
   * go out as if Anthropic had never been considered.
   *
   * This is not a caching assertion. It is the family-isolation invariant, and
   * `cache_control` is only the field that made it observable: the same seam
   * would leak anything else an adapter decided to normalise.
   */
  it("an anthropic attempt leaves the openai fallback's body untouched", async () => {
    const provider = interceptProviderFetch((request) =>
      request.url.includes("api.anthropic.example")
        ? providerJson({ error: "overloaded" }, 503)
        : providerJson(OPENAI_COMPLETION),
    );
    try {
      const res = await harness({}, ROUTES).post(
        "/v1/chat/completions",
        // `auto` is the mode EVERY family accepts, so both candidates stay on
        // the ladder and the second one is genuinely dispatched.
        chatRequest("isolation-cached", { mode: "auto" }),
      );
      expect(res.status).toBe(200);
      expect(provider.requests).toHaveLength(2);
      expect(provider.requests[0]!.url).toContain("api.anthropic.example");

      const openai = provider.requests[1]!;
      expect(openai.url).toContain("api.openai.example");
      // Anthropic's breakpoint is an Anthropic-only member. OpenAI has no
      // `cache_control`; receiving one means the Anthropic adapter wrote into
      // the object this request was built from.
      expect(JSON.stringify(openai.body)).not.toContain("cache_control");
      // And the CONTENT SHAPE is the caller's own: marking a breakpoint
      // promotes a string `content` to a block array, so a leak changes the
      // message OpenAI is asked to complete, not just its metadata.
      expect((openai.body as Record<string, any>)["messages"]).toEqual([
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: "is claim 91 covered?" },
      ]);
    } finally {
      provider.restore();
    }
  });

  /**
   * The mirror image: the OpenAI adapter REMOVES `prompt_cache` from the body
   * it sends (the member is FerroGate's own and would 400 an upstream). If that
   * removal writes through, the directive is gone before the Anthropic
   * candidate ever reads it, and the caller's contract silently evaporates on
   * failover rather than leaking.
   */
  it("an openai attempt leaves the anthropic fallback's directive intact", async () => {
    const provider = interceptProviderFetch((request) =>
      request.url.includes("api.openai.example")
        ? providerJson({ error: "overloaded" }, 503)
        : providerJson(ANTHROPIC_MESSAGE),
    );
    try {
      const res = await harness({}, ROUTES).post(
        "/v1/chat/completions",
        // `auto`, not `explicit`: `explicit` would take the OpenAI route OFF
        // the ladder, so only one candidate would ever be prepared and the
        // ordering this test exists to exercise would not happen.
        chatRequest("failover-cached", { mode: "auto" }),
      );
      expect(res.status).toBe(200);
      expect(provider.requests).toHaveLength(2);
      const anthropic = provider.requests[1]!;
      expect(anthropic.url).toContain("api.anthropic.example");
      expect((anthropic.body as Record<string, any>)["system"]).toEqual([
        { type: "text", text: SYSTEM_PROMPT, cache_control: { type: "ephemeral" } },
      ]);
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

  it("an explicit `prompt_cache` is read here too, and refused where it cannot be honoured", async () => {
    // `/v1/messages` reaches the same governed chokepoint every other ingress
    // does, so a directive it DROPS is a directive the route silently declines
    // to honour while answering 200 — the exact shape #674 exists to forbid,
    // and worse here because `off` is a retention control rather than a cost
    // knob. The route is OpenAI-backed and OpenAI cannot disable its automatic
    // caching, so the only honest answer is a refusal.
    const provider = interceptProviderFetch(() => providerJson(OPENAI_COMPLETION));
    try {
      const res = await harness({}, ROUTES).post("/v1/messages", {
        model: "gpt-4o-mini",
        max_tokens: 256,
        messages: [{ role: "user", content: "is claim 91 covered?" }],
        prompt_cache: { mode: "off" },
      });
      expect(res.status).toBe(400);
      expect((await errorBody(res)).error.code).toBe("model_capability_unsupported");
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });

  it("a `prompt_cache` on /v1/messages reaches the family's own mechanism", async () => {
    // The other half of the same claim: read means READ, not merely validated.
    const provider = interceptProviderFetch(() => providerJson(ANTHROPIC_MESSAGE));
    try {
      const res = await harness({}, ROUTES).post("/v1/messages", {
        model: "claude-logical",
        max_tokens: 256,
        system: SYSTEM_PROMPT,
        messages: [{ role: "user", content: "is claim 91 covered?" }],
        prompt_cache: { mode: "explicit", ttl: "1h" },
      });
      expect(res.status).toBe(200);
      const body = provider.lastRequest().body as Record<string, any>;
      expect(body["system"]).toEqual([
        { type: "text", text: SYSTEM_PROMPT, cache_control: { type: "ephemeral", ttl: "1h" } },
      ]);
      expect(body["messages"]).toEqual([{ role: "user", content: "is claim 91 covered?" }]);
      // FerroGate's own member never reaches a provider.
      expect(JSON.stringify(body)).not.toContain("prompt_cache");
    } finally {
      provider.restore();
    }
  });

  it("a stated directive overrides an inferred one", async () => {
    // A caller that both left native markers AND stated `off` has said two
    // things; the STATEMENT is the one it made deliberately, and `off` means
    // the markers come off rather than being honoured behind its back.
    const provider = interceptProviderFetch(() => providerJson(ANTHROPIC_MESSAGE));
    try {
      const res = await harness({}, ROUTES).post("/v1/messages", {
        model: "claude-logical",
        max_tokens: 256,
        system: [
          { type: "text", text: SYSTEM_PROMPT, cache_control: { type: "ephemeral", ttl: "1h" } },
        ],
        messages: [{ role: "user", content: "is claim 91 covered?" }],
        prompt_cache: { mode: "off" },
      });
      expect(res.status).toBe(200);
      expect(JSON.stringify(provider.lastRequest().body)).not.toContain("cache_control");
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
