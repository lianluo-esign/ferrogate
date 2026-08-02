/**
 * A caching directive must survive a cross-family failover (issue #690).
 *
 * The defect these tests pin: `cache_control` is an ANTHROPIC-shaped marker.
 * It reaches an Anthropic upstream only because the message list is copied
 * through; every other family rebuilds the upstream body and has its own
 * mechanism (Bedrock's `cachePoint`, OpenAI's automatic caching, Gemini's
 * implicit caching), so the same request is cached under entirely different
 * rules depending on which route the ladder picked — and the caller has no way
 * to say what it wanted. Cache economics differing per route, silently, is the
 * money-side twin of #674's output-contract drift.
 *
 * So the caller states ONE canonical intent (`prompt_cache`), each family
 * re-emits it in its own dialect, and what a family genuinely cannot express is
 * REFUSED rather than quietly served under different economics.
 */
import { describe, expect, test } from "vitest";

import {
  AnthropicAdapter,
  BedrockAdapter,
  GeminiAdapter,
  OpenAiCompatibleAdapter,
  SecretValue,
  VertexAiAdapter,
} from "../src/index.js";
import type { ProviderConfig } from "../src/index.js";

// --- fixtures --------------------------------------------------------------

/**
 * A body with a long, stable prefix (system + tools) and a volatile last turn —
 * the only shape prompt caching pays off on, in every family.
 */
const chatBody = (promptCache: unknown, extra: Record<string, unknown> = {}) => ({
  model: "logical",
  system: "You are a claims adjuster. <10k tokens of policy text>",
  messages: [{ role: "user", content: "is claim 91 covered?" }],
  ...(promptCache === undefined ? {} : { prompt_cache: promptCache }),
  ...extra,
});

const openaiProvider: ProviderConfig = {
  name: "openai",
  kind: "openai",
  baseUrl: "https://api.openai.example/v1/",
};
const anthropicProvider: ProviderConfig = {
  name: "anthropic",
  kind: "anthropic",
  baseUrl: "https://api.anthropic.example/v1/",
};
const geminiProvider: ProviderConfig = {
  name: "google",
  kind: "gemini",
  baseUrl: "https://generativelanguage.googleapis.example/v1beta/",
};
const vertexProvider: ProviderConfig = {
  name: "vertex",
  kind: "vertex",
  baseUrl: "https://us-central1-aiplatform.googleapis.example",
  gcpCredentials: {
    accessToken: new SecretValue("ya29.EXAMPLE"),
    projectId: "my-gcp-project",
    location: "us-central1",
  },
};
const bedrockProvider: ProviderConfig = {
  name: "bedrock",
  kind: "bedrock",
  baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.example",
  awsCredentials: {
    accessKeyId: "AKIDEXAMPLE",
    secretAccessKey: new SecretValue("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    region: "us-east-1",
  },
};

const chatPlan = (body: Record<string, unknown>) => ({
  logicalModel: "logical",
  providerModel: "physical",
  stream: false,
  body: body as never,
});

const bedrockBody = (body: Record<string, unknown>): Record<string, any> =>
  JSON.parse(new TextDecoder().decode(body as unknown as Uint8Array)) as Record<string, any>;

// --- per-family translation ------------------------------------------------

describe("the directive reaches every family's own caching mechanism", () => {
  test("anthropic marks the end of the static prefix with cache_control", () => {
    const prepared = new AnthropicAdapter().prepareChatCompletions(
      anthropicProvider,
      chatPlan(chatBody({ mode: "explicit", ttl: "1h" })),
    );
    const body = prepared.body as Record<string, any>;
    // The breakpoint lands on the LAST system block: Anthropic's cache prefix is
    // rendered tools → system → messages, so one marker there covers both the
    // tools and the system prompt, and leaves the volatile turn outside it.
    expect(body["system"]).toEqual([
      {
        type: "text",
        text: "You are a claims adjuster. <10k tokens of policy text>",
        cache_control: { type: "ephemeral", ttl: "1h" },
      },
    ]);
    // The FerroGate-only directive must never reach a provider.
    expect(body["prompt_cache"]).toBeUndefined();
  });

  test("anthropic's default ttl is the 5-minute ephemeral form", () => {
    const prepared = new AnthropicAdapter().prepareChatCompletions(
      anthropicProvider,
      chatPlan(chatBody({ mode: "auto" })),
    );
    const system = (prepared.body as Record<string, any>)["system"] as Array<Record<string, any>>;
    expect(system[0]!["cache_control"]).toEqual({ type: "ephemeral" });
  });

  test("bedrock converse marks the same boundary with a cachePoint block", () => {
    const prepared = new BedrockAdapter().prepareChatCompletions(
      bedrockProvider,
      chatPlan(chatBody({ mode: "explicit", ttl: "5m" })),
    );
    const body = bedrockBody(prepared.body as Record<string, unknown>);
    expect(body["system"]).toEqual([
      { text: "You are a claims adjuster. <10k tokens of policy text>" },
      { cachePoint: { type: "default" } },
    ]);
  });

  test("openai-compatible relies on automatic caching and strips the directive", () => {
    const prepared = new OpenAiCompatibleAdapter().prepareChatCompletions(
      openaiProvider,
      chatPlan(chatBody({ mode: "auto" })),
    );
    const body = prepared.body as Record<string, any>;
    // OpenAI caches long prefixes automatically, so `auto` is already satisfied
    // — but the directive is FerroGate's field, and OpenAI rejects unknown
    // top-level members, so leaving it on the body would 400 the request.
    expect(body["prompt_cache"]).toBeUndefined();
    expect(body["messages"]).toEqual([{ role: "user", content: "is claim 91 covered?" }]);
  });

  test("gemini and vertex rely on implicit caching and strip the directive", () => {
    const gemini = new GeminiAdapter().prepareChatCompletions(
      geminiProvider,
      chatPlan(chatBody({ mode: "auto" })),
    );
    expect((gemini.body as Record<string, any>)["prompt_cache"]).toBeUndefined();
    const vertex = new VertexAiAdapter().prepareChatCompletions(
      vertexProvider,
      chatPlan(chatBody({ mode: "auto" })),
    );
    expect((vertex.body as Record<string, any>)["prompt_cache"]).toBeUndefined();
  });
});

// --- refusals --------------------------------------------------------------

describe("a family that cannot express the directive refuses it", () => {
  test("openai cannot pin a breakpoint or a lifetime, so `explicit` is refused", () => {
    expect(() =>
      new OpenAiCompatibleAdapter().prepareChatCompletions(
        openaiProvider,
        chatPlan(chatBody({ mode: "explicit", ttl: "1h" })),
      ),
    ).toThrowError(/prompt caching/i);
  });

  test("openai's automatic caching cannot be turned off, so `off` is refused", () => {
    // "Do not cache this prompt" is a real requirement (retention, isolation).
    // Serving it on a family that caches unconditionally would answer 200 while
    // doing the opposite of what the caller asked.
    expect(() =>
      new OpenAiCompatibleAdapter().prepareChatCompletions(
        openaiProvider,
        chatPlan(chatBody({ mode: "off" })),
      ),
    ).toThrowError(/prompt caching/i);
  });

  test("bedrock's cachePoint has no selectable lifetime, so a 1h ttl is refused", () => {
    expect(() =>
      new BedrockAdapter().prepareChatCompletions(
        bedrockProvider,
        chatPlan(chatBody({ mode: "explicit", ttl: "1h" })),
      ),
    ).toThrowError(/prompt caching/i);
  });

  test("gemini refuses `explicit` (its explicit cache is an out-of-band resource)", () => {
    expect(() =>
      new GeminiAdapter().prepareChatCompletions(
        geminiProvider,
        chatPlan(chatBody({ mode: "explicit", ttl: "5m" })),
      ),
    ).toThrowError(/prompt caching/i);
  });

  test("an unknown mode is a caller error, not a silent no-op", () => {
    expect(() =>
      new AnthropicAdapter().prepareChatCompletions(
        anthropicProvider,
        chatPlan(chatBody({ mode: "forever" })),
      ),
    ).toThrowError(/prompt_cache/i);
  });
});

// --- `off` is a contract, not a hint ---------------------------------------

describe("`off` removes the caller's native markers too", () => {
  test("anthropic sends no cache_control at all when caching is off", () => {
    const prepared = new AnthropicAdapter().prepareChatCompletions(
      anthropicProvider,
      chatPlan(
        chatBody({ mode: "off" }, {
          messages: [
            {
              role: "user",
              content: [
                { type: "text", text: "policy", cache_control: { type: "ephemeral" } },
                { type: "text", text: "is claim 91 covered?" },
              ],
            },
          ],
        }),
      ),
    );
    // A native marker the caller left in place would keep writing the prompt to
    // Anthropic's cache, so "off" has to strip it — otherwise the directive is
    // a comment, not a control.
    expect(JSON.stringify(prepared.body)).not.toContain("cache_control");
  });
});
