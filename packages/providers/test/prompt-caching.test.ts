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
  AdapterError,
  AnthropicAdapter,
  BedrockAdapter,
  GeminiAdapter,
  OpenAiCompatibleAdapter,
  SecretValue,
  VertexAiAdapter,
  WorkersAiAdapter,
  chatCompletionToMessage,
  promptCacheFromBody,
  toChatCompletions,
} from "../src/index.js";
import type { ProviderConfig } from "../src/index.js";

// --- fixtures --------------------------------------------------------------

const SYSTEM_PROMPT = "You are a claims adjuster. <10k tokens of policy text>";

/**
 * A body with a long, stable prefix (the system turn) and a volatile last turn
 * — the only shape prompt caching pays off on, in every family. Written in the
 * OpenAI grammar (`role: "system"` message), because that is the shape every
 * adapter is handed: the `/v1/chat/completions` ingress produces it directly
 * and the `/v1/messages` ingress is translated into it on the way in.
 */
const chatBody = (promptCache: unknown, extra: Record<string, unknown> = {}) => ({
  model: "logical",
  messages: [
    { role: "system", content: SYSTEM_PROMPT },
    { role: "user", content: "is claim 91 covered?" },
  ],
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


const workersAiProvider: ProviderConfig = {
  name: "cf-ai",
  kind: "workers-ai",
  baseUrl: "https://api.cloudflare.example/client/v4/accounts/acct/",
  apiKey: "cf-token",
};

// --- canonical parsing -----------------------------------------------------

describe("canonical directive parsing", () => {
  test("the three modes collapse to one canonical intent", () => {
    expect(promptCacheFromBody({ prompt_cache: { mode: "auto" } } as never)).toEqual({
      kind: "auto",
    });
    expect(promptCacheFromBody({ prompt_cache: { mode: "off" } } as never)).toEqual({
      kind: "off",
    });
    // An explicit request with no ttl means the default lifetime, not "any".
    expect(promptCacheFromBody({ prompt_cache: { mode: "explicit" } } as never)).toEqual({
      kind: "explicit",
      ttl: "5m",
    });
  });

  test("a body with no directive states no intent", () => {
    expect(promptCacheFromBody({ messages: [] } as never)).toBeUndefined();
  });

  test("a ttl on a mode that promises nothing is a caller error", () => {
    // Accepting it would let a caller believe it had bought a 1h cache when
    // `auto` guarantees nothing at all.
    expect(() =>
      promptCacheFromBody({ prompt_cache: { mode: "auto", ttl: "1h" } } as never),
    ).toThrowError(/only meaningful/i);
  });

  test("an unsupported ttl is refused rather than rounded", () => {
    expect(() =>
      promptCacheFromBody({ prompt_cache: { mode: "explicit", ttl: "24h" } } as never),
    ).toThrowError(/ttl/i);
  });
});

// --- per-family translation ------------------------------------------------

describe("the directive reaches every family's own caching mechanism", () => {
  test("anthropic marks the end of the static prefix with cache_control", () => {
    const prepared = new AnthropicAdapter().prepareChatCompletions(
      anthropicProvider,
      chatPlan(chatBody({ mode: "explicit", ttl: "1h" })),
    );
    const body = prepared.body as Record<string, any>;
    // The breakpoint lands at the END of the static prefix: Anthropic's cache
    // prefix is rendered tools → system → messages, so a marker there covers
    // the tools and the system prompt while leaving the volatile turn — the
    // caller's actual question — outside the cached span.
    expect(body["messages"]).toEqual([
      {
        role: "system",
        content: [
          { type: "text", text: SYSTEM_PROMPT, cache_control: { type: "ephemeral", ttl: "1h" } },
        ],
      },
      { role: "user", content: "is claim 91 covered?" },
    ]);
    // The FerroGate-only directive must never reach a provider.
    expect(body["prompt_cache"]).toBeUndefined();
  });

  test("anthropic's default ttl is the 5-minute ephemeral form", () => {
    const prepared = new AnthropicAdapter().prepareChatCompletions(
      anthropicProvider,
      chatPlan(chatBody({ mode: "auto" })),
    );
    const messages = (prepared.body as Record<string, any>)["messages"] as Array<
      Record<string, any>
    >;
    expect(messages[0]!["content"][0]["cache_control"]).toEqual({ type: "ephemeral" });
  });

  test("a top-level `system` carries the breakpoint when the body has one", () => {
    // The `/v1/responses` canonicalizer lifts `instructions` to a top-level
    // `system`, so both spellings have to reach the same boundary.
    const prepared = new AnthropicAdapter().prepareChatCompletions(
      anthropicProvider,
      chatPlan({
        model: "logical",
        system: SYSTEM_PROMPT,
        messages: [{ role: "user", content: "is claim 91 covered?" }],
        prompt_cache: { mode: "auto" },
      }),
    );
    expect((prepared.body as Record<string, any>)["system"]).toEqual([
      { type: "text", text: SYSTEM_PROMPT, cache_control: { type: "ephemeral" } },
    ]);
  });

  test("bedrock converse marks the same boundary with a cachePoint block", () => {
    const prepared = new BedrockAdapter().prepareChatCompletions(
      bedrockProvider,
      chatPlan(chatBody({ mode: "explicit", ttl: "5m" })),
    );
    const body = prepared.body as Record<string, any>;
    // Same boundary, Converse's spelling: a `cachePoint` BLOCK after the static
    // system content rather than a member of the preceding block.
    expect(body["system"]).toEqual([
      { text: SYSTEM_PROMPT },
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
    // …and the rest of the body is untouched: no breakpoint is invented for a
    // family that chooses its own prefix.
    expect(body["messages"]).toEqual([
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: "is claim 91 covered?" },
    ]);
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

describe("no family may silently ignore the directive", () => {
  /** Every family, prepared through its own adapter, with one shared body. */
  const prepareEverywhere = (directive: unknown): Array<[string, () => unknown]> => [
    [
      "anthropic",
      () =>
        new AnthropicAdapter().prepareChatCompletions(
          anthropicProvider,
          chatPlan(chatBody(directive)),
        ).body,
    ],
    [
      "bedrock",
      () =>
        new BedrockAdapter().prepareChatCompletions(bedrockProvider, chatPlan(chatBody(directive)))
          .body,
    ],
    [
      "openai-compatible",
      () =>
        new OpenAiCompatibleAdapter().prepareChatCompletions(
          openaiProvider,
          chatPlan(chatBody(directive)),
        ).body,
    ],
    [
      "gemini",
      () =>
        new GeminiAdapter().prepareChatCompletions(geminiProvider, chatPlan(chatBody(directive)))
          .body,
    ],
    [
      "vertex",
      () =>
        new VertexAiAdapter().prepareChatCompletions(vertexProvider, chatPlan(chatBody(directive)))
          .body,
    ],
    [
      "workers-ai",
      () =>
        new WorkersAiAdapter().prepareChatCompletions(
          workersAiProvider,
          chatPlan(chatBody(directive)),
        ).body,
    ],
  ];

  test("an `explicit` contract is either honoured on the wire or refused", () => {
    // This is the whole issue in one assertion. Before #690 EVERY family in
    // this list produced a body with no caching in it and answered 200, so the
    // caller could not tell a cached leg from an uncached one. Now each one
    // either carries its own mechanism or takes itself out of the ladder.
    for (const [family, prepare] of prepareEverywhere({ mode: "explicit", ttl: "5m" })) {
      let refused: unknown;
      let body: unknown;
      try {
        body = prepare();
      } catch (error) {
        refused = error;
      }
      if (refused !== undefined) {
        expect(refused, family).toBeInstanceOf(AdapterError);
        expect((refused as AdapterError).kind, family).toBe("UnsupportedCapability");
        continue;
      }
      const serialized = JSON.stringify(body);
      expect(serialized, family).toMatch(/cache_control|cachePoint/);
      expect(serialized, family).not.toContain("prompt_cache");
    }
  });

  test("`auto` never costs a route — every family accepts it", () => {
    for (const [family, prepare] of prepareEverywhere({ mode: "auto" })) {
      expect(() => prepare(), family).not.toThrow();
      expect(JSON.stringify(prepare()), family).not.toContain("prompt_cache");
    }
  });
});

// --- family isolation ------------------------------------------------------

describe("preparing one family never rewrites the caller's body", () => {
  /**
   * Every candidate on a failover ladder is prepared from the SAME caller body.
   * An adapter that applies its family's mechanism by writing through to that
   * object is not adding a field to its own request — it is deciding what every
   * other candidate sends.
   *
   * So this asserts the invariant rather than any one field: after an adapter
   * has prepared, the caller's body is byte-identical to what it was. `#690`'s
   * `cache_control` is only the field that made the leak observable; the seam
   * would carry anything an adapter decided to normalise.
   */
  const preparers: Array<[string, (body: Record<string, unknown>) => unknown]> = [
    ["anthropic", (b) => new AnthropicAdapter().prepareChatCompletions(anthropicProvider, chatPlan(b))],
    ["bedrock", (b) => new BedrockAdapter().prepareChatCompletions(bedrockProvider, chatPlan(b))],
    [
      "openai-compatible",
      (b) => new OpenAiCompatibleAdapter().prepareChatCompletions(openaiProvider, chatPlan(b)),
    ],
    ["gemini", (b) => new GeminiAdapter().prepareChatCompletions(geminiProvider, chatPlan(b))],
    ["vertex", (b) => new VertexAiAdapter().prepareChatCompletions(vertexProvider, chatPlan(b))],
    [
      "workers-ai",
      (b) => new WorkersAiAdapter().prepareChatCompletions(workersAiProvider, chatPlan(b)),
    ],
  ];

  test("no adapter mutates the body it was handed", () => {
    for (const [family, prepare] of preparers) {
      // `auto` is the one directive every family accepts, so each adapter runs
      // its FULL preparation rather than bailing out at a refusal.
      const body = chatBody({ mode: "auto" });
      const pristine = structuredClone(body);
      prepare(body as Record<string, unknown>);
      expect(body, family).toEqual(pristine);
    }
  });

  test("a body prepared for one family is unchanged for the next", () => {
    // The ladder in miniature: one body, two families, in both orders. The
    // second family must send exactly what it would have sent alone.
    for (const order of [
      ["anthropic", "openai-compatible"],
      ["openai-compatible", "anthropic"],
    ]) {
      const shared = chatBody({ mode: "auto" });
      const solo = chatBody({ mode: "auto" });
      const [first, second] = order as [string, string];
      const prepareFirst = preparers.find(([name]) => name === first)![1];
      const prepareSecond = preparers.find(([name]) => name === second)![1];

      prepareFirst(shared as Record<string, unknown>);
      expect(
        JSON.stringify(prepareSecond(shared as Record<string, unknown>)),
        `${first} then ${second}`,
      ).toBe(JSON.stringify(prepareSecond(solo as Record<string, unknown>)));
    }
  });
});

// --- the /v1/messages translator -------------------------------------------

describe("the Anthropic-native ingress keeps the caller's caching intent", () => {
  test("a native cache_control becomes the canonical directive", () => {
    const translated = toChatCompletions({
      model: "claude-logical",
      system: [{ type: "text", text: SYSTEM_PROMPT, cache_control: { type: "ephemeral", ttl: "1h" } }],
      messages: [{ role: "user", content: "is claim 91 covered?" }],
    } as never) as Record<string, any>;
    // Every block above is REBUILT by the translation, so the marker itself
    // cannot survive; the intent is what has to, or a Claude-native caller
    // loses its whole prefix discount on FerroGate's own Claude ingress.
    expect(translated["prompt_cache"]).toEqual({ mode: "explicit", ttl: "1h" });
  });

  test("a request with no marker states no intent", () => {
    const translated = toChatCompletions({
      model: "claude-logical",
      messages: [{ role: "user", content: "hi" }],
    } as never) as Record<string, any>;
    expect(translated["prompt_cache"]).toBeUndefined();
  });

  test("the response carries the hit/miss split back in Anthropic's vocabulary", () => {
    const message = chatCompletionToMessage(
      {
        id: "chatcmpl-1",
        choices: [{ message: { role: "assistant", content: "covered" }, finish_reason: "stop" }],
        usage: {
          prompt_tokens: 9_012,
          completion_tokens: 3,
          prompt_tokens_details: { cached_tokens: 9_000 },
        },
      } as never,
      "claude-logical",
    ) as Record<string, any>;
    // OpenAI's prompt_tokens INCLUDES the cached tokens; Anthropic's
    // input_tokens excludes them, so the fresh count is the difference.
    expect(message["usage"]).toEqual({
      input_tokens: 12,
      output_tokens: 3,
      cache_read_input_tokens: 9_000,
    });
  });

  test("a response with no cached tokens keeps exactly the counters it had", () => {
    const message = chatCompletionToMessage(
      {
        choices: [{ message: { role: "assistant", content: "hi" }, finish_reason: "stop" }],
        usage: { prompt_tokens: 5, completion_tokens: 2 },
      } as never,
      "claude-logical",
    ) as Record<string, any>;
    expect(message["usage"]).toEqual({ input_tokens: 5, output_tokens: 2 });
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
