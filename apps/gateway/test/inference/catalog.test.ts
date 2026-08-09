/**
 * The env-driven model registry and the provider egress it feeds — driven
 * through the app the Worker actually deploys.
 *
 * This file exists because of a specific defect: `src/index.ts` used to mount
 * `inferenceRouteModule()` with NO dependencies, so `resolveDeps({})` handed the
 * data plane the EMPTY model resolver and a request that passed auth and Zod
 * validation then died at `400 model_not_found` without an upstream ever being
 * contacted. Every test below therefore drives the DEFAULT EXPORT of
 * `src/index.ts` — the composition root itself — with a Worker `env`, so a
 * regression that unwires the registry fails here even though the standalone
 * `createInferenceRouter` suites would stay green.
 *
 * Only the outbound provider `fetch` is faked (see `provider-mock.ts`;
 * `docs/rewrite/TESTING.md` §2 prescribes MSW, which is not installed). The
 * registry, the adapters, the dispatcher, the SSE tower, the usage tap, the
 * contract router and the auth guard are all the real ones.
 */
import { describe, expect, it } from "vitest";
import app from "../../src/index.js";
import {
  InMemoryUsageSink,
  buildModelCatalog,
  createInferenceRouter,
  defaultAuthScheme,
  modelCatalogFromEnv,
  modelsFromEnv,
} from "../../src/inference/index.js";
import type { ModelRecord, ProviderRecord } from "../../src/inference/index.js";
import { controlNamespace } from "../support/control-namespace.js";
import {
  OPENAI_CHAT_STREAM_FRAMES,
  interceptProviderFetch,
  providerJson,
  providerSse,
  readBody,
  sseBytes,
} from "./provider-mock.js";

const BASE = "https://gw.test";

/** Never a real credential — the value only has to survive the join. */
const RELAY_TOKEN = "test-relay-token-value";
const OPENAI_TOKEN = "sk-test-openai-value";

/**
 * The provider table.
 *
 * `anthropic-relay` is the shape this wiring exists to support: an
 * Anthropic-Messages-compatible relay that authenticates with
 * `Authorization: Bearer` rather than Anthropic's own `x-api-key`, declared with
 * `auth_scheme`. `openai-main` declares nothing, so it takes the family default.
 */
const PROVIDERS: readonly ProviderRecord[] = [
  {
    name: "anthropic-relay",
    kind: "anthropic",
    base_url: "https://relay.test/v1",
    api_key_var: "ANTHROPIC_AUTH_TOKEN",
    auth_scheme: "bearer",
  },
  {
    name: "openai-main",
    kind: "openai",
    base_url: "https://openai.test/v1",
    api_key_var: "OPENAI_API_KEY",
  },
];

/**
 * The logical→physical mapping. NONE of these logical names is a model id any
 * upstream would recognise — that is the point: the registry indirection has to
 * be doing real work for these tests to pass.
 */
const MODELS: readonly ModelRecord[] = [
  {
    name: "ferrogate-reasoning",
    provider: "anthropic-relay",
    provider_model: "claude-sonnet-4-5-20250929",
    capabilities: ["chat", "streaming", "tools"],
  },
  {
    name: "ferrogate-fast",
    provider: "openai-main",
    provider_model: "gpt-4o-mini",
    capabilities: ["chat", "streaming"],
  },
  {
    name: "ferrogate-retired",
    provider: "openai-main",
    provider_model: "gpt-3.5-turbo",
    enabled: false,
  },
];

/** Worker bindings: the two tables, the two secrets they NAME, and one key. */
const ENV = {
  GATEWAY_PROVIDERS: JSON.stringify(PROVIDERS),
  CONTROL_DATA: controlNamespace(),
  GATEWAY_MODELS: JSON.stringify(MODELS),
  ANTHROPIC_AUTH_TOKEN: RELAY_TOKEN,
  OPENAI_API_KEY: OPENAI_TOKEN,
  GATEWAY_STATIC_API_KEYS: JSON.stringify([
    { key: "fg_root", id: "key_root", platform_operator: true },
  ]),
};

const AUTHED = { authorization: "Bearer fg_root", "content-type": "application/json" };

async function call(path: string, init?: RequestInit): Promise<Response> {
  return await app.request(`${BASE}${path}`, init, ENV);
}

async function post(path: string, body: unknown): Promise<Response> {
  return await call(path, { method: "POST", headers: AUTHED, body: JSON.stringify(body) });
}

interface ErrorEnvelope {
  error: { message: string; code: string };
}

// ---------------------------------------------------------------------------
// Resolution + dispatch
// ---------------------------------------------------------------------------

describe("the deployed Worker resolves logical models to physical routes", () => {
  it("dispatches a logical model to its provider's endpoint with the provider's model id", async () => {
    const provider = interceptProviderFetch(() =>
      providerJson({
        id: "msg_1",
        type: "message",
        role: "assistant",
        model: "claude-sonnet-4-5-20250929",
        content: [{ type: "text", text: "hi" }],
        usage: { input_tokens: 7, output_tokens: 3 },
      }),
    );
    try {
      const res = await post("/v1/chat/completions", {
        model: "ferrogate-reasoning",
        messages: [{ role: "user", content: "hello" }],
      });
      expect(res.status).toBe(200);

      const upstream = provider.lastRequest();
      // The Anthropic adapter's endpoint, built from the PROVIDER's base_url —
      // not from anything the client sent.
      expect(upstream.url).toBe("https://relay.test/v1/messages");
      expect(upstream.method).toBe("POST");

      const body = upstream.body as Record<string, unknown>;
      // THE registry invariant: the physical id goes on the wire, and the
      // logical name the client asked for does not.
      expect(body.model).toBe("claude-sonnet-4-5-20250929");
      expect(body.model).not.toBe("ferrogate-reasoning");
      // `prepare_chat_completions` on the Anthropic family: `max_tokens` is
      // required upstream, so the adapter defaults it.
      expect(body.max_tokens).toBe(1024);
      expect(body.stream).toBe(false);
    } finally {
      provider.restore();
    }
  });

  it("authenticates the relay with the declared auth_scheme, and pins anthropic-version", async () => {
    const provider = interceptProviderFetch(() => providerJson({ id: "msg_1", content: [] }));
    try {
      await post("/v1/chat/completions", {
        model: "ferrogate-reasoning",
        messages: [{ role: "user", content: "hello" }],
      });
      const { headers } = provider.lastRequest();
      expect(headers.authorization).toBe(`Bearer ${RELAY_TOKEN}`);
      // `auth_scheme: "bearer"` REPLACES the family default; sending both would
      // let a relay that trusts either one accept a credential twice over.
      expect(headers["x-api-key"]).toBeUndefined();
      expect(headers["anthropic-version"]).toBe("2023-06-01");
      expect(headers["content-type"]).toBe("application/json");
    } finally {
      provider.restore();
    }
  });

  it("keeps the Rust family default for a provider that declares no auth_scheme", async () => {
    const provider = interceptProviderFetch(() => providerJson({ id: "chatcmpl-1", choices: [] }));
    try {
      await post("/v1/chat/completions", {
        model: "ferrogate-fast",
        messages: [{ role: "user", content: "hello" }],
      });
      const upstream = provider.lastRequest();
      expect(upstream.url).toBe("https://openai.test/v1/chat/completions");
      expect(upstream.headers.authorization).toBe(`Bearer ${OPENAI_TOKEN}`);
      expect((upstream.body as Record<string, unknown>).model).toBe("gpt-4o-mini");
    } finally {
      provider.restore();
    }
  });

  it("keeps the Rust error semantics for an unknown model — and contacts no upstream", async () => {
    const provider = interceptProviderFetch(() => providerJson({}));
    try {
      const res = await post("/v1/chat/completions", {
        model: "no-such-model",
        messages: [{ role: "user", content: "hello" }],
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorEnvelope;
      expect(body.error.code).toBe("model_not_found");
      expect(body.error.message).toBe("unknown model no-such-model");
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });

  it("distinguishes a disabled model from an unknown one", async () => {
    const res = await post("/v1/chat/completions", {
      model: "ferrogate-retired",
      messages: [{ role: "user", content: "hello" }],
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorEnvelope;
    expect(body.error.code).toBe("model_disabled");
    expect(body.error.message).toBe("model ferrogate-retired is disabled");
  });

  it("lists the configured logical models, owned by their provider", async () => {
    const res = await call("/v1/models", { headers: AUTHED });
    expect(res.status).toBe(200);
    const listing = (await res.json()) as {
      object: string;
      data: { id: string; owned_by: string }[];
    };
    expect(listing.object).toBe("list");
    expect(listing.data.map((model) => model.id).sort()).toEqual([
      "ferrogate-fast",
      "ferrogate-reasoning",
    ]);
    expect(listing.data.find((model) => model.id === "ferrogate-reasoning")?.owned_by).toBe(
      "anthropic-relay",
    );
  });

  it("forwards the inbound request's abort signal to the provider fetch", async () => {
    const controller = new AbortController();
    const original = globalThis.fetch;
    let seen: AbortSignal | null | undefined;
    globalThis.fetch = (async (_input: unknown, init?: RequestInit) => {
      seen = init?.signal;
      return providerJson({ id: "msg_1", content: [] });
    }) as typeof globalThis.fetch;
    try {
      await app.request(
        `${BASE}/v1/chat/completions`,
        {
          method: "POST",
          headers: AUTHED,
          body: JSON.stringify({
            model: "ferrogate-reasoning",
            messages: [{ role: "user", content: "hello" }],
          }),
          signal: controller.signal,
        },
        ENV,
      );
    } finally {
      globalThis.fetch = original;
    }
    // Client disconnect must reach the upstream: without a live signal here the
    // provider keeps generating (and billing) for a client that has hung up.
    //
    // This used to assert `seen === controller.signal`. It cannot any more:
    // `dispatchUpstream` now composes the client signal with the
    // `limits.dispatchTimeoutMs` deadline (`AbortSignal.any`), so the signal the
    // provider fetch receives is a DERIVED one. Identity was only ever a proxy
    // for the real invariant — that aborting the CLIENT aborts the upstream —
    // so the invariant is asserted directly instead, which still catches the
    // regression identity was guarding: the body reader's `c.req.raw`
    // replacement mints a fresh, never-aborted signal, and a derived signal
    // built from THAT would stay unaborted below.
    expect(seen).toBeInstanceOf(AbortSignal);
    expect(seen?.aborted).toBe(false);
    controller.abort(new Error("client hung up"));
    expect(seen?.aborted).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Streaming + metering, on the env-driven registry
// ---------------------------------------------------------------------------

const ANTHROPIC_STREAM_FRAMES: readonly string[] = [
  'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4-5-20250929","content":[],"usage":{"input_tokens":11,"output_tokens":0}}}',
  'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
  'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}',
  'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}',
  'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":4}}',
  'event: message_stop\ndata: {"type":"message_stop"}',
];

describe("streaming and metering over the env-driven registry", () => {
  /** The same env, driven through the standalone router so the sink is visible. */
  function metered(): {
    sink: InMemoryUsageSink;
    send: (body: unknown, path?: string) => Promise<Response>;
  } {
    const sink = new InMemoryUsageSink();
    const router = createInferenceRouter({ models: modelsFromEnv, usage: sink });
    return {
      sink,
      send: async (body: unknown, path = "/v1/chat/completions") =>
        await router.request(
          `${BASE}${path}`,
          {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(body),
          },
          ENV,
        ),
    };
  }

  it("relays the upstream SSE bytes untouched and meters the trailing usage frame", async () => {
    const provider = interceptProviderFetch(() => providerSse(ANTHROPIC_STREAM_FRAMES));
    try {
      const { sink, send } = metered();
      const res = await send({
        model: "ferrogate-reasoning",
        messages: [{ role: "user", content: "hi" }],
        stream: true,
      });

      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toBe("text/event-stream");
      expect((provider.lastRequest().body as Record<string, unknown>).stream).toBe(true);
      // Byte-for-byte: an Anthropic upstream on an Anthropic-dialect leg is a
      // pure proxy, so re-framing would be a defect, not a nicety.
      expect(await readBody(res)).toBe(sseBytes(ANTHROPIC_STREAM_FRAMES));

      // Usage is scraped from the frames the CLIENT was served: `input_tokens`
      // arrives on `message_start`, `output_tokens` only on `message_delta`, and
      // the merge has to survive both.
      const usage = sink.last;
      expect(usage?.logicalModel).toBe("ferrogate-reasoning");
      expect(usage?.provider).toBe("anthropic-relay");
      expect(usage?.providerModel).toBe("claude-sonnet-4-5-20250929");
      expect(usage?.stream).toBe(true);
      expect(usage?.promptTokens).toBe(11);
      expect(usage?.completionTokens).toBe(4);
      expect(usage?.totalTokens).toBe(15);
    } finally {
      provider.restore();
    }
  });

  it("meters a non-streaming response from its usage object", async () => {
    const provider = interceptProviderFetch(() =>
      providerJson({
        id: "msg_1",
        content: [{ type: "text", text: "hi" }],
        usage: { input_tokens: 21, output_tokens: 9 },
      }),
    );
    try {
      const { sink, send } = metered();
      const res = await send({
        model: "ferrogate-reasoning",
        messages: [{ role: "user", content: "hi" }],
      });
      expect(res.status).toBe(200);
      expect(sink.last?.promptTokens).toBe(21);
      expect(sink.last?.completionTokens).toBe(9);
      expect(sink.last?.stream).toBe(false);
      expect(sink.last?.status).toBe(200);
    } finally {
      provider.restore();
    }
  });

  it("normalizes an OpenAI upstream into Anthropic frames on the /v1/messages leg", async () => {
    const provider = interceptProviderFetch(() => providerSse(OPENAI_CHAT_STREAM_FRAMES));
    try {
      const { sink, send } = metered();
      const res = await send(
        {
          model: "ferrogate-fast",
          max_tokens: 64,
          messages: [{ role: "user", content: "hi" }],
          stream: true,
        },
        "/v1/messages",
      );
      expect(res.status).toBe(200);
      const body = await readBody(res);
      // The client asked for Anthropic and the upstream speaks OpenAI, so the
      // `MessagesStreamNormalizer` leg of `src/streaming/` has to run: the
      // upstream's own frames must NOT appear.
      expect(body).not.toBe(sseBytes(OPENAI_CHAT_STREAM_FRAMES));
      expect(body).toContain("event: message_start");
      expect(body).toContain("event: content_block_delta");
      expect(body).toContain("event: message_stop");
      // Token-by-token delivery survives the translation (issue #310): the two
      // upstream chunks stay two `text_delta`s rather than being coalesced.
      expect(body).toContain('{"type":"text_delta","text":"Hel"}');
      expect(body).toContain('{"type":"text_delta","text":"lo"}');
      // Metering reads the dialect the client was served, not the upstream's.
      expect(sink.last?.route).toBe("anthropic.messages");
      expect(sink.last?.promptTokens).toBe(11);
      expect(sink.last?.completionTokens).toBe(4);
    } finally {
      provider.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// Fail-closed table parsing
// ---------------------------------------------------------------------------

describe("model catalog validation", () => {
  const provider: ProviderRecord = {
    name: "p",
    kind: "anthropic",
    base_url: "https://p.test/v1",
  };
  const model: ModelRecord = { name: "m", provider: "p", provider_model: "physical-m" };

  it("accepts the well-formed join", () => {
    const result = buildModelCatalog([provider], [model]);
    expect(result.ok).toBe(true);
    expect(result.ok && result.routes[0]?.providerModel).toBe("physical-m");
    // No `auth_scheme` declared ⇒ the Anthropic family's Rust hard-coding.
    expect(result.ok && result.routes[0]?.authScheme).toBe("x-api-key");
    expect(result.ok && result.routes[0]?.enabled).toBe(true);
  });

  it("refuses a duplicate model name (Rust ModelRegistryError::DuplicateModel)", () => {
    const result = buildModelCatalog([provider], [model, { ...model, provider_model: "other" }]);
    expect(result).toEqual({ ok: false, reason: "duplicate model m" });
  });

  it("refuses a duplicate provider name", () => {
    const result = buildModelCatalog([provider, provider], [model]);
    expect(result).toEqual({ ok: false, reason: "duplicate provider p" });
  });

  it("refuses a model naming an unknown provider", () => {
    const result = buildModelCatalog([provider], [{ ...model, provider: "ghost" }]);
    expect(result).toEqual({ ok: false, reason: "model m names unknown provider ghost" });
  });

  it("refuses an unported adapter family rather than aliasing it onto a neighbour", () => {
    const result = buildModelCatalog([{ ...provider, kind: "not-a-family" }], [model]);
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toContain("unsupported kind not-a-family");
  });

  it("refuses a provider whose api_key_var is not bound", () => {
    const result = buildModelCatalog([{ ...provider, api_key_var: "MISSING" }], [model], {});
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toContain("api_key_var MISSING");
    // The binding NAME may be reported; a bound value must never be.
    const bound = buildModelCatalog([{ ...provider, api_key_var: "TOKEN" }], [model], {
      TOKEN: "secret-value",
    });
    expect(bound.ok && bound.routes[0]?.apiKey).toBe("secret-value");
  });

  it("treats absent tables as 'nothing configured', not as an error", () => {
    expect(modelCatalogFromEnv({})).toEqual({ ok: true, routes: [] });
  });

  it("refuses malformed JSON and an unknown field, closing the catalog", () => {
    expect(modelCatalogFromEnv({ GATEWAY_MODELS: "{not json" }).ok).toBe(false);
    const typo = modelCatalogFromEnv({
      GATEWAY_PROVIDERS: JSON.stringify([{ ...provider, base_urls: "https://x.test" }]),
    });
    expect(typo.ok).toBe(false);
  });

  it("resolves nothing at all when the table is invalid — a typo cannot widen access", () => {
    const resolver = modelsFromEnv({
      GATEWAY_PROVIDERS: JSON.stringify([provider]),
      GATEWAY_MODELS: JSON.stringify([model, model]),
    });
    expect(resolver.catalog()).toHaveLength(0);
    expect(resolver.resolve("m")).toBeNull();
  });

  it("keeps the Rust credential scheme per family", () => {
    expect(defaultAuthScheme("anthropic")).toBe("x-api-key");
    expect(defaultAuthScheme("openai")).toBe("bearer");
    expect(defaultAuthScheme("deepseek")).toBe("bearer");
    expect(defaultAuthScheme("openai-compatible")).toBe("bearer");
  });
});

// ---------------------------------------------------------------------------
// Cloudflare AI Gateway configuration (issue #672)
// ---------------------------------------------------------------------------

/**
 * The CONFIG half of the mount. The behavioural half — that a routed provider's
 * requests actually leave addressed at the gateway — is
 * `test/inference/cloudflare-ai-gateway-mount.test.ts`, through `SELF.fetch`;
 * nothing here would catch the routing being unwired again, which is why these
 * two files are separate and why that one exists at all.
 *
 * Every refusal below is a WHOLE-CATALOG refusal on purpose. The tempting
 * alternative — drop the routing and dispatch to the vendor directly — is
 * invisible to an operator who believes their traffic is being cached, rate
 * limited and logged by the AI Gateway, and invisible misconfiguration is the
 * defect class this issue is about.
 */
describe("cloudflare_ai_gateway on the provider table", () => {
  const routed: ProviderRecord = {
    name: "p",
    kind: "openai",
    base_url: "https://p.test/v1",
    cloudflare_ai_gateway: { gateway_id: "gw" },
  };
  const model: ModelRecord = { name: "m", provider: "p", provider_model: "physical-m" };
  const account = { account_id: "acct" };

  it("carries the account block and the provider block onto every route", () => {
    const result = buildModelCatalog(
      [routed],
      [{ ...model, fallbacks: [{ provider: "p", provider_model: "fallback-m" }] }],
      {},
      account,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // BOTH legs: a fallback that bypassed the gateway would be the same defect
    // at whatever share of traffic fails over.
    expect(result.routes).toHaveLength(2);
    for (const route of result.routes) {
      expect(route.cloudflareAiGateway).toEqual({
        accountId: "acct",
        gatewayId: "gw",
        // Cloudflare's public hosts, from `cloudflareConfigSchema`'s defaults.
        gatewayBaseUrl: "https://gateway.ai.cloudflare.com",
        apiBaseUrl: "https://api.cloudflare.com/client/v4",
        mode: "Compat",
      });
    }
  });

  it("leaves an unrouted provider's routes with no routing at all", () => {
    const result = buildModelCatalog(
      [{ name: "p", kind: "openai", base_url: "https://p.test/v1" }],
      [model],
      {},
      account,
    );
    expect(result.ok && result.routes[0]?.cloudflareAiGateway).toBeUndefined();
  });

  it("refuses a routed provider when the account block is absent", () => {
    const result = buildModelCatalog([routed], [model], {});
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toContain("requires the account-level");
  });

  it("refuses a routed provider whose aig_token_var is not bound, and never prints the value", () => {
    const missing = buildModelCatalog(
      [{ ...routed, cloudflare_ai_gateway: { gateway_id: "gw", aig_token_var: "MISSING" } }],
      [model],
      {},
      account,
    );
    expect(missing.ok).toBe(false);
    expect(missing.ok === false && missing.reason).toContain("aig_token_var MISSING");

    const bound = buildModelCatalog(
      [{ ...routed, cloudflare_ai_gateway: { gateway_id: "gw", aig_token_var: "AIG" } }],
      [model],
      { AIG: "cf-token-value" },
      account,
    );
    expect(bound.ok && bound.routes[0]?.cloudflareAiGateway?.aigToken).toBe("cf-token-value");
    expect(missing.ok === false && missing.reason).not.toContain("cf-token-value");
  });

  it("refuses the workers-ai pairing rather than taking the request off the AI binding", () => {
    const result = buildModelCatalog(
      [{ ...routed, kind: "workers-ai", name: "p" }],
      [model],
      {},
      account,
    );
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toContain("not supported for kind = workers-ai");
  });

  it("reads the account block out of GATEWAY_CLOUDFLARE, and refuses a malformed one", () => {
    const env = {
      GATEWAY_CLOUDFLARE: JSON.stringify(account),
      GATEWAY_PROVIDERS: JSON.stringify([
        { ...routed, cloudflare_ai_gateway: { gateway_id: "gw", mode: "unified" } },
      ]),
      GATEWAY_MODELS: JSON.stringify([model]),
    };
    const wired = modelCatalogFromEnv(env);
    expect(wired.ok && wired.routes[0]?.cloudflareAiGateway?.mode).toBe("Unified");

    // Blank is the OFF posture (and the committed wrangler.toml value), not an
    // error — it only bites once a provider asks to be routed.
    expect(modelCatalogFromEnv({ GATEWAY_CLOUDFLARE: "" }).ok).toBe(true);
    expect(modelCatalogFromEnv({ ...env, GATEWAY_CLOUDFLARE: "{not json" }).ok).toBe(false);
    // `.strict()`, like every other table here: a misspelled key must not read
    // as "no account id".
    expect(
      modelCatalogFromEnv({ ...env, GATEWAY_CLOUDFLARE: JSON.stringify({ accountId: "acct" }) }).ok,
    ).toBe(false);
  });
});
