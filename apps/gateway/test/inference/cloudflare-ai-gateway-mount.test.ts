/**
 * ANTI-UNMOUNT for Cloudflare AI Gateway routing (issue #672).
 *
 * ## What was wrong, and why the suite was green anyway
 *
 * `packages/providers/src/cloudflare.ts` — `applyCloudflareAiGatewayRouting`,
 * the per-family surface map, the BYOK-preserving header upsert — has been
 * finished and tested since issue #406. Its ONLY caller was
 * `ProviderAdapterRegistry.prepare*` (`packages/providers/src/registry.ts`), and
 * the deployed data plane never constructs that class for dispatch: it resolves
 * adapters through `defaultAdapterRegistry` in
 * `apps/gateway/src/inference/adapters.ts`. So every request left FerroGate
 * addressed straight at the vendor, and no tenant got the caching, rate
 * limiting, analytics or unified billing the AI Gateway product provides.
 *
 * `packages/providers/test/registry-cloudflare.test.ts` was green throughout —
 * it drove the routing through the unmounted class. A unit test against the
 * registry cannot see this defect BY CONSTRUCTION, which is why every
 * assertion in this file goes through `SELF.fetch`: `src/worker.ts` →
 * `src/index.ts` → `createGatewayApp` → the mounted inference module → the real
 * adapter registry → the real dispatcher, with only `globalThis.fetch`
 * intercepted at the very edge, so what is asserted is the URL and the headers
 * that would have gone on the wire.
 *
 * The negative control (`a provider with no block still dials the vendor
 * directly`) is what keeps the positives from passing on a blanket rewrite.
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  type ProviderInterceptor,
  interceptProviderFetch,
  providerJson,
} from "./provider-mock.js";

const BASE = "https://gw.test";

/** Vendor hosts. Reaching either one for real is the defect, so they are `.invalid`. */
const OPENAI_UPSTREAM = "https://openai-vendor.invalid/v1";
const ANTHROPIC_UPSTREAM = "https://anthropic-vendor.invalid/v1";

/** The tenant's account + gateway, as an operator would write them. */
const ACCOUNT_ID = "acct-672";
const GATEWAY_ID = "fg-prod-gw";

const PROVIDER_KEY_VAR = "AIG_PROBE_PROVIDER_KEY";
const PROVIDER_KEY = "sk-aig-probe";
const AIG_TOKEN_VAR = "AIG_PROBE_GATEWAY_TOKEN";
const AIG_TOKEN = "cf-aig-probe-token";

const bindings = env as unknown as Record<string, unknown>;
const ORIGINAL: Record<string, unknown> = {};

/**
 * The whole configuration surface this issue adds, exercised at once:
 *
 *  - `routed-openai` — compat mode with an authenticated gateway (`aig_token_var`);
 *  - `routed-anthropic` — compat mode on the family whose chat surface is
 *    `/v1/messages`, so the surface map is load-bearing rather than a constant;
 *  - `unified-openai` — the OTHER mode, which addresses the account REST surface
 *    and rewrites `model` to `author/model`;
 *  - `direct-openai` — no block at all: the negative control.
 */
beforeAll(() => {
  for (const name of [
    "GATEWAY_PROVIDERS",
    "GATEWAY_MODELS",
    "GATEWAY_CLOUDFLARE",
    PROVIDER_KEY_VAR,
    AIG_TOKEN_VAR,
  ]) {
    ORIGINAL[name] = bindings[name];
  }
  bindings[PROVIDER_KEY_VAR] = PROVIDER_KEY;
  bindings[AIG_TOKEN_VAR] = AIG_TOKEN;
  bindings.GATEWAY_CLOUDFLARE = JSON.stringify({ account_id: ACCOUNT_ID });
  bindings.GATEWAY_PROVIDERS = JSON.stringify([
    {
      name: "routed-openai",
      kind: "openai",
      base_url: OPENAI_UPSTREAM,
      api_key_var: PROVIDER_KEY_VAR,
      cloudflare_ai_gateway: { gateway_id: GATEWAY_ID, aig_token_var: AIG_TOKEN_VAR },
    },
    {
      name: "routed-anthropic",
      kind: "anthropic",
      base_url: ANTHROPIC_UPSTREAM,
      api_key_var: PROVIDER_KEY_VAR,
      cloudflare_ai_gateway: { gateway_id: GATEWAY_ID },
    },
    {
      name: "unified-openai",
      kind: "openai",
      base_url: OPENAI_UPSTREAM,
      api_key_var: PROVIDER_KEY_VAR,
      cloudflare_ai_gateway: { gateway_id: GATEWAY_ID, mode: "unified" },
    },
    {
      name: "direct-openai",
      kind: "openai",
      base_url: OPENAI_UPSTREAM,
      api_key_var: PROVIDER_KEY_VAR,
    },
  ]);
  bindings.GATEWAY_MODELS = JSON.stringify([
    {
      name: "aig-chat",
      provider: "routed-openai",
      provider_model: "gpt-4o-mini",
      capabilities: ["chat", "streaming"],
    },
    {
      name: "aig-embed",
      provider: "routed-openai",
      provider_model: "text-embedding-3-small",
      capabilities: ["embeddings"],
    },
    {
      name: "aig-claude",
      provider: "routed-anthropic",
      provider_model: "claude-3-5-sonnet-latest",
      capabilities: ["chat"],
    },
    {
      name: "aig-unified",
      provider: "unified-openai",
      provider_model: "gpt-4o-mini",
      capabilities: ["chat"],
    },
    {
      name: "direct-chat",
      provider: "direct-openai",
      provider_model: "gpt-4o-mini",
      capabilities: ["chat"],
    },
  ]);
});

let provider: ProviderInterceptor | undefined;

afterEach(() => {
  provider?.restore();
  provider = undefined;
});

/** A buffered OpenAI completion — enough for the gateway to finish the request. */
function completion(model: string): Record<string, unknown> {
  return {
    id: "chatcmpl-aig",
    object: "chat.completion",
    model,
    choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
    usage: { prompt_tokens: 5, completion_tokens: 2, total_tokens: 7 },
  };
}

/** A buffered Anthropic message. */
function anthropicMessage(): Record<string, unknown> {
  return {
    id: "msg_aig",
    type: "message",
    role: "assistant",
    model: "claude-3-5-sonnet-latest",
    content: [{ type: "text", text: "ok" }],
    stop_reason: "end_turn",
    usage: { input_tokens: 5, output_tokens: 2 },
  };
}

/** Answer ANY outbound call, so a wrong endpoint shows up as a URL, not a throw. */
function acceptAnything(body: Record<string, unknown>): ProviderInterceptor {
  return interceptProviderFetch(() => providerJson(body));
}

async function chat(model: string, upstream: Record<string, unknown>): Promise<Response> {
  provider = acceptAnything(upstream);
  return await SELF.fetch(`${BASE}/v1/chat/completions`, {
    method: "POST",
    headers: { authorization: "Bearer fg_root", "content-type": "application/json" },
    body: JSON.stringify({ model, messages: [{ role: "user", content: "hi" }] }),
  });
}

describe("#672 — the DEPLOYED adapter path applies Cloudflare AI Gateway routing", () => {
  it("routes an openai-compatible completion through the gateway, preserving the vendor key", async () => {
    const response = await chat("aig-chat", completion("gpt-4o-mini"));
    expect(response.status).toBe(200);

    const sent = provider!.lastRequest();
    expect(sent.url).toBe(
      `https://gateway.ai.cloudflare.com/v1/${ACCOUNT_ID}/${GATEWAY_ID}/openai/chat/completions`,
    );
    // The gateway AUTHORIZATION and the VENDOR credential are different headers
    // and both must survive: `cf-aig-authorization` authenticates FerroGate to
    // the AI Gateway, `authorization` is what the gateway passes through to
    // OpenAI. Losing the second turns every routed request into a 401.
    expect(sent.headers["cf-aig-authorization"]).toBe(`Bearer ${AIG_TOKEN}`);
    expect(sent.headers.authorization).toBe(`Bearer ${PROVIDER_KEY}`);
  });

  it("routes an anthropic completion onto the messages passthrough suffix", async () => {
    const response = await chat("aig-claude", anthropicMessage());
    expect(response.status).toBe(200);

    const sent = provider!.lastRequest();
    expect(sent.url).toBe(
      `https://gateway.ai.cloudflare.com/v1/${ACCOUNT_ID}/${GATEWAY_ID}/anthropic/v1/messages`,
    );
    // Anthropic's own credential header, not OpenAI's — the routing rewrites the
    // URL and nothing else about the request the adapter built.
    expect(sent.headers["x-api-key"]).toBe(PROVIDER_KEY);
    // This provider declares no `aig_token_var`: an UNAUTHENTICATED gateway must
    // not grow an empty `cf-aig-authorization` header.
    expect(sent.headers["cf-aig-authorization"]).toBeUndefined();
  });

  it("routes embeddings through the gateway's embeddings surface", async () => {
    provider = acceptAnything({
      object: "list",
      model: "text-embedding-3-small",
      data: [{ object: "embedding", index: 0, embedding: [0.1, 0.2] }],
      usage: { prompt_tokens: 3, total_tokens: 3 },
    });
    const response = await SELF.fetch(`${BASE}/v1/embeddings`, {
      method: "POST",
      headers: { authorization: "Bearer fg_root", "content-type": "application/json" },
      body: JSON.stringify({ model: "aig-embed", input: "hello" }),
    });
    expect(response.status).toBe(200);
    expect(provider.lastRequest().url).toBe(
      `https://gateway.ai.cloudflare.com/v1/${ACCOUNT_ID}/${GATEWAY_ID}/openai/embeddings`,
    );
  });

  it("addresses the account REST surface in unified mode and namespaces the model", async () => {
    const response = await chat("aig-unified", completion("gpt-4o-mini"));
    expect(response.status).toBe(200);

    const sent = provider!.lastRequest();
    expect(sent.url).toBe(
      `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/ai/v1/chat/completions`,
    );
    expect(sent.headers["cf-aig-gateway-id"]).toBe(GATEWAY_ID);
    // Unified mode is addressed per ACCOUNT, so the provider moves into the
    // model name: `openai/gpt-4o-mini`, not the bare physical id.
    expect((sent.body as Record<string, unknown>).model).toBe("openai/gpt-4o-mini");
  });

  it("leaves a provider with no cloudflare_ai_gateway block dialling the vendor directly", async () => {
    const response = await chat("direct-chat", completion("gpt-4o-mini"));
    expect(response.status).toBe(200);

    const sent = provider!.lastRequest();
    expect(sent.url).toBe(`${OPENAI_UPSTREAM}/chat/completions`);
    expect(sent.headers["cf-aig-authorization"]).toBeUndefined();
    expect(sent.headers["cf-aig-gateway-id"]).toBeUndefined();
  });
});
