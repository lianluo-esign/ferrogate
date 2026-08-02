import { describe, expect, test } from "vitest";

import {
  AdapterError,
  ProviderAdapterRegistry,
  SecretValue,
  applyCloudflareAiGatewayRouting,
  canonicalProviderAdapterFamily,
  isOpenAiCompatibleProviderKind,
  providerCompatibilityKind,
} from "../src/index.js";
import type { CloudflareAiGatewayRouting, ProviderConfig, ProviderHttpRequest } from "../src/index.js";

const provider = (kind: string, extra: Partial<ProviderConfig> = {}): ProviderConfig => ({
  name: "openai",
  kind,
  baseUrl: "https://api.openai.example/v1",
  apiKey: "provider-secret",
  ...extra,
});

describe("family resolution", () => {
  test("canonicalizes aliases case-insensitively and trims", () => {
    expect(canonicalProviderAdapterFamily(" OpenAI-Compatible ")).toBe("OpenAiCompatible");
    expect(canonicalProviderAdapterFamily("deepseek")).toBe("OpenAiCompatible");
    expect(canonicalProviderAdapterFamily("aws-bedrock")).toBe("Bedrock");
    expect(canonicalProviderAdapterFamily("vertex-ai")).toBe("Vertex");
    expect(canonicalProviderAdapterFamily("cohere")).toBeUndefined();
  });

  test("openai-compat + dedicated classification", () => {
    expect(isOpenAiCompatibleProviderKind("vllm")).toBe(true);
    expect(isOpenAiCompatibleProviderKind("anthropic")).toBe(false);
    expect(providerCompatibilityKind("openai")).toBe("openai-compatible");
    expect(providerCompatibilityKind("gemini")).toBe("dedicated");
  });
});

describe("ProviderAdapterRegistry", () => {
  const registry = new ProviderAdapterRegistry();

  test("resolves every family + aliases", () => {
    expect(registry.adapterFor("openai").kind()).toBe("openai-compatible");
    expect(registry.adapterFor("ollama-compatible").kind()).toBe("openai-compatible");
    expect(registry.adapterFor("openrouter").kind()).toBe("openrouter");
    expect(registry.adapterFor("aws-bedrock").kind()).toBe("bedrock");
    expect(registry.adapterFor("vertex-ai").kind()).toBe("vertex");
  });

  test("rejects an unknown kind lowercased before dispatch (edge case)", () => {
    try {
      registry.adapterFor("Cohere");
      throw new Error("expected throw");
    } catch (error) {
      expect(error).toBeInstanceOf(AdapterError);
      expect((error as AdapterError).kind).toBe("UnsupportedProviderKind");
      expect((error as AdapterError).providerKind).toBe("cohere");
    }
  });

  test("dispatches chat completions to the right surface per family", () => {
    const openai = registry.prepareChatCompletions(provider("openai"), {
      logicalModel: "fast",
      providerModel: "gpt-4o-mini",
      stream: true,
      body: { model: "fast", messages: [] },
    });
    expect(openai.endpoint).toBe("https://api.openai.example/v1/chat/completions");

    const anthropic = registry.prepareChatCompletions(provider("anthropic"), {
      logicalModel: "c",
      providerModel: "claude-3-5-sonnet-latest",
      stream: false,
      body: { model: "c", messages: [] },
    });
    expect(anthropic.endpoint).toBe("https://api.openai.example/v1/messages");
  });

  test("image generation fails closed for non-OpenAI families (issue #275)", () => {
    for (const kind of ["anthropic", "gemini", "bedrock", "vertex"]) {
      expect(() =>
        registry.prepareImages(provider(kind), {
          logicalModel: "art",
          providerModel: "m",
          body: { prompt: "a red fox" },
        }),
      ).toThrowError(/does not support image generation/);
    }
  });

  test("wraps error normalization + retryable classification", () => {
    const normalized = registry.normalizeErrorResponse(
      "openai",
      429,
      "application/json",
      new TextEncoder().encode('{"error":{"message":"rate limited","type":"rate_limit_error"}}'),
      "fg-test",
    );
    expect((normalized.body as any).error.provider_type).toBe("rate_limit_error");
    expect(registry.isRetryableStatus("openai", 429)).toBe(true);
    expect(registry.isRetryableStatus("gemini", 503)).toBe(true);
    expect(registry.isRetryableStatus("anthropic", 400)).toBe(false);
  });
});

/**
 * Issue #672 REWROTE the first two cases in this block, and the rewrite is the
 * point rather than a tidy-up.
 *
 * They used to read `registry.prepareChatCompletions(provider("openai", {
 * cloudflareAiGateway: routing(...) }), ...)` and assert the gateway endpoint —
 * green the entire time AI Gateway routing was unreachable in production,
 * because `ProviderAdapterRegistry` is not what `apps/gateway` dispatches
 * through. `ProviderConfig.cloudflareAiGateway` and the registry's routing leg
 * are both deleted now (see the docblock on `src/registry.ts`), so these cases
 * exercise `applyCloudflareAiGatewayRouting` directly, which is what this
 * package actually owns. The claim they used to make — "a prepared request comes
 * out addressed at the AI Gateway" — is now made where it can be false:
 * `apps/gateway/test/inference/cloudflare-ai-gateway-mount.test.ts`, through
 * `SELF.fetch` into the deployed Worker.
 */
describe("Cloudflare AI Gateway routing (issue #406, mounted by #672)", () => {
  const routing = (overrides: Partial<CloudflareAiGatewayRouting> = {}): CloudflareAiGatewayRouting => ({
    accountId: "acct",
    gatewayId: "gw",
    gatewayBaseUrl: "https://gateway.ai.cloudflare.com",
    apiBaseUrl: "https://api.cloudflare.com/client/v4",
    mode: "Compat",
    ...overrides,
  });
  const registry = new ProviderAdapterRegistry();

  /** What an OpenAI-compatible adapter hands over, ready to be re-addressed. */
  const preparedOpenAi = (): ProviderHttpRequest =>
    registry.prepareChatCompletions(provider("openai"), {
      logicalModel: "fast",
      providerModel: "gpt-4o-mini",
      stream: false,
      body: { model: "fast" },
    });

  test("compat mode rewrites onto the passthrough URL, preserving BYOK auth", () => {
    const prepared = preparedOpenAi();
    applyCloudflareAiGatewayRouting(
      routing({ aigToken: new SecretValue("cf-token") }),
      "OpenAiCompatible",
      "ChatCompletions",
      prepared,
    );
    expect(prepared.endpoint).toBe(
      "https://gateway.ai.cloudflare.com/v1/acct/gw/openai/chat/completions",
    );
    expect(prepared.headers.some((h) => h.name === "cf-aig-authorization")).toBe(true);
    // BYOK Authorization header is preserved.
    expect(prepared.headers.some((h) => h.value.exposeSecret() === "Bearer provider-secret")).toBe(true);
  });

  test("anthropic chat routes through the messages passthrough suffix", () => {
    const prepared = registry.prepareChatCompletions(provider("anthropic"), {
      logicalModel: "c",
      providerModel: "claude",
      stream: false,
      body: { messages: [] },
    });
    applyCloudflareAiGatewayRouting(routing(), "Anthropic", "Messages", prepared);
    expect(prepared.endpoint).toBe("https://gateway.ai.cloudflare.com/v1/acct/gw/anthropic/v1/messages");
  });

  test("the registry itself no longer routes — that leg is the gateway's now", () => {
    // The anti-regression for the deletion. If a future edit re-adds a routing
    // leg to `ProviderAdapterRegistry`, this class would once again be a second
    // place that claims to apply AI Gateway routing while production applies it
    // somewhere else. A prepared request must come out addressed at the VENDOR.
    expect(preparedOpenAi().endpoint).toBe("https://api.openai.example/v1/chat/completions");
  });

  test("unified mode rewrites model to author/model and adds gateway-id header", () => {
    const request: ProviderHttpRequest = {
      provider: "openai",
      endpoint: "https://api.openai.example/v1/chat/completions",
      body: { model: "gpt-4o-mini" },
      stream: false,
      headers: [],
    };
    applyCloudflareAiGatewayRouting(routing({ mode: "Unified" }), "OpenAiCompatible", "ChatCompletions", request);
    expect(request.endpoint).toBe("https://api.cloudflare.com/client/v4/accounts/acct/ai/v1/chat/completions");
    expect((request.body as any).model).toBe("openai/gpt-4o-mini");
    expect(request.headers.some((h) => h.name === "cf-aig-gateway-id")).toBe(true);
  });

  test("a family without a default slug and no override fails closed (edge case)", () => {
    const request: ProviderHttpRequest = {
      provider: "g",
      endpoint: "x",
      body: {},
      stream: false,
      headers: [],
    };
    expect(() =>
      applyCloudflareAiGatewayRouting(routing(), "Gemini", "ChatCompletions", request),
    ).toThrowError(/requires an explicit provider_slug/);
  });
});
