/**
 * Provider adapter registry — port of `registry.rs`.
 *
 * Holds one instance of each of the 8 adapters, resolves `kind` → adapter via
 * {@link canonicalProviderAdapterFamily}, wraps every trait method, and — after
 * preparation — applies Cloudflare AI Gateway routing (issue #406).
 *
 * ## PORT-TODO(P: inventory-request-path §3.2 "Registry", issue #406) — THE
 * ## CLOUDFLARE AI GATEWAY LEG OF THIS CLASS IS NOT MOUNTED. NOT A PLATFORM
 * ## LIMIT. NOT CLOSED.
 *
 * NARROWED — the class itself is no longer unimported. `ProviderAdapterRegistry`
 * is constructed at module scope in
 * `apps/gateway/src/inference/reliability.ts` (`RETRY_PREDICATE_REGISTRY`) and
 * its `isRetryableStatus` decides upstream retry on the deployed path, so the
 * "no importer outside this package" claim this marker used to make is stale.
 *
 * What is STILL dead is the routing leg. `apps/gateway` dispatches through its
 * OWN registry — `defaultAdapterRegistry` in
 * `apps/gateway/src/inference/adapters.ts` — built from the eight adapter
 * classes directly via `packageProviderAdapter(kind, new XAdapter())`. That
 * wrapper adapts one adapter at a time and never goes through this class, so
 * the `CloudflareRouting` capture/apply below is skipped on every request the
 * deployed data plane serves, and `applyCloudflareAiGatewayRouting` has zero
 * callers outside this package.
 *
 * Consequence: **Cloudflare AI Gateway routing is unreachable in production.**
 * `./cloudflare.ts` (`applyCloudflareAiGatewayRouting`, the per-family
 * chat/messages/responses/embeddings surface map, BYOK auth preservation) is
 * fully ported and tested, and cannot be reached — the free caching,
 * rate-limiting and observability the AI Gateway product provides are not in
 * effect for any tenant. This is the "implemented, tested, never mounted"
 * defect class — the same one `packages/routing`'s canary/shadow leg was in
 * until it was wired; that one is now closed, this one is not.
 *
 * It is also not CONFIGURABLE today, which is why fixing the wiring alone is
 * not enough: the Rust `Provider.cloudflare_ai_gateway` block
 * (`ferrogate-config/config/types.rs:1413`, validated at `validate.rs:291`
 * against a top-level `[cloudflare]` block for the account id and an optional
 * `aig_token_secret_ref`) has NO key in the gateway's `providerRecordSchema`,
 * which is `.strict()` — so a provider carrying the block would be REJECTED by
 * the config var, not ignored.
 *
 * To close, in order: (1) add `cloudflare_ai_gateway` + the account-level
 * settings to `apps/gateway/src/inference/catalog.ts` and carry them onto
 * `PhysicalRoute`; (2) have `apps/gateway/src/inference/adapters.ts` delegate to
 * this class instead of wrapping adapters one by one; (3) add a test that fails
 * when the routing is NOT applied — asserting the prepared endpoint is the AI
 * Gateway host, not merely that `applyCloudflareAiGatewayRouting` works when
 * called directly, which is what stays green through the current state.
 * See `docs/rewrite/parity-audit-request-path.md` F8.
 */
import type { ToolCall, ToolDef, ToolResult } from "@ferrogate/core";

import {
  AdapterError,
  canonicalProviderAdapterFamily,
} from "./types.js";
import type {
  ChatCompletionPlan,
  EmbeddingsPlan,
  ImagesPlan,
  ProviderAdapter,
  ProviderAdapterFamily,
  ProviderCatalogModel,
  ProviderCatalogRequest,
  ProviderConfig,
  ProviderErrorResponse,
  ProviderHttpRequest,
  ProviderUsage,
  ResponsesPlan,
} from "./types.js";
import {
  applyCloudflareAiGatewayRouting,
} from "./cloudflare.js";
import type { CloudflareAiGatewayRouting, CloudflareAiGatewaySurface } from "./cloudflare.js";
import type { Json } from "./json.js";
import { OpenAiCompatibleAdapter } from "./openai.js";
import { AnthropicAdapter } from "./anthropic.js";
import { GeminiAdapter } from "./gemini.js";
import { GrokAdapter } from "./grok.js";
import { OpenRouterAdapter } from "./openrouter.js";
import { AzureOpenAiAdapter } from "./azure.js";
import { BedrockAdapter } from "./bedrock.js";
import { VertexAiAdapter } from "./vertex.js";

/** Captures the per-provider Cloudflare routing + family before the config moves. */
class CloudflareRouting {
  private constructor(
    private readonly routing: CloudflareAiGatewayRouting | undefined,
    private readonly family: ProviderAdapterFamily | undefined,
  ) {}

  static capture(provider: ProviderConfig): CloudflareRouting {
    return new CloudflareRouting(
      provider.cloudflareAiGateway,
      canonicalProviderAdapterFamily(provider.kind),
    );
  }

  apply(
    request: ProviderHttpRequest,
    surface: (family: ProviderAdapterFamily) => CloudflareAiGatewaySurface,
  ): void {
    if (this.routing === undefined || this.family === undefined) return;
    applyCloudflareAiGatewayRouting(this.routing, this.family, surface(this.family), request);
  }
}

export class ProviderAdapterRegistry {
  readonly #openaiCompatible = new OpenAiCompatibleAdapter();
  readonly #anthropic = new AnthropicAdapter();
  readonly #gemini = new GeminiAdapter();
  readonly #grok = new GrokAdapter();
  readonly #openrouter = new OpenRouterAdapter();
  readonly #azureOpenai = new AzureOpenAiAdapter();
  readonly #bedrock = new BedrockAdapter();
  readonly #vertex = new VertexAiAdapter();

  adapterFor(kind: string): ProviderAdapter {
    switch (canonicalProviderAdapterFamily(kind)) {
      case "OpenAiCompatible":
        return this.#openaiCompatible;
      case "Anthropic":
        return this.#anthropic;
      case "Gemini":
        return this.#gemini;
      case "Grok":
        return this.#grok;
      case "OpenRouter":
        return this.#openrouter;
      case "AzureOpenAi":
        return this.#azureOpenai;
      case "Bedrock":
        return this.#bedrock;
      case "Vertex":
        return this.#vertex;
      default:
        throw AdapterError.unsupportedProviderKind(kind.trim().toLowerCase());
    }
  }

  prepareChatCompletions(
    provider: ProviderConfig,
    request: ChatCompletionPlan,
  ): ProviderHttpRequest {
    const cloudflare = CloudflareRouting.capture(provider);
    const adapter = this.adapterFor(provider.kind);
    const prepared = adapter.prepareChatCompletions(provider, request);
    cloudflare.apply(prepared, (family) =>
      family === "Anthropic" ? "Messages" : "ChatCompletions",
    );
    return prepared;
  }

  prepareResponses(provider: ProviderConfig, request: ResponsesPlan): ProviderHttpRequest {
    const cloudflare = CloudflareRouting.capture(provider);
    const adapter = this.adapterFor(provider.kind);
    const prepared = adapter.prepareResponses(provider, request);
    cloudflare.apply(prepared, (family) => (family === "Anthropic" ? "Messages" : "Responses"));
    return prepared;
  }

  prepareEmbeddings(provider: ProviderConfig, request: EmbeddingsPlan): ProviderHttpRequest {
    const cloudflare = CloudflareRouting.capture(provider);
    const adapter = this.adapterFor(provider.kind);
    const prepared = adapter.prepareEmbeddings(provider, request);
    cloudflare.apply(prepared, () => "Embeddings");
    return prepared;
  }

  translateEmbeddingsResponse(providerKind: string, body: Uint8Array, model: string): Json | null {
    return this.adapterFor(providerKind).translateEmbeddingsResponse(body, model);
  }

  prepareImages(provider: ProviderConfig, request: ImagesPlan): ProviderHttpRequest {
    return this.adapterFor(provider.kind).prepareImages(provider, request);
  }

  prepareModelCatalog(provider: ProviderConfig): ProviderCatalogRequest {
    return this.adapterFor(provider.kind).prepareModelCatalog(provider);
  }

  parseModelCatalog(providerKind: string, body: Uint8Array): ProviderCatalogModel[] {
    return this.adapterFor(providerKind).parseModelCatalog(body);
  }

  normalizeErrorResponse(
    providerKind: string,
    status: number,
    contentType: string,
    body: Uint8Array,
    requestId: string,
  ): ProviderErrorResponse {
    return this.adapterFor(providerKind).normalizeErrorResponse(
      status,
      contentType,
      body,
      requestId,
    );
  }

  extractUsage(providerKind: string, body: Uint8Array): ProviderUsage | undefined {
    return this.adapterFor(providerKind).extractUsage(body);
  }

  injectTools(providerKind: string, body: Json, tools: readonly ToolDef[]): Json {
    return this.adapterFor(providerKind).injectTools(body, tools);
  }

  extractToolCalls(providerKind: string, body: Uint8Array): ToolCall[] {
    return this.adapterFor(providerKind).extractToolCalls(body);
  }

  appendToolResults(providerKind: string, body: Json, results: readonly ToolResult[]): Json {
    return this.adapterFor(providerKind).appendToolResults(body, results);
  }

  isRetryableStatus(providerKind: string, status: number): boolean {
    return this.adapterFor(providerKind).isRetryableStatus(status);
  }
}
