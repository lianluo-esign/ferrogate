/**
 * Provider adapter registry — port of `registry.rs`.
 *
 * Holds one instance of each of the 8 adapters, resolves `kind` → adapter via
 * {@link canonicalProviderAdapterFamily}, wraps every trait method, and — after
 * preparation — applies Cloudflare AI Gateway routing (issue #406).
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
