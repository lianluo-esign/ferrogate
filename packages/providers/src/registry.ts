/**
 * Provider adapter registry — port of `registry.rs`.
 *
 * Holds one instance of each of the 9 adapters, resolves `kind` → adapter via
 * {@link canonicalProviderAdapterFamily}, and wraps every trait method.
 *
 * ## Its Cloudflare AI Gateway leg is GONE, not moved — and why it had to be
 *
 * This class used to apply `applyCloudflareAiGatewayRouting` after every
 * `prepare_*`, reading `ProviderConfig.cloudflare_ai_gateway`, exactly as
 * `registry.rs` does. On Workers that was dead code, and its own PORT-TODO said
 * so: `apps/gateway` dispatches through `defaultAdapterRegistry` in
 * `apps/gateway/src/inference/adapters.ts`, built from the adapters directly via
 * `packageProviderAdapter(kind, new XAdapter())`, and never constructs this
 * class for dispatch. So the routing was skipped on every request the deployed
 * data plane served, while `packages/providers/test/registry-cloudflare.test.ts`
 * stayed green driving it through here — a test that could not see the defect
 * by construction.
 *
 * Issue #672 mounted the routing on the path dispatch really takes
 * (`adapters.ts::withCloudflareAiGatewayRouting`, which every entry in
 * `defaultAdapterRegistry` is built through, configured by
 * `[[providers]].cloudflare_ai_gateway` + `GATEWAY_CLOUDFLARE`). The capture/
 * apply below was then DELETED rather than left in place, because leaving a
 * second adapter-construction path that also claims to route is precisely how
 * this defect survived from #406 to #672: two mechanisms, one of them reached,
 * and no way to tell from a green suite which. `applyCloudflareAiGatewayRouting`
 * (`./cloudflare.ts`) is unchanged and now has exactly one caller, in the
 * gateway.
 *
 * ## What this class still is
 *
 * A live, reached object — but a NARROWER one than `registry.rs`. It is
 * constructed at module scope in `apps/gateway/src/inference/reliability.ts`
 * (`RETRY_PREDICATE_REGISTRY`), whose `isRetryableStatus` decides upstream retry
 * on the deployed path, and its `adapterFor` is the family→adapter table the
 * package's own consumers resolve against. The `prepare*` wrappers are the
 * package's public API and are exercised by
 * `packages/providers/test/registry-cloudflare.test.ts`; they are NOT what
 * `apps/gateway` dispatches through, which is stated here so nobody adds a
 * cross-cutting request concern to this class again and believes it shipped.
 */
import type { ToolCall, ToolDef, ToolResult } from "@ferrogate/core";

import { AnthropicAdapter } from "./anthropic.js";
import { AzureOpenAiAdapter } from "./azure.js";
import { BedrockAdapter } from "./bedrock.js";
import { GeminiAdapter } from "./gemini.js";
import { GrokAdapter } from "./grok.js";
import type { Json } from "./json.js";
import { OpenAiCompatibleAdapter } from "./openai.js";
import { OpenRouterAdapter } from "./openrouter.js";
import { AdapterError, canonicalProviderAdapterFamily } from "./types.js";
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
import { VertexAiAdapter } from "./vertex.js";
import { WorkersAiAdapter } from "./workers_ai.js";

export class ProviderAdapterRegistry {
  readonly #openaiCompatible = new OpenAiCompatibleAdapter();
  readonly #anthropic = new AnthropicAdapter();
  readonly #gemini = new GeminiAdapter();
  readonly #grok = new GrokAdapter();
  readonly #openrouter = new OpenRouterAdapter();
  readonly #azureOpenai = new AzureOpenAiAdapter();
  readonly #bedrock = new BedrockAdapter();
  readonly #vertex = new VertexAiAdapter();
  /**
   * The ninth family (issue #673). Registering it HERE is not what makes it
   * reachable — see the header note: the deployed data plane builds adapters
   * through `packageProviderAdapter()` in
   * `apps/gateway/src/inference/adapters.ts` and never constructs this class for
   * dispatch. That file is where the Workers AI family is actually mounted; this
   * entry keeps the two registries from disagreeing about what exists.
   */
  readonly #workersAi = new WorkersAiAdapter();

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
      case "WorkersAi":
        return this.#workersAi;
      default:
        throw AdapterError.unsupportedProviderKind(kind.trim().toLowerCase());
    }
  }

  prepareChatCompletions(
    provider: ProviderConfig,
    request: ChatCompletionPlan,
  ): ProviderHttpRequest {
    return this.adapterFor(provider.kind).prepareChatCompletions(provider, request);
  }

  prepareResponses(provider: ProviderConfig, request: ResponsesPlan): ProviderHttpRequest {
    return this.adapterFor(provider.kind).prepareResponses(provider, request);
  }

  prepareEmbeddings(provider: ProviderConfig, request: EmbeddingsPlan): ProviderHttpRequest {
    return this.adapterFor(provider.kind).prepareEmbeddings(provider, request);
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
