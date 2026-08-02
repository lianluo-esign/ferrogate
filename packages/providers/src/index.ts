/**
 * `@ferrogate/providers` — the AI-provider adapter boundary.
 *
 * Clean-room TypeScript port of the Rust crate `ferrogate-providers`: it
 * translates FerroGate's canonical chat/responses/embeddings/images/catalog
 * "plans" into each provider's upstream wire request and normalizes
 * responses/errors/usage back. Pure and synchronous — dispatch (the `fetch()`)
 * is the gateway's job. Upstream calls may additionally be routed through
 * Cloudflare AI Gateway (issue #406).
 *
 * Modules:
 *  - `types`              — `ProviderAdapter`, config/plan/request shapes, the
 *                           `AdapterError` taxonomy, `SecretValue`, family table.
 *  - `cloudflare`         — Cloudflare AI Gateway request-rewrite (issue #406).
 *  - `canonical`          — `/v1/responses` → per-family request canonicalization.
 *  - `structured`         — `response_format`/`text.format` → per-family output
 *                           contract, or an explicit refusal (issue #674).
 *  - `models`             — logical→physical `ModelRegistry`.
 *  - `registry`           — `ProviderAdapterRegistry` (9 adapters + CF routing).
 *  - `sigv4`              — AWS SigV4 signing (Bedrock; byte-exact).
 *  - `openai`/`anthropic`/`azure`/`bedrock`/`gemini`/`grok`/`openrouter`/`vertex`
 *                         — the 8 ported provider adapters.
 *  - `workers_ai`         — the 9th family, Cloudflare Workers AI (issue #673).
 *                           No Rust ancestor: a Rust process has no `env.AI`.
 *  - `anthropic_messages` — Anthropic Messages ⇄ OpenAI chat translation (#272).
 *  - `schemas`            — Zod wire schemas for the data shapes (§3.3).
 */

// Core types + trait + family table.
export {
  AdapterError,
  BaseProviderAdapter,
  SecretValue,
  SUPPORTED_PROVIDER_ADAPTER_FAMILIES,
  canonicalProviderAdapterFamily,
  isOpenAiCompatibleProviderKind,
  providerCompatibilityKind,
} from "./types.js";
export type {
  AdapterErrorKind,
  AwsProviderCredentials,
  ChatCompletionPlan,
  EmbeddingsPlan,
  GcpProviderCredentials,
  ImagesPlan,
  ProviderAdapter,
  ProviderAdapterFamily,
  ProviderAdapterFamilyDescriptor,
  ProviderCatalogModel,
  ProviderCatalogRequest,
  ProviderConfig,
  ProviderErrorResponse,
  ProviderHeader,
  ProviderHttpRequest,
  ProviderUsage,
  ResponsesPlan,
} from "./types.js";

// JSON value model + accessors.
export type { Json, JsonObject } from "./json.js";

// Cloudflare AI Gateway routing.
export {
  applyCloudflareAiGatewayRouting,
  DEFAULT_CLOUDFLARE_AI_GATEWAY_MODE,
} from "./cloudflare.js";
export type {
  CloudflareAiGatewayMode,
  CloudflareAiGatewayRouting,
  CloudflareAiGatewaySurface,
} from "./cloudflare.js";

// Canonical request model.
export { CanonicalAiRequest } from "./canonical.js";

// Canonical structured output (`response_format` / `text.format`) — issue #674.
export {
  applyStructuredOutputToAnthropic,
  applyStructuredOutputToBedrockConverse,
  applyStructuredOutputToGemini,
  coercionToolName,
  geminiResponseSchema,
  structuredOutputFromChatBody,
  structuredOutputFromResponsesBody,
} from "./structured.js";
export type { CanonicalStructuredOutput } from "./structured.js";

// Canonical prompt-caching directive (`prompt_cache`) — issue #690.
export {
  PROMPT_CACHE_MEMBER,
  applyPromptCacheToAnthropic,
  applyPromptCacheToAutomaticFamily,
  applyPromptCacheToBedrockConverse,
  assertPromptCacheForAutomaticFamily,
  promptCacheFromBody,
  stripPromptCacheDirective,
} from "./caching.js";
export type { CanonicalPromptCache, PromptCacheTtl } from "./caching.js";

// Model registry.
export {
  DEFAULT_ROUTING_STRATEGY,
  ModelRegistry,
  ModelRegistryError,
  modelCapabilityAsStr,
  modelCapabilityFromStr,
  modelRouteWithRouting,
  newModelRegistryEntry,
  newModelRoute,
  routingStrategyAsStr,
  routingStrategyFromStr,
} from "./models.js";
export type {
  ModelCapability,
  ModelRegistryEntry,
  ModelRegistryErrorKind,
  ModelRoute,
  ResolvedModelRoute,
  RoutingStrategy,
} from "./models.js";

// Adapters + registry.
export { OpenAiCompatibleAdapter } from "./openai.js";
export { AnthropicAdapter } from "./anthropic.js";
export { AzureOpenAiAdapter } from "./azure.js";
export { BedrockAdapter } from "./bedrock.js";
export { GeminiAdapter } from "./gemini.js";
export { GrokAdapter } from "./grok.js";
export { OpenRouterAdapter } from "./openrouter.js";
export { VertexAiAdapter } from "./vertex.js";
export { WorkersAiAdapter, WORKERS_AI_KIND, WORKERS_AI_RUN_PATH_SEGMENT } from "./workers_ai.js";
export { ProviderAdapterRegistry } from "./registry.js";

// Anthropic Messages ⇄ OpenAI translation.
export {
  chatCompletionToMessage,
  finishReasonToStopReason,
  isAnthropicMessage,
  parseArguments,
  toChatCompletions,
} from "./anthropic_messages.js";

// SigV4 signing.
export {
  canonicalQueryString,
  formatTimestamps,
  presignQuery,
  presignQueryBound,
  sign,
  signStreamedWithContentHashHeader,
  signWithContentHashHeader,
  signWithContentHashHeaderAndQuery,
} from "./sigv4.js";
export type {
  AwsCredentials,
  BoundPresignedUpload,
  PresignBoundPayload,
  PresignRequest,
  SignedHeaders,
  SigningRequest,
  StreamedSigningRequest,
} from "./sigv4.js";

// Zod wire schemas.
export {
  chatCompletionPlanSchema,
  embeddingsPlanSchema,
  imagesPlanSchema,
  modelCapabilitySchema,
  modelSchema,
  providerAdapterFamilySchema,
  providerCatalogModelSchema,
  providerConfigWireSchema,
  providerErrorResponseSchema,
  providerHttpRequestWireSchema,
  providerUsageSchema,
  responsesPlanSchema,
  routingStrategySchema,
} from "./schemas.js";
export type {
  Model,
  ProviderCatalogModelWire,
  ProviderConfigWire,
  ProviderUsageWire,
} from "./schemas.js";
