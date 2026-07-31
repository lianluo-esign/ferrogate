/**
 * `apps/gateway` inference surface — the six OpenAPI operations in the
 * `inference` route group of `docs/openapi/runtime-api-contract.json`:
 *
 *   listModels · createChatCompletion · createResponse · createMessage ·
 *   createEmbedding · createImage
 *
 * Mount it from the app shell:
 *
 * ```ts
 * import { createInferenceRouter } from "./inference/index.js";
 * app.route("/", createInferenceRouter({ models, adapters, usage }));
 * ```
 *
 * With no arguments every port falls back to the in-memory default in
 * `defaults.ts`, which is enough to boot and to test but resolves no models
 * (every request answers `model_not_found`).
 */
export { createInferenceRouter } from "./handlers.js";
export type { InferenceEnv } from "./handlers.js";

export * from "./ports.js";
export * from "./schemas.js";
export * from "./errors.js";
export * from "./usage.js";
export {
  DEFAULT_INFERENCE_LIMITS,
  InMemoryModelResolver,
  InMemoryUsageSink,
  defaultCallerResolver,
  defaultRequestIds,
  defaultStreamNormalizers,
  emptyModelResolver,
  fetchDispatcher,
  passthroughNormalizers,
  platformOperatorCaller,
  resolveDeps,
} from "./defaults.js";
export {
  PROVIDER_ADAPTER_FAMILIES,
  anthropicAdapter,
  canonicalProviderKind,
  defaultAdapterRegistry,
  isOpenAiCompatibleKind,
  openAiCompatibleAdapter,
} from "./adapters.js";
export {
  chatCompletionToMessage,
  defaultAnthropicTranslator,
  finishReasonToStopReason,
  isAnthropicMessage,
  parseArguments,
  toChatCompletions,
} from "./anthropic.js";
