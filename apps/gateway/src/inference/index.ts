/**
 * `apps/gateway` inference surface — the nine OpenAPI operations in the
 * `inference` route group of `docs/openapi/runtime-api-contract.json`:
 *
 *   listModels · getModel · createChatCompletion · createResponse ·
 *   createMessage · countMessageTokens · createEmbedding · createRerank ·
 *   createImage
 *
 * Mount it from the app shell as a contract-driven `RouteModule`:
 *
 * ```ts
 * import { inferenceRouteModule } from "./inference/index.js";
 * const { app } = createGatewayApp({ modules: [inferenceRouteModule({ models })] });
 * ```
 *
 * `createInferenceRouter` remains exported as the standalone `Hono` the module
 * delegates into (and that the unit suites drive directly).
 *
 * With no arguments every port falls back to the in-memory default in
 * `defaults.ts`, which is enough to boot and to test but resolves no models
 * (every request answers `model_not_found`).
 */
export { createInferenceRouter } from "./handlers.js";
export type { InferenceEnv } from "./handlers.js";
export { inferenceRouteModule } from "./route-module.js";

export * from "./ports.js";
export * from "./estimate.js";
export {
  callerFromAuth,
  inferenceRequestScope,
  setInferenceRequestScope,
  unmeteredTokenGovernor,
} from "./identity.js";
export type {
  InferenceRequestScope,
  TokenAdmissionHandle,
  TokenGovernor,
} from "./identity.js";
export * from "./catalog.js";
export * from "./candidates.js";
export {
  runShadowMirror,
  shadowBudgetFor,
  shadowMirrorFor,
  spawnShadowMirror,
} from "./shadow.js";
export type { ShadowMirror } from "./shadow.js";
export * from "./reliability.js";
export * from "./strategy.js";
export {
  DurableObjectProviderCircuit,
  ProviderCircuitDurableObject,
} from "./circuit-do.js";
export type { ProviderCircuitNamespace } from "./circuit-do.js";
export * from "./schemas.js";
export * from "./workflow.js";
export * from "./errors.js";
export * from "./usage.js";
export {
  WORKERS_AI_BINDING,
  workersAiDispatcher,
  workersAiDispatcherFromEnv,
  workersAiModelOf,
  workersAiSseToOpenAi,
} from "./workers-ai.js";
export type { WorkersAiBinding } from "./workers-ai.js";
export {
  DEFAULT_INFERENCE_LIMITS,
  InMemoryModelResolver,
  InMemoryUsageSink,
  defaultCallerResolver,
  defaultRequestIds,
  defaultStreamNormalizers,
  emptyModelResolver,
  dispatcherFromEnv,
  fetchDispatcher,
  isolateRoutingMetrics,
  passthroughNormalizers,
  platformOperatorCaller,
  providerCircuitFor,
  resolveCandidates,
  resolveDeps,
} from "./defaults.js";
export {
  AZURE_DEFAULT_API_VERSION,
  PROVIDER_ADAPTER_FAMILIES,
  anthropicAdapter,
  azureOpenAiAdapter,
  bedrockAdapter,
  canonicalProviderKind,
  defaultAdapterRegistry,
  defaultAuthScheme,
  encodeAzurePathSegment,
  geminiAdapter,
  grokAdapter,
  isOpenAiCompatibleKind,
  openAiCompatibleAdapter,
  openRouterAdapter,
  splitAzureBaseUrl,
  vertexAdapter,
} from "./adapters.js";
export type {
  GatewayProviderFamily,
  OpenRouterProviderExtras,
  OpenRouterRoute,
} from "./adapters.js";
export {
  ProviderBodyTooLargeError,
  ProviderEndpointError,
  dispatchDeadline,
  parseProviderEndpoint,
  providerTransportFailureClass,
  providerTransportMessage,
  readBoundedProviderBody,
} from "./dispatch.js";
export {
  chatCompletionToMessage,
  defaultAnthropicTranslator,
  finishReasonToStopReason,
  isAnthropicMessage,
  parseArguments,
  toChatCompletions,
} from "./anthropic.js";
