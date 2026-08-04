/**
 * `apps/gateway` inference surface — the fourteen OpenAPI operations in the
 * `inference` route group of `docs/openapi/runtime-api-contract.json`:
 *
 *   listModels · getModel · createChatCompletion · createResponse ·
 *   createMessage · countMessageTokens · createEmbedding · createRerank ·
 *   createTranscription · createTranslation · createSpeech · createImage
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
export * from "./tenant-catalog.js";
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
export {
  audioObjectsFromEnv,
  NO_AUDIO_OBJECTS,
  parseAudioObjectReference,
  storedAssetAudioObjects,
} from "./audio-objects.js";
export type { AudioObjectReference, AudioObjectSource } from "./audio-objects.js";
export * from "./conversation.js";
export {
  D1ConversationStore,
  InMemoryConversationStore,
  NO_CONVERSATION_STORE,
  assembleChain,
  conversationStoreFromEnv,
  isDurableConversationStore,
  sweepResponseConversations,
  turnItems,
} from "./conversation-store.js";
export type {
  ChainFailure,
  ChainResolution,
  ConversationStore,
  StoredResponseTurn,
} from "./conversation-store.js";
export { assistantMessageItem, responsesOutputTap } from "./conversation-capture.js";
export type { CapturedResponseOutput } from "./conversation-capture.js";
// #689 — the middleware that writes the turn ABOVE the guardrail response
// stage. `src/index.ts` mounts it; see `conversation-commit.ts` for why the
// write cannot live in the inference router.
export { pendingTurnFor, publishPendingTurn, responseStateCommit } from "./conversation-commit.js";
export type { PendingConversationTurn } from "./conversation-commit.js";
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
  readBoundedProviderBytes,
  readBoundedStream,
} from "./dispatch.js";
export {
  chatCompletionToMessage,
  defaultAnthropicTranslator,
  finishReasonToStopReason,
  isAnthropicMessage,
  parseArguments,
  toChatCompletions,
} from "./anthropic.js";
