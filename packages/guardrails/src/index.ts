/**
 * `@ferrogate/guardrails` — typed, bounded guardrail detector contracts and
 * runtimes. Clean-room TypeScript port of the Rust crate `ferrogate-guardrails`.
 *
 * This crate owns detector EXECUTION and its safety boundary (deadlines,
 * bulkheads, circuit state, SSRF-safe endpoint validation, typed results,
 * constrained text patches) plus the immutable policy-composition domain. Policy
 * ENFORCEMENT and gateway wiring live elsewhere.
 *
 * Module map (mirrors the Rust module tree):
 *  - `bytes` / `hash`     — UTF-8 byte offsets + sync sha256/hmac (evidence).
 *  - `contract`           — detector types, verdict/finding/patch, error taxonomy.
 *  - `envelope`           — protocol normalization + patch validate/apply.
 *  - `deterministic`      — the in-repo keyword/regex/secret/JSON detector.
 *  - `net`                — SSRF private/reserved IP denylist.
 *  - `custom_http`        — bounded external HTTP detector (semaphore + circuit).
 *  - `adapters/*`         — Presidio, LLM-Guard, Workers-AI Llama-Guard, fixture.
 *  - `policy`             — revisions, scope selection, aggregation, selection.
 *  - `conformance` / `evaluation` — the offline harnesses (test/tooling).
 *
 * Security invariants preserved verbatim (see per-module docs): `matched_text`
 * is never persisted; evidence fingerprints are keyed `hmac-sha256:<hex>`;
 * fail-closed on truncation/disable/error; patch application is narrowly scoped
 * to mutable text paths.
 */

// Byte + hash primitives.
export {
  byteLen,
  byteMatchIndices,
  byteOffsetMap,
  byteSlice,
  decodeUtf8,
  encodeUtf8,
  isCharBoundary,
  isCharBoundaryBytes,
} from "./bytes.js";
export { hmacSha256, sha256, toHex } from "./hash.js";

// Contract.
export {
  CONTRACT_VERSION,
  MAX_DETECTOR_TIMEOUT_MS,
  DEFAULT_FINDING_SEVERITY,
  DetectorError,
  DetectorSecret,
  contentPatchSchema,
  dataResidencySchema,
  detectorCredentialTypeSchema,
  detectorErrorKindSchema,
  detectorResultSchema,
  detectorStageSchema,
  detectorVerdictSchema,
  findingSchema,
  findingSeveritySchema,
  firstMatchedText,
} from "./contract.js";
export type {
  ContentSegment,
  ContentSource,
  DataResidency,
  DetectorCredentialType,
  DetectorDescriptor,
  DetectorErrorKind,
  DetectorHealth,
  DetectorInput,
  DetectorResult,
  DetectorStage,
  DetectorTenant,
  DetectorVerdict,
  Finding,
  FindingSeverity,
  GuardrailDetector,
  GuardrailProtocol,
  ContentPatch,
} from "./contract.js";

// Envelope.
export {
  ALL_CONTENT_SOURCES,
  allContentSources,
  applyContentPatchesToDocument,
  contentFingerprint,
  contentSegmentSchema,
  contentSourceSchema,
  envelopeFromText,
  envelopeManagedAction,
  flattenedText,
  guardrailEnvelopeSchema,
  guardrailProtocolSchema,
  normalizeRequest,
  normalizeResponse,
  parseProtocolPath,
  segmentContentTypeSchema,
  totalTextBytes,
  validateContentPatchPermissions,
  validateContentPatchesForSegments,
} from "./envelope.js";
export type { GuardrailEnvelope, SegmentContentType } from "./envelope.js";

// Deterministic detector.
export {
  DeterministicDetector,
  MAX_FINDINGS_PER_EVALUATION,
  isMutableTextSegment,
  jsonConstraintsIsEmpty,
  jsonConstraintsSchema,
  requestConstraintsIsEmpty,
  requestConstraintsSchema,
  secretPatternSchema,
} from "./deterministic.js";
export type {
  DeterministicDetectorConfig,
  JsonConstraints,
  RequestConstraints,
  SecretPattern,
} from "./deterministic.js";

// JSON schema/pointer helpers.
export { evaluateSchema, isValidSchema, jsonPointerExists, resolveJsonPointer } from "./jsonschema.js";

// Net (SSRF).
export {
  ALLOWED_DETECTOR_ENDPOINT_SCHEMES,
  detectorEndpointRejection,
  filterResolvedDetectorAddresses,
  isDisallowedDetectorHost,
  isDisallowedDetectorIp,
  parseLooseIpv4,
} from "./net.js";
export type { DetectorAddress, DetectorEndpointRejection } from "./net.js";

// Async primitives.
export { Semaphore, TIMED_OUT, sleep, withTimeout } from "./async.js";

// Custom HTTP detector.
export {
  CustomHttpDetector,
  classifyFetchError,
  parseDetectorResponse,
  statusError,
  validateCustomHttpEndpoint,
  validateDetectorResult,
} from "./custom_http.js";
export type { CustomHttpDetectorConfig } from "./custom_http.js";

// Adapters.
export {
  AdapterCounters,
  HttpJsonTransport,
  adapterStatusError,
  charIndexToByteOffset,
  configDigest,
  hmacEvidenceFingerprint,
  nativeAdapterFailureModes,
} from "./adapters/transport.js";
export type { DetectorTransport, TransportReply } from "./adapters/transport.js";
export { PresidioDetector } from "./adapters/presidio.js";
export type { PresidioDetectorConfig } from "./adapters/presidio.js";
export { LlmGuardPromptInjectionDetector } from "./adapters/llm_guard.js";
export type { LlmGuardPromptInjectionConfig } from "./adapters/llm_guard.js";
export {
  CloudflareError,
  DEFAULT_MODEL as WORKERS_AI_LLAMA_GUARD_DEFAULT_MODEL,
  WorkersAiLlamaGuardDetector,
  classifyCloudflareError,
  cloudflareRestWorkersAiClient,
  hazardName,
  interpretResponse,
  normalizeHazardCode,
  workersAiBindingClient,
} from "./adapters/workers_ai_llama_guard.js";
export type {
  CloudflareClient,
  CloudflareErrorKind,
  LlamaGuardVerdict,
  WorkersAiBinding,
  WorkersAiClient,
  WorkersAiLlamaGuardConfig,
} from "./adapters/workers_ai_llama_guard.js";
export { FixtureTransport } from "./adapters/fixture.js";

// Policy composition.
export {
  aggregateCheckOutcomes,
  actionKindSchema,
  administrativeRank,
  checkBindingSchema,
  detectorDefinitionSchema,
  immutableId,
  localDetectorDefinition,
  managedActionClassAsStr,
  managedActionClassSchema,
  managedActionSelectorSchema,
  policyActionSchema,
  policyActions,
  policyAggregationSchema,
  policyExecutionSchema,
  policyModeSchema,
  policyRevisionSchema,
  policyRevisionStatusSchema,
  policyScopeSelectorSchema,
  policyStreamingModeSchema,
  scopeMatches,
  selectPolicyRevisions,
  selectedCheckIds,
  validateDetectorDefinition,
  validatePolicyRevision,
} from "./policy.js";
export type {
  ActionKind,
  AggregateOutcome,
  CheckBinding,
  CheckOutcome,
  DetectorDefinition,
  ManagedActionClass,
  ManagedActionContext,
  ManagedActionSelector,
  PolicyAction,
  PolicyAggregation,
  PolicyExecution,
  PolicyMode,
  PolicyRevision,
  PolicyRevisionStatus,
  PolicyRevisionView,
  PolicyScopeSelector,
  PolicySelectionContext,
  PolicyStreamingMode,
} from "./policy.js";

// Conformance + evaluation harnesses.
export {
  MockAdapter,
  PROBE_SECRET,
  allBehavioursExercised,
  assertDetectorConforms,
  conformanceProbeResult,
  conforms,
  mockResponses,
  runDetectorConformance,
} from "./conformance.js";
export type { ConformanceReport, MockResponse } from "./conformance.js";
export {
  PromotionGate,
  conservativeThresholds,
  maliciousCount,
  newEvaluationCorpus,
  recordShadowObservations,
  referenceCorpus,
  runDetectorEvaluation,
  scoreShadowObservations,
  shadowOutcomeFromResult,
} from "./evaluation.js";
export type {
  EvaluationCase,
  EvaluationCorpus,
  EvaluationMetrics,
  PromotionDecision,
  PromotionThresholds,
  RollbackDecision,
  ShadowObservation,
  ShadowOutcome,
} from "./evaluation.js";
