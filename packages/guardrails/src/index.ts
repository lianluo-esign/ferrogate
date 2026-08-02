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
 *
 * ## PORT_TODO(cutover-parity-libraries §4.4) — CLOSED 2026-08-01. Epitaph only;
 * ## no longer a marker. Kept because the *reason* the hole existed recurs.
 *
 * The finding was never that the code was wrong. All three per-finding
 * fingerprint sites HMAC under the configured `fingerprint_secret_ref` key —
 * `adapters/transport.ts::hmacEvidenceFingerprint` (used by `adapters/presidio.ts`,
 * `adapters/llm_guard.ts` and `adapters/workers_ai_llama_guard.ts`) and the
 * private `deterministic.ts::DeterministicDetector#hmacFingerprint`. What was
 * missing was the ASSERTION: every fingerprint assertion in this package's suite
 * and in `apps/gateway/test/guardrails/` was a SHAPE assertion
 * (`/^hmac-sha256:[0-9a-f]{64}$/`), and an *unkeyed* SHA-256 satisfies that shape
 * exactly as well as a keyed HMAC does. Measured, not suspected: two
 * semantically-real mutations (key → `new Uint8Array(0)`; key → a hard-coded
 * constant) each left **407/407** guardrails tests and **112/112**
 * `apps/gateway/test/guardrails/` tests GREEN.
 *
 * Why it mattered: an unkeyed digest of a short, low-entropy value (an API-key
 * fragment, a name, an account number, a prompt) is reversible by
 * dictionary/rainbow attack, which is exactly the property the keying exists to
 * remove.
 *
 * The gate is `test/fingerprint-keying.test.ts` (32 tests, test-only — no source
 * change was needed or made). It covers all four fingerprint sites and pins,
 * against an INDEPENDENT `node:crypto` oracle rather than this package's own
 * `hash.ts`: different keys ⇒ different fingerprints; the same key ⇒ the same
 * fingerprint; the fingerprint is neither the unkeyed SHA-256 nor the empty-key
 * HMAC of the input; a detector with no key emits `null`, never a bare digest;
 * and evidence is not persisted (`matched_text` null, raw value and key absent
 * from the serialized result). Proven RED by five mutations — key→empty (12
 * failed), key→constant (3), HMAC→plain SHA-256 at both sites (16),
 * `matched_text`→the matched secret (3), adapter findings→carrying the projected
 * text (2) — each restored byte-identical and re-verified GREEN at 439/439.
 *
 * Related and separately gated: `apps/gateway/src/guardrails/evidence.ts::envelopeFingerprint`
 * (the envelope-level, evidence-row fingerprint) fails closed to the literal
 * `hmac-sha256:unavailable` when no key is configured, pinned by
 * `apps/gateway/test/guardrails/evidence.test.ts:103`.
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
  CoalescedGroup,
  DeterministicDetectorConfig,
  JsonConstraints,
  RequestConstraints,
  SecretPattern,
} from "./deterministic.js";
export { coalesceSelectedSegments, regexByteMatches } from "./deterministic.js";

// Native PII detection + redaction (#680) — patterns + validators in-process,
// with an OPTIONAL Workers AI stage for the entities no grammar can reach.
export {
  InMemoryPiiTokenVault,
  PII_AI_DEFAULT_MODEL,
  PII_AI_ENTITIES,
  PII_ENTITIES,
  PiiDetector,
  cnResidentIdValid,
  ibanValid,
  luhnValid,
  piiDetectorConfig,
  piiEntityCategory,
  piiEntityLabel,
  usSsnValid,
  verbatimSpans,
} from "./pii.js";
export type {
  PiiAiEntity,
  PiiAiStageConfig,
  PiiDetectorConfig,
  PiiEntity,
  PiiHostCapabilities,
  PiiPolicyDefinition,
  PiiRedactionMode,
  PiiTokenVault,
} from "./pii.js";

// JSON schema/pointer helpers.
export {
  evaluateSchema,
  isValidSchema,
  jsonPointerExists,
  resolveJsonPointer,
} from "./jsonschema.js";

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

// Revision admission (the create-time compile gate the control plane runs).
export {
  INVALID_GUARDRAIL_POLICY_CODE,
  INVALID_REQUEST_BODY_CODE,
  admitPolicyRevision,
} from "./admission.js";
export type {
  PolicyRevisionAdmission,
  PolicyRevisionAdmissionError,
  PolicyRevisionAdmissionOptions,
} from "./admission.js";

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
  piiAiEntitySchema,
  piiAiStageSchema,
  piiEntitySchema,
  piiRedactionModeSchema,
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

// The DURABLE activated-revision binding (FLEET-CONSISTENCY FC-3).
//
// `apps/mcp` and `apps/agent-runtime` screen from the SAME
// `guardrail_policy_revisions` + `guardrail_policy_bindings` rows the gateway
// merges. It lives in this package because no app may import another app's
// module graph, so "every screening Worker reads the policy the same way" is
// only expressible as a library — see `./binding.ts`.
export {
  GUARDRAIL_BINDING_LIST_SQL,
  GUARDRAIL_BINDING_TABLE,
  GUARDRAIL_REVISION_LIST_ALL_SQL,
  GUARDRAIL_REVISION_TABLE,
  GUARDRAIL_BINDING_POINTER_SQL,
  GuardrailDetectorBuildError,
  activatedGuardrailPolicies,
  activatedPolicyFingerprint,
  buildGuardrailDetector,
  compileActivatedPolicies,
  forgetActivatedGuardrailPolicies,
  guardrailSecretsFromEnv,
  loadActivatedPolicyPointers,
  loadActivatedPolicyRevisions,
  screenGuardrailPolicies,
} from "./binding.js";
export type {
  ActivatedPolicyPointer,
  GuardrailPolicySql,
  CompiledGuardrailCheck,
  CompiledGuardrailPolicy,
  GuardrailDetectorBuildContext,
  GuardrailPolicyDatabase,
  GuardrailPolicyStatement,
  GuardrailScreeningDecision,
  GuardrailScreeningRequest,
  GuardrailSecretResolver,
} from "./binding.js";

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
