/**
 * Immutable guardrail policy revision + deterministic composition domain — port
 * of `ferrogate-guardrails::policy`.
 *
 * NOT enforcement (that lives in the gateway): the revision model, scope
 * selection, detector definitions with `validate()`, action semantics, outcome
 * aggregation, and revision selection. Every serde `deny_unknown_fields` maps to
 * a Zod `.strict()`; the hand-written `validate()` methods are ported as
 * functions returning void / throwing `DetectorError(invalid_configuration)`.
 */
import { z } from "zod";
import { DEFAULT_MODEL, normalizeHazardCode } from "./adapters/workers_ai_llama_guard.js";
import {
  DetectorError,
  type DetectorStage,
  MAX_DETECTOR_TIMEOUT_MS,
  detectorStageSchema,
  findingSeveritySchema,
} from "./contract.js";
import { validateCustomHttpEndpoint } from "./custom_http.js";
import {
  type JsonConstraints,
  type RequestConstraints,
  type SecretPattern,
  jsonConstraintsIsEmpty,
  jsonConstraintsSchema,
  requestConstraintsIsEmpty,
  requestConstraintsSchema,
  secretPatternSchema,
} from "./deterministic.js";
import { ALL_CONTENT_SOURCES, type ContentSource, contentSourceSchema } from "./envelope.js";
import {
  INJECTION_AI_DEFAULT_MODEL,
  INJECTION_CATEGORIES,
  INJECTION_REQUEST_HOOKS,
} from "./injection.js";
import { PII_AI_DEFAULT_MODEL, PII_AI_ENTITIES, PII_ENTITIES } from "./pii.js";

function invalidPolicy(message: string): DetectorError {
  return DetectorError.new("invalid_configuration", message);
}

// --- Enums ------------------------------------------------------------------

export const policyModeSchema = z.enum(["enforce", "shadow"]);
export type PolicyMode = z.infer<typeof policyModeSchema>;

export const policyExecutionSchema = z.enum(["sequential", "parallel"]);
export type PolicyExecution = z.infer<typeof policyExecutionSchema>;

export const policyStreamingModeSchema = z.enum([
  "buffer_and_enforce",
  "shadow_after_complete",
  "reject_streaming",
]);
export type PolicyStreamingMode = z.infer<typeof policyStreamingModeSchema>;

export const policyRevisionStatusSchema = z.enum(["draft", "active", "archived"]);
export type PolicyRevisionStatus = z.infer<typeof policyRevisionStatusSchema>;

/** Tagged `{ type: "all" | "any" | "threshold", minimum? }`. */
export const policyAggregationSchema = z.union([
  z.object({ type: z.literal("all") }).strict(),
  z.object({ type: z.literal("any") }).strict(),
  z.object({ type: z.literal("threshold"), minimum: z.number().int().nonnegative() }).strict(),
]);
export type PolicyAggregation =
  | { type: "all" }
  | { type: "any" }
  | { type: "threshold"; minimum: number };

export const managedActionClassSchema = z.enum([
  "mcp",
  "tool",
  "cli",
  "skill",
  "filesystem",
  "browser",
  "rest",
  "secret",
  "memory",
  "network",
]);
export type ManagedActionClass = z.infer<typeof managedActionClassSchema>;

export function managedActionClassAsStr(value: ManagedActionClass): string {
  return value;
}

export const managedActionSelectorSchema = z
  .object({
    classes: z.array(managedActionClassSchema).default([]),
    targets: z.array(z.string()).default([]),
  })
  .strict();
export type ManagedActionSelector = { classes: ManagedActionClass[]; targets: string[] };

export interface ManagedActionContext {
  class: ManagedActionClass;
  target?: string;
}

export interface PolicySelectionContext {
  organization_id?: string;
  project_id?: string;
  workspace_id?: string;
  api_key_id?: string;
  gateway_config_id?: string;
  model?: string;
  provider?: string;
  managed_action?: ManagedActionContext;
}

function managedSelectorMatches(
  selector: ManagedActionSelector,
  action: ManagedActionContext,
): boolean {
  const classMatches = selector.classes.length === 0 || selector.classes.includes(action.class);
  const targetMatches =
    selector.targets.length === 0 ||
    (action.target !== undefined && selector.targets.includes(action.target));
  return classMatches && targetMatches;
}

function validateManagedSelector(selector: ManagedActionSelector): void {
  if (selector.targets.some((t) => t.trim().length === 0)) {
    throw invalidPolicy("guardrail policy managed_action.targets cannot contain an empty value");
  }
}

// --- Scope selector ---------------------------------------------------------

export const policyScopeSelectorSchema = z
  .object({
    tenant_ids: z.array(z.string()).default([]),
    organization_ids: z.array(z.string()).default([]),
    project_ids: z.array(z.string()).default([]),
    workspace_ids: z.array(z.string()).default([]),
    api_key_ids: z.array(z.string()).default([]),
    gateway_config_ids: z.array(z.string()).default([]),
    models: z.array(z.string()).default([]),
    providers: z.array(z.string()).default([]),
    managed_action: managedActionSelectorSchema.optional(),
  })
  .strict();
export type PolicyScopeSelector = {
  tenant_ids: string[];
  organization_ids: string[];
  project_ids: string[];
  workspace_ids: string[];
  api_key_ids: string[];
  gateway_config_ids: string[];
  models: string[];
  providers: string[];
  managed_action?: ManagedActionSelector;
};

function matchesOptional(allowed: string[], actual: string | undefined): boolean {
  return allowed.length === 0 || (actual !== undefined && allowed.includes(actual));
}

export function scopeMatches(scope: PolicyScopeSelector, context: PolicySelectionContext): boolean {
  const sel = scope.managed_action;
  const act = context.managed_action;
  if (sel === undefined && act === undefined) {
    // model-content policy vs model content: ok
  } else if (sel !== undefined && act !== undefined && managedSelectorMatches(sel, act)) {
    // managed-action policy vs matching managed action: ok
  } else {
    return false;
  }

  const organizationMatches =
    scope.tenant_ids.length === 0 && scope.organization_ids.length === 0
      ? true
      : context.organization_id !== undefined &&
        (scope.tenant_ids.includes(context.organization_id) ||
          scope.organization_ids.includes(context.organization_id));

  return (
    organizationMatches &&
    matchesOptional(scope.project_ids, context.project_id) &&
    matchesOptional(scope.workspace_ids, context.workspace_id) &&
    matchesOptional(scope.api_key_ids, context.api_key_id) &&
    matchesOptional(scope.gateway_config_ids, context.gateway_config_id) &&
    matchesOptional(scope.models, context.model) &&
    matchesOptional(scope.providers, context.provider)
  );
}

export function administrativeRank(scope: PolicyScopeSelector): number {
  if (scope.gateway_config_ids.length > 0) {
    return 5;
  }
  if (scope.api_key_ids.length > 0) {
    return 4;
  }
  if (scope.workspace_ids.length > 0) {
    return 3;
  }
  if (scope.project_ids.length > 0) {
    return 2;
  }
  if (scope.tenant_ids.length > 0 || scope.organization_ids.length > 0) {
    return 1;
  }
  return 0;
}

function validateScope(scope: PolicyScopeSelector): void {
  const fields: Array<[string, string[]]> = [
    ["tenant_ids", scope.tenant_ids],
    ["organization_ids", scope.organization_ids],
    ["project_ids", scope.project_ids],
    ["workspace_ids", scope.workspace_ids],
    ["api_key_ids", scope.api_key_ids],
    ["gateway_config_ids", scope.gateway_config_ids],
    ["models", scope.models],
    ["providers", scope.providers],
  ];
  for (const [field, values] of fields) {
    if (values.some((v) => v.trim().length === 0)) {
      throw invalidPolicy(`guardrail policy scope ${field} cannot contain an empty value`);
    }
  }
  if (scope.managed_action) {
    validateManagedSelector(scope.managed_action);
  }
}

// --- Detector definition (tagged by `kind`) ---------------------------------

const DEFAULT_TIMEOUT_MS = 2_000;
const DEFAULT_MAX_CONCURRENCY = 16;
const DEFAULT_CIRCUIT_FAILURE_THRESHOLD = 3;
const DEFAULT_CIRCUIT_COOLDOWN_MS = 30_000;
const DEFAULT_MAX_PAYLOAD_BYTES = 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024;
const DEFAULT_PRESIDIO_LANGUAGE = "en";
const DEFAULT_SCORE_THRESHOLD_PERCENT = 50;

export const piiEntitySchema = z.enum(PII_ENTITIES);
export const piiAiEntitySchema = z.enum(PII_AI_ENTITIES);
export const piiRedactionModeSchema = z.enum(["mask", "pseudonymize", "tokenize"]);

/**
 * The optional Workers AI second stage. Present in the POLICY (not just in the
 * library config) because whether a tenant's prompts are sent to a model is a
 * governance decision that belongs on a signed, versioned revision — not on a
 * Worker environment variable somebody can change without an audit row.
 */
export const piiAiStageSchema = z
  .object({
    model: z.string().default(PII_AI_DEFAULT_MODEL),
    entities: z.array(piiAiEntitySchema),
    timeout_ms: z.number().int().nonnegative().default(DEFAULT_TIMEOUT_MS),
    max_input_chars: z.number().int().nonnegative().default(4_000),
  })
  .strict();

export const injectionCategorySchema = z.enum(INJECTION_CATEGORIES);
export const injectionActionSchema = z.enum(["flag", "neutralize"]);

/** The optional Workers AI classifier stage (#688), off unless a policy asks. */
export const injectionAiStageSchema = z
  .object({
    model: z.string().default(INJECTION_AI_DEFAULT_MODEL),
    timeout_ms: z.number().int().nonnegative().default(DEFAULT_TIMEOUT_MS),
    max_input_chars: z.number().int().nonnegative().default(4_000),
  })
  .strict();

export const detectorDefinitionSchema = z.discriminatedUnion("kind", [
  z
    .object({
      kind: z.literal("local"),
      keywords: z.array(z.string()).default([]),
      regex: z.array(z.string()).default([]),
      max_input_bytes: z.number().int().nonnegative().nullable().optional(),
      json: jsonConstraintsSchema.optional(),
      request: requestConstraintsSchema.optional(),
      secret_patterns: z.array(secretPatternSchema).default([]),
      fingerprint_secret_ref: z.string().nullable().optional(),
    })
    .strict(),
  z
    .object({
      kind: z.literal("custom_http"),
      endpoint: z.string(),
      timeout_ms: z.number().int().nonnegative().default(DEFAULT_TIMEOUT_MS),
      max_concurrency: z.number().int().nonnegative().default(DEFAULT_MAX_CONCURRENCY),
      circuit_failure_threshold: z
        .number()
        .int()
        .nonnegative()
        .default(DEFAULT_CIRCUIT_FAILURE_THRESHOLD),
      circuit_cooldown_ms: z.number().int().nonnegative().default(DEFAULT_CIRCUIT_COOLDOWN_MS),
      max_retries: z.number().int().nonnegative().default(0),
      max_payload_bytes: z.number().int().nonnegative().default(DEFAULT_MAX_PAYLOAD_BYTES),
      max_response_bytes: z.number().int().nonnegative().default(DEFAULT_MAX_RESPONSE_BYTES),
      allow_private_network: z.boolean().default(false),
      secret_ref: z.string().nullable().optional(),
    })
    .strict(),
  z
    .object({
      kind: z.literal("presidio"),
      endpoint: z.string(),
      language: z.string().default(DEFAULT_PRESIDIO_LANGUAGE),
      score_threshold_percent: z
        .number()
        .int()
        .nonnegative()
        .default(DEFAULT_SCORE_THRESHOLD_PERCENT),
      entities: z.array(z.string()).nullable().optional(),
      timeout_ms: z.number().int().nonnegative().default(DEFAULT_TIMEOUT_MS),
      max_payload_bytes: z.number().int().nonnegative().default(DEFAULT_MAX_PAYLOAD_BYTES),
      max_response_bytes: z.number().int().nonnegative().default(DEFAULT_MAX_RESPONSE_BYTES),
      allow_private_network: z.boolean().default(false),
      secret_ref: z.string().nullable().optional(),
      fingerprint_secret_ref: z.string(),
    })
    .strict(),
  z
    .object({
      kind: z.literal("llm_guard_prompt_injection"),
      endpoint: z.string(),
      score_threshold_percent: z
        .number()
        .int()
        .nonnegative()
        .default(DEFAULT_SCORE_THRESHOLD_PERCENT),
      timeout_ms: z.number().int().nonnegative().default(DEFAULT_TIMEOUT_MS),
      max_payload_bytes: z.number().int().nonnegative().default(DEFAULT_MAX_PAYLOAD_BYTES),
      max_response_bytes: z.number().int().nonnegative().default(DEFAULT_MAX_RESPONSE_BYTES),
      allow_private_network: z.boolean().default(false),
      secret_ref: z.string().nullable().optional(),
      fingerprint_secret_ref: z.string(),
    })
    .strict(),
  // Native PII (#680). No endpoint, no credential, no SSRF surface — the whole
  // point is that nothing leaves the isolate — so the only refs it carries are
  // the MANDATORY fingerprint key and, when the optional AI stage is on, the
  // Workers AI model slug.
  z
    .object({
      kind: z.literal("pii"),
      entities: z.array(piiEntitySchema).default([...PII_ENTITIES]),
      redaction: piiRedactionModeSchema.default("mask"),
      max_input_bytes: z.number().int().nonnegative().nullable().optional(),
      ai: piiAiStageSchema.nullable().optional(),
      fingerprint_secret_ref: z.string(),
    })
    .strict(),
  // Native prompt-injection / jailbreak screening (#688). Like `pii` it has no
  // endpoint and no credential; unlike `pii` its tuning knobs are governance
  // decisions in both directions — `min_severity` trades a missed attack
  // against a refused legitimate request, and both costs are the tenant's — so
  // they live on a signed, versioned revision rather than on an env var.
  z
    .object({
      kind: z.literal("injection"),
      categories: z.array(injectionCategorySchema).default([...INJECTION_CATEGORIES]),
      min_severity: findingSeveritySchema.default("high"),
      action: injectionActionSchema.default("flag"),
      max_input_bytes: z.number().int().nonnegative().nullable().optional(),
      ai: injectionAiStageSchema.nullable().optional(),
      fingerprint_secret_ref: z.string(),
    })
    .strict(),
  z
    .object({
      kind: z.literal("workers_ai_llama_guard"),
      model: z.string().default(DEFAULT_MODEL),
      categories: z.array(z.string()).nullable().optional(),
      timeout_ms: z.number().int().nonnegative().default(DEFAULT_TIMEOUT_MS),
      max_payload_bytes: z.number().int().nonnegative().default(DEFAULT_MAX_PAYLOAD_BYTES),
      fingerprint_secret_ref: z.string(),
    })
    .strict(),
]);
export type DetectorDefinition = z.infer<typeof detectorDefinitionSchema>;

/** Construct a `local` detector definition (Rust `DetectorDefinition::local`). */
export function localDetectorDefinition(
  keywords: string[],
  regex: string[],
  maxInputBytes: number | undefined,
): DetectorDefinition {
  return {
    kind: "local",
    keywords,
    regex,
    max_input_bytes: maxInputBytes ?? null,
    secret_patterns: [],
  };
}

function validateSemanticAdapterLimits(
  kind: string,
  scoreThresholdPercent: number,
  timeoutMs: number,
  maxPayloadBytes: number,
  maxResponseBytes: number,
  secretRef: string | null | undefined,
  fingerprintSecretRef: string,
): void {
  if (
    scoreThresholdPercent > 100 ||
    timeoutMs === 0 ||
    timeoutMs > MAX_DETECTOR_TIMEOUT_MS ||
    maxPayloadBytes === 0 ||
    maxResponseBytes === 0
  ) {
    throw invalidPolicy(`${kind} detector limits are invalid or exceed the runtime ceiling`);
  }
  if (secretRef !== null && secretRef !== undefined && secretRef.length === 0) {
    throw invalidPolicy(`${kind} detector secret_ref cannot be empty`);
  }
  if (fingerprintSecretRef.trim().length === 0) {
    throw invalidPolicy(`${kind} detector requires fingerprint_secret_ref for keyed evidence`);
  }
}

export function validateDetectorDefinition(def: DetectorDefinition): void {
  switch (def.kind) {
    case "local": {
      const json = def.json as JsonConstraints | undefined;
      const request = def.request as RequestConstraints | undefined;
      if (
        def.keywords.length === 0 &&
        def.regex.length === 0 &&
        (def.max_input_bytes === null || def.max_input_bytes === undefined) &&
        (json === undefined || jsonConstraintsIsEmpty(json)) &&
        (request === undefined || requestConstraintsIsEmpty(request)) &&
        def.secret_patterns.length === 0
      ) {
        throw invalidPolicy(
          "local guardrail detector requires at least one deterministic constraint",
        );
      }
      if (def.keywords.some((k) => k.length === 0)) {
        throw invalidPolicy("local guardrail detector keywords cannot be empty");
      }
      for (const pattern of def.regex) {
        try {
          new RegExp(pattern);
        } catch {
          throw invalidPolicy("local guardrail detector contains an invalid regex");
        }
      }
      if (def.max_input_bytes === 0) {
        throw invalidPolicy("local guardrail detector max_input_bytes must be greater than zero");
      }
      if (new Set(def.secret_patterns).size !== def.secret_patterns.length) {
        throw invalidPolicy("local guardrail secret_patterns must be unique");
      }
      const fpr = def.fingerprint_secret_ref;
      if (
        def.secret_patterns.length > 0 &&
        (fpr === null || fpr === undefined || fpr.length === 0)
      ) {
        throw invalidPolicy("local secret detection requires fingerprint_secret_ref");
      }
      if (fpr !== null && fpr !== undefined && fpr.length === 0) {
        throw invalidPolicy("local fingerprint_secret_ref cannot be empty");
      }
      break;
    }
    case "custom_http": {
      let endpoint: URL;
      try {
        endpoint = new URL(def.endpoint);
      } catch {
        throw invalidPolicy("custom_http detector endpoint is invalid");
      }
      validateCustomHttpEndpoint(endpoint, def.allow_private_network);
      if (
        def.timeout_ms === 0 ||
        def.timeout_ms > MAX_DETECTOR_TIMEOUT_MS ||
        def.max_concurrency === 0 ||
        def.circuit_failure_threshold === 0 ||
        def.circuit_cooldown_ms === 0 ||
        def.max_payload_bytes === 0 ||
        def.max_response_bytes === 0 ||
        def.max_retries > 1
      ) {
        throw invalidPolicy(
          "custom_http detector limits are invalid or exceed the runtime ceiling",
        );
      }
      if (def.secret_ref !== null && def.secret_ref !== undefined && def.secret_ref.length === 0) {
        throw invalidPolicy("custom_http detector secret_ref cannot be empty");
      }
      break;
    }
    case "presidio": {
      let endpoint: URL;
      try {
        endpoint = new URL(def.endpoint);
      } catch {
        throw invalidPolicy("presidio detector endpoint is invalid");
      }
      validateCustomHttpEndpoint(endpoint, def.allow_private_network);
      validateSemanticAdapterLimits(
        "presidio",
        def.score_threshold_percent,
        def.timeout_ms,
        def.max_payload_bytes,
        def.max_response_bytes,
        def.secret_ref,
        def.fingerprint_secret_ref,
      );
      if (def.language.trim().length === 0) {
        throw invalidPolicy("presidio detector language cannot be empty");
      }
      const entities = def.entities;
      if (
        entities !== null &&
        entities !== undefined &&
        (entities.length === 0 ||
          entities.some((e) => e.trim().length === 0) ||
          new Set(entities).size !== entities.length)
      ) {
        throw invalidPolicy("presidio detector entities must be non-empty and unique when set");
      }
      break;
    }
    case "pii": {
      if (def.entities.length === 0 || new Set(def.entities).size !== def.entities.length) {
        // An empty entity list would compile, run, find nothing and report a
        // clean pass forever — the silent-miss failure mode this detector exists
        // to remove, dressed up as a green control.
        throw invalidPolicy("pii detector entities must be non-empty and unique");
      }
      if (def.fingerprint_secret_ref.trim().length === 0) {
        throw invalidPolicy("pii detector requires fingerprint_secret_ref for keyed evidence");
      }
      if (def.max_input_bytes === 0) {
        throw invalidPolicy("pii detector max_input_bytes must be greater than zero");
      }
      const ai = def.ai;
      if (ai !== null && ai !== undefined) {
        if (ai.entities.length === 0 || new Set(ai.entities).size !== ai.entities.length) {
          throw invalidPolicy("pii detector AI entities must be non-empty and unique");
        }
        if (ai.timeout_ms === 0 || ai.timeout_ms > MAX_DETECTOR_TIMEOUT_MS) {
          throw invalidPolicy("pii detector AI limits are invalid or exceed the runtime ceiling");
        }
        if (ai.model.trim().length === 0 || ai.max_input_chars === 0) {
          throw invalidPolicy("pii detector AI model and input budget must be non-empty");
        }
      }
      break;
    }
    case "injection": {
      if (def.categories.length === 0 || new Set(def.categories).size !== def.categories.length) {
        // An empty category list compiles, runs, finds nothing and reports a
        // clean pass forever — a green control that screens nothing.
        throw invalidPolicy("injection detector categories must be non-empty and unique");
      }
      if (def.fingerprint_secret_ref.trim().length === 0) {
        throw invalidPolicy(
          "injection detector requires fingerprint_secret_ref for keyed evidence",
        );
      }
      if (def.max_input_bytes === 0) {
        throw invalidPolicy("injection detector max_input_bytes must be greater than zero");
      }
      const ai = def.ai;
      if (ai !== null && ai !== undefined) {
        if (ai.timeout_ms === 0 || ai.timeout_ms > MAX_DETECTOR_TIMEOUT_MS) {
          throw invalidPolicy(
            "injection detector AI limits are invalid or exceed the runtime ceiling",
          );
        }
        if (ai.model.trim().length === 0 || ai.max_input_chars === 0) {
          throw invalidPolicy("injection detector AI model and input budget must be non-empty");
        }
      }
      break;
    }
    case "llm_guard_prompt_injection": {
      let endpoint: URL;
      try {
        endpoint = new URL(def.endpoint);
      } catch {
        throw invalidPolicy("llm_guard detector endpoint is invalid");
      }
      validateCustomHttpEndpoint(endpoint, def.allow_private_network);
      validateSemanticAdapterLimits(
        "llm_guard_prompt_injection",
        def.score_threshold_percent,
        def.timeout_ms,
        def.max_payload_bytes,
        def.max_response_bytes,
        def.secret_ref,
        def.fingerprint_secret_ref,
      );
      break;
    }
    case "workers_ai_llama_guard": {
      if (!def.model.trim().startsWith("@cf/meta/llama-guard")) {
        throw invalidPolicy(
          "workers_ai_llama_guard detector model must be an @cf/meta/llama-guard-* slug",
        );
      }
      if (
        def.timeout_ms === 0 ||
        def.timeout_ms > MAX_DETECTOR_TIMEOUT_MS ||
        def.max_payload_bytes === 0
      ) {
        throw invalidPolicy(
          "workers_ai_llama_guard detector limits are invalid or exceed the runtime ceiling",
        );
      }
      if (def.fingerprint_secret_ref.trim().length === 0) {
        throw invalidPolicy(
          "workers_ai_llama_guard detector requires fingerprint_secret_ref for keyed evidence",
        );
      }
      const categories = def.categories;
      if (categories !== null && categories !== undefined) {
        const normalized = categories.map((c) => normalizeHazardCode(c));
        if (
          categories.length === 0 ||
          normalized.some((c) => c === undefined) ||
          new Set(normalized).size !== normalized.length
        ) {
          throw invalidPolicy(
            "workers_ai_llama_guard categories must be unique valid S-codes (S1..S14) when set",
          );
        }
      }
      break;
    }
  }
}

// --- Check binding, action, revision ----------------------------------------

export const checkBindingSchema = z
  .object({
    id: z.string(),
    enabled: z.boolean().default(true),
    stage: detectorStageSchema,
    sources: z.array(contentSourceSchema).default([...ALL_CONTENT_SOURCES]),
    detector: detectorDefinitionSchema,
    fallback_detector: detectorDefinitionSchema.optional(),
  })
  .strict();
export type CheckBinding = {
  id: string;
  enabled: boolean;
  stage: DetectorStage;
  sources: ContentSource[];
  detector: DetectorDefinition;
  fallback_detector?: DetectorDefinition;
};

export const actionKindSchema = z.enum([
  "allow",
  "block",
  "redact",
  "record",
  "require_approval",
  "quarantine",
]);
export type ActionKind = z.infer<typeof actionKindSchema>;

export const policyActionSchema = z
  .object({
    kind: actionKindSchema,
    code: z.string().nullable().optional(),
    message: z.string().nullable().optional(),
  })
  .strict();
export type PolicyAction = { kind: ActionKind; code?: string | null; message?: string | null };

export const policyActions = {
  allow: (): PolicyAction => ({ kind: "allow" }),
  record: (): PolicyAction => ({ kind: "record" }),
  block: (code: string, message: string): PolicyAction => ({ kind: "block", code, message }),
  redact: (code: string, message: string): PolicyAction => ({ kind: "redact", code, message }),
  requireApproval: (code: string, message: string): PolicyAction => ({
    kind: "require_approval",
    code,
    message,
  }),
  quarantine: (code: string, message: string): PolicyAction => ({
    kind: "quarantine",
    code,
    message,
  }),
};

function validateAction(action: PolicyAction): void {
  const enforcing =
    action.kind === "block" ||
    action.kind === "redact" ||
    action.kind === "require_approval" ||
    action.kind === "quarantine";
  if (
    enforcing &&
    (!action.code || action.code.length === 0 || !action.message || action.message.length === 0)
  ) {
    throw invalidPolicy(
      "block, redact, require_approval, and quarantine actions require non-empty code and message",
    );
  }
}

const DEFAULT_POLICY_DEADLINE_MS = 2_000;

export const policyRevisionSchema = z
  .object({
    policy_id: z.string().default(""),
    revision: z.number().int().nonnegative().default(0),
    name: z.string(),
    description: z.string().nullable().optional(),
    enforced: z.boolean().default(true),
    scope: policyScopeSelectorSchema.default({
      tenant_ids: [],
      organization_ids: [],
      project_ids: [],
      workspace_ids: [],
      api_key_ids: [],
      gateway_config_ids: [],
      models: [],
      providers: [],
    }),
    checks: z.array(checkBindingSchema),
    aggregation: policyAggregationSchema.default({ type: "all" }),
    execution: policyExecutionSchema.default("sequential"),
    mode: policyModeSchema.default("enforce"),
    streaming: policyStreamingModeSchema.default("buffer_and_enforce"),
    on_pass: z.array(policyActionSchema),
    on_fail: z.array(policyActionSchema),
    on_error: z.array(policyActionSchema),
    deadline_ms: z.number().int().nonnegative().default(DEFAULT_POLICY_DEADLINE_MS),
    created_at_unix: z.number().int().nonnegative().default(0),
    created_by: z.string().default(""),
  })
  .strict();
export type PolicyRevision = {
  policy_id: string;
  revision: number;
  name: string;
  description?: string | null;
  enforced: boolean;
  scope: PolicyScopeSelector;
  checks: CheckBinding[];
  aggregation: PolicyAggregation;
  execution: PolicyExecution;
  mode: PolicyMode;
  streaming: PolicyStreamingMode;
  on_pass: PolicyAction[];
  on_fail: PolicyAction[];
  on_error: PolicyAction[];
  deadline_ms: number;
  created_at_unix: number;
  created_by: string;
};

export function immutableId(revision: PolicyRevision): string {
  return `${revision.policy_id}@${revision.revision}`;
}

/**
 * A request-stage `injection` check MUST be bound to all four hooks (#688).
 *
 * This is a deliberate refusal to make the dangerous configuration
 * expressible. Screening only `user` is the intuitive setup and it defends
 * almost nothing: the attacker does not type into the prompt box, they poison a
 * document the retriever pulls, a tool DESCRIPTION the agent reads to choose a
 * call, or the RESULT a tool hands back. A policy that screens the prompt alone
 * looks green on every dashboard while the actual attack path is unwatched, and
 * a control that reports "clean" on an unscreened surface is worse than no
 * control — it converts an open risk into a false assurance.
 *
 * Tuning is therefore done with `min_severity`, `categories` and `action`,
 * which change what is BLOCKED. Unbinding a hook changes what is SEEN, and that
 * is not offered.
 *
 * Response-stage injection checks are unconstrained: the four hooks are
 * request-shaped (a tool result re-enters as a `tool` message on the NEXT
 * request), and a response-stage check screens assistant output for a different
 * purpose.
 */
function validateInjectionHookCoverage(check: CheckBinding): void {
  if (check.detector.kind !== "injection" || check.stage !== "request") {
    return;
  }
  const bound = new Set(check.sources);
  const missing = INJECTION_REQUEST_HOOKS.filter((hook) => !bound.has(hook));
  if (missing.length > 0) {
    throw invalidPolicy(
      `injection detector must be bound to all four request hooks; missing ${missing.join(", ")}`,
    );
  }
}

export function validatePolicyRevision(rev: PolicyRevision): void {
  if (
    rev.policy_id.trim().length === 0 ||
    rev.name.trim().length === 0 ||
    rev.created_by.trim().length === 0 ||
    rev.revision === 0
  ) {
    throw invalidPolicy("guardrail policy id, name, revision, and created_by are required");
  }
  if (rev.deadline_ms === 0 || rev.deadline_ms > MAX_DETECTOR_TIMEOUT_MS) {
    throw invalidPolicy("guardrail policy deadline must be between 1 and 30000 milliseconds");
  }
  validateScope(rev.scope);
  if (rev.checks.length === 0) {
    throw invalidPolicy("guardrail policy requires at least one check");
  }
  const checkIds = new Set<string>();
  let enabledChecks = 0;
  for (const check of rev.checks) {
    if (check.id.trim().length === 0 || checkIds.has(check.id)) {
      throw invalidPolicy("guardrail policy check ids must be non-empty and unique");
    }
    checkIds.add(check.id);
    if (check.sources.length === 0 || new Set(check.sources).size !== check.sources.length) {
      throw invalidPolicy("guardrail policy check sources must be non-empty and unique");
    }
    validateDetectorDefinition(check.detector);
    validateInjectionHookCoverage(check);
    if (check.fallback_detector) {
      if (check.fallback_detector.kind !== "local") {
        throw invalidPolicy("guardrail policy fallback_detector must be local");
      }
      validateDetectorDefinition(check.fallback_detector);
    }
    if (check.enabled) {
      enabledChecks += 1;
    }
  }
  if (enabledChecks === 0) {
    throw invalidPolicy("guardrail policy requires at least one enabled check");
  }
  if (rev.aggregation.type === "threshold") {
    if (rev.aggregation.minimum === 0 || rev.aggregation.minimum > enabledChecks) {
      throw invalidPolicy(
        "guardrail policy threshold must be between one and the enabled check count",
      );
    }
  }
  for (const [name, actions] of [
    ["on_pass", rev.on_pass],
    ["on_fail", rev.on_fail],
    ["on_error", rev.on_error],
  ] as const) {
    if (actions.length === 0) {
      throw invalidPolicy(`guardrail policy ${name} actions cannot be empty`);
    }
    for (const action of actions) {
      validateAction(action);
    }
  }
}

export function selectedCheckIds(rev: PolicyRevision, stage: DetectorStage): string[] {
  return rev.checks.filter((c) => c.enabled && c.stage === stage).map((c) => c.id);
}

export interface PolicyRevisionView {
  revision: PolicyRevision;
  status: PolicyRevisionStatus;
}

// --- Outcome aggregation ----------------------------------------------------

export type CheckOutcome = "pass" | "fail" | "error" | "disabled";
export type AggregateOutcome = "pass" | "fail" | "error";

export function aggregateCheckOutcomes(
  aggregation: PolicyAggregation,
  outcomes: CheckOutcome[],
): AggregateOutcome {
  const enabled = outcomes.filter((o) => o !== "disabled");
  if (enabled.length === 0) {
    return "error";
  }
  const passes = enabled.filter((o) => o === "pass").length;
  const failures = enabled.filter((o) => o === "fail").length;
  const errors = enabled.filter((o) => o === "error").length;
  switch (aggregation.type) {
    case "all":
      return failures > 0 ? "fail" : errors > 0 ? "error" : "pass";
    case "any":
      return passes > 0 ? "pass" : errors > 0 ? "error" : "fail";
    case "threshold": {
      const minimum = aggregation.minimum;
      if (failures >= minimum) {
        return "fail";
      }
      if (failures + errors >= minimum) {
        return "error";
      }
      return "pass";
    }
  }
}

/** Filter policies by scope match, then sort by (rank, policy_id, revision). */
export function selectPolicyRevisions(
  policies: PolicyRevision[],
  context: PolicySelectionContext,
): PolicyRevision[] {
  return policies
    .filter((p) => scopeMatches(p.scope, context))
    .sort((a, b) => {
      const rank = administrativeRank(a.scope) - administrativeRank(b.scope);
      if (rank !== 0) {
        return rank;
      }
      if (a.policy_id !== b.policy_id) {
        return a.policy_id < b.policy_id ? -1 : 1;
      }
      return a.revision - b.revision;
    });
}
