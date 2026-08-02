/**
 * OpenTelemetry **GenAI semantic conventions** — the vendor-neutral vocabulary
 * (#669).
 *
 * ## Why this module exists
 *
 * Everything else in this package speaks `ferrogate.*`: `spans.ts` names six
 * templates `ferrogate.gateway.request` / `.auth` / `.policy.evaluate` / … and
 * `otlp.ts` renders `ferrogate.tokens`, `ferrogate.request_status`, and so on.
 * That vocabulary is ours alone. Datadog, Grafana, Langfuse and Arize all key
 * their LLM views off `gen_ai.*`, and Envoy AI Gateway and TrueFoundry emit it,
 * so a customer pointing an existing stack at FerroGate saw unrecognised spans
 * and had to write a translator before the gateway told them anything.
 *
 * This module is the translation, done at the SOURCE rather than by the
 * customer. It is pure data + pure functions: it builds attribute lists and
 * OTLP metric JSON and, like the rest of the package, performs no I/O.
 *
 * ## SPEC REVISION TARGETED: semantic conventions **v1.43.0**
 *
 * Written against the registry as it stands in 2026-08, which is NOT where it
 * was: the GenAI group has been MOVED out of `open-telemetry/semantic-conventions`
 * into `open-telemetry/semantic-conventions-genai` (`docs/gen-ai/`). Every
 * `gen_ai.*` entry left behind on
 * <https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/>
 * now carries a "Deprecated — moved" badge, which is a relocation marker and
 * NOT a statement about the attribute. The new repository has published no tag
 * yet, so **v1.43.0** — the last numbered release of the parent repo that still
 * contains these definitions, and the version the moved docs cross-link to — is
 * the revision this module is pinned to. The whole group is stability
 * `Development`; nothing in `gen_ai.*` is Stable, and the names below can still
 * move under us. That is why they are constants in one file: a spec bump is one
 * diff here, not a grep across two apps.
 *
 * ## `gen_ai.system` AND `gen_ai.provider.name` — both, deliberately
 *
 * The spec renamed `gen_ai.system` to {@link GEN_AI_PROVIDER_NAME} and marks the
 * old key "Deprecated, use `gen_ai.provider.name` instead". Issue #669's
 * acceptance list names `gen_ai.system`, and it is right to: the SHIPPED
 * mappings in Datadog and Langfuse still read the old key, so emitting only the
 * new one would satisfy the spec and tell a customer's dashboard nothing. Both
 * are emitted, with the same value. The cost is one duplicated string per span;
 * the alternative is being correct and useless. Drop `gen_ai.system` when the
 * downstream mappings have caught up — not before.
 */
// TYPE-ONLY, and that is structural rather than stylistic: `otlp.ts` imports
// this module at RUNTIME to splice the GenAI metrics into the metric bag, so a
// value import back the other way would close an ESM cycle. `import type` is
// erased by the compiler, which leaves the dependency edge one-directional.
// `otlpAttribute()` is therefore inlined below as `attribute()`.
import type { OtlpAttribute } from "./otlp.js";

/** Local stand-in for `otlp.ts::otlpAttribute` — see the import note above. */
function attribute(key: string, value: string): OtlpAttribute {
  return { key, value };
}

// ---------------------------------------------------------------------------
// Attribute keys
// ---------------------------------------------------------------------------

/**
 * DEPRECATED BY THE SPEC, EMITTED ANYWAY. See the module docs: shipped Datadog
 * and Langfuse mappings still key off this. Same value as
 * {@link GEN_AI_PROVIDER_NAME}.
 */
export const GEN_AI_SYSTEM = "gen_ai.system";
/** The current spelling of "which GenAI provider served this". */
export const GEN_AI_PROVIDER_NAME = "gen_ai.provider.name";
/** `chat`, `embeddings`, `generate_content`, … — see {@link GenAiOperationName}. */
export const GEN_AI_OPERATION_NAME = "gen_ai.operation.name";
/** The model the CALLER asked for (FerroGate's logical model name). */
export const GEN_AI_REQUEST_MODEL = "gen_ai.request.model";
/** The model that actually answered (FerroGate's resolved `provider_model`). */
export const GEN_AI_RESPONSE_MODEL = "gen_ai.response.model";
/** Prompt-side tokens. Spec: "SHOULD include all types of input tokens". */
export const GEN_AI_USAGE_INPUT_TOKENS = "gen_ai.usage.input_tokens";
/** Completion-side tokens. */
export const GEN_AI_USAGE_OUTPUT_TOKENS = "gen_ai.usage.output_tokens";
/** `input` | `output` — REQUIRED on `gen_ai.client.token.usage` points. */
export const GEN_AI_TOKEN_TYPE = "gen_ai.token.type";
/**
 * `error.type` is a STABLE general-registry attribute (not `gen_ai.*`), and is
 * conditionally required on the duration metric when the operation failed. The
 * gateway publishes the HTTP status class, which the spec names explicitly as
 * an acceptable low-cardinality identifier ("`500`").
 */
export const ERROR_TYPE = "error.type";

// ---------------------------------------------------------------------------
// Well-known values
// ---------------------------------------------------------------------------

/**
 * The subset of `gen_ai.operation.name`'s well-known values FerroGate's six
 * inference operations can produce. The spec's rule is "if one of them applies,
 * the respective value MUST be used", so this is a closed mapping, not a
 * suggestion.
 */
export const GenAiOperationName = {
  /** Chat completions, Anthropic messages, and the OpenAI Responses API. */
  Chat: "chat",
  /** Legacy `/v1/completions`-shaped text completion. */
  TextCompletion: "text_completion",
  Embeddings: "embeddings",
  /**
   * Image generation. The spec has no image-specific operation; this is its
   * "multimodal content generation" value, which is the closest well-known one
   * and is preferable to inventing `image_generation` — a custom value is only
   * permitted when NO predefined value applies.
   */
  GenerateContent: "generate_content",
} as const;
export type GenAiOperationName = (typeof GenAiOperationName)[keyof typeof GenAiOperationName];

/**
 * FerroGate provider KIND → `gen_ai.provider.name`.
 *
 * The left side is `PhysicalRoute.providerKind` / `ProviderConfig.kind` — the
 * adapter family and its aliases as `packages/providers`'
 * `SUPPORTED_PROVIDER_ADAPTER_FAMILIES` spells them. The right side is a
 * well-known semconv value.
 *
 * The table is duplicated here rather than imported because this package
 * deliberately depends on nothing but `@ferrogate/core` and zod — an
 * observability crate that pulls in the provider adapters would be a dependency
 * cycle waiting to happen. `test/genai.test.ts` pins the FerroGate side against
 * the alias list so the duplication is a checked one.
 *
 * A kind with NO well-known counterpart is passed through as a custom value,
 * which the spec explicitly allows ("otherwise a custom value MAY be used").
 * That is the honest answer for `openrouter`, `vllm` or `ollama`: claiming
 * `openai` because the WIRE FORMAT is OpenAI-compatible would attribute a local
 * Llama run to OpenAI in every cost panel downstream.
 */
const PROVIDER_NAME_BY_KIND: Readonly<Record<string, string>> = {
  openai: "openai",
  anthropic: "anthropic",
  deepseek: "deepseek",
  grok: "x_ai",
  xai: "x_ai",
  gemini: "gcp.gemini",
  vertex: "gcp.vertex_ai",
  "vertex-ai": "gcp.vertex_ai",
  bedrock: "aws.bedrock",
  "aws-bedrock": "aws.bedrock",
  azure: "azure.ai.openai",
  "azure-openai": "azure.ai.openai",
  cohere: "cohere",
  groq: "groq",
  mistral: "mistral_ai",
  "mistral-ai": "mistral_ai",
  moonshot: "moonshot_ai",
  "moonshot-ai": "moonshot_ai",
  perplexity: "perplexity",
  watsonx: "ibm.watsonx.ai",
  "ibm-watsonx": "ibm.watsonx.ai",
};

/**
 * Map a FerroGate provider kind onto `gen_ai.provider.name`.
 *
 * Trimmed and lower-cased first, because `ProviderConfig.kind` is
 * operator-authored config and `canonicalProviderAdapterFamily` normalizes the
 * same way. An unknown kind is returned normalized rather than dropped — see
 * {@link PROVIDER_NAME_BY_KIND} for why a fabricated `openai` would be worse
 * than a custom value.
 */
export function genAiProviderName(providerKind: string): string {
  const normalized = providerKind.trim().toLowerCase();
  return PROVIDER_NAME_BY_KIND[normalized] ?? normalized;
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/** Histogram, unit `{token}`. Emitted once per token type. */
export const GEN_AI_CLIENT_TOKEN_USAGE = "gen_ai.client.token.usage";
/** Histogram, unit `s` — SECONDS, not the gateway's internal milliseconds. */
export const GEN_AI_CLIENT_OPERATION_DURATION = "gen_ai.client.operation.duration";

/** The spec's `ExplicitBucketBoundaries` for {@link GEN_AI_CLIENT_TOKEN_USAGE}. */
export const GEN_AI_TOKEN_USAGE_BUCKETS: readonly number[] = [
  1, 4, 16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864,
];

/** The spec's `ExplicitBucketBoundaries` for {@link GEN_AI_CLIENT_OPERATION_DURATION}. */
export const GEN_AI_OPERATION_DURATION_BUCKETS: readonly number[] = [
  0.01, 0.02, 0.04, 0.08, 0.16, 0.32, 0.64, 1.28, 2.56, 5.12, 10.24, 20.48, 40.96, 81.92,
];

// ---------------------------------------------------------------------------
// The invocation record
// ---------------------------------------------------------------------------

/**
 * One GenAI operation as the gateway observed it, in semconv terms.
 *
 * Every field is already NORMALIZED — `providerName` is a semconv value, not a
 * FerroGate kind, and `durationSeconds` is seconds. Normalizing at construction
 * rather than at render time means there is exactly one place a millisecond
 * value could be published as `s`, and it is guarded by a test.
 *
 * There is deliberately no free-form attribute bag: issue #500 is the reason
 * FerroGate's metric labels are low-cardinality, and an open map here is the
 * obvious place for someone to put a prompt or a user id.
 */
export interface GenAiInvocation {
  /** {@link GenAiOperationName}, or a documented custom value. */
  readonly operationName: string;
  /** Already mapped through {@link genAiProviderName}. */
  readonly providerName: string;
  /** The model the caller asked for. */
  readonly requestModel: string;
  /** The model that answered; omitted when it is not known. */
  readonly responseModel?: string | undefined;
  readonly inputTokens?: number | undefined;
  readonly outputTokens?: number | undefined;
  /** SECONDS. See {@link GEN_AI_CLIENT_OPERATION_DURATION}. */
  readonly durationSeconds?: number | undefined;
  /**
   * `error.type` — set only when the operation failed. The gateway passes the
   * HTTP status code as a string, per the spec's own example.
   */
  readonly errorType?: string | undefined;
}

/**
 * The span name the spec asks for: `{gen_ai.operation.name} {gen_ai.request.model}`.
 *
 * NOT applied unconditionally — see `apps/gateway/src/telemetry/emit.ts`. A
 * deployment that still has dashboards filtering on `ferrogate.gateway.request`
 * keeps that name until it opts into the `genai` profile.
 */
export function genAiSpanName(invocation: GenAiInvocation): string {
  return `${invocation.operationName} ${invocation.requestModel}`;
}

/**
 * The `gen_ai.*` span attributes for one invocation.
 *
 * OTLP/JSON here carries every attribute as a `stringValue` (see
 * `otlp.ts::attributesJson`), so the token counts are stringified integers.
 * That is a limitation of this package's OTLP renderer, not of the convention —
 * the spec types them `int`, and a backend that wants numbers reads the METRICS,
 * which are real numeric histogram points.
 *
 * A token count that the provider did not report is OMITTED rather than sent as
 * `0`: a zero would be indistinguishable from a genuinely empty completion and
 * would drag every average down.
 */
export function genAiSpanAttributes(invocation: GenAiInvocation): OtlpAttribute[] {
  const attributes: OtlpAttribute[] = [
    attribute(GEN_AI_OPERATION_NAME, invocation.operationName),
    attribute(GEN_AI_PROVIDER_NAME, invocation.providerName),
    // The deprecated alias, same value. See the module docs.
    attribute(GEN_AI_SYSTEM, invocation.providerName),
    attribute(GEN_AI_REQUEST_MODEL, invocation.requestModel),
  ];
  if (invocation.responseModel !== undefined) {
    attributes.push(attribute(GEN_AI_RESPONSE_MODEL, invocation.responseModel));
  }
  if (invocation.inputTokens !== undefined) {
    attributes.push(attribute(GEN_AI_USAGE_INPUT_TOKENS, String(invocation.inputTokens)));
  }
  if (invocation.outputTokens !== undefined) {
    attributes.push(attribute(GEN_AI_USAGE_OUTPUT_TOKENS, String(invocation.outputTokens)));
  }
  if (invocation.errorType !== undefined) {
    attributes.push(attribute(ERROR_TYPE, invocation.errorType));
  }
  return attributes;
}

/**
 * The attributes both GenAI metrics share.
 *
 * `gen_ai.operation.name` and `gen_ai.provider.name` are REQUIRED on the token
 * metric; `gen_ai.request.model` is "conditionally required, if available" and
 * the gateway always has it (a request that resolved no model produces no
 * invocation at all). `server.address`/`server.port` are deliberately NOT
 * emitted: they would be the PROVIDER's host, which is per-deployment
 * configuration and pushes the series count up without telling an operator
 * anything the provider name does not.
 */
function genAiMetricAttributes(invocation: GenAiInvocation): OtlpAttribute[] {
  const attributes: OtlpAttribute[] = [
    attribute(GEN_AI_OPERATION_NAME, invocation.operationName),
    attribute(GEN_AI_PROVIDER_NAME, invocation.providerName),
    attribute(GEN_AI_REQUEST_MODEL, invocation.requestModel),
  ];
  if (invocation.responseModel !== undefined) {
    attributes.push(attribute(GEN_AI_RESPONSE_MODEL, invocation.responseModel));
  }
  return attributes;
}

/**
 * `attributes` as an OTLP/JSON key-value list. Duplicated from `otlp.ts`'s
 * private helper rather than exported from it, so the OTLP renderer's internals
 * stay private to that module.
 */
function attributesJson(attributes: readonly OtlpAttribute[]): unknown[] {
  return attributes.map((attribute) => ({
    key: attribute.key,
    value: { stringValue: attribute.value },
  }));
}

/**
 * One OTLP/JSON histogram point holding a SINGLE observation.
 *
 * A Worker cannot accumulate — it has no process to hold a histogram in
 * (the same limit `prometheus.ts` marks) — so each request contributes one
 * point with `count: 1`, `sum: value`, and the bucket the value falls in set to
 * 1. Written out in full rather than left as `count`/`sum` only, because a
 * collector that computes quantiles needs `bucketCounts` to line up with
 * `explicitBounds`, and an empty `bucketCounts` is read by some backends as
 * "no data" rather than "unbucketed".
 */
function histogramPointJson(
  value: number,
  bounds: readonly number[],
  attributes: readonly OtlpAttribute[],
): unknown {
  // `bucketCounts` has exactly one more entry than `explicitBounds`: the last
  // one is the +Inf overflow bucket.
  const bucketCounts = new Array<number>(bounds.length + 1).fill(0);
  let index = bounds.findIndex((bound) => value <= bound);
  if (index < 0) {
    index = bounds.length;
  }
  bucketCounts[index] = 1;
  return {
    count: "1",
    sum: value,
    min: value,
    max: value,
    explicitBounds: [...bounds],
    bucketCounts: bucketCounts.map(String),
    attributes: attributesJson(attributes),
  };
}

/**
 * The GenAI metrics for one invocation, as OTLP/JSON metric objects ready to be
 * spliced into a `scopeMetrics.metrics` array.
 *
 * `aggregationTemporality: 1` is DELTA, and unlike the `2` (CUMULATIVE) the
 * counter renderer hard-codes, it is ACCURATE here: each point is one request's
 * own observation and nothing about it is cumulative. That difference is the
 * reason these are built here rather than folded into the counter bag.
 *
 * Returns an empty array when the invocation carries nothing worth a point —
 * a request whose provider reported no usage and whose duration was not
 * measured contributes no series rather than a zero one.
 */
export function genAiMetricsJson(invocation: GenAiInvocation): unknown[] {
  const metrics: unknown[] = [];
  const base = genAiMetricAttributes(invocation);

  const tokenPoints: unknown[] = [];
  if (invocation.inputTokens !== undefined) {
    tokenPoints.push(
      histogramPointJson(invocation.inputTokens, GEN_AI_TOKEN_USAGE_BUCKETS, [
        ...base,
        attribute(GEN_AI_TOKEN_TYPE, "input"),
      ]),
    );
  }
  if (invocation.outputTokens !== undefined) {
    tokenPoints.push(
      histogramPointJson(invocation.outputTokens, GEN_AI_TOKEN_USAGE_BUCKETS, [
        ...base,
        attribute(GEN_AI_TOKEN_TYPE, "output"),
      ]),
    );
  }
  if (tokenPoints.length > 0) {
    metrics.push({
      name: GEN_AI_CLIENT_TOKEN_USAGE,
      description: "Number of input and output tokens used.",
      unit: "{token}",
      histogram: { aggregationTemporality: 1, dataPoints: tokenPoints },
    });
  }

  if (invocation.durationSeconds !== undefined) {
    const attributes =
      invocation.errorType === undefined
        ? base
        : [...base, attribute(ERROR_TYPE, invocation.errorType)];
    metrics.push({
      name: GEN_AI_CLIENT_OPERATION_DURATION,
      description: "GenAI operation duration.",
      unit: "s",
      histogram: {
        aggregationTemporality: 1,
        dataPoints: [
          histogramPointJson(
            invocation.durationSeconds,
            GEN_AI_OPERATION_DURATION_BUCKETS,
            attributes,
          ),
        ],
      },
    });
  }

  return metrics;
}

// ---------------------------------------------------------------------------
// Dual emission
// ---------------------------------------------------------------------------

/**
 * Which attribute vocabulary a deployment publishes (#669).
 *
 * ## The judgement call, stated rather than buried
 *
 * The issue asks to "keep `ferrogate.*` as dual emission behind an opt-in var
 * so existing dashboards survive". Those two halves pull in opposite
 * directions: a var you must opt IN to means the default DROPS `ferrogate.*`,
 * and then no existing dashboard survives the deploy — which is the thing the
 * same sentence asks for. So the var exists and is explicit, and its DEFAULT is
 * {@link TelemetryAttributeProfile.Dual}: nothing an operator already has stops
 * working, and the `gen_ai.*` half arrives alongside it. The opt-in is to
 * NARROWING, which is the only direction that can break someone.
 */
export const TelemetryAttributeProfile = {
  /** DEFAULT. `ferrogate.*` unchanged, `gen_ai.*` added alongside. */
  Dual: "dual",
  /** `gen_ai.*` only, and the semconv `{operation} {model}` span name. */
  GenAi: "genai",
  /** Exactly the pre-#669 wire: `ferrogate.*` only, no `gen_ai.*` anywhere. */
  Ferrogate: "ferrogate",
} as const;
export type TelemetryAttributeProfile =
  (typeof TelemetryAttributeProfile)[keyof typeof TelemetryAttributeProfile];

/**
 * Parse `TELEMETRY_ATTRIBUTE_PROFILE`. Absent, blank or UNRECOGNISED all yield
 * {@link TelemetryAttributeProfile.Dual}.
 *
 * An unrecognised value falling back to the widest profile is the same posture
 * `TELEMETRY_SIGNALS` takes for an unknown token: a typo in an observability
 * var must not silently narrow what a deployment emits, and it must never fail
 * the data plane.
 */
export function telemetryAttributeProfile(raw: string | undefined): TelemetryAttributeProfile {
  switch (raw?.trim().toLowerCase()) {
    case TelemetryAttributeProfile.GenAi:
    case "gen_ai":
    case "otel":
      return TelemetryAttributeProfile.GenAi;
    case TelemetryAttributeProfile.Ferrogate:
    case "legacy":
      return TelemetryAttributeProfile.Ferrogate;
    default:
      return TelemetryAttributeProfile.Dual;
  }
}

/** True when `profile` publishes the `gen_ai.*` half. */
export function profileEmitsGenAi(profile: TelemetryAttributeProfile): boolean {
  return profile !== TelemetryAttributeProfile.Ferrogate;
}

/** True when `profile` publishes the legacy `ferrogate.*` half. */
export function profileEmitsFerrogate(profile: TelemetryAttributeProfile): boolean {
  return profile !== TelemetryAttributeProfile.GenAi;
}
