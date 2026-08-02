/**
 * `DetectorDefinition` → a live `GuardrailDetector`.
 *
 * Port of the Rust `state.rs` compile step that turned a `CheckBinding`'s
 * definition into an `Arc<dyn GuardrailDetector>` stored on `AppState`. Every
 * detector here comes STRAIGHT out of `@ferrogate/guardrails` — nothing in this
 * app re-implements a scanner, a circuit breaker or an SSRF check.
 *
 * Two Cloudflare-specific notes:
 *
 * 1. **Secret refs.** A definition names its credential/fingerprint key by
 *    `secret_ref` / `fingerprint_secret_ref`, exactly as the Rust config named
 *    a `ferrogate-secrets` reference. On Workers the only readable secret path
 *    is a DEPLOY-TIME binding (`docs/legacy/inventory-policy-core.md` appendix
 *    §8), so {@link DetectorBuildContext.secrets} resolves a ref against the
 *    Worker `env`. A ref that resolves to nothing is a hard build error — a
 *    keyed-evidence detector without its key would emit unkeyed (reversible)
 *    fingerprints, which the appendix forbids.
 * 2. **Workers AI.** `workers_ai_llama_guard` prefers the `AI` binding
 *    (`workersAiBindingClient`) over the REST client; the Rust
 *    `WorkersAiLlamaGuard` was "only constructible when a `[cloudflare]` block
 *    is configured = graceful disable", so with neither binding nor REST client
 *    available the check is DISABLED rather than silently passing.
 */
import {
  type ContentSource,
  CustomHttpDetector,
  type DetectorDefinition,
  DetectorSecret,
  DeterministicDetector,
  type GuardrailDetector,
  InjectionDetector,
  LlmGuardPromptInjectionDetector,
  PiiDetector,
  type PiiTokenVault,
  type PolicyRevision,
  PresidioDetector,
  type WorkersAiBinding,
  type WorkersAiClient,
  WorkersAiLlamaGuardDetector,
  configDigest,
  injectionDetectorConfig,
  piiDetectorConfig,
  validateDetectorDefinition,
  workersAiBindingClient,
} from "@ferrogate/guardrails";
import type { GuardrailCheckRuntime } from "./ports.js";

/** Resolves a `secret_ref` to its value. Backed by Worker secret bindings. */
export type SecretResolver = (ref: string) => string | undefined;

export interface DetectorBuildContext {
  /** `env://NAME` / `cf://store/name` resolution. Defaults to "nothing resolves". */
  readonly secrets?: SecretResolver | undefined;
  /** The `AI` binding, when the Worker has one. */
  readonly workersAi?: WorkersAiBinding | undefined;
  /** Escape hatch for a non-binding Workers-AI transport (tests, REST). */
  readonly workersAiClient?: WorkersAiClient | undefined;
  /**
   * Where a REVERSIBLE PII redaction (#680) stashes its token→value mapping.
   * Absent by default: `redaction: "tokenize"` then fails the BUILD rather than
   * quietly becoming irreversible.
   */
  readonly piiVault?: PiiTokenVault | undefined;
  /**
   * Detector overrides by check id — the seam the test suite and a future
   * shadow/canary rollout use to substitute a scripted detector without
   * touching the policy document.
   */
  readonly detectorOverrides?: Readonly<Record<string, GuardrailDetector>> | undefined;
}

export class DetectorBuildError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DetectorBuildError";
  }
}

function requireSecret(
  context: DetectorBuildContext,
  ref: string | null | undefined,
  purpose: string,
): DetectorSecret {
  const value = ref === null || ref === undefined ? undefined : context.secrets?.(ref);
  if (value === undefined || value.length === 0) {
    throw new DetectorBuildError(
      `guardrail detector ${purpose} secret ref ${ref ?? "<missing>"} did not resolve to a value`,
    );
  }
  return new DetectorSecret(value);
}

function optionalSecret(
  context: DetectorBuildContext,
  ref: string | null | undefined,
): DetectorSecret | undefined {
  if (ref === null || ref === undefined || ref.length === 0) {
    return undefined;
  }
  const value = context.secrets?.(ref);
  if (value === undefined || value.length === 0) {
    throw new DetectorBuildError(
      `guardrail detector credential secret ref ${ref} did not resolve to a value`,
    );
  }
  return new DetectorSecret(value);
}

/** `config_digest` on the evidence row — a 4-byte sha256 prefix of the config. */
export function detectorConfigDigest(definition: DetectorDefinition): string {
  return configDigest([JSON.stringify(definition)]);
}

/** The `detector_id` recorded on evidence: the definition's `kind`. */
export function detectorIdFor(definition: DetectorDefinition): string {
  return definition.kind;
}

/**
 * Build one detector. Throws {@link DetectorBuildError} for a definition that
 * cannot be satisfied in this environment; returns `undefined` ONLY for the
 * graceful-disable case (Workers-AI Llama-Guard with no Cloudflare transport),
 * which mirrors the Rust "only constructible when `[cloudflare]` is configured".
 */
export function buildDetector(
  checkId: string,
  definition: DetectorDefinition,
  sources: readonly ContentSource[],
  context: DetectorBuildContext = {},
): GuardrailDetector | undefined {
  validateDetectorDefinition(definition);
  const supportedSources = [...sources];
  const id = `${checkId}:${definition.kind}`;

  switch (definition.kind) {
    case "local": {
      const fingerprintKey =
        definition.secret_patterns.length > 0 || definition.fingerprint_secret_ref
          ? requireSecret(context, definition.fingerprint_secret_ref, "local fingerprint")
          : undefined;
      return DeterministicDetector.new({
        id,
        supported_sources: supportedSources,
        keywords: [...definition.keywords],
        regex: [...definition.regex],
        ...(definition.max_input_bytes !== null && definition.max_input_bytes !== undefined
          ? { max_input_bytes: definition.max_input_bytes }
          : {}),
        ...(definition.json !== undefined ? { json: definition.json } : {}),
        ...(definition.request !== undefined ? { request: definition.request } : {}),
        secret_patterns: [...definition.secret_patterns],
        ...(fingerprintKey !== undefined ? { fingerprint_key: fingerprintKey } : {}),
      });
    }
    case "custom_http": {
      const bearer = optionalSecret(context, definition.secret_ref);
      return CustomHttpDetector.new({
        id,
        endpoint: definition.endpoint,
        timeoutMs: definition.timeout_ms,
        maxConcurrency: definition.max_concurrency,
        circuitFailureThreshold: definition.circuit_failure_threshold,
        circuitCooldownMs: definition.circuit_cooldown_ms,
        maxRetries: definition.max_retries,
        maxPayloadBytes: definition.max_payload_bytes,
        maxResponseBytes: definition.max_response_bytes,
        allowPrivateNetwork: definition.allow_private_network,
        supportedSources,
        ...(bearer !== undefined ? { bearerToken: bearer } : {}),
      });
    }
    case "presidio": {
      const bearer = optionalSecret(context, definition.secret_ref);
      return PresidioDetector.new({
        id,
        endpoint: definition.endpoint,
        language: definition.language,
        scoreThresholdPercent: definition.score_threshold_percent,
        ...(definition.entities !== null && definition.entities !== undefined
          ? { entities: [...definition.entities] }
          : {}),
        timeoutMs: definition.timeout_ms,
        maxPayloadBytes: definition.max_payload_bytes,
        maxResponseBytes: definition.max_response_bytes,
        allowPrivateNetwork: definition.allow_private_network,
        supportedSources,
        ...(bearer !== undefined ? { bearerToken: bearer } : {}),
        fingerprintKey: requireSecret(
          context,
          definition.fingerprint_secret_ref,
          "presidio fingerprint",
        ),
      });
    }
    case "llm_guard_prompt_injection": {
      const bearer = optionalSecret(context, definition.secret_ref);
      return LlmGuardPromptInjectionDetector.new({
        id,
        endpoint: definition.endpoint,
        scoreThresholdPercent: definition.score_threshold_percent,
        timeoutMs: definition.timeout_ms,
        maxPayloadBytes: definition.max_payload_bytes,
        maxResponseBytes: definition.max_response_bytes,
        allowPrivateNetwork: definition.allow_private_network,
        supportedSources,
        ...(bearer !== undefined ? { bearerToken: bearer } : {}),
        fingerprintKey: requireSecret(
          context,
          definition.fingerprint_secret_ref,
          "llm_guard fingerprint",
        ),
      });
    }
    case "pii": {
      // Deliberately NOT the graceful-disable posture below. A PII detector the
      // host cannot fully satisfy still answers `pass`, which reads as
      // "screened and clean" — so the unsatisfiable parts raise instead. The
      // translation itself lives in the package so this site and `binding.ts`
      // cannot drift on that decision.
      return PiiDetector.new(
        piiDetectorConfig(
          id,
          definition,
          supportedSources,
          requireSecret(context, definition.fingerprint_secret_ref, "pii fingerprint"),
          {
            vault: context.piiVault,
            workersAi:
              context.workersAiClient ??
              (context.workersAi !== undefined
                ? workersAiBindingClient(context.workersAi)
                : undefined),
          },
          (message) => new DetectorBuildError(message),
        ),
      );
    }
    case "injection": {
      // Same "raise, never degrade" rule as `pii`: a policy that asks for the
      // Workers AI stage and silently runs without it still answers `pass` on a
      // paraphrased attack, which reads as "screened and clean".
      return InjectionDetector.new(
        injectionDetectorConfig(
          id,
          definition,
          supportedSources,
          requireSecret(context, definition.fingerprint_secret_ref, "injection fingerprint"),
          {
            workersAi:
              context.workersAiClient ??
              (context.workersAi !== undefined
                ? workersAiBindingClient(context.workersAi)
                : undefined),
          },
          (message) => new DetectorBuildError(message),
        ),
      );
    }
    case "workers_ai_llama_guard": {
      const client =
        context.workersAiClient ??
        (context.workersAi !== undefined ? workersAiBindingClient(context.workersAi) : undefined);
      if (client === undefined) {
        // Graceful disable, exactly as the Rust adapter was only constructible
        // with a `[cloudflare]` block. NOT a silent pass: `compilePolicyChecks`
        // marks the check disabled, and a policy whose only enabled check for a
        // stage disappears simply stops selecting that stage.
        return undefined;
      }
      return WorkersAiLlamaGuardDetector.withWorkersAi(
        {
          id,
          model: definition.model,
          ...(definition.categories !== null && definition.categories !== undefined
            ? { categories: [...definition.categories] }
            : {}),
          timeoutMs: definition.timeout_ms,
          maxPayloadBytes: definition.max_payload_bytes,
          supportedSources,
          fingerprintKey: requireSecret(
            context,
            definition.fingerprint_secret_ref,
            "workers_ai_llama_guard fingerprint",
          ),
        },
        client,
      );
    }
  }
}

/**
 * Compile every check of a revision.
 *
 * A `fallback_detector` must be Local (the package validates that); it is what
 * `provider_on_error = fallback_detector` wires up
 * (`crates/ferrogate-gateway/src/state.rs:6327-6330`).
 */
export function compilePolicyChecks(
  revision: PolicyRevision,
  context: DetectorBuildContext = {},
): readonly GuardrailCheckRuntime[] {
  const compiled: GuardrailCheckRuntime[] = [];
  for (const check of revision.checks) {
    const override = context.detectorOverrides?.[check.id];
    const detector = override ?? buildDetector(check.id, check.detector, check.sources, context);
    if (detector === undefined) {
      compiled.push({
        id: check.id,
        enabled: false,
        stage: check.stage,
        sources: [...check.sources],
        detector: disabledDetector(check.id),
        detectorId: detectorIdFor(check.detector),
        detectorConfigDigest: detectorConfigDigest(check.detector),
      });
      continue;
    }
    const fallbackKey = `${check.id}#fallback`;
    const fallback =
      context.detectorOverrides?.[fallbackKey] ??
      (check.fallback_detector !== undefined
        ? buildDetector(fallbackKey, check.fallback_detector, check.sources, context)
        : undefined);
    compiled.push({
      id: check.id,
      enabled: check.enabled,
      stage: check.stage,
      sources: [...check.sources],
      detector,
      ...(fallback !== undefined ? { fallbackDetector: fallback } : {}),
      detectorId: detectorIdFor(check.detector),
      detectorConfigDigest: detectorConfigDigest(check.detector),
    });
  }
  return compiled;
}

/** Placeholder so a disabled check still has a shape; it is never evaluated. */
function disabledDetector(checkId: string): GuardrailDetector {
  return {
    descriptor: () => ({
      id: `${checkId}:disabled`,
      version: "disabled",
      supports_request: false,
      supports_response: false,
      supports_transform: false,
      supported_sources: [],
      credential: "none",
      data_residency: "in_repo",
      max_payload_bytes: 0,
      declared_failure_modes: [],
    }),
    health: () => ({
      circuit_open: false,
      consecutive_failures: 0,
      in_flight: 0,
      request_total: 0,
      success_total: 0,
      failure_total: 0,
    }),
    evaluate: () =>
      Promise.reject(
        new Error("disabled guardrail check must never be evaluated (compile-time invariant)"),
      ),
  };
}

/**
 * A `SecretResolver` over Worker bindings.
 *
 * Refs are matched in the shapes `ferrogate-secrets` accepts: `env://NAME` and
 * a bare `NAME`. `vault://` has no Workers analogue and `cf://` is deploy-time
 * only — both must be projected onto a binding name at deploy, which is why
 * they resolve to `undefined` here (a hard build error, never a silent unkeyed
 * fingerprint).
 */
export function secretsFromEnv(env: Record<string, unknown>): SecretResolver {
  return (ref) => {
    const name = ref.startsWith("env://") ? ref.slice("env://".length) : ref;
    const value = env[name];
    return typeof value === "string" && value.length > 0 ? value : undefined;
  };
}
