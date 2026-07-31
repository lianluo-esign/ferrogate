/**
 * Cloudflare Workers AI Llama Guard content-moderation adapter — port of
 * `ferrogate-guardrails::adapters::workers_ai_llama_guard` (#422).
 *
 * Projects content to `@cf/meta/llama-guard-*` and turns its `safe`/`unsafe` +
 * hazard-category verdict into a `DetectorResult`. Content-moderation (NOT
 * prompt-injection), detect-only, ProviderSaas.
 *
 * ## The client seam (was: "blocked on ferrogate_cloudflare")
 *
 * The Rust adapter held an `Arc<ferrogate_cloudflare::CloudflareClient>` and
 * POSTed `accounts/{account_id}/ai/run/{model}`. Porting that whole REST client
 * is neither necessary nor correct on Workers: inventory-policy-core §3.8 says
 * this adapter "maps directly to Workers AI (`env.AI.run(...)`) — no external
 * client needed". So the seam is defined LOCALLY and narrowly, as the one call
 * the adapter actually makes: {@link WorkersAiClient}.`run(model, input)`.
 *
 *  - On Cloudflare, {@link workersAiBindingClient} satisfies it directly from
 *    the native `env.AI` binding — zero REST, zero token plumbing.
 *  - Off-binding (or for a per-tenant token override, which the binding has no
 *    equivalent for), {@link cloudflareRestWorkersAiClient} satisfies it from
 *    the small {@link CloudflareClient} REST interface, preserving the Rust
 *    path byte-for-byte on the wire.
 *
 * Both funnel into ONE `evaluate` implementation, so the interpretation, hazard
 * table, category allow-list and error mapping are exercised identically
 * whichever transport is wired in.
 *
 * ## Graceful disable
 *
 * The Rust detector "simply cannot exist unless the operator has configured
 * Cloudflare". Same here: a client is a required constructor argument, so the
 * detector cannot be built when Workers AI is unconfigured (no `env.AI` binding
 * and no REST credentials ⇒ nothing to pass).
 *
 * ## Failure posture: FAIL-CLOSED at the adapter
 *
 * Verified against `crates/ferrogate-guardrails/src/adapters/workers_ai_llama_guard.rs`:
 * "On a Cloudflare/Workers-AI error the detector returns a typed `DetectorError`
 * (it does NOT silently pass)". This port matches exactly — an upstream error,
 * an absent `response`, or output that cannot be interpreted all raise a
 * `DetectorError` and NEVER degrade to a `pass` verdict. Choosing whether that
 * error allows or blocks the request is the policy's `on_error`, not the
 * detector's.
 */
import { TIMED_OUT, withTimeout } from "../async.js";
import {
  AdapterCounters,
  configDigest,
  hmacEvidenceFingerprint,
  nativeAdapterFailureModes,
} from "./transport.js";
import {
  DetectorError,
  DetectorSecret,
  MAX_DETECTOR_TIMEOUT_MS,
  type ContentSource,
  type DetectorDescriptor,
  type DetectorErrorKind,
  type DetectorHealth,
  type DetectorInput,
  type DetectorResult,
  type Finding,
} from "../contract.js";
import type { GuardrailDetector } from "../contract.js";
import type { JsonValue } from "@ferrogate/core";

/** A sensible default Llama Guard model slug. */
export const DEFAULT_MODEL = "@cf/meta/llama-guard-3-8b";
const WORKERS_AI_LLAMA_GUARD_VERSION = "workers-ai-llama-guard-adapter/1";

/** The shared-client error taxonomy (mirrors `ferrogate_cloudflare::CloudflareError`). */
export type CloudflareErrorKind =
  | "config"
  | "token_resolution"
  | "transport"
  | "exhausted_retries"
  | "decode"
  | "missing_scope"
  | "unauthorized"
  | "rate_limited"
  | "api";

export class CloudflareError extends Error {
  readonly kind: CloudflareErrorKind;
  constructor(kind: CloudflareErrorKind, message: string) {
    super(message);
    this.name = "CloudflareError";
    this.kind = kind;
  }
}

/**
 * The REST slice of `ferrogate_cloudflare::CloudflareClient` needed to reach
 * Workers AI off-binding. Adapt it to the adapter's seam with
 * {@link cloudflareRestWorkersAiClient}.
 */
export interface CloudflareClient {
  /**
   * POST/GET `path` (with `{account_id}` templated by the client) and decode the
   * already-unwrapped `result` object as `T`. `tenant` selects a per-tenant token
   * override when configured. Rejects with a {@link CloudflareError}.
   */
  requestJson<T>(
    method: "GET" | "POST",
    path: string,
    body: Uint8Array | undefined,
    tenant: string | undefined,
  ): Promise<T>;
}

/**
 * The narrow port seam this adapter is written against: run one Workers AI
 * model with one input, get the (already envelope-unwrapped) result back.
 *
 * `tenant` is the calling organization id, carried only so a REST-backed client
 * can pick a per-tenant token override — the native binding ignores it.
 * Implementations SHOULD reject with a {@link CloudflareError} so the adapter
 * can classify precisely; anything else is treated as a transport failure.
 */
export interface WorkersAiClient {
  run(model: string, input: unknown, tenant?: string): Promise<unknown>;
}

/**
 * The slice of the native Workers AI binding (`env.AI`) this adapter uses.
 * Declared locally so the package stays free of a `@cloudflare/workers-types`
 * dependency; the real binding is structurally assignable to it.
 */
export interface WorkersAiBinding {
  run(model: string, input: unknown, options?: unknown): Promise<unknown>;
}

/**
 * Satisfy {@link WorkersAiClient} from the native `env.AI` binding — the
 * production wiring on Cloudflare.
 */
export function workersAiBindingClient(ai: WorkersAiBinding): WorkersAiClient {
  return {
    async run(model: string, input: unknown): Promise<unknown> {
      return ai.run(model, input);
    },
  };
}

/**
 * Satisfy {@link WorkersAiClient} from the REST {@link CloudflareClient}, on the
 * exact path and body the Rust used (`accounts/{account_id}/ai/run/{model}`,
 * `{ messages: [...] }`), for deployments that are not on the binding.
 */
export function cloudflareRestWorkersAiClient(client: CloudflareClient): WorkersAiClient {
  return {
    async run(model: string, input: unknown, tenant?: string): Promise<unknown> {
      const body = new TextEncoder().encode(JSON.stringify(input));
      return client.requestJson<unknown>(
        "POST",
        `accounts/{account_id}/ai/run/${model}`,
        body,
        tenant,
      );
    },
  };
}

export interface WorkersAiLlamaGuardConfig {
  id: string;
  model: string;
  categories?: string[];
  timeoutMs: number;
  maxPayloadBytes: number;
  supportedSources: ContentSource[];
  fingerprintKey: DetectorSecret;
}

/**
 * The Workers AI `/ai/run` request contract for Llama Guard (Rust `wire`
 * module): a chat-style `messages` array. Isolated so a vendor contract drift
 * is a one-place fix.
 */
interface RunRequest {
  messages: { role: string; content: string }[];
}

/**
 * Pull the model output out of a Workers AI result (the Rust `wire::RunResult`,
 * with the `{ success, errors, result }` envelope already stripped by the
 * client or absent on the binding).
 *
 * Anything that is not an object carrying a usable `response` is an
 * `invalid_response` DetectorError — never a silent pass.
 */
function extractRunResponse(raw: unknown): JsonValue {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw DetectorError.new(
      "invalid_response",
      "workers-ai llama-guard response is missing the model output",
    );
  }
  const response = (raw as { response?: unknown }).response;
  if (response === undefined || response === null) {
    throw DetectorError.new(
      "invalid_response",
      "workers-ai llama-guard response is missing the model output",
    );
  }
  return response as JsonValue;
}

function validateConfig(config: WorkersAiLlamaGuardConfig): void {
  const model = config.model.trim();
  if (
    config.id.trim().length === 0 ||
    model.length === 0 ||
    !model.startsWith("@cf/meta/llama-guard") ||
    config.timeoutMs === 0 ||
    config.timeoutMs > MAX_DETECTOR_TIMEOUT_MS ||
    config.maxPayloadBytes === 0 ||
    config.supportedSources.length === 0 ||
    new Set(config.supportedSources).size !== config.supportedSources.length
  ) {
    throw DetectorError.new(
      "invalid_configuration",
      "workers-ai llama-guard detector id, model, timeout, limits, or sources are invalid",
    );
  }
  if (config.categories !== undefined) {
    const normalized = config.categories.map((c) => normalizeHazardCode(c));
    if (
      config.categories.length === 0 ||
      normalized.some((c) => c === undefined) ||
      new Set(normalized).size !== normalized.length
    ) {
      throw DetectorError.new(
        "invalid_configuration",
        "workers-ai llama-guard categories must be unique valid S-codes (S1..S14) when set",
      );
    }
  }
}

export class WorkersAiLlamaGuardDetector implements GuardrailDetector {
  private config: WorkersAiLlamaGuardConfig;
  private client: WorkersAiClient;
  private model: string;
  private version: string;
  private counters = new AdapterCounters();

  private constructor(
    config: WorkersAiLlamaGuardConfig,
    client: WorkersAiClient,
    model: string,
    version: string,
  ) {
    this.config = config;
    this.client = client;
    this.model = model;
    this.version = version;
  }

  /**
   * Build against the {@link WorkersAiClient} seam — the native `env.AI`
   * binding via {@link workersAiBindingClient}, or any fake in tests.
   */
  static withWorkersAi(
    config: WorkersAiLlamaGuardConfig,
    client: WorkersAiClient,
  ): WorkersAiLlamaGuardDetector {
    validateConfig(config);
    const digest = configDigest([config.model, config.categories ? config.categories.join(",") : ""]);
    return new WorkersAiLlamaGuardDetector(
      config,
      client,
      config.model.trim(),
      `${WORKERS_AI_LLAMA_GUARD_VERSION}+cfg.${digest}`,
    );
  }

  /** Build against the REST {@link CloudflareClient}, as the Rust constructor did. */
  static new(config: WorkersAiLlamaGuardConfig, client: CloudflareClient): WorkersAiLlamaGuardDetector {
    return WorkersAiLlamaGuardDetector.withWorkersAi(config, cloudflareRestWorkersAiClient(client));
  }

  private passResult(): DetectorResult {
    return { verdict: "pass", findings: [], patches: [], detector_version: this.version };
  }

  descriptor(): DetectorDescriptor {
    return {
      id: this.config.id,
      version: this.version,
      supports_request: true,
      supports_response: true,
      supports_transform: false,
      supported_sources: [...this.config.supportedSources],
      credential: "bearer_token",
      data_residency: "provider_saas",
      max_payload_bytes: this.config.maxPayloadBytes,
      declared_failure_modes: nativeAdapterFailureModes(),
    };
  }

  health(): DetectorHealth {
    return this.counters.health();
  }

  private finding(hazardCode: string | undefined, fingerprint: string): Finding {
    const attributes: Record<string, JsonValue> = {
      provider: "workers_ai_llama_guard",
      model: this.config.model,
    };
    let category: string;
    const code = hazardCode !== undefined ? normalizeHazardCode(hazardCode) : undefined;
    if (code !== undefined) {
      attributes["hazard_code"] = code;
      attributes["hazard_name"] = hazardName(code);
      category = `content_moderation.llama_guard.${code.toLowerCase()}`;
    } else {
      category = "content_moderation.llama_guard.unsafe";
    }
    return {
      category,
      severity: "high",
      confidence: null,
      byte_start: null,
      byte_end: null,
      segment_id: null,
      fingerprint,
      matched_text: null,
      attributes,
    };
  }

  private async evaluateInner(input: DetectorInput, deadlineMs: number): Promise<DetectorResult> {
    const projected = input.segments
      .filter((s) => this.config.supportedSources.includes(s.source))
      .map((s) => s.text)
      .join("\n");
    if (new TextEncoder().encode(projected).length > this.config.maxPayloadBytes) {
      throw DetectorError.new(
        "payload_too_large",
        "workers-ai llama-guard detector request exceeds configured limit",
      );
    }
    if (projected.length === 0) {
      return this.passResult();
    }
    const runInput: RunRequest = { messages: [{ role: "user", content: projected }] };
    const remaining = deadlineMs - Date.now();
    if (remaining <= 0) {
      throw DetectorError.new("timeout", "workers-ai llama-guard detector deadline expired");
    }
    const attemptTimeout = Math.min(remaining, this.config.timeoutMs);
    // FAIL-CLOSED: any upstream rejection becomes a typed DetectorError; there
    // is no path from here to a `pass` verdict (see the module doc).
    const call = Promise.resolve()
      .then(() => this.client.run(this.model, runInput, input.tenant.organization_id))
      .catch((error: unknown) => {
        throw classifyCloudflareError(error);
      });
    const raced = await withTimeout(call, attemptTimeout);
    if (raced === TIMED_OUT) {
      throw DetectorError.new("timeout", "workers-ai llama-guard detector request timed out");
    }

    const response = extractRunResponse(raced);
    const verdict = interpretResponse(response);
    if (verdict === undefined) {
      throw DetectorError.new(
        "invalid_response",
        "workers-ai llama-guard response could not be interpreted",
      );
    }
    if (!verdict.isUnsafe) {
      return this.passResult();
    }

    let flagged: string[];
    if (this.config.categories) {
      const allow = new Set(this.config.categories.map((c) => normalizeHazardCode(c)));
      const retained = verdict.categories.filter((c) => allow.has(normalizeHazardCode(c)));
      if (retained.length === 0 && verdict.categories.length > 0) {
        return this.passResult();
      }
      flagged = retained;
    } else {
      flagged = [...verdict.categories];
    }

    const fingerprint = hmacEvidenceFingerprint(this.config.fingerprintKey, projected);
    const findings =
      flagged.length === 0
        ? [this.finding(undefined, fingerprint)]
        : flagged.map((code) => this.finding(code, fingerprint));

    return { verdict: "fail", findings, patches: [], detector_version: this.version };
  }

  async evaluate(input: DetectorInput, deadlineMs: number): Promise<DetectorResult> {
    this.counters.recordRequest();
    if (Date.now() >= deadlineMs) {
      this.counters.recordFailureNow();
      throw DetectorError.new(
        "timeout",
        "workers-ai llama-guard detector deadline expired before execution",
      );
    }
    return this.counters.recordOutcome(this.evaluateInner(input, deadlineMs));
  }
}

/** The interpreted Llama Guard verdict: overall safety + flagged S-codes. */
export interface LlamaGuardVerdict {
  isUnsafe: boolean;
  categories: string[];
}

/** Interpret the model `response` value into a verdict (string / bool / object). */
export function interpretResponse(value: JsonValue): LlamaGuardVerdict | undefined {
  if (typeof value === "string") {
    return interpretText(value);
  }
  if (typeof value === "boolean") {
    return { isUnsafe: !value, categories: [] };
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return interpretObject(value as Record<string, JsonValue>);
  }
  return undefined;
}

function interpretText(text: string): LlamaGuardVerdict {
  const tokens = text
    .trim()
    .split(/[\s,]+/)
    .filter((t) => t.length > 0);
  const first = tokens[0] ?? "";
  const isUnsafe = first.toLowerCase() === "unsafe";
  const categories: string[] = [];
  if (isUnsafe) {
    for (const token of tokens.slice(1)) {
      const code = normalizeHazardCode(token);
      if (code !== undefined && !categories.includes(code)) {
        categories.push(code);
      }
    }
  }
  return { isUnsafe, categories };
}

function interpretObject(map: Record<string, JsonValue>): LlamaGuardVerdict | undefined {
  if (typeof map["safe"] === "boolean") {
    const rawCategories = map["categories"];
    const categories = Array.isArray(rawCategories)
      ? dedup(
          rawCategories
            .filter((c): c is string => typeof c === "string")
            .map((c) => normalizeHazardCode(c))
            .filter((c): c is string => c !== undefined),
        )
      : [];
    return { isUnsafe: !map["safe"], categories };
  }

  const categories: string[] = [];
  let recognized = false;
  for (const [key, value] of Object.entries(map)) {
    const code = normalizeHazardCode(key);
    if (code === undefined) {
      continue;
    }
    recognized = true;
    let categorySafe = true;
    if (typeof value === "boolean") {
      categorySafe = value;
    } else if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      const inner = (value as Record<string, JsonValue>)["safe"];
      categorySafe = typeof inner === "boolean" ? inner : true;
    }
    if (!categorySafe) {
      categories.push(code);
    }
  }
  if (!recognized) {
    return undefined;
  }
  const deduped = dedup(categories);
  return { isUnsafe: deduped.length > 0, categories: deduped };
}

function dedup(codes: string[]): string[] {
  const seen = new Set<string>();
  return codes.filter((c) => (seen.has(c) ? false : (seen.add(c), true)));
}

/** Normalize a hazard token to a canonical `S<n>` (1..=14), or `undefined`. */
export function normalizeHazardCode(token: string): string | undefined {
  const trimmed = token.trim();
  const rest = trimmed.startsWith("s") || trimmed.startsWith("S") ? trimmed.slice(1) : undefined;
  if (rest === undefined || !/^\d+$/.test(rest)) {
    return undefined;
  }
  const n = Number.parseInt(rest, 10);
  return n >= 1 && n <= 14 ? `S${n}` : undefined;
}

/** Best-effort HTTP status carried by a Workers AI binding rejection. */
function upstreamStatus(error: unknown): number | undefined {
  if (error === null || typeof error !== "object") {
    return undefined;
  }
  const bag = error as { status?: unknown; statusCode?: unknown };
  for (const value of [bag.status, bag.statusCode]) {
    if (typeof value === "number" && Number.isInteger(value)) {
      return value;
    }
  }
  return undefined;
}

/** Human-readable name for an MLCommons/Llama-Guard-3 hazard S-code. */
export function hazardName(code: string): string {
  const table: Record<string, string> = {
    S1: "Violent Crimes",
    S2: "Non-Violent Crimes",
    S3: "Sex-Related Crimes",
    S4: "Child Sexual Exploitation",
    S5: "Defamation",
    S6: "Specialized Advice",
    S7: "Privacy",
    S8: "Intellectual Property",
    S9: "Indiscriminate Weapons",
    S10: "Hate",
    S11: "Suicide & Self-Harm",
    S12: "Sexual Content",
    S13: "Elections",
    S14: "Code Interpreter Abuse",
  };
  return table[code] ?? "Unknown Hazard Category";
}

/**
 * Map an upstream failure onto the guardrail detector error taxonomy.
 *
 * Handles the three shapes the seam can produce: a {@link CloudflareError} from
 * a REST client (the Rust taxonomy, mapped 1:1), a `DetectorError` a client
 * already classified, and the native binding's `InferenceUpstreamError`-style
 * rejection, which carries an HTTP `status`/`statusCode` and no kind.
 *
 * Every branch yields a `DetectorError`. There is no branch that yields a pass:
 * the adapter is fail-closed and the policy `on_error` decides the rest.
 */
export function classifyCloudflareError(error: unknown): DetectorError {
  if (error instanceof DetectorError) {
    return error;
  }
  if (!(error instanceof CloudflareError)) {
    const status = upstreamStatus(error);
    if (status === 401 || status === 403) {
      return DetectorError.new(
        "unauthorized",
        "workers-ai llama-guard token is invalid or missing the Workers AI scope",
      );
    }
    if (status === 429) {
      return DetectorError.new("overloaded", "workers-ai llama-guard is rate limited");
    }
  }
  const kind = error instanceof CloudflareError ? error.kind : "transport";
  let mapped: DetectorErrorKind;
  let message: string;
  switch (kind) {
    case "config":
    case "token_resolution":
      mapped = "invalid_configuration";
      message = "workers-ai llama-guard client is misconfigured";
      break;
    case "transport":
    case "exhausted_retries":
      mapped = "unavailable";
      message = "workers-ai llama-guard endpoint is unavailable";
      break;
    case "decode":
      mapped = "invalid_response";
      message = "workers-ai llama-guard returned an undecodable response";
      break;
    case "missing_scope":
    case "unauthorized":
      mapped = "unauthorized";
      message = "workers-ai llama-guard token is invalid or missing the Workers AI scope";
      break;
    case "rate_limited":
      mapped = "overloaded";
      message = "workers-ai llama-guard is rate limited";
      break;
    case "api":
      mapped = "unavailable";
      message = "workers-ai llama-guard returned an API error";
      break;
  }
  return DetectorError.new(mapped, message);
}
