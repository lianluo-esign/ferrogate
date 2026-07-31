/**
 * Cloudflare Workers AI Llama Guard content-moderation adapter — port of
 * `ferrogate-guardrails::adapters::workers_ai_llama_guard` (#422).
 *
 * Projects content to `@cf/meta/llama-guard-*` and turns its `safe`/`unsafe` +
 * hazard-category verdict into a `DetectorResult`. Content-moderation (NOT
 * prompt-injection), detect-only, ProviderSaas. Only constructible with a live
 * `CloudflareClient` (graceful disable when Cloudflare is unconfigured). On a CF
 * error it surfaces a typed `DetectorError` — the policy `on_error` owns
 * fail-open/closed.
 *
 * PORT-TODO(inventory §3.4c / §3.8): the Rust `ferrogate_cloudflare::CloudflareClient`
 * is a shared REST/Workers-AI client. On CF this maps to the native
 * `env.AI.run("@cf/meta/llama-guard-*")` binding. Here we depend on a small
 * {@link CloudflareClient} interface so the app layer can inject either an
 * `env.AI`-backed client or a REST client; the adapter logic (interpret,
 * hazard table, category allow-list, error mapping) is fully ported.
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

/** Minimal shared Cloudflare client seam the adapter needs (see PORT-TODO). */
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

export interface WorkersAiLlamaGuardConfig {
  id: string;
  model: string;
  categories?: string[];
  timeoutMs: number;
  maxPayloadBytes: number;
  supportedSources: ContentSource[];
  fingerprintKey: DetectorSecret;
}

interface RunResult {
  response?: JsonValue | null;
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
  private client: CloudflareClient;
  private path: string;
  private version: string;
  private counters = new AdapterCounters();

  private constructor(
    config: WorkersAiLlamaGuardConfig,
    client: CloudflareClient,
    path: string,
    version: string,
  ) {
    this.config = config;
    this.client = client;
    this.path = path;
    this.version = version;
  }

  static new(config: WorkersAiLlamaGuardConfig, client: CloudflareClient): WorkersAiLlamaGuardDetector {
    validateConfig(config);
    const digest = configDigest([config.model, config.categories ? config.categories.join(",") : ""]);
    const path = `accounts/{account_id}/ai/run/${config.model.trim()}`;
    return new WorkersAiLlamaGuardDetector(
      config,
      client,
      path,
      `${WORKERS_AI_LLAMA_GUARD_VERSION}+cfg.${digest}`,
    );
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
    const body = new TextEncoder().encode(
      JSON.stringify({ messages: [{ role: "user", content: projected }] }),
    );
    const remaining = deadlineMs - Date.now();
    if (remaining <= 0) {
      throw DetectorError.new("timeout", "workers-ai llama-guard detector deadline expired");
    }
    const attemptTimeout = Math.min(remaining, this.config.timeoutMs);
    const call = this.client
      .requestJson<RunResult>("POST", this.path, body, input.tenant.organization_id)
      .catch((error) => {
        throw classifyCloudflareError(error);
      });
    const raced = await withTimeout(call, attemptTimeout);
    if (raced === TIMED_OUT) {
      throw DetectorError.new("timeout", "workers-ai llama-guard detector request timed out");
    }
    const result = raced;

    const response = result.response;
    if (response === undefined || response === null) {
      throw DetectorError.new(
        "invalid_response",
        "workers-ai llama-guard response is missing the model output",
      );
    }
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

/** Map a `CloudflareError` onto the guardrail detector error taxonomy. */
export function classifyCloudflareError(error: unknown): DetectorError {
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
