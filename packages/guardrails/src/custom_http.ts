/**
 * Built-in `custom_http` detector runtime — port of
 * `ferrogate-guardrails::custom_http`.
 *
 * Bounded HTTP execution with deadlines, a semaphore bulkhead, circuit state,
 * retries (capped at 1), response-size limits, and detector-result validation.
 * Uses `fetch()` in place of reqwest; SSRF DNS filtering is replaced by endpoint
 * host/IP-literal validation (see `./net` PORT-TODO). Deadlines are epoch-millis.
 */
import { z } from "zod";
import { Semaphore, TIMED_OUT, withTimeout } from "./async.js";
import { byteLen, encodeUtf8, isCharBoundary } from "./bytes.js";
import {
  CONTRACT_VERSION,
  type ContentSegment,
  type ContentSource,
  type DetectorDescriptor,
  DetectorError,
  type DetectorErrorKind,
  type DetectorHealth,
  type DetectorInput,
  type DetectorResult,
  type DetectorSecret,
  type Finding,
  type GuardrailDetector,
  MAX_DETECTOR_TIMEOUT_MS,
  contentPatchSchema,
  findingSchema,
} from "./contract.js";
import { validateContentPatchesForSegments } from "./envelope.js";
import { detectorEndpointRejection } from "./net.js";

export interface CustomHttpDetectorConfig {
  id: string;
  endpoint: string;
  timeoutMs: number;
  maxConcurrency: number;
  circuitFailureThreshold: number;
  circuitCooldownMs: number;
  maxRetries: number;
  maxPayloadBytes: number;
  maxResponseBytes: number;
  allowPrivateNetwork: boolean;
  supportedSources: ContentSource[];
  bearerToken?: DetectorSecret;
}

interface CircuitState {
  consecutiveFailures: number;
  openedAt: number | undefined;
  halfOpenProbe: boolean;
}

const detectorWireResponseSchema = z
  .object({
    verdict: z.enum(["pass", "fail"]).optional(),
    match: z.boolean().optional(),
    matched_text: z.string().optional(),
    category: z.string().optional(),
    findings: z.array(findingSchema).default([]),
    patches: z.array(contentPatchSchema).default([]),
    detector_version: z.string().optional(),
  })
  .passthrough();

export class CustomHttpDetector implements GuardrailDetector {
  private config: CustomHttpDetectorConfig;
  private endpoint: URL;
  private permits: Semaphore;
  private circuit: CircuitState = {
    consecutiveFailures: 0,
    openedAt: undefined,
    halfOpenProbe: false,
  };
  private requestTotal = 0;
  private successTotal = 0;
  private failureTotal = 0;

  private constructor(config: CustomHttpDetectorConfig, endpoint: URL) {
    this.config = config;
    this.endpoint = endpoint;
    this.permits = new Semaphore(config.maxConcurrency);
  }

  static new(config: CustomHttpDetectorConfig): CustomHttpDetector {
    validateConfig(config);
    let endpoint: URL;
    try {
      endpoint = new URL(config.endpoint);
    } catch {
      throw DetectorError.new(
        "invalid_configuration",
        "guardrail detector endpoint is not a valid URL",
      );
    }
    validateCustomHttpEndpoint(endpoint, config.allowPrivateNetwork);
    return new CustomHttpDetector(config, endpoint);
  }

  descriptor(): DetectorDescriptor {
    return {
      id: this.config.id,
      version: "custom-http/1",
      supports_request: true,
      supports_response: true,
      supports_transform: true,
      supported_sources: [...this.config.supportedSources],
      credential: this.config.bearerToken ? "bearer_token" : "none",
      data_residency: "provider_saas",
      max_payload_bytes: this.config.maxPayloadBytes,
      declared_failure_modes: [
        "timeout",
        "unavailable",
        "invalid_response",
        "overloaded",
        "unauthorized",
        "payload_too_large",
        "circuit_open",
        "invalid_configuration",
        "invalid_patch",
        "stale_patch",
        "internal",
      ],
    };
  }

  health(): DetectorHealth {
    return {
      circuit_open: this.circuit.openedAt !== undefined,
      consecutive_failures: this.circuit.consecutiveFailures,
      in_flight: this.permits.inFlight(),
      request_total: this.requestTotal,
      success_total: this.successTotal,
      failure_total: this.failureTotal,
    };
  }

  private enterCircuit(now: number): void {
    const state = this.circuit;
    if (state.openedAt === undefined) {
      return;
    }
    if (now - state.openedAt < this.config.circuitCooldownMs || state.halfOpenProbe) {
      throw DetectorError.new("circuit_open", "guardrail detector circuit is open");
    }
    state.halfOpenProbe = true;
  }

  private recordSuccess(): void {
    this.successTotal += 1;
    this.circuit.consecutiveFailures = 0;
    this.circuit.openedAt = undefined;
    this.circuit.halfOpenProbe = false;
  }

  private recordFailure(error: DetectorError, now: number): void {
    this.failureTotal += 1;
    if (!error.affectsCircuit()) {
      this.circuit.halfOpenProbe = false;
      return;
    }
    this.circuit.consecutiveFailures += 1;
    this.circuit.halfOpenProbe = false;
    if (this.circuit.consecutiveFailures >= this.config.circuitFailureThreshold) {
      this.circuit.openedAt = now;
    }
  }

  private async sendOnce(
    requestBody: Uint8Array,
    attemptTimeoutMs: number,
  ): Promise<DetectorResult> {
    const controller = new AbortController();
    const headers: Record<string, string> = {
      "content-type": "application/json",
      accept: "application/json",
    };
    if (this.config.bearerToken) {
      headers.authorization = `Bearer ${this.config.bearerToken.expose()}`;
    }
    let response: Response;
    try {
      const fetchPromise = fetch(this.endpoint.toString(), {
        method: "POST",
        headers,
        body: requestBody,
        redirect: "error",
        signal: controller.signal,
      });
      const raced = await withTimeout(fetchPromise, attemptTimeoutMs);
      if (raced === TIMED_OUT) {
        controller.abort();
        throw DetectorError.new("timeout", "guardrail detector request timed out");
      }
      response = raced;
    } catch (error) {
      if (error instanceof DetectorError) {
        throw error;
      }
      throw classifyFetchError(error);
    }
    if (!response.ok) {
      throw statusError(response.status);
    }
    const contentLength = response.headers.get("content-length");
    if (
      contentLength !== null &&
      Number.parseInt(contentLength, 10) > this.config.maxResponseBytes
    ) {
      throw DetectorError.new(
        "payload_too_large",
        "guardrail detector response exceeds configured limit",
      );
    }
    const bytes = await this.readBounded(response);
    return parseDetectorResponse(bytes);
  }

  private async readBounded(response: Response): Promise<Uint8Array> {
    const reader = response.body?.getReader();
    if (!reader) {
      const buf = new Uint8Array(await response.arrayBuffer());
      if (buf.length > this.config.maxResponseBytes) {
        throw DetectorError.new(
          "payload_too_large",
          "guardrail detector response exceeds configured limit",
        );
      }
      return buf;
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      let chunk: ReadableStreamReadResult<Uint8Array>;
      try {
        chunk = await reader.read();
      } catch {
        throw DetectorError.new("unavailable", "guardrail detector response could not be read");
      }
      if (chunk.done) {
        break;
      }
      const remaining = this.config.maxResponseBytes - total;
      if (chunk.value.length > remaining) {
        throw DetectorError.new(
          "payload_too_large",
          "guardrail detector response exceeds configured limit",
        );
      }
      chunks.push(chunk.value);
      total += chunk.value.length;
    }
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      out.set(chunk, offset);
      offset += chunk.length;
    }
    return out;
  }

  async evaluate(input: DetectorInput, deadlineMs: number): Promise<DetectorResult> {
    this.requestTotal += 1;
    const now = Date.now();
    if (now >= deadlineMs) {
      const error = DetectorError.new(
        "timeout",
        "guardrail detector deadline expired before execution",
      );
      this.recordFailure(error, now);
      throw error;
    }
    try {
      this.enterCircuit(now);
    } catch (error) {
      this.failureTotal += 1;
      throw error;
    }

    const projectedSegments = input.segments.filter((s) =>
      this.config.supportedSources.includes(s.source),
    );
    const projectedText =
      input.segments.length === 0 && this.config.supportedSources.includes("unknown")
        ? input.text
        : projectedSegments.map((s) => s.text).join("\n");
    if (byteLen(projectedText) > this.config.maxPayloadBytes) {
      const error = DetectorError.new(
        "payload_too_large",
        "guardrail detector request exceeds configured limit",
      );
      this.recordFailure(error, Date.now());
      throw error;
    }

    const request = {
      contract_version: CONTRACT_VERSION,
      protocol: input.protocol,
      stage: input.stage,
      tenant: input.tenant,
      model: input.model ?? null,
      provider: input.provider ?? null,
      text: projectedText,
      segments: projectedSegments,
    };
    const requestBody = encodeUtf8(JSON.stringify(request));
    if (requestBody.length > this.config.maxPayloadBytes) {
      const error = DetectorError.new(
        "payload_too_large",
        "guardrail detector request exceeds configured limit",
      );
      this.recordFailure(error, Date.now());
      throw error;
    }

    const permit = await this.permits.acquire(Math.max(0, deadlineMs - Date.now()));
    if (!permit) {
      const error = DetectorError.new(
        "overloaded",
        "guardrail detector concurrency wait exceeded deadline",
      );
      this.recordFailure(error, Date.now());
      throw error;
    }

    let attempt = 0;
    let result: DetectorResult | undefined;
    let failure: DetectorError | undefined;
    try {
      for (;;) {
        const remaining = deadlineMs - Date.now();
        if (remaining <= 0) {
          failure = DetectorError.new("timeout", "guardrail detector deadline expired");
          break;
        }
        const attemptTimeout = Math.min(remaining, this.config.timeoutMs);
        try {
          const candidate = await this.sendOnce(requestBody, attemptTimeout);
          validateDetectorResult(projectedText, projectedSegments, candidate);
          result = candidate;
          break;
        } catch (error) {
          const detectorError = error instanceof DetectorError ? error : classifyFetchError(error);
          if (detectorError.retriable() && attempt < this.config.maxRetries) {
            attempt += 1;
            continue;
          }
          failure = detectorError;
          break;
        }
      }
    } finally {
      permit();
    }

    if (result) {
      this.recordSuccess();
      return result;
    }
    const error = failure ?? DetectorError.new("internal", "guardrail detector produced no result");
    this.recordFailure(error, Date.now());
    throw error;
  }
}

/** Parse a detector wire response (new `verdict` or legacy `match`+`matched_text`). */
export function parseDetectorResponse(bytes: Uint8Array): DetectorResult {
  let json: unknown;
  try {
    json = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw DetectorError.new("invalid_response", "guardrail detector returned invalid JSON");
  }
  const parsed = detectorWireResponseSchema.safeParse(json);
  if (!parsed.success) {
    throw DetectorError.new("invalid_response", "guardrail detector returned invalid JSON");
  }
  const wire = parsed.data;
  let verdict: "pass" | "fail";
  if (wire.verdict !== undefined) {
    verdict = wire.verdict;
  } else if (wire.match === true) {
    verdict = "fail";
  } else if (wire.match === false) {
    verdict = "pass";
  } else {
    throw DetectorError.new("invalid_response", "guardrail detector response is missing verdict");
  }
  if (wire.match === true && wire.matched_text === undefined) {
    throw DetectorError.new(
      "invalid_response",
      "legacy guardrail detector match is missing matched_text",
    );
  }
  const findings: Finding[] = wire.findings as Finding[];
  if (wire.matched_text !== undefined) {
    findings.unshift({
      category: wire.category ?? "custom_http",
      severity: "high",
      confidence: null,
      byte_start: null,
      byte_end: null,
      segment_id: null,
      fingerprint: null,
      matched_text: wire.matched_text,
      attributes: {},
    });
  }
  return {
    verdict,
    findings,
    patches: wire.patches,
    detector_version: wire.detector_version ?? "custom-http/1",
  };
}

/** Validate detector-returned patches + finding byte ranges against segments. */
export function validateDetectorResult(
  text: string,
  segments: ContentSegment[],
  result: DetectorResult,
): void {
  validateContentPatchesForSegments(segments, result.patches);
  for (const finding of result.findings) {
    let coordinateText: string;
    if (finding.segment_id != null) {
      const segment = segments.find((s) => s.segment_id === finding.segment_id);
      if (!segment) {
        throw DetectorError.new(
          "invalid_response",
          "guardrail detector returned a finding for an unknown segment",
        );
      }
      coordinateText = segment.text;
    } else {
      coordinateText = text;
    }
    const start = finding.byte_start;
    const end = finding.byte_end;
    if (start == null && end == null) {
      continue;
    }
    if (
      start == null ||
      end == null ||
      start > end ||
      end > byteLen(coordinateText) ||
      !isCharBoundary(coordinateText, start) ||
      !isCharBoundary(coordinateText, end)
    ) {
      throw DetectorError.new(
        "invalid_response",
        "guardrail detector returned an invalid finding byte range",
      );
    }
  }
}

function validateConfig(config: CustomHttpDetectorConfig): void {
  if (
    config.id.trim().length === 0 ||
    config.maxConcurrency === 0 ||
    config.circuitFailureThreshold === 0 ||
    config.timeoutMs === 0 ||
    config.timeoutMs > MAX_DETECTOR_TIMEOUT_MS ||
    config.circuitCooldownMs === 0 ||
    config.maxPayloadBytes === 0 ||
    config.maxResponseBytes === 0 ||
    config.maxRetries > 1 ||
    config.supportedSources.length === 0 ||
    new Set(config.supportedSources).size !== config.supportedSources.length
  ) {
    throw DetectorError.new(
      "invalid_configuration",
      "guardrail detector limits or source declarations are invalid, timeout exceeds 30 seconds, or retries exceed one",
    );
  }
}

/**
 * Validate a detector endpoint URL: http(s), host, no userinfo/query/fragment,
 * and — unless private networking is explicitly allowed — no `localhost` or
 * denylisted IP literal in any resolver-accepted spelling.
 *
 * The rules live in `./net` (`detectorEndpointRejection`); this function owns
 * only the mapping onto the two ported Rust messages. Accepts a raw string as
 * well as a `URL` so callers that have not parsed yet get the same checks.
 */
export function validateCustomHttpEndpoint(
  endpoint: URL | string,
  allowPrivateNetwork: boolean,
): void {
  const rejection = detectorEndpointRejection(endpoint, allowPrivateNetwork);
  if (rejection === undefined) {
    return;
  }
  if (rejection === "invalid_url") {
    throw DetectorError.new(
      "invalid_configuration",
      "guardrail detector endpoint is not a valid URL",
    );
  }
  if (rejection === "private_network_host") {
    throw DetectorError.new(
      "invalid_configuration",
      "guardrail detector private-network endpoint requires explicit allow_private_network",
    );
  }
  throw DetectorError.new(
    "invalid_configuration",
    "guardrail detector endpoint must be an http(s) URL without credentials, query, or fragment",
  );
}

/** Classify a `fetch` rejection into the detector error taxonomy. */
export function classifyFetchError(error: unknown): DetectorError {
  if (error instanceof DetectorError) {
    return error;
  }
  const name = error instanceof Error ? error.name : "";
  if (name === "AbortError" || name === "TimeoutError") {
    return DetectorError.new("timeout", "guardrail detector request timed out");
  }
  return DetectorError.new("unavailable", "guardrail detector is unavailable");
}

/** Map a non-success HTTP status onto the detector error taxonomy. */
export function statusError(status: number): DetectorError {
  let kind: DetectorErrorKind;
  let message: string;
  if (status === 401 || status === 403) {
    kind = "unauthorized";
    message = "guardrail detector rejected its configured credential";
  } else if (status === 429) {
    kind = "overloaded";
    message = "guardrail detector is rate limited";
  } else if (status >= 500 && status <= 599) {
    kind = "unavailable";
    message = "guardrail detector returned a server error";
  } else {
    kind = "invalid_response";
    message = "guardrail detector returned an unexpected HTTP status";
  }
  return DetectorError.new(kind, message);
}
