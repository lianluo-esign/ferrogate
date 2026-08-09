/**
 * Native adapter transport seam + shared helpers — port of
 * `ferrogate-guardrails::adapters` (mod.rs).
 *
 * `DetectorTransport` is the single seam between an adapter and the network:
 * production uses {@link HttpJsonTransport} (`fetch`, bounded response, optional
 * bearer, endpoint SSRF validation); tests use `FixtureTransport`.
 */

import { TIMED_OUT, withTimeout } from "../async.js";
import { byteLen } from "../bytes.js";
import {
  DetectorError,
  type DetectorErrorKind,
  type DetectorHealth,
  type DetectorSecret,
} from "../contract.js";
import { classifyFetchError, statusError, validateCustomHttpEndpoint } from "../custom_http.js";
import { hmacSha256, sha256, toHex } from "../hash.js";

/** A raw HTTP reply: status code plus bounded body bytes. */
export interface TransportReply {
  status: number;
  body: Uint8Array;
}

/** POST JSON to the transport's endpoint and return the reply. */
export interface DetectorTransport {
  postJson(body: Uint8Array): Promise<TransportReply>;
}

/** Production transport: bounded `fetch`, no redirects, optional bearer token. */
export class HttpJsonTransport implements DetectorTransport {
  private endpoint: URL;
  private timeoutMs: number;
  private bearerToken: DetectorSecret | undefined;
  private maxResponseBytes: number;

  constructor(
    endpoint: URL,
    timeoutMs: number,
    _allowPrivateNetwork: boolean,
    bearerToken: DetectorSecret | undefined,
    maxResponseBytes: number,
  ) {
    this.endpoint = endpoint;
    this.timeoutMs = timeoutMs;
    this.bearerToken = bearerToken;
    this.maxResponseBytes = maxResponseBytes;
  }

  async postJson(body: Uint8Array): Promise<TransportReply> {
    const controller = new AbortController();
    const headers: Record<string, string> = {
      "content-type": "application/json",
      accept: "application/json",
    };
    if (this.bearerToken) {
      headers.authorization = `Bearer ${this.bearerToken.expose()}`;
    }
    let response: Response;
    try {
      const raced = await withTimeout(
        fetch(this.endpoint.toString(), {
          method: "POST",
          headers,
          body,
          redirect: "error",
          signal: controller.signal,
        }),
        this.timeoutMs,
      );
      if (raced === TIMED_OUT) {
        controller.abort();
        throw DetectorError.new("timeout", "guardrail adapter request timed out");
      }
      response = raced;
    } catch (error) {
      throw classifyFetchError(error);
    }
    const contentLength = response.headers.get("content-length");
    if (contentLength !== null && Number.parseInt(contentLength, 10) > this.maxResponseBytes) {
      throw DetectorError.new(
        "payload_too_large",
        "guardrail adapter response exceeds configured limit",
      );
    }
    const bytes = await this.readBounded(response);
    return { status: response.status, body: bytes };
  }

  private async readBounded(response: Response): Promise<Uint8Array> {
    const reader = response.body?.getReader();
    if (!reader) {
      const buf = new Uint8Array(await response.arrayBuffer());
      if (buf.length > this.maxResponseBytes) {
        throw DetectorError.new(
          "payload_too_large",
          "guardrail adapter response exceeds configured limit",
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
        throw DetectorError.new("unavailable", "guardrail adapter response could not be read");
      }
      if (chunk.done) {
        break;
      }
      if (chunk.value.length > this.maxResponseBytes - total) {
        throw DetectorError.new(
          "payload_too_large",
          "guardrail adapter response exceeds configured limit",
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

  static build(
    endpoint: URL,
    timeoutMs: number,
    allowPrivateNetwork: boolean,
    bearerToken: DetectorSecret | undefined,
    maxResponseBytes: number,
  ): HttpJsonTransport {
    validateCustomHttpEndpoint(endpoint, allowPrivateNetwork);
    return new HttpJsonTransport(
      endpoint,
      timeoutMs,
      allowPrivateNetwork,
      bearerToken,
      maxResponseBytes,
    );
  }
}

/** Map a non-success HTTP status onto the shared detector error taxonomy. */
export function adapterStatusError(status: number): DetectorError {
  if (status < 100 || status > 599) {
    return DetectorError.new(
      "invalid_response",
      "guardrail adapter returned an invalid HTTP status",
    );
  }
  return statusError(status);
}

/** Keyed, non-reversible evidence fingerprint: `hmac-sha256:<hex>`. */
export function hmacEvidenceFingerprint(key: DetectorSecret, value: string): string {
  return `hmac-sha256:${toHex(hmacSha256(key.asBytes(), new TextEncoder().encode(value)))}`;
}

/**
 * Convert a Unicode code-point index (as reported by Python services such as
 * Presidio) to a UTF-8 byte offset in `text`. `undefined` when out of range.
 */
export function charIndexToByteOffset(text: string, charIndex: number): number | undefined {
  let count = 0;
  let byteOffset = 0;
  for (const ch of text) {
    if (count === charIndex) {
      return byteOffset;
    }
    const cp = ch.codePointAt(0) ?? 0;
    byteOffset += cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
    count += 1;
  }
  return charIndex === count ? byteLen(text) : undefined;
}

/** 4-byte (8 hex) digest of an adapter's config, appended to its version. */
export function configDigest(parts: string[]): string {
  const encoder = new TextEncoder();
  const buffers: Uint8Array[] = [];
  let total = 0;
  for (const part of parts) {
    const bytes = encoder.encode(part);
    buffers.push(bytes, new Uint8Array([0]));
    total += bytes.length + 1;
  }
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const buf of buffers) {
    joined.set(buf, offset);
    offset += buf.length;
  }
  return toHex(sha256(joined).subarray(0, 4));
}

/** Success/failure counters shared by native adapters (no circuit breaker). */
export class AdapterCounters {
  private requestTotal = 0;
  private successTotal = 0;
  private failureTotal = 0;

  recordRequest(): void {
    this.requestTotal += 1;
  }

  async recordOutcome<T>(outcome: Promise<T>): Promise<T> {
    try {
      const value = await outcome;
      this.successTotal += 1;
      return value;
    } catch (error) {
      this.failureTotal += 1;
      throw error;
    }
  }

  recordFailureNow(): void {
    this.failureTotal += 1;
  }

  health(): DetectorHealth {
    return {
      circuit_open: false,
      consecutive_failures: 0,
      in_flight: 0,
      request_total: this.requestTotal,
      success_total: this.successTotal,
      failure_total: this.failureTotal,
    };
  }
}

/** Failure modes native adapters may surface (no CircuitOpen, no patch kinds). */
export function nativeAdapterFailureModes(): DetectorErrorKind[] {
  return [
    "timeout",
    "unavailable",
    "invalid_response",
    "overloaded",
    "unauthorized",
    "payload_too_large",
    "invalid_configuration",
    "internal",
  ];
}
