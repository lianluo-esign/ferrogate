/**
 * The pluggable malware-scan backend for hosted assets — port of the Rust
 * `ferrogate-gateway/src/asset_scan.rs` (issues #179/#261/#366).
 *
 * This closes the HTTP half of the screening PORT-TODO on {@link
 * AssetScreener}. That marker classified the three unported detectors, and this
 * is the one it named as reachable today: *"the HTTP scanner is a plain `fetch`
 * to an operator-configured endpoint and is implementable today"*. Two of the
 * three stay open for the reasons stated there and restated at the bottom of
 * this docstring, so nothing here is a silent substitution for them.
 *
 * ## What is ported, and where it is faithful to the byte
 *
 * | Rust | here |
 * |---|---|
 * | `ScanVerdict` (`Clean` / `Infected` / `Unavailable`) | {@link ScanVerdict} |
 * | `ScannerUnavailablePolicy` | {@link ScannerUnavailablePolicy} |
 * | `resolve_scan_outcome` | {@link resolveScanOutcome} — same three messages |
 * | `parse_http_scan_response` | {@link parseHttpScanResponse} |
 * | `HttpScanner` (reqwest) | {@link HttpContentScanner} (`fetch`) |
 * | `AssetScanConfig::should_defer_scan` | {@link DeferringScreener} |
 * | `AssetScanConfig::from_env` | {@link assetScreenerFromEnv} |
 *
 * `Unavailable` is a first-class verdict in both, and that is the whole point
 * of the port: a scanner that is DOWN must never be indistinguishable from a
 * scanner that answered "clean". The only two admissible answers are refusing
 * the push or admitting it to quarantine, and which one is an operator choice
 * (`ASSET_SCANNER_UNAVAILABLE`), defaulting — as in Rust — to fail-closed.
 *
 * ## The one deliberate departure, stated so it is not mistaken for parity
 *
 * `resolveScanOutcome` REJECTS infected content (`422 asset_scan_rejected`),
 * exactly as the Rust does. {@link BuiltinEicarScreener} — the offline default
 * used when no backend is configured — instead QUARANTINES an EICAR hit, which
 * is the store-but-withhold posture `test/assets/r2.test.ts` pins against the
 * live bucket (a push is 202, the pull is 404). That difference is pre-existing
 * and deliberate on the builtin; it is NOT copied here, because a configured
 * backend's `Infected` is a real detection and the Rust refuses the push.
 *
 * ## Still open, and why (unchanged from the marker on `AssetScreener`)
 *
 *  - **clamd** — a Worker cannot fork/exec, so the in-process `clamscan` has no
 *    analogue. The closest reachable form is an INSTREAM client over
 *    `connect()` from `cloudflare:sockets` against an operator-hosted clamd,
 *    which is a different deployment contract and must be its own slice.
 *  - **minisign** — `crypto.subtle.verify("Ed25519", …)` exists in workerd; the
 *    minisign CONTAINER format and the trusted-key store are what is unwritten.
 *  - **cross-tenant publish approval** — an approval-record store this app has
 *    no table for.
 *
 * ## Gate (1) lives in `content-gate.ts`, NOT here — CLOSED
 *
 * `screen_asset_push` runs THREE gates. This file is gates (2)/(3); gate (1) —
 * the per-`asset_type` content-type allowlist and the `mcp_manifest` **stdio
 * refusal** — is `./content-gate.ts`, and `AssetService` calls it DIRECTLY,
 * ahead of any `AssetScreener`, on both `putAsset` and `commitUpload`.
 *
 * It is deliberately not a screener and must not be folded into one. Everything
 * in THIS file is selected by `assetScreenerFromEnv` and replaceable by an
 * injected double; gate (1) refuses a manifest that would make a CONSUMING
 * agent spawn a local process, and a control of that kind must not be reachable
 * through a configuration seam. `test/assets/content-gate.test.ts` pins that
 * with a screener that admits everything and is never even consulted for a
 * gate-1 refusal.
 */
import type {
  AssetScreener,
  AssetScreeningRejection,
  AssetScreeningRequest,
  AssetScreeningVerdict,
  AssetStreamScreeningRequest,
} from "./ports.js";
import { BuiltinEicarScreener } from "./ports.js";

// ---------------------------------------------------------------------------
// Verdicts and the outcome policy
// ---------------------------------------------------------------------------

/**
 * The raw answer a scanner gives, BEFORE policy is applied — Rust `ScanVerdict`.
 *
 * `unavailable` (the scanner could not be reached, timed out, or answered
 * something unparseable) is deliberately distinct from `clean` so it can never
 * be silently treated as a pass.
 */
export type ScanVerdict =
  | { readonly kind: "clean" }
  | { readonly kind: "infected"; readonly signature: string }
  | { readonly kind: "unavailable"; readonly reason: string };

/**
 * What to do when the scanner itself is unavailable — Rust
 * `ScannerUnavailablePolicy`. Never "allow": the choice is only between
 * refusing the push and admitting it to quarantine (stored, invisible).
 */
export type ScannerUnavailablePolicy = "fail_closed" | "quarantine";

/** The resolved decision — Rust `ScanOutcome`. */
export type ScanOutcome =
  | { readonly kind: "admit" }
  | { readonly kind: "quarantine"; readonly reason: string }
  | { readonly kind: "reject"; readonly reason: string };

/**
 * Fold a {@link ScanVerdict} into a {@link ScanOutcome} under the configured
 * unavailable policy — Rust `resolve_scan_outcome`, including its three message
 * strings verbatim. `infected` ALWAYS rejects (the policy is not consulted);
 * `unavailable` never admits.
 */
export function resolveScanOutcome(
  verdict: ScanVerdict,
  policy: ScannerUnavailablePolicy,
): ScanOutcome {
  switch (verdict.kind) {
    case "clean":
      return { kind: "admit" };
    case "infected":
      return { kind: "reject", reason: `content failed malware scan: ${verdict.signature}` };
    case "unavailable":
      return policy === "fail_closed"
        ? { kind: "reject", reason: `scanner unavailable (fail-closed): ${verdict.reason}` }
        : {
            kind: "quarantine",
            reason: `scanner unavailable, admitted to quarantine: ${verdict.reason}`,
          };
  }
}

/** A pluggable content scanner — Rust `AssetScanner`. */
export interface AssetContentScanner {
  /** Stable identifier for the manifest/audit (`eicar`, `clamav`, `http`). */
  readonly backendName: string;
  scan(content: Uint8Array): Promise<ScanVerdict>;
}

// ---------------------------------------------------------------------------
// The hosted-scanner HTTP backend
// ---------------------------------------------------------------------------

/** Rust `scanner_timeout_secs()` default. */
export const DEFAULT_SCANNER_TIMEOUT_SECONDS = 30;

/**
 * Parse a hosted-scanner JSON body into a verdict — Rust
 * `parse_http_scan_response`. Pure, so it is testable without a network.
 *
 * Anything that is not a recognised verdict is `unavailable`, never `clean`:
 * a scanner that answers `{"verdict":"maybe"}` has not vouched for the bytes.
 */
export function parseHttpScanResponse(body: string): ScanVerdict {
  let value: unknown;
  try {
    value = JSON.parse(body);
  } catch (error) {
    return {
      kind: "unavailable",
      reason: `scanner reply not JSON: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
  const record =
    typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
  const verdict = record.verdict;
  if (verdict === "clean") return { kind: "clean" };
  if (verdict === "infected") {
    const signature = record.signature;
    return {
      kind: "infected",
      signature: typeof signature === "string" ? signature : "unknown-signature",
    };
  }
  return {
    kind: "unavailable",
    reason: `scanner returned unknown verdict "${typeof verdict === "string" ? verdict : "<missing>"}"`,
  };
}

/**
 * Hosted-scanner HTTP adapter — Rust `HttpScanner`: POST the raw bytes as
 * `application/octet-stream` and read a
 * `{"verdict":"clean|infected","signature":"…"}` JSON reply.
 *
 * `reqwest`'s client-level timeout becomes `AbortSignal.timeout`, and every
 * failure mode on the way — transport error, timeout, non-2xx status, unread
 * body — is `unavailable` with the Rust's own wording, never a pass.
 *
 * `globalThis.fetch` is read at CALL time, never captured at construction, so
 * the same interception seam the inference suite uses works here too.
 */
export class HttpContentScanner implements AssetContentScanner {
  readonly backendName = "http";
  readonly #endpoint: string;
  readonly #timeoutMs: number;

  constructor(endpoint: string, timeoutSeconds: number = DEFAULT_SCANNER_TIMEOUT_SECONDS) {
    this.#endpoint = endpoint;
    this.#timeoutMs = timeoutSeconds * 1000;
  }

  async scan(content: Uint8Array): Promise<ScanVerdict> {
    let response: Response;
    try {
      response = await globalThis.fetch(this.#endpoint, {
        method: "POST",
        headers: { "content-type": "application/octet-stream" },
        body: content.buffer.slice(
          content.byteOffset,
          content.byteOffset + content.byteLength,
        ) as ArrayBuffer,
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
    } catch (error) {
      return {
        kind: "unavailable",
        reason: `scanner HTTP error: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
    if (!response.ok) {
      return { kind: "unavailable", reason: `scanner returned status ${response.status}` };
    }
    let body: string;
    try {
      body = await response.text();
    } catch (error) {
      return {
        kind: "unavailable",
        reason: `scanner body error: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
    return parseHttpScanResponse(body);
  }
}

// ---------------------------------------------------------------------------
// Screeners
// ---------------------------------------------------------------------------

/** `422` — Rust `StatusCode::UNPROCESSABLE_ENTITY` on a scan refusal. */
const SCAN_REJECTED_STATUS = 422;
/** Rust `ScreeningRejection { code: "asset_scan_rejected", … }`. */
const SCAN_REJECTED_CODE = "asset_scan_rejected";

/**
 * The {@link AssetScreener} an operator-configured backend produces: run the
 * scanner over the bytes, then apply {@link resolveScanOutcome}.
 *
 * The three outcomes map onto the screening contract the way the Rust maps them
 * onto `ScanState`:
 *
 *  - `admit` ⇒ `visible`
 *  - `quarantine` ⇒ `quarantined` (stored, withheld from every read surface)
 *  - `reject` ⇒ `422 asset_scan_rejected`, and NOTHING is stored — `putAsset`
 *    screens before it writes either the object or the row.
 */
export class ScannerBackedScreener implements AssetScreener {
  readonly #scanner: AssetContentScanner;
  readonly #policy: ScannerUnavailablePolicy;

  constructor(scanner: AssetContentScanner, policy: ScannerUnavailablePolicy = "fail_closed") {
    this.#scanner = scanner;
    this.#policy = policy;
  }

  /** The backend name recorded in the audit/manifest (Rust `backend_name`). */
  get backendName(): string {
    return this.#scanner.backendName;
  }

  async screen(
    request: AssetScreeningRequest,
  ): Promise<AssetScreeningVerdict | AssetScreeningRejection> {
    const verdict = await this.#scanner.scan(request.content);
    const outcome = resolveScanOutcome(verdict, this.#policy);
    if (outcome.kind === "reject") {
      return {
        status: SCAN_REJECTED_STATUS,
        code: SCAN_REJECTED_CODE,
        message: outcome.reason,
      };
    }
    const backend = this.#scanner.backendName;
    if (outcome.kind === "quarantine") {
      return {
        visibility: "quarantined",
        auditDetail: `scan=quarantined backend=${backend} reason=${outcome.reason} signature=absent approval=not_required`,
        manifest: manifestOf(request, backend, "quarantined", outcome.reason),
      };
    }
    return {
      visibility: "visible",
      auditDetail: `scan=clean backend=${backend} signature=absent approval=not_required`,
      manifest: manifestOf(request, backend, "clean"),
    };
  }

  async streamedScreen(request: AssetStreamScreeningRequest): Promise<AssetScreeningVerdict> {
    return streamedPendingScanVerdict(request, this.#scanner.backendName, "scanner_requires_buffering");
  }
}

/**
 * The async-scan threshold — Rust `AssetScanConfig::should_defer_scan`.
 *
 * Content STRICTLY larger than `thresholdBytes` is admitted `pending_scan`
 * instead of being scanned inline: stored, invisible to every read surface, and
 * promotable only through `promoteAssetVisibility` once an out-of-band pass
 * proves it clean. Below the threshold the wrapped screener decides, unchanged.
 *
 * It is a DECORATOR rather than a field on one screener for two reasons. The
 * Rust applies the threshold around whichever backend is configured (it is a
 * property of the config, not of the scanner), and wrapping preserves the
 * wrapped screener's own posture exactly — notably {@link
 * BuiltinEicarScreener}'s quarantine-on-EICAR, which differs from
 * {@link resolveScanOutcome} and must not be rewritten by composing it.
 *
 * This is also what makes `promoteAssetVisibility` REACHABLE in a deployment:
 * before it, no shipped screener ever produced `pending_scan`, so the promotion
 * operation could only be exercised by a test double.
 */
export class DeferringScreener implements AssetScreener {
  readonly #inner: AssetScreener;
  readonly #thresholdBytes: number;
  readonly #backendName: string;

  constructor(inner: AssetScreener, thresholdBytes: number, backendName = "deferred") {
    this.#inner = inner;
    this.#thresholdBytes = thresholdBytes;
    this.#backendName = backendName;
  }

  async screen(
    request: AssetScreeningRequest,
  ): Promise<AssetScreeningVerdict | AssetScreeningRejection> {
    if (request.content.byteLength > this.#thresholdBytes) {
      const reason = `deferred_async_threshold_bytes=${this.#thresholdBytes}`;
      return {
        visibility: "pending_scan",
        auditDetail: `scan=pending_scan backend=${this.#backendName} reason=${reason} signature=absent approval=not_required`,
        manifest: manifestOf(request, this.#backendName, "pending_scan", reason),
      };
    }
    return this.#inner.screen(request);
  }

  async streamedScreen(
    request: AssetStreamScreeningRequest,
  ): Promise<AssetScreeningVerdict | AssetScreeningRejection> {
    if (request.sizeBytes > this.#thresholdBytes) {
      return streamedPendingScanVerdict(
        request,
        this.#backendName,
        `deferred_async_threshold_bytes=${this.#thresholdBytes}`,
      );
    }
    if (this.#inner.streamedScreen !== undefined) {
      return this.#inner.streamedScreen(request);
    }
    return streamedPendingScanVerdict(request, this.#backendName, "scanner_requires_buffering");
  }
}

function streamedPendingScanVerdict(
  request: AssetStreamScreeningRequest,
  backend: string,
  reason: string,
): AssetScreeningVerdict {
  return {
    visibility: "pending_scan",
    auditDetail: `scan=pending_scan backend=${backend} reason=${reason} signature=absent approval=not_required`,
    manifest: {
      scanner: backend,
      outcome: "pending_scan",
      reason,
      sha256: request.contentSha256,
      size_bytes: request.sizeBytes,
      screened_at_unix: request.nowUnix,
    },
  };
}

/** The manifest shape {@link BuiltinEicarScreener} already records, plus the backend. */
function manifestOf(
  request: AssetScreeningRequest,
  backend: string,
  outcome: string,
  reason?: string,
): Record<string, unknown> {
  return {
    scanner: backend,
    outcome,
    ...(reason !== undefined ? { reason } : {}),
    sha256: request.contentSha256,
    size_bytes: request.content.byteLength,
    screened_at_unix: request.nowUnix,
  };
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * Worker vars the scan backend reads — the port of the Rust
 * `FERROGATE_ASSET_SCANNER*` environment table. Every one is optional and the
 * unset deployment keeps the offline builtin, which is the Rust default.
 */
export interface AssetScannerBindings {
  /** `"http"` selects the hosted-scanner backend. Anything else ⇒ builtin. */
  readonly ASSET_SCANNER?: string;
  /** Hosted-scanner URL. REQUIRED by `"http"`; absent ⇒ builtin (Rust falls back). */
  readonly ASSET_SCANNER_ENDPOINT?: string;
  /** Per-scan deadline in seconds. Defaults to 30; a non-positive value is ignored. */
  readonly ASSET_SCANNER_TIMEOUT_SECS?: string;
  /** `"quarantine"` to admit-and-withhold when the scanner is down. Default fail-closed. */
  readonly ASSET_SCANNER_UNAVAILABLE?: string;
  /** Objects strictly larger than this defer to an out-of-band scan. */
  readonly ASSET_SCANNER_ASYNC_THRESHOLD_BYTES?: string;
}

function positiveInteger(raw: unknown): number | undefined {
  if (typeof raw !== "string" || raw.trim() === "") return undefined;
  const parsed = Number(raw.trim());
  return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined;
}

function nonNegativeInteger(raw: unknown): number | undefined {
  if (typeof raw !== "string" || raw.trim() === "") return undefined;
  const parsed = Number(raw.trim());
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : undefined;
}

/**
 * The configured content scanner, or `null` when none is selected — Rust
 * `AssetScanConfig::from_env` + `build_scanner`, minus the clamd arm.
 *
 * `ASSET_SCANNER="http"` with no endpoint yields `null`, exactly as the Rust
 * falls back to the offline default rather than pointing at nothing.
 */
export function contentScannerFromEnv(env: AssetScannerBindings): AssetContentScanner | null {
  if (env.ASSET_SCANNER?.trim() !== "http") return null;
  const endpoint = env.ASSET_SCANNER_ENDPOINT?.trim();
  if (endpoint === undefined || endpoint === "") return null;
  return new HttpContentScanner(
    endpoint,
    positiveInteger(env.ASSET_SCANNER_TIMEOUT_SECS) ?? DEFAULT_SCANNER_TIMEOUT_SECONDS,
  );
}

/** `"quarantine"` ⇒ quarantine; everything else ⇒ fail-closed (the Rust default). */
export function unavailablePolicyFromEnv(env: AssetScannerBindings): ScannerUnavailablePolicy {
  return env.ASSET_SCANNER_UNAVAILABLE?.trim() === "quarantine" ? "quarantine" : "fail_closed";
}

/**
 * The screener a deployment's vars select, or `null` to keep the caller's
 * default ({@link BuiltinEicarScreener}).
 *
 * The two knobs are INDEPENDENT, which is why this cannot be a single `if`:
 * a threshold with no backend still defers large objects (the builtin decides
 * the rest), and a backend with no threshold scans everything inline.
 */
export function assetScreenerFromEnv(
  env: AssetScannerBindings,
  fallback: AssetScreener = new BuiltinEicarScreener(),
): AssetScreener | null {
  const scanner = contentScannerFromEnv(env);
  const threshold = nonNegativeInteger(env.ASSET_SCANNER_ASYNC_THRESHOLD_BYTES);
  if (scanner === null && threshold === undefined) return null;
  const base =
    scanner === null ? fallback : new ScannerBackedScreener(scanner, unavailablePolicyFromEnv(env));
  if (threshold === undefined) return base;
  return new DeferringScreener(base, threshold, scanner?.backendName ?? "builtin-eicar");
}
