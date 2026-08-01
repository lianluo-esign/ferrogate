/**
 * The typed Cloudflare error taxonomy.
 *
 * Ported from `crates/ferrogate-cloudflare/src/error.rs`. Every `client/v4`
 * endpoint answers with `{ success, errors[], result }`, and a non-2xx status
 * and a `success: false` body carry the SAME `errors[]` array of
 * `{ code, message }` pairs. This flattens that, plus the transport/decode
 * failure modes, into one discriminated kind so every consumer classifies
 * failures identically instead of re-deriving the codes — which is precisely
 * what the two hand-rolled partial clients in this tree were each doing.
 *
 * ## The two audited traps (do not "improve" these)
 *
 * Rate-limit detection is `status === 429` ALONE.
 *
 * 1. An earlier Rust version also matched `code === 10013`. That numeral is not
 *    a rate limit in ANY Cloudflare product: in R2 it is `IncompleteBody`
 *    (HTTP 400 — the request body was truncated, which can never succeed on
 *    retry) and in the general `client/v4` namespace it is
 *    `workers.api.error.unknown` (HTTP 500). The collision went live once R2
 *    started routing through the shared mapper, and it made a truncated upload
 *    read as "rate limited" to the operator.
 * 2. R2's real rate-limit code IS `10058`/`TooManyRequests` — but it always
 *    arrives with HTTP 429, so the status already classifies it. Adding a bare
 *    `code === 10058` match would reintroduce the same collision class: in
 *    Cloudflare's Lists / Bulk-Redirect namespace `10058` means "list items
 *    incompatible with list type" (HTTP 400).
 *
 * Cross-namespace audit result: the `9xxx` account/token codes are disjoint
 * from R2's `10001`–`1000_7x` range plus the `100100` `EntityTooLarge` outlier.
 * R2's own auth codes (`10002` Unauthorized/401, `10003` AccessDenied/403,
 * `10035` SignatureDoesNotMatch/403, `10042` NotEntitled/403) need no numeric
 * entries because the `401`/`403` status branch already catches them.
 */

import { requiredGroupNames } from "./scopes.js";

/** A single `{ code, message }` entry from a Cloudflare error envelope. */
export interface CloudflareApiErrorEntry {
  readonly code: number;
  readonly message: string;
}

/**
 * Codes meaning "the token is valid but is missing a required permission
 * group". `9109` is "Unauthorized to access requested resource"; `9103`/`9107`
 * are its siblings. Surfaced as `missing_scope` so `preflight()` can NAME the
 * permission groups an operator must add, rather than failing opaquely at first
 * use in production.
 */
export const MISSING_SCOPE_CODES: readonly number[] = [9103, 9107, 9109];

/**
 * Codes meaning the credential itself is bad (unknown / expired / malformed),
 * as opposed to merely under-scoped.
 */
export const AUTHENTICATION_CODES: readonly number[] = [1000, 9106, 10000];

/** Every failure mode of the shared Cloudflare client. */
export type CloudflareErrorKind =
  /** Static configuration is unusable. Raised before any request is attempted. */
  | "config"
  /** A token *reference* could not be turned into a secret. */
  | "token_resolution"
  /** The request produced no usable response (DNS/TLS/connect/timeout/body). */
  | "transport"
  /** A response body could not be decoded as the expected envelope/result. */
  | "decode"
  /** The credential is valid but lacks a required permission group. */
  | "missing_scope"
  /** The credential is unknown, expired, or malformed. */
  | "unauthorized"
  /** Cloudflare's global API rate limit (~1,200 req / 5 min / user) was hit. */
  | "rate_limited"
  /** A non-2xx / `success:false` response that is not an auth/scope/rate case. */
  | "api"
  /** The retry budget was exhausted on a retryable transport/5xx failure. */
  | "exhausted_retries";

function joinErrors(errors: readonly CloudflareApiErrorEntry[]): string {
  if (errors.length === 0) return "no error detail";
  return errors.map((error) => `[${error.code}] ${error.message}`).join("; ");
}

/**
 * The single error type this package throws.
 *
 * `kind` is the discriminator; the remaining fields are populated per kind.
 * Consumers should switch on `kind` rather than parse `message` — the message
 * shape is preserved from Rust for operator continuity, not as an API.
 */
export class CloudflareError extends Error {
  override readonly name = "CloudflareError";
  readonly kind: CloudflareErrorKind;
  /** The decoded envelope error array; empty for non-API kinds. */
  readonly errors: readonly CloudflareApiErrorEntry[];
  /** The HTTP status, for `api` (and the response that produced any mapped kind). */
  readonly status: number | undefined;
  /** The server's `Retry-After`, in milliseconds, when it sent one. */
  readonly retryAfterMs: number | undefined;
  /** How many transport calls were made, for `rate_limited`/`exhausted_retries`. */
  readonly attempts: number | undefined;
  /** For `missing_scope`: every permission group an operator should grant. */
  readonly requiredPermissionGroups: readonly string[] | undefined;

  private constructor(
    kind: CloudflareErrorKind,
    message: string,
    fields: {
      errors?: readonly CloudflareApiErrorEntry[];
      status?: number;
      retryAfterMs?: number;
      attempts?: number;
      requiredPermissionGroups?: readonly string[];
      cause?: unknown;
    } = {},
  ) {
    super(message, fields.cause === undefined ? undefined : { cause: fields.cause });
    this.kind = kind;
    this.errors = fields.errors ?? [];
    this.status = fields.status;
    this.retryAfterMs = fields.retryAfterMs;
    this.attempts = fields.attempts;
    this.requiredPermissionGroups = fields.requiredPermissionGroups;
  }

  static config(detail: string): CloudflareError {
    return new CloudflareError("config", `cloudflare config error: ${detail}`);
  }

  static tokenResolution(detail: string): CloudflareError {
    return new CloudflareError("token_resolution", `cloudflare token resolution error: ${detail}`);
  }

  static transport(detail: string, cause?: unknown): CloudflareError {
    return new CloudflareError("transport", `cloudflare transport error: ${detail}`, { cause });
  }

  static decode(detail: string): CloudflareError {
    return new CloudflareError("decode", `cloudflare response decode error: ${detail}`);
  }

  static rateLimited(retryAfterMs: number | undefined, attempts: number): CloudflareError {
    const suffix =
      retryAfterMs === undefined ? "" : ` (retry-after ${Math.floor(retryAfterMs / 1000)}s)`;
    return new CloudflareError(
      "rate_limited",
      `cloudflare rate limit hit after ${attempts} attempt(s)${suffix}`,
      { retryAfterMs, attempts },
    );
  }

  static exhaustedRetries(attempts: number, last: CloudflareError): CloudflareError {
    return new CloudflareError(
      "exhausted_retries",
      `cloudflare request failed after ${attempts} attempt(s): ${last.message}`,
      { attempts, cause: last },
    );
  }

  /**
   * Map a fully-received response into a typed error.
   *
   * Precedence: `429` → missing-scope codes → (`401`/`403` **or** auth codes) →
   * generic `api`. See the module docblock for why rate-limit detection is the
   * status alone.
   *
   * This runs AFTER the retry loop has returned, so a mapped error never
   * re-enters it: a `400 + code 10013` response is issued exactly once.
   */
  static fromResponse(
    status: number,
    retryAfterMs: number | undefined,
    errors: readonly CloudflareApiErrorEntry[],
    requiredPermissionGroups?: readonly string[],
  ): CloudflareError {
    if (status === 429) {
      return CloudflareError.rateLimited(retryAfterMs, 0);
    }
    if (errors.some((error) => MISSING_SCOPE_CODES.includes(error.code))) {
      const required = requiredPermissionGroups ?? DEFAULT_REQUIRED_GROUPS();
      return new CloudflareError(
        "missing_scope",
        `cloudflare token is missing a required permission group (${joinErrors(errors)}); ` +
          `grant the token these permission groups: ${required.join(", ")}`,
        { errors, status, requiredPermissionGroups: required },
      );
    }
    if (
      status === 401 ||
      status === 403 ||
      errors.some((error) => AUTHENTICATION_CODES.includes(error.code))
    ) {
      return new CloudflareError(
        "unauthorized",
        `cloudflare authentication failed (${joinErrors(errors)})`,
        { errors, status },
      );
    }
    return new CloudflareError(
      "api",
      `cloudflare API error (HTTP ${status}): ${joinErrors(errors)}`,
      { errors, status },
    );
  }

  /** A rate-limit error re-stamped with the real attempt count from the loop. */
  withAttempts(attempts: number): CloudflareError {
    if (this.kind !== "rate_limited") return this;
    return CloudflareError.rateLimited(this.retryAfterMs, attempts);
  }

  /**
   * Whether the retry loop should retry this error.
   *
   * Only transport failures and rate limits. Notably a `500` mapped through
   * {@link fromResponse} is NOT retryable here — 5xx retrying happens at the
   * STATUS level inside the loop, before mapping, which is the same split the
   * Rust client had.
   */
  get retryable(): boolean {
    return this.kind === "transport" || this.kind === "rate_limited";
  }
}

function DEFAULT_REQUIRED_GROUPS(): readonly string[] {
  return requiredGroupNames();
}
