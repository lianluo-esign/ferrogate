/**
 * The response headers FerroGate's OWN refusals carry (#726).
 *
 * The counterpart to `inference/errors.ts::relayedRateLimitHeaders`, which
 * handles the numbers that come from an upstream. These are the numbers that
 * come from THIS gateway's limiter, and until #726 there were none: the limiter
 * computed `retryAfterSeconds`, `refuse()` stashed it on the `HttpError` behind
 * an option that defaulted to off, and `writeJsonError` never read it — so even
 * with the option ON, nothing was emitted. A caller refused by FerroGate could
 * not tell how long to wait or how big the window was.
 *
 * ## THE NAMES ARE THE CONTRACT
 *
 * `x-ratelimit-remaining-tokens` is not a label, it is a wire format: an SDK
 * that looks for it and finds `x-ratelimit-tokens-remaining` does not warn, it
 * simply stops pacing. So the names are built from one template below and
 * asserted by exact string in the tests, and they are the OpenAI family rather
 * than an invention, because that is the family a client pointed at an
 * OpenAI-compatible endpoint already reads.
 *
 * ## THE VALUES ARE DERIVED, NEVER CONSTANT
 *
 * A hard-coded `Retry-After` is worse than none: every client that respects it
 * wakes at the same instant and the thundering herd is now synchronised. Every
 * number here comes off the window that actually refused —
 * `RateLimitOutcome.limit` / `.remaining` / `.retryAfterSeconds`, all three
 * computed inside the limiter (`window.ts`) at the moment of the denial.
 *
 * The residual synchronisation is inherent and deliberate: callers sharing one
 * fixed window share one reset instant, so they are told the same truthful
 * number. Adding jitter here would make the header LIE — a client that woke
 * early would be refused again, having been told it would not be. Client-side
 * jitter on top of a truthful deadline is the SDK's job, and both official SDKs
 * do it.
 */

/**
 * Which dimension refused. The suffix of every header name below, so the two
 * families cannot drift apart or be pluralised differently.
 */
export type RateLimitDimension = "requests" | "tokens";

/** The state of the window that refused, as the limiter reported it. */
export interface RateLimitDenial {
  readonly dimension: RateLimitDimension;
  /** The window's configured cap — the tenant/project/key value that won the merge. */
  readonly limit: number;
  /** What is left in the window. Zero for RPM; often NOT zero for TPM. */
  readonly remaining: number;
  /** Whole seconds until the window rolls. */
  readonly retryAfterSeconds: number;
}

/** `Retry-After`, in RFC 9110 delta-seconds. */
export const RETRY_AFTER_HEADER = "retry-after" as const;

/** The three `x-ratelimit-*` names for one dimension, in OpenAI's spelling. */
export function rateLimitHeaderNames(dimension: RateLimitDimension): {
  limit: string;
  remaining: string;
  reset: string;
} {
  return {
    limit: `x-ratelimit-limit-${dimension}`,
    remaining: `x-ratelimit-remaining-${dimension}`,
    reset: `x-ratelimit-reset-${dimension}`,
  };
}

/**
 * The header bag for a limiter refusal.
 *
 * Only the dimension that ACTUALLY refused is reported. A TPM denial says
 * nothing about the RPM window (that window did not refuse and its counters
 * were never read on this path), and emitting a guessed pair for it would be
 * inventing a number — the same defect as a constant, one dimension over.
 *
 * `x-ratelimit-reset-*` is emitted in OpenAI's documented duration form
 * (`"7s"`) rather than as a bare integer, because that is what a client written
 * against the OpenAI headers parses. `retry-after` stays a bare integer,
 * because that is what RFC 9110 and both SDKs' backoff readers require. The two
 * carry the SAME number in two spellings on purpose.
 */
export function rateLimitDenialHeaders(denial: RateLimitDenial): Record<string, string> {
  const names = rateLimitHeaderNames(denial.dimension);
  return {
    [RETRY_AFTER_HEADER]: String(denial.retryAfterSeconds),
    [names.limit]: String(denial.limit),
    [names.remaining]: String(denial.remaining),
    [names.reset]: `${denial.retryAfterSeconds}s`,
  };
}
