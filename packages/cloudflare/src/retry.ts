/**
 * The deterministic Cloudflare retry/backoff schedule — slice **S4**.
 *
 * Ported from `crates/ferrogate-cloudflare/src/client.rs:148-170`
 * (`RetryPolicy`). Cloudflare's global API limit is **~1,200 requests / 5 min /
 * user** (≈4 req/s), so a transient 429 or 502 on an account-management call is
 * expected traffic, not an outage.
 *
 * ## No jitter, on purpose
 *
 * The schedule is deterministic so it is EXACTLY assertable with an injected
 * clock. That is what lets a test distinguish "retried on the documented
 * schedule" from "retried somehow", and it is why `test/retry.test.ts` asserts
 * the millisecond sequence rather than a call count. Adding jitter would be a
 * downgrade in provability, not an improvement; if a thundering herd ever
 * matters here, add jitter as an explicit, separately-tested policy field.
 *
 * ## Retry is opt-IN for non-GET calls
 *
 * The Rust loop retried EVERY method on a 5xx. On Workers that is unsafe for
 * `POST /accounts/{id}/tokens`: a retried mint creates a SECOND credential
 * whose secret Cloudflare returns exactly once and can never be read back. So
 * {@link executeWithRetry} takes an explicit `enabled` flag and
 * `CloudflareClient` defaults it to GET-only. This divergence is deliberate and
 * is recorded in `docs/rewrite/cf-crate-assessment.md` §S4.
 */

/** Retry/backoff policy honouring Cloudflare's global API rate limit. */
export interface RetryPolicy {
  readonly maxRetries: number;
  readonly baseBackoffMs: number;
  readonly maxBackoffMs: number;
}

/** The Rust defaults, verbatim: 4 retries, 1s base, 60s cap. */
export const DEFAULT_RETRY_POLICY: RetryPolicy = {
  maxRetries: 4,
  baseBackoffMs: 1_000,
  maxBackoffMs: 60_000,
};

/**
 * The HTTP statuses worth re-issuing. Note `501` is absent: a blanket "any 5xx"
 * match would retry a Not Implemented forever.
 */
export const RETRYABLE_STATUSES: readonly number[] = [429, 500, 502, 503, 504];

/** Whether a status should be re-issued by {@link executeWithRetry}. */
export function isRetryableStatus(status: number): boolean {
  return RETRYABLE_STATUSES.includes(status);
}

/**
 * The delay before the `attempt`-th retry (0-based).
 *
 * The server's `Retry-After` **wins** when present (itself capped at
 * `maxBackoffMs`); otherwise `baseBackoffMs * 2^attempt`, capped. Arithmetic
 * saturates, so a large attempt count cannot overflow into `Infinity` or a
 * negative sleep.
 */
export function backoffDelayMs(
  policy: RetryPolicy,
  attempt: number,
  retryAfterMs?: number,
): number {
  if (retryAfterMs !== undefined) {
    return Math.min(retryAfterMs, policy.maxBackoffMs);
  }
  // `2 ** attempt` becomes Infinity past ~1024; Math.min collapses that to the
  // cap, and the cap is what every large attempt should yield anyway.
  const exponential = policy.baseBackoffMs * 2 ** attempt;
  return Math.min(
    Number.isFinite(exponential) ? exponential : policy.maxBackoffMs,
    policy.maxBackoffMs,
  );
}

/** The sleep seam. Injecting a fake clock lets tests assert the schedule. */
export interface Clock {
  sleep(milliseconds: number): Promise<void>;
}

/**
 * The production clock. Prefers workerd's `scheduler.wait`, which is the
 * platform-native way to yield, and falls back to `setTimeout` off-Worker (the
 * CLI and deploy scripts run under Bun/Node).
 */
export const systemClock: Clock = {
  sleep(milliseconds: number): Promise<void> {
    const scheduler = (globalThis as { scheduler?: { wait?: (ms: number) => Promise<void> } })
      .scheduler;
    if (typeof scheduler?.wait === "function") return scheduler.wait(milliseconds);
    return new Promise((resolve) => setTimeout(resolve, milliseconds));
  },
};

/** The minimum an attempt must report for the loop to classify it. */
export interface RetryableOutcome {
  readonly status: number;
  readonly retryAfterMs?: number;
}

export interface RetryOptions<T extends RetryableOutcome = RetryableOutcome> {
  readonly policy?: RetryPolicy;
  readonly clock?: Clock;
  /** `false` collapses the loop to a single attempt. Default `true`. */
  readonly enabled?: boolean;
  /**
   * Whether a received outcome is worth re-issuing. Defaults to
   * {@link isRetryableStatus} on its status.
   *
   * Override it when "retryable" is finer than the status alone, for example
   * when a caller must distinguish an outright rejection from an ambiguous
   * write response.
   */
  readonly isRetryableOutcome?: (outcome: T) => boolean;
  /** Whether a THROWN failure is worth re-issuing. Default: never. */
  readonly isRetryableError?: (error: unknown) => boolean;
  /**
   * Wraps the final thrown error once the budget has been spent. Mirrors Rust's
   * `ExhaustedRetries`: a failure on attempt 0 escapes UNWRAPPED, because there
   * were no retries to report.
   */
  readonly wrapExhaustedError?: (attempts: number, error: unknown) => unknown;
}

export interface RetryResult<T> {
  readonly outcome: T;
  /** Transport calls made. 1 = succeeded first try. */
  readonly attempts: number;
}

/**
 * Run `attempt` under the backoff schedule.
 *
 * Returns the FINAL outcome whatever its status — classifying a non-2xx is the
 * caller's job, and doing it here would put a mapped error back into the loop.
 * That separation is what guarantees a `400 + code 10013` response is issued
 * exactly once.
 */
export async function executeWithRetry<T extends RetryableOutcome>(
  attempt: () => Promise<T>,
  options: RetryOptions<T> = {},
): Promise<RetryResult<T>> {
  const policy = options.policy ?? DEFAULT_RETRY_POLICY;
  const clock = options.clock ?? systemClock;
  const maxRetries = options.enabled === false ? 0 : policy.maxRetries;
  const isRetryableError = options.isRetryableError ?? (() => false);

  let attemptIndex = 0;
  for (;;) {
    let outcome: T;
    try {
      outcome = await attempt();
    } catch (error) {
      if (isRetryableError(error) && attemptIndex < maxRetries) {
        await clock.sleep(backoffDelayMs(policy, attemptIndex));
        attemptIndex += 1;
        continue;
      }
      if (attemptIndex === 0 || options.wrapExhaustedError === undefined) throw error;
      throw options.wrapExhaustedError(attemptIndex + 1, error);
    }
    const retryable = options.isRetryableOutcome ?? ((value: T) => isRetryableStatus(value.status));
    if (retryable(outcome) && attemptIndex < maxRetries) {
      await clock.sleep(backoffDelayMs(policy, attemptIndex, outcome.retryAfterMs));
      attemptIndex += 1;
      continue;
    }
    return { outcome, attempts: attemptIndex + 1 };
  }
}
