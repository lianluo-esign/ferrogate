/**
 * The deterministic retry/backoff schedule — ported 1:1 from
 * `crates/ferrogate-cloudflare/src/client.rs:148-170` (`RetryPolicy`).
 *
 * Cloudflare's global API limit is ~1,200 requests / 5 min / user (~4 req/s).
 * Defaults: 4 retries, 1s base, 60s cap. The server's `Retry-After` wins when
 * present (itself capped); otherwise `base * 2^attempt`, capped, saturating.
 *
 * There is deliberately **NO JITTER**. That is not an oversight and must not be
 * "improved": determinism is what makes the schedule exactly assertable with an
 * injected clock, which is the only reason a test can tell "it retried on the
 * documented schedule" from "it retried somehow".
 */
import { describe, expect, test } from "vitest";
import {
  DEFAULT_RETRY_POLICY,
  RETRYABLE_STATUSES,
  backoffDelayMs,
  executeWithRetry,
  isRetryableStatus,
} from "../src/retry.js";
import { RecordingClock } from "./support.js";

describe("RetryPolicy defaults", () => {
  test("the Rust defaults, verbatim", () => {
    expect(DEFAULT_RETRY_POLICY).toEqual({
      maxRetries: 4,
      baseBackoffMs: 1_000,
      maxBackoffMs: 60_000,
    });
  });
});

describe("backoffDelayMs", () => {
  test("doubles from the base with no jitter", () => {
    const schedule = [0, 1, 2, 3, 4, 5].map((attempt) =>
      backoffDelayMs(DEFAULT_RETRY_POLICY, attempt),
    );
    expect(schedule).toEqual([1_000, 2_000, 4_000, 8_000, 16_000, 32_000]);
  });

  test("is deterministic — the same attempt always yields the same delay", () => {
    const first = backoffDelayMs(DEFAULT_RETRY_POLICY, 3);
    for (let i = 0; i < 25; i += 1) {
      expect(backoffDelayMs(DEFAULT_RETRY_POLICY, 3)).toBe(first);
    }
  });

  test("caps at maxBackoff instead of growing", () => {
    expect(backoffDelayMs(DEFAULT_RETRY_POLICY, 6)).toBe(60_000);
    expect(backoffDelayMs(DEFAULT_RETRY_POLICY, 40)).toBe(60_000);
  });

  test("saturates rather than overflowing on an absurd attempt count", () => {
    expect(backoffDelayMs(DEFAULT_RETRY_POLICY, 1_000)).toBe(60_000);
    expect(Number.isFinite(backoffDelayMs(DEFAULT_RETRY_POLICY, 1_000))).toBe(true);
  });

  test("the server's Retry-After wins over the exponential schedule", () => {
    expect(backoffDelayMs(DEFAULT_RETRY_POLICY, 0, 7_000)).toBe(7_000);
    // Even when the exponential term would have been larger.
    expect(backoffDelayMs(DEFAULT_RETRY_POLICY, 5, 250)).toBe(250);
  });

  test("a Retry-After larger than maxBackoff is still capped", () => {
    expect(backoffDelayMs(DEFAULT_RETRY_POLICY, 0, 3_600_000)).toBe(60_000);
  });
});

describe("isRetryableStatus", () => {
  test("exactly 429 | 500 | 502 | 503 | 504", () => {
    expect([...RETRYABLE_STATUSES]).toEqual([429, 500, 502, 503, 504]);
    for (const status of [429, 500, 502, 503, 504]) {
      expect(isRetryableStatus(status)).toBe(true);
    }
    for (const status of [200, 201, 400, 401, 403, 404, 409, 422, 501, 505]) {
      expect(isRetryableStatus(status)).toBe(false);
    }
  });

  test("501 is NOT retryable — a 5xx blanket match would be wrong", () => {
    expect(isRetryableStatus(501)).toBe(false);
  });
});

describe("executeWithRetry", () => {
  test("a first-try success makes exactly one attempt and never sleeps", async () => {
    const clock = new RecordingClock();
    let calls = 0;
    const result = await executeWithRetry(
      async () => {
        calls += 1;
        return { status: 200, value: "ok" };
      },
      { clock },
    );
    expect(result.attempts).toBe(1);
    expect(result.outcome.value).toBe("ok");
    expect(calls).toBe(1);
    expect(clock.slept).toEqual([]);
  });

  test("retries a 503 and reports the attempt count on eventual success", async () => {
    const clock = new RecordingClock();
    const statuses = [503, 503, 200];
    let call = 0;
    const result = await executeWithRetry(
      async () => ({ status: statuses[call++] as number }),
      { clock },
    );
    expect(result.attempts).toBe(3);
    expect(clock.slept).toEqual([1_000, 2_000]);
  });

  test("exhausts at maxRetries and hands back the last retryable response", async () => {
    const clock = new RecordingClock();
    let calls = 0;
    const result = await executeWithRetry(
      async () => {
        calls += 1;
        return { status: 429 };
      },
      { clock },
    );
    expect(calls).toBe(5); // 1 initial + 4 retries
    expect(result.attempts).toBe(5);
    expect(result.outcome.status).toBe(429);
    expect(clock.slept).toEqual([1_000, 2_000, 4_000, 8_000]);
  });

  test("a per-response Retry-After steers each individual sleep", async () => {
    const clock = new RecordingClock();
    const script = [
      { status: 429, retryAfterMs: 3_000 },
      { status: 429 },
      { status: 429, retryAfterMs: 500 },
      { status: 200 },
    ];
    let call = 0;
    await executeWithRetry(async () => script[call++] as { status: number }, { clock });
    // attempt 0 → server hint 3s; attempt 1 → no hint → base*2^1 = 2s;
    // attempt 2 → server hint 0.5s.
    expect(clock.slept).toEqual([3_000, 2_000, 500]);
  });

  test("`enabled: false` disables retry entirely — the idempotency gate", async () => {
    const clock = new RecordingClock();
    let calls = 0;
    const result = await executeWithRetry(
      async () => {
        calls += 1;
        return { status: 500 };
      },
      { clock, enabled: false },
    );
    expect(calls).toBe(1);
    expect(result.attempts).toBe(1);
    expect(clock.slept).toEqual([]);
  });

  test("a thrown error is retried only when isRetryableError says so", async () => {
    const clock = new RecordingClock();
    let calls = 0;
    await expect(
      executeWithRetry(
        async () => {
          calls += 1;
          throw new Error("connect reset");
        },
        { clock, isRetryableError: () => true },
      ),
    ).rejects.toThrow();
    expect(calls).toBe(5);
    expect(clock.slept).toEqual([1_000, 2_000, 4_000, 8_000]);
  });

  test("a non-retryable throw escapes immediately, unwrapped", async () => {
    const clock = new RecordingClock();
    const boom = new Error("bad request");
    let calls = 0;
    await expect(
      executeWithRetry(
        async () => {
          calls += 1;
          throw boom;
        },
        { clock },
      ),
    ).rejects.toBe(boom);
    expect(calls).toBe(1);
    expect(clock.slept).toEqual([]);
  });

  test("wrapExhaustedError only wraps AFTER a retry was actually spent", async () => {
    const clock = new RecordingClock();
    const boom = new Error("timeout");
    const wrapped = new Error("wrapped");

    // attempt 0 failure, retry disabled → the raw error escapes unwrapped, as
    // in Rust (`if attempt == 0 { return Err(err) }`).
    await expect(
      executeWithRetry(
        async () => {
          throw boom;
        },
        { clock, enabled: false, wrapExhaustedError: () => wrapped },
      ),
    ).rejects.toBe(boom);

    // With the budget spent, the wrapper is applied and told how many attempts.
    let seenAttempts = 0;
    await expect(
      executeWithRetry(
        async () => {
          throw boom;
        },
        {
          clock,
          isRetryableError: () => true,
          wrapExhaustedError: (attempts) => {
            seenAttempts = attempts;
            return wrapped;
          },
        },
      ),
    ).rejects.toBe(wrapped);
    expect(seenAttempts).toBe(5);
  });

  test("isRetryableOutcome narrows retryability below the status alone", async () => {
    // The shape `@ferrogate/storage`'s D1 REST transport needs: a 429 is a
    // rejection and always safe to re-issue; a 5xx is ambiguous and is retried
    // only when the statement cannot have mutated anything.
    const clock = new RecordingClock();
    let calls = 0;
    const result = await executeWithRetry(
      async () => {
        calls += 1;
        return { status: 502 };
      },
      { clock, isRetryableOutcome: ({ status }) => status === 429 },
    );
    expect(calls).toBe(1);
    expect(result.outcome.status).toBe(502);
    expect(clock.slept).toEqual([]);
  });

  test("isRetryableOutcome can also WIDEN retryability", async () => {
    const clock = new RecordingClock();
    const script = [{ status: 409 }, { status: 200 }];
    let call = 0;
    const result = await executeWithRetry(async () => script[call++] as { status: number }, {
      clock,
      isRetryableOutcome: ({ status }) => status === 409,
    });
    expect(result.attempts).toBe(2);
  });

  test("an explicit policy overrides the defaults", async () => {
    const clock = new RecordingClock();
    let calls = 0;
    await executeWithRetry(
      async () => {
        calls += 1;
        return { status: 500 };
      },
      { clock, policy: { maxRetries: 2, baseBackoffMs: 10, maxBackoffMs: 15 } },
    );
    expect(calls).toBe(3);
    expect(clock.slept).toEqual([10, 15]); // 10, then min(20, 15) = 15
  });
});
