/**
 * {@link RateLimiter} backed by {@link RateLimiterDurableObject} — the
 * production limiter.
 *
 * This is the thin half: all arithmetic lives in `window.ts` (inside the DO),
 * all key derivation in `keys.ts`. What this file owns is (a) turning a counter
 * key into the right DO stub, through the namespacing guard, and (b) mapping a
 * transport failure onto Rust's `Err(_)` arm, which is a **503
 * `governance_counter_unavailable`, never a 429**.
 *
 * FAIL-CLOSED NOTE. Rust's `Local` backend fails OPEN in one narrow place — a
 * poisoned `Mutex` makes `try_consume` return `Ok(true)` — because a poisoned
 * lock in-process means a thread panicked mid-update and the counter is
 * unusable. A DO RPC failure is a different event (a transient dispatch error),
 * and Rust's own `Redis` backend propagates it as `Err`, producing the 503. So
 * that is what happens here: a counter outage is surfaced, not silently
 * ignored, matching the cluster backend Rust actually shipped for multi-node.
 */
import type { RateLimiterDurableObject, RateLimiterNamespace } from "./durable-object.js";
import { type CounterWindow, assertNamespacedCounterKey } from "./keys.js";
import type {
  RateLimitOutcome,
  RateLimiter,
  Reservation,
  ReservationOutcome,
  TokenAdmission,
} from "./ports.js";

/** Render a thrown value for the `governance_counter_unavailable` detail. */
function detailOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export class DurableObjectRateLimiter implements RateLimiter {
  constructor(private readonly namespace: RateLimiterNamespace) {}

  /**
   * Address the instance for `counterKey`.
   *
   * The guard runs HERE, at the last point before a caller-influenced string
   * becomes a Durable Object name. `idFromName` hashes its argument, so two
   * different names are two different instances and one name is one instance —
   * which makes "what may become a name" the whole of the isolation argument.
   */
  #stub(counterKey: string): DurableObjectStub<RateLimiterDurableObject> {
    assertNamespacedCounterKey(counterKey);
    return this.namespace.get(this.namespace.idFromName(counterKey));
  }

  async consumeRequest(windows: readonly CounterWindow[]): Promise<RateLimitOutcome> {
    // Rust charges each window in order and short-circuits on the first denial.
    for (const window of windows) {
      // OUTSIDE the try: a namespacing violation is a programming error and
      // must propagate as a 500, never be laundered into the `unavailable`
      // (503 `governance_counter_unavailable`) arm, which would let a bad call
      // site look like a transient counter outage.
      const stub = this.#stub(window.counterKey);
      try {
        const result = await stub.consumeRequest(window.limit);
        if (!result.allowed) {
          return {
            allowed: false,
            counterKey: window.counterKey,
            limit: window.limit,
            retryAfterSeconds: result.retryAfterSeconds,
          };
        }
      } catch (error) {
        return { allowed: "unavailable", detail: detailOf(error) };
      }
    }
    return { allowed: true };
  }

  async consumeTokens(window: CounterWindow, estimatedTokens: number): Promise<TokenAdmission> {
    const stub = this.#stub(window.counterKey);
    try {
      const result = await stub.consumeTokens(window.limit, estimatedTokens);
      if (!result.allowed) {
        return {
          allowed: false,
          counterKey: window.counterKey,
          limit: window.limit,
          retryAfterSeconds: result.retryAfterSeconds,
        };
      }
      return {
        allowed: true,
        counterKey: window.counterKey,
        windowStartedAt: result.windowStartedAt,
        estimatedTokens,
      };
    } catch (error) {
      return { allowed: "unavailable", detail: detailOf(error) };
    }
  }

  async settleTokens(admission: TokenAdmission, actualTokens: number): Promise<void> {
    if (admission.allowed !== true) return;
    try {
      await this.#stub(admission.counterKey).settleTokens(
        admission.windowStartedAt,
        admission.estimatedTokens,
        actualTokens,
      );
    } catch {
      // The response has already been delivered; a settlement failure only
      // leaves the window charged at the estimate, which is the Rust behavior.
    }
  }

  async reserveTokenBudget(
    counterKey: string,
    committed: number,
    budget: number,
    estimatedTokens: number,
  ): Promise<ReservationOutcome> {
    const stub = this.#stub(counterKey);
    try {
      const reserved = await stub.reserveTokenBudget(committed, budget, estimatedTokens);
      if (!reserved) return { outcome: "insufficient" };
      return {
        outcome: "reserved",
        reservation: releaseOnce(estimatedTokens, () => stub.releaseTokenBudget(estimatedTokens)),
      };
    } catch (error) {
      return { outcome: "unavailable", detail: detailOf(error) };
    }
  }

  async reserveMonthlyBudget(
    counterKey: string,
    committedUsd: number,
    budgetUsd: number,
    estimatedUsd: number,
  ): Promise<ReservationOutcome> {
    // A hold of nothing is not a guard; taking it would only cost a round trip.
    if (estimatedUsd <= 0) return { outcome: "not_applicable" };
    const stub = this.#stub(counterKey);
    try {
      const reserved = await stub.reserveMonthlyBudget(committedUsd, budgetUsd, estimatedUsd);
      if (!reserved) return { outcome: "insufficient" };
      return {
        outcome: "reserved",
        reservation: releaseOnce(estimatedUsd, () => stub.releaseMonthlyBudget(estimatedUsd)),
      };
    } catch (error) {
      return { outcome: "unavailable", detail: detailOf(error) };
    }
  }

  async reserveWalletCredits(
    counterKey: string,
    balanceCredits: number,
    estimatedCredits: number,
  ): Promise<ReservationOutcome> {
    // Rust `NotApplicable`: an unpriced route estimates 0 credits and takes no
    // hold, so a zero-cost request is never blocked by a wallet.
    if (estimatedCredits <= 0) return { outcome: "not_applicable" };
    const stub = this.#stub(counterKey);
    try {
      const reserved = await stub.reserveWalletCredits(balanceCredits, estimatedCredits);
      if (!reserved) return { outcome: "insufficient" };
      return {
        outcome: "reserved",
        reservation: releaseOnce(estimatedCredits, () =>
          stub.releaseWalletCredits(estimatedCredits),
        ),
      };
    } catch (error) {
      return { outcome: "unavailable", detail: detailOf(error) };
    }
  }
}

/**
 * Wrap a release in Rust's `released: bool` idempotence, so `settle()` followed
 * by the `finally` in {@link withReservation} frees the hold exactly once.
 */
export function releaseOnce(amount: number, release: () => Promise<unknown>): Reservation {
  let released = false;
  return {
    amount,
    async release(): Promise<void> {
      if (released) return;
      released = true;
      try {
        await release();
      } catch {
        // Best-effort, exactly as Rust's `let _ = redis.release_tokens(..)`.
        // The hold expires with the DO instance in the worst case.
      }
    },
  };
}
