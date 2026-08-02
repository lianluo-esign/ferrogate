/**
 * A single-isolate {@link RateLimiter}. This is the direct analogue of Rust's
 * `ClusterCounterBackend::Local` — a `Map` of counter key → window state, held
 * in process memory.
 *
 * **It is NOT a production backend on Workers, and that is the whole point of
 * this module existing separately.** A Worker runs in many isolates
 * simultaneously; a `Map` here is per-isolate, so a 60 rpm limit becomes 60·N.
 * The inventory flags exactly this ("Local `Mutex<HashMap>` counters are
 * per-isolate and non-atomic across isolates"). Use it for:
 *
 *  - pure-logic tests of the request path that do not need a DO binding, and
 *  - `wrangler dev` sessions where no DO namespace is bound.
 *
 * `DurableObjectRateLimiter` is the one to wire in `src/index.ts`.
 *
 * It shares `window.ts` with the DO, so both backends compute admission
 * identically; only the atomicity domain differs.
 */
import { releaseOnce } from "./do-limiter.js";
import { type CounterWindow, assertNamespacedCounterKey } from "./keys.js";
import type { RateLimitOutcome, RateLimiter, ReservationOutcome, TokenAdmission } from "./ports.js";
import {
  RequestWindow,
  SpendLedger,
  TokenBudgetLedger,
  TokenWindow,
  WalletLedger,
  secondsUntilWindowReset,
} from "./window.js";

interface Entry {
  readonly rpm: RequestWindow;
  readonly tpm: TokenWindow;
  readonly tokenBudget: TokenBudgetLedger;
  readonly wallet: WalletLedger;
  readonly monthlyBudget: SpendLedger;
}

export interface InMemoryRateLimiterOptions {
  /** Unix-seconds clock. Injected so window rollover is testable. */
  readonly clock?: () => number;
}

export class InMemoryRateLimiter implements RateLimiter {
  readonly #entries = new Map<string, Entry>();
  readonly #clock: () => number;

  constructor(options: InMemoryRateLimiterOptions = {}) {
    this.#clock = options.clock ?? (() => Math.floor(Date.now() / 1000));
  }

  /** Same guard as the DO limiter — an unnamespaced key can never be counted. */
  #entry(counterKey: string): Entry {
    assertNamespacedCounterKey(counterKey);
    let entry = this.#entries.get(counterKey);
    if (entry === undefined) {
      entry = {
        rpm: new RequestWindow(),
        tpm: new TokenWindow(),
        tokenBudget: new TokenBudgetLedger(),
        wallet: new WalletLedger(),
        monthlyBudget: new SpendLedger(),
      };
      this.#entries.set(counterKey, entry);
    }
    return entry;
  }

  async consumeRequest(windows: readonly CounterWindow[]): Promise<RateLimitOutcome> {
    const now = this.#clock();
    for (const window of windows) {
      const entry = this.#entry(window.counterKey);
      if (!entry.rpm.tryConsume(window.limit, now)) {
        return {
          allowed: false,
          counterKey: window.counterKey,
          limit: window.limit,
          retryAfterSeconds: secondsUntilWindowReset(entry.rpm.state, now),
        };
      }
    }
    return { allowed: true };
  }

  async consumeTokens(window: CounterWindow, estimatedTokens: number): Promise<TokenAdmission> {
    const now = this.#clock();
    const entry = this.#entry(window.counterKey);
    if (!entry.tpm.tryConsume(window.limit, estimatedTokens, now)) {
      return {
        allowed: false,
        counterKey: window.counterKey,
        limit: window.limit,
        retryAfterSeconds: secondsUntilWindowReset(entry.tpm.state, now),
      };
    }
    return {
      allowed: true,
      counterKey: window.counterKey,
      windowStartedAt: entry.tpm.state.windowStartedAt,
      estimatedTokens,
    };
  }

  async settleTokens(admission: TokenAdmission, actualTokens: number): Promise<void> {
    if (admission.allowed !== true) return;
    this.#entry(admission.counterKey).tpm.settle(
      admission.windowStartedAt,
      admission.estimatedTokens,
      actualTokens,
    );
  }

  async reserveTokenBudget(
    counterKey: string,
    committed: number,
    budget: number,
    estimatedTokens: number,
  ): Promise<ReservationOutcome> {
    const entry = this.#entry(counterKey);
    if (!entry.tokenBudget.tryReserve(committed, budget, estimatedTokens)) {
      return { outcome: "insufficient" };
    }
    return {
      outcome: "reserved",
      reservation: releaseOnce(estimatedTokens, async () =>
        entry.tokenBudget.release(estimatedTokens),
      ),
    };
  }

  async reserveMonthlyBudget(
    counterKey: string,
    committedUsd: number,
    budgetUsd: number,
    estimatedUsd: number,
  ): Promise<ReservationOutcome> {
    if (estimatedUsd <= 0) return { outcome: "not_applicable" };
    const entry = this.#entry(counterKey);
    if (!entry.monthlyBudget.tryReserve(committedUsd, budgetUsd, estimatedUsd)) {
      return { outcome: "insufficient" };
    }
    return {
      outcome: "reserved",
      reservation: releaseOnce(estimatedUsd, async () => entry.monthlyBudget.release(estimatedUsd)),
    };
  }

  async reserveWalletCredits(
    counterKey: string,
    balanceCredits: number,
    estimatedCredits: number,
  ): Promise<ReservationOutcome> {
    if (estimatedCredits <= 0) return { outcome: "not_applicable" };
    const entry = this.#entry(counterKey);
    if (!entry.wallet.tryReserve(balanceCredits, estimatedCredits)) {
      return { outcome: "insufficient" };
    }
    return {
      outcome: "reserved",
      reservation: releaseOnce(estimatedCredits, async () =>
        entry.wallet.release(estimatedCredits),
      ),
    };
  }
}
