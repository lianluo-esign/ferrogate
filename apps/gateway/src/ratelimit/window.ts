/**
 * The pure counter primitives — no Durable Object, no I/O, no clock.
 *
 * Clean-room port of the four structures the Rust `ClusterCounterBackend::Local`
 * kept in `Mutex<HashMap>` process memory
 * (`crates/ferrogate-gateway/src/state.rs`):
 *
 * | Rust                                       | here                     |
 * |--------------------------------------------|--------------------------|
 * | `ApiKeyRequestWindow` (RPM, fixed 60s)      | {@link RequestWindow}    |
 * | `ApiKeyTokenWindow` (TPM, fixed 60s)        | {@link TokenWindow}      |
 * | `token_reservations: HashMap<String,u64>`   | {@link TokenBudgetLedger}|
 * | `wallet_reservations: HashMap<String,i64>`  | {@link WalletLedger}     |
 *
 * Plus one structure Rust never had, because Rust never bounded it:
 * {@link SpendLedger}, the in-flight half of a monthly USD budget (#679).
 *
 * The Rust map key was the counter key and the value the per-key state. On
 * Workers the map itself disappears: one Durable Object INSTANCE is addressed
 * per counter key (`idFromName(counterKey)`), so each instance holds exactly one
 * of each structure below. `durable-object.ts` is that instance;
 * `memory.ts` re-uses these same structures for the single-isolate limiter, so
 * both backends provably share one implementation of the arithmetic.
 *
 * Everything here takes `now` as an argument exactly as Rust's
 * `try_consume(limit, now_unix_seconds)` did, which is what makes window
 * rollover testable without sleeping.
 */

/** The Rust window length. `ApiKeyRequestWindow`/`ApiKeyTokenWindow` both use 60. */
export const WINDOW_SECONDS = 60;

/** Rust u64 saturating arithmetic, in a language with one number type. */
function saturatingSub(a: number, b: number): number {
  return Math.max(0, a - b);
}

/** Serializable state of a fixed window (what the DO persists). */
export interface WindowState {
  /** Unix seconds the current window opened at. `0` = never opened. */
  windowStartedAt: number;
  /** Requests (RPM) or tokens (TPM) charged to the current window. */
  used: number;
}

/** A fresh, never-opened window — Rust `#[derive(Default)]`. */
export function emptyWindow(): WindowState {
  return { windowStartedAt: 0, used: 0 };
}

/**
 * Roll the window over when `now` is a full {@link WINDOW_SECONDS} past its
 * start, mirroring Rust exactly:
 *
 * ```rust
 * if now_unix_seconds.saturating_sub(state.window_started_at) >= 60 {
 *     state.window_started_at = now_unix_seconds;
 *     state.count = 0;
 * }
 * ```
 *
 * Note this is a FIXED window anchored at first use, not a minute-aligned or
 * sliding one: the boundary moves to `now` on the first call after expiry. The
 * classic fixed-window burst (up to `2 * limit` across a boundary) is inherited
 * from the Rust implementation deliberately — changing it here would be a
 * silent behavior change, not a port.
 */
function rollOver(state: WindowState, now: number): void {
  if (saturatingSub(now, state.windowStartedAt) >= WINDOW_SECONDS) {
    state.windowStartedAt = now;
    state.used = 0;
  }
}

/** Whole seconds until the current window expires; `0` when it already has. */
export function secondsUntilWindowReset(state: WindowState, now: number): number {
  const elapsed = saturatingSub(now, state.windowStartedAt);
  return saturatingSub(WINDOW_SECONDS, elapsed);
}

/**
 * Requests-per-minute window. Rust `ApiKeyRequestWindow`.
 *
 * `limit == 0` rejects every request (`count >= 0` is immediately true), which
 * is the Rust behavior and the reason a zero RPM policy is a hard stop rather
 * than "unlimited".
 */
export class RequestWindow {
  constructor(readonly state: WindowState = emptyWindow()) {}

  /** Rust `try_consume(limit, now) -> bool`. Charges 1 on success. */
  tryConsume(limit: number, now: number): boolean {
    rollOver(this.state, now);
    // Rust: `if state.count >= limit { return false }`.
    if (this.state.used >= limit) return false;
    this.state.used += 1;
    return true;
  }
}

/**
 * Tokens-per-minute window. Rust `ApiKeyTokenWindow` — "structurally identical
 * to `ApiKeyRequestWindow` except it sums a caller-supplied token count instead
 * of incrementing by one per call".
 *
 * Note the deliberate asymmetry with {@link RequestWindow}, carried over
 * verbatim: RPM rejects on `used >= limit` (before charging), TPM rejects on
 * `used + tokens > limit`. With `tokens == 1` they coincide; with a large
 * estimate TPM admits a request that lands exactly ON the limit.
 */
export class TokenWindow {
  constructor(readonly state: WindowState = emptyWindow()) {}

  /** Rust `try_consume(limit, tokens, now) -> bool`. Charges `tokens` on success. */
  tryConsume(limit: number, tokens: number, now: number): boolean {
    rollOver(this.state, now);
    if (this.state.used + tokens > limit) return false;
    this.state.used += tokens;
    return true;
  }

  /**
   * Reconcile an admission-time ESTIMATE against the ACTUAL token usage, once
   * the response has completed. See the reservation/settlement discussion in
   * `ports.ts`; `windowStartedAt` is the value observed at admission, so a
   * settlement that arrives after the window already rolled is DROPPED rather
   * than retro-charged to an unrelated window.
   *
   * PORT-EXTENSION(inventory-request-path §1.7 "Counters"): the Rust TPM window
   * has no settlement at all — it charges the estimate and never revisits it,
   * so a long stream under-counts (or over-counts) the window for a full
   * minute. Nothing here weakens that: admission still charges the estimate, so
   * with settlement disabled the behavior is byte-identical to Rust. Settlement
   * is opt-in (`RateLimitOptions.settleTokens`).
   */
  settle(windowStartedAt: number, estimated: number, actual: number): void {
    if (this.state.windowStartedAt !== windowStartedAt) return;
    this.state.used = Math.max(0, this.state.used - estimated + actual);
  }
}

/**
 * In-flight holds against a MONTHLY token budget. Rust `token_reservations`
 * + `try_reserve_tokens` / `release_tokens`.
 *
 * This is the concurrency guard, not the budget itself: `committed` (the
 * durable rollup sum) is read by the caller and passed in, and the ledger only
 * owns the in-flight portion. Because settlement only ever INCREASES
 * `committed` and every increase is paired with a `release`, a slightly stale
 * (lower) `committed` can never let the summed in-flight holds exceed the
 * budget.
 */
export class TokenBudgetLedger {
  #reserved = 0;

  get reserved(): number {
    return this.#reserved;
  }

  /**
   * Rust `try_reserve_tokens`: reserve iff
   * `committed + reserved + estimated <= budget`. Returns `true` when the hold
   * was taken.
   */
  tryReserve(committed: number, budget: number, estimated: number): boolean {
    if (committed + this.#reserved + estimated > budget) return false;
    this.#reserved += estimated;
    return true;
  }

  /** Rust `release_tokens` (also what `ApiKeyTokenReservation::Drop` runs). */
  release(tokens: number): void {
    this.#reserved = saturatingSub(this.#reserved, tokens);
  }
}

/**
 * In-flight holds against a MONTHLY USD BUDGET — the #679 counter.
 *
 * Same arithmetic as {@link TokenBudgetLedger} and deliberately a DIFFERENT
 * object, because the two are different money in different units against
 * different caps. They share a Durable Object instance whenever a budget rung
 * is `key`-scoped (`"key:{id}"` addresses one instance), so folding them into
 * one pool would let a monthly-TOKEN reservation consume a scope's USD budget
 * and vice versa.
 *
 * `committed` is the durable `usage_monthly_rollups.cost_usd` the caller has
 * already read; this ledger only owns the in-flight portion, which is precisely
 * the part D1 cannot serialise. Because settlement only ever INCREASES
 * `committed` and every increase is paired with a `release`, a slightly stale
 * (lower) `committed` still cannot let the summed in-flight holds exceed the
 * budget.
 *
 * Money is a float here, as it is in `usage_monthly_rollups.cost_usd` (REAL) and
 * in `quota_policies.monthly_budget_usd`. The comparison inherits float
 * behavior; at the magnitudes involved (cents against dollars) the error is
 * many orders of magnitude below one credit (1e-6 USD).
 */
export class SpendLedger extends TokenBudgetLedger {}

/**
 * In-flight prepaid-wallet credit holds. Rust `wallet_reservations` +
 * `try_reserve_wallet_credits` / `release_wallet_credits` — the issue #169
 * concurrent-overdraft fix.
 *
 * Credits are signed in Rust (`i64`) because a wallet may legitimately be
 * negative; the reserve comparison is `reserved + estimated > balance`, with NO
 * `committed` term, since `balance_credits` is already net of settled debits.
 */
export class WalletLedger {
  #reserved = 0;

  get reserved(): number {
    return this.#reserved;
  }

  /** Rust `try_reserve_wallet_credits`. */
  tryReserve(balanceCredits: number, estimatedCredits: number): boolean {
    if (this.#reserved + estimatedCredits > balanceCredits) return false;
    this.#reserved += estimatedCredits;
    return true;
  }

  /** Rust `release_wallet_credits`. */
  release(credits: number): void {
    this.#reserved = saturatingSub(this.#reserved, credits);
  }
}
