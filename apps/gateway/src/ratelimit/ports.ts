/**
 * The narrow `RateLimiter` port the request path codes against.
 *
 * The request path must be testable without a Durable Object, and the DO must
 * be replaceable (Rust had two backends behind the same seam:
 * `ClusterCounterBackend::{Local, Redis}`). So everything upstream of this file
 * — `middleware.ts`, and the inference handlers the integrate step wires — sees
 * only {@link RateLimiter}. `durable-object.ts` + `do-limiter.ts` supply the
 * production implementation; `memory.ts` supplies the single-isolate one.
 *
 * ## RPM vs TPM: why they cannot share a code path
 *
 * **RPM is decided at ADMISSION.** A request costs exactly 1, that cost is known
 * before anything is dispatched, and Rust charges it in `auth::finalize_auth`
 * before the handler runs.
 *
 * **TPM is a cost that is not known until AFTER the response.** Rust resolves
 * this by charging an ESTIMATE at dispatch time
 * (`try_consume_api_key_tokens_per_minute(counter_key, limit,
 * estimated_usage.total_tokens)` in `server/chat.rs`) and never revisiting it.
 * The estimate is therefore the whole of the enforcement: a stream that emits
 * far more tokens than estimated is not clawed back within that minute, and one
 * that emits fewer leaves the window over-charged until it rolls.
 *
 * This port keeps that reservation/settlement split EXPLICIT rather than
 * pretending TPM is an admission counter:
 *
 *  - {@link RateLimiter.consumeTokens} is the admission half. It charges the
 *    estimate and returns the window generation it charged
 *    ({@link TokenAdmission.windowStartedAt}), which is what makes a later
 *    settlement addressable.
 *  - {@link RateLimiter.settleTokens} is the settlement half — the piece Rust
 *    does NOT have. It swaps `estimated` for `actual` in the same window, and
 *    is a no-op if that window has already rolled (a settlement must never
 *    retro-charge an unrelated minute). It is OPT-IN: leave it uncalled and
 *    behavior is identical to Rust.
 *
 * The two other Rust counters are true reservations with a release, and are
 * modelled as such, since JS has no `Drop`:
 *
 *  - {@link RateLimiter.reserveTokenBudget} → `try_reserve_tokens` /
 *    `ApiKeyTokenReservation` (monthly token budget, issue #330).
 *  - {@link RateLimiter.reserveWalletCredits} → `try_reserve_wallet_credits` /
 *    `WalletCreditReservation` (prepaid-credit overdraft, issue #169).
 *
 * Rust released those on `Drop`, so a cancelled or errored request still freed
 * its hold. TypeScript has no destructor, so a caller MUST release in a
 * `finally` (or `ctx.waitUntil`). {@link withReservation} does that for you.
 */
import type { CounterWindow } from "./keys.js";

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

/**
 * The result of an admission check.
 *
 * `unavailable` is a first-class outcome rather than a thrown error because
 * Rust distinguishes it: `try_consume_*` returns `anyhow::Result<bool>`, and an
 * `Err` becomes `503 governance_counter_unavailable`, NOT a 429. Collapsing the
 * two would turn a counter-backend outage into a rate-limit denial and hide it.
 */
export type RateLimitOutcome =
  | { readonly allowed: true }
  | {
      readonly allowed: false;
      /** The window that denied. Never logged to the client; used for metrics. */
      readonly counterKey: string;
      readonly limit: number;
      /** Whole seconds until that window rolls. See {@link RateLimitOptions}. */
      readonly retryAfterSeconds: number;
    }
  | { readonly allowed: "unavailable"; readonly detail: string };

/** {@link RateLimiter.consumeTokens} result — an outcome plus the settlement handle. */
export type TokenAdmission =
  | {
      readonly allowed: true;
      readonly counterKey: string;
      /**
       * The window generation the estimate was charged to. Pass it back to
       * {@link RateLimiter.settleTokens} so a settlement arriving after the
       * window rolled is dropped instead of charged to the next minute.
       */
      readonly windowStartedAt: number;
      readonly estimatedTokens: number;
    }
  | {
      readonly allowed: false;
      readonly counterKey: string;
      readonly limit: number;
      readonly retryAfterSeconds: number;
    }
  | { readonly allowed: "unavailable"; readonly detail: string };

/**
 * An in-flight hold. The TS stand-in for Rust's `Drop`-released reservation
 * guards — see {@link withReservation}.
 */
export interface Reservation {
  /** Amount held (tokens, or credits). */
  readonly amount: number;
  /**
   * Rust `release_tokens` / `release_wallet_credits`. Idempotent: Rust's guards
   * carry a `released: bool` so `settle()` followed by `Drop` releases once.
   */
  release(): Promise<void>;
}

/** Rust `WalletReservationOutcome` / `Option<ApiKeyTokenReservation>`. */
export type ReservationOutcome =
  | { readonly outcome: "reserved"; readonly reservation: Reservation }
  /** Rust `Ok(None)` / `Insufficient` — reject before dispatch. */
  | { readonly outcome: "insufficient" }
  /** Nothing governs this request (no wallet row, zero estimate). Rust `NotApplicable`. */
  | { readonly outcome: "not_applicable" }
  | { readonly outcome: "unavailable"; readonly detail: string };

// ---------------------------------------------------------------------------
// The port
// ---------------------------------------------------------------------------

export interface RateLimiter {
  /**
   * RPM admission. Rust:
   *
   * ```rust
   * for (counter_key, limit) in auth.request_windows() {
   *     require_request_budget(state, &counter_key, limit, request_id)?;
   * }
   * ```
   *
   * Windows are charged IN ORDER and the first denial short-circuits, so an
   * earlier window in the list has already been incremented when a later one
   * denies. That is Rust's behavior and is preserved deliberately: the windows
   * are independent budgets (a per-key cap and a tenant aggregate), and the
   * partial charge is what makes a caller that keeps retrying past a tenant cap
   * also burn its own key budget rather than probing for free.
   */
  consumeRequest(windows: readonly CounterWindow[]): Promise<RateLimitOutcome>;

  /**
   * TPM admission with the pre-dispatch token ESTIMATE. Rust
   * `try_consume_api_key_tokens_per_minute`.
   */
  consumeTokens(window: CounterWindow, estimatedTokens: number): Promise<TokenAdmission>;

  /**
   * Settle a prior {@link consumeTokens} against the response's real usage.
   * No-op when `admission.allowed !== true`. Never throws — a settlement
   * failure must not fail an already-delivered response.
   */
  settleTokens(admission: TokenAdmission, actualTokens: number): Promise<void>;

  /**
   * Monthly token-budget hold. Rust `try_reserve_tokens(api_key_id, committed,
   * budget, estimated_tokens)`; `committed` is the durable rollup sum the caller
   * has already read.
   */
  reserveTokenBudget(
    counterKey: string,
    committed: number,
    budget: number,
    estimatedTokens: number,
  ): Promise<ReservationOutcome>;

  /**
   * Prepaid-wallet credit hold. Rust `try_reserve_wallet_credits(tenant_id,
   * balance_credits, estimated_credits)`. A zero/negative estimate is
   * `not_applicable` (Rust takes no hold for an unpriced route).
   */
  reserveWalletCredits(
    counterKey: string,
    balanceCredits: number,
    estimatedCredits: number,
  ): Promise<ReservationOutcome>;
}

/**
 * Run `body` with a reservation held, releasing it whatever happens — the TS
 * replacement for Rust's `impl Drop for ApiKeyTokenReservation`.
 */
export async function withReservation<T>(
  outcome: ReservationOutcome,
  body: () => Promise<T>,
): Promise<T> {
  if (outcome.outcome !== "reserved") return await body();
  try {
    return await body();
  } finally {
    await outcome.reservation.release();
  }
}

// ---------------------------------------------------------------------------
// The Rust 429 taxonomy
// ---------------------------------------------------------------------------

/**
 * Every refusal this layer can produce, with the EXACT Rust status, code and
 * message. Sourced from `auth.rs::require_request_budget`,
 * `auth.rs::finalize_auth` and `server/chat.rs`.
 *
 * Rust attaches NO `Retry-After` header to any of them — `write_json_error`
 * writes `content-type`, `content-length`, `x-request-id`, `x-trace-id`,
 * `x-ferrogate-runtime` and the CORS headers, and nothing else; the only
 * `Retry-After` in the Rust tree is READ from an upstream response
 * (`control-plane-client/src/transport.rs`), never written. So the header is
 * off by default here too, and {@link RateLimitOptions.retryAfterHeader} is an
 * explicit opt-in rather than a silent addition.
 */
export const RATE_LIMIT_REFUSALS = {
  /** `require_request_budget` — the RPM denial. `{request_id}` is interpolated. */
  rate_limit_exceeded: {
    status: 429,
    code: "rate_limit_exceeded",
    message: (requestId: string) =>
      `API key request rate limit is exhausted for request ${requestId}`,
  },
  /** `server/chat.rs` (and embeddings/images/messages) — the TPM denial. */
  tpm_limit_exceeded: {
    status: 429,
    code: "tpm_limit_exceeded",
    message: () => "quota policy tokens-per-minute limit is exhausted for this request",
  },
  /** `finalize_auth` — monthly USD budget for the winning scope. */
  monthly_budget_exceeded: {
    status: 429,
    code: "monthly_budget_exceeded",
    message: () => "quota policy monthly budget has been exhausted for this scope",
  },
  /** `finalize_auth` / `WalletReservationOutcome::Insufficient` (issue #169). */
  wallet_balance_exhausted: {
    status: 429,
    code: "wallet_balance_exhausted",
    message: () => "prepaid credit balance has been exhausted for this tenant",
  },
  /** `authenticate_durable` / static-key path — `monthly_token_budget == 0`. */
  token_budget_exceeded: {
    status: 429,
    code: "token_budget_exceeded",
    message: () => "API key token budget is exhausted",
  },
  /**
   * `finalize_auth` — a policy anywhere in the chain is `enabled = false`. NOT a
   * 429: a disabled scope is a hard deny, not a throttle.
   */
  quota_scope_disabled: {
    status: 403,
    code: "quota_scope_disabled",
    message: (scopeKind: string) =>
      `quota policy at scope ${scopeKind} disables this request's tenant/project/workspace/key chain`,
  },
  /**
   * `require_request_budget` `Err(_)` arm — the counter backend itself failed.
   * 503, deliberately NOT 429.
   */
  governance_counter_unavailable: {
    status: 503,
    code: "governance_counter_unavailable",
    message: (detail: string) => `gateway counter backend is unavailable: ${detail}`,
  },
} as const;

/** Tunables for {@link rateLimit}. */
export interface RateLimitOptions {
  /**
   * Emit `Retry-After: <seconds>` on a 429. **Rust emits no such header**;
   * default `false` keeps byte-parity with the Rust responses. Turn it on only
   * as a deliberate, documented improvement.
   */
  readonly retryAfterHeader?: boolean;
  /**
   * Call {@link RateLimiter.settleTokens} once the response's real usage is
   * known. **Rust never settles a TPM window**; default `false` keeps parity.
   */
  readonly settleTokens?: boolean;
}
