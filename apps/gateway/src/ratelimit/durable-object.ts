/**
 * `RateLimiterDurableObject` — the Workers replacement for the Rust
 * `Mutex<HashMap>` counters.
 *
 * ## Why a Durable Object and not a module-scope Map
 *
 * `ClusterCounterBackend::Local` held its RPM/TPM/token/wallet windows in
 * `Arc<Mutex<HashMap<..>>>`: one process, one lock, therefore atomic. A Worker
 * has no equivalent. Isolates are created and destroyed per colo, per version,
 * per burst; a module-scope `Map` is per-isolate, so N isolates give N
 * independent counters and a limit of 60 rpm silently becomes 60·N. That is why
 * `docs/legacy/inventory-request-path.md` calls the counters out as the single
 * hardest thing to port ("Local `Mutex<HashMap>` counters are per-isolate and
 * non-atomic across isolates → **must** move to DO/Rate-Limiting on Workers").
 *
 * A Durable Object is the platform's answer: exactly one instance per id,
 * globally, with single-threaded execution. `ctx.blockConcurrencyWhile` in the
 * constructor is the lock; the instance itself is the `HashMap` entry.
 *
 * ## Sharding: one instance per counter key
 *
 * The Rust map key becomes the DO NAME (`idFromName(counterKey)`), so this class
 * holds ONE window per dimension rather than a map of them. Consequences:
 *
 *  - a tenant-scope window (`"tenant:t1"`) is one instance shared by every key
 *    under that tenant, which is exactly the aggregate semantics the quota merge
 *    intends;
 *  - a per-key window (`"key:k1"`) is its own instance, so per-key traffic never
 *    serializes behind a tenant aggregate it does not contend for;
 *  - blast radius of a hot key is one DO, not one global counter.
 *
 * `idFromName` hashes the name, so a colliding name is the ONLY way two logical
 * counters can share an instance — hence the namespacing invariant enforced in
 * `keys.ts` before any name reaches here.
 *
 * ## Durability
 *
 * The two fixed windows are written through to `ctx.storage` (unawaited: the DO
 * output gate holds the response until the write lands, so this costs no
 * latency and cannot deliver a reply that a crash would un-count). They are
 * restored on construction, so DO eviction between requests does not silently
 * reset a window — a strictly stronger guarantee than the Rust process memory.
 *
 * In-flight RESERVATIONS are deliberately NOT persisted. They model requests
 * currently executing in this instance's lifetime; a restart means those
 * requests are gone, so resurrecting their holds would leak budget forever.
 * Rust behaves identically (a process restart empties `token_reservations`).
 */
import { DurableObject } from "cloudflare:workers";
import {
  RequestWindow,
  SpendLedger,
  TokenBudgetLedger,
  TokenWindow,
  WalletLedger,
  type WindowState,
  emptyWindow,
  remainingInWindow,
  secondsUntilWindowReset,
} from "./window.js";

const RPM_STORAGE_KEY = "window:rpm";
const TPM_STORAGE_KEY = "window:tpm";

/** {@link RateLimiterDurableObject.consumeRequest} reply. Structured-cloneable. */
export interface DoRequestResult {
  readonly allowed: boolean;
  /** Whole seconds until the denying window rolls. `0` when allowed. */
  readonly retryAfterSeconds: number;
  /** Requests left in the window against `limit` (#726). `0` when denied. */
  readonly remaining: number;
}

/** {@link RateLimiterDurableObject.consumeTokens} reply. */
export interface DoTokenResult {
  readonly allowed: boolean;
  /** Window generation the estimate was charged to; pass back to `settleTokens`. */
  readonly windowStartedAt: number;
  readonly retryAfterSeconds: number;
  /**
   * Tokens left in the window against `limit` (#726). Computed INSIDE the DO,
   * on the same single-threaded read that decided the denial — deriving it in
   * the caller would race the next request into the same window.
   */
  readonly remaining: number;
}

/**
 * One counter key's worth of state. Every method is an RPC entry point reachable
 * only through the `RATE_LIMIT` binding — there is no `fetch()` surface, so this
 * object is not addressable from the internet.
 */
export class RateLimiterDurableObject extends DurableObject {
  #rpm = new RequestWindow();
  #tpm = new TokenWindow();
  #tokenBudget = new TokenBudgetLedger();
  #wallet = new WalletLedger();
  /** #679 — in-flight USD against this scope's monthly budget. */
  #monthlyBudget = new SpendLedger();

  /**
   * Unix-seconds clock. Rust threaded `now_unix_seconds()` into every
   * `try_consume`, which is what made its window tests deterministic; the same
   * seam is kept here so `test/ratelimit/` can pin time via
   * `runInDurableObject(stub, (instance) => { instance.clock = () => t })`.
   *
   * It is a plain field, NOT an RPC method: `cloudflare:test`'s
   * `runInDurableObject` is the only way to reach it, and that API exists only
   * in the test pool. Nothing over the DO binding can rewrite it.
   */
  clock: () => number = () => Math.floor(Date.now() / 1000);

  constructor(ctx: DurableObjectState, env: unknown) {
    super(ctx, env as never);
    // The DO "lock": no RPC runs until the restore completes.
    ctx.blockConcurrencyWhile(async () => {
      const rpm = await ctx.storage.get<WindowState>(RPM_STORAGE_KEY);
      const tpm = await ctx.storage.get<WindowState>(TPM_STORAGE_KEY);
      this.#rpm = new RequestWindow(rpm ?? emptyWindow());
      this.#tpm = new TokenWindow(tpm ?? emptyWindow());
    });
  }

  /** Rust `ApiKeyRequestWindow::try_consume` — charges one request. */
  consumeRequest(limit: number): DoRequestResult {
    const now = this.clock();
    const allowed = this.#rpm.tryConsume(limit, now);
    // Unawaited on purpose: DO output gating holds the RPC reply until the
    // write completes, so this is durable without adding a round trip.
    void this.ctx.storage.put(RPM_STORAGE_KEY, { ...this.#rpm.state });
    return {
      allowed,
      retryAfterSeconds: allowed ? 0 : secondsUntilWindowReset(this.#rpm.state, now),
      remaining: remainingInWindow(this.#rpm.state, limit),
    };
  }

  /** Rust `ApiKeyTokenWindow::try_consume` — charges the pre-dispatch estimate. */
  consumeTokens(limit: number, estimatedTokens: number): DoTokenResult {
    const now = this.clock();
    const allowed = this.#tpm.tryConsume(limit, estimatedTokens, now);
    void this.ctx.storage.put(TPM_STORAGE_KEY, { ...this.#tpm.state });
    return {
      allowed,
      windowStartedAt: this.#tpm.state.windowStartedAt,
      retryAfterSeconds: allowed ? 0 : secondsUntilWindowReset(this.#tpm.state, now),
      remaining: remainingInWindow(this.#tpm.state, limit),
    };
  }

  /**
   * Swap an admission estimate for the response's real usage. Dropped when the
   * window has rolled since admission — see `TokenWindow.settle`.
   */
  settleTokens(windowStartedAt: number, estimatedTokens: number, actualTokens: number): void {
    this.#tpm.settle(windowStartedAt, estimatedTokens, actualTokens);
    void this.ctx.storage.put(TPM_STORAGE_KEY, { ...this.#tpm.state });
  }

  /** Rust `try_reserve_tokens`. `true` = hold taken. */
  reserveTokenBudget(committed: number, budget: number, estimatedTokens: number): boolean {
    return this.#tokenBudget.tryReserve(committed, budget, estimatedTokens);
  }

  /** Rust `release_tokens` (= `ApiKeyTokenReservation::settle` / `Drop`). */
  releaseTokenBudget(tokens: number): void {
    this.#tokenBudget.release(tokens);
  }

  /**
   * #679 — hold `estimatedUsd` against this scope's monthly USD budget.
   * `committedUsd` is the `usage_monthly_rollups` figure the caller read.
   *
   * THIS IS THE SERIALISATION POINT. The equivalent D1 sequence (read
   * `cost_usd`, compare, admit) has no critical section, so N requests that
   * arrive together all read the same figure and all pass. A Durable Object
   * runs one call at a time on one instance per counter key, so the Nth caller
   * necessarily observes the N-1 holds ahead of it.
   */
  reserveMonthlyBudget(committedUsd: number, budgetUsd: number, estimatedUsd: number): boolean {
    return this.#monthlyBudget.tryReserve(committedUsd, budgetUsd, estimatedUsd);
  }

  /** Release a {@link reserveMonthlyBudget} hold — the caller's `finally`. */
  releaseMonthlyBudget(usd: number): void {
    this.#monthlyBudget.release(usd);
  }

  /** Rust `try_reserve_wallet_credits`. `true` = hold taken. */
  reserveWalletCredits(balanceCredits: number, estimatedCredits: number): boolean {
    return this.#wallet.tryReserve(balanceCredits, estimatedCredits);
  }

  /** Rust `release_wallet_credits` (= `WalletCreditReservation::Drop`). */
  releaseWalletCredits(credits: number): void {
    this.#wallet.release(credits);
  }

  /** Read-only introspection for tests and metrics. Never mutates. */
  snapshot(): {
    readonly rpm: WindowState;
    readonly tpm: WindowState;
    readonly reservedTokens: number;
    readonly reservedWalletCredits: number;
    readonly reservedBudgetUsd: number;
  } {
    return {
      rpm: { ...this.#rpm.state },
      tpm: { ...this.#tpm.state },
      reservedTokens: this.#tokenBudget.reserved,
      reservedWalletCredits: this.#wallet.reserved,
      reservedBudgetUsd: this.#monthlyBudget.reserved,
    };
  }
}

/**
 * The binding shape `do-limiter.ts` needs. Declared structurally so the
 * composition root can pass a real `DurableObjectNamespace` without this module
 * importing the app's `GatewayBindings` (which it does not own).
 */
export interface RateLimiterNamespace {
  idFromName(name: string): DurableObjectId;
  get(id: DurableObjectId): DurableObjectStub<RateLimiterDurableObject>;
}
