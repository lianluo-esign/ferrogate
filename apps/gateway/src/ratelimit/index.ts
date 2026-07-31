/**
 * `apps/gateway/src/ratelimit` — rate limiting + quota enforcement on a
 * Durable Object.
 *
 * Clean-room port of the Rust `ClusterCounterBackend` RPM/TPM/token/wallet
 * counters (`crates/ferrogate-gateway/src/state.rs`), the admission checks in
 * `auth::finalize_auth`, and the TPM gate in `server/chat.rs`. The multi-level
 * quota MERGE is not re-implemented: `@ferrogate/policy`'s
 * `resolveEffectiveQuota` + `QuotaScopeSelector.counterKey` are called directly.
 *
 * ```
 *  request ─▶ contractAuth ─▶ rateLimit ────────────────▶ handler
 *                              │                            │
 *                              │ resolveEffectiveQuota      │ enforceTokensPerMinute(estimate)
 *                              │ requestWindows() (RPM)     │ settleTokenUsage(actual)
 *                              ▼                            ▼
 *                        RateLimiter ──── DO: one instance per counter key
 * ```
 *
 * ===========================================================================
 * WIRING — what the integrate step must add. Three edits, none in this dir.
 * ===========================================================================
 *
 * **1. `apps/gateway/src/worker.ts`** — add this line. workerd resolves a DO
 * binding's `class_name` against the ENTRY module, so without it the Worker
 * fails at startup with "Durable Object class RateLimiterDurableObject not
 * found". `@cloudflare/vitest-pool-workers` does NOT reproduce that check, so
 * the unit suite would stay green on an unbootable Worker:
 *
 * ```ts
 * export { RateLimiterDurableObject } from "./ratelimit/index.js";
 * ```
 *
 * (A DO class IS a legal named export of the entry module — the restriction
 * documented in `worker.ts` is on non-handler, non-class values.)
 *
 * **2. `apps/gateway/wrangler.toml`** — the binding plus its migration. The
 * file's "NOT DECLARED — and why" block already reserves `RATE_LIMIT` for this
 * slice; replace that bullet with:
 *
 * ```toml
 * [[durable_objects.bindings]]
 * name = "RATE_LIMIT"
 * class_name = "RateLimiterDurableObject"
 *
 * [[migrations]]
 * tag = "v1"
 * new_sqlite_classes = ["RateLimiterDurableObject"]
 * ```
 *
 * Also declare the quota tables `quota.ts` reads (both fail closed when empty):
 *
 * ```toml
 * GATEWAY_QUOTA_POLICIES = "[]"
 * GATEWAY_PLANS = "{}"
 * GATEWAY_TENANT_PLANS = "{}"
 * ```
 *
 * and add `RATE_LIMIT?: DurableObjectNamespace` +
 * `GATEWAY_QUOTA_POLICIES?/GATEWAY_PLANS?/GATEWAY_TENANT_PLANS?: string` to
 * `GatewayBindings` in `src/ports.ts`.
 *
 * **3. Mount the middleware AFTER `contractAuth` and BEFORE the routes.**
 * Hono runs matched handlers in REGISTRATION order, so `app.use("*", …)` added
 * after `createGatewayApp` returns would run after the route handler and never
 * gate anything. The middleware must be registered inside the composition root,
 * between these two existing lines of `src/routes/index.ts`:
 *
 * ```ts
 *   app.use("*", contractAuth(options.deps ?? depsFromEnv));
 * + for (const middleware of options.middleware ?? []) app.use("*", middleware);
 *   const router = new GatewayRouter(app);
 * ```
 *
 * with `readonly middleware?: readonly MiddlewareHandler<GatewayEnv>[]` added to
 * `CreateGatewayAppOptions`. Then in `src/index.ts`:
 *
 * ```ts
 * import { rateLimit } from "./ratelimit/index.js";
 * const { app, router } = createGatewayApp({
 *   modules: GATEWAY_ROUTE_MODULES,
 *   middleware: [rateLimit()],
 * });
 * ```
 *
 * `rateLimit()` with no arguments picks the DO limiter when `RATE_LIMIT` is
 * bound and the config-var quota source; both fail closed.
 *
 * **4. (inference slice) TPM.** In each AI handler, where the Rust calls
 * `try_consume_api_key_tokens_per_minute`:
 *
 * ```ts
 * const admission = await enforceTokensPerMinute(c, estimatedTotalTokens);
 * // … dispatch, stream …
 * await settleTokenUsage(c, admission, usage.totalTokens); // opt-in, see ports.ts
 * ```
 *
 * ===========================================================================
 */
export {
  type CounterWindow,
  CounterKeyNamespaceError,
  assertNamespacedCounterKey,
  counterKeyForScope,
  isNamespacedCounterKey,
  parseCounterKey,
  perKeyCounterKey,
  requestWindows,
  tokenBudgetCounterKey,
  tpmWindow,
  walletCounterKey,
} from "./keys.js";

export {
  type RateLimitOptions,
  type RateLimitOutcome,
  type RateLimiter,
  type Reservation,
  type ReservationOutcome,
  type TokenAdmission,
  RATE_LIMIT_REFUSALS,
  withReservation,
} from "./ports.js";

export {
  WINDOW_SECONDS,
  type WindowState,
  RequestWindow,
  TokenBudgetLedger,
  TokenWindow,
  WalletLedger,
  emptyWindow,
  secondsUntilWindowReset,
} from "./window.js";

export {
  type DoRequestResult,
  type DoTokenResult,
  type RateLimiterNamespace,
  RateLimiterDurableObject,
} from "./durable-object.js";

export { DurableObjectRateLimiter, releaseOnce } from "./do-limiter.js";
export { InMemoryRateLimiter, type InMemoryRateLimiterOptions } from "./memory.js";

export {
  type QuotaBindings,
  type QuotaPolicySnapshot,
  type QuotaPolicySource,
  type QuotaResolution,
  type QuotaSubject,
  type MonthlySpendReading,
  type SpendBindings,
  type SpendSource,
  type WalletBalanceReading,
  NO_QUOTA_POLICIES,
  NO_SPEND_SOURCE,
  currentPeriodMonth,
  d1QuotaPolicySource,
  d1SpendSource,
  monthlyBudgetScope,
  quotaPolicySourceFromEnv,
  quotaPolicySourceFromVars,
  resolveQuotaWindows,
  spendSourceFromEnv,
} from "./quota.js";

export {
  type RateLimitBindings,
  type RateLimitDeps,
  type ResolvedWindows,
  type TokenAdmissionRefusal,
  admitTokensPerMinute,
  enforceTokensPerMinute,
  isTokenAdmissionRefusal,
  limiterForEnv,
  rateLimit,
  rateLimitRouteModule,
  resolvedWindows,
  settleTokenUsage,
  subjectFor,
} from "./middleware.js";
