/**
 * The request-path enforcement: Hono middleware for RPM, and a function the
 * inference handlers call for TPM.
 *
 * ## Where each check sits, and why they are two different things
 *
 * Rust enforces the quota chain in `auth::finalize_auth`, in this order:
 *
 *   1. `denied_by`               → **403** `quota_scope_disabled`
 *   2. `monthly_budget_usd`      → 429 `monthly_budget_exceeded`
 *   3. wallet balance            → 429 `wallet_balance_exhausted`
 *   4. `request_windows()` (RPM) → 429 `rate_limit_exceeded`
 *
 * …and TPM separately, in each AI handler, *after* the token estimate exists
 * (`server/chat.rs`, `embeddings.rs`, `images.rs`, `messages.rs`):
 *
 *   5. `tpm_window()`            → 429 `tpm_limit_exceeded`
 *
 * Steps 1 and 4 are what {@link rateLimit} does — everything decidable from the
 * credential alone. Steps 2 and 3 need durable spend/balance reads that belong
 * to `@ferrogate/storage` + `@ferrogate/billing`; the counters they reserve
 * against are implemented (`RateLimiter.reserveTokenBudget` /
 * `reserveWalletCredits`) and the refusals are spelled out in
 * `RATE_LIMIT_REFUSALS`, but the *balance source* is not this slice's — see the
 * PORT-TODO below.
 *
 * Step 5 is NOT middleware, for the same reason it is not middleware in Rust: a
 * token estimate does not exist until the request body has been parsed and the
 * model resolved, which happens inside the handler. It is exported as two plain
 * functions — {@link admitTokensPerMinute} (reports the refusal) and
 * {@link enforceTokensPerMinute} (throws it) — and the inference handlers call
 * the reporting form at the Rust call site, after `planUpstream` and before
 * dispatch. `rateLimit` leaves the merged TPM window on the context for them
 * ({@link setResolvedWindows}), because Rust resolves the quota ONCE in
 * `finalize_auth` and every handler reads `auth.effective_quota` rather than
 * re-merging the chain.
 *
 * That last hop is easy to lose: the inference handlers run inside the INNER
 * Hono app that `inferenceRouteModule` delegates into, which does not share a
 * context with this middleware. `src/inference/identity.ts` is what carries the
 * windows across, and `test/inference/wiring.test.ts` fails if it stops.
 */
import type { Context, MiddlewareHandler } from "hono";
import { HttpError } from "../middleware/errors.js";
import type { AuthContext, GatewayEnv } from "../ports.js";
import type { GatewayRouter, RouteModule } from "../routes/index.js";
import { DurableObjectRateLimiter } from "./do-limiter.js";
import type { RateLimiterNamespace } from "./durable-object.js";
import type { CounterWindow } from "./keys.js";
import { InMemoryRateLimiter } from "./memory.js";
import {
  RATE_LIMIT_REFUSALS,
  type RateLimitOptions,
  type RateLimitOutcome,
  type RateLimiter,
  type TokenAdmission,
} from "./ports.js";
import {
  type QuotaBindings,
  type QuotaPolicySource,
  type QuotaSubject,
  quotaPolicySourceFromEnv,
  resolveQuotaWindows,
} from "./quota.js";

/**
 * Bindings this module reads.
 *
 * Declared here rather than added to `src/ports.ts` `GatewayBindings` because
 * that file belongs to the composition root, not to this slice. The integrate
 * step should fold `RATE_LIMIT` into `GatewayBindings` when it wires the
 * middleware; until then {@link rateLimit} reads it through this structural
 * type. See the WIRING block in `index.ts`.
 */
export interface RateLimitBindings extends QuotaBindings {
  /** The `RateLimiterDurableObject` namespace. Absent ⇒ in-memory fallback. */
  readonly RATE_LIMIT?: RateLimiterNamespace | undefined;
}

/** Wiring for {@link rateLimit}. Every field has a runnable default. */
export interface RateLimitDeps extends RateLimitOptions {
  /** Override the limiter. Defaults to the DO limiter when `RATE_LIMIT` is bound. */
  readonly limiter?: RateLimiter | ((env: RateLimitBindings) => RateLimiter);
  /** Override the policy source. Defaults to {@link quotaPolicySourceFromEnv}. */
  readonly quotas?: QuotaPolicySource | ((env: RateLimitBindings) => QuotaPolicySource);
  /**
   * The TOK-12 per-credential `request_limit_per_minute`, which lives on the API
   * key row rather than in a quota policy. `AuthContext` in `src/ports.ts` does
   * not carry it yet, so it is supplied here.
   *
   * PORT-TODO(inventory-edge-control §5.2): CROSS-FILE, not cross-platform.
   * `D1ApiKeyResolver` ALREADY reads `request_limit_per_minute` off the
   * `api_keys` row (`src/keys/resolver.ts::resolveStoredKey`) and then drops it,
   * because `AuthContext` in `src/ports.ts` — the composition root's file, not
   * this slice's — has no field to carry it.
   *
   * The remaining change is one optional member on `AuthContext`
   * (`requestLimitPerMinute?: number`), one line in `toAuthContext`, and
   * replacing this hook with `auth.requestLimitPerMinute` in `subjectFor`.
   *
   * Consequence while it is open, stated plainly: a durable key's per-credential
   * TOK-12 RPM cap is enforced ONLY where a caller injects this hook
   * (`test/ratelimit/harness/worker.ts` does; `src/index.ts` does not), so in
   * the deployed Worker that column is currently inert and only the quota-policy
   * chain limits a D1-resolved credential.
   */
  readonly perKeyRequestLimit?: (auth: AuthContext) => number | undefined;
}

/**
 * Pick the limiter for an environment.
 *
 * A bound `RATE_LIMIT` namespace gives the atomic, cross-isolate counter. With
 * NO binding the in-memory limiter is used, which is per-isolate and therefore
 * NOT a correct production limiter — that is why it is only reached when the
 * operator has not bound the DO at all, and why `memory.ts` says so loudly.
 * Falling back to "no limiting whatsoever" would be worse: a misconfigured
 * deploy would silently serve unlimited traffic.
 */
export function limiterForEnv(env: RateLimitBindings): RateLimiter {
  const namespace = env.RATE_LIMIT;
  return namespace === undefined
    ? new InMemoryRateLimiter()
    : new DurableObjectRateLimiter(namespace);
}

/** Build the {@link QuotaSubject} for the authenticated caller, or `null`. */
export function subjectFor(c: Context<GatewayEnv>, perKeyLimit?: number): QuotaSubject | null {
  const auth = c.get("auth");
  if (auth === null || auth === undefined) return null;
  // Rust `request_windows()` returns an EMPTY vec when `api_key_id` is None, so
  // a credential with no key id is unlimited — not denied.
  const apiKeyId = auth.subject;
  if (apiKeyId === null || apiKeyId === "") return null;
  return {
    apiKeyId,
    chain: {
      tenantId: auth.tenancy.tenantId ?? undefined,
      projectId: auth.tenancy.projectId ?? undefined,
      workspaceId: auth.tenancy.workspaceId ?? undefined,
      keyId: apiKeyId,
    },
    requestLimitPerMinute: perKeyLimit,
  };
}

/** Turn a denial into the exact Rust `AuthError`, and attach `Retry-After` if asked. */
function refuse(
  outcome: Extract<RateLimitOutcome, { allowed: false }>,
  code: "rate_limit_exceeded" | "tpm_limit_exceeded",
  requestId: string,
  options: RateLimitOptions,
): never {
  const refusal = RATE_LIMIT_REFUSALS[code];
  const message =
    code === "rate_limit_exceeded"
      ? RATE_LIMIT_REFUSALS.rate_limit_exceeded.message(requestId)
      : RATE_LIMIT_REFUSALS.tpm_limit_exceeded.message();
  const error = new HttpError(refusal.status, refusal.code, message);
  if (options.retryAfterHeader === true) {
    // Opt-in only; Rust attaches no Retry-After. `HttpError` carries no header
    // bag, so the value rides along for a wrapper that wants to emit it.
    (error as HttpError & { retryAfterSeconds?: number }).retryAfterSeconds =
      outcome.retryAfterSeconds;
  }
  throw error;
}

/** Counter-backend failure → 503, never 429 (Rust `require_request_budget` `Err` arm). */
function unavailable(detail: string): never {
  const refusal = RATE_LIMIT_REFUSALS.governance_counter_unavailable;
  throw new HttpError(refusal.status, refusal.code, refusal.message(detail));
}

/**
 * The RPM + quota-denial guard.
 *
 * MUST be mounted AFTER `contractAuth`, because it reads `c.get("auth")` — a
 * request that is not authenticated yet has no scope chain to merge, and an
 * anonymous operation (`/healthz`) has none at all and passes straight through,
 * matching Rust (the RPM check lives inside `finalize_auth`, which anonymous
 * requests never enter).
 */
export function rateLimit(deps: RateLimitDeps = {}): MiddlewareHandler<GatewayEnv> {
  return async function rateLimitMiddleware(c, next) {
    const auth = c.get("auth");
    if (auth === null || auth === undefined) {
      await next();
      return;
    }

    // `src/ports.ts` is not this slice's to extend, so the extra bindings are
    // read structurally. See `RateLimitBindings`.
    const env = c.env as unknown as RateLimitBindings;
    const limiter =
      typeof deps.limiter === "function" ? deps.limiter(env) : (deps.limiter ?? limiterForEnv(env));
    const quotas =
      typeof deps.quotas === "function"
        ? deps.quotas(env)
        : (deps.quotas ?? quotaPolicySourceFromEnv(env));

    const subject = subjectFor(c, deps.perKeyRequestLimit?.(auth));
    if (subject === null) {
      await next();
      return;
    }

    const resolution = await resolveQuotaWindows(quotas, subject);
    if (!resolution.ok) {
      // Rust: a quota lookup failure is 503 `quota_resolution_unavailable`.
      throw new HttpError(
        503,
        "quota_resolution_unavailable",
        `quota policy lookup failed: ${resolution.detail}`,
      );
    }

    // 1. A disabled policy anywhere in the chain is a hard deny — 403, not 429.
    const deniedBy = resolution.quota.deniedBy;
    if (deniedBy !== undefined) {
      const refusal = RATE_LIMIT_REFUSALS.quota_scope_disabled;
      throw new HttpError(refusal.status, refusal.code, refusal.message(deniedBy));
    }

    // PORT-TODO(inventory-request-path §1.6 "Budgets"): steps 2 and 3 of
    // `finalize_auth` — `monthly_budget_exceeded` and `wallet_balance_exhausted`
    // — are the ONLY two of the five Rust admission gates still open here.
    //
    // CROSS-PACKAGE, not cross-platform. Everything on THIS side is built: the
    // counters (`RateLimiter.reserveTokenBudget` / `reserveWalletCredits`, both
    // with a release path since JS has no `Drop`), the refusals
    // (`RATE_LIMIT_REFUSALS.monthly_budget_exceeded` /
    // `wallet_balance_exhausted`) and the estimate they would be charged with
    // (`src/inference/estimate.ts`). What is missing is the BALANCE SOURCE:
    // Rust reads `sum_scope_committed_spend(scope, month)` and the prepaid
    // wallet row out of `ferrogate-storage`, and `@ferrogate/storage` has no
    // adapter on this seam yet.
    //
    // To close: add a `SpendSource` port next to `QuotaPolicySource` in
    // `./quota.ts` returning `{ committedSpendUsd, walletBalanceCredits }` for
    // the subject chain, back it with D1, and insert the two checks HERE — in
    // this order, before the RPM check, because Rust refuses on budget before
    // it spends a request from the window.
    //
    // Consequence while it is open: a key over its monthly budget, or a tenant
    // with an exhausted prepaid wallet, is NOT refused at admission. Step 5
    // (TPM) below and step 4 (RPM) still bound it, and metering still records
    // the spend — but the hard stop is absent.

    // 4. RPM.
    const outcome = await limiter.consumeRequest(resolution.rpm);
    if (outcome.allowed === "unavailable") unavailable(outcome.detail);
    if (!outcome.allowed) {
      refuse(outcome, "rate_limit_exceeded", c.get("requestId") ?? "", deps);
    }

    // Publish the resolved windows so the inference handlers can enforce TPM
    // without re-merging the chain (Rust resolves the quota ONCE in
    // `finalize_auth` and the handlers read `auth.effective_quota`).
    setResolvedWindows(c, { tpm: resolution.tpm, limiter, options: deps });
    await next();
  };
}

/**
 * The ZERO-EDIT wiring: `rateLimit` packaged as a {@link RouteModule}.
 *
 * `createGatewayApp` registers `app.use("*", contractAuth(...))` first, then
 * every module's `register()`, then the module's own routes. Hono runs matched
 * handlers in REGISTRATION order, so a module that registers a middleware in
 * its `register()` — and mounts no routes of its own — lands exactly where the
 * Rust check lives: after authentication, before the handlers.
 *
 * Put it FIRST in the module list so it precedes the routes of every other
 * module:
 *
 * ```ts
 * createGatewayApp({ modules: [rateLimitRouteModule(), ...GATEWAY_ROUTE_MODULES] })
 * ```
 *
 * Caveat, stated plainly: routes registered BEFORE the modules — `getHealthz`,
 * `getReadyz` and the seven 501 tooling stubs — are not covered by this form.
 * `getHealthz`/`getReadyz` are contract-`anonymous`, which the middleware skips
 * anyway, so only the tooling stubs differ, and they answer 501 without
 * touching an upstream. The `middleware` option described in `index.ts` covers
 * all 31 and is the preferred wiring; this exists so the limiter can be mounted
 * without touching the composition root at all.
 */
export function rateLimitRouteModule(deps: RateLimitDeps = {}): RouteModule {
  const middleware = rateLimit(deps);
  return {
    operationIds: [],
    register(router: GatewayRouter): void {
      router.app.use("*", middleware);
    },
  };
}

// ---------------------------------------------------------------------------
// TPM — enforced by the handler, after the estimate exists
// ---------------------------------------------------------------------------

/** What {@link rateLimit} leaves behind for {@link enforceTokensPerMinute}. */
export interface ResolvedWindows {
  readonly tpm: CounterWindow | null;
  readonly limiter: RateLimiter;
  readonly options: RateLimitOptions;
}

/**
 * Stashed on the Hono context under a symbol-like key rather than a typed
 * `Variables` field, because `GatewayVariables` in `src/ports.ts` belongs to the
 * composition root. The integrate step may promote it to a real variable.
 */
const RESOLVED_WINDOWS_KEY = "ferrogate.ratelimit.windows";

export function setResolvedWindows(c: Context<GatewayEnv>, windows: ResolvedWindows): void {
  (c as unknown as { set(k: string, v: unknown): void }).set(RESOLVED_WINDOWS_KEY, windows);
}

export function resolvedWindows(c: Context<GatewayEnv>): ResolvedWindows | undefined {
  return (c as unknown as { get(k: string): ResolvedWindows | undefined }).get(
    RESOLVED_WINDOWS_KEY,
  );
}

/** A TPM refusal, in the shape `inference/errors.ts` renders. */
export interface TokenAdmissionRefusal {
  readonly status: number;
  readonly code: string;
  readonly message: string;
  /**
   * Whole seconds until the denying window rolls, present only on the 429.
   * Whether it is EMITTED is still `RateLimitOptions.retryAfterHeader`'s
   * decision (Rust attaches no `Retry-After`); this only carries the value so
   * the opt-in wrapper has one.
   */
  readonly retryAfterSeconds?: number;
}

/**
 * Rust step 5 — the tokens-per-minute gate, charged with the PRE-DISPATCH
 * ESTIMATE, reported rather than thrown.
 *
 * This is the form the inference handlers use. They run inside the INNER Hono
 * app that `inferenceRouteModule` delegates into, and that app has no error
 * handler: an `HttpError` thrown there would be rendered as a 500 instead of
 * the Rust 429. So the refusal is RETURNED, and `handlers.ts` sends it through
 * the same `errorResponse` envelope as every other rejection.
 *
 * Three outcomes, matching the three Rust arms of
 * `try_consume_api_key_tokens_per_minute`:
 *
 *  - `null`   → `auth.tpm_window()` was `None`; nothing governs this request.
 *  - refusal  → `Ok(false)` is 429 `tpm_limit_exceeded`; `Err` is 503
 *               `governance_counter_unavailable`, never a 429 (a counter
 *               backend that is DOWN has not proven the caller is over limit).
 *  - handle   → `Ok(true)`, plus the settlement handle.
 */
export async function admitTokensPerMinute(
  c: Context<GatewayEnv>,
  estimatedTokens: number,
): Promise<TokenAdmission | TokenAdmissionRefusal | null> {
  const resolved = resolvedWindows(c);
  if (resolved === undefined || resolved.tpm === null) return null;
  const admission = await resolved.limiter.consumeTokens(resolved.tpm, estimatedTokens);
  if (admission.allowed === "unavailable") {
    const refusal = RATE_LIMIT_REFUSALS.governance_counter_unavailable;
    return {
      status: refusal.status,
      code: refusal.code,
      message: refusal.message(admission.detail),
    };
  }
  if (!admission.allowed) {
    const refusal = RATE_LIMIT_REFUSALS.tpm_limit_exceeded;
    return {
      status: refusal.status,
      code: refusal.code,
      message: refusal.message(),
      retryAfterSeconds: admission.retryAfterSeconds,
    };
  }
  return admission;
}

/** True for the {@link admitTokensPerMinute} arm that denies the request. */
export function isTokenAdmissionRefusal(
  value: TokenAdmission | TokenAdmissionRefusal | null,
): value is TokenAdmissionRefusal {
  return value !== null && "status" in value;
}

/**
 * Rust step 5 as a THROWING guard, for a caller that sits on the outer app and
 * wants the `HttpError` rendered by `onError`.
 *
 * Kept as the documented middleware-chain form and implemented on top of
 * {@link admitTokensPerMinute}, so the two forms cannot drift in what they
 * refuse — only in how they report it.
 *
 * Returns the admission handle for {@link settleTokenUsage}. A `null` return
 * means no TPM limit governs this request.
 */
export async function enforceTokensPerMinute(
  c: Context<GatewayEnv>,
  estimatedTokens: number,
): Promise<TokenAdmission | null> {
  const admitted = await admitTokensPerMinute(c, estimatedTokens);
  if (isTokenAdmissionRefusal(admitted)) {
    const error = new HttpError(admitted.status, admitted.code, admitted.message);
    // Opt-in only; Rust attaches no Retry-After. Same contract as `refuse`.
    if (
      resolvedWindows(c)?.options.retryAfterHeader === true &&
      admitted.retryAfterSeconds !== undefined
    ) {
      (error as HttpError & { retryAfterSeconds?: number }).retryAfterSeconds =
        admitted.retryAfterSeconds;
    }
    throw error;
  }
  return admitted;
}

/**
 * Reconcile a TPM admission against the response's real token usage.
 *
 * OPT-IN (`RateLimitOptions.settleTokens`): Rust never settles a TPM window, so
 * the default leaves the estimate charged and the port is byte-identical.
 * Safe to call unconditionally — it no-ops when disabled or when the admission
 * was not granted, and never throws.
 */
export async function settleTokenUsage(
  c: Context<GatewayEnv>,
  admission: TokenAdmission | null,
  actualTokens: number,
): Promise<void> {
  const resolved = resolvedWindows(c);
  if (resolved === undefined || admission === null) return;
  if (resolved.options.settleTokens !== true) return;
  await resolved.limiter.settleTokens(admission, actualTokens);
}
