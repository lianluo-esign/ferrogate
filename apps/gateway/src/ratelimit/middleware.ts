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
 * Steps 1 THROUGH 4 are all what {@link rateLimit} does, in that order. Steps 2
 * and 3 need durable spend/balance reads, which arrive through the
 * {@link SpendSource} port in `./quota.ts`: `d1SpendSource` reads
 * `usage_monthly_rollups` (the winning scope's aggregate spend for the current
 * calendar month) and `wallets` minus the live `wallet_reservations` holds, all
 * out of the TENANT database the `DB` binding already points at. A deployment
 * with no `DB` bound gets `NO_SPEND_SOURCE`, which reports the same values an
 * empty store would — 0 spent, no wallet — so binding the database can only
 * tighten admission, never loosen it.
 *
 * ## The four guards this file MOUNTS, which existed and guarded nothing
 *
 * Everything above was already here. What follows was implemented, tested, and
 * had zero callers under `apps/` — the defect class
 * `docs/rewrite/parity-audit-storage.md` §4.1 names. Each is now called from the
 * chain below, and each has an assertion that fails when the call is removed
 * (`test/ratelimit/guards.test.ts`, `test/metering/usage-ledger.test.ts`):
 *
 *   3b. **wallet no-oversell** (`./wallet.ts` → `@ferrogate/storage`'s
 *       `D1WalletStore.reserveWalletCredits`) → 429 `wallet_balance_exhausted`.
 *       Step 3 is a READ and cannot bound a race; the storage guard puts the
 *       decision inside the writing statement and therefore can. Both are kept:
 *       step 3 bounds cumulative spend, 3b bounds concurrent overdraft.
 *   5.  **workflow-run budget pre-flight** (`./workflow.ts` →
 *       `@ferrogate/policy`'s `preflightWorkflowBudget`) → **402**
 *       `workflow_budget_exceeded`, matching `server/agent_runs.rs:756`.
 *   6.  **operator deny rules** (`./policy.ts` → `@ferrogate/policy`'s
 *       `BasicPolicyEngine`) → 403 with the rule's own code and message,
 *       matching `server/chat.rs:421`.
 *   5b. **`api_keys.monthly_token_budget`** (`./token-budget.ts` →
 *       `@ferrogate/storage`'s `sumApiKeyCommittedTokens` +
 *       `RateLimiter.reserveTokenBudget`) → 429 `token_budget_exceeded`,
 *       enforced in {@link admitTokensPerMinute} where the estimate exists.
 *
 * ## Holds are released in a `finally`, because JS has no `Drop`
 *
 * Steps 3b and 5b take RESERVATIONS, which Rust released when the guard was
 * dropped. Every hold taken during admission is pushed onto a per-request list
 * and released in the middleware's `finally`, so a request refused by a LATER
 * step — or one that throws anywhere in the chain — cannot strand credits or
 * token budget. The durable wallet hold additionally carries an
 * `expires_at_unix` (`WALLET_HOLD_TTL_SECONDS`), which is the second release
 * for the case a `finally` cannot cover: an isolate that dies mid-request.
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
import { type CounterWindow, tokenBudgetCounterKey } from "./keys.js";
import { InMemoryRateLimiter } from "./memory.js";
import {
  RATE_LIMIT_REFUSALS,
  type RateLimitOptions,
  type RateLimitOutcome,
  type RateLimiter,
  type TokenAdmission,
} from "./ports.js";
import {
  type PolicyBindings,
  type PolicyRuleSet,
  type PolicyRulesResolution,
  evaluatePolicyRules,
  policyRulesFromEnv,
} from "./policy.js";
import {
  type QuotaBindings,
  type QuotaPolicySource,
  type QuotaSubject,
  type SpendBindings,
  type SpendSource,
  currentPeriodMonth,
  monthlyBudgetScope,
  quotaPolicySourceFromEnv,
  resolveQuotaWindows,
  spendSourceFromEnv,
} from "./quota.js";
import {
  type TokenBudgetBindings,
  type TokenBudgetSource,
  tokenBudgetSourceFromEnv,
} from "./token-budget.js";
import {
  type WalletAdmission,
  type WalletAdmissionBindings,
  walletAdmissionFromEnv,
  walletHoldId,
} from "./wallet.js";
import {
  type WorkflowBudgetBindings,
  type WorkflowBudgetSource,
  type WorkflowStepDeclaration,
  preflightStep,
  workflowBudgetSourceFromEnv,
  workflowDeclarationFrom,
} from "./workflow.js";

/**
 * Bindings this module reads.
 *
 * Declared here rather than added to `src/ports.ts` `GatewayBindings` because
 * that file belongs to the composition root, not to this slice. The integrate
 * step should fold `RATE_LIMIT` into `GatewayBindings` when it wires the
 * middleware; until then {@link rateLimit} reads it through this structural
 * type. See the WIRING block in `index.ts`.
 */
export interface RateLimitBindings
  extends QuotaBindings,
    SpendBindings,
    WalletAdmissionBindings,
    TokenBudgetBindings,
    WorkflowBudgetBindings,
    PolicyBindings {
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
   * Override the spend/wallet source behind admission steps 2 and 3. Defaults
   * to {@link spendSourceFromEnv}, i.e. the tenant database when `DB` is bound.
   */
  readonly spend?: SpendSource | ((env: RateLimitBindings) => SpendSource);
  /**
   * Override the prepaid-wallet no-oversell guard (admission step 3b). Defaults
   * to {@link walletAdmissionFromEnv}, i.e. `@ferrogate/storage`'s
   * `D1WalletStore` on the tenant database when `DB` is bound.
   */
  readonly wallet?: WalletAdmission | ((env: RateLimitBindings) => WalletAdmission);
  /**
   * Override the `api_keys.monthly_token_budget` source (step 5b). Defaults to
   * {@link tokenBudgetSourceFromEnv}.
   */
  readonly tokenBudget?: TokenBudgetSource | ((env: RateLimitBindings) => TokenBudgetSource);
  /**
   * Override the workflow-run execution-budget source (step 5). Defaults to
   * {@link workflowBudgetSourceFromEnv}.
   */
  readonly workflowBudgets?:
    | WorkflowBudgetSource
    | ((env: RateLimitBindings) => WorkflowBudgetSource);
  /**
   * Override the operator deny rules (step 6). Defaults to
   * {@link policyRulesFromEnv}, i.e. the `GATEWAY_POLICY_RULES` var parsed with
   * `packages/config`'s own `policyRuleSchema`.
   */
  readonly policies?: PolicyRuleSet | ((env: RateLimitBindings) => PolicyRulesResolution);
  /**
   * Resolve the physical provider for a logical model, so a `providers`-scoped
   * deny rule names the provider the request would really have reached.
   *
   * Defaults to the SAME registry the dispatcher resolves against
   * (`modelsFromEnv`, i.e. `GATEWAY_PROVIDERS` / `GATEWAY_MODELS`), which is
   * what `src/index.ts` hands `inferenceRouteModule`. Overridable for the same
   * reason `guardrails()` takes the hook: a composition that injects its own
   * `ModelResolver` must be able to keep the two in agreement, and a policy
   * engine resolving against a DIFFERENT registry than the dispatcher would
   * deny (or fail to deny) on a provider nobody was going to call.
   */
  readonly providerForModel?: (model: string, env: RateLimitBindings) => string | undefined;
  /**
   * The clock the monthly-budget period key is derived from
   * (`AppState::current_period_month`). Injectable so a test can pin the
   * calendar month it seeds a rollup row for.
   */
  readonly nowUnixSeconds?: () => number;
  /**
   * OPTIONAL OVERRIDE for the TOK-12 per-credential `request_limit_per_minute`.
   *
   * This used to be the ONLY source of that cap, because `AuthContext` had no
   * field to carry it: `D1ApiKeyResolver` read `request_limit_per_minute` off
   * the `api_keys` row and dropped it, so in the deployed Worker the column was
   * inert and only the quota-policy chain limited a D1-resolved credential.
   * `AuthContext.requestLimitPerMinute` now exists and `subjectFor` reads it, so
   * the DEPLOYED path enforces the column with no hook injected at all.
   *
   * The hook survives for the two cases the credential row cannot answer:
   * a caller whose key state lives outside `api_keys` (the ratelimit harness
   * seeds limits by api-key id), and an operator override in front of the row.
   * It WINS when it returns a number, and falls back to the credential when it
   * returns `undefined` — so injecting it can only tighten or redirect, never
   * silently disable the row's own cap.
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

/**
 * Build the {@link QuotaSubject} for the authenticated caller, or `null`.
 *
 * `perKeyLimit` is the {@link RateLimitDeps.perKeyRequestLimit} override; when
 * it is `undefined` the cap comes off the CREDENTIAL
 * (`AuthContext.requestLimitPerMinute`, populated from the `api_keys` row by
 * `src/keys/resolver.ts`). `0` is a real Rust value — "refuse every request" —
 * so the fallback is written as an explicit `undefined` check and never as
 * `perKeyLimit || auth.requestLimitPerMinute`, which would silently upgrade a
 * `0` override into the row's own (larger) cap.
 */
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
    requestLimitPerMinute: perKeyLimit ?? auth.requestLimitPerMinute,
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
    const spend =
      typeof deps.spend === "function" ? deps.spend(env) : (deps.spend ?? spendSourceFromEnv(env));
    const wallet =
      typeof deps.wallet === "function"
        ? deps.wallet(env)
        : (deps.wallet ?? walletAdmissionFromEnv(env));
    const tokenBudget =
      typeof deps.tokenBudget === "function"
        ? deps.tokenBudget(env)
        : (deps.tokenBudget ?? tokenBudgetSourceFromEnv(env));
    const workflowBudgets =
      typeof deps.workflowBudgets === "function"
        ? deps.workflowBudgets(env)
        : (deps.workflowBudgets ?? workflowBudgetSourceFromEnv(env));
    const policyResolution: PolicyRulesResolution =
      typeof deps.policies === "function"
        ? deps.policies(env)
        : deps.policies !== undefined
          ? { ok: true, rules: deps.policies }
          : policyRulesFromEnv(env);
    // Unreadable deny rules refuse EVERYTHING (see `policy.ts`): a rule table
    // that cannot be parsed must not degrade to "no rules", because losing a
    // deny rule grants access. This is the one place in the limiter where fail
    // closed does not mean "configure nothing".
    if (!policyResolution.ok) {
      throw new HttpError(
        503,
        "policy_rules_unavailable",
        `operator policy rules could not be read: ${policyResolution.detail}`,
      );
    }

    // Read BEFORE the subject short-circuit: a credential with no api-key id is
    // unlimited by the quota chain (Rust `request_windows()` returns an empty
    // vec) but it still spends a workflow run's execution budget, and a
    // malformed declaration is a 400 whether or not a quota governs the caller.
    const declaration = workflowDeclarationFrom(c.req.raw.headers);
    if (declaration.kind === "invalid") {
      throw new HttpError(400, "invalid_workflow_declaration", declaration.detail);
    }
    const workflowStep = declaration.kind === "declared" ? declaration.step : null;

    const subject = subjectFor(c, deps.perKeyRequestLimit?.(auth));
    if (subject === null) {
      if (workflowStep !== null) {
        await enforceWorkflowBudget(
          workflowBudgets,
          workflowStep,
          auth.tenancy.tenantId ?? "",
          deps.nowUnixSeconds?.() ?? Math.floor(Date.now() / 1000),
        );
      }
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

    // 2. The monthly USD budget, measured against the scope that WON the
    //    chain's `min` (`finalize_auth` → `AppState::monthly_budget_exceeded`).
    //
    //    Both of the next two blocks run BEFORE the RPM check, in Rust's order:
    //    a request refused for being over budget must not also spend a slot
    //    from the RPM window, or a caller that is hard-denied anyway would burn
    //    the budget of the requests that are still allowed.
    const budgetUsd = resolution.quota.monthlyBudgetUsd;
    if (budgetUsd !== undefined) {
      const scope = monthlyBudgetScope(resolution.quota, subject.chain);
      // `null` = no attribution at all to measure spend against. Rust returns
      // `Ok(false)` there: nothing to compare, so nothing to refuse.
      if (scope !== null) {
        const spent = await spend.committedSpendUsd(
          scope.kind,
          scope.id,
          currentPeriodMonth(deps.nowUnixSeconds?.()),
        );
        if (!spent.ok) {
          // Rust: `Err` on the rollup read is 503, NOT a 429 — a storage
          // outage has not proven the caller is over budget.
          throw new HttpError(
            503,
            "quota_resolution_unavailable",
            `monthly budget lookup failed: ${spent.detail}`,
          );
        }
        // `>=`, not `>`: Rust refuses AT the cap (`spent >= budget_usd`).
        if (spent.committedSpendUsd >= budgetUsd) {
          const refusal = RATE_LIMIT_REFUSALS.monthly_budget_exceeded;
          throw new HttpError(refusal.status, refusal.code, refusal.message());
        }
      }
    }

    // 3. Prepaid-credit wallet balance (issue #169) — enforced INDEPENDENTLY of
    //    the budget above: a wallet tracks money actually paid, while
    //    `monthly_budget_usd` is a configured throttle, so neither implies the
    //    other and a tenant can be denied by either alone.
    //
    //    Opt-in per tenant: a tenant with no wallet row is never denied, which
    //    is what keeps this purely additive for everyone who has not adopted
    //    prepaid billing.
    //
    //    COST, stated because it is on the hot path: this is one D1 `batch()`
    //    per authenticated request that carries a tenant, whether or not that
    //    tenant has a wallet. Rust pays the same point lookup unconditionally
    //    in `finalize_auth` (issue #373 awaits `get_wallet` inline), so this is
    //    parity rather than a regression — but if it ever needs to be cheaper,
    //    the answer is a negative cache of "this tenant has no wallet" keyed on
    //    the isolate (the same shape as `src/keys/cache.ts`), NOT skipping the
    //    read, which would make the gate depend on request order.
    const walletTenantId = subject.chain.tenantId;
    if (walletTenantId !== undefined && walletTenantId !== "") {
      const balance = await spend.walletBalanceCredits(walletTenantId);
      if (!balance.ok) {
        throw new HttpError(
          503,
          "quota_resolution_unavailable",
          `wallet balance lookup failed: ${balance.detail}`,
        );
      }
      // `<= 0` on the AVAILABLE balance (funded minus live holds), so a tenant
      // whose in-flight requests have already committed the balance is refused
      // here rather than admitted to race the ones already dispatched.
      if (balance.availableCredits !== null && balance.availableCredits <= 0) {
        const refusal = RATE_LIMIT_REFUSALS.wallet_balance_exhausted;
        throw new HttpError(refusal.status, refusal.code, refusal.message());
      }
    }

    /**
     * Every reservation this request took, released in the `finally` below.
     *
     * The list is the TS stand-in for Rust's `Drop`: from here on the chain can
     * refuse (a later guard), throw (a handler), or complete, and in all three
     * cases the holds go back. Nothing after this point may `return` without
     * passing through the `finally`.
     */
    const holds: { release(): Promise<void> }[] = [];
    try {
      // 3b. THE NO-OVERSELL GUARD — `@ferrogate/storage`'s `D1WalletStore`
      //     three-statement atomic batch, whose predicate lives INSIDE the
      //     INSERT. Step 3 above is a read and cannot bound a race; this can,
      //     and it is the only thing here that can. See `./wallet.ts`.
      if (walletTenantId !== undefined && walletTenantId !== "") {
        const requestId = c.get("requestId") ?? "";
        const reserved = await wallet.reserve(
          walletTenantId,
          walletHoldId(requestId),
          deps.nowUnixSeconds?.() ?? Math.floor(Date.now() / 1000),
        );
        if (reserved.kind === "unavailable") {
          // An outage has not proven the caller is overdrawn: 503, never 429.
          throw new HttpError(
            503,
            "quota_resolution_unavailable",
            `wallet reservation failed: ${reserved.detail}`,
          );
        }
        if (reserved.kind === "insufficient") {
          const refusal = RATE_LIMIT_REFUSALS.wallet_balance_exhausted;
          throw new HttpError(refusal.status, refusal.code, refusal.message());
        }
        if (reserved.kind === "admitted") holds.push(reserved.hold);
      }

      // 4. RPM.
      const outcome = await limiter.consumeRequest(resolution.rpm);
      if (outcome.allowed === "unavailable") unavailable(outcome.detail);
      if (!outcome.allowed) {
        refuse(outcome, "rate_limit_exceeded", c.get("requestId") ?? "", deps);
      }

      // 5. Workflow-run execution budget, zero proposed spend — which still
      //    decides `exhausted` and `wall_clock` completely. The token dimension
      //    is re-checked in `admitTokensPerMinute`, where an estimate exists.
      if (workflowStep !== null) {
        await enforceWorkflowBudget(
          workflowBudgets,
          workflowStep,
          subject.chain.tenantId ?? "",
          deps.nowUnixSeconds?.() ?? Math.floor(Date.now() / 1000),
        );
      }

      // 6. Operator deny rules (`[[policies]]`) — 403 with the RULE's own code
      //    and message, exactly as `server/chat.rs:421` renders them. After the
      //    quota chain, matching Rust: the policy check lives in the handler,
      //    downstream of `finalize_auth`.
      const decision = await evaluatePolicyRules(c, auth, policyResolution.rules, {
        ...(deps.providerForModel === undefined
          ? {}
          : {
              providerForModel: (model: string, e: unknown) =>
                deps.providerForModel?.(model, e as RateLimitBindings),
            }),
      });
      if (decision.kind === "deny") {
        throw new HttpError(403, decision.code, decision.message);
      }

      // Publish the resolved windows so the inference handlers can enforce TPM
      // without re-merging the chain (Rust resolves the quota ONCE in
      // `finalize_auth` and the handlers read `auth.effective_quota`).
      setResolvedWindows(c, {
        tpm: resolution.tpm,
        limiter,
        options: deps,
        holds,
        tokenBudget,
        apiKeyId: subject.apiKeyId,
        tenantId: subject.chain.tenantId,
        ...(workflowStep === null
          ? {}
          : { workflow: { source: workflowBudgets, step: workflowStep } }),
        nowUnixSeconds: deps.nowUnixSeconds,
      });
      await next();
    } finally {
      // Rust released these when the guard dropped; JS has no destructor, so
      // this is the release. `release()` never throws (see `./wallet.ts` and
      // `do-limiter.ts::releaseOnce`), so a settlement problem cannot turn an
      // already-served response into a 500.
      for (const hold of holds) {
        await hold.release();
      }
    }
  };
}

/**
 * Step 5 — the durable workflow-run envelope, pre-flighted with a zero spend.
 *
 * Refuses with **402 `workflow_budget_exceeded`** and the denial's own message,
 * matching `server/agent_runs.rs:756` (`StatusCode::PAYMENT_REQUIRED`) rather
 * than inventing a status. A lookup failure is 503: an unreadable envelope has
 * not proven the run is exhausted, and admitting on it would be the free-spend
 * direction.
 */
async function enforceWorkflowBudget(
  source: WorkflowBudgetSource,
  step: WorkflowStepDeclaration,
  tenantId: string,
  nowUnixSeconds: number,
): Promise<void> {
  const lookup = await source.forStep(step, tenantId);
  if (lookup.kind === "unavailable") {
    throw new HttpError(
      503,
      "workflow_budget_unavailable",
      `workflow run budget lookup failed: ${lookup.detail}`,
    );
  }
  if (lookup.kind === "unbudgeted") return;
  const preflight = preflightStep(lookup.budget, 0, 0, 0, nowUnixSeconds);
  if (!preflight.ok) {
    throw new HttpError(402, "workflow_budget_exceeded", preflight.denial.message);
  }
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
  /**
   * The request's live reservation list, owned by `rateLimit`'s `finally`.
   *
   * {@link admitTokensPerMinute} pushes the monthly-token-budget hold onto it
   * rather than releasing it itself, because a hold taken deep inside the
   * handler must survive until the handler is done and must be freed even when
   * the handler throws. Optional so a caller that builds windows by hand (a
   * unit test) is not forced to invent one.
   */
  readonly holds?: { release(): Promise<void> }[] | undefined;
  /** `api_keys.monthly_token_budget` + the committed sum (step 5b). */
  readonly tokenBudget?: TokenBudgetSource | undefined;
  /** The credential the budget is charged to. */
  readonly apiKeyId?: string | undefined;
  readonly tenantId?: string | undefined;
  /** The declared workflow run, when the request carries one (step 5). */
  readonly workflow?:
    | { readonly source: WorkflowBudgetSource; readonly step: WorkflowStepDeclaration }
    | undefined;
  readonly nowUnixSeconds?: (() => number) | undefined;
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
/**
 * Step 5b — `api_keys.monthly_token_budget`, the loop this wave closed.
 *
 * `RateLimiter.reserveTokenBudget` and
 * `D1UsageLedger.sumApiKeyCommittedTokens` both existed with tests and no
 * caller, because nothing produced a `committed` count. `./token-budget.ts`
 * supplies it, `../metering/usage-ledger.ts` grows it, and this is the call.
 *
 * Returns `null` when nothing governs the request, or a refusal. The hold, when
 * one is taken, goes onto the request's release list — NOT released here: the
 * budget must stay held for the whole request, or two concurrent calls from one
 * key each see the other's tokens as un-reserved and both are admitted past the
 * cap.
 */
async function admitMonthlyTokenBudget(
  resolved: ResolvedWindows,
  estimatedTokens: number,
): Promise<TokenAdmissionRefusal | null> {
  const source = resolved.tokenBudget;
  const apiKeyId = resolved.apiKeyId;
  if (source === undefined || apiKeyId === undefined || apiKeyId === "") return null;

  const reading = await source.forApiKey(apiKeyId, resolved.tenantId);
  if (!reading.ok) {
    const refusal = RATE_LIMIT_REFUSALS.governance_counter_unavailable;
    return { status: refusal.status, code: refusal.code, message: refusal.message(reading.detail) };
  }
  if (reading.budget === undefined) return null;

  // SECURITY: the counter key comes from `keys.ts`, which routes every
  // derivation through `@ferrogate/policy`'s `QuotaScopeSelector.counterKey`
  // and asserts the result is scope-namespaced. Re-deriving it here — even as
  // the bare api-key id, which is what Rust used — is how a tenant that mints a
  // virtual key named `tenant:<victim>` collides another tenant's aggregate
  // window. `test/ratelimit/keys.test.ts` holds that attack.
  const outcome = await resolved.limiter.reserveTokenBudget(
    tokenBudgetCounterKey(apiKeyId),
    reading.committedTokens,
    reading.budget,
    estimatedTokens,
  );
  if (outcome.outcome === "unavailable") {
    const refusal = RATE_LIMIT_REFUSALS.governance_counter_unavailable;
    return { status: refusal.status, code: refusal.code, message: refusal.message(outcome.detail) };
  }
  if (outcome.outcome === "insufficient") {
    const refusal = RATE_LIMIT_REFUSALS.token_budget_exceeded;
    return { status: refusal.status, code: refusal.code, message: refusal.message() };
  }
  if (outcome.outcome === "reserved") {
    resolved.holds?.push(outcome.reservation);
  }
  return null;
}

/** Step 5c — the workflow envelope's token dimension, with the real estimate. */
async function admitWorkflowTokens(
  resolved: ResolvedWindows,
  estimatedTokens: number,
): Promise<TokenAdmissionRefusal | null> {
  const workflow = resolved.workflow;
  if (workflow === undefined) return null;

  const nowUnix = resolved.nowUnixSeconds?.() ?? Math.floor(Date.now() / 1000);
  const lookup = await workflow.source.forStep(workflow.step, resolved.tenantId ?? "");
  if (lookup.kind === "unavailable") {
    return {
      status: 503,
      code: "workflow_budget_unavailable",
      message: `workflow run budget lookup failed: ${lookup.detail}`,
    };
  }
  if (lookup.kind === "unbudgeted") return null;

  const preflight = preflightStep(lookup.budget, 0, estimatedTokens, 0, nowUnix);
  if (preflight.ok) return null;
  return { status: 402, code: "workflow_budget_exceeded", message: preflight.denial.message };
}

export async function admitTokensPerMinute(
  c: Context<GatewayEnv>,
  estimatedTokens: number,
): Promise<TokenAdmission | TokenAdmissionRefusal | null> {
  const resolved = resolvedWindows(c);
  if (resolved === undefined) return null;

  // 5b. `api_keys.monthly_token_budget` (#330). Checked BEFORE the TPM window
  //     because it is the harder limit — a caller over its lifetime budget is
  //     refused outright, not throttled — and because Rust decides it upstream
  //     of the handler (`authenticate_durable` / `try_reserve_api_key_tokens`).
  const budgetRefusal = await admitMonthlyTokenBudget(resolved, estimatedTokens);
  if (budgetRefusal !== null) return budgetRefusal;

  // 5c. The workflow envelope's TOKEN dimension, now that an estimate exists.
  //     The middleware pre-flighted the same envelope with a zero spend, which
  //     could only decide `exhausted` and `wall_clock`; this is the step that
  //     refuses a run about to breach `token_budget` — before the provider is
  //     paid, which is the whole point of pre-flighting at all.
  const workflowRefusal = await admitWorkflowTokens(resolved, estimatedTokens);
  if (workflowRefusal !== null) return workflowRefusal;

  if (resolved.tpm === null) return null;
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
