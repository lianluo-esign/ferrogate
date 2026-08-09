/**
 * The ADMISSION LADDER — the half of Rust's `authenticate()` that was dropped
 * when the monolith became five Workers.
 *
 * ## Rust, verbatim
 *
 * `crates/ferrogate-gateway/src/auth.rs::finalize_auth` runs, in this order and
 * with these exact statuses and codes:
 *
 *   1. `denied_by`               → **403** `quota_scope_disabled`
 *   2. `monthly_budget_usd`      → 429 `monthly_budget_exceeded`
 *   3. wallet balance            → 429 `wallet_balance_exhausted`
 *   4. `request_windows()` (RPM) → 429 `rate_limit_exceeded`
 *
 * …and every lookup failure along the way is a **503**, never an admission and
 * never a 429: `quota_resolution_unavailable` for the policy/spend/wallet reads,
 * `governance_counter_unavailable` for the counter backend. A storage outage has
 * not proven the caller is over budget, and a limiter that admitted everyone
 * during an outage would be a free-traffic hole rather than graceful
 * degradation.
 *
 * The identity gates that come BEFORE this ladder in Rust — `403
 * tenant_identity_required` and the lifecycle-suspension check — were already
 * ported onto this Worker (`../middleware/auth.ts`: `tenant_scope_denied` and
 * the `tenancy_suspended` arm of `ApiKeyResolution`). What was missing was
 * MONEY AND RATE, which is what this file adds.
 *
 * ## Step 3b, which Rust could not have
 *
 * Between 3 and 4 sits the prepaid-wallet NO-OVERSELL reservation
 * (`./wallet.ts` → `@ferrogate/storage`'s `D1WalletStore`). Step 3 is a READ and
 * cannot bound a race; the storage guard puts the decision inside the writing
 * statement and therefore can. Rust closed the same race with Postgres
 * `SELECT … FOR UPDATE`, which D1 does not have. Both are kept: 3 bounds
 * cumulative spend, 3b bounds concurrent overdraft.
 *
 * ## Holds are released by the caller, because JS has no `Drop`
 *
 * Step 3b takes a RESERVATION, which Rust released when the guard dropped.
 * Every hold taken here is returned on the {@link AdmissionGrant} and released
 * by `contractAuth`'s `finally`, so a request refused by a LATER step — or one
 * that throws anywhere downstream — cannot strand credits. A refusal raised
 * INSIDE this file releases before it throws. The durable hold additionally
 * carries an `expires_at_unix`, which is the second release for the case a
 * `finally` cannot cover: an isolate that dies mid-request.
 */
import type { QuotaScopeChain } from "@ferrogate/policy";
import type { TenantDatabaseRouter } from "@ferrogate/storage";

import { HttpError } from "../middleware/errors.js";
import type { AuthContext } from "../ports.js";
import { type CounterBindings, type RequestCounter, counterFromEnv } from "./counter.js";
import {
  type QuotaBindings,
  type QuotaPolicySource,
  type QuotaSubject,
  type SpendBindings,
  type SpendSource,
  currentPeriodMonth,
  monthlyBudgetCharges,
  quotaPolicySourceFromEnv,
  resolveQuotaWindows,
  routedSpendSource,
  spendSourceFromEnv,
} from "./quota.js";
import {
  type WalletAdmission,
  type WalletAdmissionBindings,
  type WalletHold,
  routedWalletAdmission,
  walletAdmissionFromEnv,
  walletHoldId,
} from "./wallet.js";

/**
 * Every refusal this ladder can produce, with the EXACT Rust status, code and
 * message. Sourced from `auth.rs::finalize_auth` and
 * `auth.rs::require_request_budget`.
 *
 * Rust attaches NO `Retry-After` to any of them (`write_json_error` writes
 * `content-type`, `content-length`, `x-request-id`, `x-trace-id`,
 * `x-ferrogate-runtime` and the CORS headers, and nothing else), so none is
 * attached here either.
 */
export const ADMISSION_REFUSALS = {
  /** A policy anywhere in the chain is `enabled = false`. A DENY, not a throttle. */
  quota_scope_disabled: {
    status: 403,
    code: "quota_scope_disabled",
    message: (scopeKind: string): string =>
      `quota policy at scope ${scopeKind} disables this request's tenant/project/workspace/key chain`,
  },
  monthly_budget_exceeded: {
    status: 429,
    code: "monthly_budget_exceeded",
    message: (): string => "quota policy monthly budget has been exhausted for this scope",
  },
  wallet_balance_exhausted: {
    status: 429,
    code: "wallet_balance_exhausted",
    message: (): string => "prepaid credit balance has been exhausted for this tenant",
  },
  rate_limit_exceeded: {
    status: 429,
    code: "rate_limit_exceeded",
    message: (requestId: string): string =>
      `API key request rate limit is exhausted for request ${requestId}`,
  },
  /** Any policy/spend/wallet lookup failure. 503, deliberately NOT 429. */
  quota_resolution_unavailable: {
    status: 503,
    code: "quota_resolution_unavailable",
    message: (detail: string): string => detail,
  },
  /** The counter backend itself failed — Rust's `require_request_budget` `Err(_)`. */
  governance_counter_unavailable: {
    status: 503,
    code: "governance_counter_unavailable",
    message: (detail: string): string => `gateway counter backend is unavailable: ${detail}`,
  },
} as const;

/** What admission needs to know about the request. */
export interface AdmissionRequest {
  readonly auth: AuthContext;
  /** Interpolated into the Rust `rate_limit_exceeded` message, and the hold id. */
  readonly requestId: string;
}

/** The holds an admitted request is carrying. */
export interface AdmissionGrant {
  /** Release every hold. Idempotent, never throws. */
  release(): Promise<void>;
}

/**
 * The port `../middleware/auth.ts` codes against.
 *
 * `admit` RESOLVES for an admitted request and THROWS an {@link HttpError} for
 * a refused one, which is how every other gate on this Worker reports. A
 * refusal has already released whatever it took.
 */
export interface AdmissionPort {
  admit(request: AdmissionRequest): Promise<AdmissionGrant>;
}

/** No holds were taken. */
const NO_HOLDS: AdmissionGrant = {
  async release(): Promise<void> {
    // Nothing to release.
  },
};

/** Wrap the wallet holds in a release-once grant (Rust's `released: bool`). */
function grantFor(holds: readonly WalletHold[]): AdmissionGrant {
  if (holds.length === 0) return NO_HOLDS;
  let released = false;
  return {
    async release(): Promise<void> {
      if (released) return;
      released = true;
      for (const hold of holds) await hold.release();
    },
  };
}

/** Bindings the whole ladder reads. */
export interface AdmissionBindings
  extends QuotaBindings,
    SpendBindings,
    WalletAdmissionBindings,
    CounterBindings {}

/** Wiring for {@link admissionFromEnv}. Every field has a runnable default. */
export interface AdmissionDeps {
  readonly quotas?: QuotaPolicySource;
  readonly spend?: SpendSource;
  readonly wallet?: WalletAdmission;
  readonly counter?: RequestCounter;
  readonly nowUnixSeconds?: () => number;
  /**
   * The per-tenant Durable Object router (#821). Present ⇒ the MONEY legs — the
   * monthly-budget rollups and the prepaid wallet, both {@link SpendSource} and
   * the no-oversell guard — route to the CALLER tenant's own object rather than
   * the shared `env.DB`, exactly as `apps/gateway`'s admission does. Absent ⇒
   * the `env.DB` fallback below, which is the `"off"`/no-`TENANT_DATA` posture.
   *
   * An injected `spend`/`wallet` still WINS over the router, so a test can pin
   * either leg without providing a routable object.
   */
  readonly router?: TenantDatabaseRouter;
}

/**
 * Project the authenticated caller into a {@link QuotaSubject}.
 *
 * `keyId` is left UNDEFINED for a credential that carries no api-key id, so the
 * chain is merged without a key scope and no RPM window is derived — Rust's
 * `request_windows()` returns an EMPTY vec when `api_key_id` is `None`, i.e.
 * such a credential is UNLIMITED by the chain, not denied. The budget and
 * wallet gates below still apply to it, because `finalize_auth` runs them off
 * `tenant_context()` and never consults the key id.
 */
export function subjectFor(auth: AuthContext): QuotaSubject {
  const apiKeyId = auth.subject ?? "";
  const chain: QuotaScopeChain = {
    ...(auth.tenancy.tenantId ? { tenantId: auth.tenancy.tenantId } : {}),
    ...(auth.tenancy.projectId ? { projectId: auth.tenancy.projectId } : {}),
    ...(auth.tenancy.workspaceId ? { workspaceId: auth.tenancy.workspaceId } : {}),
    ...(apiKeyId === "" ? {} : { keyId: apiKeyId }),
  };
  return {
    apiKeyId,
    chain,
    // `0` is a real Rust value — "refuse every request" — so this is an
    // explicit `undefined` check and never `a ?? b`, which would silently
    // upgrade a `0` cap into "no cap".
    requestLimitPerMinute: auth.requestLimitPerMinute,
  };
}

/** Build the refusal for a code in {@link ADMISSION_REFUSALS}. */
function refuse(refusal: { status: number; code: string }, message: string): HttpError {
  return new HttpError(refusal.status, refusal.code, message);
}

/**
 * The ladder itself.
 *
 * Written as a free function over its four ports so a test can drive any single
 * step in isolation, and so the composition in {@link admissionFromEnv} is the
 * only place that names a binding.
 */
export function admissionPort(
  deps: AdmissionDeps & { readonly env: AdmissionBindings },
): AdmissionPort {
  const quotas = deps.quotas ?? quotaPolicySourceFromEnv(deps.env);
  const counter = deps.counter ?? counterFromEnv(deps.env);
  const now = deps.nowUnixSeconds ?? ((): number => Math.floor(Date.now() / 1000));
  const router = deps.router;
  // The `env.DB` fallbacks, kept for the `"off"`/no-`TENANT_DATA` posture (and
  // for a credential that carries no tenant to route on). Reading them here is
  // also what keeps the `env.DB` binding declared-and-read.
  const legacySpend = deps.spend ?? spendSourceFromEnv(deps.env);
  const legacyWallet = deps.wallet ?? walletAdmissionFromEnv(deps.env);

  return {
    async admit({ auth, requestId }: AdmissionRequest): Promise<AdmissionGrant> {
      const subject = subjectFor(auth);

      // The MONEY legs route to the CALLER tenant's own object when a router is
      // bound and the subject carries a tenant. An injected `spend`/`wallet`
      // still wins (a test pinning either leg). A tenant-less credential and a
      // no-router deployment both fall back to the shared `env.DB` legs.
      const callerTenantId = subject.chain.tenantId;
      const routeMoney =
        router !== undefined && callerTenantId !== undefined && callerTenantId !== "";
      const spend =
        deps.spend ?? (routeMoney ? routedSpendSource(router, callerTenantId) : legacySpend);
      const wallet =
        deps.wallet ?? (routeMoney ? routedWalletAdmission(router) : legacyWallet);

      const resolution = await resolveQuotaWindows(quotas, subject);
      if (!resolution.ok) {
        throw refuse(
          ADMISSION_REFUSALS.quota_resolution_unavailable,
          `quota policy lookup failed: ${resolution.detail}`,
        );
      }

      // 1. A disabled policy anywhere in the chain is a hard deny — 403, not 429.
      const deniedBy = resolution.quota.deniedBy;
      if (deniedBy !== undefined) {
        throw refuse(
          ADMISSION_REFUSALS.quota_scope_disabled,
          ADMISSION_REFUSALS.quota_scope_disabled.message(deniedBy),
        );
      }

      // 2. The monthly USD budget — EVERY rung of the nested ladder (#679),
      //    each against its own scope's aggregate rollup. Enforcing only the
      //    scope that won the chain's `min` left every ancestor cap
      //    unevaluated: a $100 key under a $5,000 project mins to $100, so the
      //    project's rollup was never read and its sibling keys could spend it
      //    dry unnoticed.
      //
      //    BEFORE the RPM check, in Rust's order: a request refused for being
      //    over budget must not also spend a slot from the RPM window, or a
      //    caller that is hard-denied anyway would burn the budget of the
      //    requests that are still allowed.
      for (const charge of monthlyBudgetCharges(resolution.quota, subject.chain)) {
        const spent = await spend.committedSpendUsd(
          charge.kind,
          charge.id,
          currentPeriodMonth(now()),
        );
        if (!spent.ok) {
          throw refuse(
            ADMISSION_REFUSALS.quota_resolution_unavailable,
            `monthly budget lookup failed: ${spent.detail}`,
          );
        }
        // `>=`, not `>`: Rust refuses AT the cap (`spent >= budget_usd`).
        if (spent.committedSpendUsd >= charge.limitUsd) {
          throw refuse(
            ADMISSION_REFUSALS.monthly_budget_exceeded,
            ADMISSION_REFUSALS.monthly_budget_exceeded.message(),
          );
        }
      }

      // 3. Prepaid-credit wallet balance (issue #169) — enforced INDEPENDENTLY
      //    of the budget above: a wallet tracks money actually paid, while
      //    `monthly_budget_usd` is a configured throttle, so neither implies the
      //    other and a tenant can be denied by either alone. Opt-in per tenant:
      //    a tenant with no wallet row is never denied.
      const tenantId = subject.chain.tenantId;
      if (tenantId !== undefined && tenantId !== "") {
        const balance = await spend.walletBalanceCredits(tenantId);
        if (!balance.ok) {
          throw refuse(
            ADMISSION_REFUSALS.quota_resolution_unavailable,
            `wallet balance lookup failed: ${balance.detail}`,
          );
        }
        // `<= 0` on the AVAILABLE balance (funded minus live holds), so a
        // tenant whose in-flight requests have already committed the balance is
        // refused here rather than admitted to race the ones already dispatched.
        if (balance.availableCredits !== null && balance.availableCredits <= 0) {
          throw refuse(
            ADMISSION_REFUSALS.wallet_balance_exhausted,
            ADMISSION_REFUSALS.wallet_balance_exhausted.message(),
          );
        }
      }

      const holds: WalletHold[] = [];
      try {
        // 3b. THE NO-OVERSELL GUARD — `@ferrogate/storage`'s `D1WalletStore`
        //     three-statement atomic batch, whose predicate lives INSIDE the
        //     INSERT. Step 3 is a read and cannot bound a race; this can.
        if (tenantId !== undefined && tenantId !== "") {
          const reserved = await wallet.reserve(tenantId, walletHoldId(requestId), now());
          if (reserved.kind === "unavailable") {
            // An outage has not proven the caller is overdrawn: 503, never 429.
            throw refuse(
              ADMISSION_REFUSALS.quota_resolution_unavailable,
              `wallet reservation failed: ${reserved.detail}`,
            );
          }
          if (reserved.kind === "insufficient") {
            throw refuse(
              ADMISSION_REFUSALS.wallet_balance_exhausted,
              ADMISSION_REFUSALS.wallet_balance_exhausted.message(),
            );
          }
          if (reserved.kind === "admitted") holds.push(reserved.hold);
        }

        // 4. RPM. Windows are charged in order; the first denial short-circuits.
        const outcome = await counter.consumeRequest(resolution.rpm);
        if (outcome.allowed === "unavailable") {
          throw refuse(
            ADMISSION_REFUSALS.governance_counter_unavailable,
            ADMISSION_REFUSALS.governance_counter_unavailable.message(outcome.detail),
          );
        }
        if (!outcome.allowed) {
          throw refuse(
            ADMISSION_REFUSALS.rate_limit_exceeded,
            ADMISSION_REFUSALS.rate_limit_exceeded.message(requestId),
          );
        }
      } catch (error) {
        // A refusal (or any throw) after a hold was taken must give it back
        // before the response leaves. The caller's `finally` cannot: it never
        // receives a grant for a request that was refused here.
        await grantFor(holds).release();
        throw error;
      }

      return grantFor(holds);
    },
  };
}

/**
 * The {@link AdmissionPort} `resolveDeps` installs.
 *
 * Every source is chosen by which binding exists, and every one of them fails
 * CLOSED: `CONTROL_DB` absent ⇒ the dev var; `DB` absent ⇒ the readings an
 * EMPTY store would give (0 spent, no wallet — so binding the database can only
 * tighten); `RATE_LIMIT` absent ⇒ the per-isolate counter rather than no
 * counting at all.
 */
export function admissionFromEnv(env: AdmissionBindings, deps: AdmissionDeps = {}): AdmissionPort {
  return admissionPort({ ...deps, env });
}
