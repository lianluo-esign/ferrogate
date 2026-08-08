/**
 * The ADMISSION half of Rust's `authenticate()` — a 1:1 port of
 * `crates/ferrogate-gateway/src/auth.rs::finalize_auth`, mounted on
 * `apps/mcp`.
 *
 * ## The defect this file closes
 *
 * In the Rust tree `POST /v1/mcp` and `POST /v1/mcp/tool/execute` shared a
 * process with `POST /v1/chat/completions`, so `finalize_auth` ran on all of
 * them: every successfully identified `AuthContext` was charged the quota
 * chain, the monthly budget, the prepaid wallet and the per-minute request
 * window BEFORE a tool could run. When that single process was split into five
 * Workers the admission half crossed into `apps/gateway` and nowhere else, so a
 * credential at its RPM ceiling and over its monthly budget was REFUSED on
 * `/v1/chat/completions` and ADMITTED on MCP `tools/call` — which reaches a
 * paid upstream and a paid asset pull. `docs/rewrite/CUTOVER-READINESS.md`
 * finding D1: "the exploit is call the other endpoint".
 *
 * ## The ladder, in Rust's order — and why the order is the control
 *
 *   1. quota chain resolution fails → **503** `quota_resolution_unavailable`
 *   2. `denied_by`                  → **403** `quota_scope_disabled`
 *   3. `monthly_budget_usd`         → **429** `monthly_budget_exceeded`
 *   4. wallet balance               → **429** `wallet_balance_exhausted`
 *   4b. wallet no-oversell reserve  → **429** `wallet_balance_exhausted`
 *   5. `request_windows()` (RPM)    → **429** `rate_limit_exceeded`
 *
 * Steps 2–4 run BEFORE the RPM check because a request refused for being over
 * budget must not also spend a slot from the RPM window: otherwise a caller
 * that is hard-denied anyway burns the budget of the requests that are still
 * allowed. Rust's order, kept deliberately.
 *
 * The gate runs AFTER the credential ladder in `src/auth.ts` (401 for an
 * unknown / disabled / revoked / expired key, 403 only for an authenticated
 * caller missing the operation's scope). That order is also the control: an
 * under-scoped caller must be refused without charging a counter.
 *
 * ## FAIL CLOSED, always
 *
 * Every lookup failure — the policy chain, the rollup, the wallet, the counter
 * backend — is a **503**, never an admit and never a 429. A backend outage has
 * not proven the caller is over limit, and a limiter that admitted everyone
 * during an outage would be a free-traffic hole rather than a graceful
 * degradation. `apps/gateway/src/ratelimit/quota.ts` argues the same posture
 * for the same reason; this matches it.
 */
import type { EffectiveQuota } from "@ferrogate/policy";
import type { TenantDatabaseRouter } from "@ferrogate/storage";

import { type McpRateLimiter, type RateLimiterNamespace, limiterForEnv } from "./counters.js";
import {
  NO_QUOTA_POLICIES,
  type QuotaPolicySource,
  type QuotaSubject,
  type SpendSource,
  type WalletHold,
  currentPeriodMonth,
  d1QuotaPolicySource,
  monthlyBudgetCharges,
  resolveQuotaWindows,
  spendSourceForTenant,
  tenantSpendResolver,
  walletHoldId,
} from "./quota.js";

/**
 * The refusal shape, identical to `src/ports.ts`'s `AuthError` so the gate's
 * answers travel the SAME rendering path as an authentication failure and reach
 * the client in the FerroGate error envelope.
 */
export interface AdmissionRefusal {
  readonly status: number;
  readonly code: string;
  readonly message: string;
}

/**
 * Every refusal this layer can produce, with the EXACT Rust status, code and
 * message. Sourced from `auth.rs::finalize_auth` and
 * `auth.rs::require_request_budget`.
 *
 * Rust attaches NO `Retry-After` to any of them — `write_json_error` writes
 * `content-type`, `content-length`, `x-request-id`, `x-trace-id`,
 * `x-ferrogate-runtime` and the CORS headers and nothing else — so none is
 * added here either.
 */
export const ADMISSION_REFUSALS = {
  /** `finalize_auth` — a policy anywhere in the chain is `enabled = false`. */
  quota_scope_disabled: (scopeKind: string): AdmissionRefusal => ({
    status: 403,
    code: "quota_scope_disabled",
    message: `quota policy at scope ${scopeKind} disables this request's tenant/project/workspace/key chain`,
  }),
  /** `finalize_auth` — monthly USD budget for the winning scope. */
  monthly_budget_exceeded: (): AdmissionRefusal => ({
    status: 429,
    code: "monthly_budget_exceeded",
    message: "quota policy monthly budget has been exhausted for this scope",
  }),
  /** `finalize_auth` / `WalletReservationOutcome::Insufficient` (issue #169). */
  wallet_balance_exhausted: (): AdmissionRefusal => ({
    status: 429,
    code: "wallet_balance_exhausted",
    message: "prepaid credit balance has been exhausted for this tenant",
  }),
  /** `require_request_budget` — the RPM denial. */
  rate_limit_exceeded: (requestId: string): AdmissionRefusal => ({
    status: 429,
    code: "rate_limit_exceeded",
    message: `API key request rate limit is exhausted for request ${requestId}`,
  }),
  /** Any quota/spend/wallet LOOKUP failure. 503, deliberately not 429. */
  quota_resolution_unavailable: (detail: string): AdmissionRefusal => ({
    status: 503,
    code: "quota_resolution_unavailable",
    message: detail,
  }),
  /** `require_request_budget` `Err(_)` — the counter backend itself failed. */
  governance_counter_unavailable: (detail: string): AdmissionRefusal => ({
    status: 503,
    code: "governance_counter_unavailable",
    message: `gateway counter backend is unavailable: ${detail}`,
  }),
} as const;

/**
 * The authenticated identity the gate reads, declared STRUCTURALLY so this
 * module does not import `src/ports.ts` (which imports it back).
 */
export interface AdmissionIdentity {
  readonly apiKeyId?: string | undefined;
  readonly organizationId?: string | undefined;
  readonly projectId?: string | undefined;
  readonly workspaceId?: string | undefined;
  /** TOK-12 `api_keys.request_limit_per_minute`, when the row carried one. */
  readonly requestLimitPerMinute?: number | undefined;
}

export type AdmissionOutcome =
  | {
      readonly ok: true;
      /**
       * Reservations this request took, which the caller MUST release. JS has
       * no `Drop`; Rust released these when the guard dropped.
       */
      readonly holds: readonly WalletHold[];
      /** The same resolved quota used by the admission ladder. */
      readonly egressQuota?: EffectiveQuota;
    }
  | { readonly ok: false; readonly error: AdmissionRefusal };

/** The seam `src/http.ts` codes against. */
export interface AdmissionPort {
  admit(identity: AdmissionIdentity, requestId: string): Promise<AdmissionOutcome>;
}

/**
 * A gate that admits everything.
 *
 * The honest name for "this deployment has no control database, so there is no
 * `quota_policies` table to read and no policy could have been configured". It
 * is NOT a fail-open on a lookup ERROR — those are 503 in {@link McpAdmissionGate}.
 */
export const ADMIT_ALL: AdmissionPort = {
  async admit(): Promise<AdmissionOutcome> {
    return { ok: true, holds: [] };
  },
};

/** Wiring for {@link McpAdmissionGate}. */
export interface McpAdmissionOptions {
  readonly limiter: McpRateLimiter;
  readonly quotas: QuotaPolicySource;
  /**
   * Per-tenant routing for the SPEND half. `undefined` ⇒ no tenant database is
   * reachable, so there is no recorded spend and no wallet — the same reading
   * an empty store gives.
   */
  readonly router?: TenantDatabaseRouter | undefined;
  /** Injected unix-SECONDS clock, so the period month is pinnable in tests. */
  readonly now?: () => number;
  /** Override the spend resolution (unit tests inject a stub source here). */
  readonly spendFor?: (
    tenantId: string,
  ) => Promise<{ ok: true; source: SpendSource } | { ok: false; detail: string }>;
}

export class McpAdmissionGate implements AdmissionPort {
  readonly #options: McpAdmissionOptions;
  readonly #now: () => number;

  constructor(options: McpAdmissionOptions) {
    this.#options = options;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  async admit(identity: AdmissionIdentity, requestId: string): Promise<AdmissionOutcome> {
    const apiKeyId = identity.apiKeyId ?? "";
    const tenantId = identity.organizationId ?? "";
    const subject: QuotaSubject = {
      apiKeyId,
      chain: {
        ...(identity.organizationId === undefined ? {} : { tenantId: identity.organizationId }),
        ...(identity.projectId === undefined ? {} : { projectId: identity.projectId }),
        ...(identity.workspaceId === undefined ? {} : { workspaceId: identity.workspaceId }),
        ...(apiKeyId === "" ? {} : { keyId: apiKeyId }),
      },
      requestLimitPerMinute: identity.requestLimitPerMinute,
    };

    // 1. The merged chain. A lookup failure is 503 — an outage has not proven
    //    anything about this caller's entitlement.
    const resolution = await resolveQuotaWindows(this.#options.quotas, subject);
    if (!resolution.ok) {
      return refuse(
        ADMISSION_REFUSALS.quota_resolution_unavailable(
          `quota policy lookup failed: ${resolution.detail}`,
        ),
      );
    }

    // 2. A disabled policy anywhere in the chain is a hard deny — 403, not 429.
    const deniedBy = resolution.quota.deniedBy;
    if (deniedBy !== undefined) return refuse(ADMISSION_REFUSALS.quota_scope_disabled(deniedBy));

    // The spend store is the TENANT's database, resolved once for both the
    // budget and the wallet legs.
    const spend =
      this.#options.spendFor !== undefined
        ? await this.#options.spendFor(tenantId)
        : await spendSourceForTenant(this.#options.router, tenantId);
    if (!spend.ok) {
      return refuse(ADMISSION_REFUSALS.quota_resolution_unavailable(spend.detail));
    }

    // 3. The monthly USD budget — EVERY rung of the nested ladder (#679), each
    //    against its own scope's aggregate rollup. Enforcing only the scope
    //    that won the chain's `min` left every ancestor cap unevaluated: a
    //    $100 key under a $5,000 project mins to $100, so the project's rollup
    //    was never read and its sibling keys could spend it dry unnoticed.
    for (const charge of monthlyBudgetCharges(resolution.quota, subject.chain)) {
      const spent = await spend.source.committedSpendUsd(
        charge.kind,
        charge.id,
        currentPeriodMonth(this.#now()),
      );
      if (!spent.ok) {
        return refuse(
          ADMISSION_REFUSALS.quota_resolution_unavailable(
            `monthly budget lookup failed: ${spent.detail}`,
          ),
        );
      }
      // `>=`, not `>`: Rust refuses AT the cap (`spent >= budget_usd`).
      if (spent.committedSpendUsd >= charge.limitUsd) {
        return refuse(ADMISSION_REFUSALS.monthly_budget_exceeded());
      }
    }

    // 4. Prepaid-credit wallet balance (issue #169) — enforced INDEPENDENTLY of
    //    the budget above: a wallet tracks money actually paid, while
    //    `monthly_budget_usd` is a configured throttle, so neither implies the
    //    other and a tenant can be denied by either alone.
    //
    //    Opt-in per tenant: a tenant with no wallet row is never denied, which
    //    is what keeps this purely additive for everyone who has not adopted
    //    prepaid billing.
    if (tenantId !== "") {
      const balance = await spend.source.walletBalanceCredits(tenantId);
      if (!balance.ok) {
        return refuse(
          ADMISSION_REFUSALS.quota_resolution_unavailable(
            `wallet balance lookup failed: ${balance.detail}`,
          ),
        );
      }
      // `<= 0` on the AVAILABLE balance (funded minus live holds), so a tenant
      // whose in-flight requests have already committed the balance is refused
      // here rather than admitted to race the ones already dispatched.
      if (balance.availableCredits !== null && balance.availableCredits <= 0) {
        return refuse(ADMISSION_REFUSALS.wallet_balance_exhausted());
      }
    }

    const holds: WalletHold[] = [];
    // 4b. THE NO-OVERSELL GUARD. Step 4 is a READ and cannot bound a race;
    //     `@ferrogate/storage`'s three-statement atomic batch puts the decision
    //     INSIDE the writing statement and therefore can. Both are kept: step 4
    //     bounds cumulative spend, this bounds concurrent overdraft.
    if (tenantId !== "") {
      const reserved = await spend.source.reserveWallet(
        tenantId,
        walletHoldId(requestId),
        this.#now(),
      );
      if (reserved.kind === "unavailable") {
        return refuse(
          ADMISSION_REFUSALS.quota_resolution_unavailable(
            `wallet reservation failed: ${reserved.detail}`,
          ),
        );
      }
      if (reserved.kind === "insufficient") {
        return refuse(ADMISSION_REFUSALS.wallet_balance_exhausted());
      }
      if (reserved.kind === "admitted") holds.push(reserved.hold);
    }

    // 5. RPM. Charged LAST so nothing above it can burn a slot from a window a
    //    refused request was never going to use.
    const outcome = await this.#options.limiter.consumeRequest(resolution.rpm);
    if (outcome.allowed === "unavailable") {
      await releaseAll(holds);
      return refuse(ADMISSION_REFUSALS.governance_counter_unavailable(outcome.detail));
    }
    if (!outcome.allowed) {
      // The refused request keeps no hold: releasing here is what stops a
      // rate-limited client from parking the whole wallet in reservations.
      await releaseAll(holds);
      return refuse(ADMISSION_REFUSALS.rate_limit_exceeded(requestId));
    }

    return { ok: true, holds, egressQuota: resolution.quota };
  }
}

function refuse(error: AdmissionRefusal): AdmissionOutcome {
  return { ok: false, error };
}

/** Release every hold, best effort. `release()` never throws (see `quota.ts`). */
export async function releaseAll(holds: readonly WalletHold[]): Promise<void> {
  for (const hold of holds) await hold.release();
}

/** Bindings {@link admissionFromEnv} reads. */
export interface AdmissionBindings {
  /** The CONTROL database — `quota_policies`, `plans`, `tenants`. */
  readonly DB?: D1Database | undefined;
  readonly BILLING_DB?: D1Database | undefined;
  readonly MCP_CONTROL_STORAGE?: string | undefined;
  readonly CONTROL_DATA?: DurableObjectNamespace | undefined;
  /** The SHARED `RateLimiterDurableObject` namespace (see `./counters.ts`). */
  readonly RATE_LIMIT?: RateLimiterNamespace | undefined;
}

/**
 * The gate the composition root gets.
 *
 * `env.DB` bound ⇒ the real ladder over `quota_policies` + the tenant-routed
 * spend store. No control database ⇒ {@link ADMIT_ALL}, because a deployment
 * with no `quota_policies` table has no configured policy to enforce — the same
 * argument `durableAuth` makes for `UnboundAuth` in the other direction, and
 * the reason binding `DB` can only ever TIGHTEN admission.
 */
export function admissionFromEnv(
  env: AdmissionBindings,
  router?: TenantDatabaseRouter,
): AdmissionPort {
  const db = controlDatabaseFrom(env);
  if (db === undefined) return ADMIT_ALL;
  return new McpAdmissionGate({
    limiter: limiterForEnv(env),
    quotas: d1QuotaPolicySource(db),
    ...(router === undefined ? {} : { router }),
    // The registry table is probed before the router is used, so a deployment
    // that has not applied the control migration admits (nothing is
    // provisioned) instead of answering 503 forever.
    spendFor: tenantSpendResolver(db, router),
  });
}

export { NO_QUOTA_POLICIES };
import { controlDatabaseFrom } from "../control-data";
