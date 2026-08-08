/**
 * The admission ladder, re-applied OFF the request path (#698, slice 2/3).
 *
 * ## Why this file has to exist at all
 *
 * `rateLimit()` (src/ratelimit/middleware.ts) is Hono middleware. It reads the
 * `AuthContext` off a `Context`, resolves the tenant database off a `Context`,
 * and throws `HttpError` at a client that is waiting. A batch executor has no
 * `Context` and no client, so NONE of it is callable — and yet a batch line is
 * the same paid provider call the middleware exists to govern. Executing 50,000
 * of them with no budget gate would make `/v1/batches` the one door in the
 * gateway through which a tenant can spend without limit, which is the exact
 * inverse of what #698 is for ("with our own governance, metering and budget
 * enforcement").
 *
 * So the ladder is COMPOSED here from the same primitives the middleware uses —
 * `quotaPolicySourceFromEnv` → `resolveQuotaWindows` → `monthlyBudgetCharges` →
 * `SpendSource.committedSpendUsd`, plus the wallet reading and `#681`'s
 * residency gate — against the scope chain persisted on the batch row when it
 * was created.
 *
 * ## What is deliberately NOT re-applied, and why
 *
 * - **RPM/TPM windows.** They are a per-minute admission device for interactive
 *   traffic; a batch is asynchronous by definition and its throughput is bounded
 *   instead by `DEFAULT_MAX_LINES_PER_TICK` (`../batch/executor.ts`, a constant
 *   and deliberately not an env var — there is no deployment-time reason to
 *   raise it and a wrong value costs paid provider calls) plus
 *   `GATEWAY_BATCH_SWEEP_LIMIT` and the queue's own concurrency. Consuming a
 *   caller's RPM window from a background sweep would
 *   also make a batch throttle the tenant's live traffic, which no OpenAI-
 *   compatible client expects.
 * - **The wallet RESERVATION (step 3b).** A reservation is a hold released by
 *   the response of the request that took it; there is no such request here.
 *   The wallet BALANCE (step 3) is read and enforced, so a tenant at zero
 *   credits is refused — the cap is cumulative rather than concurrent.
 *
 * Both omissions are stated because a reader must be able to tell "considered
 * and rejected" from "forgotten", and because the second one is the honest
 * weaker half: batch spend is bounded by re-reading settled spend, not by
 * holding against it.
 *
 * ## Cost, stated
 *
 * The budget read is one D1 point lookup per rung. Doing it per LINE would be
 * one lookup per paid call, which for a 50,000-line job is 50,000 reads to
 * enforce a number that moves only as fast as metering settles. So it is
 * re-read at the start of every tick and then every
 * {@link BATCH_BUDGET_RECHECK_LINES} lines. The overshoot that buys is bounded
 * by that many lines' cost, and is the same class of overshoot the request path
 * accepts between its read-based check and its hold.
 */
import type { QuotaScopeChain } from "@ferrogate/policy";
import type { StoredBatch } from "@ferrogate/storage";
import type { PhysicalRoute } from "../inference/ports.js";
import {
  type QuotaSubject,
  RATE_LIMIT_REFUSALS,
  type SpendSource,
  currentPeriodMonth,
  d1SpendSource,
  monthlyBudgetCharges,
  quotaPolicySourceFromEnv,
  resolveQuotaWindows,
} from "../ratelimit/index.js";
import { residencyViolations } from "../residency/policy.js";
import { type ResidencyBindings, residencyPolicySourceFromEnv } from "../residency/source.js";
import { type TenancyBindings, resolverForEnv } from "../tenancy/index.js";

/**
 * Lines executed between two budget re-reads. See the module docs.
 *
 * STRICTLY SMALLER than {@link DEFAULT_MAX_LINES_PER_TICK}, and that is a
 * correctness constraint rather than a taste: the guard is evaluated at the top
 * of the loop, so with the two numbers equal the counter only ever reaches
 * `maxLinesPerTick - 1` and the re-check can never fire — the rung both module
 * docblocks describe would be dead code, and a tenant whose budget is exhausted
 * at line 2 of a tick would still pay for the other 23.
 */
export const BATCH_BUDGET_RECHECK_LINES = 10;

/** A refusal, shaped exactly like the middleware's so the codes stay shared. */
export interface BatchRefusal {
  readonly code: string;
  readonly message: string;
}

export type BatchGateResult = { readonly ok: true } | ({ readonly ok: false } & BatchRefusal);

const ALLOWED: BatchGateResult = { ok: true };

function refuse(code: string, message: string): BatchGateResult {
  return { ok: false, code, message };
}

/** The scope chain the batch was created under. */
export function batchScopeChain(batch: StoredBatch): QuotaScopeChain {
  const chain: QuotaScopeChain = { tenantId: batch.tenantId };
  if (batch.projectId !== undefined && batch.projectId !== "") chain.projectId = batch.projectId;
  if (batch.apiKeyId !== undefined && batch.apiKeyId !== "") chain.keyId = batch.apiKeyId;
  return chain;
}

/** The seams the tests replace. Production resolves every one from `env`. */
export interface BatchGovernanceDeps {
  readonly spend?: ((env: unknown, batch: StoredBatch) => Promise<SpendSource>) | undefined;
  readonly nowUnix?: (() => number) | undefined;
}

/**
 * The per-job gate, built once per tick and consulted per line.
 *
 * Instances are cheap and hold NO bindings beyond the ones handed to
 * {@link createBatchGovernance}; a new one is built for every tick because a
 * policy can change between ticks and a job that ran yesterday must be
 * re-admitted today.
 */
export interface BatchGovernance {
  /**
   * The job-level gate: is this tenant/project/key still inside its budget and
   * wallet? Called at the start of a tick and every
   * {@link BATCH_BUDGET_RECHECK_LINES} lines.
   *
   * A storage failure is a REFUSAL with `quota_resolution_unavailable`, never
   * an allow: an unreadable rollup has not proven the caller has headroom, and
   * the request path reaches the same conclusion (503) from the same reading.
   */
  admitSpend(): Promise<BatchGateResult>;
  /** The per-route gate (#681): may this tenant's prompt reach this provider? */
  admitRoute(route: PhysicalRoute): Promise<BatchGateResult>;
}

async function defaultSpendSource(env: unknown, batch: StoredBatch): Promise<SpendSource> {
  // The batch's OWN tenant database, resolved through the same fail-closed
  // resolver the request path uses. There is deliberately no `env.DB`
  // fallback: reading a shared database to admit a routed tenant is a budget
  // decision taken against the wrong money.
  const handle = await resolverForEnv(env as TenancyBindings).forTenant(batch.tenantId);
  return d1SpendSource(handle.db);
}

export function createBatchGovernance(
  env: unknown,
  batch: StoredBatch,
  deps: BatchGovernanceDeps = {},
): BatchGovernance {
  const spendFor = deps.spend ?? defaultSpendSource;
  const nowUnix = deps.nowUnix ?? (() => Math.floor(Date.now() / 1000));
  const chain = batchScopeChain(batch);
  const subject: QuotaSubject = { apiKeyId: batch.apiKeyId ?? "", chain };
  const residencySource = residencyPolicySourceFromEnv(env as ResidencyBindings);

  return {
    async admitSpend(): Promise<BatchGateResult> {
      let spend: SpendSource;
      try {
        spend = await spendFor(env, batch);
      } catch (error) {
        return refuse(
          "quota_resolution_unavailable",
          `batch spend lookup failed: ${error instanceof Error ? error.message : String(error)}`,
        );
      }

      const resolution = await resolveQuotaWindows(quotaPolicySourceFromEnv(env as never), subject);
      if (!resolution.ok) {
        return refuse(
          "quota_resolution_unavailable",
          `quota policy lookup failed: ${resolution.detail}`,
        );
      }
      // Step 1 — a disabled scope anywhere in the chain is a hard deny, and it
      // is a hard deny here too. A tenant switched off mid-batch must stop
      // spending on the very next line.
      const deniedBy = resolution.quota.deniedBy;
      if (deniedBy !== undefined) {
        const refusal = RATE_LIMIT_REFUSALS.quota_scope_disabled;
        return refuse(refusal.code, refusal.message(deniedBy));
      }

      // Step 2 — EVERY rung of the nested monthly budget (#679), each against
      // its own scope's aggregate rollup. Same `>=` as the request path: the
      // cap is refused AT the limit, not past it.
      const charges = monthlyBudgetCharges(resolution.quota, chain, subject.apiKeyId);
      const periodMonth = currentPeriodMonth(nowUnix());
      for (const charge of charges) {
        const spent = await spend.committedSpendUsd(charge.kind, charge.id, periodMonth);
        if (!spent.ok) {
          return refuse(
            "quota_resolution_unavailable",
            `monthly budget lookup failed: ${spent.detail}`,
          );
        }
        if (spent.committedSpendUsd >= charge.limitUsd) {
          const refusal = RATE_LIMIT_REFUSALS.monthly_budget_exceeded;
          return refuse(refusal.code, refusal.message());
        }
      }

      // Step 3 — the prepaid wallet balance, independent of the budget above.
      // `null` is "this tenant has no wallet", which is never a denial.
      const balance = await spend.walletBalanceCredits(batch.tenantId);
      if (!balance.ok) {
        return refuse(
          "quota_resolution_unavailable",
          `wallet balance lookup failed: ${balance.detail}`,
        );
      }
      if (balance.availableCredits !== null && balance.availableCredits <= 0) {
        const refusal = RATE_LIMIT_REFUSALS.wallet_balance_exhausted;
        return refuse(refusal.code, refusal.message());
      }
      return ALLOWED;
    },

    async admitRoute(route: PhysicalRoute): Promise<BatchGateResult> {
      // #681, and the same function route eligibility uses — the evals
      // consumer's precedent. Fail CLOSED on an unreadable policy: a batch
      // ships the tenant's prompts to a provider exactly as the request path
      // does, and "we could not tell" is not permission.
      const policy = await residencySource.policyFor(batch.tenantId);
      if (!policy.ok) {
        return refuse(
          "residency_policy_unavailable",
          "the tenant's data-residency policy could not be read",
        );
      }
      const violations = residencyViolations(route, policy.policy);
      if (violations.length > 0) {
        // The SAME code `inference/candidates.ts` raises when no candidate
        // route satisfies the policy. A second code for the same fact would
        // give an operator two things to grep for one control.
        return refuse(
          "residency_policy_not_satisfiable",
          `route ${route.provider} may not carry this tenant's data: ${violations.join(", ")}`,
        );
      }
      return ALLOWED;
    },
  };
}
