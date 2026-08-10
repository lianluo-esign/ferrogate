/**
 * `api_keys.monthly_token_budget` — the operand that was missing, and the read
 * that supplies it.
 *
 * ## The loop that was open
 *
 * `RateLimiter.reserveTokenBudget(counterKey, committed, budget, estimated)` has
 * existed since the limiter landed, in all three implementations, with eight
 * assertions on it. `@ferrogate/storage`'s `D1UsageLedger.sumApiKeyCommittedTokens`
 * — the SQL `SUM` Rust pushes down in `sum_api_key_committed_tokens` — has
 * existed since the storage port landed, with its own tests. Neither had a
 * caller, because nothing PRODUCED a `committed` count:
 *
 *  - the consumer end (`middleware.ts`) enforced rpm/tpm and the monthly USD
 *    budget and never invoked `reserveTokenBudget`;
 *  - the producer end never wrote `usage_aggregate_rollups` at all — the
 *    gateway's metering path settled into the CONTROL database's
 *    `billing_ledger` and stopped there.
 *
 * So a durable key with a budget of one million tokens could never exhaust it,
 * and the only surviving token check was the degenerate
 * `monthly_token_budget === 0` on STATIC config keys (`src/adapters.ts:272`).
 *
 * This module closes the READ half. The WRITE half is
 * `../metering/usage-ledger.ts`, which mounts `D1UsageLedger` on the metering
 * drain so every settled request accumulates into the very rows this file sums.
 * Both halves are needed: either one alone leaves the budget unenforceable.
 *
 * ## Why `committed` is a lifetime total and the budget is called "monthly"
 *
 * `sum_api_key_committed_tokens` sums `usage_aggregate_rollups` over the key's
 * whole history — that is what the Rust function does, and this port does not
 * quietly improve on it. The name `monthly_token_budget` is the column's, and
 * the period-scoped question is a different read (`getUsageMonthlyRollup`),
 * which is what the monthly USD budget in `quota.ts` uses. The two are not
 * interchangeable and are deliberately not merged here.
 */
import { D1UsageLedger } from "@ferrogate/storage";
import { gatewayTenantHandle } from "./wallet.js";

/** Bindings this module reads. */
export interface TokenBudgetBindings {
  /**
   * The TENANT database, holding `api_keys` (the budget) and
   * `usage_aggregate_rollups` + `tenant_contexts` (the committed sum).
   */
  readonly DB?: D1Database | undefined;
}

/**
 * A key's budget and how much of it is already spent.
 *
 * `budget === undefined` means the column is NULL — no budget governs this key,
 * which is the normal state and must never be read as "budget of zero".
 */
export type TokenBudgetReading =
  | {
      readonly ok: true;
      readonly budget: number | undefined;
      readonly committedTokens: number;
    }
  | { readonly ok: false; readonly detail: string };

/**
 * Supplies the two numbers `reserveTokenBudget` needs.
 *
 * A RESULT type, not a bare pair, for the same reason `SpendSource` is one: a
 * failed lookup is `503 governance_counter_unavailable`, never "budget of
 * zero" (which would refuse every request) and never "no budget" (which would
 * admit every request). A storage outage has proven nothing about the caller.
 */
export interface TokenBudgetSource {
  forApiKey(apiKeyId: string, tenantId: string | undefined): Promise<TokenBudgetReading>;
}

/**
 * The source for a deployment with no tenant database bound.
 *
 * `budget: undefined` is the TRUE reading of an absent `api_keys` table: no key
 * row exists, so no key carries a budget. Binding `DB` can therefore only add
 * enforcement, never remove it.
 */
export const NO_TOKEN_BUDGET: TokenBudgetSource = {
  async forApiKey(): Promise<TokenBudgetReading> {
    return { ok: true, budget: undefined, committedTokens: 0 };
  },
};

const MONTHLY_TOKEN_BUDGET_SQL = "SELECT monthly_token_budget FROM api_keys WHERE id = ?";

/**
 * The durable source: `api_keys.monthly_token_budget` plus
 * `D1UsageLedger.sumApiKeyCommittedTokens`.
 *
 * The budget is read first and the SUM is issued ONLY when a budget exists.
 * That ordering is the whole cost story: keys with no budget — every key, in
 * every deployment that has not adopted the feature — pay one indexed
 * primary-key lookup and nothing else, while a budgeted key pays the aggregate
 * it is asking for. Issuing both unconditionally would put a `SUM` over an
 * unbounded rollup history on the hot path of requests that can never be
 * refused by it.
 */
export function d1TokenBudgetSource(db: D1Database): TokenBudgetSource {
  return {
    async forApiKey(apiKeyId: string, tenantId: string | undefined): Promise<TokenBudgetReading> {
      let budget: number | undefined;
      try {
        const row = await db
          .prepare(MONTHLY_TOKEN_BUDGET_SQL)
          .bind(apiKeyId)
          .first<{ monthly_token_budget: number | null }>();
        const value = row?.monthly_token_budget;
        budget = value === null || value === undefined ? undefined : Number(value);
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        return { ok: false, detail: `cloudflare d1: token budget lookup failed: ${detail}` };
      }

      if (budget === undefined) return { ok: true, budget: undefined, committedTokens: 0 };

      try {
        // The handle's tenant is only the mis-routing tripwire for WRITES; this
        // read is by api-key id. An unattributed credential still resolves,
        // with the empty tenant, because refusing to read a budget would mean
        // not enforcing it.
        const ledger = new D1UsageLedger(gatewayTenantHandle(db, tenantId ?? ""));
        const committedTokens = await ledger.sumApiKeyCommittedTokens(apiKeyId);
        return { ok: true, budget, committedTokens };
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        return { ok: false, detail: `cloudflare d1: committed token sum failed: ${detail}` };
      }
    },
  };
}
