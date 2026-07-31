/**
 * `D1UsageLedger` — the metering/usage capture leg of the main path.
 *
 * This is where `UsageSink.record` (apps/gateway/src/inference/ports.ts:285)
 * lands durably. One settled inference call produces, in ONE atomic `batch()`
 * on the tenant's database:
 *
 *   1. the `tenant_contexts` row the aggregate is attributed to (idempotent by
 *      its deterministic id);
 *   2. the per-(context, model, provider) cumulative token totals;
 *   3. the per-(period, scope) monthly rollup that monthly-budget enforcement
 *      and the usage/cost report API read.
 *
 * They are one batch and not three writes because a rollup that references a
 * `tenant_contexts` row which failed to write is unattributable — and because a
 * partially-applied usage record double-counts on retry. The batch is the
 * Postgres transaction's replacement.
 *
 * ## Accumulation is `+`, never assignment
 *
 * Every counter merges with `existing + excluded`, so an at-least-once delivery
 * from a queue is *additive*, not last-write-wins. That is the correct semantic
 * for a counter but it is NOT idempotent: replaying the same request id twice
 * counts it twice.
 *
 * The claim that makes it exactly-once IS now ported — see
 * {@link ../d1/billing-d1.js D1BillingEventLedger}, which claims
 * `billing_event_id` and enqueues the outbox row in one atomic
 * `controlDb.batch()` (inventory §1.5.8 item 8). Run it FIRST and accumulate
 * here only when it returns `recorded: true`.
 *
 * PORT-TODO(inventory-data-billing §1.5.8) — PLATFORM LIMIT, NOT CLOSED.
 * **D1 has no transaction spanning two databases.** `batch()` is scoped to the
 * one `D1Database` whose `prepare()` produced the statements; there is no
 * cross-database `BEGIN`, no two-phase commit, and no distributed-transaction
 * API on Workers. `billing_events` is in the CONTROL database and this
 * accumulate is on a TENANT database, so the claim and the accumulate CANNOT be
 * one commit no matter how they are arranged, and the Postgres single-transaction
 * shape is unreachable.
 *
 * The approximation implemented instead is **claim-then-accumulate**: the
 * control-database claim is durable and atomic on its own, and it is the
 * *narrower* half — a crash after a won claim but before the accumulate
 * UNDER-counts one call's tokens rather than double-billing it, which is the
 * correct direction to fail. Closing the remaining window would need an idempotency
 * key on the tenant side too (a per-`billing_event_id` marker row folded into
 * THIS batch), which is a schema change and a separate slice.
 *
 * So: the CALLER still owns ordering (claim first, accumulate only on a win),
 * and the gateway records once per settled request at the end of the stream.
 * `test/d1/usage-d1.test.ts` pins the additive (non-idempotent) semantics of
 * this batch so the approximation cannot be mistaken for exactly-once.
 */
import { periodMonthFromUnix, usageMonthlyRollupId } from "../ids.js";
import type { QuotaScopeKind, StoredUsageMonthlyRollup } from "../quota.js";
import { type TenantDatabaseHandle, requireAtomicBatch } from "../tenant-router.js";
import { StorageError } from "../errors.js";
import { bindOptional, d1Error } from "./rows.js";

/** The tenant/project/api-key identity a usage aggregate is attributed to. */
export interface UsageTenantContext {
  id: string;
  organizationId?: string;
  teamId?: string;
  projectId?: string;
  workspaceId?: string;
  userId?: string;
  apiKeyId?: string;
}

/** One settled inference call's usage, as the gateway's `Usage` reduces to. */
export interface UsageAggregateWrite {
  context: UsageTenantContext;
  logicalModel: string;
  provider: string;
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  costUsd: number;
  /** Non-2xx responses still meter (they consumed prompt tokens upstream). */
  isError: boolean;
  occurredAtUnix: number;
  /**
   * Which scopes to fold this call into. The Rust path writes one row per level
   * of the hierarchy the caller occupies (tenant, project, workspace, key), and
   * the overview read sums ONLY the `tenant` rows so the fan-out can never
   * double-count a request.
   */
  scopes: readonly { scopeType: QuotaScopeKind; scopeId: string }[];
}

export class D1UsageLedger {
  private readonly db: D1Database;

  constructor(private readonly handle: TenantDatabaseHandle) {
    this.db = handle.db;
  }

  /**
   * Persist one settled call: context + aggregate + every scope's monthly
   * rollup, as one atomic batch.
   */
  async persistUsageAggregate(write: UsageAggregateWrite): Promise<void> {
    requireAtomicBatch(this.handle, "persist_usage_aggregate");
    if (write.scopes.length === 0) {
      throw StorageError.runtime(
        "persist_usage_aggregate requires at least one scope; a call folded into no scope " +
          "is spend that no budget check can ever see",
      );
    }
    const periodMonth = periodMonthFromUnix(write.occurredAtUnix);
    const aggregateId = `${write.context.id}:${write.logicalModel}:${write.provider}`;
    const errorDelta = write.isError ? 1 : 0;

    const statements: D1PreparedStatement[] = [
      // 1. The attribution row. `DO NOTHING` because a context's identity
      //    columns are immutable — re-deriving them on every call would be a
      //    write amplification with no effect.
      this.db
        .prepare(
          "INSERT INTO tenant_contexts " +
            "(id, organization_id, team_id, project_id, workspace_id, user_id, api_key_id) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING",
        )
        .bind(
          write.context.id,
          bindOptional(write.context.organizationId),
          bindOptional(write.context.teamId),
          bindOptional(write.context.projectId),
          bindOptional(write.context.workspaceId),
          bindOptional(write.context.userId),
          bindOptional(write.context.apiKeyId),
        ),
      // 2. Cumulative token totals for this (context, model, provider).
      this.db
        .prepare(
          "INSERT INTO usage_aggregate_rollups " +
            "(id, tenant_context_id, logical_model, provider, prompt_tokens, " +
            " completion_tokens, total_tokens, updated_at_unix) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) " +
            "ON CONFLICT (id) DO UPDATE SET " +
            "prompt_tokens = usage_aggregate_rollups.prompt_tokens + excluded.prompt_tokens, " +
            "completion_tokens = usage_aggregate_rollups.completion_tokens + " +
            "                    excluded.completion_tokens, " +
            "total_tokens = usage_aggregate_rollups.total_tokens + excluded.total_tokens, " +
            "updated_at_unix = max(usage_aggregate_rollups.updated_at_unix, " +
            "                      excluded.updated_at_unix)",
        )
        .bind(
          aggregateId,
          write.context.id,
          write.logicalModel,
          write.provider,
          write.promptTokens,
          write.completionTokens,
          write.totalTokens,
          write.occurredAtUnix,
        ),
    ];

    // 3. One monthly rollup row per scope level the caller occupies.
    for (const scope of write.scopes) {
      statements.push(
        this.db
          .prepare(
            "INSERT INTO usage_monthly_rollups " +
              "(id, period_month, scope_type, scope_id, prompt_tokens, completion_tokens, " +
              " total_tokens, cost_usd, request_count, error_count, updated_at_unix) " +
              "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?) " +
              "ON CONFLICT (id) DO UPDATE SET " +
              "prompt_tokens = usage_monthly_rollups.prompt_tokens + excluded.prompt_tokens, " +
              "completion_tokens = usage_monthly_rollups.completion_tokens + " +
              "                    excluded.completion_tokens, " +
              "total_tokens = usage_monthly_rollups.total_tokens + excluded.total_tokens, " +
              "cost_usd = usage_monthly_rollups.cost_usd + excluded.cost_usd, " +
              "request_count = usage_monthly_rollups.request_count + excluded.request_count, " +
              "error_count = usage_monthly_rollups.error_count + excluded.error_count, " +
              "updated_at_unix = max(usage_monthly_rollups.updated_at_unix, " +
              "                      excluded.updated_at_unix)",
          )
          .bind(
            usageMonthlyRollupId(periodMonth, scope.scopeType, scope.scopeId),
            periodMonth,
            scope.scopeType,
            scope.scopeId,
            write.promptTokens,
            write.completionTokens,
            write.totalTokens,
            write.costUsd,
            errorDelta,
            write.occurredAtUnix,
          ),
      );
    }

    try {
      await this.db.batch(statements);
    } catch (error) {
      throw d1Error("persist_usage_aggregate", error);
    }
  }

  /** The current-month cumulative rollup for one scope, or `undefined`. */
  async getUsageMonthlyRollup(
    periodMonth: string,
    scopeType: QuotaScopeKind,
    scopeId: string,
  ): Promise<StoredUsageMonthlyRollup | undefined> {
    try {
      const row = await this.db
        .prepare(
          "SELECT id, period_month, scope_type, scope_id, prompt_tokens, completion_tokens, " +
            "total_tokens, cost_usd, request_count, error_count, updated_at_unix " +
            "FROM usage_monthly_rollups WHERE id = ?",
        )
        .bind(usageMonthlyRollupId(periodMonth, scopeType, scopeId))
        .first<{
          id: string;
          period_month: string;
          scope_type: string;
          scope_id: string;
          prompt_tokens: number;
          completion_tokens: number;
          total_tokens: number;
          cost_usd: number;
          request_count: number;
          error_count: number;
          updated_at_unix: number;
        }>();
      if (!row) return undefined;
      return {
        id: row.id,
        periodMonth: row.period_month,
        scopeType: row.scope_type as QuotaScopeKind,
        scopeId: row.scope_id,
        promptTokens: row.prompt_tokens,
        completionTokens: row.completion_tokens,
        totalTokens: row.total_tokens,
        costUsd: row.cost_usd,
        requestCount: row.request_count,
        errorCount: row.error_count,
        updatedAtUnix: row.updated_at_unix,
      };
    } catch (error) {
      throw d1Error("get_usage_monthly_rollup", error);
    }
  }
}
