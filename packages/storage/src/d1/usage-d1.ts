import { StorageError } from "../errors.js";
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
 * ## Accumulation is `+`, with a tenant-local event claim
 *
 * Every counter merges with `existing + excluded`, so an at-least-once delivery
 * from a queue is *additive*, not last-write-wins. When `UsageAggregateWrite`
 * carries `sourceId`, statement 0 inserts that id into `usage_event_claims` and
 * every additive statement is guarded by the un-applied claim. A replay can
 * therefore repair a partially completed batch without counting it twice.
 *
 * The tenant-local `usage_event_claims` row makes this aggregate exactly-once
 * within its own batch. Billing settlement is a separate tenant-local batch in
 * `packages/billing/src/metering/d1.ts`; the gateway records the billing event,
 * ledger, wallet settlement, and report outbox there first, then accumulates
 * usage here. The two batches remain separately replayable and additive only
 * once.
 *
 * PORT-TODO(L: inventory-data-billing §1.5.8) — PLATFORM LIMIT, NOT CLOSED.
 * **D1 has no transaction spanning two databases.** `batch()` is scoped to the
 * one `D1Database` whose `prepare()` produced the statements; there is no
 * cross-database `BEGIN`, no two-phase commit, and no distributed-transaction
 * API on Workers. Billing settlement and usage accumulation are separate
 * batches even inside one tenant object, so they still cannot be one commit
 * across the two storage abstractions and the Postgres single-transaction shape
 * is unreachable.
 *
 * The approximation implemented instead is **claim-then-accumulate**: the
 * billing claim is durable and atomic on its own, and it is the *narrower* half
 * — a crash after a won claim but before the accumulate
 * UNDER-counts one call's tokens rather than double-billing it, which is the
 * correct direction to fail.
 *
 * The tenant-local usage claim closes the old additive replay window; it still
 * cannot make billing settlement and usage accumulation one commit. The
 * cross-batch limit below remains.
 *
 * So: the CALLER still owns ordering (claim first, accumulate only on a win),
 * and the gateway records once per settled request at the end of the stream.
 * `test/d1/usage-d1.test.ts` pins both source-less additive behavior and the
 * source-id guarded behavior used by the gateway.
 */
import { periodMonthFromUnix, usageMetadataRollupId, usageMonthlyRollupId } from "../ids.js";
import type { StoredUsageMetadataRollup } from "../metadata-rollups.js";
import type { QuotaScopeKind, StoredUsageMonthlyRollup } from "../quota.js";
import { type TenantDatabaseHandle, requireAtomicBatch } from "../tenant-router.js";
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

/** Durable control-projection intent written in the same tenant batch. */
export interface UsageProjectionRetryIntent {
  sourceId: string;
  payloadJson: string;
}

/** Optional presence touch that belongs to the settled usage event. */
export interface UsagePresenceTouch {
  tenantId: string;
  apiKeyId: string;
  seenAtUnix: number;
}

/** Optional agent-cost delta that belongs to the settled usage event. */
export interface UsageAgentCostBurn {
  tenantId: string;
  agentKey: string;
  period: string;
  deltaUsd: number;
  nowUnix: number;
}

/** One settled inference call's usage, as the gateway's `Usage` reduces to. */
export interface UsageAggregateWrite {
  /** Stable metering event id. When present, the tenant batch is idempotent. */
  sourceId?: string;
  context: UsageTenantContext;
  logicalModel: string;
  provider: string;
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  /**
   * Prompt tokens served from a prompt cache — a SUBSET of {@link promptTokens}
   * (issue #667), so `totalTokens` is unaffected by it.
   *
   * Rolled up because the cached-read discount is otherwise priced into
   * `costUsd` and visible nowhere else, which makes a surprising invoice
   * unexplainable from the very tables the usage report reads. Absent is `0`,
   * which is what a provider reporting no cached tokens means and what a row
   * written before the #667 migration carries.
   */
  cachedInputTokens?: number;
  /** Prompt tokens written INTO a prompt cache — a SUBSET of {@link promptTokens}. */
  cacheWriteTokens?: number;
  /** Reasoning/thinking tokens — a SUBSET of {@link completionTokens}. */
  reasoningTokens?: number;
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
  /**
   * Caller-supplied metadata pairs this call is ALSO attributed to (#171/#226) —
   * `{"feature": "search", "customer": "acme"}`. Each pair increments one
   * `usage_metadata_rollups` row INSIDE the same batch as the spend, so
   * attribution can never land without the spend it explains (and vice versa).
   *
   * Omitted / empty is the ordinary case and adds no statements. Iterated in
   * sorted key order so the fan-out is deterministic, matching
   * {@link ../metadata-rollups.js MemoryMetadataRollupStore} (Rust `BTreeMap`).
   */
  metadata?: ReadonlyMap<string, string>;
  /** Inserted atomically with the object rollups when fleet projection is enabled. */
  projectionRetry?: UsageProjectionRetryIntent;
  /** Presence is part of the same settled usage transaction, when attributed. */
  presenceTouch?: UsagePresenceTouch;
  /** Agent burn is part of the same settled usage transaction, when attributed. */
  agentCostBurn?: UsageAgentCostBurn;
}

/**
 * Metadata pairs in sorted-key order, so the statement fan-out is deterministic
 * (Rust iterates a `BTreeMap`). Determinism is not cosmetic here: two isolates
 * writing the same pairs in different orders would take the SQLite row locks in
 * different orders, which is how a deadlock is built.
 */
function sortedMetadataPairs(
  metadata: ReadonlyMap<string, string> | undefined,
): [string, string][] {
  if (metadata === undefined || metadata.size === 0) return [];
  return [...metadata.keys()].sort().map((key) => [key, metadata.get(key) as string]);
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
    // #667. `?? 0` rather than a required field: a caller written before the
    // cached counters existed still compiles and still accumulates correctly,
    // because "not reported" and "zero cached tokens" are the same row delta.
    const cachedInputTokens = write.cachedInputTokens ?? 0;
    const cacheWriteTokens = write.cacheWriteTokens ?? 0;
    const reasoningTokens = write.reasoningTokens ?? 0;
    // `""` (not NULL) for an org-less/legacy context: the deterministic rollup
    // id is `{period}:{org}:{key}:{value}`, and a NULL segment would make two
    // different rows collide on one id. The column defaults to `''` for the
    // same reason.
    const organizationId = write.context.organizationId ?? "";
    const sourceId = write.sourceId?.trim() === "" ? undefined : write.sourceId?.trim();
    const claimGuard =
      sourceId === undefined
        ? ""
        : " WHERE EXISTS (SELECT 1 FROM usage_event_claims " +
          "WHERE source_id = ? AND applied_at_unix IS NULL)";
    const claimParams = sourceId === undefined ? [] : [sourceId];

    const statements: D1PreparedStatement[] = [];
    if (sourceId !== undefined) {
      statements.push(
        this.db
          .prepare(
            "INSERT INTO usage_event_claims (source_id, applied_at_unix) " +
              "VALUES (?, NULL) ON CONFLICT (source_id) DO NOTHING",
          )
          .bind(sourceId),
      );
    }
    statements.push(
      // 1. The attribution row. `DO NOTHING` because a context's identity
      //    columns are immutable — re-deriving them on every call would be a
      //    write amplification with no effect.
      this.db
        .prepare(
          `INSERT INTO tenant_contexts (id, organization_id, team_id, project_id, workspace_id, user_id, api_key_id) ${
            sourceId === undefined
              ? "VALUES (?, ?, ?, ?, ?, ?, ?)"
              : `SELECT ?, ?, ?, ?, ?, ?, ?${claimGuard}`
          } ON CONFLICT (id) DO NOTHING`,
        )
        .bind(
          write.context.id,
          bindOptional(write.context.organizationId),
          bindOptional(write.context.teamId),
          bindOptional(write.context.projectId),
          bindOptional(write.context.workspaceId),
          bindOptional(write.context.userId),
          bindOptional(write.context.apiKeyId),
          ...claimParams,
        ),
      // 2. Cumulative token totals for this (context, model, provider).
      this.db
        .prepare(
          `INSERT INTO usage_aggregate_rollups (id, tenant_context_id, logical_model, provider, prompt_tokens,  completion_tokens, total_tokens, cached_input_tokens, cache_write_tokens,  reasoning_tokens, updated_at_unix) ${
            sourceId === undefined
              ? "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
              : `SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?${claimGuard}`
          } ON CONFLICT (id) DO UPDATE SET prompt_tokens = usage_aggregate_rollups.prompt_tokens + excluded.prompt_tokens, completion_tokens = usage_aggregate_rollups.completion_tokens +                     excluded.completion_tokens, total_tokens = usage_aggregate_rollups.total_tokens + excluded.total_tokens, cached_input_tokens = usage_aggregate_rollups.cached_input_tokens +                       excluded.cached_input_tokens, cache_write_tokens = usage_aggregate_rollups.cache_write_tokens +                      excluded.cache_write_tokens, reasoning_tokens = usage_aggregate_rollups.reasoning_tokens +                    excluded.reasoning_tokens, updated_at_unix = max(usage_aggregate_rollups.updated_at_unix,                       excluded.updated_at_unix)`,
        )
        .bind(
          aggregateId,
          write.context.id,
          write.logicalModel,
          write.provider,
          write.promptTokens,
          write.completionTokens,
          write.totalTokens,
          cachedInputTokens,
          cacheWriteTokens,
          reasoningTokens,
          write.occurredAtUnix,
          ...claimParams,
        ),
    );

    // 3. One monthly rollup row per scope level the caller occupies.
    for (const scope of write.scopes) {
      statements.push(
        this.db
          .prepare(
            `INSERT INTO usage_monthly_rollups (id, period_month, scope_type, scope_id, prompt_tokens, completion_tokens,  total_tokens, cached_input_tokens, cache_write_tokens, reasoning_tokens,  cost_usd, request_count, error_count, updated_at_unix) ${
              sourceId === undefined
                ? "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)"
                : `SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?${claimGuard}`
            } ON CONFLICT (id) DO UPDATE SET prompt_tokens = usage_monthly_rollups.prompt_tokens + excluded.prompt_tokens, completion_tokens = usage_monthly_rollups.completion_tokens +                     excluded.completion_tokens, total_tokens = usage_monthly_rollups.total_tokens + excluded.total_tokens, cached_input_tokens = usage_monthly_rollups.cached_input_tokens +                       excluded.cached_input_tokens, cache_write_tokens = usage_monthly_rollups.cache_write_tokens +                      excluded.cache_write_tokens, reasoning_tokens = usage_monthly_rollups.reasoning_tokens +                    excluded.reasoning_tokens, cost_usd = usage_monthly_rollups.cost_usd + excluded.cost_usd, request_count = usage_monthly_rollups.request_count + excluded.request_count, error_count = usage_monthly_rollups.error_count + excluded.error_count, updated_at_unix = max(usage_monthly_rollups.updated_at_unix,                       excluded.updated_at_unix)`,
          )
          .bind(
            usageMonthlyRollupId(periodMonth, scope.scopeType, scope.scopeId),
            periodMonth,
            scope.scopeType,
            scope.scopeId,
            write.promptTokens,
            write.completionTokens,
            write.totalTokens,
            cachedInputTokens,
            cacheWriteTokens,
            reasoningTokens,
            write.costUsd,
            errorDelta,
            write.occurredAtUnix,
            ...claimParams,
          ),
      );
    }

    // 4. One metadata rollup row per caller metadata pair (#171/#226). These
    //    are in the SAME batch as the monthly rollups on purpose: the metadata
    //    breakdown is a re-slice of the very spend statement 3 recorded, so a
    //    world where one committed and the other did not is a world where
    //    "what did feature X cost" disagrees with the invoice.
    for (const [metadataKey, metadataValue] of sortedMetadataPairs(write.metadata)) {
      statements.push(
        this.db
          .prepare(
            `INSERT INTO usage_metadata_rollups (id, period_month, organization_id, metadata_key, metadata_value, prompt_tokens,  completion_tokens, total_tokens, cost_usd, request_count, error_count,  updated_at_unix) ${
              sourceId === undefined
                ? "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)"
                : `SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?${claimGuard}`
            } ON CONFLICT (id) DO UPDATE SET prompt_tokens = usage_metadata_rollups.prompt_tokens + excluded.prompt_tokens, completion_tokens = usage_metadata_rollups.completion_tokens +                     excluded.completion_tokens, total_tokens = usage_metadata_rollups.total_tokens + excluded.total_tokens, cost_usd = usage_metadata_rollups.cost_usd + excluded.cost_usd, request_count = usage_metadata_rollups.request_count + excluded.request_count, error_count = usage_metadata_rollups.error_count + excluded.error_count, updated_at_unix = max(usage_metadata_rollups.updated_at_unix,                       excluded.updated_at_unix)`,
          )
          .bind(
            usageMetadataRollupId(periodMonth, organizationId, metadataKey, metadataValue),
            periodMonth,
            organizationId,
            metadataKey,
            metadataValue,
            write.promptTokens,
            write.completionTokens,
            write.totalTokens,
            write.costUsd,
            errorDelta,
            write.occurredAtUnix,
            ...claimParams,
          ),
      );
    }

    if (write.presenceTouch !== undefined) {
      statements.push(
        this.db
          .prepare(
            `INSERT INTO observed_agent_presence (tenant_id, api_key_id, first_seen_at_unix, last_seen_at_unix, request_count, ${
              sourceId === undefined
                ? " updated_at_unix) VALUES (?, ?, ?, ?, 1, ?)"
                : ` updated_at_unix) SELECT ?, ?, ?, ?, 1, ?${claimGuard}`
            } ON CONFLICT (tenant_id, api_key_id) DO UPDATE SET last_seen_at_unix = max(observed_agent_presence.last_seen_at_unix,                         excluded.last_seen_at_unix), first_seen_at_unix = min(observed_agent_presence.first_seen_at_unix,                          excluded.first_seen_at_unix), request_count = observed_agent_presence.request_count + excluded.request_count, updated_at_unix = max(observed_agent_presence.updated_at_unix,                       excluded.updated_at_unix)`,
          )
          .bind(
            write.presenceTouch.tenantId,
            write.presenceTouch.apiKeyId,
            write.presenceTouch.seenAtUnix,
            write.presenceTouch.seenAtUnix,
            write.presenceTouch.seenAtUnix,
            ...claimParams,
          ),
      );
    }

    if (write.agentCostBurn !== undefined) {
      statements.push(
        this.db
          .prepare(
            `INSERT INTO agent_cost_burn (tenant_id, agent_key, period, accumulated_usd, first_seen_unix, updated_at_unix) ${
              sourceId === undefined
                ? "VALUES (?, ?, ?, ?, ?, ?)"
                : `SELECT ?, ?, ?, ?, ?, ?${claimGuard}`
            } ON CONFLICT (tenant_id, agent_key, period) DO UPDATE SET accumulated_usd = agent_cost_burn.accumulated_usd + excluded.accumulated_usd, first_seen_unix = min(agent_cost_burn.first_seen_unix, excluded.first_seen_unix), updated_at_unix = max(agent_cost_burn.updated_at_unix, excluded.updated_at_unix)`,
          )
          .bind(
            write.agentCostBurn.tenantId,
            write.agentCostBurn.agentKey,
            write.agentCostBurn.period,
            write.agentCostBurn.deltaUsd,
            write.agentCostBurn.nowUnix,
            write.agentCostBurn.nowUnix,
            ...claimParams,
          ),
      );
    }

    if (write.projectionRetry !== undefined && organizationId !== "") {
      statements.push(
        this.db
          .prepare(
            `INSERT INTO usage_projection_retries (source_id, tenant_id, occurred_at_unix, payload_json, attempts,  next_attempt_unix, created_at_unix, updated_at_unix) ${
              sourceId === undefined
                ? "VALUES (?, ?, ?, ?, 0, 0, unixepoch(), unixepoch())"
                : `SELECT ?, ?, ?, ?, 0, 0, unixepoch(), unixepoch()${claimGuard}`
            } ON CONFLICT (source_id) DO UPDATE SET tenant_id = excluded.tenant_id, occurred_at_unix = excluded.occurred_at_unix, payload_json = excluded.payload_json, updated_at_unix = unixepoch()`,
          )
          .bind(
            write.projectionRetry.sourceId,
            organizationId,
            write.occurredAtUnix,
            write.projectionRetry.payloadJson,
            ...claimParams,
          ),
      );
    }

    if (sourceId !== undefined) {
      statements.push(
        this.db
          .prepare(
            "UPDATE usage_event_claims SET applied_at_unix = ? " +
              "WHERE source_id = ? AND applied_at_unix IS NULL",
          )
          .bind(write.occurredAtUnix, sourceId),
      );
    }

    try {
      await this.db.batch(statements);
    } catch (error) {
      throw d1Error("persist_usage_aggregate", error);
    }
  }

  /**
   * The metadata breakdown for one metadata key (ports Rust
   * `list_usage_metadata_rollups`, #171/#226) — "what did each value of
   * `feature` cost this month".
   *
   * `organizationId` is the tenancy filter, and it is NOT optional-as-in-
   * "everything": passing an org restricts the read to that org's rows, exactly
   * as Rust's `Some(org)` arm does, so a tenant admin cannot read another
   * tenant's breakdown out of a shared database. Passing `undefined` is the
   * platform-operator read across every org in THIS tenant database.
   *
   * `""` is a real, distinct organization id — the pre-#226 / platform-scoped
   * rows — and is queryable as itself, which is why the schema defaults the
   * column to `''` rather than NULL.
   *
   * Ordered `period_month ASC, metadata_value ASC` — the Rust/Postgres order,
   * and the SAME order `MemoryMetadataRollupStore` produces, so the two backends
   * cannot be observed to disagree.
   */
  async listUsageMetadataRollups(
    metadataKey: string,
    organizationId?: string,
  ): Promise<StoredUsageMetadataRollup[]> {
    const columns =
      "id, period_month, organization_id, metadata_key, metadata_value, prompt_tokens, " +
      "completion_tokens, total_tokens, cost_usd, request_count, error_count, updated_at_unix";
    try {
      const statement =
        organizationId === undefined
          ? this.db
              .prepare(
                `SELECT ${columns} FROM usage_metadata_rollups WHERE metadata_key = ? ORDER BY period_month ASC, metadata_value ASC`,
              )
              .bind(metadataKey)
          : this.db
              .prepare(
                `SELECT ${columns} FROM usage_metadata_rollups WHERE metadata_key = ? AND organization_id = ? ORDER BY period_month ASC, metadata_value ASC`,
              )
              .bind(metadataKey, organizationId);
      const rows = await statement.all<{
        id: string;
        period_month: string;
        organization_id: string;
        metadata_key: string;
        metadata_value: string;
        prompt_tokens: number;
        completion_tokens: number;
        total_tokens: number;
        cost_usd: number;
        request_count: number;
        error_count: number;
        updated_at_unix: number;
      }>();
      return rows.results.map((row) => ({
        id: row.id,
        periodMonth: row.period_month,
        organizationId: row.organization_id,
        metadataKey: row.metadata_key,
        metadataValue: row.metadata_value,
        promptTokens: row.prompt_tokens,
        completionTokens: row.completion_tokens,
        totalTokens: row.total_tokens,
        costUsd: row.cost_usd,
        requestCount: row.request_count,
        errorCount: row.error_count,
        updatedAtUnix: row.updated_at_unix,
      }));
    } catch (error) {
      throw d1Error("list_usage_metadata_rollups", error);
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
            "total_tokens, cached_input_tokens, cache_write_tokens, reasoning_tokens, " +
            "cost_usd, request_count, error_count, updated_at_unix " +
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
          cached_input_tokens: number;
          cache_write_tokens: number;
          reasoning_tokens: number;
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
        // #667. `?? 0` guards the one case the column cannot: a database that
        // has not yet run `0002_cached_reasoning_tokens.sql`, where D1 returns
        // the row without the key rather than failing the SELECT.
        cachedInputTokens: row.cached_input_tokens ?? 0,
        cacheWriteTokens: row.cache_write_tokens ?? 0,
        reasoningTokens: row.reasoning_tokens ?? 0,
        costUsd: row.cost_usd,
        requestCount: row.request_count,
        errorCount: row.error_count,
        updatedAtUnix: row.updated_at_unix,
      };
    } catch (error) {
      throw d1Error("get_usage_monthly_rollup", error);
    }
  }

  /**
   * Total tokens already committed against one API key — Rust
   * `sum_api_key_committed_tokens` (inventory-data-billing §1.2, #330).
   *
   * This is the `committed` operand of
   * `RateLimiter.reserveTokenBudget(counterKey, committed, budget,
   * estimatedTokens)` (`apps/gateway/src/ratelimit/ports.ts`), which enforces
   * `api_keys.monthly_token_budget`. Until this existed there was no supplier
   * for it at all, so that budget was unenforced for every durable key and only
   * the degenerate `monthly_token_budget === 0` check on STATIC config keys
   * survived — a key with a million-token budget could never exhaust it.
   *
   * Two properties are deliberate and both are pinned by
   * `test/d1/usage-d1.test.ts`:
   *
   *  - The sum is pushed into SQL, exactly as Rust does. Reading the rows and
   *    summing in the isolate would pull an unbounded result set through the D1
   *    wire on every admission check.
   *  - An API key with no usage yet answers `0`, from `COALESCE`, NOT
   *    `undefined`. A caller that had to distinguish "no rows" from "no tokens"
   *    would eventually treat the absent case as unlimited, which is the failure
   *    direction that costs money.
   *
   * NOTE the scope: this is the key's LIFETIME committed total over
   * `usage_aggregate_rollups`, which is what Rust's function sums. The
   * period-scoped question is a different read — {@link getUsageMonthlyRollup}.
   *
   * The former PORT_TODO(inventory-data-billing §1.2, #330) — CLOSED, and
   * removed here rather than left standing, because it had gone stale in the
   * direction that matters: it claimed "`apps/gateway/src/ratelimit/
   * middleware.ts` … still never invokes `reserveTokenBudget`, so the token
   * budget is not yet enforced on a live request".
   *
   * It does now. `apps/gateway/src/ratelimit/middleware.ts` step 5b
   * (`admitTokensPerMinute` → the `resolved.limiter.reserveTokenBudget(
   * tokenBudgetCounterKey(apiKeyId), reading.committedTokens, reading.budget,
   * estimatedTokens)` call) feeds this sum in through
   * `src/ratelimit/token-budget.ts`, holds the reservation for the whole
   * request and releases it in the middleware's `finally`. So both halves and
   * the call between them exist on the deployed admission ladder.
   */
  async sumApiKeyCommittedTokens(apiKeyId: string): Promise<number> {
    try {
      const row = await this.db
        .prepare(
          "SELECT COALESCE(SUM(r.total_tokens), 0) AS committed " +
            "FROM usage_aggregate_rollups r " +
            "JOIN tenant_contexts c ON c.id = r.tenant_context_id " +
            "WHERE c.api_key_id = ?",
        )
        .bind(apiKeyId)
        .first<{ committed: number }>();
      return row?.committed ?? 0;
    } catch (error) {
      throw d1Error("sum_api_key_committed_tokens", error);
    }
  }
}
