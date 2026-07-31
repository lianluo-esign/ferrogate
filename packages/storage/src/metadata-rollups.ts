/**
 * Per-calendar-month usage/cost rollups keyed by an arbitrary caller metadata
 * key/value pair (ports `ferrogate-storage::metadata_rollups`, issues #171/#226).
 *
 * A settled request with N metadata pairs increments N rows, mirroring how one
 * event fans out into up to four `usage_monthly_rollups` rows. Rows are scoped to
 * the originating `organizationId` ("" = none/legacy) so a tenant admin sees only
 * their own breakdown; a platform operator sees all.
 *
 * PORT-TODO(inventory-data-billing §1.4.4 `usage_metadata_rollups`): this family
 * has NO durable twin. `sql/d1-ts/tenant/0001_init_tenant.sql` creates the table
 * and `test/d1/schema.test.ts` pins its columns, but no code ever writes a row:
 * `D1UsageLedger.persistUsageAggregate` (`./d1/usage-d1.ts`) batches
 * `tenant_contexts` + `usage_aggregate_rollups` + `usage_monthly_rollups` and
 * stops there, and nothing implements Rust's `list_usage_metadata_rollups`
 * (`crates/ferrogate-storage/src/control_plane_store_d1/usage.rs`). Why it
 * matters: metadata rollups are the ONLY aggregation dimension orthogonal to the
 * tenant/project/workspace/key scope chain — Rust's
 * `state_quota_and_policy.rs::list_usage_metadata_rollups` is how an operator
 * answers "what did feature X / customer Y cost" (#171/#226). Today that question
 * has no answer on this platform and the spend is unattributable after the fact.
 * The close is one more statement per metadata pair inside the SAME
 * `persistUsageAggregate` batch (so attribution cannot land without the spend it
 * explains) plus a D1 read for the admin list.
 */
import { usageMetadataRollupId } from "./ids.js";

export interface StoredUsageMetadataRollup {
  id: string;
  /** `YYYY-MM`, UTC. */
  periodMonth: string;
  organizationId: string;
  metadataKey: string;
  metadataValue: string;
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  costUsd: number;
  requestCount: number;
  errorCount: number;
  updatedAtUnix: number;
}

/** One settled request's usage/cost delta, fanned out across its metadata pairs. */
export interface UsageMonthlyDelta {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  costUsd: number;
  isError: boolean;
}

export class MemoryMetadataRollupStore {
  private readonly rows = new Map<string, StoredUsageMetadataRollup>();

  /**
   * Fan a settled delta out into one increment per metadata pair (ports
   * `increment_usage_metadata_rollups`). A no-op when `metadata` is empty.
   */
  incrementUsageMetadataRollups(
    organizationId: string,
    metadata: ReadonlyMap<string, string>,
    periodMonth: string,
    delta: UsageMonthlyDelta,
    nowUnix: number,
  ): void {
    // Iterate in sorted key order so the fan-out is deterministic (Rust BTreeMap).
    for (const metadataKey of [...metadata.keys()].sort()) {
      const metadataValue = metadata.get(metadataKey) as string;
      const id = usageMetadataRollupId(periodMonth, organizationId, metadataKey, metadataValue);
      const rollup = this.rows.get(id) ?? {
        id,
        periodMonth,
        organizationId,
        metadataKey,
        metadataValue,
        promptTokens: 0,
        completionTokens: 0,
        totalTokens: 0,
        costUsd: 0,
        requestCount: 0,
        errorCount: 0,
        updatedAtUnix: 0,
      };
      rollup.promptTokens += delta.promptTokens;
      rollup.completionTokens += delta.completionTokens;
      rollup.totalTokens += delta.totalTokens;
      rollup.costUsd += delta.costUsd;
      rollup.requestCount += 1;
      rollup.errorCount += delta.isError ? 1 : 0;
      rollup.updatedAtUnix = nowUnix;
      this.rows.set(id, rollup);
    }
  }

  /**
   * Rollups for `metadataKey`, optionally narrowed to one org. Ordered by period
   * ascending then metadata value (ports `list_usage_metadata_rollups`).
   */
  listUsageMetadataRollups(
    metadataKey: string,
    organizationId: string | undefined,
  ): StoredUsageMetadataRollup[] {
    const out = [...this.rows.values()]
      .filter((r) => r.metadataKey === metadataKey)
      .filter((r) => organizationId === undefined || r.organizationId === organizationId)
      .map((r) => ({ ...r }));
    out.sort(
      (a, b) =>
        a.periodMonth.localeCompare(b.periodMonth) ||
        a.metadataValue.localeCompare(b.metadataValue),
    );
    return out;
  }
}
