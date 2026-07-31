/**
 * Per-calendar-month usage/cost rollups keyed by an arbitrary caller metadata
 * key/value pair (ports `ferrogate-storage::metadata_rollups`, issues #171/#226).
 *
 * A settled request with N metadata pairs increments N rows, mirroring how one
 * event fans out into up to four `usage_monthly_rollups` rows. Rows are scoped to
 * the originating `organizationId` ("" = none/legacy) so a tenant admin sees only
 * their own breakdown; a platform operator sees all.
 *
 * CLOSED — former marker inventory-data-billing §1.4.4. The durable twin now
 * exists: `D1UsageLedger.persistUsageAggregate` (`./d1/usage-d1.ts`) appends one
 * `usage_metadata_rollups` upsert per metadata pair to the SAME atomic batch
 * that writes `tenant_contexts` + `usage_aggregate_rollups` +
 * `usage_monthly_rollups`, so the attribution cannot commit without the spend it
 * explains and the spend cannot commit without its attribution; and
 * `D1UsageLedger.listUsageMetadataRollups` is the admin read (Rust
 * `list_usage_metadata_rollups`, `control_plane_store_d1/usage.rs`), ordered
 * `period_month ASC, metadata_value ASC` like Postgres — the same order this
 * module's in-memory twin produces — and filtered by
 * `organization_id` so one tenant cannot read another's breakdown.
 *
 * The one-batch property is the load-bearing claim and it is pinned by
 * mutation in `test/d1/usage-d1.test.ts` > "metadata rollups ride the same
 * batch": splitting the metadata write into a second `batch()` turns that test
 * red. The store below stays as the executable in-memory specification the D1
 * twin is asserted to agree with — same fan-out, same sorted key order, same
 * `""`-organization rule.
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
