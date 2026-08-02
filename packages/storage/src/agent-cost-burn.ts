/**
 * Durable, atomically-accumulating per-agent cost-burn ledger (ports
 * `ferrogate-storage::agent_cost_burn`, issue #428).
 *
 * One row per `(tenantId, agentKey, period)` whose `accumulatedUsd` is bumped by
 * a single atomic conditional upsert that RETURNS the new total, so concurrent
 * adds for one key can never lose an increment. `agentKey` is the STABLE
 * per-agent identity, not the per-run id; `period` reuses the `YYYY-MM` window.
 */
import { agentCostBurnKey } from "./ids.js";

export interface StoredAgentCostBurn {
  tenantId: string;
  agentKey: string;
  period: string;
  accumulatedUsd: number;
  firstSeenUnix: number;
  updatedAtUnix: number;
}

export class MemoryAgentBurnStore {
  private readonly rows = new Map<string, StoredAgentCostBurn>();

  /**
   * Atomically add `deltaUsd` and return the new accumulated total. Serialized by
   * the single JS thread, so concurrent adds fold into one row without loss —
   * the same guarantee as the Postgres `accumulated_usd + EXCLUDED` conflict clause.
   */
  addAgentBurn(
    tenantId: string,
    agentKey: string,
    period: string,
    deltaUsd: number,
    nowUnix: number,
  ): number {
    const key = agentCostBurnKey(tenantId, agentKey, period);
    const existing = this.rows.get(key);
    if (existing) {
      existing.accumulatedUsd += deltaUsd;
      existing.updatedAtUnix = nowUnix;
      return existing.accumulatedUsd;
    }
    const row: StoredAgentCostBurn = {
      tenantId,
      agentKey,
      period,
      accumulatedUsd: deltaUsd,
      firstSeenUnix: nowUnix,
      updatedAtUnix: nowUnix,
    };
    this.rows.set(key, row);
    return row.accumulatedUsd;
  }

  getAgentBurn(tenantId: string, agentKey: string, period: string): number | undefined {
    return this.rows.get(agentCostBurnKey(tenantId, agentKey, period))?.accumulatedUsd;
  }

  /**
   * Burn rows for `period`, biggest total first, optionally tenant-scoped. The
   * tenant scope is the isolation boundary; `undefined` is the operator view.
   */
  listAgentCostBurn(tenantScope: string | undefined, period: string): StoredAgentCostBurn[] {
    const out = [...this.rows.values()]
      .filter((r) => r.period === period)
      .filter((r) => tenantScope === undefined || r.tenantId === tenantScope)
      .map((r) => ({ ...r }));
    out.sort(
      (a, b) =>
        b.accumulatedUsd - a.accumulatedUsd ||
        a.tenantId.localeCompare(b.tenantId) ||
        a.agentKey.localeCompare(b.agentKey),
    );
    return out;
  }
}
