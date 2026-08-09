/**
 * Monotonic upserts on real D1 (inventory §1.5.6).
 *
 * ## The invariant, and why it is not "just an upsert"
 *
 * Three families accumulate state from writes that can arrive **out of order**:
 * an observed-presence touch retried after a queue delay, a replay floor
 * re-announced by a lagging deployment, a cost-burn tick replayed from an
 * at-least-once queue. A plain `ON CONFLICT DO UPDATE SET x = excluded.x` is
 * LAST-WRITE-WINS, so a delayed write carrying an older timestamp **moves the
 * row backwards** — the agent disappears from the presence window, the replay
 * floor drops and a superseded snapshot is accepted again.
 *
 * The fix is that the merge itself must be order-independent: a *lattice join*
 * rather than an assignment.
 *
 *   * high-water columns (`last_seen_at_unix`, `last_accepted_revision`,
 *     `updated_at_unix`)  → `max(existing, incoming)`
 *   * low-water columns (`first_seen_at_unix`, `first_seen_unix`)
 *                                                → `min(existing, incoming)`
 *   * counters (`request_count`, `accumulated_usd`)
 *                                                → `existing + incoming`
 *
 * All three are commutative and associative, so any arrival order — and any
 * number of duplicate deliveries for `max`/`min` — reaches the same row.
 *
 * ## SQLite specifics that matter here
 *
 * `max(a, b)` and `min(a, b)` with TWO arguments are SQLite **scalar**
 * functions; the one-argument forms are the aggregates. SQLite has no
 * `GREATEST`/`LEAST` (which is what the Postgres backend used), so the scalar
 * two-argument form is the port. Inside `DO UPDATE` the existing row must be
 * addressed table-qualified (`observed_agent_presence.last_seen_at_unix`) and
 * the incoming one through `excluded.*`; writing the column bare would resolve
 * to the existing value on both sides and silently make the merge a no-op.
 *
 * Counters use `+` and NOT `max`: two genuinely distinct requests in the same
 * second must both count. That asymmetry is why `request_count` cannot be
 * folded with the timestamps and is stated here rather than being inferred.
 */

import type { StoredAgentCostBurn } from "../agent-cost-burn.js";
import type { ObservedAgentPresenceTouch, StoredObservedAgentPresence } from "../presence.js";
import type { TenantDatabaseHandle, TenantDatabaseRouter } from "../tenant-router.js";
import { d1Error } from "./rows.js";

// The DTOs are the SAME types the in-memory stores use (`../presence.js`,
// `../agent-cost-burn.js`) rather than D1-local copies. That is deliberate: a
// second declaration of the same row would let the two backends drift a field
// apart without a single compile error.

/**
 * Monotonic upserts against one TENANT database (presence, cost burn, replay
 * floors). Replay floors are tenant-private after #863.
 */
export class TenantMonotonicUpserts {
  private readonly db: D1Database;

  constructor(handle: TenantDatabaseHandle) {
    this.db = handle.db;
  }

  /**
   * Record one presence touch. Monotonic in both directions: `last_seen`
   * only ever moves forward, `first_seen` only ever moves backward, and the
   * request count accumulates.
   */
  async touchPresence(touch: ObservedAgentPresenceTouch, requestCount = 1): Promise<void> {
    const count = requestCount;
    try {
      await this.db
        .prepare(
          "INSERT INTO observed_agent_presence " +
            "(tenant_id, api_key_id, first_seen_at_unix, last_seen_at_unix, request_count, " +
            " updated_at_unix) " +
            "VALUES (?, ?, ?, ?, ?, ?) " +
            "ON CONFLICT (tenant_id, api_key_id) DO UPDATE SET " +
            "last_seen_at_unix = max(observed_agent_presence.last_seen_at_unix, " +
            "                        excluded.last_seen_at_unix), " +
            "first_seen_at_unix = min(observed_agent_presence.first_seen_at_unix, " +
            "                         excluded.first_seen_at_unix), " +
            "request_count = observed_agent_presence.request_count + excluded.request_count, " +
            "updated_at_unix = max(observed_agent_presence.updated_at_unix, " +
            "                      excluded.updated_at_unix)",
        )
        .bind(
          touch.tenantId,
          touch.apiKeyId,
          touch.seenAtUnix,
          touch.seenAtUnix,
          count,
          touch.seenAtUnix,
        )
        .run();
    } catch (error) {
      throw d1Error("touch_observed_presence", error);
    }
  }

  async getPresence(
    tenantId: string,
    apiKeyId: string,
  ): Promise<StoredObservedAgentPresence | undefined> {
    try {
      const row = await this.db
        .prepare(
          "SELECT tenant_id, api_key_id, first_seen_at_unix, last_seen_at_unix, request_count, " +
            "updated_at_unix FROM observed_agent_presence WHERE tenant_id = ? AND api_key_id = ?",
        )
        .bind(tenantId, apiKeyId)
        .first<{
          tenant_id: string;
          api_key_id: string;
          first_seen_at_unix: number;
          last_seen_at_unix: number;
          request_count: number;
          updated_at_unix: number;
        }>();
      if (!row) return undefined;
      return {
        tenantId: row.tenant_id,
        apiKeyId: row.api_key_id,
        firstSeenAtUnix: row.first_seen_at_unix,
        lastSeenAtUnix: row.last_seen_at_unix,
        requestCount: row.request_count,
        updatedAtUnix: row.updated_at_unix,
      };
    } catch (error) {
      throw d1Error("get_observed_presence", error);
    }
  }

  /**
   * Accumulate CF-hosted-agent runtime cost for one (tenant, agent, period).
   * `accumulated_usd` is REAL because it is compared against
   * `quota_policies.agent_cost_budget_usd`, which is REAL; keeping both in the
   * same representation is what makes the budget comparison exact.
   */
  async accumulateAgentCostBurn(
    tenantId: string,
    agentKey: string,
    period: string,
    deltaUsd: number,
    nowUnix: number,
  ): Promise<void> {
    try {
      await this.db
        .prepare(
          "INSERT INTO agent_cost_burn " +
            "(tenant_id, agent_key, period, accumulated_usd, first_seen_unix, updated_at_unix) " +
            "VALUES (?, ?, ?, ?, ?, ?) " +
            "ON CONFLICT (tenant_id, agent_key, period) DO UPDATE SET " +
            "accumulated_usd = agent_cost_burn.accumulated_usd + excluded.accumulated_usd, " +
            "first_seen_unix = min(agent_cost_burn.first_seen_unix, excluded.first_seen_unix), " +
            "updated_at_unix = max(agent_cost_burn.updated_at_unix, excluded.updated_at_unix)",
        )
        .bind(tenantId, agentKey, period, deltaUsd, nowUnix, nowUnix)
        .run();
    } catch (error) {
      throw d1Error("accumulate_agent_cost_burn", error);
    }
  }

  async getAgentCostBurn(
    tenantId: string,
    agentKey: string,
    period: string,
  ): Promise<StoredAgentCostBurn | undefined> {
    try {
      const row = await this.db
        .prepare(
          "SELECT tenant_id, agent_key, period, accumulated_usd, first_seen_unix, " +
            "updated_at_unix FROM agent_cost_burn " +
            "WHERE tenant_id = ? AND agent_key = ? AND period = ?",
        )
        .bind(tenantId, agentKey, period)
        .first<{
          tenant_id: string;
          agent_key: string;
          period: string;
          accumulated_usd: number;
          first_seen_unix: number;
          updated_at_unix: number;
        }>();
      if (!row) return undefined;
      return {
        tenantId: row.tenant_id,
        agentKey: row.agent_key,
        period: row.period,
        accumulatedUsd: row.accumulated_usd,
        firstSeenUnix: row.first_seen_unix,
        updatedAtUnix: row.updated_at_unix,
      };
    } catch (error) {
      throw d1Error("get_agent_cost_burn", error);
    }
  }

  /** Raise the tenant-private replay floor. */
  async raiseReplayFloor(
    tenantId: string,
    deploymentId: string,
    revision: number,
    nowUnix: number,
  ): Promise<number> {
    try {
      const row = await this.db
        .prepare(
          "INSERT INTO control_plane_replay_floors " +
            "(tenant_id, deployment_id, last_accepted_revision, updated_at_unix) " +
            "VALUES (?, ?, ?, ?) " +
            "ON CONFLICT (tenant_id, deployment_id) DO UPDATE SET " +
            "last_accepted_revision = max(control_plane_replay_floors.last_accepted_revision, " +
            "                             excluded.last_accepted_revision), " +
            "updated_at_unix = max(control_plane_replay_floors.updated_at_unix, " +
            "                      excluded.updated_at_unix) " +
            "RETURNING last_accepted_revision",
        )
        .bind(tenantId, deploymentId, revision, nowUnix)
        .first<{ last_accepted_revision: number }>();
      if (!row) throw d1Error("raise_replay_floor", new Error("upsert returned no row"));
      return row.last_accepted_revision;
    } catch (error) {
      throw d1Error("raise_replay_floor", error);
    }
  }

  async getReplayFloor(tenantId: string, deploymentId: string): Promise<number | undefined> {
    try {
      const row = await this.db
        .prepare(
          "SELECT last_accepted_revision FROM control_plane_replay_floors " +
            "WHERE tenant_id = ? AND deployment_id = ?",
        )
        .bind(tenantId, deploymentId)
        .first<{ last_accepted_revision: number }>();
      return row ? row.last_accepted_revision : undefined;
    } catch (error) {
      throw d1Error("get_replay_floor", error);
    }
  }
}

/**
 * Compatibility façade for callers that still own a "control" dependency.
 * Replay floors are tenant-private after #863, so every operation resolves the
 * tenant object and delegates to {@link TenantMonotonicUpserts}. There is no
 * control-D1 SQL or fallback path here.
 */
export class ControlMonotonicUpserts {
  constructor(private readonly router: TenantDatabaseRouter) {}

  /**
   * Raise a deployment's accepted-revision high-water mark. Returns the floor
   * AFTER the merge, which is `max(existing, revision)` — so a caller that
   * re-announces an older revision reads back the newer one and can detect that
   * its snapshot is superseded.
   */
  async raiseReplayFloor(
    tenantId: string,
    deploymentId: string,
    revision: number,
    nowUnix: number,
  ): Promise<number> {
    const handle = await this.router.forTenant(tenantId);
    return new TenantMonotonicUpserts(handle).raiseReplayFloor(
      tenantId,
      deploymentId,
      revision,
      nowUnix,
    );
  }

  async getReplayFloor(tenantId: string, deploymentId: string): Promise<number | undefined> {
    const handle = await this.router.forTenant(tenantId);
    return new TenantMonotonicUpserts(handle).getReplayFloor(tenantId, deploymentId);
  }
}
