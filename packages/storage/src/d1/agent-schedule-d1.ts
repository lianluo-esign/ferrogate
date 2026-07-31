/**
 * `D1AgentScheduleStore` — the durable half of `../agent-schedule.ts` (#246), on
 * a tenant handle.
 *
 * ## The at-most-once gate lives here and nowhere else
 *
 * {@link D1AgentScheduleStore.insertScheduleFire} runs
 * `INSERT ... ON CONFLICT (schedule_id, scheduled_fire_at_unix) DO NOTHING
 * RETURNING fire_id` against the `UNIQUE (schedule_id, scheduled_fire_at_unix)`
 * in `sql/d1-ts/tenant/0001_init_tenant.sql`. A returned row means THIS caller
 * won the slot; an empty set means a peer already claimed it.
 *
 * That single statement is the entire correctness argument for at-most-once
 * firing. There is no lock, no lease, and no coordination anywhere else in the
 * schedule path — two Workers woken by the same cron minute both compute the
 * same deterministic slot and both attempt the same deterministic
 * `fire_id`, and SQLite admits exactly one. Remove the `ON CONFLICT` and the
 * insert throws instead, which a caller could plausibly swallow; remove the
 * UNIQUE and BOTH callers win and the same paid agent run is dispatched twice.
 * `test/d1/agent-schedule-d1.test.ts` races the claim and mutation-pins both.
 *
 * ## Delete must cascade, by hand
 *
 * D1 carries no cross-table FK, so the Postgres `ON DELETE CASCADE` from
 * `agent_schedule_fires` onto `agent_schedules` is gone.
 * {@link D1AgentScheduleStore.deleteSchedule} deletes the fire rows AND the
 * schedule as ONE atomic `batch()`. That is not tidiness: an orphaned fire
 * ledger would make a re-created same-id schedule believe its first slots had
 * already fired, and the at-most-once gate would then silently suppress every
 * one of them.
 *
 * ## Which database
 *
 * Both tables are TENANT-database tables, so the cascade batch and the claim are
 * local and their atomicity is genuine.
 */
import {
  type CatchupPolicy,
  type OverlapPolicy,
  type ScheduleFireOutcome,
  type ScheduleSpecKind,
  type ScheduleTargetKind,
  type StoredAgentSchedule,
  type StoredAgentScheduleFire,
  agentScheduleFireId,
  catchupPolicyFromString,
  overlapPolicyFromString,
  scheduleFireOutcomeFromString,
  scheduleSpecKindFromString,
  scheduleTargetKindFromString,
  validateAgentSchedule,
} from "../agent-schedule.js";
import { StorageError } from "../errors.js";
import { type TenantDatabaseHandle, requireAtomicBatch } from "../tenant-router.js";
import {
  bindOptional,
  boolFromSqlite,
  boolToSqlite,
  d1Error,
  optionalNumber,
  optionalText,
} from "./rows.js";

/** The projection order shared by every `agent_schedules` read. */
export const AGENT_SCHEDULE_COLUMNS =
  "schedule_id, tenant_id, workspace_id, name, enabled, spec_kind, cron_expr, timezone, " +
  "interval_secs, target_kind, target_json, overlap_policy, catchup_policy, jitter_secs, " +
  "next_fire_at_unix, last_fire_at_unix, created_at_unix, updated_at_unix, revision";

/** The projection order shared by every `agent_schedule_fires` read. */
export const AGENT_SCHEDULE_FIRE_COLUMNS =
  "fire_id, schedule_id, scheduled_fire_at_unix, fired_at_unix, node_id, outcome, " +
  "dispatch_id, run_id, detail";

/**
 * The at-most-once claim. Exported so the mutation proof can assert the
 * `ON CONFLICT ... DO NOTHING RETURNING` is present in the SQL the store
 * actually runs — an outcome-only test would still pass against a plain INSERT
 * wrapped in a try/catch, which loses the ability to tell "I won" from "the
 * write failed".
 */
export const INSERT_SCHEDULE_FIRE_SQL = `INSERT INTO agent_schedule_fires (${AGENT_SCHEDULE_FIRE_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (schedule_id, scheduled_fire_at_unix) DO NOTHING RETURNING fire_id`;

/**
 * The due scan. `enabled = 1` is the SQLite spelling of the Postgres boolean,
 * and `next_fire_at_unix IS NOT NULL` keeps an unschedulable definition (a
 * broken interval, an uncomputable cron) permanently out of the hot path rather
 * than re-erroring on it every tick. Both predicates match the partial index.
 */
export const LIST_DUE_SCHEDULES_SQL = `SELECT ${AGENT_SCHEDULE_COLUMNS} FROM agent_schedules WHERE enabled = 1 AND next_fire_at_unix IS NOT NULL AND next_fire_at_unix <= ? ORDER BY next_fire_at_unix ASC LIMIT ?`;

interface AgentScheduleRow {
  schedule_id: string;
  tenant_id: string;
  workspace_id: string;
  name: string;
  enabled: number;
  spec_kind: string;
  cron_expr: string | null;
  timezone: string;
  interval_secs: number | null;
  target_kind: string;
  target_json: string;
  overlap_policy: string;
  catchup_policy: string;
  jitter_secs: number;
  next_fire_at_unix: number | null;
  last_fire_at_unix: number | null;
  created_at_unix: number;
  updated_at_unix: number;
  revision: number;
}

function requireEnum<T>(value: T | undefined, column: string, raw: string): T {
  if (value === undefined) {
    // Fail CLOSED on an unknown token. Defaulting an unrecognized
    // `overlap_policy` to `skip`, or an unrecognized `catchup_policy` to
    // `skip_missed`, would silently change when a schedule fires.
    throw StorageError.runtime(`unknown ${column} ${raw}`);
  }
  return value;
}

function intoStoredSchedule(row: AgentScheduleRow): StoredAgentSchedule {
  const specKind: ScheduleSpecKind = requireEnum(
    scheduleSpecKindFromString(row.spec_kind),
    "agent_schedules.spec_kind",
    row.spec_kind,
  );
  const targetKind: ScheduleTargetKind = requireEnum(
    scheduleTargetKindFromString(row.target_kind),
    "agent_schedules.target_kind",
    row.target_kind,
  );
  const overlapPolicy: OverlapPolicy = requireEnum(
    overlapPolicyFromString(row.overlap_policy),
    "agent_schedules.overlap_policy",
    row.overlap_policy,
  );
  const catchupPolicy: CatchupPolicy = requireEnum(
    catchupPolicyFromString(row.catchup_policy),
    "agent_schedules.catchup_policy",
    row.catchup_policy,
  );
  return {
    scheduleId: row.schedule_id,
    tenantId: row.tenant_id,
    workspaceId: row.workspace_id,
    name: row.name,
    enabled: boolFromSqlite(row.enabled),
    specKind,
    cronExpr: optionalText(row.cron_expr),
    timezone: row.timezone,
    intervalSecs: optionalNumber(row.interval_secs),
    targetKind,
    targetJson: row.target_json,
    overlapPolicy,
    catchupPolicy,
    jitterSecs: Number(row.jitter_secs),
    nextFireAtUnix: optionalNumber(row.next_fire_at_unix),
    lastFireAtUnix: optionalNumber(row.last_fire_at_unix),
    createdAtUnix: Number(row.created_at_unix),
    updatedAtUnix: Number(row.updated_at_unix),
    revision: Number(row.revision),
  };
}

interface AgentScheduleFireRow {
  fire_id: string;
  schedule_id: string;
  scheduled_fire_at_unix: number;
  fired_at_unix: number;
  node_id: string | null;
  outcome: string;
  dispatch_id: string | null;
  run_id: string | null;
  detail: string | null;
}

function intoStoredFire(row: AgentScheduleFireRow): StoredAgentScheduleFire {
  const outcome: ScheduleFireOutcome = requireEnum(
    scheduleFireOutcomeFromString(row.outcome),
    "agent_schedule_fires.outcome",
    row.outcome,
  );
  return {
    fireId: row.fire_id,
    scheduleId: row.schedule_id,
    scheduledFireAtUnix: Number(row.scheduled_fire_at_unix),
    firedAtUnix: Number(row.fired_at_unix),
    nodeId: optionalText(row.node_id),
    outcome,
    dispatchId: optionalText(row.dispatch_id),
    runId: optionalText(row.run_id),
    detail: optionalText(row.detail),
  };
}

function changes(result: D1Response): number {
  const meta = result.meta as { changes?: number } | undefined;
  return meta?.changes ?? 0;
}

export class D1AgentScheduleStore {
  private readonly db: D1Database;

  constructor(private readonly handle: TenantDatabaseHandle) {
    this.db = handle.db;
  }

  /**
   * Create or replace a schedule definition.
   *
   * Validated BEFORE the write ({@link ../agent-schedule.js
   * validateAgentSchedule}), so a broken cron expression or a `target_json` that
   * is not JSON is refused at the API boundary instead of silently landing and
   * then failing inside a background tick nobody is watching.
   *
   * `created_at_unix` is preserved across a replace; `revision` is taken from the
   * caller so an admin API can carry its own optimistic-concurrency token.
   */
  async upsertSchedule(schedule: StoredAgentSchedule): Promise<void> {
    const problem = validateAgentSchedule(schedule);
    if (problem !== undefined) {
      throw StorageError.runtime(`invalid agent schedule ${schedule.scheduleId}: ${problem}`);
    }
    try {
      await this.db
        .prepare(
          `INSERT INTO agent_schedules (${AGENT_SCHEDULE_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (schedule_id) DO UPDATE SET workspace_id = excluded.workspace_id, name = excluded.name, enabled = excluded.enabled, spec_kind = excluded.spec_kind, cron_expr = excluded.cron_expr, timezone = excluded.timezone, interval_secs = excluded.interval_secs, target_kind = excluded.target_kind, target_json = excluded.target_json, overlap_policy = excluded.overlap_policy, catchup_policy = excluded.catchup_policy, jitter_secs = excluded.jitter_secs, next_fire_at_unix = excluded.next_fire_at_unix, last_fire_at_unix = excluded.last_fire_at_unix, updated_at_unix = excluded.updated_at_unix, revision = excluded.revision`,
        )
        .bind(
          schedule.scheduleId,
          schedule.tenantId,
          schedule.workspaceId,
          schedule.name,
          boolToSqlite(schedule.enabled),
          schedule.specKind,
          bindOptional(schedule.cronExpr),
          schedule.timezone,
          bindOptional(schedule.intervalSecs),
          schedule.targetKind,
          schedule.targetJson,
          schedule.overlapPolicy,
          schedule.catchupPolicy,
          schedule.jitterSecs,
          bindOptional(schedule.nextFireAtUnix),
          bindOptional(schedule.lastFireAtUnix),
          schedule.createdAtUnix,
          schedule.updatedAtUnix,
          schedule.revision,
        )
        .run();
    } catch (error) {
      throw d1Error("upsert_agent_schedule", error);
    }
  }

  /** One schedule by id, or `undefined`. */
  async getSchedule(scheduleId: string): Promise<StoredAgentSchedule | undefined> {
    try {
      const row = await this.db
        .prepare(`SELECT ${AGENT_SCHEDULE_COLUMNS} FROM agent_schedules WHERE schedule_id = ?`)
        .bind(scheduleId)
        .first<AgentScheduleRow>();
      return row === null ? undefined : intoStoredSchedule(row);
    } catch (error) {
      throw d1Error("get_agent_schedule", error);
    }
  }

  /** One tenant's schedules, optionally one workspace, ordered by name. */
  async listSchedules(tenantId: string, workspaceId?: string): Promise<StoredAgentSchedule[]> {
    try {
      const statement =
        workspaceId === undefined
          ? this.db
              .prepare(
                `SELECT ${AGENT_SCHEDULE_COLUMNS} FROM agent_schedules WHERE tenant_id = ? ORDER BY workspace_id ASC, name ASC`,
              )
              .bind(tenantId)
          : this.db
              .prepare(
                `SELECT ${AGENT_SCHEDULE_COLUMNS} FROM agent_schedules WHERE tenant_id = ? AND workspace_id = ? ORDER BY name ASC`,
              )
              .bind(tenantId, workspaceId);
      const rows = await statement.all<AgentScheduleRow>();
      return rows.results.map(intoStoredSchedule);
    } catch (error) {
      throw d1Error("list_agent_schedules", error);
    }
  }

  /**
   * Enabled schedules whose `next_fire_at_unix` has arrived, soonest first,
   * bounded by `limit`.
   *
   * The bound is not a nicety: an unbounded due scan after a long outage would
   * pull every backlogged schedule into one tick, and a Worker invocation has a
   * wall-clock budget. A backlog drains across ticks instead.
   */
  async listDueSchedules(nowUnix: number, limit: number): Promise<StoredAgentSchedule[]> {
    if (!Number.isInteger(limit) || limit <= 0) {
      throw StorageError.runtime(
        `list_due_agent_schedules requires a positive integer limit, got ${limit}`,
      );
    }
    try {
      const rows = await this.db
        .prepare(LIST_DUE_SCHEDULES_SQL)
        .bind(nowUnix, limit)
        .all<AgentScheduleRow>();
      return rows.results.map(intoStoredSchedule);
    } catch (error) {
      throw d1Error("list_due_agent_schedules", error);
    }
  }

  /**
   * Move a schedule's cursor after a fire: record the slot as
   * `last_fire_at_unix` and set the new `next_fire_at_unix`.
   *
   * `nextFireAtUnix === undefined` writes SQL NULL and leaves the schedule
   * UNSCHEDULED — the fail-safe state for a definition whose next fire cannot be
   * computed. The due query skips it, so a broken schedule stops firing instead
   * of firing wrongly, and an operator sees a null cursor rather than a loop.
   */
  async advanceSchedule(
    scheduleId: string,
    lastFireAtUnix: number,
    nextFireAtUnix: number | undefined,
    nowUnix: number,
  ): Promise<boolean> {
    try {
      const result = await this.db
        .prepare(
          "UPDATE agent_schedules SET last_fire_at_unix = ?, next_fire_at_unix = ?, " +
            "updated_at_unix = ? WHERE schedule_id = ?",
        )
        .bind(lastFireAtUnix, bindOptional(nextFireAtUnix), nowUnix, scheduleId)
        .run();
      return changes(result) > 0;
    } catch (error) {
      throw d1Error("advance_agent_schedule", error);
    }
  }

  /**
   * Claim one `(schedule, slot)` — THE at-most-once gate.
   *
   * `true` means this caller won the slot and MUST run the target exactly once.
   * `false` means a peer already claimed it and this caller must do nothing —
   * not retry, not run the target "just in case". A `false` is a normal outcome
   * on every tick where two isolates raced, not an error.
   *
   * The `fireId` is recomputed here from `(scheduleId, slot)` rather than taken
   * from the caller, so a caller that generated a random id cannot accidentally
   * defeat the deterministic-key half of the idempotency.
   */
  async insertScheduleFire(fire: StoredAgentScheduleFire): Promise<boolean> {
    const fireId = agentScheduleFireId(fire.scheduleId, fire.scheduledFireAtUnix);
    try {
      const result = await this.db
        .prepare(INSERT_SCHEDULE_FIRE_SQL)
        .bind(
          fireId,
          fire.scheduleId,
          fire.scheduledFireAtUnix,
          fire.firedAtUnix,
          bindOptional(fire.nodeId),
          fire.outcome,
          bindOptional(fire.dispatchId),
          bindOptional(fire.runId),
          bindOptional(fire.detail),
        )
        .all<{ fire_id: string }>();
      return result.results.length > 0;
    } catch (error) {
      throw d1Error("insert_agent_schedule_fire", error);
    }
  }

  /** One schedule's fire history, most recent slot first, bounded by `limit`. */
  async listScheduleFires(scheduleId: string, limit: number): Promise<StoredAgentScheduleFire[]> {
    if (!Number.isInteger(limit) || limit <= 0) {
      throw StorageError.runtime(
        `list_agent_schedule_fires requires a positive integer limit, got ${limit}`,
      );
    }
    try {
      const rows = await this.db
        .prepare(
          `SELECT ${AGENT_SCHEDULE_FIRE_COLUMNS} FROM agent_schedule_fires WHERE schedule_id = ? ORDER BY scheduled_fire_at_unix DESC LIMIT ?`,
        )
        .bind(scheduleId, limit)
        .all<AgentScheduleFireRow>();
      return rows.results.map(intoStoredFire);
    } catch (error) {
      throw d1Error("list_agent_schedule_fires", error);
    }
  }

  /**
   * Delete a schedule AND cascade its fire ledger, as one atomic `batch()`.
   *
   * The cascade is mandatory, not hygiene. D1 has no cross-table FK, so a
   * surviving fire ledger would make a schedule re-created with the same id
   * believe its early slots had already fired — and the at-most-once gate would
   * then suppress every one of them, silently, forever.
   *
   * `true` iff the schedule row existed; the `RETURNING` on the second statement
   * reports that, so a concurrent delete is `false` rather than a phantom
   * success.
   */
  async deleteSchedule(scheduleId: string): Promise<boolean> {
    requireAtomicBatch(this.handle, "delete_agent_schedule");
    try {
      const results = await this.db.batch([
        this.db.prepare("DELETE FROM agent_schedule_fires WHERE schedule_id = ?").bind(scheduleId),
        this.db
          .prepare("DELETE FROM agent_schedules WHERE schedule_id = ? RETURNING schedule_id")
          .bind(scheduleId),
      ]);
      return (results[1] as D1Result<{ schedule_id: string }>).results.length > 0;
    } catch (error) {
      throw d1Error("delete_agent_schedule", error);
    }
  }
}
