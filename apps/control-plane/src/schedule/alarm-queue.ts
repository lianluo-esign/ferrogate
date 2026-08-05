/**
 * Tenant schedule alarm delivery.
 *
 * The TenantDataObject owns the native deadline. This module owns the work
 * after that deadline: read the current tenant-local schedule rows, claim each
 * due slot with the object-local D1 batch, and only then dispatch the target.
 * There is deliberately no fleet list here; one queue message addresses one
 * tenant object.
 */
import {
  agentScheduleFireId,
  decodeTenantScheduleAlarm,
  type StoredAgentSchedule,
  type StoredAgentScheduleFire,
  planScheduleTick,
  scheduledDispatchId,
} from "@ferrogate/storage";
import type { ControlPlaneBindings, ControlPlaneDeps } from "../ports.js";
import { resolveDeps } from "../adapters.js";
import {
  dispatchScheduleTarget,
  SELF_HOSTED_DISPATCH_COLLECTION,
  type ScheduleFireResult,
} from "./engine.js";
import {
  openTenantScheduleRepository,
  recordFromStoredSchedule,
  rearmTenantScheduleAlarm,
  type TenantScheduleRepository,
} from "./tenant-schedule.js";
import { openTenantWorkerRepository } from "../store/tenant-worker.js";
import { manualScheduleFireId, scheduleSpecFromRecord } from "./model.js";

export const TENANT_SCHEDULE_ALARM_BATCH_SIZE = 200;

/** Minimal queue batch shape used by the entrypoint and node-side tests. */
export interface TenantScheduleAlarmBatch {
  readonly messages: readonly {
    readonly body: unknown;
    ack?(): void;
    retry?(): void;
  }[];
  retryAll?(options?: unknown): void;
}

export interface TenantScheduleAlarmReport {
  readonly tenantId: string;
  readonly scanned: number;
  readonly claimed: number;
  readonly skipped: number;
  readonly advanced: number;
  readonly dispatched: number;
  readonly errors: readonly string[];
}

const TERMINAL_DISPATCH_STATUSES = new Set([
  "acked",
  "completed",
  "succeeded",
  "failed",
  "cancelled",
  "canceled",
  "expired",
]);

function tenantScope(tenantId: string): { kind: "tenant"; tenantId: string } {
  return { kind: "tenant", tenantId };
}

async function previousDispatchUnacked(
  deps: ControlPlaneDeps,
  schedule: StoredAgentSchedule,
): Promise<boolean> {
  if (schedule.lastFireAtUnix === undefined || schedule.overlapPolicy !== "skip") return false;
  const record = await deps.store.get(
    SELF_HOSTED_DISPATCH_COLLECTION,
    tenantScope(schedule.tenantId),
    scheduledDispatchId(schedule.scheduleId, schedule.lastFireAtUnix),
  );
  if (record === null) return false;
  return !TERMINAL_DISPATCH_STATUSES.has(
    typeof record.status === "string" ? record.status : "",
  );
}

function provisionalFire(
  schedule: StoredAgentSchedule,
  slot: number,
  nowUnix: number,
  outcome: StoredAgentScheduleFire["outcome"],
): StoredAgentScheduleFire {
  return {
    fireId: agentScheduleFireId(schedule.scheduleId, slot),
    scheduleId: schedule.scheduleId,
    scheduledFireAtUnix: slot,
    firedAtUnix: nowUnix,
    nodeId: "control-plane-alarm",
    outcome,
    dispatchId: undefined,
    runId: undefined,
    detail: undefined,
  };
}

async function updateOutcome(
  repository: TenantScheduleRepository,
  fire: StoredAgentScheduleFire,
  result: ScheduleFireResult,
): Promise<void> {
  await repository.store.updateScheduleFireOutcome(
    fire.fireId,
    result.outcome,
    result.dispatch_id ?? undefined,
    result.run_id ?? undefined,
    result.detail ?? undefined,
  );
}

/** Keep the self-hosted dispatch queue in the tenant object with the schedule. */
async function projectSelfHostedDispatch(
  deps: ControlPlaneDeps,
  schedule: StoredAgentSchedule,
  result: ScheduleFireResult,
  nowUnix: number,
): Promise<void> {
  const dispatchId = result.dispatch_id;
  if (dispatchId === null || dispatchId === undefined) return;
  const record = await deps.store.get(
    SELF_HOSTED_DISPATCH_COLLECTION,
    tenantScope(schedule.tenantId),
    dispatchId,
  );
  if (record === null || typeof record.worker_id !== "string" || record.worker_id.trim() === "") {
    return;
  }
  const repository = await openTenantWorkerRepository(deps.tenantDatabases, schedule.tenantId);
  if (repository !== null) {
    await repository.recordDispatch(dispatchId, record, nowUnix);
  }
}

/** Process one validated alarm message against one tenant object. */
export async function runTenantScheduleAlarm(
  deps: ControlPlaneDeps,
  message: ReturnType<typeof decodeTenantScheduleAlarm>,
  nowUnix = Math.floor(Date.now() / 1000),
): Promise<TenantScheduleAlarmReport | null> {
  const repository = await openTenantScheduleRepository(
    deps.tenantDatabases,
    message.tenant_id,
    deps.controlDatabase,
  );
  if (repository === null) return null;

  const now = Math.max(nowUnix, message.scheduled_at_unix);
  const due = await repository.store.listDueSchedules(now, TENANT_SCHEDULE_ALARM_BATCH_SIZE);
  let claimed = 0;
  let skipped = 0;
  let advanced = 0;
  let dispatched = 0;
  const errors: string[] = [];

  for (const schedule of due) {
    let claimedFire: StoredAgentScheduleFire | undefined;
    try {
      const unacked = await previousDispatchUnacked(deps, schedule);
      const action = planScheduleTick(schedule, now, () => unacked);
      if (action.kind === "not_due") continue;

      if (action.kind === "advance_only") {
        if (
          await repository.store.advanceScheduleIfCurrent(
            schedule.scheduleId,
            action.slot,
            action.slot,
            action.advanceTo,
            now,
            schedule.revision,
          )
        ) {
          advanced += 1;
        }
        continue;
      }

      const fire = provisionalFire(schedule, action.slot, now, "error");
      const won = await repository.store.claimAndAdvanceSchedule(
        fire,
        action.advanceTo,
        now,
        schedule.revision,
      );
      if (!won) {
        skipped += 1;
        continue;
      }
      claimedFire = fire;
      claimed += 1;

      if (action.kind === "record_skip") {
        await repository.store.updateScheduleFireOutcome(
          fire.fireId,
          action.outcome,
          undefined,
          undefined,
          "previous dispatch still in flight",
        );
        skipped += 1;
        continue;
      }

      const record = recordFromStoredSchedule(schedule);
      const result = await dispatchScheduleTarget(
        { store: deps.store, lifecycle: deps.lifecycle, nodeId: "control-plane-alarm" },
        record,
        scheduleSpecFromRecord(record),
        action.slot,
        now,
      );
      await projectSelfHostedDispatch(deps, schedule, result, now);
      await updateOutcome(repository, fire, result);
      if (result.outcome === "dispatched") dispatched += 1;
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      if (claimedFire !== undefined) {
        try {
          await repository.store.updateScheduleFireOutcome(
            claimedFire.fireId,
            "error",
            undefined,
            undefined,
            detail,
          );
        } catch (outcomeError) {
          errors.push(
            `${schedule.scheduleId}: failed to persist dispatch error: ${
              outcomeError instanceof Error ? outcomeError.message : String(outcomeError)
            }`,
          );
        }
      }
      errors.push(`${schedule.scheduleId}: ${detail}`);
    }
  }

  await rearmTenantScheduleAlarm(deps.tenantDatabases, message.tenant_id);
  return {
    tenantId: message.tenant_id,
    scanned: due.length,
    claimed,
    skipped,
    advanced,
    dispatched,
    errors,
  };
}

/** Manual run-now for a schedule already loaded from a tenant object. */
export async function runTenantScheduleNow(
  deps: ControlPlaneDeps,
  repository: TenantScheduleRepository,
  schedule: StoredAgentSchedule,
  nowUnix: number,
): Promise<StoredAgentScheduleFire> {
  const fireId = manualScheduleFireId(schedule.scheduleId, nowUnix);
  const claimedFire: StoredAgentScheduleFire = {
    fireId,
    scheduleId: schedule.scheduleId,
    scheduledFireAtUnix: nowUnix,
    firedAtUnix: nowUnix,
    nodeId: "control-plane",
    outcome: "error",
    dispatchId: undefined,
    runId: undefined,
    detail: "manual run-now claim pending",
  };
  if (!(await repository.store.insertScheduleFireWithId(claimedFire))) {
    const existing =
      (await repository.store.getScheduleFire(fireId)) ??
      (await repository.store.getScheduleFireForSlot(schedule.scheduleId, nowUnix));
    if (existing === undefined) {
      throw new Error(`manual schedule fire ${fireId} was claimed but its row is unavailable`);
    }
    return existing;
  }

  const record = recordFromStoredSchedule(schedule);
  try {
    const result = await dispatchScheduleTarget(
      { store: deps.store, lifecycle: deps.lifecycle, nodeId: "control-plane" },
      record,
      scheduleSpecFromRecord(record),
      nowUnix,
      nowUnix,
    );
    await projectSelfHostedDispatch(deps, schedule, result, nowUnix);
    await repository.store.updateScheduleFireOutcome(
      fireId,
      result.outcome,
      result.dispatch_id ?? undefined,
      result.run_id ?? undefined,
      result.detail ?? "manual run-now trigger",
    );
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    await repository.store.updateScheduleFireOutcome(fireId, "error", undefined, undefined, detail);
  }
  await rearmTenantScheduleAlarm(deps.tenantDatabases, schedule.tenantId);
  return (await repository.store.getScheduleFire(fireId)) ?? claimedFire;
}

/** Queue entrypoint. Malformed messages are permanently bad and are acked. */
export async function consumeTenantScheduleAlarmBatch(
  batch: TenantScheduleAlarmBatch,
  env: ControlPlaneBindings,
): Promise<void> {
  const deps = resolveDeps(env, { requestId: "schedule-alarm-queue" });
  const supportsPerMessageRetry = batch.messages.every(
    (message) => message.retry !== undefined,
  );
  let retryBatch = false;
  for (const message of batch.messages) {
    let decoded: ReturnType<typeof decodeTenantScheduleAlarm>;
    try {
      decoded = decodeTenantScheduleAlarm(message.body);
    } catch {
      message.ack?.();
      continue;
    }
    try {
      await runTenantScheduleAlarm(deps, decoded);
      message.ack?.();
    } catch {
      const retry = message.retry;
      if (supportsPerMessageRetry && retry !== undefined) {
        retry();
      } else {
        // Structural test batches may expose only retryAll. Cloudflare's real
        // MessageBatch has retry(), so this fallback is never used in the
        // deployed queue and is kept only for the compatibility seam.
        retryBatch = true;
      }
    }
  }
  if (retryBatch) batch.retryAll?.();
}
