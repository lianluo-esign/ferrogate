/**
 * Tenant-owned schedule persistence for the Durable Object backend.
 *
 * The legacy control-plane scheduler stores an `agent-schedules` document in
 * the account database. A tenant object is different: the object is already
 * the isolation boundary, so schedule ids are only unique inside that tenant
 * and every read must be routed with the tenant before it can touch SQL.
 *
 * This adapter intentionally contains no fleet scan. Platform-operator views
 * may fan out over the provisioned tenant roster, but the hot path always
 * resolves one tenant and opens one `D1AgentScheduleStore`.
 */
import {
  D1AgentScheduleStore,
  type ScheduleFireOutcome,
  type StoredAgentSchedule,
  type StoredAgentScheduleFire,
  type TenantDatabaseHandle,
  type TenantDatabaseRouter,
  scheduleFireOutcomeFromString,
} from "@ferrogate/storage";
import type { CallerScope, StoreRecord } from "../ports.js";
import {
  RESOURCE_BACKFILL_BATCH_SIZE,
  backfillTenantResourceKinds,
} from "../store/resource-backfill.js";
import { scheduleSpecFromRecord } from "./model.js";

export const DEFAULT_SCHEDULE_WORKSPACE = "default";
export const TYPED_SCHEDULE_MIGRATION_MARK = "agent_schedule_typed_migration_v1";

export interface TenantScheduleRepository {
  readonly handle: TenantDatabaseHandle;
  readonly store: D1AgentScheduleStore;
}

/** Resolve a tenant schedule store without falling back to the control DB. */
export async function openTenantScheduleRepository(
  router: TenantDatabaseRouter,
  tenantId: string,
  controlDatabase?: D1Database | null,
): Promise<TenantScheduleRepository | null> {
  const handle = await router.forTenant(tenantId);
  if (handle.source !== "durable_object") return null;
  const store = new D1AgentScheduleStore(handle);
  if (controlDatabase !== null && controlDatabase !== undefined) {
    await migrateLegacySchedules(controlDatabase, handle, store, tenantId);
  }
  return { handle, store };
}

interface LegacyScheduleResourceRow {
  readonly resource_kind: string;
  readonly resource_id: string;
  readonly document_json: string;
  readonly revision: number;
  readonly created_at_unix: number;
  readonly updated_at_unix: number;
}

function legacyRecord(row: LegacyScheduleResourceRow, tenantId: string): StoreRecord {
  let parsed: unknown;
  try {
    parsed = JSON.parse(row.document_json);
  } catch {
    throw new Error(`legacy ${row.resource_kind}/${row.resource_id} has malformed document_json`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`legacy ${row.resource_kind}/${row.resource_id} is not an object document`);
  }
  return {
    ...(parsed as StoreRecord),
    id: row.resource_id,
    tenant_id: tenantId,
    revision: row.revision,
    created_at_unix: row.created_at_unix,
    updated_at_unix: row.updated_at_unix,
  };
}

function legacyFireFromRecord(
  record: StoreRecord,
  row: LegacyScheduleResourceRow,
): StoredAgentScheduleFire {
  const scheduleId = requiredString(record.schedule_id, `${row.resource_id}.schedule_id`);
  const scheduledFireAtUnix = optionalUnix(record.scheduled_fire_at_unix);
  const firedAtUnix = optionalUnix(record.fired_at_unix);
  if (scheduledFireAtUnix === undefined || firedAtUnix === undefined) {
    throw new Error(`legacy ${row.resource_kind}/${row.resource_id} has invalid fire timestamps`);
  }
  const rawOutcome = requiredString(record.outcome, `${row.resource_id}.outcome`);
  const outcome: ScheduleFireOutcome | undefined = scheduleFireOutcomeFromString(rawOutcome);
  if (outcome === undefined)
    throw new Error(`legacy ${row.resource_id} has unknown fire outcome ${rawOutcome}`);
  return {
    fireId: row.resource_id,
    scheduleId,
    scheduledFireAtUnix,
    firedAtUnix,
    nodeId: typeof record.node_id === "string" ? record.node_id : undefined,
    outcome,
    dispatchId: typeof record.dispatch_id === "string" ? record.dispatch_id : undefined,
    runId: typeof record.run_id === "string" ? record.run_id : undefined,
    detail: typeof record.detail === "string" ? record.detail : undefined,
  };
}

/**
 * Copy legacy generic schedule documents before the alarm path can observe an
 * empty typed table. The generic backfill is paged, so drain it fully before
 * taking the typed migration mark; otherwise a large tenant would be marked
 * complete after only the first 200 compatibility rows.
 */
async function migrateLegacySchedules(
  controlDatabase: D1Database,
  handle: TenantDatabaseHandle,
  store: D1AgentScheduleStore,
  tenantId: string,
): Promise<void> {
  let page: { scanned: number };
  do {
    page = await backfillTenantResourceKinds(controlDatabase, handle.db, tenantId);
  } while (page.scanned === RESOURCE_BACKFILL_BATCH_SIZE);

  const mark = await handle.db
    .prepare("SELECT 1 AS applied FROM tenant_provisioning_marks WHERE tenant_id = ? AND mark = ?")
    .bind(tenantId, TYPED_SCHEDULE_MIGRATION_MARK)
    .first<{ applied: number }>();
  if (mark !== null) return;

  const rows = await handle.db
    .prepare(
      "SELECT resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix FROM tenant_resources WHERE resource_kind IN (?, ?) ORDER BY resource_kind, resource_id",
    )
    .bind("agent-schedules", "agent-schedule-fires")
    .all<LegacyScheduleResourceRow>();

  for (const row of rows.results) {
    const record = legacyRecord(row, tenantId);
    if (row.resource_kind === "agent-schedules") {
      if ((await store.getSchedule(row.resource_id)) === undefined) {
        await store.upsertSchedule(storedScheduleFromRecord(record, tenantId, row.updated_at_unix));
      }
    } else {
      await store.insertScheduleFireWithId(legacyFireFromRecord(record, row));
    }
  }

  await handle.db
    .prepare(
      `INSERT INTO tenant_provisioning_marks (tenant_id, mark, detail, applied_at_unix)
       VALUES (?, ?, ?, ?)
       ON CONFLICT (tenant_id, mark) DO NOTHING`,
    )
    .bind(
      tenantId,
      TYPED_SCHEDULE_MIGRATION_MARK,
      JSON.stringify({ version: 1, rows: rows.results.length }),
      Math.floor(Date.now() / 1000),
    )
    .run();
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${field} must be a non-empty string`);
  }
  return value.trim();
}

function optionalUnix(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) ? value : undefined;
}

function targetObject(record: Readonly<Record<string, unknown>>): Record<string, unknown> {
  if (
    typeof record.target === "object" &&
    record.target !== null &&
    !Array.isArray(record.target)
  ) {
    return record.target as Record<string, unknown>;
  }
  if (typeof record.target_json === "string" && record.target_json.trim() !== "") {
    try {
      const parsed: unknown = JSON.parse(record.target_json);
      if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      // The durable write path below refuses malformed JSON. This fallback is
      // only for reading a legacy row without turning a list endpoint into a
      // cross-tenant exception.
    }
  }
  return {};
}

/** Convert the admin wire/document shape into the tenant table DTO. */
export function storedScheduleFromRecord(
  record: Readonly<Record<string, unknown>>,
  tenantId: string,
  nowUnix: number,
): StoredAgentSchedule {
  const id = requiredString(record.id, "agent schedule id");
  const spec = scheduleSpecFromRecord(record);
  const workspaceId =
    typeof record.workspace_id === "string" && record.workspace_id.trim() !== ""
      ? record.workspace_id.trim()
      : DEFAULT_SCHEDULE_WORKSPACE;
  const name =
    typeof record.name === "string" && record.name.trim() !== "" ? record.name.trim() : id;
  const createdAtUnix = optionalUnix(record.created_at_unix) ?? nowUnix;
  const updatedAtUnix = optionalUnix(record.updated_at_unix) ?? nowUnix;
  const revision = optionalUnix(record.revision) ?? 1;

  return {
    scheduleId: id,
    tenantId: requiredString(tenantId, "tenant_id"),
    workspaceId,
    name,
    enabled: spec.enabled,
    specKind: spec.spec_kind,
    cronExpr: spec.cron_expr ?? undefined,
    timezone: spec.timezone,
    intervalSecs: spec.interval_secs ?? undefined,
    targetKind: spec.target_kind,
    targetJson: JSON.stringify(targetObject(record)),
    overlapPolicy: spec.overlap_policy,
    catchupPolicy: spec.catchup_policy,
    jitterSecs: spec.jitter_secs,
    nextFireAtUnix: optionalUnix(record.next_fire_at_unix),
    lastFireAtUnix: optionalUnix(record.last_fire_at_unix),
    createdAtUnix,
    updatedAtUnix,
    revision,
  };
}

function parseTargetJson(targetJson: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(targetJson);
    if (typeof value === "object" && value !== null && !Array.isArray(value)) {
      return value as Record<string, unknown>;
    }
  } catch {
    // A malformed durable row is surfaced as an empty target, never executed
    // as arbitrary data. The write validator prevents new rows from reaching
    // this branch.
  }
  return {};
}

/** Convert the tenant DTO back into the existing admin response shape. */
export function recordFromStoredSchedule(schedule: StoredAgentSchedule): StoreRecord {
  return {
    id: schedule.scheduleId,
    tenant_id: schedule.tenantId,
    workspace_id: schedule.workspaceId,
    name: schedule.name,
    enabled: schedule.enabled,
    spec_kind: schedule.specKind,
    cron_expr: schedule.cronExpr ?? null,
    timezone: schedule.timezone,
    interval_secs: schedule.intervalSecs ?? null,
    target_kind: schedule.targetKind,
    target: parseTargetJson(schedule.targetJson),
    target_json: schedule.targetJson,
    overlap_policy: schedule.overlapPolicy,
    catchup_policy: schedule.catchupPolicy,
    jitter_secs: schedule.jitterSecs,
    next_fire_at_unix: schedule.nextFireAtUnix ?? null,
    last_fire_at_unix: schedule.lastFireAtUnix ?? null,
    created_at_unix: schedule.createdAtUnix,
    updated_at_unix: schedule.updatedAtUnix,
    revision: schedule.revision,
  };
}

/** Convert one tenant fire row into the admin response shape. */
export function recordFromStoredFire(fire: StoredAgentScheduleFire): StoreRecord {
  return {
    id: fire.fireId,
    fire_id: fire.fireId,
    schedule_id: fire.scheduleId,
    scheduled_fire_at_unix: fire.scheduledFireAtUnix,
    fired_at_unix: fire.firedAtUnix,
    node_id: fire.nodeId ?? null,
    outcome: fire.outcome,
    dispatch_id: fire.dispatchId ?? null,
    run_id: fire.runId ?? null,
    detail: fire.detail ?? null,
  };
}

/** Resolve the tenant requested by an admin operation. */
export function tenantForScheduleScope(
  scope: CallerScope,
  requestedTenantId: unknown,
): string | null {
  if (scope.kind === "tenant") return scope.tenantId;
  if (typeof requestedTenantId !== "string" || requestedTenantId.trim() === "") return null;
  return requestedTenantId.trim();
}

export async function getTenantSchedule(
  router: TenantDatabaseRouter,
  tenantId: string,
  scheduleId: string,
  controlDatabase?: D1Database | null,
): Promise<{
  repository: TenantScheduleRepository;
  schedule: StoredAgentSchedule | undefined;
} | null> {
  const repository = await openTenantScheduleRepository(router, tenantId, controlDatabase);
  if (repository === null) return null;
  return { repository, schedule: await repository.store.getSchedule(scheduleId) };
}

export async function listTenantSchedules(
  router: TenantDatabaseRouter,
  tenantId: string,
  workspaceId?: string,
  controlDatabase?: D1Database | null,
): Promise<{ repository: TenantScheduleRepository; schedules: StoredAgentSchedule[] } | null> {
  const repository = await openTenantScheduleRepository(router, tenantId, controlDatabase);
  if (repository === null) return null;
  return { repository, schedules: await repository.store.listSchedules(tenantId, workspaceId) };
}

/** Arm the object's single alarm to the earliest enabled schedule deadline. */
export async function rearmTenantScheduleAlarm(
  router: TenantDatabaseRouter,
  tenantId: string,
  schedules?: readonly StoredAgentSchedule[],
): Promise<boolean> {
  if (router.rearmScheduleAlarm !== undefined) {
    await router.rearmScheduleAlarm(tenantId);
    return true;
  }
  if (router.setScheduleAlarm === undefined || router.clearScheduleAlarm === undefined) {
    return false;
  }
  if (schedules === undefined) return false;
  const earliest = schedules
    .filter(
      (schedule) =>
        schedule.enabled &&
        schedule.nextFireAtUnix !== undefined &&
        schedule.nextFireAtUnix !== null,
    )
    .map((schedule) => schedule.nextFireAtUnix as number)
    .sort((left, right) => left - right)[0];
  if (earliest === undefined) {
    await router.clearScheduleAlarm(tenantId);
  } else {
    await router.setScheduleAlarm(tenantId, earliest);
  }
  return true;
}
