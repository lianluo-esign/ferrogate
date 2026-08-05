/**
 * The queue message emitted by a tenant object's schedule alarm.
 *
 * The alarm is tenant-local, so the message deliberately carries no schedule,
 * worker, workspace, or target data. A consumer uses the tenant id to address
 * that tenant's object and reads the current private rows there. Keeping the
 * payload this small makes a queue retry safe to inspect and prevents an alarm
 * from becoming a cross-tenant data export.
 */

export const TENANT_SCHEDULE_ALARM_KIND = "tenant-schedule-alarm" as const;
export const TENANT_SCHEDULE_ALARM_VERSION = 1 as const;

export interface TenantScheduleAlarmMessage {
  readonly kind: typeof TENANT_SCHEDULE_ALARM_KIND;
  readonly version: typeof TENANT_SCHEDULE_ALARM_VERSION;
  readonly tenant_id: string;
  readonly scheduled_at_unix: number;
}

export class TenantScheduleAlarmError extends Error {
  override readonly name = "TenantScheduleAlarmError";
}

function requireTenantId(raw: unknown): string {
  if (typeof raw !== "string" || raw.trim() === "") {
    throw new TenantScheduleAlarmError("tenant_id must be a non-empty string");
  }
  return raw.trim();
}

function requireUnixSeconds(raw: unknown): number {
  if (typeof raw !== "number" || !Number.isSafeInteger(raw) || raw < 0) {
    throw new TenantScheduleAlarmError("scheduled_at_unix must be a non-negative safe integer");
  }
  return raw;
}

/** Build the only payload a tenant schedule alarm is allowed to publish. */
export function tenantScheduleAlarmMessage(
  tenantId: string,
  scheduledAtUnix: number,
): TenantScheduleAlarmMessage {
  return {
    kind: TENANT_SCHEDULE_ALARM_KIND,
    version: TENANT_SCHEDULE_ALARM_VERSION,
    tenant_id: requireTenantId(tenantId),
    scheduled_at_unix: requireUnixSeconds(scheduledAtUnix),
  };
}

/** Serialize an alarm using the same validated shape used by queue bindings. */
export function encodeTenantScheduleAlarm(message: TenantScheduleAlarmMessage): string {
  return JSON.stringify(
    tenantScheduleAlarmMessage(message.tenant_id, message.scheduled_at_unix),
  );
}

/** Parse and validate an untrusted queue body before addressing any object. */
export function decodeTenantScheduleAlarm(raw: unknown): TenantScheduleAlarmMessage {
  let value: unknown = raw;
  if (typeof raw === "string") {
    try {
      value = JSON.parse(raw) as unknown;
    } catch {
      throw new TenantScheduleAlarmError("alarm body must be valid JSON");
    }
  }

  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TenantScheduleAlarmError("alarm body must be an object");
  }
  const record = value as Record<string, unknown>;
  if (record.kind !== TENANT_SCHEDULE_ALARM_KIND) {
    throw new TenantScheduleAlarmError("alarm kind is not tenant-schedule-alarm");
  }
  if (record.version !== TENANT_SCHEDULE_ALARM_VERSION) {
    throw new TenantScheduleAlarmError("unsupported tenant schedule alarm version");
  }
  return tenantScheduleAlarmMessage(record.tenant_id as string, record.scheduled_at_unix as number);
}

/**
 * Check the routing boundary before a consumer reads or writes tenant state.
 * This is intentionally an exact comparison, never a prefix or workspace-only
 * match.
 */
export function assertTenantScheduleAlarmTenant(
  message: TenantScheduleAlarmMessage,
  tenantId: string,
): void {
  const expected = requireTenantId(tenantId);
  if (message.tenant_id !== expected) {
    throw new TenantScheduleAlarmError(
      `tenant schedule alarm belongs to ${message.tenant_id}, not ${expected}`,
    );
  }
}
