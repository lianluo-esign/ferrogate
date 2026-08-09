import { describe, expect, test } from "vitest";
import {
  TENANT_SCHEDULE_ALARM_KIND,
  assertTenantScheduleAlarmTenant,
  decodeTenantScheduleAlarm,
  encodeTenantScheduleAlarm,
  tenantScheduleAlarmMessage,
} from "../src/index.js";

describe("tenant schedule alarm contract", () => {
  test("publishes only the tenant routing key and alarm time", () => {
    const message = tenantScheduleAlarmMessage(" tenant-a ", 1_800_000_000);

    expect(message).toEqual({
      kind: TENANT_SCHEDULE_ALARM_KIND,
      version: 1,
      tenant_id: "tenant-a",
      scheduled_at_unix: 1_800_000_000,
    });
    expect(Object.keys(message).sort()).toEqual([
      "kind",
      "scheduled_at_unix",
      "tenant_id",
      "version",
    ]);
  });

  test("round-trips encoded queue data and rejects unsupported versions", () => {
    const encoded = encodeTenantScheduleAlarm(tenantScheduleAlarmMessage("tenant-a", 42));
    expect(decodeTenantScheduleAlarm(encoded)).toEqual(tenantScheduleAlarmMessage("tenant-a", 42));

    expect(() =>
      decodeTenantScheduleAlarm({
        kind: TENANT_SCHEDULE_ALARM_KIND,
        version: 2,
        tenant_id: "tenant-a",
        scheduled_at_unix: 42,
      }),
    ).toThrow(/unsupported/);
  });

  test("rejects malformed tenant or time values before routing", () => {
    expect(() => tenantScheduleAlarmMessage(" ", 42)).toThrow(/tenant_id/);
    expect(() => tenantScheduleAlarmMessage("tenant-a", -1)).toThrow(/scheduled_at_unix/);
    expect(() => decodeTenantScheduleAlarm("not-json")).toThrow(/valid JSON/);
  });

  test("does not allow a queue message to cross a tenant boundary", () => {
    const message = tenantScheduleAlarmMessage("tenant-a", 42);
    expect(() => assertTenantScheduleAlarmTenant(message, "tenant-a")).not.toThrow();
    expect(() => assertTenantScheduleAlarmTenant(message, "tenant-b")).toThrow(/tenant-a/);
  });
});
