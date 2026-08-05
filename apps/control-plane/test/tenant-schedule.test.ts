import { describe, expect, test } from "vitest";
import {
  DEFAULT_SCHEDULE_WORKSPACE,
  recordFromStoredSchedule,
  storedScheduleFromRecord,
  tenantForScheduleScope,
} from "../src/schedule/tenant-schedule.js";

describe("tenant schedule adapter", () => {
  test("converts a schedule document into tenant-owned row data", () => {
    const stored = storedScheduleFromRecord(
      {
        id: "schedule-a",
        name: "nightly",
        spec_kind: "interval",
        interval_secs: 60,
        target_kind: "agent_run",
        target: { agent: "researcher" },
      },
      "tenant-a",
      100,
    );

    expect(stored).toMatchObject({
      scheduleId: "schedule-a",
      tenantId: "tenant-a",
      workspaceId: DEFAULT_SCHEDULE_WORKSPACE,
      targetJson: '{"agent":"researcher"}',
      nextFireAtUnix: undefined,
    });
  });

  test("round-trips typed schedule fields without exposing a second tenant", () => {
    const record = recordFromStoredSchedule(
      storedScheduleFromRecord(
        {
          id: "schedule-a",
          tenant_id: "tenant-a",
          workspace_id: "workspace-a",
          name: "nightly",
          cron_expr: "0 3 * * *",
          target: { agent: "researcher" },
          next_fire_at_unix: 120,
        },
        "tenant-a",
        100,
      ),
    );

    expect(record).toMatchObject({
      id: "schedule-a",
      tenant_id: "tenant-a",
      workspace_id: "workspace-a",
      next_fire_at_unix: 120,
      target: { agent: "researcher" },
    });
  });

  test("tenant credentials cannot select a different tenant for an operation", () => {
    expect(tenantForScheduleScope({ kind: "tenant", tenantId: "tenant-a" }, "tenant-b")).toBe(
      "tenant-a",
    );
    expect(tenantForScheduleScope({ kind: "platform_operator" }, "tenant-b")).toBe("tenant-b");
    expect(tenantForScheduleScope({ kind: "platform_operator" }, undefined)).toBeNull();
  });
});
