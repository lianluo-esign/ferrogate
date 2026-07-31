/**
 * Contract group `admin_agent_schedule` (8 operations).
 *
 * The canonical admin CRUD family — `crates/ferrogate-gateway/src/server/agent_schedules.rs`
 * is the file the generic handlers in `./resource.ts` were ported from, so this
 * module is mostly the six derived shapes plus two bespoke operations:
 *
 * ```
 *   GET  /admin/v1/agent-schedules/{id}/fires     list past fires of one schedule
 *   POST /admin/v1/agent-schedules/{id}/run-now   fire it immediately
 * ```
 *
 * `run-now` is a mutation on an existing row (`admin.write`), so it loads the
 * schedule *for the caller's scope* first — Rust's `load_scoped_schedule`. A
 * tenant-scoped caller firing another tenant's schedule would be a
 * cross-tenant write, which is why the id is never used bare.
 */
import { z } from "zod";
import {
  actionHandler,
  adminRecordSchema,
  crudGroup,
  subListHandler,
  type CollectionSpec,
  type GroupModule,
} from "./resource.js";

export const agentScheduleSchema = adminRecordSchema.extend({
  /** Cron expression or interval the scheduler fires on. */
  schedule: z.string().trim().min(1).optional(),
  enabled: z.boolean().optional(),
  workspace_id: z.string().trim().min(1).nullish(),
});

const AGENT_SCHEDULE_SPEC: CollectionSpec = {
  segment: "agent-schedules",
  object: "agent_schedule",
  body: agentScheduleSchema,
};

export const adminAgentScheduleRoutes: GroupModule = crudGroup(
  "admin_agent_schedule",
  [AGENT_SCHEDULE_SPEC],
  {
    listAdminAgentScheduleFires: subListHandler({
      parent: AGENT_SCHEDULE_SPEC,
      parentParam: "id",
      collection: "agent-schedule-fires",
      parentField: "schedule_id",
    }),

    runAdminAgentScheduleNow: actionHandler({
      spec: AGENT_SCHEDULE_SPEC,
      param: "id",
      apply: (_record, _body, now) => ({ last_run_requested_at: now, run_now: true }),
    }),
  },
);
