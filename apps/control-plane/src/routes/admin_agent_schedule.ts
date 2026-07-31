/**
 * Contract group `admin_agent_schedule` (8 operations).
 *
 * ```
 *   GET    /admin/v1/agent-schedules              list
 *   POST   /admin/v1/agent-schedules              create   (201)
 *   GET    /admin/v1/agent-schedules/{id}         read
 *   PUT    /admin/v1/agent-schedules/{id}         replace
 *   PATCH  /admin/v1/agent-schedules/{id}         merge
 *   DELETE /admin/v1/agent-schedules/{id}         delete   (cascades the fires)
 *   GET    /admin/v1/agent-schedules/{id}/fires   fire history
 *   POST   /admin/v1/agent-schedules/{id}/run-now fire it immediately
 * ```
 *
 * ## THE MOUNT
 *
 * This module is where `src/schedule/` becomes reachable. Before it, the group
 * was pure document CRUD over `./resource.ts`'s generic handlers:
 * `docs/rewrite/parity-audit-storage.md` §4.2 found that "a schedule an
 * operator creates never fires" — the `schedule` string was stored unvalidated,
 * `/fires` listed a collection nothing appended to, and `run-now` set
 * `{ run_now: true }` on the document and dispatched nothing.
 *
 * Four mounts, each with a test that fails when it is removed
 * (`test/schedule-wiring.test.ts` drives all four through `SELF`):
 *
 *  1. **create / replace / merge** run {@link normalizeScheduleSpec}, so an
 *     unparseable cron expression, an unknown IANA timezone, a non-positive
 *     interval or a negative jitter is `400` at write time instead of a stored
 *     schedule that silently never fires; and each write stamps
 *     `next_fire_at_unix`, which is the field the tick loop scans.
 *  2. **delete** cascades the fire ledger. `sql/d1-ts/tenant/0001_init_tenant.sql`
 *     says out loud that the Postgres `ON DELETE CASCADE` onto `agent_schedules`
 *     is gone in this dialect and the delete "must cascade the fire rows
 *     ITSELF": without it, deleting and recreating a schedule under the same id
 *     inherits the old ledger, and the at-most-once gate then suppresses the
 *     new schedule's first fires.
 *  3. **run-now** calls {@link runScheduleNow} — the real target dispatch plus
 *     a `manual:`-prefixed fire row.
 *  4. **fires** reads the ledger the engine writes, newest slot first.
 *
 * Tenant attribution is the store's, unchanged: `ControlPlaneStore` stamps
 * `tenant_id` from the caller's scope on every write, so a tenant-scoped caller
 * cannot mint a schedule into another tenant. That matters more here than for a
 * static document, because a schedule later runs UNATTENDED under whatever
 * tenancy it carries — which is also why {@link runScheduleNow} and the tick
 * both re-check the tenancy lifecycle before dispatching.
 */
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import type { ControlPlaneDeps, StoreRecord } from "../ports.js";
import { adminDeleted, adminItem, listResponse, parseListQuery } from "../responses.js";
import {
  SCHEDULE_FIRE_COLLECTION,
  type ScheduleEngineDeps,
  runScheduleNow,
} from "../schedule/engine.js";
import { ScheduleSpecError, normalizeScheduleSpec } from "../schedule/model.js";
import {
  type CollectionSpec,
  type GroupModule,
  type Handler,
  adminRecordSchema,
  crudGroup,
  depsOf,
  json,
  pathParam,
  readJson,
  scopeOf,
} from "./resource.js";

/**
 * The wire shape. Every firing field is optional so a PATCH may change one of
 * them, and the CROSS-field rules (a cron kind needs an expression, an interval
 * kind needs a positive interval) live in `normalizeScheduleSpec` rather than
 * in Zod — they depend on the STORED record, which Zod cannot see.
 */
export const agentScheduleSchema = adminRecordSchema.extend({
  /** Cron expression. Legacy alias for `cron_expr`; still accepted. */
  schedule: z.string().trim().min(1).optional(),
  cron_expr: z.string().trim().min(1).optional(),
  spec_kind: z.string().trim().min(1).optional(),
  timezone: z.string().trim().min(1).optional(),
  interval_secs: z.number().int().optional(),
  target_kind: z.string().trim().min(1).optional(),
  target: z.record(z.unknown()).optional(),
  overlap_policy: z.string().trim().min(1).optional(),
  catchup_policy: z.string().trim().min(1).optional(),
  jitter_secs: z.number().int().optional(),
  enabled: z.boolean().optional(),
  workspace_id: z.string().trim().min(1).nullish(),
});

const SCHEDULE_COLLECTION = "agent-schedules";

const AGENT_SCHEDULE_SPEC: CollectionSpec = {
  segment: SCHEDULE_COLLECTION,
  object: "agent_schedule",
  body: agentScheduleSchema,
};

/** The engine's dependencies, taken from the app's composition root. */
function engineDeps(deps: ControlPlaneDeps): ScheduleEngineDeps {
  return { store: deps.store, lifecycle: deps.lifecycle, nodeId: "control-plane" };
}

/** A rejected spec is a `400`, with the reason the operator needs. */
function specError(error: unknown): never {
  if (error instanceof ScheduleSpecError) {
    throw new HttpError(400, "invalid_request_body", `request body is invalid: ${error.message}`);
  }
  throw error;
}

/**
 * Validate the firing spec and stamp the derived fields onto the document.
 *
 * The derived fields are what make the schedule real: `next_fire_at_unix` is
 * the only thing the due scan looks at, so a write that skipped this step would
 * store a perfectly valid-looking schedule that the tick loop never sees.
 */
function withFiringState(
  body: Record<string, unknown>,
  existing: Record<string, unknown> | null,
  now: number,
): Record<string, unknown> {
  let normalized: ReturnType<typeof normalizeScheduleSpec>;
  try {
    normalized = normalizeScheduleSpec(body, existing, now);
  } catch (error) {
    return specError(error);
  }
  return {
    ...body,
    ...normalized.spec,
    next_fire_at_unix: normalized.nextFireAt,
    last_fire_at_unix: existing?.last_fire_at_unix ?? null,
    updated_at_unix: now,
    created_at_unix: existing?.created_at_unix ?? now,
  };
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

const createSchedule: Handler = async (c) => {
  const deps = depsOf(c);
  const scope = scopeOf(c);
  const body = (await readJson(c, agentScheduleSchema)) as Record<string, unknown>;
  const declaredId = body.id;
  const id =
    typeof declaredId === "string" && declaredId.trim() !== ""
      ? declaredId.trim()
      : crypto.randomUUID();
  const record = { ...withFiringState(body, null, nowSeconds()), id } as StoreRecord;
  try {
    const stored = await deps.store.create(SCHEDULE_COLLECTION, scope, record);
    return json(c, 201, adminItem("agent_schedule", stored));
  } catch (error) {
    if (error instanceof Error && error.name === "StoreConflictError") {
      throw new HttpError(409, "conflict", `agent_schedule ${id} already exists`);
    }
    throw error;
  }
};

const replaceSchedule: Handler = async (c) => {
  const deps = depsOf(c);
  const scope = scopeOf(c);
  const id = pathParam(c, "id");
  const body = (await readJson(c, agentScheduleSchema)) as Record<string, unknown>;
  const existing = await deps.store.get(SCHEDULE_COLLECTION, scope, id);
  if (existing === null) throw notFound(id);
  // A PUT is a FULL replace, so the spec is derived from the body alone —
  // passing `existing` would let an omitted `cron_expr` survive a replace that
  // meant to drop it. The firing STATE (`last_fire_at_unix`, `created_at_unix`)
  // is not operator data and does carry over.
  const record = { ...withFiringState(body, null, nowSeconds()), id } as StoreRecord;
  const stored = await deps.store.replace(SCHEDULE_COLLECTION, scope, id, {
    ...record,
    last_fire_at_unix: existing.last_fire_at_unix ?? null,
    created_at_unix: existing.created_at_unix ?? nowSeconds(),
  });
  if (stored === null) throw notFound(id);
  return json(c, 200, adminItem("agent_schedule", stored));
};

const mergeSchedule: Handler = async (c) => {
  const deps = depsOf(c);
  const scope = scopeOf(c);
  const id = pathParam(c, "id");
  const body = (await readJson(c, agentScheduleSchema)) as Record<string, unknown>;
  const existing = await deps.store.get(SCHEDULE_COLLECTION, scope, id);
  if (existing === null) throw notFound(id);
  const patch = withFiringState(body, existing, nowSeconds());
  const stored = await deps.store.merge(SCHEDULE_COLLECTION, scope, id, patch);
  if (stored === null) throw notFound(id);
  return json(c, 200, adminItem("agent_schedule", stored));
};

/**
 * Delete the schedule AND its fire ledger.
 *
 * The cascade is not tidiness. The fire ledger is keyed on
 * `(schedule_id, slot)`, so a recreated schedule with the same id inherits
 * every old row; the at-most-once gate then reads those as "already fired" and
 * suppresses the new schedule's fires — for as long as the old slots keep
 * recurring. The tenant DDL calls this out explicitly.
 */
const deleteSchedule: Handler = async (c) => {
  const deps = depsOf(c);
  const scope = scopeOf(c);
  const id = pathParam(c, "id");
  const removed = await deps.store.remove(SCHEDULE_COLLECTION, scope, id);
  if (!removed) throw notFound(id);

  const fires = await deps.store.list(SCHEDULE_FIRE_COLLECTION, scope, {
    offset: 0,
    limit: Number.MAX_SAFE_INTEGER,
    paginate: false,
    search: null,
    filters: { schedule_id: id },
  });
  for (const fire of fires.items) {
    await deps.store.remove(SCHEDULE_FIRE_COLLECTION, scope, String(fire.id));
  }
  return json(c, 200, adminDeleted("agent_schedule", id));
};

/**
 * `GET /{id}/fires` — the durable fire history, newest slot first.
 *
 * Ordered rather than left in document order because the question an operator
 * asks a fire log is "did the last one work", and `subListHandler`'s insertion
 * order answers it only by accident.
 */
const listFires: Handler = async (c) => {
  const deps = depsOf(c);
  const scope = scopeOf(c);
  const scheduleId = pathParam(c, "id");
  if ((await deps.store.get(SCHEDULE_COLLECTION, scope, scheduleId)) === null) {
    throw notFound(scheduleId);
  }
  const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
  const scoped = { ...query, filters: { ...query.filters, schedule_id: scheduleId } };
  const page = await deps.store.list(SCHEDULE_FIRE_COLLECTION, scope, scoped);
  const items = [...page.items].sort(
    (left, right) =>
      Number(right.scheduled_fire_at_unix ?? 0) - Number(left.scheduled_fire_at_unix ?? 0),
  );
  return json(c, 200, listResponse({ items, total: page.total }, scoped));
};

/**
 * `POST /{id}/run-now` — the manual trigger (#251).
 *
 * `202 Accepted` with `{ object: "agent_schedule_fire", fire }`, which is Rust
 * `handle_admin_agent_schedule_run_now`'s response verbatim
 * (`StatusCode::ACCEPTED`, `AdminAgentScheduleRunNowResponse`). Both halves are
 * deliberate parity rather than taste: **202** because the control plane has
 * TRIGGERED the target, not completed it (the run is driven out of band), and
 * the **fire record** because the operator pressed a button to make something
 * happen — echoing the unchanged schedule back is precisely how the previous
 * implementation managed to look successful while dispatching nothing.
 */
const runNow: Handler = async (c) => {
  const deps = depsOf(c);
  const scope = scopeOf(c);
  const id = pathParam(c, "id");
  const schedule = await deps.store.get(SCHEDULE_COLLECTION, scope, id);
  if (schedule === null) throw notFound(id);
  const fire = await runScheduleNow(engineDeps(deps), schedule, nowSeconds());
  return json(c, 202, { object: "agent_schedule_fire", fire });
};

function notFound(id: string): HttpError {
  return new HttpError(404, "not_found", `agent_schedule ${id} not found`);
}

export const adminAgentScheduleRoutes: GroupModule = crudGroup(
  "admin_agent_schedule",
  [AGENT_SCHEDULE_SPEC],
  {
    createAdminAgentSchedule: createSchedule,
    putAdminAgentSchedule: replaceSchedule,
    patchAdminAgentSchedule: mergeSchedule,
    deleteAdminAgentSchedule: deleteSchedule,
    listAdminAgentScheduleFires: listFires,
    runAdminAgentScheduleNow: runNow,
  },
);
