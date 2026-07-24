// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: FerroGate agent scheduling routes (issue #426): governed create/list/cancel over
//   a Cloudflare agent's in-DO SQLite scheduler (one-shot, cron, interval), with the
//   cancel-before-recreate duplicate guard and a pinned dispatch callback. Cloudflare has NO
//   external enqueue API — scheduling is in-agent only, so these bearer-gated Worker routes
//   are the only tethered path FerroGate uses to drive an agent's schedules.

import { getAgentByName } from "agents";

import { json, requireBearer } from "./auth";
import { MAX_SQL_VALUE_BYTES } from "./memory";
import type { RawSqlResult, SqlBinding } from "./memory";
import type { AgentGateway, Env } from "./index";

// ---------------------------------------------------------------------------
// Scheduling facts (pinned Agents SDK 0.0.109 — verified against node_modules)
// ---------------------------------------------------------------------------
//
// * `this.schedule(when, callback, payload)` takes THREE arguments in this pin
//   (no `opts`): `when` = seconds delay (type "delayed") | Date (type
//   "scheduled") | cron string (type "cron", minute precision, auto-
//   rescheduled by the SDK's alarm handler). The callback is a METHOD NAME
//   that must exist on the agent class.
// * Management: `getSchedule(id)` (async), `getSchedules(criteria)` (SYNC in
//   this pin), `cancelSchedule(id)` (async; returns `true` even for a missing
//   id, so existence is checked separately here).
// * Persistence: rows in `cf_agents_schedules`, multiplexed through the DO's
//   single alarm (`_scheduleNextAlarm`); they survive hibernation/restart and
//   the constructor re-arms the alarm on wake — no onStart re-establishment
//   is needed.
// * `scheduleEvery()` DOES NOT EXIST in 0.0.109 (verified: zero occurrences
//   in the package dist). Interval tasks are EMULATED here as a delayed
//   schedule whose dispatch re-arms itself. The seam still probes for a
//   native `scheduleEvery` so a future SDK upgrade is picked up defensively.
// * Duplicate guard (github.com/cloudflare/agents #1049): repeated interval
//   creation duplicates rows. Every create here is CANCEL-BEFORE-RECREATE
//   keyed by the FerroGate `taskId`, making create idempotent for all kinds.

/**
 * The ONLY method name FerroGate schedules callbacks onto. Pinning the
 * callback closes the obvious hole: if callers could name arbitrary agent
 * methods, a schedule could invoke `destroyRun`/`cancel`/any RPC verb with an
 * attacker-chosen payload. All scheduled work funnels through the agent's
 * `runScheduledTask` dispatcher instead.
 */
export const SCHEDULE_DISPATCH_METHOD = "runScheduledTask";

/** Execution log table written by the dispatcher; readable via /memory/sql/query. */
export const SCHEDULE_RUN_LOG_TABLE = "fg_schedule_task_runs";

/** Default per-instance cap on concurrent schedule rows (alarm-row hygiene). */
export const DEFAULT_MAX_SCHEDULED_TASKS = 100;

/** FerroGate task ids: path-safe, no separator ambiguity, bounded length. */
const TASK_ID_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

/** FerroGate schedule kinds (mapped onto the SDK's scheduled/delayed/cron). */
export type ScheduleKind = "once" | "cron" | "interval";

/** Wire spec for one scheduled task (the `task` object of /schedule/create). */
export interface ScheduleTaskSpec {
  /** FerroGate's stable task key — the cancel-before-recreate dedup key. */
  taskId: string;
  kind: ScheduleKind;
  /** `once`: run after this many seconds (mutually exclusive with `at`). */
  delaySeconds?: number;
  /** `once`: run at this ISO-8601 instant (mutually exclusive with `delaySeconds`). */
  at?: string;
  /** `cron`: SDK cron expression — minute precision, auto-rescheduling. */
  cron?: string;
  /** `interval`: repeat every N seconds (emulated on this SDK pin). */
  everySeconds?: number;
  /** Opaque payload handed to the dispatcher; JSON ≤ 2 MB (DO value limit). */
  data?: unknown;
}

/**
 * The payload envelope actually persisted into `cf_agents_schedules.payload`.
 * Carries the FerroGate task identity so list/cancel can key on `taskId`, and
 * `everySeconds`/`emulated` so an interval dispatch knows to re-arm itself.
 */
export interface ScheduledTaskEnvelope {
  taskId: string;
  kind: ScheduleKind;
  everySeconds?: number;
  /** True when the interval is the delayed-self-re-arm emulation (no native scheduleEvery). */
  emulated?: boolean;
  data: unknown;
}

/** SDK schedule row shape (the pinned `Schedule<T>` flattened, payload parsed). */
export interface SdkScheduleRow {
  id: string;
  callback: string;
  payload: unknown;
  type: "scheduled" | "delayed" | "cron";
  time?: number;
  delayInSeconds?: number;
  cron?: string;
}

/** One schedule as reported over the wire by list/create. */
export interface ScheduleWireRecord {
  /** SDK schedule row id (`cf_agents_schedules.id`). */
  id: string;
  /** FerroGate task key, or null for rows FerroGate did not mint. */
  taskId: string | null;
  /** FerroGate kind, or null for foreign rows. */
  kind: ScheduleKind | null;
  /** Raw SDK row type. */
  sdkType: "scheduled" | "delayed" | "cron";
  callback: string;
  /** Next execution time (epoch SECONDS — the SDK's unit), if known. */
  time: number | null;
  cron: string | null;
  everySeconds: number | null;
  data: unknown;
}

/**
 * The slice of the agent the schedule verbs need. `AgentGateway` satisfies it
 * structurally; keeping the verbs against this seam keeps them out of index.ts
 * (engineering standard #429) and unit-testable without a Durable Object.
 * `scheduleEvery` is OPTIONAL: absent on the pinned SDK, probed defensively in
 * case a future upgrade adds it.
 */
export interface AgentScheduleHost {
  /** The agent instance name — the isolation unit. */
  name: string;
  schedule(
    when: Date | string | number,
    callback: string,
    payload?: unknown,
  ): Promise<SdkScheduleRow>;
  getSchedules(criteria?: {
    id?: string;
    type?: "scheduled" | "delayed" | "cron";
  }): SdkScheduleRow[];
  cancelSchedule(id: string): Promise<boolean>;
  /** Native sub-minute interval — NOT present on agents 0.0.109. */
  scheduleEvery?(
    seconds: number,
    callback: string,
    payload?: unknown,
  ): Promise<SdkScheduleRow>;
  /** Dispatcher-side execution log (reuses the memory layer-2 SQL seam). */
  rawSql(query: string, bindings: SqlBinding[]): RawSqlResult;
  /** Per-instance cap on concurrent schedule rows. */
  maxScheduledTasks: number;
}

/** Parse the `SCHEDULE_MAX_TASKS_PER_INSTANCE` var, falling back to the default. */
export function scheduledTaskCap(raw: string | undefined): number {
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 1) {
    return DEFAULT_MAX_SCHEDULED_TASKS;
  }
  return parsed;
}

// ---------------------------------------------------------------------------
// RPC-safe result envelope (same discipline as memory.ts: DO RPC strips a
// thrown error's class identity, so verbs return a discriminated result).
// ---------------------------------------------------------------------------

/** Error vocabulary; the route maps codes onto HTTP statuses (422/429/400). */
export type ScheduleErrorCode = "invalid_task" | "schedule_limit" | "schedule_error";

/** Discriminated success/failure envelope returned by every schedule RPC verb. */
export type ScheduleResult<T> =
  | ({ ok: true } & T)
  | { ok: false; code: ScheduleErrorCode; message: string };

// ---------------------------------------------------------------------------
// Spec validation
// ---------------------------------------------------------------------------

/**
 * Validate a create spec. Returns an error message (→ `invalid_task`, HTTP
 * 422) or `null` when acceptable. Strict, never sanitizing — a lossily
 * "fixed" taskId would break the cancel-before-recreate dedup key.
 */
export function validateTaskSpec(spec: unknown): string | null {
  if (typeof spec !== "object" || spec === null || Array.isArray(spec)) {
    return "task must be a JSON object";
  }
  const task = spec as Record<string, unknown>;
  if (typeof task.taskId !== "string" || !TASK_ID_PATTERN.test(task.taskId)) {
    return "task.taskId must match [A-Za-z0-9._-]{1,128}";
  }
  const kind = task.kind;
  if (kind !== "once" && kind !== "cron" && kind !== "interval") {
    return "task.kind must be once/cron/interval";
  }
  if (kind === "once") {
    const hasDelay = task.delaySeconds !== undefined;
    const hasAt = task.at !== undefined;
    if (hasDelay === hasAt) {
      return "task kind once requires exactly one of delaySeconds or at";
    }
    if (hasDelay && (!Number.isInteger(task.delaySeconds) || (task.delaySeconds as number) < 0)) {
      return "task.delaySeconds must be a non-negative integer (seconds)";
    }
    if (hasAt && (typeof task.at !== "string" || Number.isNaN(Date.parse(task.at)))) {
      return "task.at must be an ISO-8601 date string";
    }
  }
  if (kind === "cron" && (typeof task.cron !== "string" || task.cron.trim().length === 0)) {
    return "task kind cron requires a non-empty cron expression";
  }
  if (
    kind === "interval" &&
    (!Number.isInteger(task.everySeconds) || (task.everySeconds as number) < 1)
  ) {
    return "task kind interval requires everySeconds >= 1";
  }
  const envelopeBytes = new TextEncoder().encode(
    JSON.stringify({ taskId: task.taskId, kind, data: task.data ?? null }),
  ).length;
  if (envelopeBytes > MAX_SQL_VALUE_BYTES) {
    return `task payload is ${envelopeBytes} bytes; the Durable Object SQLite value limit is ${MAX_SQL_VALUE_BYTES}`;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Row <-> wire mapping
// ---------------------------------------------------------------------------

function envelopeOf(row: SdkScheduleRow): Partial<ScheduledTaskEnvelope> | null {
  const payload = row.payload;
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    return null;
  }
  const env = payload as Partial<ScheduledTaskEnvelope>;
  return typeof env.taskId === "string" ? env : null;
}

function toWire(row: SdkScheduleRow): ScheduleWireRecord {
  const env = envelopeOf(row);
  return {
    id: row.id,
    taskId: env?.taskId ?? null,
    kind: env?.kind === "once" || env?.kind === "cron" || env?.kind === "interval"
      ? env.kind
      : null,
    sdkType: row.type,
    callback: row.callback,
    time: typeof row.time === "number" ? row.time : null,
    cron: typeof row.cron === "string" ? row.cron : null,
    everySeconds: typeof env?.everySeconds === "number" ? env.everySeconds : null,
    data: env ? (env.data ?? null) : row.payload,
  };
}

/** All schedule rows FerroGate minted for `taskId` (the dedup key). */
function rowsForTask(host: AgentScheduleHost, taskId: string): SdkScheduleRow[] {
  return host.getSchedules().filter((row) => envelopeOf(row)?.taskId === taskId);
}

/**
 * The DUPLICATE GUARD (github.com/cloudflare/agents #1049): cancel every
 * existing row keyed by `taskId` before creating a replacement. Applied on
 * every create — one-shot/cron re-issues stay idempotent, and interval
 * re-creation can never accumulate duplicate rows on this or any future SDK.
 */
async function cancelTaskRows(host: AgentScheduleHost, taskId: string): Promise<number> {
  const rows = rowsForTask(host, taskId);
  for (const row of rows) {
    await host.cancelSchedule(row.id);
  }
  return rows.length;
}

// ---------------------------------------------------------------------------
// RPC verbs (run inside the Durable Object, called via thin index.ts delegates)
// ---------------------------------------------------------------------------

/** RPC verb: cancel-before-recreate, then schedule per the spec's kind. */
export async function scheduleCreate(
  host: AgentScheduleHost,
  spec: unknown,
): Promise<
  ScheduleResult<{ instance: string; schedule: ScheduleWireRecord; replaced: number }>
> {
  const violation = validateTaskSpec(spec);
  if (violation) {
    return { ok: false, code: "invalid_task", message: violation };
  }
  const task = spec as ScheduleTaskSpec;

  try {
    // Duplicate guard FIRST (see cancelTaskRows), then enforce the row cap on
    // what actually remains.
    const replaced = await cancelTaskRows(host, task.taskId);
    const existing = host.getSchedules().length;
    if (existing >= host.maxScheduledTasks) {
      return {
        ok: false,
        code: "schedule_limit",
        message: `instance already holds ${existing} schedules (cap ${host.maxScheduledTasks})`,
      };
    }

    const envelope: ScheduledTaskEnvelope = {
      taskId: task.taskId,
      kind: task.kind,
      data: task.data ?? null,
    };

    let row: SdkScheduleRow;
    switch (task.kind) {
      case "once": {
        const when =
          task.delaySeconds !== undefined ? task.delaySeconds : new Date(task.at as string);
        row = await host.schedule(when, SCHEDULE_DISPATCH_METHOD, envelope);
        break;
      }
      case "cron": {
        // Cron validity is the SDK's call (getNextCronTime throws on garbage);
        // a throw surfaces as schedule_error below.
        row = await host.schedule(task.cron as string, SCHEDULE_DISPATCH_METHOD, envelope);
        break;
      }
      case "interval": {
        envelope.everySeconds = task.everySeconds;
        if (typeof host.scheduleEvery === "function") {
          // Native path (future SDK): safe because the guard above cancelled
          // any prior rows — the #1049 duplicate bug cannot accumulate.
          row = await host.scheduleEvery(
            task.everySeconds as number,
            SCHEDULE_DISPATCH_METHOD,
            envelope,
          );
        } else {
          // Pinned-SDK path (agents 0.0.109 has NO scheduleEvery): emulate as
          // a delayed one-shot whose dispatch re-arms itself.
          envelope.emulated = true;
          row = await host.schedule(
            task.everySeconds as number,
            SCHEDULE_DISPATCH_METHOD,
            envelope,
          );
        }
        break;
      }
    }
    return { ok: true, instance: host.name, schedule: toWire(row), replaced };
  } catch (err) {
    return { ok: false, code: "schedule_error", message: (err as Error).message ?? String(err) };
  }
}

/** RPC verb: list schedules, optionally filtered by taskId and/or kind. */
export function scheduleList(
  host: AgentScheduleHost,
  criteria?: { taskId?: string; kind?: ScheduleKind },
): ScheduleResult<{ instance: string; schedules: ScheduleWireRecord[]; count: number }> {
  try {
    let schedules = host.getSchedules().map(toWire);
    if (criteria?.taskId !== undefined) {
      schedules = schedules.filter((s) => s.taskId === criteria.taskId);
    }
    if (criteria?.kind !== undefined) {
      schedules = schedules.filter((s) => s.kind === criteria.kind);
    }
    return { ok: true, instance: host.name, schedules, count: schedules.length };
  } catch (err) {
    return { ok: false, code: "schedule_error", message: (err as Error).message ?? String(err) };
  }
}

/**
 * RPC verb: cancel by FerroGate taskId (all rows for the task) or by raw SDK
 * schedule id. Reports how many rows were actually removed — the pinned SDK's
 * `cancelSchedule` returns `true` even for a missing id, so existence is
 * checked against `getSchedules` first.
 */
export async function scheduleCancel(
  host: AgentScheduleHost,
  selector: { taskId?: string; scheduleId?: string },
): Promise<ScheduleResult<{ instance: string; cancelled: number }>> {
  const hasTask = typeof selector.taskId === "string" && selector.taskId.length > 0;
  const hasId = typeof selector.scheduleId === "string" && selector.scheduleId.length > 0;
  if (hasTask === hasId) {
    return {
      ok: false,
      code: "invalid_task",
      message: "provide exactly one of taskId or scheduleId",
    };
  }
  try {
    if (hasTask) {
      const cancelled = await cancelTaskRows(host, selector.taskId as string);
      return { ok: true, instance: host.name, cancelled };
    }
    const exists = host.getSchedules({ id: selector.scheduleId as string }).length > 0;
    if (exists) {
      await host.cancelSchedule(selector.scheduleId as string);
    }
    return { ok: true, instance: host.name, cancelled: exists ? 1 : 0 };
  } catch (err) {
    return { ok: false, code: "schedule_error", message: (err as Error).message ?? String(err) };
  }
}

/**
 * The pinned dispatcher body (the agent's `runScheduledTask` delegates here).
 * Records the execution into {@link SCHEDULE_RUN_LOG_TABLE} — readable via
 * `/memory/sql/query`, which is how a live test proves alarm firings survived
 * hibernation — and re-arms EMULATED intervals (delayed rows are deleted by
 * the SDK after firing, so the next tick must be scheduled here; the re-arm
 * is guarded by cancel-before-recreate too, so a duplicate can never take
 * root even if a stale row lingers).
 */
export async function dispatchScheduledTask(
  host: AgentScheduleHost,
  payload: unknown,
): Promise<void> {
  const env =
    typeof payload === "object" && payload !== null && !Array.isArray(payload)
      ? (payload as Partial<ScheduledTaskEnvelope>)
      : null;
  const taskId = typeof env?.taskId === "string" ? env.taskId : "unknown";
  const kind =
    env?.kind === "once" || env?.kind === "cron" || env?.kind === "interval"
      ? env.kind
      : "unknown";

  host.rawSql(
    `create table if not exists ${SCHEDULE_RUN_LOG_TABLE} (
      task_id text not null,
      kind text not null,
      fired_at integer not null
    )`,
    [],
  );
  host.rawSql(
    `insert into ${SCHEDULE_RUN_LOG_TABLE} (task_id, kind, fired_at) values (?, ?, ?)`,
    [taskId, kind, Date.now()],
  );

  if (
    env?.kind === "interval" &&
    env.emulated === true &&
    Number.isInteger(env.everySeconds) &&
    (env.everySeconds as number) >= 1 &&
    taskId !== "unknown"
  ) {
    await cancelTaskRows(host, taskId);
    await host.schedule(env.everySeconds as number, SCHEDULE_DISPATCH_METHOD, env);
  }
}

// ---------------------------------------------------------------------------
// Route dispatch
// ---------------------------------------------------------------------------

const ERROR_STATUS: Record<ScheduleErrorCode, number> = {
  invalid_task: 422,
  schedule_limit: 429,
  schedule_error: 400,
};

/** Structural envelope view (DO RPC stubs defeat `ScheduleResult<T>` inference). */
type ScheduleResultLike =
  | { ok: true }
  | { ok: false; code: ScheduleErrorCode; message: string };

function scheduleResponse(result: ScheduleResultLike): Response {
  if (!result.ok) {
    return json({ error: result.code, message: result.message }, ERROR_STATUS[result.code]);
  }
  return json(result);
}

interface ScheduleRequestBody {
  instance?: unknown;
  task?: unknown;
  taskId?: unknown;
  scheduleId?: unknown;
  kind?: unknown;
}

/**
 * Schedule routes (issue #426), all POST + bearer-gated. POST bodies (never
 * query strings) carry the instance name, since names embed tenant identity:
 *
 *   POST /schedule/create  { instance, task }                schedule one task
 *   POST /schedule/list    { instance, taskId?, kind? }      list (optionally filtered)
 *   POST /schedule/cancel  { instance, taskId | scheduleId } cancel by task or row id
 *
 * There is NO external enqueue primitive on Cloudflare — `this.schedule` is
 * in-agent only, so these routes RPC into the named agent, exactly like the
 * /control/* and /memory/* surfaces. The instance name is minted by the Rust
 * side's naming scheme (`fg.{tenant}.{session}.{run}`); the Worker never
 * derives names itself.
 */
export async function handleSchedule(request: Request, env: Env, url: URL): Promise<Response> {
  const denied = requireBearer(request, env.GATEWAY_CONTROL_TOKEN);
  if (denied) return denied;
  if (request.method !== "POST") {
    return json({ error: "schedule routes are POST-only" }, 405);
  }

  let body: ScheduleRequestBody;
  try {
    body = (await request.json()) as ScheduleRequestBody;
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
  const instance = body.instance;
  if (typeof instance !== "string" || instance.length === 0 || instance.length > 512) {
    return json({ error: "missing or invalid instance name" }, 400);
  }

  const verb = url.pathname.slice("/schedule/".length);
  try {
    const agent = await getAgentByName<Env, AgentGateway>(env.AGENT_GATEWAY, instance);
    switch (verb) {
      case "create":
        return scheduleResponse(await agent.scheduleCreate(body.task));
      case "list": {
        const kind = body.kind;
        if (
          kind !== undefined &&
          kind !== "once" &&
          kind !== "cron" &&
          kind !== "interval"
        ) {
          return json({ error: "kind must be once/cron/interval" }, 400);
        }
        return scheduleResponse(
          await agent.scheduleList({
            taskId: typeof body.taskId === "string" ? body.taskId : undefined,
            kind,
          }),
        );
      }
      case "cancel":
        return scheduleResponse(
          await agent.scheduleCancel({
            taskId: typeof body.taskId === "string" ? body.taskId : undefined,
            scheduleId: typeof body.scheduleId === "string" ? body.scheduleId : undefined,
          }),
        );
      default:
        return json({ error: `unknown schedule verb: ${verb}` }, 404);
    }
  } catch (err) {
    return json({ error: `schedule call failed: ${(err as Error).message}` }, 502);
  }
}
