/**
 * Policy-driven retention for `request_logs` — the answer to "and then it grows
 * forever", which is the other half of turning on an append-only evidence table.
 *
 * ## What was actually missing
 *
 * `@ferrogate/storage`'s `planLogRetention` has been ported, pure and tested
 * since #263/#284, and `retention.ts` in that package says plainly that
 * *nothing ever CALLED a planner*, so `request_logs` would grow without bound
 * in a deployed environment. A `packages/*` library has no Worker entry module
 * and therefore no `[triggers] crons`; a schedule can only be declared on a
 * deployable. This module is that call site, hanging off the `scheduled`
 * handler the gateway already exposes for the billing outbox.
 *
 * The planner is REUSED rather than restated. Its semantics — fail-safe KEEP on
 * any doubt, `minAgeSecs` as an absolute floor, an inert policy pruning nothing
 * — are the contract, and re-deriving them in a SQL `DELETE` here is how the
 * two would come to disagree about a boundary case that only shows up as
 * missing evidence.
 *
 * ## `keepLastN` is REFUSED for request logs, loudly
 *
 * `planLogRetention` supports two dimensions: `maxAgeSecs` (age) and
 * `keepLastN` (count). Only age is honoured here, and a policy that sets
 * `keepLastN` is rejected at parse time so the whole policy is inert.
 *
 * That is not laziness, it is the only sound choice available. `keepLastN` is
 * defined over a rank — "the newest N rows" — so evaluating it correctly needs
 * the FULL ordering of the tenant's rows, and a sweep on an unbounded
 * append-only table has to work on a bounded window or it cannot terminate
 * inside a Worker's CPU budget. Feeding a windowed candidate set to a
 * rank-based rule silently mis-prunes: every row in the window looks like it is
 * beyond the keep-count. Age, by contrast, is a per-row predicate and is
 * therefore EXACTLY correct on any window, which is why the sweep can bound its
 * work and still be right.
 *
 * Refusing a policy is fail-safe in the direction that matters: an unsupported
 * rule keeps data rather than deleting it, and the operator sees an unapplied
 * policy rather than a trail with holes in it.
 *
 * ## Where the policy comes from
 *
 * NOT from `retention_policies`, and this is worth being explicit about because
 * that table exists. It is a TENANT-database table. Retention resolves the
 * policy from `[vars]`, discovers its tenant set from the PROVISIONED ROSTER
 * (`provisionedTenants()`, the same fan-out every other Track-A sweep takes),
 * and deletes each tenant's authoritative object plus the unattributed
 * PLATFORM_DATA object. The control `request_logs` projection this sweep once
 * also pruned is NOT touched any more: its dual-write was G2-stopped, it has no
 * runtime reader, and its mirror is frozen awaiting the physical DROP — a sweep
 * that DELETEd from it would be the last tenant-data write into the shared
 * control singleton (no-tenant-data-mirror red line) and would fault the moment
 * the table is dropped. The operator config is the device this gateway already
 * uses for every other fleet-wide operator table (`GATEWAY_PROVIDERS`,
 * `TENANCY_LIFECYCLE`, `TENANT_RBAC_ACTIONS`).
 *
 * Two vars:
 *
 *  - `REQUEST_LOG_RETENTION_DAYS` — the fleet-wide default, committed as 400
 *    (13 months). Chosen ABOVE, not at, the six-month floor an EU AI Act Art.
 *    12 record-keeping obligation implies, because a retention window that
 *    equals the obligation deletes the evidence on the day it is still owed.
 *  - `REQUEST_LOG_RETENTION_POLICIES` — per-tenant overrides, e.g.
 *    `{"acme": {"days": 30}, "gov": {"days": 2555}}`, for a customer whose
 *    residency or DPA terms differ from the fleet's.
 *
 * A `days` of `0` means KEEP FOREVER, not "delete everything today": a
 * mistyped/blank number must never be the one that erases a trail.
 */
import {
  type LogRetentionCandidate,
  type RetentionPolicy,
  planLogRetention,
} from "@ferrogate/storage";
import { REQUEST_LOG_TABLE, type RequestLogDatabase } from "./d1.js";
import { requestLogPlatformDatabaseFrom, requestLogTenantDatabaseFromEnv } from "./sink.js";

/** `[vars] REQUEST_LOG_RETENTION_DAYS` — the fleet-wide window. */
export const REQUEST_LOG_RETENTION_DAYS_VAR = "REQUEST_LOG_RETENTION_DAYS";
/** `[vars] REQUEST_LOG_RETENTION_POLICIES` — `{"<tenant>": {"days": N}}`. */
export const REQUEST_LOG_RETENTION_POLICIES_VAR = "REQUEST_LOG_RETENTION_POLICIES";

/**
 * How many rows one sweep may consider, per scope.
 *
 * The sweep runs on a Cron tick and must finish inside a Worker's CPU budget,
 * so it prunes a bounded slice and lets the next tick continue. Bounded rather
 * than unbounded is also what makes the first sweep after enabling retention on
 * a large table safe: it deletes 5 000 rows and comes back in a minute, instead
 * of timing out and deleting nothing forever.
 */
export const REQUEST_LOG_SWEEP_MAX_ROWS = 5_000;

/** One resolved retention rule and the tenant it governs. */
export interface RequestLogRetentionScope {
  /** `undefined` = the fleet-wide default, applied to every other tenant. */
  readonly tenantId?: string | undefined;
  readonly policy: RetentionPolicy;
}

const SECONDS_PER_DAY = 86_400;

/**
 * Parse one `{ days }` rule.
 *
 * Returns `undefined` — i.e. NO policy, i.e. keep — for anything that is not a
 * positive finite number of days, and for any rule carrying `keep_last_n`. Both
 * are the fail-safe direction: a malformed retention rule must never be read as
 * a shorter one.
 */
function policyFrom(rule: unknown): RetentionPolicy | undefined {
  if (typeof rule !== "object" || rule === null) return undefined;
  const record = rule as Record<string, unknown>;
  if (record.keep_last_n !== undefined) return undefined;
  const days = record.days;
  if (typeof days !== "number" || !Number.isFinite(days) || days <= 0) return undefined;
  return {
    maxAgeSecs: Math.floor(days * SECONDS_PER_DAY),
    // No grace window beyond the age rule itself: unlike an asset version,
    // a request log has no publish/rollback race for a floor to protect.
    minAgeSecs: 0,
  };
}

function parseDays(raw: unknown): RetentionPolicy | undefined {
  if (typeof raw !== "string" || raw.trim() === "") return undefined;
  const days = Number(raw.trim());
  return policyFrom({ days });
}

/**
 * Read the operator's retention configuration off `env`.
 *
 * A malformed `REQUEST_LOG_RETENTION_POLICIES` yields NO overrides rather than
 * throwing: this runs from a Cron handler, and a JSON typo must not stop the
 * fleet-wide default sweeping too.
 */
export function requestLogRetentionFromEnv(env: unknown): RequestLogRetentionScope[] {
  if (typeof env !== "object" || env === null) return [];
  const scopes: RequestLogRetentionScope[] = [];

  // Indexed off `env` directly rather than through a renamed local, so
  // `test/env-var-drift.test.ts`'s `env[CONST]` scanner can SEE these two
  // reads. A read it cannot see is reported as a declared-but-unread var, i.e.
  // as dead config — and the "fix" for that accusation is deleting a live
  // operator knob from `wrangler.toml`.
  const fleet = parseDays((env as Record<string, unknown>)[REQUEST_LOG_RETENTION_DAYS_VAR]);
  if (fleet !== undefined) scopes.push({ policy: fleet });

  const raw = (env as Record<string, unknown>)[REQUEST_LOG_RETENTION_POLICIES_VAR];
  if (typeof raw === "string" && raw.trim() !== "") {
    try {
      const parsed: unknown = JSON.parse(raw);
      if (typeof parsed === "object" && parsed !== null) {
        for (const [tenantId, rule] of Object.entries(parsed as Record<string, unknown>)) {
          const policy = policyFrom(rule);
          if (policy !== undefined && tenantId !== "") scopes.push({ tenantId, policy });
        }
      }
    } catch {
      // A malformed override table leaves the fleet default in charge.
    }
  }
  return scopes;
}

interface CandidateRow {
  readonly request_id: string;
  readonly tenant?: string | null;
  readonly started_at_unix: number;
}

/** What one sweep did, so the caller can say whether retention is working. */
export interface RequestLogSweepResult {
  readonly scanned: number;
  readonly pruned: number;
}

interface RetentionFence {
  readonly sql: string;
  readonly params: readonly (string | number | null)[];
}

/** Delete exactly one object's rows by id, never every tenant's same id. */
function deleteCandidateStatements(
  db: RequestLogDatabase,
  rows: readonly CandidateRow[],
): unknown[] {
  return rows.map((row) => {
    if (typeof row.tenant === "string") {
      return db
        .prepare(`DELETE FROM ${REQUEST_LOG_TABLE} WHERE request_id = ? AND tenant = ?`)
        .bind(row.request_id, row.tenant);
    }
    return db
      .prepare(`DELETE FROM ${REQUEST_LOG_TABLE} WHERE request_id = ? AND tenant IS NULL`)
      .bind(row.request_id);
  });
}

/** Resolve an authoritative object without letting a Cron binding fault escape. */
function tenantDatabaseForSweep(env: unknown, tenantId: string): RequestLogDatabase | undefined {
  try {
    return requestLogTenantDatabaseFromEnv(env, tenantId);
  } catch {
    // A missing/unreachable object leaves its evidence in place. The next tick
    // can retry after the binding or object becomes available.
    return undefined;
  }
}

/**
 * Plan and delete one bounded candidate window against ONE authoritative
 * database — a tenant's own object, or the unattributed PLATFORM_DATA object.
 *
 * There is no second (projection) database any more: the control mirror this
 * sweep once also deleted from was retired (see the module header), so the sweep
 * is single-destination and needs no cross-database ordering guarantee.
 */
async function sweepCandidates(
  authoritativeDb: RequestLogDatabase,
  policy: RetentionPolicy,
  nowUnix: number,
  maxRows: number,
  fence: RetentionFence,
): Promise<RequestLogSweepResult> {
  let rows: CandidateRow[];
  try {
    const result = (await authoritativeDb
      .prepare(
        `SELECT request_id, tenant, started_at_unix FROM ${REQUEST_LOG_TABLE}${fence.sql}
          ORDER BY started_at_unix ASC LIMIT ?`,
      )
      .bind(...fence.params, maxRows)
      .all()) as { results?: CandidateRow[] };
    rows = result.results ?? [];
  } catch {
    return { scanned: 0, pruned: 0 };
  }

  const candidates: LogRetentionCandidate[] = rows.map((row) => ({
    id: row.request_id,
    createdAtUnix: row.started_at_unix,
  }));
  const doomed = planLogRetention(candidates, nowUnix, policy);
  if (doomed.length === 0) return { scanned: rows.length, pruned: 0 };
  const doomedRows = rows.filter((row) => doomed.includes(row.request_id));

  try {
    await authoritativeDb.batch(deleteCandidateStatements(authoritativeDb, doomedRows));
  } catch {
    return { scanned: rows.length, pruned: 0 };
  }
  return { scanned: rows.length, pruned: doomed.length };
}

/**
 * Apply one scope's rule to one authoritative database.
 *
 * The candidate window is the OLDEST rows in the scope, because those are the
 * only ones an age rule can select; ordering ascending means the sweep does
 * useful work on its first tick against a large table instead of paging through
 * rows it will certainly keep. The caller must pass the authoritative database
 * for a tenant scope; this function never chooses a shared fallback.
 *
 * Never throws: a retention failure is an unpruned table, which is safe.
 */
export async function sweepRequestLogRetention(
  authoritativeDb: RequestLogDatabase,
  scope: RequestLogRetentionScope,
  nowUnix: number,
  maxRows: number = REQUEST_LOG_SWEEP_MAX_ROWS,
): Promise<RequestLogSweepResult> {
  const fence =
    scope.tenantId === undefined
      ? { sql: "", params: [] }
      : { sql: " WHERE tenant = ?", params: [scope.tenantId] };
  return sweepCandidates(authoritativeDb, scope.policy, nowUnix, maxRows, fence);
}

/**
 * Sweep the PLATFORM_DATA singleton's request-log table (Zero-D1 Plan B).
 *
 * The whole table IS the platform domain — every row is unattributed by
 * construction — so there is no tenant fence and the sweep considers the oldest
 * rows across the object. This is now the ONLY place unattributed request-log
 * rows are pruned: the control projection's `sweepUnscopedProjection`, which
 * once also bounded the (frozen, DROP-bound) control mirror, was retired with
 * this slice.
 *
 * Never throws — a retention failure is an unpruned table, which is safe.
 */
export async function sweepPlatformRequestLogRetention(
  platformDb: RequestLogDatabase,
  policy: RetentionPolicy,
  nowUnix: number,
  maxRows: number = REQUEST_LOG_SWEEP_MAX_ROWS,
): Promise<RequestLogSweepResult> {
  return sweepCandidates(platformDb, policy, nowUnix, maxRows, { sql: "", params: [] });
}

/** Resolve the platform singleton without letting a Cron binding fault escape. */
function platformDatabaseForSweep(env: unknown): RequestLogDatabase | undefined {
  try {
    return requestLogPlatformDatabaseFrom(env);
  } catch {
    // A missing/unreachable platform object leaves its evidence in place; the
    // next tick retries once the binding or object becomes available.
    return undefined;
  }
}

/**
 * Every configured scope, swept once. The `scheduled` handler's entry point.
 *
 * `tenants` is the PROVISIONED ROSTER (`provisionedTenants()`) the scheduled
 * handler already resolved — the same fleet fan-out every other Track-A sweep
 * takes. It REPLACES the old `SELECT DISTINCT tenant FROM request_logs` against
 * the control mirror: discovery no longer reads control, and every deletion
 * targets a tenant's own authoritative object. Unattributed rows are pruned on
 * the PLATFORM_DATA object. The control projection is not touched at all.
 *
 * With no vars configured this resolves to zero scopes and returns without
 * touching any database — an operator who has not opted into retention keeps
 * everything, which is the only safe default for evidence. With the registry
 * unavailable the roster is empty, so only explicit per-tenant overrides and the
 * platform object are swept; under-pruning is the fail-safe direction.
 */
export async function sweepRequestLogs(
  env: unknown,
  tenants: readonly string[],
  nowUnix: number,
): Promise<RequestLogSweepResult> {
  let scanned = 0;
  let pruned = 0;
  const scopes = requestLogRetentionFromEnv(env);
  const overrides = new Map<string, RetentionPolicy>();
  for (const scope of scopes) {
    if (scope.tenantId !== undefined) overrides.set(scope.tenantId, scope.policy);
  }

  for (const [tenantId, policy] of overrides) {
    const authoritative = tenantDatabaseForSweep(env, tenantId);
    if (authoritative === undefined) continue;
    const result = await sweepRequestLogRetention(authoritative, { tenantId, policy }, nowUnix);
    scanned += result.scanned;
    pruned += result.pruned;
  }

  const fleet = scopes.find((scope) => scope.tenantId === undefined);
  if (fleet !== undefined) {
    // The unattributed platform object, swept under the fleet policy. This is the
    // only place unscoped rows are pruned now that the control unscoped sweep is
    // retired. Skipped when PLATFORM_DATA is not yet bound.
    const platformDb = platformDatabaseForSweep(env);
    if (platformDb !== undefined) {
      const platform = await sweepPlatformRequestLogRetention(platformDb, fleet.policy, nowUnix);
      scanned += platform.scanned;
      pruned += platform.pruned;
    }

    // Every provisioned tenant the fleet default governs, minus those with an
    // explicit override already swept above. Each deletion hits that tenant's own
    // authoritative object; no control read discovers them any more.
    for (const tenantId of tenants) {
      if (tenantId === "" || overrides.has(tenantId)) continue;
      const authoritative = tenantDatabaseForSweep(env, tenantId);
      if (authoritative === undefined) continue;
      const result = await sweepRequestLogRetention(
        authoritative,
        { tenantId, policy: fleet.policy },
        nowUnix,
      );
      scanned += result.scanned;
      pruned += result.pruned;
    }
  }
  return { scanned, pruned };
}
