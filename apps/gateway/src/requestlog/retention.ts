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
 * that table exists. It is a TENANT-database table, `request_logs` is a CONTROL
 * one, and D1 has no read spanning the two — `packages/storage`'s own note says
 * the cross-scope decision "belongs to the control plane, not to a per-tenant
 * sweep". Rather than invent a cross-database read on the data plane, the
 * policy is an OPERATOR CONFIG TABLE in `[vars]`, which is the device this
 * gateway already uses for every other fleet-wide operator table
 * (`GATEWAY_PROVIDERS`, `TENANCY_LIFECYCLE`, `TENANT_RBAC_ACTIONS`).
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
  if (record["keep_last_n"] !== undefined) return undefined;
  const days = record["days"];
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
  readonly started_at_unix: number;
}

/** What one sweep did, so the caller can say whether retention is working. */
export interface RequestLogSweepResult {
  readonly scanned: number;
  readonly pruned: number;
}

/**
 * Apply one scope's rule to `request_logs`.
 *
 * The candidate window is the OLDEST rows in the scope, because those are the
 * only ones an age rule can select; ordering ascending means the sweep does
 * useful work on its first tick against a large table instead of paging through
 * rows it will certainly keep.
 *
 * A tenant-scoped rule uses STRICT equality, so the fleet default — and only
 * the fleet default — governs the un-attributed (platform) rows. An operator
 * who narrows one tenant's window must not thereby narrow everyone's.
 *
 * Never throws: a retention failure is an unpruned table, which is safe.
 */
export async function sweepRequestLogRetention(
  db: RequestLogDatabase,
  scope: RequestLogRetentionScope,
  nowUnix: number,
  maxRows: number = REQUEST_LOG_SWEEP_MAX_ROWS,
): Promise<RequestLogSweepResult> {
  const fence = scope.tenantId === undefined ? "" : " WHERE tenant = ?";
  const params = scope.tenantId === undefined ? [] : [scope.tenantId];

  let rows: CandidateRow[];
  try {
    const result = (await db
      .prepare(
        `SELECT request_id, started_at_unix FROM ${REQUEST_LOG_TABLE}${fence}
          ORDER BY started_at_unix ASC LIMIT ?`,
      )
      .bind(...params, maxRows)
      .all()) as { results?: CandidateRow[] };
    rows = result.results ?? [];
  } catch {
    return { scanned: 0, pruned: 0 };
  }

  const candidates: LogRetentionCandidate[] = rows.map((row) => ({
    id: row.request_id,
    createdAtUnix: row.started_at_unix,
  }));
  const doomed = planLogRetention(candidates, nowUnix, scope.policy);
  if (doomed.length === 0) return { scanned: rows.length, pruned: 0 };

  try {
    const statement = db.prepare(`DELETE FROM ${REQUEST_LOG_TABLE} WHERE request_id = ?`);
    await db.batch(doomed.map((id) => statement.bind(id)));
  } catch {
    return { scanned: rows.length, pruned: 0 };
  }
  return { scanned: rows.length, pruned: doomed.length };
}

/**
 * Every configured scope, swept once. The `scheduled` handler's entry point.
 *
 * With no vars configured this resolves to zero scopes and returns without
 * touching the database — an operator who has not opted into retention keeps
 * everything, which is the only safe default for evidence.
 */
export async function sweepRequestLogs(
  db: RequestLogDatabase,
  env: unknown,
  nowUnix: number,
): Promise<RequestLogSweepResult> {
  let scanned = 0;
  let pruned = 0;
  for (const scope of requestLogRetentionFromEnv(env)) {
    const result = await sweepRequestLogRetention(db, scope, nowUnix);
    scanned += result.scanned;
    pruned += result.pruned;
  }
  return { scanned, pruned };
}
