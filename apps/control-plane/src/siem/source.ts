/**
 * The read side of the SIEM pump (#683): one fenced, forward, keyset-paged
 * batch of evidence.
 *
 * ## This is not a second read path
 *
 * Every part of the projection and the fence is IMPORTED from
 * `../routes/admin_request_log.ts`, which is the module that already answers
 * `GET /admin/v1/request-logs`, `…/request-log-exports` and
 * `…/audit-events`. Nothing is restated here. The reason is the one that module
 * gives for sharing its own projection between its list and its export: a push
 * path that could see a row the console cannot is a cross-tenant leak with a
 * different front door, and a push path that projected a row differently would
 * make a customer's SIEM and this platform's API disagree about what happened.
 * `test/siem-export.test.ts` holds that as a property — the pump's documents
 * must equal the JSONL export's for the same tenant.
 *
 * ## The two things that ARE different, and why
 *
 *  1. **Time runs forwards.** The admin list reads `request_logs` newest-first,
 *     because an operator reads it backwards from an incident. A cursor cannot:
 *     "everything after X" is only meaningful in ascending order.
 *  2. **Keyset, not offset.** `LIMIT/OFFSET` on an append-heavy table shifts
 *     under inserts, so resuming by offset silently drops exactly the rows that
 *     arrived while the pump was down. The keyset predicate names a ROW.
 *
 * ## The horizon
 *
 * Batches stop at `now - visibilityLagSeconds`. A `request_logs` row is KEYED
 * on when a request started and WRITTEN when it completed, so without the lag a
 * slow request lands behind a cursor that has already passed its timestamp and
 * is never exported — an invisible gap, which is the failure this whole feature
 * exists to prevent. See `SiemSink.visibilityLagSeconds` for the residual this
 * does not fix.
 */
import type { CallerScope, StoreRecord } from "../ports.js";
import {
  type AuditEventRow,
  REQUEST_LOG_COLUMNS,
  type RequestLogRow,
  auditEventDocument,
  auditTenantFence,
  requestLogDocument,
  requestLogTenantFence,
} from "../routes/admin_request_log.js";
import { AUDIT_TABLE, REQUEST_LOG_TABLE } from "../store/d1.js";
import type { SiemStream } from "./config.js";
import type { SiemCursorPosition } from "./cursor.js";

/** One row on its way out: the wire document plus the key that ordered it. */
export interface SiemRow {
  readonly position: SiemCursorPosition;
  readonly document: StoreRecord;
}

/**
 * The `WHERE` clause, fence first.
 *
 * The fence helpers return a clause that STARTS with ` WHERE`, and an empty
 * string for a platform-operator scope. An empty string here would silently
 * produce a query with no tenant predicate at all — every tenant's evidence, in
 * one customer's SIEM — so it is refused rather than accommodated. It should be
 * unreachable (`parseSiemSinks` rejects a sink with no tenant, so every scope
 * this module builds is tenant-kind); this is the second lock on the same door,
 * and `test/siem-export.test.ts` proves the first one by mutation.
 */
function fenced(fence: { sql: string; params: string[] }, rest: string): string {
  if (fence.sql === "") {
    throw new Error("siem export: refusing to read evidence without a tenant fence");
  }
  return `${fence.sql} AND ${rest}`;
}

/**
 * `(ts, id) > (?, ?)` written out longhand.
 *
 * SQLite supports row values and would accept the tuple form, but the expanded
 * form is what the composite index can use on every SQLite build, and it makes
 * the tiebreaker's direction visible to a reader — which matters, because
 * getting `>=` in the second arm would re-deliver one row per batch forever.
 */
const KEYSET = (ts: string, id: string) => `(${ts} > ? OR (${ts} = ? AND ${id} > ?))`;

async function requestLogBatch(
  db: D1Database,
  scope: CallerScope,
  after: SiemCursorPosition,
  horizon: number,
  limit: number,
): Promise<readonly SiemRow[]> {
  const fence = requestLogTenantFence(scope);
  const where = fenced(
    fence,
    `${KEYSET("started_at_unix", "request_id")} AND started_at_unix <= ?`,
  );
  const result = await db
    .prepare(
      `SELECT ${REQUEST_LOG_COLUMNS}
         FROM ${REQUEST_LOG_TABLE}${where}
        ORDER BY started_at_unix ASC, request_id ASC
        LIMIT ?`,
    )
    .bind(...fence.params, after.ts, after.ts, after.id, horizon, limit)
    .all<RequestLogRow>();
  return result.results.map((row) => ({
    position: { ts: row.started_at_unix, id: row.request_id },
    document: requestLogDocument(row),
  }));
}

async function auditEventBatch(
  db: D1Database,
  scope: CallerScope,
  after: SiemCursorPosition,
  horizon: number,
  limit: number,
): Promise<readonly SiemRow[]> {
  const fence = auditTenantFence(scope);
  const where = fenced(fence, `${KEYSET("occurred_at_unix", "id")} AND occurred_at_unix <= ?`);
  const result = await db
    .prepare(
      // The four chain columns ride along because an audit row's value to a
      // customer is that they can VERIFY it (#684): `row_hash`/`prev_hash` and
      // the raw `audit_json` bytes are what `scripts/verify-audit-chain.mjs`
      // recomputes. A SIEM copy without them is a copy nobody can trust.
      `SELECT id, request_id, agent_run_id, tenant, occurred_at_unix, audit_json,
              chain_key, seq, prev_hash, row_hash
         FROM ${AUDIT_TABLE}${where}
        ORDER BY occurred_at_unix ASC, id ASC
        LIMIT ?`,
    )
    .bind(...fence.params, after.ts, after.ts, after.id, horizon, limit)
    .all<AuditEventRow>();
  return result.results.map((row) => ({
    position: { ts: row.occurred_at_unix, id: row.id },
    document: auditEventDocument(row),
  }));
}

/**
 * The next batch for one (tenant, stream), strictly after `after` and no newer
 * than `horizon`. Empty means "caught up", which is the pump's stop condition.
 */
export function readSiemBatch(
  db: D1Database,
  stream: SiemStream,
  tenant: string,
  after: SiemCursorPosition,
  horizon: number,
  limit: number,
): Promise<readonly SiemRow[]> {
  // Built here, from the sink's tenant, and never from a request: the pump has
  // no caller, so there is nothing that could arrive claiming to be one.
  const scope: CallerScope = { kind: "tenant", tenantId: tenant };
  return stream === "request_logs"
    ? requestLogBatch(db, scope, after, horizon, limit)
    : auditEventBatch(db, scope, after, horizon, limit);
}
