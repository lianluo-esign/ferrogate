/**
 * Policy-driven retention for guardrail evidence (#665) — the answer to "and
 * then it grows forever", which is the other half of turning on an append-only
 * evidence table.
 *
 * ## Why this reuses #664's policy rather than declaring its own vars
 *
 * `REQUEST_LOG_RETENTION_DAYS` / `REQUEST_LOG_RETENTION_POLICIES` already
 * express, per tenant, how long this deployment keeps the record of what the
 * gateway DID. A guardrail evaluation is a row of exactly that record — it is
 * joined to a request log by `request_id` and read through the same
 * investigation view — so giving it a second, independently-set window would
 * create a state nobody wants and everybody would eventually reach: a request
 * log whose screening evidence has been deleted, or screening evidence for a
 * request that no longer exists. An investigation that can only half-answer is
 * the failure this issue exists to fix.
 *
 * Adding vars is also not free in this tree: the env-var drift gates pin the
 * declared set exactly, and two knobs that must be kept equal are a worse
 * operator surface than one.
 *
 * If a later slice genuinely needs to diverge (a jurisdiction that requires
 * screening evidence longer than traffic logs), the split belongs in
 * `requestlog/retention.ts::RequestLogRetentionScope` as a per-table override,
 * not in a parallel copy of the parser.
 *
 * ## `ON DELETE CASCADE` does the child rows
 *
 * `guardrail_check_evaluations.evaluation_id` is declared
 * `REFERENCES guardrail_evaluations(id) ON DELETE CASCADE`, so deleting the
 * parent takes its checks with it. The sweep therefore issues ONE delete per
 * doomed evaluation and cannot leave an orphaned check row — evidence pointing
 * at a decision that no longer exists, which is worse than no row at all.
 *
 * D1 enables foreign keys by default, but a database that somehow does not
 * would silently accumulate orphans; the child sweep below is issued
 * unconditionally for that reason and is a no-op when the cascade already ran.
 */
import {
  type LogRetentionCandidate,
  type RetentionPolicy,
  planLogRetention,
} from "@ferrogate/storage";
import { evidenceProjectionKey } from "../requestlog/d1.js";
import {
  REQUEST_LOG_SWEEP_MAX_ROWS,
  type RequestLogRetentionScope,
  type RequestLogSweepResult,
  requestLogRetentionFromEnv,
} from "../requestlog/retention.js";
import {
  GUARDRAIL_CHECK_TABLE,
  GUARDRAIL_EVALUATION_TABLE,
  type GuardrailEvidenceDatabase,
  guardrailTenantDatabaseFromEnv,
} from "./evidence-d1.js";

interface ProjectionCandidateRow {
  readonly projection_key: string;
  readonly id: string;
  readonly tenant?: string | null;
  readonly occurred_at_unix: number;
}

/**
 * Delete a set of rows from the shared projection by its tenant-qualified
 * keys. Logical evaluation ids are not unique in CONTROL, so deleting by
 * `id` would remove another tenant's evidence when the same deterministic id
 * is reused.
 */
function projectionDeleteStatements(
  db: GuardrailEvidenceDatabase,
  keys: readonly string[],
): unknown[] {
  const parents = db.prepare(`DELETE FROM ${GUARDRAIL_EVALUATION_TABLE} WHERE projection_key = ?`);
  const children = db.prepare(
    `DELETE FROM ${GUARDRAIL_CHECK_TABLE} WHERE evaluation_projection_key = ?`,
  );
  return [...keys.map((key) => children.bind(key)), ...keys.map((key) => parents.bind(key))];
}

/** Delete authoritative object rows by their local logical ids. */
function tenantDeleteStatements(db: GuardrailEvidenceDatabase, ids: readonly string[]): unknown[] {
  const parents = db.prepare(`DELETE FROM ${GUARDRAIL_EVALUATION_TABLE} WHERE id = ?`);
  const children = db.prepare(`DELETE FROM ${GUARDRAIL_CHECK_TABLE} WHERE evaluation_id = ?`);
  return [...ids.map((id) => children.bind(id)), ...ids.map((id) => parents.bind(id))];
}

/**
 * Apply one scope's rule to a bounded projection window.
 *
 * The candidate window is the OLDEST rows in the scope, because those are the
 * only ones an age rule can select; ascending order means the sweep does useful
 * work on its first tick against a large table instead of paging through rows
 * it will certainly keep.
 *
 * A tenant-scoped rule uses STRICT equality, so the fleet default — and only
 * the fleet default — governs the un-attributed (platform) rows. An operator
 * who narrows one tenant's window must not thereby narrow everyone's.
 *
 * Never throws: a retention failure is an unpruned table, which is safe.
 */
async function sweepGuardrailProjectionRows(
  db: GuardrailEvidenceDatabase,
  policy: RetentionPolicy,
  nowUnix: number,
  maxRows: number,
  fence: string,
  params: readonly (string | number)[],
): Promise<RequestLogSweepResult> {
  let rows: ProjectionCandidateRow[];
  try {
    const result = (await db
      .prepare(
        `SELECT projection_key, id, tenant, occurred_at_unix FROM ${GUARDRAIL_EVALUATION_TABLE}${fence}
          ORDER BY occurred_at_unix ASC LIMIT ?`,
      )
      .bind(...params, maxRows)
      .all()) as { results?: ProjectionCandidateRow[] };
    rows = result.results ?? [];
  } catch {
    return { scanned: 0, pruned: 0 };
  }

  const candidates: LogRetentionCandidate[] = rows.map((row) => ({
    id: row.projection_key,
    createdAtUnix: row.occurred_at_unix,
  }));
  // The PLANNER is reused rather than restated as a SQL predicate. Its
  // semantics — fail-safe KEEP on any doubt, `minAgeSecs` as an absolute floor,
  // an inert policy pruning nothing — are the contract, and re-deriving them in
  // a `DELETE ... WHERE occurred_at_unix < ?` here is how the two would come to
  // disagree about a boundary case that only shows up as missing evidence.
  const doomed = planLogRetention(candidates, nowUnix, policy);
  if (doomed.length === 0) return { scanned: rows.length, pruned: 0 };

  try {
    await db.batch(projectionDeleteStatements(db, doomed));
  } catch {
    return { scanned: rows.length, pruned: 0 };
  }
  return { scanned: rows.length, pruned: doomed.length };
}

/**
 * Apply one scope's rule to the CONTROL projection only.
 *
 * This remains exported for the small projection-level tests and for callers
 * that intentionally operate on a single database. The scheduled sweep below
 * uses the object-first path for tenant-attributed rows.
 */
export async function sweepGuardrailEvidenceRetention(
  db: GuardrailEvidenceDatabase,
  scope: RequestLogRetentionScope,
  nowUnix: number,
  maxRows: number = REQUEST_LOG_SWEEP_MAX_ROWS,
): Promise<RequestLogSweepResult> {
  const fence = scope.tenantId === undefined ? "" : " WHERE tenant = ?";
  const params = scope.tenantId === undefined ? [] : [scope.tenantId];
  return sweepGuardrailProjectionRows(db, scope.policy, nowUnix, maxRows, fence, params);
}

interface TenantCandidateRow {
  readonly id: string;
  readonly occurred_at_unix: number;
}

const AUTHORITY_ID_CHUNK_SIZE = 90;

/**
 * Remove projection rows whose authority was already deleted by an earlier
 * sweep. This is the recovery path for a successful object delete followed by
 * a failed projection delete: discovery still sees the mirror, but the normal
 * authority candidate query no longer sees anything to delete.
 */
async function sweepStaleTenantGuardrailProjectionRows(
  projectionDb: GuardrailEvidenceDatabase | undefined,
  authoritativeDb: GuardrailEvidenceDatabase,
  tenantId: string,
  policy: RetentionPolicy,
  nowUnix: number,
  maxRows: number,
): Promise<RequestLogSweepResult> {
  if (projectionDb === undefined || projectionDb === authoritativeDb) {
    return { scanned: 0, pruned: 0 };
  }

  let rows: ProjectionCandidateRow[];
  try {
    const result = (await projectionDb
      .prepare(
        `SELECT projection_key, id, tenant, occurred_at_unix FROM ${GUARDRAIL_EVALUATION_TABLE}
          WHERE tenant = ? ORDER BY occurred_at_unix ASC LIMIT ?`,
      )
      .bind(tenantId, maxRows)
      .all()) as { results?: ProjectionCandidateRow[] };
    rows = result.results ?? [];
  } catch {
    return { scanned: 0, pruned: 0 };
  }

  const doomedKeys = new Set(
    planLogRetention(
      rows.map((row) => ({ id: row.projection_key, createdAtUnix: row.occurred_at_unix })),
      nowUnix,
      policy,
    ),
  );
  const candidates = rows.filter((row) => doomedKeys.has(row.projection_key));
  if (candidates.length === 0) return { scanned: rows.length, pruned: 0 };

  const existing = new Set<string>();
  for (let offset = 0; offset < candidates.length; offset += AUTHORITY_ID_CHUNK_SIZE) {
    const chunk = candidates.slice(offset, offset + AUTHORITY_ID_CHUNK_SIZE);
    try {
      const result = (await authoritativeDb
        .prepare(
          `SELECT id FROM ${GUARDRAIL_EVALUATION_TABLE}
            WHERE tenant = ? AND id IN (${placeholders(chunk.length)})`,
        )
        .bind(tenantId, ...chunk.map((row) => row.id))
        .all()) as { results?: { id?: unknown }[] };
      for (const row of result.results ?? []) {
        if (typeof row.id === "string") existing.add(row.id);
      }
    } catch {
      // An authority lookup failure must keep the derived row. The object is
      // still the source of truth, so uncertainty never authorizes deletion.
      return { scanned: rows.length, pruned: 0 };
    }
  }

  const stale = candidates.filter((row) => !existing.has(row.id));
  if (stale.length === 0) return { scanned: rows.length, pruned: 0 };
  try {
    await projectionDb.batch(
      projectionDeleteStatements(
        projectionDb,
        stale.map((row) => row.projection_key),
      ),
    );
  } catch {
    return { scanned: rows.length, pruned: 0 };
  }
  return { scanned: rows.length, pruned: stale.length };
}

/**
 * Sweep one tenant object, then remove only the matching projection rows.
 *
 * D1 offers no cross-database transaction. Keeping the projection until the
 * object delete succeeds preserves the authoritative evidence when either the
 * object or the projection is temporarily unavailable.
 */
async function sweepTenantGuardrailEvidenceRetention(
  authoritativeDb: GuardrailEvidenceDatabase,
  tenantId: string,
  policy: RetentionPolicy,
  nowUnix: number,
  maxRows: number,
  projectionDb: GuardrailEvidenceDatabase | undefined,
): Promise<RequestLogSweepResult> {
  const stale = await sweepStaleTenantGuardrailProjectionRows(
    projectionDb,
    authoritativeDb,
    tenantId,
    policy,
    nowUnix,
    maxRows,
  );

  let rows: TenantCandidateRow[];
  try {
    const result = (await authoritativeDb
      .prepare(
        `SELECT id, occurred_at_unix FROM ${GUARDRAIL_EVALUATION_TABLE}
          WHERE tenant = ? ORDER BY occurred_at_unix ASC LIMIT ?`,
      )
      .bind(tenantId, maxRows)
      .all()) as { results?: TenantCandidateRow[] };
    rows = result.results ?? [];
  } catch {
    return { scanned: 0, pruned: 0 };
  }

  const candidates: LogRetentionCandidate[] = rows.map((row) => ({
    id: row.id,
    createdAtUnix: row.occurred_at_unix,
  }));
  const doomed = planLogRetention(candidates, nowUnix, policy);
  if (doomed.length === 0) {
    return { scanned: stale.scanned + rows.length, pruned: stale.pruned };
  }

  try {
    await authoritativeDb.batch(tenantDeleteStatements(authoritativeDb, doomed));
  } catch {
    return { scanned: stale.scanned + rows.length, pruned: stale.pruned };
  }

  const projectionKeys = doomed.map((id) => evidenceProjectionKey(tenantId, id));
  if (projectionDb === undefined || projectionDb === authoritativeDb) {
    return { scanned: stale.scanned + rows.length, pruned: stale.pruned + doomed.length };
  }
  try {
    await projectionDb.batch(projectionDeleteStatements(projectionDb, projectionKeys));
  } catch {
    return { scanned: stale.scanned + rows.length, pruned: stale.pruned + doomed.length };
  }
  return { scanned: stale.scanned + rows.length, pruned: stale.pruned + doomed.length };
}

/** Resolve an authoritative object without letting a Cron binding fault escape. */
function tenantDatabaseForSweep(
  env: unknown,
  tenantId: string,
): GuardrailEvidenceDatabase | undefined {
  try {
    return guardrailTenantDatabaseFromEnv(env, tenantId);
  } catch {
    // A missing/unreachable object leaves its evidence in place. The next tick
    // can retry after the binding or object becomes available.
    return undefined;
  }
}

function placeholders(count: number): string {
  return new Array(count).fill("?").join(", ");
}

/** Discover only tenants with rows old enough for the fleet policy. */
async function tenantIdsFromProjection(
  projectionDb: GuardrailEvidenceDatabase,
  maxRows: number,
  excluded: readonly string[],
  policy: RetentionPolicy,
  nowUnix: number,
): Promise<string[]> {
  const maxAgeSecs = policy.maxAgeSecs;
  if (maxAgeSecs === undefined || !Number.isFinite(maxAgeSecs)) return [];
  const eligibleBeforeUnix = nowUnix - maxAgeSecs;
  const exclusion =
    excluded.length === 0 ? "" : ` AND tenant NOT IN (${placeholders(excluded.length)})`;
  try {
    const result = (await projectionDb
      .prepare(
        `SELECT tenant FROM ${GUARDRAIL_EVALUATION_TABLE}
          WHERE tenant IS NOT NULL AND tenant <> ''
            AND occurred_at_unix < ?${exclusion}
          GROUP BY tenant ORDER BY tenant ASC LIMIT ?`,
      )
      .bind(eligibleBeforeUnix, ...excluded, maxRows)
      .all()) as { results?: { tenant?: unknown }[] };
    return (result.results ?? [])
      .map((row) => (typeof row.tenant === "string" ? row.tenant : ""))
      .filter((tenantId) => tenantId !== "");
  } catch {
    return [];
  }
}

/** Sweep platform/unattributed evidence, which has no tenant object. */
async function sweepUnscopedProjection(
  projectionDb: GuardrailEvidenceDatabase,
  policy: RetentionPolicy,
  nowUnix: number,
): Promise<RequestLogSweepResult> {
  return sweepGuardrailProjectionRows(
    projectionDb,
    policy,
    nowUnix,
    REQUEST_LOG_SWEEP_MAX_ROWS,
    " WHERE tenant IS NULL OR tenant = ''",
    [],
  );
}

/**
 * Every configured scope, swept once. The `scheduled` handler's entry point.
 *
 * With no vars configured this resolves to zero scopes and returns without
 * touching the database — an operator who has not opted into retention keeps
 * everything, which is the only safe default for evidence.
 */
export async function sweepGuardrailEvidence(
  db: GuardrailEvidenceDatabase | undefined,
  env: unknown,
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
    const result = await sweepTenantGuardrailEvidenceRetention(
      authoritative,
      tenantId,
      policy,
      nowUnix,
      REQUEST_LOG_SWEEP_MAX_ROWS,
      db,
    );
    scanned += result.scanned;
    pruned += result.pruned;
  }

  const fleet = scopes.find((scope) => scope.tenantId === undefined);
  if (fleet !== undefined && db !== undefined) {
    const unscoped = await sweepUnscopedProjection(db, fleet.policy, nowUnix);
    scanned += unscoped.scanned;
    pruned += unscoped.pruned;

    const tenantIds = await tenantIdsFromProjection(
      db,
      REQUEST_LOG_SWEEP_MAX_ROWS,
      [...overrides.keys()],
      fleet.policy,
      nowUnix,
    );
    for (const tenantId of tenantIds) {
      const authoritative = tenantDatabaseForSweep(env, tenantId);
      if (authoritative === undefined) continue;
      const result = await sweepTenantGuardrailEvidenceRetention(
        authoritative,
        tenantId,
        fleet.policy,
        nowUnix,
        REQUEST_LOG_SWEEP_MAX_ROWS,
        db,
      );
      scanned += result.scanned;
      pruned += result.pruned;
    }
  }
  return { scanned, pruned };
}
