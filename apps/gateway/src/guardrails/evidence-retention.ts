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
 * ## Where the rows live (Track A)
 *
 * Attributed evidence lives ONLY in each tenant's authoritative object;
 * un-attributed (platform-operator) evidence lives ONLY in the PLATFORM_DATA
 * singleton. The shared-CONTROL projection this sweep once also pruned was
 * retired and DROPped: deleting from it would have been the last tenant-data
 * write into the shared control singleton (no-tenant-data-mirror red line) and
 * would fault the moment the table is dropped. Discovery is therefore the
 * PROVISIONED ROSTER (`provisionedTenants()`, the same fan-out every other
 * Track-A sweep takes), NOT a `SELECT DISTINCT tenant` against a control mirror.
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
import {
  REQUEST_LOG_SWEEP_MAX_ROWS,
  type RequestLogSweepResult,
  requestLogRetentionFromEnv,
} from "../requestlog/retention.js";
import {
  GUARDRAIL_CHECK_TABLE,
  GUARDRAIL_EVALUATION_TABLE,
  type GuardrailEvidenceDatabase,
  guardrailTenantDatabaseFromEnv,
} from "./evidence-d1.js";
import { guardrailEvidencePlatformDatabaseFrom } from "./evidence-sink.js";

/** Delete authoritative object rows by their local logical ids. */
function tenantDeleteStatements(db: GuardrailEvidenceDatabase, ids: readonly string[]): unknown[] {
  const parents = db.prepare(`DELETE FROM ${GUARDRAIL_EVALUATION_TABLE} WHERE id = ?`);
  const children = db.prepare(`DELETE FROM ${GUARDRAIL_CHECK_TABLE} WHERE evaluation_id = ?`);
  return [...ids.map((id) => children.bind(id)), ...ids.map((id) => parents.bind(id))];
}

interface TenantCandidateRow {
  readonly id: string;
  readonly occurred_at_unix: number;
}

/**
 * Plan and delete one bounded candidate window against ONE authoritative
 * database — a tenant's own object, or the un-attributed PLATFORM_DATA object.
 *
 * The candidate window is the OLDEST rows in the scope, because those are the
 * only ones an age rule can select; ascending order means the sweep does useful
 * work on its first tick against a large table instead of paging through rows
 * it will certainly keep. There is no second (projection) database to reconcile
 * any more (Track A), so the sweep is single-destination.
 *
 * Never throws: a retention failure is an unpruned table, which is safe.
 */
async function sweepObjectGuardrailEvidence(
  authoritativeDb: GuardrailEvidenceDatabase,
  policy: RetentionPolicy,
  nowUnix: number,
  maxRows: number,
  fence: string,
  params: readonly (string | number)[],
): Promise<RequestLogSweepResult> {
  let rows: TenantCandidateRow[];
  try {
    const result = (await authoritativeDb
      .prepare(
        `SELECT id, occurred_at_unix FROM ${GUARDRAIL_EVALUATION_TABLE}${fence}
          ORDER BY occurred_at_unix ASC LIMIT ?`,
      )
      .bind(...params, maxRows)
      .all()) as { results?: TenantCandidateRow[] };
    rows = result.results ?? [];
  } catch {
    return { scanned: 0, pruned: 0 };
  }

  const candidates: LogRetentionCandidate[] = rows.map((row) => ({
    id: row.id,
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
    await authoritativeDb.batch(tenantDeleteStatements(authoritativeDb, doomed));
  } catch {
    return { scanned: rows.length, pruned: 0 };
  }
  return { scanned: rows.length, pruned: doomed.length };
}

/**
 * Sweep one tenant's authoritative object under `policy`.
 *
 * A tenant-scoped rule uses STRICT `tenant = ?` equality on the object's own
 * rows; the object holds only this tenant's evidence, so the fence is a
 * belt-and-braces guard rather than a cross-tenant filter.
 *
 * Never throws: a retention failure is an unpruned table, which is safe.
 */
async function sweepTenantGuardrailEvidenceRetention(
  authoritativeDb: GuardrailEvidenceDatabase,
  tenantId: string,
  policy: RetentionPolicy,
  nowUnix: number,
  maxRows: number,
): Promise<RequestLogSweepResult> {
  return sweepObjectGuardrailEvidence(authoritativeDb, policy, nowUnix, maxRows, " WHERE tenant = ?", [
    tenantId,
  ]);
}

/**
 * Sweep the platform object (Track A).
 *
 * The platform object holds ONLY platform/un-attributed evidence, so the whole
 * table IS the platform domain: no tenant fence, and no second database to
 * reconcile. It is id-keyed like a tenant object (no `projection_key`), so
 * deletes go by `id` and the child checks follow through `ON DELETE CASCADE`.
 * This is the ONLY place un-attributed evidence is pruned now that the control
 * projection is retired.
 *
 * Never throws: a retention failure is an unpruned table, which is safe.
 */
async function sweepPlatformGuardrailEvidenceRetention(
  platformDb: GuardrailEvidenceDatabase,
  policy: RetentionPolicy,
  nowUnix: number,
  maxRows: number,
): Promise<RequestLogSweepResult> {
  return sweepObjectGuardrailEvidence(platformDb, policy, nowUnix, maxRows, "", []);
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

/** Resolve the platform object without letting a Cron binding fault escape. */
function platformDatabaseForSweep(env: unknown): GuardrailEvidenceDatabase | undefined {
  try {
    return guardrailEvidencePlatformDatabaseFrom(env);
  } catch {
    // A missing/unreachable object leaves its evidence in place. The next tick
    // can retry after the binding or object becomes available.
    return undefined;
  }
}

/**
 * Every configured scope, swept once. The `scheduled` handler's entry point.
 *
 * `tenants` is the PROVISIONED ROSTER (`provisionedTenants()`) the scheduled
 * handler already resolved — the same fleet fan-out `sweepRequestLogs` takes. It
 * REPLACES the old `SELECT tenant FROM guardrail_evaluations` discovery against
 * the control mirror: every deletion targets a tenant's own authoritative object
 * or the PLATFORM_DATA object, and the retired control projection is not touched.
 *
 * With no vars configured this resolves to zero scopes and returns without
 * touching any database — an operator who has not opted into retention keeps
 * everything, which is the only safe default for evidence. With the registry
 * unavailable the roster is empty, so only explicit per-tenant overrides and the
 * platform object are swept; under-pruning is the fail-safe direction.
 */
export async function sweepGuardrailEvidence(
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
    const result = await sweepTenantGuardrailEvidenceRetention(
      authoritative,
      tenantId,
      policy,
      nowUnix,
      REQUEST_LOG_SWEEP_MAX_ROWS,
    );
    scanned += result.scanned;
    pruned += result.pruned;
  }

  const fleet = scopes.find((scope) => scope.tenantId === undefined);
  if (fleet !== undefined) {
    // The un-attributed platform object, swept under the fleet policy. This is the
    // only place unscoped rows are pruned now that the control unscoped sweep is
    // retired. Skipped when PLATFORM_DATA is not yet bound.
    const platformDb = platformDatabaseForSweep(env);
    if (platformDb !== undefined) {
      const platform = await sweepPlatformGuardrailEvidenceRetention(
        platformDb,
        fleet.policy,
        nowUnix,
        REQUEST_LOG_SWEEP_MAX_ROWS,
      );
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
      const result = await sweepTenantGuardrailEvidenceRetention(
        authoritative,
        tenantId,
        fleet.policy,
        nowUnix,
        REQUEST_LOG_SWEEP_MAX_ROWS,
      );
      scanned += result.scanned;
      pruned += result.pruned;
    }
  }
  return { scanned, pruned };
}
