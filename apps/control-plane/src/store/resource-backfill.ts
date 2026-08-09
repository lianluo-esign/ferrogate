/**
 * Idempotent bridge from the legacy control document table to tenant objects.
 *
 * The old rows stay in control D1 as a compatibility projection during this
 * migration. `INSERT ... ON CONFLICT DO NOTHING` makes the bridge safe to run
 * again after a crash and preserves a newer object-local write. Every call is
 * row-bounded; the durable cursor lives in the tenant object so a later call
 * resumes after the last control row it examined rather than relying on an
 * in-memory cursor that a Worker eviction loses.
 */

import { RESOURCE_TABLE, TENANT_RESOURCE_TABLE, tenantResourceTombstoneMark } from "./d1.js";
import { TENANT_RESOURCE_KINDS } from "./resource-kinds.js";

/** The object-local mark that stores the generic resource backfill cursor. */
export const RESOURCE_BACKFILL_MARK = "control_plane_resource_backfill_v1";

/** Maximum legacy rows copied by one request before the next request resumes. */
export const RESOURCE_BACKFILL_BATCH_SIZE = 200;

interface LegacyResourceRow {
  readonly resource_id: string;
  readonly document_json: string;
  readonly revision: number;
  readonly created_at_unix: number;
  readonly updated_at_unix: number;
}

interface BackfillState {
  readonly kindIndex: number;
  readonly cursor: string | null;
  readonly complete: boolean;
}

export interface TenantResourceBackfillResult {
  readonly scanned: number;
  readonly copied: number;
}

function initialState(): BackfillState {
  return { kindIndex: 0, cursor: null, complete: false };
}

function detailOf(state: BackfillState): string {
  return JSON.stringify({ version: 1, ...state });
}

function stateOf(detail: string | null | undefined): BackfillState {
  if (detail === undefined || detail === null || detail.trim() === "") return initialState();
  try {
    const value: unknown = JSON.parse(detail);
    if (typeof value !== "object" || value === null) return initialState();
    const candidate = value as Record<string, unknown>;
    const kindIndex =
      typeof candidate.kindIndex === "number" && Number.isSafeInteger(candidate.kindIndex)
        ? Math.max(0, candidate.kindIndex)
        : 0;
    return {
      kindIndex,
      cursor: typeof candidate.cursor === "string" ? candidate.cursor : null,
      complete: candidate.complete === true,
    };
  } catch {
    return initialState();
  }
}

async function readState(tenantDb: D1Database, tenantId: string): Promise<BackfillState> {
  const row = await tenantDb
    .prepare("SELECT detail FROM tenant_provisioning_marks WHERE tenant_id = ? AND mark = ?")
    .bind(tenantId, RESOURCE_BACKFILL_MARK)
    .first<{ detail: string | null }>();
  return stateOf(row?.detail);
}

function markStatement(
  tenantDb: D1Database,
  tenantId: string,
  state: BackfillState,
): D1PreparedStatement {
  return tenantDb
    .prepare(
      `INSERT INTO tenant_provisioning_marks
         (tenant_id, mark, detail, applied_at_unix)
       VALUES (?, ?, ?, ?)
       ON CONFLICT (tenant_id, mark) DO UPDATE SET
         detail = excluded.detail,
         applied_at_unix = excluded.applied_at_unix`,
    )
    .bind(tenantId, RESOURCE_BACKFILL_MARK, detailOf(state), Math.floor(Date.now() / 1000));
}

/** Copy legacy rows for one tenant, preserving their revision/timestamps. */
export async function backfillTenantResourceKinds(
  controlDb: D1Database,
  tenantDb: D1Database,
  tenantId: string,
): Promise<TenantResourceBackfillResult> {
  let scanned = 0;
  let copied = 0;
  let remaining = RESOURCE_BACKFILL_BATCH_SIZE;
  let state = await readState(tenantDb, tenantId);

  if (state.complete) return { scanned, copied };

  while (state.kindIndex < TENANT_RESOURCE_KINDS.length && remaining > 0) {
    const kind = TENANT_RESOURCE_KINDS[state.kindIndex];
    if (kind === undefined) break;
    // `json_valid` guards the extract: a malformed legacy document would abort
    // the whole scan with a SQLITE error otherwise. The corrupt row is NOT
    // silently lost — it stays on control D1, where the reader's
    // `parseDocument` refuses it loudly by name ("unparseable document_json").
    const ownerOf =
      "CASE WHEN json_valid(document_json) THEN json_extract(document_json, '$.tenant_id') END";
    const predicate =
      state.cursor === null
        ? `resource_kind = ? AND ${ownerOf} = ?`
        : `resource_kind = ? AND ${ownerOf} = ? AND resource_id > ?`;
    const values =
      state.cursor === null
        ? [kind, tenantId, remaining]
        : [kind, tenantId, state.cursor, remaining];
    const page = await controlDb
      .prepare(
        `SELECT resource_id, document_json, revision, created_at_unix, updated_at_unix
           FROM ${RESOURCE_TABLE}
          WHERE ${predicate}
          ORDER BY resource_id
          LIMIT ?`,
      )
      .bind(...values)
      .all<LegacyResourceRow>();
    const rows = page.results;

    if (rows.length === 0) {
      state = { kindIndex: state.kindIndex + 1, cursor: null, complete: false };
      continue;
    }

    scanned += rows.length;
    const nextState: BackfillState =
      rows.length < remaining
        ? { kindIndex: state.kindIndex + 1, cursor: null, complete: false }
        : {
            kindIndex: state.kindIndex,
            cursor: rows.at(-1)?.resource_id ?? state.cursor,
            complete: false,
          };
    const result = await tenantDb.batch([
      ...rows.map((row) =>
        tenantDb
          .prepare(
            `INSERT INTO ${TENANT_RESOURCE_TABLE}
               (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
             SELECT ?, ?, ?, ?, ?, ?
              WHERE NOT EXISTS (
                SELECT 1 FROM tenant_provisioning_marks
                 WHERE tenant_id = ? AND mark = ?
              )
             ON CONFLICT (resource_kind, resource_id) DO NOTHING`,
          )
          .bind(
            kind,
            row.resource_id,
            row.document_json,
            row.revision,
            row.created_at_unix,
            row.updated_at_unix,
            tenantId,
            tenantResourceTombstoneMark(kind, row.resource_id),
          ),
      ),
      markStatement(tenantDb, tenantId, nextState),
    ]);
    copied += result
      .slice(0, rows.length)
      .reduce((total, entry) => total + (entry.meta.changes ?? 0), 0);
    remaining -= rows.length;
    state = nextState;
  }

  if (state.kindIndex >= TENANT_RESOURCE_KINDS.length && !state.complete) {
    await tenantDb.batch([
      markStatement(tenantDb, tenantId, {
        kindIndex: TENANT_RESOURCE_KINDS.length,
        cursor: null,
        complete: true,
      }),
    ]);
  }

  return { scanned, copied };
}
