/**
 * Idempotent bridge from the legacy control document table to tenant objects.
 *
 * The old rows stay in control D1 as a compatibility projection during this
 * migration. `INSERT ... ON CONFLICT DO NOTHING` makes the bridge safe to run
 * again after a crash and preserves a newer object-local write. Every call is
 * page-bounded; a later call resumes by re-reading the remaining compatibility
 * rows rather than relying on an in-memory cursor that a Worker eviction loses.
 */
import { TENANT_RESOURCE_KINDS } from "./resource-kinds.js";
import { RESOURCE_TABLE, TENANT_RESOURCE_TABLE } from "./d1.js";

const PAGE_SIZE = 200;

interface LegacyResourceRow {
  readonly resource_id: string;
  readonly document_json: string;
  readonly revision: number;
  readonly created_at_unix: number;
  readonly updated_at_unix: number;
}

export interface TenantResourceBackfillResult {
  readonly scanned: number;
  readonly copied: number;
}

/** Copy legacy rows for one tenant, preserving their revision/timestamps. */
export async function backfillTenantResourceKinds(
  controlDb: D1Database,
  tenantDb: D1Database,
  tenantId: string,
): Promise<TenantResourceBackfillResult> {
  let scanned = 0;
  let copied = 0;

  for (const kind of TENANT_RESOURCE_KINDS) {
    let offset = 0;
    for (;;) {
      const page = await controlDb
        .prepare(
          `SELECT resource_id, document_json, revision, created_at_unix, updated_at_unix
             FROM ${RESOURCE_TABLE}
            WHERE resource_kind = ?
              AND json_extract(document_json, '$.tenant_id') = ?
            ORDER BY resource_id
            LIMIT ? OFFSET ?`,
        )
        .bind(kind, tenantId, PAGE_SIZE, offset)
        .all<LegacyResourceRow>();
      const rows = page.results;
      scanned += rows.length;
      if (rows.length === 0) break;

      const result = await tenantDb.batch(
        rows.map((row) =>
          tenantDb
            .prepare(
              `INSERT INTO ${TENANT_RESOURCE_TABLE}
                 (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT (resource_kind, resource_id) DO NOTHING`,
            )
            .bind(
              kind,
              row.resource_id,
              row.document_json,
              row.revision,
              row.created_at_unix,
              row.updated_at_unix,
            ),
        ),
      );
      copied += result.reduce((total, entry) => total + (entry.meta.changes ?? 0), 0);
      offset += rows.length;
      if (rows.length < PAGE_SIZE) break;
    }
  }

  return { scanned, copied };
}
