import type { TenantDatabaseRouter } from "@ferrogate/storage";
import { evidenceProjectionKey } from "./requestlog/d1.js";

const MANAGED_EVIDENCE_TABLE = "managed_worker_isolation_evidence";
const PROJECTION_BATCH_LIMIT = 500;

interface ManagedEvidenceRow {
  readonly id: string;
  readonly occurred_at_unix: number;
  readonly evidence_json: string;
}

function controlDatabaseFrom(env: unknown): D1Database | undefined {
  if (typeof env !== "object" || env === null) return undefined;
  const db = (env as { CONTROL_DB?: unknown }).CONTROL_DB;
  return typeof db === "object" && db !== null && typeof (db as D1Database).prepare === "function"
    ? (db as D1Database)
    : undefined;
}

/** Repair the control mirror of tenant-authoritative managed isolation evidence. */
export async function sweepManagedIsolationEvidence(
  env: unknown,
  router: TenantDatabaseRouter,
  tenantIds: readonly string[],
  limit = PROJECTION_BATCH_LIMIT,
): Promise<void> {
  const projection = controlDatabaseFrom(env);
  if (projection === undefined) return;
  for (const tenantId of tenantIds) {
    if (tenantId.trim() === "") continue;
    try {
      const handle = await router.forTenant(tenantId);
      if (handle.source !== "durable_object") continue;
      const pageSize = Math.max(1, Math.trunc(limit));
      let cursor: { occurredAtUnix: number; id: string } | undefined;
      for (;;) {
        const result =
          cursor === undefined
            ? await handle.db
                .prepare(
                  `SELECT id, occurred_at_unix, evidence_json
                     FROM ${MANAGED_EVIDENCE_TABLE}
                    ORDER BY occurred_at_unix ASC, id ASC
                    LIMIT ?`,
                )
                .bind(pageSize)
                .all<ManagedEvidenceRow>()
            : await handle.db
                .prepare(
                  `SELECT id, occurred_at_unix, evidence_json
                     FROM ${MANAGED_EVIDENCE_TABLE}
                    WHERE occurred_at_unix > ? OR (occurred_at_unix = ? AND id > ?)
                    ORDER BY occurred_at_unix ASC, id ASC
                    LIMIT ?`,
                )
                .bind(cursor.occurredAtUnix, cursor.occurredAtUnix, cursor.id, pageSize)
                .all<ManagedEvidenceRow>();
        if (result.results.length === 0) break;
        await projection.batch(
          result.results.map((row) =>
            projection
              .prepare(
                `INSERT INTO ${MANAGED_EVIDENCE_TABLE}
                   (projection_key, id, tenant, occurred_at_unix, evidence_json)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT (projection_key) DO UPDATE SET
                   id = excluded.id,
                   tenant = excluded.tenant,
                   occurred_at_unix = excluded.occurred_at_unix,
                   evidence_json = excluded.evidence_json`,
              )
              .bind(
                evidenceProjectionKey(tenantId, row.id),
                row.id,
                tenantId,
                row.occurred_at_unix,
                row.evidence_json,
              ),
          ),
        );
        const last = result.results.at(-1);
        if (last === undefined || result.results.length < pageSize) break;
        cursor = { occurredAtUnix: last.occurred_at_unix, id: last.id };
      }
    } catch (error) {
      console.warn(
        `[ferrogate] managed isolation evidence repair skipped for ${tenantId}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }
}
