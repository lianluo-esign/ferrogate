/** D1 persistence for tenant-scoped batch jobs (#698, slice 1). */

import {
  type BatchList,
  type BatchStatus,
  BATCH_STATUS_PREDECESSORS,
  type BatchStore,
  type StoredBatch,
} from "../batches.js";
import { StorageError } from "../errors.js";
import { type TenantDatabaseHandle, requireAtomicBatch } from "../tenant-router.js";
import { bindOptional, d1Error, optionalNumber, optionalText } from "./rows.js";

export const BATCH_COLUMNS =
  "id, tenant_id, input_file_id, endpoint, completion_window, status, output_file_id, " +
  "error_file_id, request_counts_json, metadata_json, created_at_unix, in_progress_at_unix, " +
  "finalizing_at_unix, completed_at_unix, failed_at_unix, expired_at_unix, " +
  "cancelling_at_unix, cancelled_at_unix, expires_at_unix";

interface BatchRow {
  id: string;
  tenant_id: string;
  input_file_id: string;
  endpoint: string;
  completion_window: string;
  status: string;
  output_file_id: string | null;
  error_file_id: string | null;
  request_counts_json: string;
  metadata_json: string;
  created_at_unix: number;
  in_progress_at_unix: number | null;
  finalizing_at_unix: number | null;
  completed_at_unix: number | null;
  failed_at_unix: number | null;
  expired_at_unix: number | null;
  cancelling_at_unix: number | null;
  cancelled_at_unix: number | null;
  expires_at_unix: number;
}

function parseJson<T>(value: string, field: string): T {
  try {
    return JSON.parse(value) as T;
  } catch {
    throw StorageError.runtime(`batches.${field} is not valid JSON`);
  }
}

function intoBatch(row: BatchRow): StoredBatch {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    inputFileId: row.input_file_id,
    endpoint: row.endpoint,
    completionWindow: row.completion_window,
    status: row.status as BatchStatus,
    outputFileId: optionalText(row.output_file_id),
    errorFileId: optionalText(row.error_file_id),
    requestCounts: parseJson<StoredBatch["requestCounts"]>(
      row.request_counts_json,
      "request_counts_json",
    ),
    metadata: parseJson<StoredBatch["metadata"]>(row.metadata_json, "metadata_json"),
    createdAtUnix: Number(row.created_at_unix),
    inProgressAtUnix: optionalNumber(row.in_progress_at_unix),
    finalizingAtUnix: optionalNumber(row.finalizing_at_unix),
    completedAtUnix: optionalNumber(row.completed_at_unix),
    failedAtUnix: optionalNumber(row.failed_at_unix),
    expiredAtUnix: optionalNumber(row.expired_at_unix),
    cancellingAtUnix: optionalNumber(row.cancelling_at_unix),
    cancelledAtUnix: optionalNumber(row.cancelled_at_unix),
    expiresAtUnix: Number(row.expires_at_unix),
  };
}

function changes(result: D1Response): number {
  return (result.meta as { changes?: number } | undefined)?.changes ?? 0;
}

export class D1BatchStore implements BatchStore {
  private readonly db: D1Database;

  constructor(private readonly handle: TenantDatabaseHandle) {
    this.db = handle.db;
  }

  async create(batch: StoredBatch): Promise<void> {
    requireAtomicBatch(this.handle, "create_batch");
    try {
      await this.db
        .prepare(
          `INSERT INTO batches (${BATCH_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          batch.id,
          batch.tenantId,
          batch.inputFileId,
          batch.endpoint,
          batch.completionWindow,
          batch.status,
          bindOptional(batch.outputFileId),
          bindOptional(batch.errorFileId),
          JSON.stringify(batch.requestCounts),
          JSON.stringify(batch.metadata),
          batch.createdAtUnix,
          bindOptional(batch.inProgressAtUnix),
          bindOptional(batch.finalizingAtUnix),
          bindOptional(batch.completedAtUnix),
          bindOptional(batch.failedAtUnix),
          bindOptional(batch.expiredAtUnix),
          bindOptional(batch.cancellingAtUnix),
          bindOptional(batch.cancelledAtUnix),
          batch.expiresAtUnix,
        )
        .run();
    } catch (error) {
      throw d1Error("create_batch", error);
    }
  }

  async get(tenantId: string, batchId: string): Promise<StoredBatch | undefined> {
    try {
      const row = await this.db
        .prepare(`SELECT ${BATCH_COLUMNS} FROM batches WHERE tenant_id = ? AND id = ?`)
        .bind(tenantId, batchId)
        .first<BatchRow>();
      return row === null ? undefined : intoBatch(row);
    } catch (error) {
      throw d1Error("get_batch", error);
    }
  }

  async list(tenantId: string, after: string | undefined, limit: number): Promise<BatchList> {
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw StorageError.runtime(`list_batches requires a limit between 1 and 100, got ${limit}`);
    }
    try {
      const rows = await this.db
        .prepare(
          `SELECT ${BATCH_COLUMNS} FROM batches
           WHERE tenant_id = ?
             AND (? IS NULL OR (created_at_unix, id) <
               (SELECT created_at_unix, id FROM batches WHERE tenant_id = ? AND id = ?))
           ORDER BY created_at_unix DESC, id DESC LIMIT ?`,
        )
        .bind(tenantId, bindOptional(after), tenantId, after ?? "", limit + 1)
        .all<BatchRow>();
      const data = rows.results.slice(0, limit).map(intoBatch);
      return { data, hasMore: rows.results.length > data.length };
    } catch (error) {
      throw d1Error("list_batches", error);
    }
  }

  async updateStatus(
    tenantId: string,
    batchId: string,
    status: BatchStatus,
    atUnix: number,
  ): Promise<StoredBatch | undefined> {
    requireAtomicBatch(this.handle, "update_batch_status");
    const predecessors = BATCH_STATUS_PREDECESSORS[status];
    if (predecessors.length === 0) return undefined;

    const timestampAssignments: string[] = [];
    const binds: unknown[] = [status];
    if (status === "in_progress") {
      timestampAssignments.push("in_progress_at_unix = ?");
      binds.push(atUnix);
    } else if (status === "finalizing") {
      timestampAssignments.push("finalizing_at_unix = ?");
      binds.push(atUnix);
    } else if (status === "completed") {
      timestampAssignments.push("completed_at_unix = ?");
      binds.push(atUnix);
    } else if (status === "failed") {
      timestampAssignments.push("failed_at_unix = ?");
      binds.push(atUnix);
    } else if (status === "expired") {
      timestampAssignments.push("expired_at_unix = ?");
      binds.push(atUnix);
    } else if (status === "cancelling") {
      timestampAssignments.push("cancelling_at_unix = ?");
      binds.push(atUnix);
    } else if (status === "cancelled") {
      timestampAssignments.push("cancelling_at_unix = COALESCE(cancelling_at_unix, ?)");
      timestampAssignments.push("cancelled_at_unix = ?");
      binds.push(atUnix, atUnix);
    }
    const placeholders = predecessors.map(() => "?").join(", ");
    binds.push(tenantId, batchId, ...predecessors);
    try {
      const result = await this.db
        .prepare(
          `UPDATE batches SET status = ?, ${timestampAssignments.join(", ")}
           WHERE tenant_id = ? AND id = ? AND status IN (${placeholders})
           RETURNING ${BATCH_COLUMNS}`,
        )
        .bind(...binds)
        .first<BatchRow>();
      // D1's first() returns null for an empty RETURNING result. Keep the
      // fallback for local drivers that expose only changes().
      if (result === null) return undefined;
      return intoBatch(result);
    } catch (error) {
      throw d1Error("update_batch_status", error);
    }
  }
}
