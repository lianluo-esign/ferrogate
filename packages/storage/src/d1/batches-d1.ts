/** D1 persistence for tenant-scoped batch jobs (#698, slices 1-3). */

import {
  BATCH_EXECUTABLE_STATUSES,
  BATCH_STATUS_PREDECESSORS,
  BATCH_TERMINAL_STATUSES,
  type BatchExecutionMode,
  type BatchList,
  type BatchProgressPatch,
  type BatchStatus,
  type BatchStore,
  type StoredBatch,
  type StoredBatchResult,
} from "../batches.js";
import { StorageError } from "../errors.js";
import { type TenantDatabaseHandle, requireAtomicBatch } from "../tenant-router.js";
import { bindOptional, boolFromSqlite, d1Error, optionalNumber, optionalText } from "./rows.js";

export const BATCH_COLUMNS =
  "id, tenant_id, input_file_id, endpoint, completion_window, status, output_file_id, " +
  "error_file_id, request_counts_json, metadata_json, created_at_unix, in_progress_at_unix, " +
  "finalizing_at_unix, completed_at_unix, failed_at_unix, expired_at_unix, " +
  "cancelling_at_unix, cancelled_at_unix, expires_at_unix";

/** The columns `sql/d1-ts/tenant/0024_batch_execution.sql` adds. */
const BATCH_EXECUTION_ONLY_COLUMNS =
  "api_key_id, project_id, next_line_index, attempt_count, " +
  "lease_owner, lease_expires_at_unix, failure_code, failure_message, " +
  "execution_mode, provider, provider_batch_id";

/** 0022 columns plus the 0023 execution columns. Read paths use this. */
export const BATCH_EXECUTION_COLUMNS = `${BATCH_COLUMNS}, ${BATCH_EXECUTION_ONLY_COLUMNS}`;

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
  // 0023 — absent on a row read through `BATCH_COLUMNS`.
  api_key_id?: string | null;
  project_id?: string | null;
  next_line_index?: number | null;
  attempt_count?: number | null;
  lease_owner?: string | null;
  lease_expires_at_unix?: number | null;
  failure_code?: string | null;
  failure_message?: string | null;
  execution_mode?: string | null;
  provider?: string | null;
  provider_batch_id?: string | null;
}

interface BatchResultRow {
  batch_id: string;
  line_index: number;
  custom_id: string;
  succeeded: number;
  body_json: string;
  created_at_unix: number;
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
    apiKeyId: optionalText(row.api_key_id),
    projectId: optionalText(row.project_id),
    nextLineIndex: optionalNumber(row.next_line_index),
    attemptCount: optionalNumber(row.attempt_count),
    leaseOwner: optionalText(row.lease_owner),
    leaseExpiresAtUnix: optionalNumber(row.lease_expires_at_unix),
    failureCode: optionalText(row.failure_code),
    failureMessage: optionalText(row.failure_message),
    executionMode: optionalText(row.execution_mode) as BatchExecutionMode | undefined,
    provider: optionalText(row.provider),
    providerBatchId: optionalText(row.provider_batch_id),
  };
}

function intoResult(row: BatchResultRow): StoredBatchResult {
  return {
    batchId: row.batch_id,
    lineIndex: Number(row.line_index),
    customId: row.custom_id,
    succeeded: boolFromSqlite(row.succeeded),
    body: parseJson<unknown>(row.body_json, "body_json"),
    createdAtUnix: Number(row.created_at_unix),
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
          `INSERT INTO batches (${BATCH_COLUMNS}, api_key_id, project_id, next_line_index, attempt_count)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
          bindOptional(batch.apiKeyId),
          bindOptional(batch.projectId),
          batch.nextLineIndex ?? 0,
          batch.attemptCount ?? 0,
        )
        .run();
    } catch (error) {
      throw d1Error("create_batch", error);
    }
  }

  async get(tenantId: string, batchId: string): Promise<StoredBatch | undefined> {
    try {
      const row = await this.db
        .prepare(`SELECT ${BATCH_EXECUTION_COLUMNS} FROM batches WHERE tenant_id = ? AND id = ?`)
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
          `SELECT ${BATCH_EXECUTION_COLUMNS} FROM batches
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
    // A terminal status drops the lease in the SAME statement. Leaving it set
    // would keep a finished job inside `claimable`'s "leased, come back later"
    // window until the lease expired, and — worse — would make a cancelled job
    // look busy to `requestCancel`, which decides between the direct and the
    // `cancelling` arm on exactly that field.
    if (BATCH_TERMINAL_STATUSES.includes(status)) {
      timestampAssignments.push("lease_owner = NULL", "lease_expires_at_unix = NULL");
    }
    const placeholders = predecessors.map(() => "?").join(", ");
    binds.push(tenantId, batchId, ...predecessors);
    try {
      const result = await this.db
        .prepare(
          `UPDATE batches SET status = ?, ${timestampAssignments.join(", ")}
           WHERE tenant_id = ? AND id = ? AND status IN (${placeholders})
           RETURNING ${BATCH_EXECUTION_COLUMNS}`,
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

  // -------------------------------------------------------------------------
  // Execution (#698 slice 2/3)
  // -------------------------------------------------------------------------

  async claimable(
    tenantId: string,
    nowUnix: number,
    limit: number,
  ): Promise<readonly StoredBatch[]> {
    const placeholders = BATCH_EXECUTABLE_STATUSES.map(() => "?").join(", ");
    try {
      const rows = await this.db
        .prepare(
          `SELECT ${BATCH_EXECUTION_COLUMNS} FROM batches
           WHERE tenant_id = ? AND status IN (${placeholders})
             AND COALESCE(lease_expires_at_unix, 0) <= ?
           ORDER BY created_at_unix ASC, id ASC LIMIT ?`,
        )
        .bind(tenantId, ...BATCH_EXECUTABLE_STATUSES, nowUnix, limit)
        .all<BatchRow>();
      return rows.results.map(intoBatch);
    } catch (error) {
      throw d1Error("claimable_batches", error);
    }
  }

  async claim(
    tenantId: string,
    batchId: string,
    owner: string,
    nowUnix: number,
    leaseSeconds: number,
  ): Promise<StoredBatch | undefined> {
    requireAtomicBatch(this.handle, "claim_batch");
    const placeholders = BATCH_EXECUTABLE_STATUSES.map(() => "?").join(", ");
    try {
      // ONE guarded UPDATE, deliberately. A read-then-write would let the Cron
      // sweep and a Queue redelivery both observe a free lease and both start
      // dispatching the same paid lines.
      const result = await this.db
        .prepare(
          `UPDATE batches
              SET lease_owner = ?, lease_expires_at_unix = ?, attempt_count = attempt_count + 1
            WHERE tenant_id = ? AND id = ? AND status IN (${placeholders})
              AND (COALESCE(lease_expires_at_unix, 0) <= ? OR lease_owner = ?)
            RETURNING ${BATCH_EXECUTION_COLUMNS}`,
        )
        .bind(
          owner,
          nowUnix + leaseSeconds,
          tenantId,
          batchId,
          ...BATCH_EXECUTABLE_STATUSES,
          nowUnix,
          owner,
        )
        .first<BatchRow>();
      return result === null ? undefined : intoBatch(result);
    } catch (error) {
      throw d1Error("claim_batch", error);
    }
  }

  async release(tenantId: string, batchId: string, owner: string): Promise<void> {
    requireAtomicBatch(this.handle, "release_batch");
    try {
      await this.db
        .prepare(
          `UPDATE batches SET lease_owner = NULL, lease_expires_at_unix = NULL
            WHERE tenant_id = ? AND id = ? AND lease_owner = ?`,
        )
        .bind(tenantId, batchId, owner)
        .run();
    } catch (error) {
      throw d1Error("release_batch", error);
    }
  }

  async saveProgress(
    tenantId: string,
    batchId: string,
    patch: BatchProgressPatch,
  ): Promise<StoredBatch | undefined> {
    requireAtomicBatch(this.handle, "save_batch_progress");
    const assignments: string[] = [];
    const binds: unknown[] = [];
    const set = (column: string, value: unknown): void => {
      assignments.push(`${column} = ?`);
      binds.push(value);
    };
    if (patch.requestCounts !== undefined) {
      set("request_counts_json", JSON.stringify(patch.requestCounts));
    }
    if (patch.nextLineIndex !== undefined) set("next_line_index", patch.nextLineIndex);
    if (patch.outputFileId !== undefined) set("output_file_id", patch.outputFileId);
    if (patch.errorFileId !== undefined) set("error_file_id", patch.errorFileId);
    if (patch.executionMode !== undefined) set("execution_mode", patch.executionMode);
    if (patch.provider !== undefined) set("provider", patch.provider);
    if (patch.providerBatchId !== undefined) set("provider_batch_id", patch.providerBatchId);
    if (patch.failureCode !== undefined) set("failure_code", patch.failureCode);
    if (patch.failureMessage !== undefined) set("failure_message", patch.failureMessage);
    if (assignments.length === 0) return this.get(tenantId, batchId);
    binds.push(tenantId, batchId);
    try {
      const result = await this.db
        .prepare(
          `UPDATE batches SET ${assignments.join(", ")}
            WHERE tenant_id = ? AND id = ?
            RETURNING ${BATCH_EXECUTION_COLUMNS}`,
        )
        .bind(...binds)
        .first<BatchRow>();
      return result === null ? undefined : intoBatch(result);
    } catch (error) {
      throw d1Error("save_batch_progress", error);
    }
  }

  async putResults(batchId: string, results: readonly StoredBatchResult[]): Promise<void> {
    if (results.length === 0) return;
    requireAtomicBatch(this.handle, "put_batch_results");
    try {
      // `ON CONFLICT DO UPDATE`, not `DO NOTHING`: Queues are at-least-once, so
      // a redelivered line must OVERWRITE its row. `DO NOTHING` would freeze
      // the first (possibly transport-failed) attempt as the published answer.
      await this.db.batch(
        results.map((result) =>
          this.db
            .prepare(
              `INSERT INTO batch_request_results
                 (batch_id, line_index, custom_id, succeeded, body_json, created_at_unix)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT (batch_id, line_index) DO UPDATE SET
                 custom_id = excluded.custom_id,
                 succeeded = excluded.succeeded,
                 body_json = excluded.body_json,
                 created_at_unix = excluded.created_at_unix`,
            )
            .bind(
              batchId,
              result.lineIndex,
              result.customId,
              result.succeeded ? 1 : 0,
              JSON.stringify(result.body),
              result.createdAtUnix,
            ),
        ),
      );
    } catch (error) {
      throw d1Error("put_batch_results", error);
    }
  }

  async listResults(batchId: string): Promise<readonly StoredBatchResult[]> {
    try {
      const rows = await this.db
        .prepare(
          `SELECT batch_id, line_index, custom_id, succeeded, body_json, created_at_unix
             FROM batch_request_results WHERE batch_id = ? ORDER BY line_index ASC`,
        )
        .bind(batchId)
        .all<BatchResultRow>();
      return rows.results.map(intoResult);
    } catch (error) {
      throw d1Error("list_batch_results", error);
    }
  }

  async requestCancel(
    tenantId: string,
    batchId: string,
    atUnix: number,
  ): Promise<StoredBatch | undefined> {
    const current = await this.get(tenantId, batchId);
    if (current === undefined) return undefined;
    const leased = (current.leaseExpiresAtUnix ?? 0) > atUnix;
    return this.updateStatus(tenantId, batchId, leased ? "cancelling" : "cancelled", atUnix);
  }
}
