/**
 * Tenant-scoped batch jobs (#698, slice 1).
 *
 * This module owns the batch DTO and the state-machine vocabulary. The D1
 * implementation in `./d1/batches-d1.ts` persists it; the memory store is the
 * reference backend used by the gateway's plain request tests.
 */

export const BATCH_STATUSES = [
  "validating",
  "in_progress",
  "finalizing",
  "completed",
  "failed",
  "expired",
  "cancelling",
  "cancelled",
] as const;

export type BatchStatus = (typeof BATCH_STATUSES)[number];

export interface BatchRequestCounts {
  readonly total: number;
  readonly completed: number;
  readonly failed: number;
}

export interface StoredBatch {
  readonly id: string;
  readonly tenantId: string;
  readonly inputFileId: string;
  readonly endpoint: string;
  readonly completionWindow: string;
  readonly status: BatchStatus;
  readonly outputFileId?: string | undefined;
  readonly errorFileId?: string | undefined;
  readonly requestCounts: BatchRequestCounts;
  readonly metadata: Readonly<Record<string, string>>;
  readonly createdAtUnix: number;
  readonly inProgressAtUnix?: number | undefined;
  readonly finalizingAtUnix?: number | undefined;
  readonly completedAtUnix?: number | undefined;
  readonly failedAtUnix?: number | undefined;
  readonly expiredAtUnix?: number | undefined;
  readonly cancellingAtUnix?: number | undefined;
  readonly cancelledAtUnix?: number | undefined;
  readonly expiresAtUnix: number;
}

export interface BatchList {
  readonly data: readonly StoredBatch[];
  readonly hasMore: boolean;
}

export interface BatchStore {
  create(batch: StoredBatch): Promise<void>;
  get(tenantId: string, batchId: string): Promise<StoredBatch | undefined>;
  list(tenantId: string, after: string | undefined, limit: number): Promise<BatchList>;
  updateStatus(
    tenantId: string,
    batchId: string,
    status: BatchStatus,
    atUnix: number,
  ): Promise<StoredBatch | undefined>;
}

/**
 * The legal current states for each target. `cancelled` also accepts a direct
 * request cancellation from the two open states: slice 1 has no executor to
 * advance `cancelling`, so the HTTP cancel operation completes synchronously.
 */
export const BATCH_STATUS_PREDECESSORS: Readonly<Record<BatchStatus, readonly BatchStatus[]>> = {
  validating: [],
  in_progress: ["validating"],
  finalizing: ["in_progress"],
  completed: ["finalizing"],
  failed: ["validating", "in_progress", "finalizing"],
  expired: ["validating", "in_progress", "finalizing"],
  cancelling: ["validating", "in_progress"],
  cancelled: ["validating", "in_progress", "cancelling"],
};

export function batchStatusCanTransition(from: BatchStatus, to: BatchStatus): boolean {
  return BATCH_STATUS_PREDECESSORS[to].includes(from);
}

/** Reference in-memory backend; no production request path uses this. */
export class MemoryBatchStore implements BatchStore {
  readonly #batches = new Map<string, StoredBatch>();

  async create(batch: StoredBatch): Promise<void> {
    if (this.#batches.has(batch.id)) {
      throw new Error(`batch ${batch.id} already exists`);
    }
    this.#batches.set(batch.id, cloneBatch(batch));
  }

  async get(tenantId: string, batchId: string): Promise<StoredBatch | undefined> {
    const batch = this.#batches.get(batchId);
    return batch?.tenantId === tenantId ? cloneBatch(batch) : undefined;
  }

  async list(tenantId: string, after: string | undefined, limit: number): Promise<BatchList> {
    const batches = [...this.#batches.values()]
      .filter((batch) => batch.tenantId === tenantId)
      .sort(batchOrder);
    const start = after === undefined ? 0 : batches.findIndex((batch) => batch.id === after) + 1;
    const visible = start > 0 ? batches.slice(start) : after === undefined ? batches : [];
    const data = visible.slice(0, limit).map(cloneBatch);
    return { data, hasMore: visible.length > data.length };
  }

  async updateStatus(
    tenantId: string,
    batchId: string,
    status: BatchStatus,
    atUnix: number,
  ): Promise<StoredBatch | undefined> {
    const current = await this.get(tenantId, batchId);
    if (current === undefined || !batchStatusCanTransition(current.status, status)) return undefined;
    const next = withStatusTimestamp(current, status, atUnix);
    this.#batches.set(batchId, next);
    return cloneBatch(next);
  }
}

function batchOrder(left: StoredBatch, right: StoredBatch): number {
  return right.createdAtUnix - left.createdAtUnix || right.id.localeCompare(left.id);
}

function withStatusTimestamp(batch: StoredBatch, status: BatchStatus, atUnix: number): StoredBatch {
  const next: StoredBatch = { ...batch, status };
  switch (status) {
    case "in_progress":
      return { ...next, inProgressAtUnix: atUnix };
    case "finalizing":
      return { ...next, finalizingAtUnix: atUnix };
    case "completed":
      return { ...next, completedAtUnix: atUnix };
    case "failed":
      return { ...next, failedAtUnix: atUnix };
    case "expired":
      return { ...next, expiredAtUnix: atUnix };
    case "cancelling":
      return { ...next, cancellingAtUnix: atUnix };
    case "cancelled":
      return {
        ...next,
        cancellingAtUnix: next.cancellingAtUnix ?? atUnix,
        cancelledAtUnix: atUnix,
      };
    case "validating":
      return next;
  }
}

function cloneBatch(batch: StoredBatch): StoredBatch {
  return {
    ...batch,
    requestCounts: { ...batch.requestCounts },
    metadata: { ...batch.metadata },
  };
}
