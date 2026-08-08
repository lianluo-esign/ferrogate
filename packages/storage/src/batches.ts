/**
 * Tenant-scoped batch jobs (#698, slices 1-3).
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

/**
 * How a job is being executed (#698 slice 2/3).
 *
 * `local` = the gateway reads the input JSONL and dispatches each line itself.
 * `native` = the whole job was handed to the provider's own batch endpoint and
 * the gateway polls it. The distinction is persisted rather than recomputed
 * because a catalogue change mid-flight must not make a job that was submitted
 * natively start being re-executed line by line.
 */
export const BATCH_EXECUTION_MODES = ["local", "native"] as const;
export type BatchExecutionMode = (typeof BATCH_EXECUTION_MODES)[number];

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
  /**
   * The credential and project that created the job.
   *
   * The executor runs with no request and therefore no `AuthContext`, so this
   * is the only record of the scope chain the budget ladder must be re-applied
   * against. See `sql/d1-ts/tenant/0024_batch_execution.sql`.
   */
  readonly apiKeyId?: string | undefined;
  readonly projectId?: string | undefined;
  /** Zero-based index of the next input line to execute. */
  readonly nextLineIndex?: number | undefined;
  /** How many times a tick has claimed this job. Bounds a poison job. */
  readonly attemptCount?: number | undefined;
  readonly leaseOwner?: string | undefined;
  readonly leaseExpiresAtUnix?: number | undefined;
  /** The refusal recorded when the job as a whole failed. */
  readonly failureCode?: string | undefined;
  readonly failureMessage?: string | undefined;
  readonly executionMode?: BatchExecutionMode | undefined;
  readonly provider?: string | undefined;
  readonly providerBatchId?: string | undefined;
}

/** One executed input line, as the finalizer will write it to JSONL. */
export interface StoredBatchResult {
  readonly batchId: string;
  readonly lineIndex: number;
  readonly customId: string;
  readonly succeeded: boolean;
  /** The whole output line object, already OpenAI-shaped. */
  readonly body: unknown;
  readonly createdAtUnix: number;
}

/** The execution fields one tick writes back. Absent = leave unchanged. */
export interface BatchProgressPatch {
  readonly requestCounts?: BatchRequestCounts | undefined;
  readonly nextLineIndex?: number | undefined;
  readonly outputFileId?: string | undefined;
  readonly errorFileId?: string | undefined;
  readonly executionMode?: BatchExecutionMode | undefined;
  readonly provider?: string | undefined;
  readonly providerBatchId?: string | undefined;
  readonly failureCode?: string | undefined;
  readonly failureMessage?: string | undefined;
}

export interface BatchList {
  readonly data: readonly StoredBatch[];
  readonly hasMore: boolean;
}

/** The statuses a tick may still advance. Everything else is terminal. */
export const BATCH_EXECUTABLE_STATUSES: readonly BatchStatus[] = [
  "validating",
  "in_progress",
  "finalizing",
  "cancelling",
];

/** The statuses nothing advances out of; reaching one drops the lease. */
export const BATCH_TERMINAL_STATUSES: readonly BatchStatus[] = [
  "completed",
  "failed",
  "expired",
  "cancelled",
];

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

  // -------------------------------------------------------------------------
  // Execution (#698 slice 2/3)
  // -------------------------------------------------------------------------

  /**
   * Non-terminal jobs whose lease is free or expired, oldest first. A read,
   * not a claim: {@link BatchStore.claim} is what makes ownership exclusive.
   */
  claimable(tenantId: string, nowUnix: number, limit: number): Promise<readonly StoredBatch[]>;
  /**
   * Take the lease, atomically. `undefined` when another invocation holds an
   * unexpired lease or the row has since become terminal.
   *
   * MUST be a single guarded write: the Cron and a Queue redelivery routinely
   * race for the same job, and a batch line is a paid provider call.
   */
  claim(
    tenantId: string,
    batchId: string,
    owner: string,
    nowUnix: number,
    leaseSeconds: number,
  ): Promise<StoredBatch | undefined>;
  /** Give the lease back early. A no-op when `owner` no longer holds it. */
  release(tenantId: string, batchId: string, owner: string): Promise<void>;
  /** Merge execution progress onto the row without touching `status`. */
  saveProgress(
    tenantId: string,
    batchId: string,
    patch: BatchProgressPatch,
  ): Promise<StoredBatch | undefined>;
  /** Upsert executed lines, keyed `(batchId, lineIndex)`. */
  putResults(batchId: string, results: readonly StoredBatchResult[]): Promise<void>;
  /** Every executed line for a job, in input order. */
  listResults(batchId: string): Promise<readonly StoredBatchResult[]>;
  /**
   * Client cancellation.
   *
   * An UNLEASED job is cancelled outright — nothing is running, so there is
   * nothing to wind down. A LEASED job goes to `cancelling` and the executor
   * that owns it finishes the transition, which is the OpenAI semantics and
   * the only way to avoid publishing output for a job the client has
   * abandoned.
   */
  requestCancel(
    tenantId: string,
    batchId: string,
    atUnix: number,
  ): Promise<StoredBatch | undefined>;
}

/**
 * The legal current states for each target.
 *
 * `cancelled` accepts `validating`/`in_progress` DIRECTLY as well as via
 * `cancelling`, and that is not a slice-1 leftover: {@link
 * BatchStore.requestCancel} takes the direct arm only when the row carries no
 * live lease, i.e. when no executor is mid-tick on it and there is nothing to
 * wind down. A LEASED job takes the `cancelling` arm and its owning tick
 * finishes the transition, so an abandoned job never publishes output.
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
  readonly #results = new Map<string, Map<number, StoredBatchResult>>();

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
    if (current === undefined || !batchStatusCanTransition(current.status, status))
      return undefined;
    const next = withStatusTimestamp(current, status, atUnix);
    this.#batches.set(batchId, next);
    return cloneBatch(next);
  }

  async claimable(
    tenantId: string,
    nowUnix: number,
    limit: number,
  ): Promise<readonly StoredBatch[]> {
    return [...this.#batches.values()]
      .filter(
        (batch) =>
          batch.tenantId === tenantId &&
          BATCH_EXECUTABLE_STATUSES.includes(batch.status) &&
          (batch.leaseExpiresAtUnix ?? 0) <= nowUnix,
      )
      .sort((left, right) => left.createdAtUnix - right.createdAtUnix)
      .slice(0, limit)
      .map(cloneBatch);
  }

  async claim(
    tenantId: string,
    batchId: string,
    owner: string,
    nowUnix: number,
    leaseSeconds: number,
  ): Promise<StoredBatch | undefined> {
    const current = this.#batches.get(batchId);
    if (current === undefined || current.tenantId !== tenantId) return undefined;
    if (!BATCH_EXECUTABLE_STATUSES.includes(current.status)) return undefined;
    if ((current.leaseExpiresAtUnix ?? 0) > nowUnix && current.leaseOwner !== owner) {
      return undefined;
    }
    const next: StoredBatch = {
      ...current,
      leaseOwner: owner,
      leaseExpiresAtUnix: nowUnix + leaseSeconds,
      attemptCount: (current.attemptCount ?? 0) + 1,
    };
    this.#batches.set(batchId, next);
    return cloneBatch(next);
  }

  async release(tenantId: string, batchId: string, owner: string): Promise<void> {
    const current = this.#batches.get(batchId);
    if (current === undefined || current.tenantId !== tenantId) return;
    if (current.leaseOwner !== owner) return;
    this.#batches.set(batchId, {
      ...current,
      leaseOwner: undefined,
      leaseExpiresAtUnix: undefined,
    });
  }

  async saveProgress(
    tenantId: string,
    batchId: string,
    patch: BatchProgressPatch,
  ): Promise<StoredBatch | undefined> {
    const current = this.#batches.get(batchId);
    if (current === undefined || current.tenantId !== tenantId) return undefined;
    const next: StoredBatch = {
      ...current,
      requestCounts: patch.requestCounts ?? current.requestCounts,
      nextLineIndex: patch.nextLineIndex ?? current.nextLineIndex,
      outputFileId: patch.outputFileId ?? current.outputFileId,
      errorFileId: patch.errorFileId ?? current.errorFileId,
      executionMode: patch.executionMode ?? current.executionMode,
      provider: patch.provider ?? current.provider,
      providerBatchId: patch.providerBatchId ?? current.providerBatchId,
      failureCode: patch.failureCode ?? current.failureCode,
      failureMessage: patch.failureMessage ?? current.failureMessage,
    };
    this.#batches.set(batchId, next);
    return cloneBatch(next);
  }

  async putResults(batchId: string, results: readonly StoredBatchResult[]): Promise<void> {
    const lines = this.#results.get(batchId) ?? new Map<number, StoredBatchResult>();
    for (const result of results) lines.set(result.lineIndex, { ...result });
    this.#results.set(batchId, lines);
  }

  async listResults(batchId: string): Promise<readonly StoredBatchResult[]> {
    return [...(this.#results.get(batchId)?.values() ?? [])]
      .sort((left, right) => left.lineIndex - right.lineIndex)
      .map((result) => ({ ...result }));
  }

  async requestCancel(
    tenantId: string,
    batchId: string,
    atUnix: number,
  ): Promise<StoredBatch | undefined> {
    const current = await this.get(tenantId, batchId);
    if (current === undefined) return undefined;
    const leased = (current.leaseExpiresAtUnix ?? 0) > atUnix;
    const target: BatchStatus = leased ? "cancelling" : "cancelled";
    return this.updateStatus(tenantId, batchId, target, atUnix);
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
