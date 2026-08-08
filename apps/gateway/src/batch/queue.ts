/**
 * The `BATCH_JOBS` queue — the FAST trigger for the executor (#698, slice 2).
 *
 * ```
 *   createBatch ─ctx.waitUntil─▶ enqueueBatchJob ─▶ env.BATCH_JOBS.send(wire)
 *                                                          │
 *                                              consumeBatchJobBatch ─▶ runBatchTick
 *                                                          │
 *                                       more work remains? ─▶ re-enqueue
 * ```
 *
 * ## Why a queue AND a Cron, when either alone would "work"
 *
 * The Cron alone would mean a batch created at 12:00:01 sits idle until 12:01,
 * and a 50,000-line job would advance one tick per minute — 33 hours for a job
 * with a 24-hour completion window. The queue alone would mean a job whose
 * message was never produced (an unbound binding, a `waitUntil` that lost its
 * isolate) is stranded forever with no second look.
 *
 * So: the queue drives THROUGHPUT and the Cron is the RECOVERY floor. The
 * executor's lease is what lets both run without doubling anyone's bill.
 *
 * ## Why the consumer RE-ENQUEUES instead of looping
 *
 * A tick is bounded by design (see `./executor.ts`), so a long job needs many
 * of them. Looping inside one invocation would blow the Worker's CPU budget on
 * exactly the largest jobs; re-sending a message hands the next tick a fresh
 * invocation with a fresh budget. It is also the only way a job survives an
 * eviction mid-flight.
 *
 * ## The retry rule
 *
 * Every message is ACKED, including one whose tick refused a job for budget,
 * because none of those become true on redelivery and a redelivery costs paid
 * provider calls. `retryAll()` is armed ONLY when a tick reports `retry: true`,
 * which the executor sets exactly for a durable-write or publication failure.
 */
import type { BatchExecutorDeps, BatchTickResult } from "./executor.js";
import { runBatchTick } from "./executor.js";

/** The `object` discriminator `gatewayQueue` partitions on. */
export const BATCH_JOB_MESSAGE_OBJECT = "batch.job";

/** The queue body. FLAT and snake_case, like every other queue in this app. */
export interface BatchJobWire {
  readonly object: typeof BATCH_JOB_MESSAGE_OBJECT;
  readonly tenant_id: string;
  readonly batch_id: string;
}

/**
 * `[[queues.producers]] binding = "BATCH_JOBS"`, structurally.
 *
 * The SHAPE is checked rather than assumed, for the reason `evals/sink.ts`
 * gives: `env` is `unknown` here and a plain var carrying this name would
 * otherwise be `send()`-ed and fail where nobody is watching.
 */
export interface BatchJobQueue {
  send(body: unknown, options?: unknown): Promise<void>;
  sendBatch(messages: Iterable<{ body: unknown }>, options?: unknown): Promise<void>;
}

export interface BatchJobQueueBindings {
  readonly BATCH_JOBS?: unknown;
}

function isQueue(value: unknown): value is BatchJobQueue {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<BatchJobQueue>;
  return typeof candidate.send === "function" && typeof candidate.sendBatch === "function";
}

/** `env.BATCH_JOBS`, when it really is a Queue producer binding. */
export function batchJobQueueFrom(env: unknown): BatchJobQueue | undefined {
  if (typeof env !== "object" || env === null) return undefined;
  const candidate = (env as BatchJobQueueBindings).BATCH_JOBS;
  return isQueue(candidate) ? candidate : undefined;
}

/** Decode a delivery body. `undefined` for anything that is not ours. */
export function batchJobFromWire(body: unknown): BatchJobWire | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const source = body as Record<string, unknown>;
  if (source.object !== BATCH_JOB_MESSAGE_OBJECT) return undefined;
  const tenantId = source.tenant_id;
  const batchId = source.batch_id;
  if (typeof tenantId !== "string" || tenantId === "") return undefined;
  if (typeof batchId !== "string" || batchId === "") return undefined;
  return { object: BATCH_JOB_MESSAGE_OBJECT, tenant_id: tenantId, batch_id: batchId };
}

/**
 * Ask for a tick on this job. NEVER REJECTS.
 *
 * Called from `createBatch` on `ctx.waitUntil`, i.e. after the response object
 * exists. A rejection could only surface as a logged Worker exception on a
 * request that SUCCEEDED — and with no binding the Cron still picks the job up
 * within a minute, so the correct behaviour when this cannot send is to say so
 * in the log and let the recovery path do its job.
 */
export async function enqueueBatchJob(
  env: unknown,
  tenantId: string,
  batchId: string,
): Promise<boolean> {
  const queue = batchJobQueueFrom(env);
  if (queue === undefined) return false;
  try {
    const wire: BatchJobWire = {
      object: BATCH_JOB_MESSAGE_OBJECT,
      tenant_id: tenantId,
      batch_id: batchId,
    };
    await queue.send(wire);
    return true;
  } catch (error) {
    console.warn(
      `[ferrogate] batch ${batchId} could not be enqueued; the cron sweep will pick it up: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
    return false;
  }
}

/** The `MessageBatch` slice this consumer uses, structurally. */
export interface BatchJobMessageBatch {
  readonly queue?: string;
  readonly messages: readonly { readonly body: unknown; ack?(): void }[];
  retryAll?(options?: unknown): void;
}

export interface BatchJobConsumeResult {
  /** Jobs a tick actually advanced. */
  readonly ticked: number;
  /** Messages whose body could not be decoded; acked, never retried. */
  readonly malformed: number;
  /** Jobs handed back for another tick. */
  readonly reenqueued: number;
  readonly retried: boolean;
  readonly results: readonly BatchTickResult[];
}

/** Statuses that still have work left and therefore earn another message. */
const CONTINUES = new Set(["validating", "in_progress", "finalizing", "cancelling"]);

/**
 * Apply one queue delivery. NEVER throws — a consumer that throws gets its
 * batch redelivered anyway, so throwing only loses the ability to say what
 * happened.
 */
export async function consumeBatchJobBatch(
  batch: BatchJobMessageBatch,
  env: unknown,
  deps: BatchExecutorDeps = {},
): Promise<BatchJobConsumeResult> {
  const jobs: BatchJobWire[] = [];
  let malformed = 0;
  for (const message of batch.messages) {
    const job = batchJobFromWire(message.body);
    if (job === undefined) {
      malformed += 1;
      message.ack?.();
      continue;
    }
    jobs.push(job);
  }
  if (jobs.length === 0) {
    return { ticked: 0, malformed, reenqueued: 0, retried: false, results: [] };
  }

  const results: BatchTickResult[] = [];
  let retried = false;
  let reenqueued = 0;
  for (const job of jobs) {
    let result: BatchTickResult;
    try {
      result = await runBatchTick(env, job.tenant_id, job.batch_id, deps);
    } catch (error) {
      // `runBatchTick` already converts its own failures into a `retry` result,
      // so reaching here means the store itself could not be resolved. That is
      // a durable-side failure: arm the retry.
      console.warn(
        `[ferrogate] batch ${job.batch_id} tick failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      retried = true;
      continue;
    }
    results.push(result);
    if (result.retry) {
      retried = true;
      continue;
    }
    // More work left, and NOT "unclaimed": an unclaimed job is one another
    // invocation is already driving, and re-enqueuing it would spin the queue
    // against a lease that will not free for two minutes.
    if (result.status !== "unclaimed" && CONTINUES.has(result.status)) {
      if (await enqueueBatchJob(env, job.tenant_id, job.batch_id)) reenqueued += 1;
    }
  }

  if (retried) {
    batch.retryAll?.();
    return { ticked: results.length, malformed, reenqueued, retried: true, results };
  }
  for (const message of batch.messages) message.ack?.();
  return { ticked: results.length, malformed, reenqueued, retried: false, results };
}
