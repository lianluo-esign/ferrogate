/**
 * THE MOUNTS for #698 — the two seams that can be deleted with a green suite.
 *
 * ## What this file exists for
 *
 * A mutation sweep replaced `await sweepBatchExecution(env, tenantIds, { usage })`
 * in `src/index.ts::gatewayScheduled` and the whole `batchJobs` partition in
 * `gatewayQueue` with `void` no-ops, and every batch-adjacent suite plus every
 * fleet invariant stayed green. That is the "fake mount" defect class
 * `test/metering/cron-mount.test.ts` and `test/evals/mount.test.ts` were written
 * for, and neither of them covers batches: `cron-trigger.test.ts` asserts the
 * `[triggers]` stanza and nothing about what runs on it, and no test in the repo
 * mentions `BATCH_JOBS` outside `batch-executor.test.ts`'s hand-built consumer
 * call. A rebase that drops either mount ships a Worker where no cron ever
 * advances a batch and every `batch.job` message falls through to the
 * request-log consumer.
 *
 * ## Why the observable is `attempt_count`, and why it cannot be faked
 *
 * The tick is driven against a REAL row in tenant_a's Durable Object database,
 * through the real `resolverForEnv` → `D1BatchStore`. `BatchStore.claim` is a
 * single guarded `UPDATE … SET attempt_count = attempt_count + 1`, and nothing
 * else in the gateway writes that column. So "the counter moved" means an
 * executor tick reached this tenant's database through the composition root —
 * an emptied mount moves nothing.
 *
 * The batch's input file id points at nothing, so the tick then fails the job
 * with `batch_input_unreadable`, which is asserted too: it proves the tick RAN
 * rather than merely claiming, and it is a terminal state, so the row cannot be
 * re-claimed by the second half of this file.
 */
import { createExecutionContext, env as poolEnv, waitOnExecutionContext } from "cloudflare:test";
import { D1BatchStore, type StoredBatch } from "@ferrogate/storage";
import { beforeEach, describe, expect, it } from "vitest";
import { BATCH_JOB_MESSAGE_OBJECT } from "../src/batch/index.js";
import { gatewayQueue } from "../src/index.js";
import { resolverForEnv } from "../src/tenancy/index.js";
import handler from "../src/worker.js";

const TENANT = "tenant_a";
const NOW = () => Math.floor(Date.now() / 1000);

function workerEnv(): Record<string, unknown> {
  return poolEnv as unknown as Record<string, unknown>;
}

/**
 * The tenant handle the EXECUTOR itself resolves, rather than a hand-built
 * Durable Object router: which backend `resolverForEnv` picks for a tenant is
 * `tenancy/`'s contract and not what this file is gating, and seeding the other
 * one would make the mount look unmounted.
 */
async function batchStore(): Promise<D1BatchStore> {
  return new D1BatchStore(await resolverForEnv(workerEnv() as never).forTenant(TENANT));
}

async function seedBatch(id: string): Promise<StoredBatch> {
  const store = await batchStore();
  const createdAtUnix = NOW();
  const batch: StoredBatch = {
    id,
    tenantId: TENANT,
    // Deliberately absent from the asset store: the tick must get far enough
    // to try to read it and then fail the job, which is a terminal state.
    inputFileId: "file-missing-on-purpose",
    endpoint: "/v1/chat/completions",
    completionWindow: "24h",
    status: "validating",
    requestCounts: { total: 0, completed: 0, failed: 0 },
    metadata: {},
    createdAtUnix,
    expiresAtUnix: createdAtUnix + 24 * 60 * 60,
    apiKeyId: "key_mount",
    nextLineIndex: 0,
    attemptCount: 0,
  };
  await store.create(batch);
  return batch;
}

async function readBatch(id: string): Promise<StoredBatch | undefined> {
  return (await batchStore()).get(TENANT, id);
}

beforeEach(async () => {
  const handle = await resolverForEnv(workerEnv() as never).forTenant(TENANT);
  await handle.db.batch([
    handle.db.prepare("DELETE FROM batch_request_results"),
    handle.db.prepare("DELETE FROM batches"),
  ]);
});

describe("seam 1 — gatewayQueue routes a batch.job message to the executor", () => {
  it("advances the job through the DEPLOYED queue entry point", async () => {
    const batch = await seedBatch(`batch_mount_${crypto.randomUUID().replace(/-/g, "")}`);

    await gatewayQueue(
      {
        queue: "replace-at-deploy-ferrogate-batch-jobs",
        messages: [
          {
            body: {
              object: BATCH_JOB_MESSAGE_OBJECT,
              tenant_id: TENANT,
              batch_id: batch.id,
            },
            ack: () => undefined,
          },
        ],
        retryAll: () => undefined,
      } as never,
      workerEnv(),
    );

    const advanced = await readBatch(batch.id);
    // Only `BatchStore.claim` writes this column, and only an executor tick
    // calls it. The `void`-ed mount leaves it at 0.
    expect(advanced?.attemptCount).toBe(1);
    expect(advanced?.status).toBe("failed");
    expect(advanced?.failureCode).toBe("batch_input_unreadable");
  });

  it("leaves a NON-batch message to the other consumers", async () => {
    const batch = await seedBatch(`batch_mount_${crypto.randomUUID().replace(/-/g, "")}`);

    // A request-log body. If the partition in `gatewayQueue` were dropped, this
    // would still not touch the batch — the point of the assertion is the
    // reverse direction: the batch consumer must not run on every delivery.
    await gatewayQueue(
      {
        queue: "replace-at-deploy-ferrogate-request-log",
        messages: [{ body: { object: "not.a.batch.job" }, ack: () => undefined }],
        retryAll: () => undefined,
      } as never,
      workerEnv(),
    );

    expect((await readBatch(batch.id))?.attemptCount).toBe(0);
    expect((await readBatch(batch.id))?.status).toBe("validating");
  });
});

describe("seam 2 — the Cron sweep advances claimable jobs", () => {
  it("advances the job from the ENTRY MODULE's scheduled handler", async () => {
    const scheduled = handler.scheduled;
    if (typeof scheduled !== "function") {
      throw new Error("the gateway entry module exports no `scheduled` handler");
    }
    const batch = await seedBatch(`batch_mount_${crypto.randomUUID().replace(/-/g, "")}`);
    const ctx = createExecutionContext();

    await scheduled(
      { cron: "* * * * *", scheduledTime: Date.now(), noRetry: () => undefined } as never,
      workerEnv() as never,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    const advanced = await readBatch(batch.id);
    expect(advanced?.attemptCount).toBe(1);
    expect(advanced?.status).toBe("failed");
    expect(advanced?.failureCode).toBe("batch_input_unreadable");
  });
});
