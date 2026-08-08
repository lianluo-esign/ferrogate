/**
 * The batch job store against REAL D1/SQLite (#698, slices 1-3).
 *
 * This suite exists because the execution half of `D1BatchStore` is almost
 * entirely SQL — a guarded `UPDATE … WHERE … RETURNING` for the lease, an
 * `ON CONFLICT … DO UPDATE` for the per-line results — and none of it is
 * exercised by `MemoryBatchStore`. It is also the only place that proves
 * `sql/d1-ts/tenant/0024_batch_execution.sql` APPLIES: every column it adds is
 * read back here, so a migration that failed to run shows up as `no such
 * column` rather than as a silently absent field.
 */
import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import { D1BatchStore, type StoredBatch, type TenantDatabaseHandle } from "../../src/index.js";
import { TENANT_A, TENANT_B, setupTenantRouter, tenantDb } from "./harness.js";

const NOW = 1_784_073_600;

let handleA: TenantDatabaseHandle;
let handleB: TenantDatabaseHandle;

beforeAll(async () => {
  const router = await setupTenantRouter();
  handleA = await router.forTenant(TENANT_A);
  handleB = await router.forTenant(TENANT_B);
});

beforeEach(async () => {
  for (const tenantId of [TENANT_A, TENANT_B]) {
    const db = tenantDb(tenantId);
    await db.batch([
      db.prepare("DELETE FROM batch_request_results"),
      db.prepare("DELETE FROM batches"),
    ]);
  }
});

function row(overrides: Partial<StoredBatch> = {}): StoredBatch {
  return {
    id: "batch_1",
    tenantId: TENANT_A,
    inputFileId: "file-in",
    endpoint: "/v1/chat/completions",
    completionWindow: "24h",
    status: "validating",
    requestCounts: { total: 0, completed: 0, failed: 0 },
    metadata: { job: "d1" },
    createdAtUnix: NOW,
    expiresAtUnix: NOW + 86_400,
    apiKeyId: "key_1",
    projectId: "proj_1",
    nextLineIndex: 0,
    attemptCount: 0,
    ...overrides,
  };
}

describe("D1BatchStore — 0023 execution columns", () => {
  test("round-trips the creating scope chain and the cursor", async () => {
    const store = new D1BatchStore(handleA);
    await store.create(row());

    const stored = await store.get(TENANT_A, "batch_1");
    expect(stored).toMatchObject({
      apiKeyId: "key_1",
      projectId: "proj_1",
      nextLineIndex: 0,
      attemptCount: 0,
    });
    expect(stored?.leaseOwner).toBeUndefined();
    expect(stored?.executionMode).toBeUndefined();
  });

  test("saveProgress merges only the fields it is given", async () => {
    const store = new D1BatchStore(handleA);
    await store.create(row());

    await store.saveProgress(TENANT_A, "batch_1", { executionMode: "native", provider: "openai" });
    const afterFirst = await store.saveProgress(TENANT_A, "batch_1", { nextLineIndex: 7 });

    expect(afterFirst).toMatchObject({
      executionMode: "native",
      provider: "openai",
      nextLineIndex: 7,
      // Untouched by either patch.
      requestCounts: { total: 0, completed: 0, failed: 0 },
    });
  });
});

describe("D1BatchStore — the lease", () => {
  test("a second owner cannot claim a live lease, and can once it expires", async () => {
    const store = new D1BatchStore(handleA);
    await store.create(row());

    const first = await store.claim(TENANT_A, "batch_1", "tick_a", NOW, 120);
    expect(first?.leaseOwner).toBe("tick_a");
    expect(first?.attemptCount).toBe(1);

    expect(await store.claim(TENANT_A, "batch_1", "tick_b", NOW + 10, 120)).toBeUndefined();
    // The SAME owner may extend its own lease — a long tick must not lock
    // itself out of its own job.
    expect(await store.claim(TENANT_A, "batch_1", "tick_a", NOW + 10, 120)).toBeDefined();

    const afterExpiry = await store.claim(TENANT_A, "batch_1", "tick_b", NOW + 1_000, 120);
    expect(afterExpiry?.leaseOwner).toBe("tick_b");
    expect(afterExpiry?.attemptCount).toBe(3);
  });

  test("a terminal batch cannot be claimed at all", async () => {
    const store = new D1BatchStore(handleA);
    await store.create(row());
    await store.updateStatus(TENANT_A, "batch_1", "cancelled", NOW);

    expect(await store.claim(TENANT_A, "batch_1", "tick_a", NOW, 120)).toBeUndefined();
  });

  test("reaching a terminal status drops the lease in the same statement", async () => {
    const store = new D1BatchStore(handleA);
    await store.create(row());
    await store.claim(TENANT_A, "batch_1", "tick_a", NOW, 120);

    const failed = await store.updateStatus(TENANT_A, "batch_1", "failed", NOW + 5);

    expect(failed?.leaseOwner).toBeUndefined();
    expect(failed?.leaseExpiresAtUnix).toBeUndefined();
  });

  test("release only frees the lease its own owner holds", async () => {
    const store = new D1BatchStore(handleA);
    await store.create(row());
    await store.claim(TENANT_A, "batch_1", "tick_a", NOW, 120);

    await store.release(TENANT_A, "batch_1", "tick_b");
    expect((await store.get(TENANT_A, "batch_1"))?.leaseOwner).toBe("tick_a");

    await store.release(TENANT_A, "batch_1", "tick_a");
    expect((await store.get(TENANT_A, "batch_1"))?.leaseOwner).toBeUndefined();
  });

  test("claimable skips leased and terminal rows and stays tenant-scoped", async () => {
    const storeA = new D1BatchStore(handleA);
    const storeB = new D1BatchStore(handleB);
    await storeA.create(row({ id: "batch_free" }));
    await storeA.create(row({ id: "batch_busy" }));
    await storeA.create(row({ id: "batch_done" }));
    await storeB.create(row({ id: "batch_other", tenantId: TENANT_B }));

    await storeA.claim(TENANT_A, "batch_busy", "tick_a", NOW, 120);
    await storeA.updateStatus(TENANT_A, "batch_done", "cancelled", NOW);

    const claimable = await storeA.claimable(TENANT_A, NOW + 1, 10);
    expect(claimable.map((batch) => batch.id)).toEqual(["batch_free"]);

    // Once the lease has expired the busy row is claimable again — that is the
    // whole recovery story for an executor that died mid-tick.
    const later = await storeA.claimable(TENANT_A, NOW + 1_000, 10);
    expect(later.map((batch) => batch.id).sort()).toEqual(["batch_busy", "batch_free"]);
  });
});

describe("D1BatchStore — cancellation", () => {
  test("an unleased job cancels outright; a leased one goes to cancelling", async () => {
    const store = new D1BatchStore(handleA);
    await store.create(row({ id: "batch_idle" }));
    await store.create(row({ id: "batch_busy" }));
    await store.claim(TENANT_A, "batch_busy", "tick_a", NOW, 120);

    expect((await store.requestCancel(TENANT_A, "batch_idle", NOW))?.status).toBe("cancelled");
    const busy = await store.requestCancel(TENANT_A, "batch_busy", NOW);
    expect(busy?.status).toBe("cancelling");
    expect(busy?.cancellingAtUnix).toBe(NOW);
    expect(busy?.cancelledAtUnix).toBeUndefined();

    // The owning tick finishes the transition.
    expect((await store.updateStatus(TENANT_A, "batch_busy", "cancelled", NOW + 3))?.status).toBe(
      "cancelled",
    );
  });
});

describe("D1BatchStore — per-line results", () => {
  test("a redelivered line OVERWRITES its row instead of doubling the output", async () => {
    const store = new D1BatchStore(handleA);
    await store.create(row());

    await store.putResults("batch_1", [
      {
        batchId: "batch_1",
        lineIndex: 0,
        customId: "a",
        succeeded: false,
        body: { v: 1 },
        createdAtUnix: NOW,
      },
      {
        batchId: "batch_1",
        lineIndex: 1,
        customId: "b",
        succeeded: true,
        body: { v: 2 },
        createdAtUnix: NOW,
      },
    ]);
    await store.putResults("batch_1", [
      {
        batchId: "batch_1",
        lineIndex: 0,
        customId: "a",
        succeeded: true,
        body: { v: 3 },
        createdAtUnix: NOW + 1,
      },
    ]);

    const results = await store.listResults("batch_1");
    expect(results).toHaveLength(2);
    expect(results[0]).toMatchObject({ lineIndex: 0, succeeded: true, body: { v: 3 } });
    expect(results[1]).toMatchObject({ lineIndex: 1, succeeded: true, body: { v: 2 } });
  });

  test("results come back in input order regardless of write order", async () => {
    const store = new D1BatchStore(handleA);
    await store.create(row());
    await store.putResults("batch_1", [
      {
        batchId: "batch_1",
        lineIndex: 5,
        customId: "e",
        succeeded: true,
        body: {},
        createdAtUnix: NOW,
      },
      {
        batchId: "batch_1",
        lineIndex: 2,
        customId: "c",
        succeeded: true,
        body: {},
        createdAtUnix: NOW,
      },
    ]);

    expect((await store.listResults("batch_1")).map((r) => r.lineIndex)).toEqual([2, 5]);
  });

  test("another tenant's store cannot read this batch's row", async () => {
    const storeA = new D1BatchStore(handleA);
    const storeB = new D1BatchStore(handleB);
    await storeA.create(row());

    expect(await storeB.get(TENANT_A, "batch_1")).toBeUndefined();
    expect(await storeB.claim(TENANT_A, "batch_1", "tick_b", NOW, 120)).toBeUndefined();
  });
});
