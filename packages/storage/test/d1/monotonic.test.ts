/**
 * Monotonic upserts against REAL D1 (inventory §1.5.6).
 *
 * The property under test is ORDER INDEPENDENCE: a delayed or replayed write
 * carrying an older timestamp must never move a high-water column backwards.
 * Every one of these tests deliberately delivers writes out of order, because
 * an in-order-only test passes against a plain last-write-wins upsert and
 * therefore proves nothing.
 */
import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import {
  ControlMonotonicUpserts,
  TenantMonotonicUpserts,
  type TenantDatabaseHandle,
} from "../../src/index.js";
import { TENANT_A, TENANT_B, resetTenantData, setupDatabases } from "./harness.js";

const NOW = 1_700_000_000;

let handleA: TenantDatabaseHandle;
let handleB: TenantDatabaseHandle;
let control: ControlMonotonicUpserts;

beforeAll(async () => {
  const router = await setupDatabases();
  handleA = await router.forTenant(TENANT_A);
  handleB = await router.forTenant(TENANT_B);
  control = new ControlMonotonicUpserts(router.control());
});

beforeEach(async () => {
  await resetTenantData(env.TENANT_DB_A);
  await resetTenantData(env.TENANT_DB_B);
  await env.CONTROL_DB.prepare("DELETE FROM control_plane_replay_floors").run();
});

describe("observed presence", () => {
  test("an OUT-OF-ORDER touch does not move last_seen backwards", async () => {
    const upserts = new TenantMonotonicUpserts(handleA);
    await upserts.touchPresence({ tenantId: TENANT_A, apiKeyId: "k1", seenAtUnix: NOW + 100 });
    // A retried/queued touch arriving late with an OLDER timestamp.
    await upserts.touchPresence({ tenantId: TENANT_A, apiKeyId: "k1", seenAtUnix: NOW });

    const row = await upserts.getPresence(TENANT_A, "k1");
    expect(row?.lastSeenAtUnix).toBe(NOW + 100); // max, not last-write
    expect(row?.firstSeenAtUnix).toBe(NOW); // min, so the late one DID lower it
    expect(row?.updatedAtUnix).toBe(NOW + 100);
  });

  test("request counts ACCUMULATE (they are not max-folded)", async () => {
    const upserts = new TenantMonotonicUpserts(handleA);
    await upserts.touchPresence({ tenantId: TENANT_A, apiKeyId: "k1", seenAtUnix: NOW });
    await upserts.touchPresence({ tenantId: TENANT_A, apiKeyId: "k1", seenAtUnix: NOW });
    // A COALESCED touch standing in for five requests, as the fire-and-forget
    // off-hot-path batcher produces.
    await upserts.touchPresence({ tenantId: TENANT_A, apiKeyId: "k1", seenAtUnix: NOW }, 5);
    // Three distinct requests in the SAME second must all count; folding this
    // column with max() would silently under-report every burst.
    expect((await upserts.getPresence(TENANT_A, "k1"))?.requestCount).toBe(7);
  });

  test("the merge is order-independent: shuffled delivery reaches the same row", async () => {
    const upserts = new TenantMonotonicUpserts(handleA);
    const stamps = [NOW + 30, NOW + 10, NOW + 50, NOW, NOW + 20];
    for (const seenAtUnix of stamps) {
      await upserts.touchPresence({ tenantId: TENANT_A, apiKeyId: "k2", seenAtUnix });
    }
    const forward = await upserts.getPresence(TENANT_A, "k2");

    for (const seenAtUnix of [...stamps].reverse()) {
      await upserts.touchPresence({ tenantId: TENANT_A, apiKeyId: "k3", seenAtUnix });
    }
    const reversed = await upserts.getPresence(TENANT_A, "k3");

    expect(forward?.lastSeenAtUnix).toBe(reversed?.lastSeenAtUnix);
    expect(forward?.firstSeenAtUnix).toBe(reversed?.firstSeenAtUnix);
    expect(forward?.requestCount).toBe(reversed?.requestCount);
  });

  test("CONCURRENT touches all count and converge on the max timestamp", async () => {
    const upserts = new TenantMonotonicUpserts(handleA);
    await Promise.all(
      Array.from({ length: 12 }, (_, i) =>
        upserts.touchPresence({ tenantId: TENANT_A, apiKeyId: "k4", seenAtUnix: NOW + i }),
      ),
    );
    const row = await upserts.getPresence(TENANT_A, "k4");
    expect(row?.requestCount).toBe(12);
    expect(row?.lastSeenAtUnix).toBe(NOW + 11);
    expect(row?.firstSeenAtUnix).toBe(NOW);
  });

  test("presence is per-tenant-database, so one tenant cannot read another's", async () => {
    await new TenantMonotonicUpserts(handleA).touchPresence({
      tenantId: TENANT_A,
      apiKeyId: "k1",
      seenAtUnix: NOW,
    });
    expect(await new TenantMonotonicUpserts(handleB).getPresence(TENANT_A, "k1")).toBeUndefined();
  });
});

describe("agent cost burn", () => {
  test("accumulates USD and min-folds first_seen under out-of-order delivery", async () => {
    const upserts = new TenantMonotonicUpserts(handleA);
    await upserts.accumulateAgentCostBurn(TENANT_A, "agent_1", "2026-07", 1.5, NOW + 100);
    await upserts.accumulateAgentCostBurn(TENANT_A, "agent_1", "2026-07", 2.25, NOW);

    const row = await upserts.getAgentCostBurn(TENANT_A, "agent_1", "2026-07");
    expect(row?.accumulatedUsd).toBeCloseTo(3.75, 10);
    expect(row?.firstSeenUnix).toBe(NOW);
    expect(row?.updatedAtUnix).toBe(NOW + 100);
  });

  test("periods and agents are separate rows", async () => {
    const upserts = new TenantMonotonicUpserts(handleA);
    await upserts.accumulateAgentCostBurn(TENANT_A, "agent_1", "2026-07", 1, NOW);
    await upserts.accumulateAgentCostBurn(TENANT_A, "agent_1", "2026-08", 2, NOW);
    await upserts.accumulateAgentCostBurn(TENANT_A, "agent_2", "2026-07", 4, NOW);

    expect((await upserts.getAgentCostBurn(TENANT_A, "agent_1", "2026-07"))?.accumulatedUsd).toBe(
      1,
    );
    expect((await upserts.getAgentCostBurn(TENANT_A, "agent_1", "2026-08"))?.accumulatedUsd).toBe(
      2,
    );
    expect((await upserts.getAgentCostBurn(TENANT_A, "agent_2", "2026-07"))?.accumulatedUsd).toBe(
      4,
    );
  });

  test("CONCURRENT accumulation loses nothing", async () => {
    const upserts = new TenantMonotonicUpserts(handleA);
    await Promise.all(
      Array.from({ length: 20 }, () =>
        upserts.accumulateAgentCostBurn(TENANT_A, "agent_hot", "2026-07", 0.5, NOW),
      ),
    );
    expect((await upserts.getAgentCostBurn(TENANT_A, "agent_hot", "2026-07"))?.accumulatedUsd).toBe(
      10,
    );
  });
});

describe("control-plane replay floors", () => {
  test("a lower revision NEVER lowers the floor, and the caller reads back the winner", async () => {
    expect(await control.raiseReplayFloor("t", "deploy_1", 10, NOW)).toBe(10);
    // A lagging deployment re-announces an older snapshot.
    expect(await control.raiseReplayFloor("t", "deploy_1", 4, NOW + 1)).toBe(10);
    expect(await control.getReplayFloor("t", "deploy_1")).toBe(10);

    expect(await control.raiseReplayFloor("t", "deploy_1", 11, NOW + 2)).toBe(11);
  });

  test("floors are per (tenant, deployment)", async () => {
    await control.raiseReplayFloor("t1", "d1", 5, NOW);
    await control.raiseReplayFloor("t1", "d2", 9, NOW);
    await control.raiseReplayFloor("t2", "d1", 1, NOW);
    expect(await control.getReplayFloor("t1", "d1")).toBe(5);
    expect(await control.getReplayFloor("t1", "d2")).toBe(9);
    expect(await control.getReplayFloor("t2", "d1")).toBe(1);
  });

  test("CONCURRENT announcements converge on the maximum", async () => {
    const revisions = [7, 3, 12, 1, 9, 12, 2];
    await Promise.all(revisions.map((r) => control.raiseReplayFloor("t", "d", r, NOW)));
    expect(await control.getReplayFloor("t", "d")).toBe(12);
  });

  test("an unknown floor reads back as undefined, not 0", async () => {
    // 0 would be indistinguishable from a real floor of 0, which is a legal
    // starting revision — the caller must be able to tell "never announced".
    expect(await control.getReplayFloor("nobody", "nowhere")).toBeUndefined();
  });
});
