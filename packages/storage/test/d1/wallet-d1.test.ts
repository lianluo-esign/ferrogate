/**
 * The no-oversell proof, against a REAL D1 database (inventory §1.5.1/§1.5.2).
 *
 * These assertions are only meaningful because the database is real: they claim
 * that `batch()` is one transaction, that an empty `RETURNING` set is the
 * guard's refusal, and that SQLite serializes writers per database. A fake
 * would satisfy all three by construction and prove nothing.
 */
import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import { D1WalletStore, StorageError, type TenantDatabaseHandle } from "../../src/index.js";
import {
  TENANT_A,
  TENANT_B,
  resetTenantData,
  seedWallet,
  setupTenantRouter,
  tenantDb,
} from "./harness.js";

const NOW = 1_700_000_000;
const LATER = NOW + 3_600;

let handleA: TenantDatabaseHandle;
let handleB: TenantDatabaseHandle;

beforeAll(async () => {
  const router = await setupTenantRouter();
  handleA = await router.forTenant(TENANT_A);
  handleB = await router.forTenant(TENANT_B);
});

beforeEach(async () => {
  await resetTenantData(tenantDb(TENANT_A));
  await resetTenantData(tenantDb(TENANT_B));
});

describe("D1WalletStore — no-oversell reserve", () => {
  test("CONCURRENT DOUBLE SPEND: 5 parallel reserves against a balance affording 4 admit exactly 4", async () => {
    const store = new D1WalletStore(handleA);
    await seedWallet(handleA, 400);

    // Fire all five WITHOUT awaiting in between, so the five `batch()` calls are
    // in flight against the same database at the same time. This is the actual
    // double-spend attempt; sequential calls would prove nothing about the guard.
    const outcomes = await Promise.all(
      [1, 2, 3, 4, 5].map((n) =>
        store.reserveWalletCredits(`hold_${n}`, TENANT_A, 100, LATER, NOW),
      ),
    );

    const reserved = outcomes.filter((o) => o.kind === "reserved");
    const insufficient = outcomes.filter((o) => o.kind === "insufficient");
    expect(reserved).toHaveLength(4);
    expect(insufficient).toHaveLength(1);

    // The durable state must agree with what the callers were told — a reserve
    // that reported `insufficient` but left a row behind would be an oversell
    // that the return value hid.
    const live = await handleA.db
      .prepare(
        "SELECT COALESCE(SUM(amount_credits), 0) AS held FROM wallet_reservations " +
          "WHERE tenant_id = ? AND status = 'active'",
      )
      .bind(TENANT_A)
      .first<{ held: number }>();
    expect(live?.held).toBe(400);

    // THE INVARIANT, stated directly: never hold more than the balance.
    expect(live?.held).toBeLessThanOrEqual(400);
    expect(await store.availableCredits(TENANT_A, NOW)).toBe(0);
  });

  test("20 parallel reserves against a balance affording 7 admit exactly 7", async () => {
    const store = new D1WalletStore(handleA);
    await seedWallet(handleA, 700);

    const outcomes = await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        store.reserveWalletCredits(`burst_${i}`, TENANT_A, 100, LATER, NOW),
      ),
    );

    expect(outcomes.filter((o) => o.kind === "reserved")).toHaveLength(7);
    expect(outcomes.filter((o) => o.kind === "insufficient")).toHaveLength(13);
    expect(await store.availableCredits(TENANT_A, NOW)).toBe(0);
  });

  test("a single reserve that exceeds available balance reports the shortfall, not an error", async () => {
    const store = new D1WalletStore(handleA);
    await seedWallet(handleA, 250);

    const outcome = await store.reserveWalletCredits("hold_big", TENANT_A, 300, LATER, NOW);
    expect(outcome).toEqual({
      kind: "insufficient",
      availableCredits: 250,
      requestedCredits: 300,
    });
    expect(await store.getReservation("hold_big")).toBeUndefined();
  });

  test("a tenant with no wallet row reports no_wallet, distinctly from insufficient", async () => {
    const store = new D1WalletStore(handleA);
    const outcome = await store.reserveWalletCredits("hold_nw", TENANT_A, 10, LATER, NOW);
    expect(outcome).toEqual({ kind: "no_wallet" });
  });

  test("EXPIRED holds do not count against available balance", async () => {
    const store = new D1WalletStore(handleA);
    await seedWallet(handleA, 100);

    // A hold that has already expired.
    expect(
      (await store.reserveWalletCredits("hold_stale", TENANT_A, 100, NOW - 1, NOW - 10)).kind,
    ).toBe("reserved");
    // ...so the full balance is still available to a fresh hold.
    expect(await store.availableCredits(TENANT_A, NOW)).toBe(100);
    expect((await store.reserveWalletCredits("hold_fresh", TENANT_A, 100, LATER, NOW)).kind).toBe(
      "reserved",
    );
  });

  test("replaying the same hold id is idempotent; changing its amount is a conflict", async () => {
    const store = new D1WalletStore(handleA);
    await seedWallet(handleA, 500);

    const first = await store.reserveWalletCredits("hold_dup", TENANT_A, 100, LATER, NOW);
    const second = await store.reserveWalletCredits("hold_dup", TENANT_A, 100, LATER, NOW + 5);
    expect(first.kind).toBe("reserved");
    expect(second.kind).toBe("reserved");
    // Only ONE hold exists — the replay did not double-reserve.
    expect(await store.availableCredits(TENANT_A, NOW)).toBe(400);

    await expect(
      store.reserveWalletCredits("hold_dup", TENANT_A, 999, LATER, NOW),
    ).rejects.toMatchObject({ kind: "conflict" });
  });

  test("a non-positive amount is refused before any I/O", async () => {
    const store = new D1WalletStore(handleA);
    await seedWallet(handleA, 500);
    await expect(
      store.reserveWalletCredits("hold_zero", TENANT_A, 0, LATER, NOW),
    ).rejects.toMatchObject({ kind: "conflict" });
    expect(await store.getReservation("hold_zero")).toBeUndefined();
  });
});

describe("D1WalletStore — cross-tenant isolation", () => {
  test("tenant A's holds are invisible in tenant B's database", async () => {
    const storeA = new D1WalletStore(handleA);
    const storeB = new D1WalletStore(handleB);
    await seedWallet(handleA, 500);
    await seedWallet(handleB, 500);

    await storeA.reserveWalletCredits("hold_iso", TENANT_A, 400, LATER, NOW);

    // Same hold id, different tenant, different physical database.
    expect(await storeB.getReservation("hold_iso")).toBeUndefined();
    expect(await storeB.availableCredits(TENANT_B, NOW)).toBe(500);
    expect(await storeA.availableCredits(TENANT_A, NOW)).toBe(100);
  });

  test("writing tenant B's id through tenant A's handle is refused (mis-routing tripwire)", async () => {
    const storeA = new D1WalletStore(handleA);
    await seedWallet(handleA, 500);
    await expect(
      storeA.reserveWalletCredits("hold_wrong", TENANT_B, 10, LATER, NOW),
    ).rejects.toThrow(/refusing to cross tenant isolation/);
  });
});

describe("D1WalletStore — capture and cancel", () => {
  test("settle debits exactly once, links the settlement to the hold, and replays idempotently", async () => {
    const store = new D1WalletStore(handleA);
    await seedWallet(handleA, 500);
    await store.reserveWalletCredits("hold_s", TENANT_A, 120, LATER, NOW);

    const first = await store.settleWalletReservation("hold_s", NOW + 1);
    expect(first.newlyApplied).toBe(true);
    expect(first.reservation.status).toBe("settled");
    expect(first.reservation.settlementId).toBe("hold_s");
    expect(first.settlement.deltaCredits).toBe(-120);
    expect(first.settlement.balanceAfterCredits).toBe(380);
    expect((await store.getWallet(TENANT_A))?.balanceCredits).toBe(380);

    const replay = await store.settleWalletReservation("hold_s", NOW + 2);
    expect(replay.newlyApplied).toBe(false);
    // The balance did NOT move again.
    expect((await store.getWallet(TENANT_A))?.balanceCredits).toBe(380);
  });

  test("CONCURRENT settle of one hold debits exactly once", async () => {
    const store = new D1WalletStore(handleA);
    await seedWallet(handleA, 500);
    await store.reserveWalletCredits("hold_race", TENANT_A, 200, LATER, NOW);

    const outcomes = await Promise.allSettled([
      store.settleWalletReservation("hold_race", NOW + 1),
      store.settleWalletReservation("hold_race", NOW + 1),
      store.settleWalletReservation("hold_race", NOW + 1),
    ]);
    const applied = outcomes.filter(
      (o) => o.status === "fulfilled" && o.value.newlyApplied === true,
    );
    expect(applied).toHaveLength(1);
    // 500 - 200, exactly once, no matter how the three interleaved.
    expect((await store.getWallet(TENANT_A))?.balanceCredits).toBe(300);
  });

  test("release restores available balance and is idempotent; a settled hold cannot be released", async () => {
    const store = new D1WalletStore(handleA);
    await seedWallet(handleA, 500);
    await store.reserveWalletCredits("hold_r", TENANT_A, 300, LATER, NOW);
    expect(await store.availableCredits(TENANT_A, NOW)).toBe(200);

    const released = await store.releaseWalletReservation("hold_r", NOW + 1);
    expect(released.status).toBe("released");
    expect(await store.availableCredits(TENANT_A, NOW)).toBe(500);
    // Balance itself never moved — a release is not a refund.
    expect((await store.getWallet(TENANT_A))?.balanceCredits).toBe(500);

    expect((await store.releaseWalletReservation("hold_r", NOW + 2)).status).toBe("released");

    await store.reserveWalletCredits("hold_r2", TENANT_A, 100, LATER, NOW);
    await store.settleWalletReservation("hold_r2", NOW + 1);
    await expect(store.releaseWalletReservation("hold_r2", NOW + 2)).rejects.toMatchObject({
      kind: "conflict",
    });
  });

  test("a released hold cannot be settled, and an expired one is refused and released", async () => {
    const store = new D1WalletStore(handleA);
    await seedWallet(handleA, 500);

    await store.reserveWalletCredits("hold_rel", TENANT_A, 50, LATER, NOW);
    await store.releaseWalletReservation("hold_rel", NOW + 1);
    await expect(store.settleWalletReservation("hold_rel", NOW + 2)).rejects.toMatchObject({
      kind: "conflict",
    });

    await store.reserveWalletCredits("hold_exp", TENANT_A, 50, NOW + 10, NOW);
    await expect(store.settleWalletReservation("hold_exp", NOW + 20)).rejects.toMatchObject({
      kind: "conflict",
    });
    // The refusal ALSO released it, so the credits are not stranded.
    expect((await store.getReservation("hold_exp"))?.status).toBe("released");
    expect((await store.getWallet(TENANT_A))?.balanceCredits).toBe(500);
  });

  test("settling an unknown hold is not_found", async () => {
    const store = new D1WalletStore(handleA);
    await expect(store.settleWalletReservation("nope", NOW)).rejects.toMatchObject({
      kind: "not_found",
    });
  });

  test("sweep releases every expired active hold, once", async () => {
    const store = new D1WalletStore(handleA);
    await seedWallet(handleA, 1_000);
    await store.reserveWalletCredits("sw_1", TENANT_A, 10, NOW + 5, NOW);
    await store.reserveWalletCredits("sw_2", TENANT_A, 10, NOW + 5, NOW);
    await store.reserveWalletCredits("sw_live", TENANT_A, 10, LATER, NOW);

    expect(await store.sweepExpiredWalletReservations(NOW + 10)).toEqual(["sw_1", "sw_2"]);
    // Second sweep finds nothing — the guard `status = 'active'` already fired.
    expect(await store.sweepExpiredWalletReservations(NOW + 10)).toEqual([]);
    expect((await store.getReservation("sw_live"))?.status).toBe("active");
  });
});

describe("D1WalletStore — standalone balance settlement", () => {
  test("a top-up applies once and replays without moving the balance again", async () => {
    const store = new D1WalletStore(handleA);
    await seedWallet(handleA, 100);

    const first = await store.settleWalletBalance("topup_1", TENANT_A, 250, NOW);
    expect(first.newlyApplied).toBe(true);
    expect(first.settlement.balanceAfterCredits).toBe(350);
    expect((await store.getWallet(TENANT_A))?.balanceCredits).toBe(350);

    const replay = await store.settleWalletBalance("topup_1", TENANT_A, 250, NOW + 1);
    expect(replay.newlyApplied).toBe(false);
    expect((await store.getWallet(TENANT_A))?.balanceCredits).toBe(350);
  });

  test("CONCURRENT duplicate top-ups apply exactly once", async () => {
    const store = new D1WalletStore(handleA);
    await seedWallet(handleA, 100);

    await Promise.allSettled([
      store.settleWalletBalance("topup_race", TENANT_A, 500, NOW),
      store.settleWalletBalance("topup_race", TENANT_A, 500, NOW),
      store.settleWalletBalance("topup_race", TENANT_A, 500, NOW),
    ]);
    expect((await store.getWallet(TENANT_A))?.balanceCredits).toBe(600);
  });

  test("replaying a settlement id with a different amount is a conflict", async () => {
    const store = new D1WalletStore(handleA);
    await seedWallet(handleA, 100);
    await store.settleWalletBalance("topup_2", TENANT_A, 50, NOW);
    await expect(store.settleWalletBalance("topup_2", TENANT_A, 500, NOW)).rejects.toMatchObject({
      kind: "conflict",
    });
  });
});

describe("D1WalletStore — atomicity is a precondition, not a hope", () => {
  test("a handle that cannot do atomic batch is refused outright", async () => {
    const restLike: TenantDatabaseHandle = {
      tenantId: TENANT_A,
      db: handleA.db,
      source: "rest",
      supportsAtomicBatch: false,
    };
    const store = new D1WalletStore(restLike);
    await expect(store.reserveWalletCredits("hold_rest", TENANT_A, 10, LATER, NOW)).rejects.toThrow(
      /requires atomic batch\(\)\+RETURNING/,
    );
    // Nothing was written — the refusal happens before any statement runs.
    expect(await new D1WalletStore(handleA).getReservation("hold_rest")).toBeUndefined();
  });

  test("StorageError is the single taxonomy the D1 paths raise", async () => {
    const store = new D1WalletStore(handleA);
    await expect(store.settleWalletReservation("ghost", NOW)).rejects.toBeInstanceOf(StorageError);
  });
});
