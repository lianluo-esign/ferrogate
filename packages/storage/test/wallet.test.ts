import { beforeEach, describe, expect, test } from "vitest";
import { MemoryWalletStore, StorageError, type StoredWallet } from "../src/index.js";

function wallet(tenantId: string, balance: number): StoredWallet {
  return {
    id: tenantId,
    tenantId,
    balanceCredits: balance,
    dunning: false,
    createdAtUnix: 0,
    updatedAtUnix: 0,
  };
}

describe("MemoryWalletStore — no-oversell reserve (§1.5.1)", () => {
  let store: MemoryWalletStore;
  beforeEach(() => {
    store = new MemoryWalletStore();
  });

  test("N reserves against a balance affording N-1 admit exactly N-1", () => {
    store.upsertWallet(wallet("t1", 40)); // affords 4 holds of 10 = balance 40 → 4 admits
    let admitted = 0;
    for (let i = 0; i < 5; i++) {
      const r = store.reserveWalletCredits(`hold-${i}`, "t1", 10, 1000, 0);
      if (r.kind === "reserved") admitted++;
      else expect(r.kind).toBe("insufficient");
    }
    expect(admitted).toBe(4);
  });

  test("insufficient reports available net of live holds", () => {
    store.upsertWallet(wallet("t1", 15));
    expect(store.reserveWalletCredits("a", "t1", 10, 1000, 0).kind).toBe("reserved");
    const r = store.reserveWalletCredits("b", "t1", 10, 1000, 0);
    expect(r).toEqual({ kind: "insufficient", availableCredits: 5, requestedCredits: 10 });
  });

  test("an expired hold no longer counts against available", () => {
    store.upsertWallet(wallet("t1", 10));
    store.reserveWalletCredits("a", "t1", 10, 100, 0); // expires at 100
    // At now=200 the first hold is expired → the full balance is available again.
    expect(store.reserveWalletCredits("b", "t1", 10, 500, 200).kind).toBe("reserved");
  });

  test("re-reserving the same id is an idempotent no-op", () => {
    store.upsertWallet(wallet("t1", 100));
    const first = store.reserveWalletCredits("h", "t1", 10, 1000, 0);
    const again = store.reserveWalletCredits("h", "t1", 10, 1000, 0);
    expect(again).toEqual(first);
  });

  test("replay with a changed amount is a conflict", () => {
    store.upsertWallet(wallet("t1", 100));
    store.reserveWalletCredits("h", "t1", 10, 1000, 0);
    expect(() => store.reserveWalletCredits("h", "t1", 20, 1000, 0)).toThrowError(StorageError);
  });

  test("a tenant with no wallet is no_wallet (opt-in)", () => {
    expect(store.reserveWalletCredits("h", "t1", 10, 1000, 0).kind).toBe("no_wallet");
  });

  test("a non-positive amount is a conflict", () => {
    store.upsertWallet(wallet("t1", 100));
    expect(() => store.reserveWalletCredits("h", "t1", 0, 1000, 0)).toThrowError(StorageError);
  });
});

describe("MemoryWalletStore — settle / release / sweep (§1.5.2)", () => {
  let store: MemoryWalletStore;
  beforeEach(() => {
    store = new MemoryWalletStore();
    store.upsertWallet(wallet("t1", 100));
  });

  test("settle debits the balance and is idempotent on replay", () => {
    store.reserveWalletCredits("h", "t1", 30, 1000, 0);
    const first = store.settleWalletReservation("h", 10);
    expect(first.newlyApplied).toBe(true);
    expect(first.settlement.deltaCredits).toBe(-30);
    expect(store.getWallet("t1")?.balanceCredits).toBe(70);
    const replay = store.settleWalletReservation("h", 20);
    expect(replay.newlyApplied).toBe(false);
    expect(store.getWallet("t1")?.balanceCredits).toBe(70); // not debited twice
  });

  test("settling an expired hold releases it and refuses", () => {
    store.reserveWalletCredits("h", "t1", 30, 100, 0);
    expect(() => store.settleWalletReservation("h", 200)).toThrowError(StorageError);
    expect(store.listWalletReservations("t1")[0]?.status).toBe("released");
  });

  test("release cancels an active hold; a settled hold cannot be released", () => {
    store.reserveWalletCredits("h", "t1", 30, 1000, 0);
    expect(store.releaseWalletReservation("h", 5).status).toBe("released");
    store.reserveWalletCredits("s", "t1", 10, 1000, 0);
    store.settleWalletReservation("s", 5);
    expect(() => store.releaseWalletReservation("s", 6)).toThrowError(StorageError);
  });

  test("sweep releases expired unowned holds but never a payment-owned one", () => {
    store.reserveWalletCredits("orphan", "t1", 10, 100, 0);
    store.reserveWalletCredits("owned", "t1", 10, 100, 0);
    store.protectHoldId("owned");
    expect(store.sweepExpiredWalletReservations(200)).toEqual(["orphan"]);
  });
});
