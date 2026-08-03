/**
 * The bigint-exact half of `D1WalletStore`, against a REAL D1 database:
 * `ensureWallet`, `balanceCreditsExact`, and `settleWalletBalance`'s two money
 * hazards (a `number`-rounded amount, and a settlement for a tenant that has no
 * wallet row).
 *
 * These are only meaningful against a real database. The claims are that
 * SQLite's INTEGER affinity converts a bound decimal STRING losslessly, that
 * `balance_credits + '<text>'` is exact integer arithmetic, and that
 * `CAST(... AS TEXT)` reads back what was written — a fake would satisfy all
 * three by construction.
 */
import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import { D1WalletStore, type TenantDatabaseHandle } from "../../src/index.js";
import { TENANT_A, resetTenantData, seedWallet, setupTenantRouter, tenantDb } from "./harness.js";

const NOW = 1_700_000_000;

/**
 * `100_000_000_000_001` cents. The exact product is one hundred quadrillion
 * plus ten thousand; the nearest double is sixteen credits short.
 */
const HUGE = 1_000_000_000_000_010_000n;

let handleA: TenantDatabaseHandle;

beforeAll(async () => {
  const router = await setupTenantRouter();
  handleA = await router.forTenant(TENANT_A);
});

beforeEach(async () => {
  await resetTenantData(tenantDb(TENANT_A));
});

/** The column read exactly, without going through the store under test. */
async function rawCredits(tenantId: string): Promise<string | null> {
  const row = await tenantDb(TENANT_A)
    .prepare("SELECT CAST(balance_credits AS TEXT) AS c FROM wallets WHERE tenant_id = ?")
    .bind(tenantId)
    .first<{ c: string }>();
  return row === null ? null : row.c;
}

describe("ensureWallet", () => {
  test("creates the row when the tenant has never adopted prepaid billing", async () => {
    const store = new D1WalletStore(handleA);
    expect(await store.ensureWallet(TENANT_A, NOW)).toBe(true);
    expect(await rawCredits(TENANT_A)).toBe("0");
  });

  test("NEVER moves an existing balance — the difference from upsertWallet", async () => {
    const store = new D1WalletStore(handleA);
    await seedWallet(handleA, 750);

    expect(await store.ensureWallet(TENANT_A, NOW)).toBe(false);
    // The failure this pins: "make sure the wallet exists" zeroing a funded
    // customer. `upsertWallet` would have done exactly that.
    expect(await rawCredits(TENANT_A)).toBe("750");
  });

  test("adopts at an opening balance a double could not carry", async () => {
    const store = new D1WalletStore(handleA);
    expect(await store.ensureWallet(TENANT_A, NOW, HUGE)).toBe(true);
    expect(await rawCredits(TENANT_A)).toBe(HUGE.toString());
  });
});

describe("balanceCreditsExact", () => {
  test("reads a balance past 2^53 without drift", async () => {
    const store = new D1WalletStore(handleA);
    await store.ensureWallet(TENANT_A, NOW, HUGE);

    expect(await store.balanceCreditsExact(TENANT_A)).toBe(HUGE);
    // `getWallet` decodes through D1's default `number` mapping, which is the
    // lossy path this method exists to bypass. Stated as an assertion so the
    // difference cannot silently disappear.
    expect(BigInt((await store.getWallet(TENANT_A))?.balanceCredits ?? 0)).not.toBe(HUGE);
  });

  test("keeps `no wallet` distinct from `zero`", async () => {
    const store = new D1WalletStore(handleA);
    expect(await store.balanceCreditsExact(TENANT_A)).toBeUndefined();
    await store.ensureWallet(TENANT_A, NOW);
    expect(await store.balanceCreditsExact(TENANT_A)).toBe(0n);
  });
});

describe("settleWalletBalance — bigint amounts", () => {
  test("applies an amount a `number` multiply would have rounded", async () => {
    const store = new D1WalletStore(handleA);
    await store.ensureWallet(TENANT_A, NOW);

    await store.settleWalletBalance("topup_huge", TENANT_A, HUGE, NOW);

    expect(await store.balanceCreditsExact(TENANT_A)).toBe(HUGE);
    expect(await rawCredits(TENANT_A)).toBe("1000000000000010000");
  });

  test("accumulates exactly across two settlements", async () => {
    const store = new D1WalletStore(handleA);
    await store.ensureWallet(TENANT_A, NOW);

    await store.settleWalletBalance("a", TENANT_A, HUGE, NOW);
    await store.settleWalletBalance("b", TENANT_A, 10_000n, NOW);

    expect(await store.balanceCreditsExact(TENANT_A)).toBe(HUGE + 10_000n);
  });

  test("a replay of a huge amount is a no-op, not a second apply", async () => {
    const store = new D1WalletStore(handleA);
    await store.ensureWallet(TENANT_A, NOW);

    expect((await store.settleWalletBalance("t", TENANT_A, HUGE, NOW)).newlyApplied).toBe(true);
    expect((await store.settleWalletBalance("t", TENANT_A, HUGE, NOW)).newlyApplied).toBe(false);
    expect(await store.balanceCreditsExact(TENANT_A)).toBe(HUGE);
  });

  test("a replay whose amount differs only past the 53rd bit is a CONFLICT", async () => {
    const store = new D1WalletStore(handleA);
    await store.ensureWallet(TENANT_A, NOW);
    await store.settleWalletBalance("t", TENANT_A, HUGE, NOW);

    // The two amounts are equal as doubles and different as money. Comparing
    // through the lossy decode would wave this through as "the same movement".
    await expect(store.settleWalletBalance("t", TENANT_A, HUGE + 16n, NOW)).rejects.toMatchObject({
      kind: "conflict",
    });
    expect(await store.balanceCreditsExact(TENANT_A)).toBe(HUGE);
  });

  test("still refuses a non-integer `number` amount", async () => {
    const store = new D1WalletStore(handleA);
    await store.ensureWallet(TENANT_A, NOW);
    await expect(store.settleWalletBalance("t", TENANT_A, 1.5, NOW)).rejects.toMatchObject({
      kind: "conflict",
    });
  });
});

describe("settleWalletBalance — a tenant with NO wallet row", () => {
  test("refuses, and does NOT burn the settlement id", async () => {
    const store = new D1WalletStore(handleA);

    await expect(store.settleWalletBalance("topup", TENANT_A, 500n, NOW)).rejects.toMatchObject({
      kind: "not_found",
    });
    // The hazard: an `UPDATE` matching no row while the id is already claimed.
    // The credit would vanish AND the repairing retry would report itself as an
    // already-applied replay. Both halves are asserted.
    expect(await store.getSettlement("topup")).toBeUndefined();

    await store.ensureWallet(TENANT_A, NOW);
    const repaired = await store.settleWalletBalance("topup", TENANT_A, 500n, NOW);
    expect(repaired.newlyApplied).toBe(true);
    expect(await store.balanceCreditsExact(TENANT_A)).toBe(500n);
  });
});
