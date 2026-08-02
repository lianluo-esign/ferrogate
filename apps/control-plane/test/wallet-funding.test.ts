/**
 * The WRITE half of the `wallets` group — the MOUNT GATE for prepaid money.
 *
 * ## What was wrong
 *
 * `POST /admin/v1/wallets/{tenant_id}/adjust` wrote `balance_cents` onto a
 * `control_plane_resources` document in the CONTROL database and answered
 * `200`. The data plane admits a request against `wallets.balance_credits` in
 * the TENANT database (`apps/gateway/src/ratelimit/wallet.ts` → `@ferrogate/
 * storage`'s `D1WalletStore.reserveWalletCredits`; `apps/gateway/src/ratelimit/
 * quota.ts:624` reads the same column). **Two databases, two tables, two
 * units.** So an operator could top a customer up, watch the API answer 200,
 * and the customer was still refused with `wallet_balance_exhausted` on the
 * very next request. That is the money defect these tests exist to close, and
 * every one of them asserts the EFFECT — whether the money can be spent — not
 * the status code the admin API returns.
 *
 * ## Why the admission assertion is `D1WalletStore.reserveWalletCredits`
 *
 * That method IS the gateway's wallet gate: `apps/gateway/src/ratelimit/
 * wallet.ts` constructs `D1WalletStore` on the request's tenant handle and
 * calls it, and `apps/gateway/src/ratelimit/quota.ts` reads
 * `balance_credits` minus the live `wallet_reservations` holds — the exact
 * arithmetic `availableCredits` performs. Calling the shared implementation
 * from `@ferrogate/storage` against the REAL migrated tenant database is
 * therefore the closest a test in THIS workspace can stand to the gateway
 * boundary without importing another app; a re-typed copy of the gateway's SQL
 * would be a fixture and could not fail if the column moved.
 *
 * ## The seeded wallet is deliberately EXHAUSTED, not absent
 *
 * A tenant with NO `wallets` row has not adopted prepaid billing, and the
 * gateway must never deny it (`quota.ts`'s `availableCredits: null` branch). The
 * scenario that hurts is the one where the customer HAS adopted it and has run
 * dry: refused at the gateway, topped up by an operator, still refused. So the
 * fixture is a `balance_credits = 0` row, written with raw SQL rather than
 * through the code under test.
 */
import { SELF } from "cloudflare:test";
import { D1WalletStore, type TenantDatabaseHandle } from "@ferrogate/storage";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey } from "./harness.js";
import {
  TENANT_A,
  TENANT_B,
  applyTenantSchema,
  registerTenantDatabases,
  resetTenantD1,
  tenantDbA,
  tenantDbB,
} from "./tenant-db.js";

const OPERATOR = operatorKey.secret;

/** 1 USD = 100 cents = 1_000_000 credits, so one cent is 10_000 credits. */
const CREDITS_PER_CENT = 10_000n;

function handleFor(tenantId: string, database: D1Database): TenantDatabaseHandle {
  return { tenantId, db: database, source: "native_binding", supportsAtomicBatch: true };
}

function walletStore(tenantId: string, database: D1Database): D1WalletStore {
  return new D1WalletStore(handleFor(tenantId, database));
}

/**
 * Seed a prepaid wallet the customer has already drained, with raw SQL.
 *
 * A fixture built through the code under test cannot show that the code under
 * test moves what is actually in the table.
 */
async function seedExhaustedWallet(
  database: D1Database,
  tenantId: string,
  balanceCredits = "0",
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO wallets (id, tenant_id, balance_credits, dunning, created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, 0, 1, 1)`,
    )
    // Bound as TEXT because D1 refuses a JS bigint outright
    // (`D1_TYPE_ERROR: Type 'bigint' not supported`) and a JS number cannot
    // carry the large balances these tests use. SQLite's INTEGER affinity
    // converts the decimal string exactly.
    .bind(tenantId, tenantId, balanceCredits)
    .run();
}

/** `wallets.balance_credits` read EXACTLY — as text, so no double is involved. */
async function balanceCreditsExact(database: D1Database, tenantId: string): Promise<bigint | null> {
  const row = await database
    .prepare("SELECT CAST(balance_credits AS TEXT) AS credits FROM wallets WHERE tenant_id = ?")
    .bind(tenantId)
    .first<{ credits: string }>();
  return row === null ? null : BigInt(row.credits);
}

/** `POST /admin/v1/wallets` — the admin document the movement routes require. */
async function createWalletDocument(tenantId: string, balanceCents = 0): Promise<Response> {
  return await SELF.fetch(
    `${BASE}/admin/v1/wallets`,
    jsonRequest(OPERATOR, "POST", { tenant_id: tenantId, balance_cents: balanceCents }),
  );
}

async function adjust(tenantId: string, body: Record<string, unknown>): Promise<Response> {
  return await SELF.fetch(
    `${BASE}/admin/v1/wallets/${tenantId}/adjust`,
    jsonRequest(OPERATOR, "POST", body),
  );
}

async function charge(tenantId: string, body: Record<string, unknown>): Promise<Response> {
  return await SELF.fetch(
    `${BASE}/admin/v1/wallets/${tenantId}/charge`,
    jsonRequest(OPERATOR, "POST", body),
  );
}

/**
 * The gateway's admission decision, run through the SHARED implementation the
 * gateway itself calls. `kind` is the whole assertion: `reserved` is admitted,
 * `insufficient` is the `wallet_balance_exhausted` refusal.
 */
async function gatewayAdmits(
  tenantId: string,
  database: D1Database,
  holdId: string,
  holdCredits = 1,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const result = await walletStore(tenantId, database).reserveWalletCredits(
    holdId,
    tenantId,
    holdCredits,
    now + 60,
    now,
  );
  return result.kind;
}

/** The ledger entries the admin surface reports, oldest first. */
async function ledgerEntries(tenantId: string): Promise<Record<string, unknown>[]> {
  const res = await SELF.fetch(`${BASE}/admin/v1/wallets/${tenantId}/ledger`, {
    headers: bearer(OPERATOR),
  });
  expect(res.status).toBe(200);
  return ((await res.json()) as { data: Record<string, unknown>[] }).data;
}

beforeAll(async () => {
  await applySchema();
  await applyTenantSchema();
});

beforeEach(async () => {
  arm({ store: "d1", staticKeys: [operatorKey], rbac: { [TENANT_A]: ["*"], [TENANT_B]: ["*"] } });
  await resetD1();
  await resetTenantD1();
  await registerTenantDatabases();
});

describe("MOUNT: crediting a wallet funds a request", () => {
  it("a drained customer is refused, credited through the admin API, then ADMITTED", async () => {
    await seedExhaustedWallet(tenantDbA(), TENANT_A);
    expect((await createWalletDocument(TENANT_A)).status).toBe(201);

    // BEFORE — the customer is exactly where the support ticket starts.
    expect(await gatewayAdmits(TENANT_A, tenantDbA(), "hold-before")).toBe("insufficient");

    // The operator tops them up by $5.00.
    const credited = await adjust(TENANT_A, { amount_cents: 500, reason: "top-up" });
    expect(credited.status).toBe(200);

    // AFTER — the SAME decision, now admitted. Before the write half existed
    // this stayed "insufficient": the 200 above moved a document nothing reads.
    expect(await gatewayAdmits(TENANT_A, tenantDbA(), "hold-after")).toBe("reserved");
    expect(await balanceCreditsExact(tenantDbA(), TENANT_A)).toBe(500n * CREDITS_PER_CENT);
  });

  it("the credit lands in the CREDITED tenant's database and nowhere else", async () => {
    await seedExhaustedWallet(tenantDbA(), TENANT_A);
    await seedExhaustedWallet(tenantDbB(), TENANT_B);
    expect((await createWalletDocument(TENANT_A)).status).toBe(201);
    expect((await createWalletDocument(TENANT_B)).status).toBe(201);

    expect((await adjust(TENANT_A, { amount_cents: 500, reason: "top-up" })).status).toBe(200);

    expect(await balanceCreditsExact(tenantDbA(), TENANT_A)).toBe(5_000_000n);
    // The control. Without it, a router that handed everybody the same handle
    // would pass the test above.
    expect(await balanceCreditsExact(tenantDbB(), TENANT_B)).toBe(0n);
    expect(await gatewayAdmits(TENANT_B, tenantDbB(), "hold-b")).toBe("insufficient");
  });

  it("charging a wallet DEBITS the balance the gateway spends against", async () => {
    await seedExhaustedWallet(tenantDbA(), TENANT_A, String(1000n * CREDITS_PER_CENT));
    expect((await createWalletDocument(TENANT_A, 1000)).status).toBe(201);

    expect((await charge(TENANT_A, { amount_cents: 400, reason: "manual" })).status).toBe(200);

    expect(await balanceCreditsExact(tenantDbA(), TENANT_A)).toBe(600n * CREDITS_PER_CENT);
  });

  it("a charge is refused against the money that actually exists, not the document", async () => {
    // The document claims $10; the tenant database — which is what the data
    // plane spends — is empty, because the gateway already spent it. A charge
    // decided on the document would drive real money negative.
    await seedExhaustedWallet(tenantDbA(), TENANT_A, "0");
    expect((await createWalletDocument(TENANT_A, 1000)).status).toBe(201);

    expect((await charge(TENANT_A, { amount_cents: 400, reason: "manual" })).status).toBe(409);
    expect(await balanceCreditsExact(tenantDbA(), TENANT_A)).toBe(0n);
  });
});

describe("MONEY: a double-submitted credit applies exactly once", () => {
  it("the same `reference` credits the tenant balance once, not twice", async () => {
    await seedExhaustedWallet(tenantDbA(), TENANT_A);
    expect((await createWalletDocument(TENANT_A)).status).toBe(201);

    const body = { amount_cents: 500, reason: "top-up", reference: "stripe_pi_123" };
    const first = await adjust(TENANT_A, body);
    const second = await adjust(TENANT_A, body);

    expect(first.status).toBe(200);
    // A replay is not an error — the operator's retry after a timeout must be
    // safe — but it must move nothing.
    expect(second.status).toBe(200);
    expect(await balanceCreditsExact(tenantDbA(), TENANT_A)).toBe(500n * CREDITS_PER_CENT);
    expect((await ledgerEntries(TENANT_A)).length).toBe(1);
  });

  it("reusing a `reference` for a DIFFERENT amount is a conflict, not a silent apply", async () => {
    await seedExhaustedWallet(tenantDbA(), TENANT_A);
    expect((await createWalletDocument(TENANT_A)).status).toBe(201);

    expect(
      (await adjust(TENANT_A, { amount_cents: 500, reason: "a", reference: "ref-1" })).status,
    ).toBe(200);
    expect(
      (await adjust(TENANT_A, { amount_cents: 900, reason: "b", reference: "ref-1" })).status,
    ).toBe(409);

    expect(await balanceCreditsExact(tenantDbA(), TENANT_A)).toBe(500n * CREDITS_PER_CENT);
  });

  it("two credits WITHOUT a reference are two distinct movements", async () => {
    // The control for the idempotency tests above: without an idempotency key
    // two identical POSTs are two separate operator actions, and collapsing
    // them would silently swallow a real second credit.
    await seedExhaustedWallet(tenantDbA(), TENANT_A);
    expect((await createWalletDocument(TENANT_A)).status).toBe(201);

    expect((await adjust(TENANT_A, { amount_cents: 500, reason: "top-up" })).status).toBe(200);
    expect((await adjust(TENANT_A, { amount_cents: 500, reason: "top-up" })).status).toBe(200);

    expect(await balanceCreditsExact(tenantDbA(), TENANT_A)).toBe(1000n * CREDITS_PER_CENT);
    expect((await ledgerEntries(TENANT_A)).length).toBe(2);
  });
});

describe("UNITS: cents → credits is exact, with no double in the path", () => {
  /**
   * `100_000_000_000_001 * 10_000` is 1_000_000_000_000_010_000 exactly, but
   * the nearest double is 1_000_000_000_000_009_984 — 16 credits adrift.
   * (`Number.prototype.toString` prints the SHORTEST decimal that round-trips,
   * so the wrong value even *prints* as the right one; only an exact reader
   * catches it, which is why the balance is read back as TEXT.)
   */
  const CENTS = 100_000_000_000_001;
  const EXACT_CREDITS = 1_000_000_000_000_010_000n;

  it("credits a value a float multiply would round", async () => {
    await seedExhaustedWallet(tenantDbA(), TENANT_A);
    expect((await createWalletDocument(TENANT_A)).status).toBe(201);

    expect((await adjust(TENANT_A, { amount_cents: CENTS, reason: "exactness" })).status).toBe(200);

    const stored = await balanceCreditsExact(tenantDbA(), TENANT_A);
    expect(stored).toBe(EXACT_CREDITS);
    // The failure this pins: the drifted product a `number` multiply produces.
    expect(stored).not.toBe(BigInt(CENTS * 10_000));
  });

  it("accumulates exactly across two movements", async () => {
    await seedExhaustedWallet(tenantDbA(), TENANT_A);
    expect((await createWalletDocument(TENANT_A)).status).toBe(201);

    expect((await adjust(TENANT_A, { amount_cents: CENTS, reason: "one" })).status).toBe(200);
    expect((await adjust(TENANT_A, { amount_cents: 1, reason: "two" })).status).toBe(200);

    expect(await balanceCreditsExact(tenantDbA(), TENANT_A)).toBe(EXACT_CREDITS + CREDITS_PER_CENT);
  });
});

describe("the document-only deployment is unchanged", () => {
  it("a tenant with no provisioned database still adjusts its document", async () => {
    // `registerTenantDatabases` never registers this tenant, so
    // `tenantDatabaseFor` answers null and the surface keeps exactly the
    // behaviour it had before the projection existed.
    const tenant = "tenant_without_a_database";
    expect((await createWalletDocument(tenant, 1000)).status).toBe(201);

    const adjusted = await adjust(tenant, { amount_cents: 500, reason: "top-up" });
    expect(adjusted.status).toBe(200);
    expect((await adjusted.json()) as { wallet: { balance_cents: number } }).toMatchObject({
      wallet: { balance_cents: 1500 },
    });
    // Nothing was written into anyone else's database.
    expect(await balanceCreditsExact(tenantDbA(), tenant)).toBe(null);
  });
});

describe("the CONTROL document mirrors the money that exists", () => {
  it("`balance_cents` after a movement is the tenant balance, not the document's own running total", async () => {
    // The document says $10 and the tenant database says $2 — the four dollars
    // the gateway spent. The next movement must re-base on the truth, or the
    // admin surface reports money that cannot be spent forever after.
    await seedExhaustedWallet(tenantDbA(), TENANT_A, String(200n * CREDITS_PER_CENT));
    expect((await createWalletDocument(TENANT_A, 1000)).status).toBe(201);

    const credited = await adjust(TENANT_A, { amount_cents: 300, reason: "top-up" });
    expect(credited.status).toBe(200);
    expect((await credited.json()) as { wallet: { balance_cents: number } }).toMatchObject({
      wallet: { balance_cents: 500 },
    });
    expect(await balanceCreditsExact(tenantDbA(), TENANT_A)).toBe(500n * CREDITS_PER_CENT);
  });

  it("a raw `db.batch` failure cannot leave the ledger entry without the money", async () => {
    // The ordering rule, observed rather than asserted about: a CREDIT writes
    // the control ledger claim FIRST and the tenant money SECOND, so the only
    // crash residue is an unfunded claim that a retry with the same reference
    // repairs. Here the first attempt is completed normally and then the
    // TENANT half alone is rolled back by hand, simulating exactly that crash.
    await seedExhaustedWallet(tenantDbA(), TENANT_A);
    expect((await createWalletDocument(TENANT_A)).status).toBe(201);

    const body = { amount_cents: 500, reason: "top-up", reference: "ref-crash" };
    expect((await adjust(TENANT_A, body)).status).toBe(200);
    // Undo the tenant leg — the state a crash between the two legs leaves.
    await tenantDbA().batch([
      tenantDbA().prepare("DELETE FROM wallet_settlements"),
      tenantDbA()
        .prepare("UPDATE wallets SET balance_credits = 0 WHERE tenant_id = ?")
        .bind(TENANT_A),
    ]);
    expect(await gatewayAdmits(TENANT_A, tenantDbA(), "hold-mid")).toBe("insufficient");

    // The operator retries the same movement. A replay that only 409'd would
    // leave the customer permanently unfunded with a ledger entry saying
    // otherwise; the replay must drive the outstanding leg forward.
    expect((await adjust(TENANT_A, body)).status).toBe(200);
    expect(await balanceCreditsExact(tenantDbA(), TENANT_A)).toBe(500n * CREDITS_PER_CENT);
    expect((await ledgerEntries(TENANT_A)).length).toBe(1);
  });
});

describe("payment methods reach the tenant database too", () => {
  it("a created payment method is a row in the tenant's own database", async () => {
    const created = await SELF.fetch(
      `${BASE}/admin/v1/payment-methods`,
      jsonRequest(OPERATOR, "POST", {
        id: "pm-1",
        tenant_id: TENANT_A,
        provider: "stripe",
        provider_customer_id: "cus_1",
        provider_payment_method_id: "pm_stripe_1",
        is_default: true,
      }),
    );
    expect(created.status).toBe(201);

    const row = await tenantDbA()
      .prepare("SELECT id, provider, provider_payment_method_id FROM payment_methods WHERE id = ?")
      .bind("pm-1")
      .first<Record<string, unknown>>();
    expect(row).toMatchObject({ id: "pm-1", provider: "stripe" });
  });

  it("deleting a payment method removes the tenant row", async () => {
    await SELF.fetch(
      `${BASE}/admin/v1/payment-methods`,
      jsonRequest(OPERATOR, "POST", {
        id: "pm-1",
        tenant_id: TENANT_A,
        provider: "stripe",
        provider_customer_id: "cus_1",
        provider_payment_method_id: "pm_stripe_1",
      }),
    );
    // The row has to be there before the delete can mean anything — otherwise
    // "gone afterwards" is true of a projection that never ran.
    expect(
      await tenantDbA().prepare("SELECT id FROM payment_methods WHERE id = 'pm-1'").first(),
    ).not.toBe(null);

    const deleted = await SELF.fetch(`${BASE}/admin/v1/payment-methods/pm-1`, {
      method: "DELETE",
      headers: bearer(OPERATOR),
    });
    expect(deleted.status).toBe(200);

    const row = await tenantDbA()
      .prepare("SELECT id FROM payment_methods WHERE id = ?")
      .bind("pm-1")
      .first<Record<string, unknown>>();
    expect(row).toBe(null);
  });
});

describe("the audit trail survives", () => {
  it("a projected movement still writes its control-database ledger entry", async () => {
    await seedExhaustedWallet(tenantDbA(), TENANT_A);
    expect((await createWalletDocument(TENANT_A)).status).toBe(201);
    expect((await adjust(TENANT_A, { amount_cents: 500, reason: "top-up" })).status).toBe(200);

    const entries = await ledgerEntries(TENANT_A);
    expect(entries.length).toBe(1);
    expect(entries[0]).toMatchObject({ kind: "adjustment", amount_cents: 500, reason: "top-up" });
    // And the control database really has it, not just the response envelope.
    const row = await db()
      .prepare(
        "SELECT COUNT(*) AS n FROM control_plane_resources WHERE resource_kind = 'wallet-ledger'",
      )
      .first<{ n: number }>();
    expect(row?.n).toBe(1);
  });
});
