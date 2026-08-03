/**
 * #790 — a tenant may READ its wallet and may not MOVE its balance.
 *
 * `authorizeWalletTenant` was one fence for `GET /admin/v1/wallets/{tenant_id}`,
 * for the ledger read, and for `POST .../adjust` and `POST .../charge`. It asks
 * "is this wallet MINE?", which is the right question for a read and, on a
 * money movement, is the escalation itself — and `walletAdjustSchema`'s
 * `amount_cents` is SIGNED and is handed to the movement as the delta, so a
 * tenant-scoped `admin.write` key could credit itself:
 *
 * ```
 *   POST /admin/v1/wallets/t1/adjust   Bearer <t1 admin.write key>
 *   {"amount_cents": 10000000, "reason": "self-credit"}   ->  200
 *   balance_cents 500 -> 10000500,  balance_credits "100005000000"
 * ```
 *
 * That is not a document number: the movement runs the full ledgered path and
 * projects `wallets.balance_credits` in the TENANT database, which is what
 * `apps/gateway`'s admission spends.
 *
 * The cases below pin BOTH halves of the split, because a fence is only as good
 * as the read it leaves alone, and every refusal asserts that **neither the
 * balance NOR the ledger moved** — a refusal that still wrote would be worse
 * than the allow, because the operator reads a 403 and the money moved anyway.
 */
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";

const OPERATOR = operatorKey.secret;
const TENANT_KEY = "k-t1";
const OPENING_CENTS = 500;

beforeEach(async () => {
  arm({ staticKeys: [operatorKey], nativeKeys: [tenantKey(TENANT_KEY, "t1")] });
  const created = await SELF.fetch(
    `${BASE}/admin/v1/wallets`,
    jsonRequest(OPERATOR, "POST", {
      tenant_id: "t1",
      balance_cents: OPENING_CENTS,
      currency: "USD",
    }),
  );
  expect(created.status).toBe(201);
});

/** The balance right now, read with the OPERATOR credential. */
async function balanceAsOperator(tenantId = "t1"): Promise<number> {
  const response = await SELF.fetch(`${BASE}/admin/v1/wallets/${tenantId}`, {
    headers: bearer(OPERATOR),
  });
  expect(response.status).toBe(200);
  const body = (await response.json()) as { wallet: { balance_cents: number } };
  return body.wallet.balance_cents;
}

/**
 * Every ledger entry for the wallet, read with the OPERATOR credential.
 *
 * The balance alone is not enough to hold the refusal: the two legs are written
 * as one unit, but a fence placed in the wrong half of the handler could refuse
 * after the entry was claimed, leaving the operator an unexplained row.
 */
async function ledgerAsOperator(tenantId = "t1"): Promise<{ kind: string; amount_cents: number }[]> {
  const response = await SELF.fetch(`${BASE}/admin/v1/wallets/${tenantId}/ledger`, {
    headers: bearer(OPERATOR),
  });
  expect(response.status).toBe(200);
  const body = (await response.json()) as { data: { kind: string; amount_cents: number }[] };
  return body.data;
}

/** Nothing happened: the balance is the operator's opening one and the ledger is empty. */
async function expectUnmoved(tenantId = "t1"): Promise<void> {
  expect(await balanceAsOperator(tenantId)).toBe(OPENING_CENTS);
  expect(await ledgerAsOperator(tenantId)).toEqual([]);
}

describe("#790: a tenant may read its wallet but may not move its balance", () => {
  it("still lets the tenant READ its own balance", async () => {
    // Fencing this would "fix" the escalation by breaking the product: a
    // customer that cannot see its prepaid balance cannot tell an exhausted
    // wallet from an outage.
    const response = await SELF.fetch(`${BASE}/admin/v1/wallets/t1`, {
      headers: bearer(TENANT_KEY),
    });
    expect(response.status).toBe(200);
    expect((await response.json()) as { wallet: { balance_cents: number } }).toMatchObject({
      wallet: { balance_cents: OPENING_CENTS, currency: "USD" },
    });
  });

  it("still lets the tenant READ its own ledger", async () => {
    // Same reason: the ledger is how a customer reconciles what it was charged.
    const response = await SELF.fetch(`${BASE}/admin/v1/wallets/t1/ledger`, {
      headers: bearer(TENANT_KEY),
    });
    expect(response.status).toBe(200);
  });

  it("refuses the tenant crediting its own wallet, and nothing moves", async () => {
    // THE DEFECT, exactly as reported.
    const response = await SELF.fetch(
      `${BASE}/admin/v1/wallets/t1/adjust`,
      jsonRequest(TENANT_KEY, "POST", { amount_cents: 10_000_000, reason: "self-credit" }),
    );
    expect(response.status).toBe(403);
    expect((await response.json()) as { error: { code: string } }).toMatchObject({
      error: { code: "wallet_movement_operator_only" },
    });
    await expectUnmoved();
  });

  it("refuses a NEGATIVE self-adjustment too, and says why in the refusal", async () => {
    // The judgement call, argued in `authorizeWalletMovement`: a debit is not an
    // escalation of the balance, but `adjust` is the OPERATOR's verb — its
    // ledger rows say "an operator moved this money for this reason" — and the
    // caller-chosen `reference` makes any tenant-writable movement a claim on
    // the operator's idempotency namespace (see the reference case below).
    const response = await SELF.fetch(
      `${BASE}/admin/v1/wallets/t1/adjust`,
      jsonRequest(TENANT_KEY, "POST", { amount_cents: -100, reason: "write-down" }),
    );
    expect(response.status).toBe(403);
    const body = (await response.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("wallet_movement_operator_only");
    expect(body.error.message).toContain("may read its own wallet");
    await expectUnmoved();
  });

  it("refuses the tenant charging its own wallet, and nothing moves", async () => {
    const response = await SELF.fetch(
      `${BASE}/admin/v1/wallets/t1/charge`,
      jsonRequest(TENANT_KEY, "POST", { amount_cents: 100, reason: "self-charge" }),
    );
    expect(response.status).toBe(403);
    expect((await response.json()) as { error: { code: string } }).toMatchObject({
      error: { code: "wallet_movement_operator_only" },
    });
    await expectUnmoved();
  });

  it("refuses BEFORE the wallet is resolved — the write leg is not an existence oracle", async () => {
    // t9's wallet does not exist. A fence placed after the lookup would answer
    // 404 here and 403 elsewhere, which is a probe for which tenants have
    // adopted prepaid billing. One refusal, one code, no probe.
    arm({ staticKeys: [operatorKey], nativeKeys: [tenantKey("k-t9", "t9")] });
    const response = await SELF.fetch(
      `${BASE}/admin/v1/wallets/t9/adjust`,
      jsonRequest("k-t9", "POST", { amount_cents: 1, reason: "probe" }),
    );
    expect(response.status).toBe(403);
    expect((await response.json()) as { error: { code: string } }).toMatchObject({
      error: { code: "wallet_movement_operator_only" },
    });
  });

  it("refuses BEFORE the body is parsed — an invalid body still answers 403", async () => {
    // A caller this verb will never admit is not told which fields its request
    // was missing. `reason` is mandatory, so this body is a 400 for an operator.
    const response = await SELF.fetch(
      `${BASE}/admin/v1/wallets/t1/adjust`,
      jsonRequest(TENANT_KEY, "POST", { amount_cents: 5 }),
    );
    expect(response.status).toBe(403);
    await expectUnmoved();
  });

  it("leaves no claim on the operator's idempotency namespace", async () => {
    // The door the issue asked about. The ledger entry id is DERIVED from the
    // caller-chosen `reference` (`walletLedgerEntryId`), and the replay check
    // compares only the AMOUNT — not the kind, not who wrote it. So a tenant
    // that may write any movement can squat a reference the operator is about
    // to use: at a different amount the operator's real movement is refused 409
    // forever, and at the same amount it is mistaken for a replay and skips the
    // control leg entirely. The refusal has to leave that namespace clean.
    const squat = await SELF.fetch(
      `${BASE}/admin/v1/wallets/t1/adjust`,
      jsonRequest(TENANT_KEY, "POST", {
        amount_cents: -1,
        reason: "squat",
        reference: "promo-2026-08",
      }),
    );
    expect(squat.status).toBe(403);

    const operatorCredit = await SELF.fetch(
      `${BASE}/admin/v1/wallets/t1/adjust`,
      jsonRequest(OPERATOR, "POST", {
        amount_cents: 5_000,
        reason: "promotional credit",
        reference: "promo-2026-08",
      }),
    );
    expect(operatorCredit.status).toBe(200);
    expect(await balanceAsOperator()).toBe(OPENING_CENTS + 5_000);
    expect(await ledgerAsOperator()).toMatchObject([{ kind: "adjustment", amount_cents: 5_000 }]);
  });

  it("still refuses a tenant naming ANOTHER tenant's wallet", async () => {
    // The pre-existing #185 fence, which the new one must not replace: a
    // cross-tenant caller keeps answering `tenant_scope_denied` on the READ.
    const response = await SELF.fetch(`${BASE}/admin/v1/wallets/t2`, {
      headers: bearer(TENANT_KEY),
    });
    expect(response.status).toBe(403);
    expect((await response.json()) as { error: { code: string } }).toMatchObject({
      error: { code: "tenant_scope_denied" },
    });
  });

  it("leaves the operator's own adjust and charge working", async () => {
    // The fence must not be "nobody moves money", which would pass every case
    // above while breaking the surface this group exists for.
    const credited = await SELF.fetch(
      `${BASE}/admin/v1/wallets/t1/adjust`,
      jsonRequest(OPERATOR, "POST", { amount_cents: 1_000, reason: "top-up" }),
    );
    expect(credited.status).toBe(200);
    expect(await balanceAsOperator()).toBe(1_500);

    const charged = await SELF.fetch(
      `${BASE}/admin/v1/wallets/t1/charge`,
      jsonRequest(OPERATOR, "POST", { amount_cents: 200 }),
    );
    expect(charged.status).toBe(200);
    expect(await balanceAsOperator()).toBe(1_300);
    expect(await ledgerAsOperator()).toMatchObject([
      { kind: "adjustment", amount_cents: 1_000 },
      { kind: "charge", amount_cents: -200 },
    ]);
  });
});
