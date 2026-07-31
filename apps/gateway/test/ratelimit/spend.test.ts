/**
 * Admission steps 2 and 3 — `monthly_budget_exceeded` and
 * `wallet_balance_exhausted` — against REAL D1 in `workerd`.
 *
 * Rust runs five gates in `auth::finalize_auth`, in this order:
 *
 *   1. `denied_by`          → 403 `quota_scope_disabled`
 *   2. `monthly_budget_usd` → 429 `monthly_budget_exceeded`
 *   3. wallet balance       → 429 `wallet_balance_exhausted`
 *   4. RPM                  → 429 `rate_limit_exceeded`
 *   5. TPM (in the handler) → 429 `tpm_limit_exceeded`
 *
 * 2 and 3 were the last two unported ones. Nothing here is mocked: `env.DB` is
 * miniflare's real SQLite tenant database with the DEPLOYED migration applied
 * (`test/setup-d1.ts`), and the rows seeded below are read back by the same
 * `d1SpendSource` the deployed Worker builds from `env.DB`.
 *
 * ## The end-to-end half is the point
 *
 * `describe("the deployed app")` drives `SELF` — i.e. `src/worker.ts` →
 * `createGatewayApp({ middleware: GATEWAY_MIDDLEWARE })` → `rateLimit()` with
 * NO arguments, so the spend source is whatever `spendSourceFromEnv(c.env)`
 * builds for the real binding. Those tests fail if the two checks are removed
 * from `rateLimit`, if `spendSourceFromEnv` stops finding `env.DB`, or if
 * `rateLimit()` is ever dropped from `GATEWAY_MIDDLEWARE` — the "implemented,
 * tested, never mounted" failure mode this repo has shipped twice.
 */
import { SELF, env } from "cloudflare:test";
import { QuotaScopeSelector } from "@ferrogate/policy";
import { periodMonthFromUnix, usageMonthlyRollupId } from "@ferrogate/storage";
import { beforeEach, describe, expect, test } from "vitest";
import {
  NO_SPEND_SOURCE,
  currentPeriodMonth,
  d1SpendSource,
  monthlyBudgetScope,
  spendSourceFromEnv,
} from "../../src/ratelimit/index.js";

const db = (env as unknown as { DB: D1Database }).DB;
const controlDb = (env as unknown as { CONTROL_DB: D1Database }).CONTROL_DB;

const NOW = 1_800_000_000;
/** The month `currentPeriodMonth(NOW)` keys on — `2027-01`. */
const MONTH = periodMonthFromUnix(NOW);

/** `GET /v1/models` is the cheapest authenticated contract operation. */
const MODELS = "https://gateway.test/v1/models";
/** tenant_a, api key id `key_unscoped`, empty scope set ⇒ data-plane access. */
const TENANT_A_KEY = "fg_tenant_unscoped";

async function seedRollup(
  scopeType: string,
  scopeId: string,
  costUsd: number,
  periodMonth: string = MONTH,
): Promise<void> {
  await db
    .prepare(
      "INSERT OR REPLACE INTO usage_monthly_rollups " +
        "(id, period_month, scope_type, scope_id, cost_usd, updated_at_unix) " +
        "VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(
      usageMonthlyRollupId(periodMonth, scopeType as "tenant", scopeId),
      periodMonth,
      scopeType,
      scopeId,
      costUsd,
      NOW,
    )
    .run();
}

async function seedWallet(tenantId: string, balanceCredits: number): Promise<void> {
  await db
    .prepare(
      "INSERT OR REPLACE INTO wallets " +
        "(id, tenant_id, balance_credits, created_at_unix, updated_at_unix) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(tenantId, tenantId, balanceCredits, NOW, NOW)
    .run();
}

async function seedHold(
  id: string,
  tenantId: string,
  amountCredits: number,
  status: string,
  expiresAtUnix: number,
): Promise<void> {
  await db
    .prepare(
      "INSERT OR REPLACE INTO wallet_reservations " +
        "(id, tenant_id, amount_credits, status, expires_at_unix, created_at_unix, updated_at_unix) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id, tenantId, amountCredits, status, expiresAtUnix, NOW, NOW)
    .run();
}

/** A `quota_policies` row in the CONTROL database, which is where they live. */
async function seedPolicy(
  scopeType: string,
  scopeId: string,
  monthlyBudgetUsd: number | null,
): Promise<void> {
  await controlDb
    .prepare(
      "INSERT OR REPLACE INTO quota_policies " +
        "(id, scope_type, scope_id, monthly_budget_usd, enabled) VALUES (?, ?, ?, ?, 1)",
    )
    .bind(`${scopeType}:${scopeId}`, scopeType, scopeId, monthlyBudgetUsd)
    .run();
}

async function get(key: string): Promise<Response> {
  return await SELF.fetch(MODELS, { headers: { Authorization: `Bearer ${key}` } });
}

interface ErrorEnvelope {
  readonly error: { readonly code: string; readonly message: string; readonly type: string };
}

beforeEach(async () => {
  await db.prepare("DELETE FROM usage_monthly_rollups").run();
  await db.prepare("DELETE FROM wallets").run();
  await db.prepare("DELETE FROM wallet_reservations").run();
  await controlDb.prepare("DELETE FROM quota_policies").run();
});

// ---------------------------------------------------------------------------
// The source
// ---------------------------------------------------------------------------

describe("d1SpendSource — monthly spend", () => {
  test("an absent rollup row is 0 spent, not a failure", async () => {
    const reading = await d1SpendSource(db).committedSpendUsd("tenant", "tenant_nobody", MONTH);
    expect(reading).toEqual({ ok: true, committedSpendUsd: 0 });
  });

  test("reads `cost_usd` for the exact (month, scope) tuple", async () => {
    await seedRollup("tenant", "tenant_a", 12.5);
    const reading = await d1SpendSource(db).committedSpendUsd("tenant", "tenant_a", MONTH);
    expect(reading).toEqual({ ok: true, committedSpendUsd: 12.5 });
  });

  test("a DIFFERENT scope kind with the same id does not share the row", async () => {
    // `usage_monthly_rollups` is UNIQUE on (period_month, scope_type, scope_id):
    // a key-scope budget must never be satisfied by tenant-scope spend.
    await seedRollup("tenant", "shared_id", 99);
    const reading = await d1SpendSource(db).committedSpendUsd("key", "shared_id", MONTH);
    expect(reading).toEqual({ ok: true, committedSpendUsd: 0 });
  });

  test("spend from ANOTHER month is not counted", async () => {
    await seedRollup("tenant", "tenant_a", 99, "1999-01");
    const reading = await d1SpendSource(db).committedSpendUsd("tenant", "tenant_a", MONTH);
    expect(reading).toEqual({ ok: true, committedSpendUsd: 0 });
  });

  test("a query failure is `ok: false`, never 0 spent", async () => {
    // A source that swallowed an outage into `0` would hand every over-budget
    // tenant unlimited spend for its duration.
    const broken = {
      prepare(): never {
        throw new Error("D1_ERROR: no such table: usage_monthly_rollups");
      },
    } as unknown as D1Database;
    const reading = await d1SpendSource(broken).committedSpendUsd("tenant", "t", MONTH);
    expect(reading.ok).toBe(false);
    expect(reading.ok === false && reading.detail).toContain("no such table");
  });
});

describe("d1SpendSource — wallet balance", () => {
  test("no wallet row ⇒ `null`, the never-deny reading", async () => {
    const reading = await d1SpendSource(db).walletBalanceCredits("tenant_a");
    expect(reading).toEqual({ ok: true, availableCredits: null });
  });

  test("a wallet at ZERO is `0`, which is NOT `null`", async () => {
    await seedWallet("tenant_a", 0);
    const reading = await d1SpendSource(db).walletBalanceCredits("tenant_a");
    expect(reading).toEqual({ ok: true, availableCredits: 0 });
  });

  test("live holds are subtracted from the funded balance", async () => {
    await seedWallet("tenant_a", 1000);
    await seedHold("hold_1", "tenant_a", 400, "active", NOW + 60);
    await seedHold("hold_2", "tenant_a", 100, "active", NOW + 60);
    const reading = await d1SpendSource(db, () => NOW).walletBalanceCredits("tenant_a");
    expect(reading).toEqual({ ok: true, availableCredits: 500 });
  });

  test("EXPIRED and non-active holds are not subtracted", async () => {
    await seedWallet("tenant_a", 1000);
    // Expiry is the release JS has no `Drop` for: a crashed request must not
    // strand credits forever.
    await seedHold("hold_expired", "tenant_a", 700, "active", NOW - 1);
    await seedHold("hold_settled", "tenant_a", 200, "settled", NOW + 60);
    await seedHold("hold_released", "tenant_a", 50, "released", NOW + 60);
    const reading = await d1SpendSource(db, () => NOW).walletBalanceCredits("tenant_a");
    expect(reading).toEqual({ ok: true, availableCredits: 1000 });
  });

  test("another tenant's holds never touch this balance", async () => {
    await seedWallet("tenant_a", 100);
    await seedHold("hold_other", "tenant_b", 100, "active", NOW + 60);
    const reading = await d1SpendSource(db, () => NOW).walletBalanceCredits("tenant_a");
    expect(reading).toEqual({ ok: true, availableCredits: 100 });
  });

  test("a batch failure is `ok: false`, never a `null` wallet", async () => {
    const broken = {
      prepare: () => ({ bind: () => ({}) }),
      batch(): never {
        throw new Error("D1_ERROR: no such table: wallets");
      },
    } as unknown as D1Database;
    const reading = await d1SpendSource(broken).walletBalanceCredits("tenant_a");
    expect(reading.ok).toBe(false);
    expect(reading.ok === false && reading.detail).toContain("no such table");
  });
});

describe("spendSourceFromEnv", () => {
  test("a bound D1 tenant database gives the durable source", async () => {
    await seedWallet("tenant_a", 42);
    const source = spendSourceFromEnv({ DB: db });
    expect(await source.walletBalanceCredits("tenant_a")).toEqual({
      ok: true,
      availableCredits: 42,
    });
  });

  test("no binding ⇒ the empty-store readings, which deny nothing", async () => {
    expect(spendSourceFromEnv({})).toBe(NO_SPEND_SOURCE);
    expect(await NO_SPEND_SOURCE.committedSpendUsd("tenant", "t", MONTH)).toEqual({
      ok: true,
      committedSpendUsd: 0,
    });
    expect(await NO_SPEND_SOURCE.walletBalanceCredits("t")).toEqual({
      ok: true,
      availableCredits: null,
    });
  });

  test("a `DB` that is a plain VAR string is not treated as a database", async () => {
    // `db.prepare` on a string would throw on the request path instead of
    // degrading to the empty-store source.
    expect(spendSourceFromEnv({ DB: "not-a-database" as unknown as D1Database })).toBe(
      NO_SPEND_SOURCE,
    );
  });
});

// ---------------------------------------------------------------------------
// Which scope a budget is charged against
// ---------------------------------------------------------------------------

describe("monthlyBudgetScope", () => {
  const chain = {
    tenantId: "tenant_a",
    projectId: "proj_a",
    workspaceId: "ws_a",
    keyId: "key_a",
  };

  test("the scope that WON the chain's min is authoritative", () => {
    const scope = monthlyBudgetScope(
      { monthlyBudgetScope: new QuotaScopeSelector("project", "proj_a") },
      chain,
    );
    // Not the key: a project budget holds across every key under it.
    expect(scope).toEqual({ kind: "project", id: "proj_a" });
  });

  test("with no recorded scope, the most specific attributed one is used", () => {
    expect(monthlyBudgetScope({}, chain)).toEqual({ kind: "key", id: "key_a" });
    expect(monthlyBudgetScope({}, { tenantId: "tenant_a" })).toEqual({
      kind: "tenant",
      id: "tenant_a",
    });
  });

  test("no attribution at all ⇒ null, i.e. nothing to refuse", () => {
    expect(monthlyBudgetScope({}, {})).toBeNull();
  });
});

describe("currentPeriodMonth", () => {
  test("is the UTC calendar month of the supplied instant", () => {
    expect(currentPeriodMonth(NOW)).toBe(MONTH);
    expect(currentPeriodMonth(0)).toBe("1970-01");
  });
});

// ---------------------------------------------------------------------------
// The deployed app — `SELF` → src/worker.ts → GATEWAY_MIDDLEWARE → rateLimit()
// ---------------------------------------------------------------------------

describe("the deployed app: step 2 — monthly budget", () => {
  test("under budget the request is served", async () => {
    await seedPolicy("tenant", "tenant_a", 10);
    await seedRollup("tenant", "tenant_a", 1, currentPeriodMonth());
    const response = await get(TENANT_A_KEY);
    expect(response.status).toBe(200);
  });

  test("spend AT the cap is refused — 429 monthly_budget_exceeded", async () => {
    await seedPolicy("tenant", "tenant_a", 10);
    // Rust refuses on `spent >= budget`, so exactly-at-cap denies.
    await seedRollup("tenant", "tenant_a", 10, currentPeriodMonth());

    const response = await get(TENANT_A_KEY);
    expect(response.status).toBe(429);
    const body = (await response.json()) as ErrorEnvelope;
    expect(body.error.type).toBe("ferrogate_error");
    expect(body.error.code).toBe("monthly_budget_exceeded");
    // The Rust `finalize_auth` message, verbatim.
    expect(body.error.message).toBe(
      "quota policy monthly budget has been exhausted for this scope",
    );
  });

  test("the budget is charged to the WINNING scope, not the api key", async () => {
    // A tenant-scope budget with tenant-scope spend denies…
    await seedPolicy("tenant", "tenant_a", 5);
    await seedRollup("tenant", "tenant_a", 6, currentPeriodMonth());
    expect((await get(TENANT_A_KEY)).status).toBe(429);

    // …while the same spend recorded at the KEY scope does not, because the
    // tenant budget is measured against the tenant's aggregate rollup.
    await db.prepare("DELETE FROM usage_monthly_rollups").run();
    await seedRollup("key", "key_unscoped", 6, currentPeriodMonth());
    expect((await get(TENANT_A_KEY)).status).toBe(200);
  });

  test("spend without any budget policy never refuses", async () => {
    await seedRollup("tenant", "tenant_a", 1_000_000, currentPeriodMonth());
    expect((await get(TENANT_A_KEY)).status).toBe(200);
  });
});

describe("the deployed app: step 3 — prepaid wallet", () => {
  test("a tenant with NO wallet row is never refused (opt-in)", async () => {
    expect((await get(TENANT_A_KEY)).status).toBe(200);
  });

  test("a funded wallet is served", async () => {
    await seedWallet("tenant_a", 5_000);
    expect((await get(TENANT_A_KEY)).status).toBe(200);
  });

  test("an exhausted wallet is refused — 429 wallet_balance_exhausted", async () => {
    await seedWallet("tenant_a", 0);
    const response = await get(TENANT_A_KEY);
    expect(response.status).toBe(429);
    const body = (await response.json()) as ErrorEnvelope;
    expect(body.error.code).toBe("wallet_balance_exhausted");
    expect(body.error.message).toBe("prepaid credit balance has been exhausted for this tenant");
  });

  test("live holds that consume the balance refuse the NEXT request", async () => {
    // Issue #169's concurrent-overdraft case: the balance is positive but every
    // credit is already committed to in-flight requests.
    await seedWallet("tenant_a", 500);
    await seedHold("hold_inflight", "tenant_a", 500, "active", Math.floor(Date.now() / 1000) + 300);
    const response = await get(TENANT_A_KEY);
    expect(response.status).toBe(429);
    expect(((await response.json()) as ErrorEnvelope).error.code).toBe("wallet_balance_exhausted");
  });

  test("another tenant's exhausted wallet does not refuse this one", async () => {
    await seedWallet("tenant_b", 0);
    expect((await get(TENANT_A_KEY)).status).toBe(200);
  });

  test("an anonymous operation is never wallet-checked", async () => {
    await seedWallet("tenant_a", 0);
    expect((await SELF.fetch("https://gateway.test/healthz")).status).toBe(200);
  });
});

describe("the deployed app: ordering and failure posture", () => {
  test("a DISABLED policy still answers 403, ahead of the budget check", async () => {
    await controlDb
      .prepare(
        "INSERT OR REPLACE INTO quota_policies " +
          "(id, scope_type, scope_id, monthly_budget_usd, enabled) VALUES (?, ?, ?, ?, 0)",
      )
      .bind("tenant:tenant_a", "tenant", "tenant_a", 1)
      .run();
    await seedRollup("tenant", "tenant_a", 500, currentPeriodMonth());
    await seedWallet("tenant_a", 0);

    const response = await get(TENANT_A_KEY);
    // Step 1 wins: a disabled scope is a hard deny, not a throttle.
    expect(response.status).toBe(403);
    expect(((await response.json()) as ErrorEnvelope).error.code).toBe("quota_scope_disabled");
  });

  test("budget is refused BEFORE the wallet, matching finalize_auth's order", async () => {
    await seedPolicy("tenant", "tenant_a", 1);
    await seedRollup("tenant", "tenant_a", 2, currentPeriodMonth());
    await seedWallet("tenant_a", 0);
    const body = (await (await get(TENANT_A_KEY)).json()) as ErrorEnvelope;
    expect(body.error.code).toBe("monthly_budget_exceeded");
  });
});
