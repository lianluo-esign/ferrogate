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
 * NO arguments, so the spend source is whatever the composition root builds for
 * the real bindings. Those tests fail if the two checks are removed from
 * `rateLimit`, if the source stops finding its database, or if `rateLimit()` is
 * ever dropped from `GATEWAY_MIDDLEWARE` — the "implemented, tested, never
 * mounted" failure mode this repo has shipped twice.
 *
 * ## THE TWO LEGS READ TWO DATABASES, and the end-to-end tests say which
 *
 * `wrangler.toml` ships `GATEWAY_TENANT_DB_ROUTING = "durable_object"`, so a
 * tenant's `wallets`/`wallet_reservations` rows live inside
 * `TENANT_DATA.idFromName(tenantId)` and NOT in the shared `env.DB`. Admission
 * step 3b has reserved there since #819; step 3's balance read now follows it
 * (`defaultSpendSource` in `src/ratelimit/middleware.ts`). `usage_monthly_rollups`
 * did NOT move, because `src/metering/` still writes it to `env.DB`.
 *
 * So the deployed-app wallet cases seed {@link seedRoutedWallet} while the
 * deployed-app budget cases keep seeding `db`, and that asymmetry is the
 * property under test rather than an inconsistency to tidy: seeding `env.DB` and
 * watching the wallet gate refuse would now prove only that some database
 * somewhere had a row in it. The two 429 cases below FAILED against `env.DB` the
 * moment the balance read was routed, which is the correct signal and the reason
 * they moved — the same move `test/ratelimit/guards.test.ts` records for 3b.
 *
 * The UNIT cases keep using `db`: `d1SpendSource(db)` is the `"off"`-mode
 * constructor, still shipped for self-hosted single-tenant deploys.
 */
import { SELF, env } from "cloudflare:test";
import { QuotaScopeSelector } from "@ferrogate/policy";
import {
  DurableObjectTenantDatabaseRouter,
  periodMonthFromUnix,
  usageMonthlyRollupId,
} from "@ferrogate/storage";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import {
  NO_SPEND_SOURCE,
  currentPeriodMonth,
  d1SpendSource,
  monthlyBudgetScope,
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

/**
 * One tenant's ROUTED database — the object `SELF` actually reads, addressed the
 * same way the gateway addresses it.
 *
 * Built through `@ferrogate/storage`'s router rather than by calling
 * `idFromName` here, so this helper cannot drift from the deployed addressing.
 * If it did, these tests would seed one object and assert against another.
 */
function tenantWalletDb(tenantId: string): D1Database {
  const bindings = env as unknown as {
    TENANT_DATA: ConstructorParameters<typeof DurableObjectTenantDatabaseRouter>[0];
    CONTROL_DB: D1Database;
  };
  return new DurableObjectTenantDatabaseRouter(
    bindings.TENANT_DATA,
    bindings.CONTROL_DB,
  ).databaseFor(tenantId);
}

/**
 * {@link seedRollup}, but into the tenant's OWN object — what `SELF` reads.
 *
 * Since the Zero-D1 cutover the deployed budget leg no longer reads `env.DB`:
 * `defaultSpendSource` (src/ratelimit/middleware.ts) resolves
 * `usage_monthly_rollups` through `tenantDatabaseOf(c).handle()`, i.e. the
 * tenant's Durable Object, the same handle the wallet leg reads. The module
 * comment above about the two legs reading two databases describes the pre-cutover
 * posture; the deployed-app cases below seed the object for BOTH legs now.
 */
async function seedRoutedRollup(
  tenantId: string,
  scopeType: string,
  scopeId: string,
  costUsd: number,
  periodMonth: string = MONTH,
): Promise<void> {
  await tenantWalletDb(tenantId)
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

/** {@link seedWallet}, but into the tenant's OWN object — what `SELF` reads. */
async function seedRoutedWallet(tenantId: string, balanceCredits: number): Promise<void> {
  await tenantWalletDb(tenantId)
    .prepare(
      "INSERT OR REPLACE INTO wallets " +
        "(id, tenant_id, balance_credits, created_at_unix, updated_at_unix) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(tenantId, tenantId, balanceCredits, NOW, NOW)
    .run();
}

/** {@link seedHold}, but into the tenant's OWN object. */
async function seedRoutedHold(
  id: string,
  tenantId: string,
  amountCredits: number,
  status: string,
  expiresAtUnix: number,
): Promise<void> {
  await tenantWalletDb(tenantId)
    .prepare(
      "INSERT OR REPLACE INTO wallet_reservations " +
        "(id, tenant_id, amount_credits, status, expires_at_unix, created_at_unix, updated_at_unix) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id, tenantId, amountCredits, status, expiresAtUnix, NOW, NOW)
    .run();
}

/**
 * A `quota_policies` row in the OWNING tenant's object (Track A hard-cut: the
 * shared control mirror was removed, so `SELF` reads them from the tenant's own
 * object). These cases use tenant-scope rows, so `scopeId` is the tenant id.
 */
async function seedPolicy(
  scopeType: string,
  scopeId: string,
  monthlyBudgetUsd: number | null,
): Promise<void> {
  await tenantWalletDb(scopeId)
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

beforeAll(async () => {
  // `test/setup-d1.ts` seeds the fixture tenants' roster rows but leaves
  // `migration_state` at its schema DEFAULT — 'shared', a PRE-cutover state,
  // which makes the dispatching router serve them from the legacy shared
  // `env.DB`. The deployed-app cases below assert the post-cutover posture
  // (the tenant's own object is the authority), so the cutover is recorded.
  await controlDb
    .prepare("UPDATE tenant_databases SET migration_state = 'done' WHERE tenant_id IN (?, ?)")
    .bind("tenant_a", "tenant_b")
    .run();
});

beforeEach(async () => {
  await db.prepare("DELETE FROM usage_monthly_rollups").run();
  await db.prepare("DELETE FROM wallets").run();
  await db.prepare("DELETE FROM wallet_reservations").run();
  // Track A / 0045 dropped the control mirror of `quota_policies`; it is now
  // tenant-object authoritative and reset per-tenant below.
  // The tenants' OBJECTS are truncated explicitly, and they have to be: this
  // pool's per-test isolated storage rolls back D1 and the DO key-value API,
  // but rows a Durable Object holds in `ctx.storage.sql` survive into the next
  // test. Without this a wallet seeded by an earlier case would decide a later
  // one. Same reset `guards.test.ts` makes, for the same reason.
  for (const tenantId of ["tenant_a", "tenant_b"]) {
    const routed = tenantWalletDb(tenantId);
    await routed.prepare("DELETE FROM wallet_reservations").run();
    await routed.prepare("DELETE FROM wallets").run();
    await routed.prepare("DELETE FROM usage_monthly_rollups").run();
    // Track A hard-cut: quota_policies is now tenant-object authoritative, and a
    // DO's `ctx.storage.sql` rows survive into the next test (see above), so a
    // policy an earlier case seeded must be cleared here too.
    await routed.prepare("DELETE FROM quota_policies").run();
  }
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

describe("NO_SPEND_SOURCE — the empty-store readings that deny nothing", () => {
  test("committed spend is zero and wallet balance is opt-in null", async () => {
    // Since #821 PR2-delete the shared-`env.DB` `spendSourceFromEnv` resolver is
    // gone; the composition root's inert base is `NO_SPEND_SOURCE`, and the live
    // spend authority is the tenant-object-routed source (`d1SpendSource` over a
    // resolved handle, exercised above).
    expect(await NO_SPEND_SOURCE.committedSpendUsd("tenant", "t", MONTH)).toEqual({
      ok: true,
      committedSpendUsd: 0,
    });
    expect(await NO_SPEND_SOURCE.walletBalanceCredits("t")).toEqual({
      ok: true,
      availableCredits: null,
    });
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
    await seedRoutedRollup("tenant_a", "tenant", "tenant_a", 1, currentPeriodMonth());
    const response = await get(TENANT_A_KEY);
    expect(response.status).toBe(200);
  });

  test("spend AT the cap is refused — 429 monthly_budget_exceeded", async () => {
    await seedPolicy("tenant", "tenant_a", 10);
    // Rust refuses on `spent >= budget`, so exactly-at-cap denies.
    await seedRoutedRollup("tenant_a", "tenant", "tenant_a", 10, currentPeriodMonth());

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
    await seedRoutedRollup("tenant_a", "tenant", "tenant_a", 6, currentPeriodMonth());
    expect((await get(TENANT_A_KEY)).status).toBe(429);

    // …while the same spend recorded at the KEY scope does not, because the
    // tenant budget is measured against the tenant's aggregate rollup.
    await tenantWalletDb("tenant_a").prepare("DELETE FROM usage_monthly_rollups").run();
    await seedRoutedRollup("tenant_a", "key", "key_unscoped", 6, currentPeriodMonth());
    expect((await get(TENANT_A_KEY)).status).toBe(200);
  });

  test("spend without any budget policy never refuses", async () => {
    await seedRoutedRollup("tenant_a", "tenant", "tenant_a", 1_000_000, currentPeriodMonth());
    expect((await get(TENANT_A_KEY)).status).toBe(200);
  });
});

describe("the deployed app: step 3 — prepaid wallet", () => {
  test("a tenant with NO wallet row is never refused (opt-in)", async () => {
    expect((await get(TENANT_A_KEY)).status).toBe(200);
  });

  test("a funded wallet is served", async () => {
    await seedRoutedWallet("tenant_a", 5_000);
    expect((await get(TENANT_A_KEY)).status).toBe(200);
  });

  test("an exhausted wallet is refused — 429 wallet_balance_exhausted", async () => {
    await seedRoutedWallet("tenant_a", 0);
    const response = await get(TENANT_A_KEY);
    expect(response.status).toBe(429);
    const body = (await response.json()) as ErrorEnvelope;
    expect(body.error.code).toBe("wallet_balance_exhausted");
    expect(body.error.message).toBe("prepaid credit balance has been exhausted for this tenant");
  });

  test("live holds that consume the balance refuse the NEXT request", async () => {
    // Issue #169's concurrent-overdraft case: the balance is positive but every
    // credit is already committed to in-flight requests.
    await seedRoutedWallet("tenant_a", 500);
    await seedRoutedHold(
      "hold_inflight",
      "tenant_a",
      500,
      "active",
      Math.floor(Date.now() / 1000) + 300,
    );
    const response = await get(TENANT_A_KEY);
    expect(response.status).toBe(429);
    expect(((await response.json()) as ErrorEnvelope).error.code).toBe("wallet_balance_exhausted");
  });

  test("another tenant's exhausted wallet does not refuse this one", async () => {
    await seedRoutedWallet("tenant_b", 0);
    expect((await get(TENANT_A_KEY)).status).toBe(200);
  });

  test("an anonymous operation is never wallet-checked", async () => {
    await seedRoutedWallet("tenant_a", 0);
    expect((await SELF.fetch("https://gateway.test/healthz")).status).toBe(200);
  });

  test("a balance in the SHARED `DB` is not the balance the gate reads", async () => {
    // The regression this whole split closes. A deployment migrated from
    // `GATEWAY_TENANT_DB_ROUTING = "off"` still carries the tenant's legacy row
    // in `env.DB`, and nothing in the routed topology writes it any more. If
    // step 3 read it, this tenant — funded in the object the gate is supposed
    // to enforce — would be refused 429 forever, and topping up the object
    // could never clear it. Deleting `defaultSpendSource`'s routed arm turns
    // this red.
    await seedWallet("tenant_a", 0);
    await seedRoutedWallet("tenant_a", 5_000);
    expect((await get(TENANT_A_KEY)).status).toBe(200);
  });

  test("a stale FUNDED row in the shared `DB` cannot admit a drained tenant", async () => {
    // The mirror, and the reason routing the read is not merely cosmetic: the
    // shared row says 1,000,000 credits and the tenant's own object says zero.
    // The object wins, because the object is what the money moves in.
    await seedWallet("tenant_a", 1_000_000);
    await seedRoutedWallet("tenant_a", 0);
    const response = await get(TENANT_A_KEY);
    expect(response.status).toBe(429);
    expect(((await response.json()) as ErrorEnvelope).error.code).toBe("wallet_balance_exhausted");
  });
});

describe("the deployed app: ordering and failure posture", () => {
  test("a DISABLED policy still answers 403, ahead of the budget check", async () => {
    // Track A hard-cut: seeded into the tenant's own object, where `SELF` reads.
    await tenantWalletDb("tenant_a")
      .prepare(
        "INSERT OR REPLACE INTO quota_policies " +
          "(id, scope_type, scope_id, monthly_budget_usd, enabled) VALUES (?, ?, ?, ?, 0)",
      )
      .bind("tenant:tenant_a", "tenant", "tenant_a", 1)
      .run();
    await seedRoutedRollup("tenant_a", "tenant", "tenant_a", 500, currentPeriodMonth());
    await seedRoutedWallet("tenant_a", 0);

    const response = await get(TENANT_A_KEY);
    // Step 1 wins: a disabled scope is a hard deny, not a throttle.
    expect(response.status).toBe(403);
    expect(((await response.json()) as ErrorEnvelope).error.code).toBe("quota_scope_disabled");
  });

  test("budget is refused BEFORE the wallet, matching finalize_auth's order", async () => {
    await seedPolicy("tenant", "tenant_a", 1);
    await seedRoutedRollup("tenant_a", "tenant", "tenant_a", 2, currentPeriodMonth());
    await seedRoutedWallet("tenant_a", 0);
    const body = (await (await get(TENANT_A_KEY)).json()) as ErrorEnvelope;
    expect(body.error.code).toBe("monthly_budget_exceeded");
  });
});
