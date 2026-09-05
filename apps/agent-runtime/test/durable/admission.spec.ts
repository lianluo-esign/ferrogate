/**
 * THE MONEY GATES, against REAL migrated D1 databases.
 *
 * `test/admission.test.ts` proves the quota-scope and RPM legs of Rust's
 * `finalize_auth`, which need no storage. The two legs that DO need storage —
 * the monthly USD budget (`usage_monthly_rollups`) and the prepaid wallet
 * (`wallets` + `wallet_reservations`) — are proven here, because proving them
 * against a var would prove nothing about the deployed path.
 *
 * Everything below goes through `SELF.fetch` into the REAL `src/worker.ts` with
 * the harness's two bound, MIGRATED databases and the `FG_DEV_*` bundle absent
 * (`harness/wrangler.toml`). So this file exercises:
 *
 *  - `d1QuotaPolicySource` — the per-tenant `quota_policies` + `spend_throttles`
 *    legs in the caller tenant's OWN object (Track A hard-cut: the shared control
 *    mirror was removed) plus the account-global `plans` floor in `CONTROL_DB`,
 *    the source that WINS over `FG_DEV_QUOTA_POLICIES` whenever the control
 *    database is bound;
 *  - `routedSpendSource` — `usage_monthly_rollups.cost_usd` and
 *    `wallets.balance_credits` minus live holds, in the CALLER tenant's OWN
 *    Durable Object (#821 PR2a): the money legs route to the same object the
 *    credential resolves through, never the shared `env.DB` a routed deployment
 *    does not write. That is why the rollups and wallets below are seeded there;
 *  - `routedWalletAdmission` — `@ferrogate/storage`'s `D1WalletStore`, the atomic
 *    no-oversell reservation, over that routed object handle;
 *  - `api_keys.request_limit_per_minute` — the TOK-12 column the D1 resolver
 *    used to read and DROP.
 *
 * ## Tenancy is the isolation, deliberately
 *
 * Every fixture here lives in a tenant of its own (`tenant-budget`,
 * `tenant-wallet`, …). The pre-existing durable specs all run in `tenant-a`,
 * which this file governs with NOTHING — so a quota row seeded here cannot
 * silently start refusing `mount.spec.ts`.
 */
import { env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import {
  hashVirtualApiKeySecret,
  virtualApiKeyLast4,
  virtualApiKeyPrefix,
} from "../../src/durable/hash.js";
import { bearer, errorCode, get, post, setupDurablePorts, tenantResourceDb } from "./setup.js";

const AGENT_SCOPES = ["agents.invoke", "agent.runs.create", "agent.runs.read"];

/** Over its monthly USD budget: the rollup already meets the cap. */
const KEY_OVER_BUDGET = "fg_durable_over_budget0";
/** Same tenant shape, but the rollup is well under the cap. */
const KEY_UNDER_BUDGET = "fg_durable_under_budge";
/** A tenant with a wallet row funded to ZERO. */
const KEY_EMPTY_WALLET = "fg_durable_empty_walle";
/** A tenant with a FUNDED wallet — the negative control for the wallet gate. */
const KEY_FUNDED_WALLET = "fg_durable_funded_wall";
/** `api_keys.request_limit_per_minute = 1`, read straight off the row. */
const KEY_ROW_RPM = "fg_durable_row_rpm_cap";
/** A `quota_policies` row in the tenant's OWN object with `enabled = 0`. */
const KEY_DISABLED_SCOPE = "fg_durable_disabled_sc";

interface AdmissionKey {
  readonly id: string;
  readonly secret: string;
  readonly tenantId: string;
  readonly requestLimitPerMinute?: number;
}

const ADMISSION_KEYS: readonly AdmissionKey[] = [
  { id: "key_over_budget", secret: KEY_OVER_BUDGET, tenantId: "tenant-budget-over" },
  { id: "key_under_budget", secret: KEY_UNDER_BUDGET, tenantId: "tenant-budget-under" },
  { id: "key_empty_wallet", secret: KEY_EMPTY_WALLET, tenantId: "tenant-wallet-empty" },
  { id: "key_funded_wallet", secret: KEY_FUNDED_WALLET, tenantId: "tenant-wallet-funded" },
  {
    id: "key_row_rpm",
    secret: KEY_ROW_RPM,
    tenantId: "tenant-row-rpm",
    requestLimitPerMinute: 1,
  },
  { id: "key_disabled_scope", secret: KEY_DISABLED_SCOPE, tenantId: "tenant-scope-disabled" },
];

const INSERT_ADMISSION_KEY_SQL =
  "INSERT OR REPLACE INTO api_keys (id, workspace_id, tenant_id, project_id, name, " +
  "key_prefix, key_hash, last4, enabled, scopes_json, request_limit_per_minute) " +
  "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)";

/** #821 — hop 1 of the two-hop credential model: the CONTROL directory row. */
const INSERT_ADMISSION_DIRECTORY_SQL =
  "INSERT OR REPLACE INTO api_key_directory (key_hash, id, tenant_id, project_id, " +
  "workspace_id, key_prefix, last4, enabled) VALUES (?, ?, ?, 'proj-adm', 'ws-adm', ?, ?, 1)";

const INSERT_POLICY_SQL =
  "INSERT OR REPLACE INTO quota_policies (id, scope_type, scope_id, rpm_limit, " +
  "monthly_budget_usd, enabled) VALUES (?, 'tenant', ?, ?, ?, ?)";

const INSERT_ROLLUP_SQL =
  "INSERT OR REPLACE INTO usage_monthly_rollups (id, period_month, scope_type, scope_id, " +
  "cost_usd, updated_at_unix) VALUES (?, ?, 'tenant', ?, ?, 0)";

const INSERT_WALLET_SQL =
  "INSERT OR REPLACE INTO wallets (id, tenant_id, balance_credits, created_at_unix, " +
  "updated_at_unix) VALUES (?, ?, ?, 0, 0)";

/**
 * The UTC `YYYY-MM` the ladder derives with `periodMonthFromUnix(now)`.
 *
 * Computed from the SAME clock the Worker reads rather than hard-coded, so this
 * file does not need re-seeding every month — and so a month whose rollup was
 * seeded under a different key cannot make the budget assertion pass for the
 * wrong reason.
 */
function currentPeriodMonth(): string {
  return new Date().toISOString().slice(0, 7);
}

let seeded = false;

async function seedAdmissionFixtures(): Promise<void> {
  if (seeded) return;
  await setupDurablePorts();

  for (const row of ADMISSION_KEYS) {
    const keyHash = await hashVirtualApiKeySecret(row.secret);
    const keyPrefix = virtualApiKeyPrefix(row.secret);
    const last4 = virtualApiKeyLast4(row.secret);
    // Hop 1: the CONTROL directory routes the hash to its tenant.
    await env.CONTROL_DB.prepare(INSERT_ADMISSION_DIRECTORY_SQL)
      .bind(keyHash, row.id, row.tenantId, keyPrefix, last4)
      .run();
    // Hop 2: the AUTHORITATIVE `api_keys` row in that tenant's OWN object.
    await (await tenantResourceDb(row.tenantId))
      .prepare(INSERT_ADMISSION_KEY_SQL)
      .bind(
        row.id,
        "ws-adm",
        row.tenantId,
        "proj-adm",
        row.id,
        keyPrefix,
        keyHash,
        last4,
        JSON.stringify(AGENT_SCOPES),
        row.requestLimitPerMinute ?? null,
      )
      .run();
  }

  // The tenant OBJECT: the quota chain. Track A hard-cut — `quota_policies` is
  // per-tenant data read from each tenant's OWN object, never the (removed)
  // control mirror, so each policy row is seeded into its own tenant's object.
  // Both budget tenants get the SAME $10 cap, so the only difference between the
  // two outcomes below is the rollup row.
  await (await tenantResourceDb("tenant-budget-over"))
    .prepare(INSERT_POLICY_SQL)
    .bind("qp_budget_over", "tenant-budget-over", null, 10, 1)
    .run();
  await (await tenantResourceDb("tenant-budget-under"))
    .prepare(INSERT_POLICY_SQL)
    .bind("qp_budget_under", "tenant-budget-under", null, 10, 1)
    .run();
  await (await tenantResourceDb("tenant-scope-disabled"))
    .prepare(INSERT_POLICY_SQL)
    .bind("qp_scope_disabled", "tenant-scope-disabled", null, null, 0)
    .run();

  // The tenant OBJECT (#821 PR2a): the spend rollups. `>=` refuses AT the cap,
  // so 10 of a $10 budget is a refusal and 1 is not. Seeded in the caller's own
  // object because that is where the routed admission ladder now reads them —
  // seeding `env.DB` would make every budget read `0` and admit an over-cap
  // tenant, which is the very regression this slice closes.
  const period = currentPeriodMonth();
  await (await tenantResourceDb("tenant-budget-over"))
    .prepare(INSERT_ROLLUP_SQL)
    .bind(`${period}:tenant:tenant-budget-over`, period, "tenant-budget-over", 10)
    .run();
  await (await tenantResourceDb("tenant-budget-under"))
    .prepare(INSERT_ROLLUP_SQL)
    .bind(`${period}:tenant:tenant-budget-under`, period, "tenant-budget-under", 1)
    .run();

  // The tenant OBJECT: the prepaid wallets. A tenant with NO row is never
  // denied, which is what every other tenant in this harness relies on.
  await (await tenantResourceDb("tenant-wallet-empty"))
    .prepare(INSERT_WALLET_SQL)
    .bind("tenant-wallet-empty", "tenant-wallet-empty", 0)
    .run();
  await (await tenantResourceDb("tenant-wallet-funded"))
    .prepare(INSERT_WALLET_SQL)
    .bind("tenant-wallet-funded", "tenant-wallet-funded", 1_000_000)
    .run();

  seeded = true;
}

beforeAll(seedAdmissionFixtures);

/** `POST /v1/agent-jobs` — the money-spending verb the bypass reached. */
async function submit(key: string): Promise<Response> {
  return await post("/v1/agent-jobs", bearer(key), {
    input: "write the patch",
    required_capabilities: ["coding"],
    idempotency_key: `adm-${key}-${Math.random().toString(36).slice(2)}`,
  });
}

describe("the monthly USD budget, off usage_monthly_rollups in the tenant OBJECT", () => {
  it("REFUSES a tenant whose committed spend has reached its cap — read from the DO", async () => {
    const response = await submit(KEY_OVER_BUDGET);
    expect(response.status).toBe(429);
    expect(await errorCode(response)).toBe("monthly_budget_exceeded");
  });

  it("ADMITS the same shape of tenant when the rollup is under the cap", async () => {
    // Same $10 policy, same scope type, same key shape — only `cost_usd`
    // differs. Without this the refusal above could be caused by anything.
    const response = await submit(KEY_UNDER_BUDGET);
    expect(response.status).toBe(202);
  });

  it("reads the budget from the OBJECT, not the shared env.DB — routing is the point", async () => {
    // The rollup lives in the tenant's own object; the shared `env.DB` holds NO
    // row for it. If the ladder still read `env.DB` the over-cap tenant would be
    // admitted, so this is the assertion that would fail on an un-routed gate.
    const period = currentPeriodMonth();
    const inObject = await (await tenantResourceDb("tenant-budget-over"))
      .prepare("SELECT cost_usd FROM usage_monthly_rollups WHERE period_month = ? AND scope_id = ?")
      .bind(period, "tenant-budget-over")
      .first<{ cost_usd: number }>();
    expect(Number(inObject?.cost_usd ?? -1)).toBe(10);
    const inShared = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM usage_monthly_rollups WHERE scope_id = ?",
    )
      .bind("tenant-budget-over")
      .first<{ n: number }>();
    expect(Number(inShared?.n ?? -1)).toBe(0);
  });
});

describe("the prepaid wallet, off wallets + wallet_reservations in the tenant OBJECT", () => {
  it("REFUSES a tenant whose wallet is funded to zero — read from the DO", async () => {
    const response = await submit(KEY_EMPTY_WALLET);
    expect(response.status).toBe(429);
    expect(await errorCode(response)).toBe("wallet_balance_exhausted");
  });

  it("ADMITS a funded tenant, and releases the hold it took — all in the DO", async () => {
    const response = await submit(KEY_FUNDED_WALLET);
    expect(response.status).toBe(202);

    const fundedDb = await tenantResourceDb("tenant-wallet-funded");
    // The hold is a HOLD, not a debit: `contractAuth`'s `finally` releases it,
    // so no `active` reservation may survive the request — and it must have been
    // taken in the tenant OBJECT (the no-oversell reserve routed there), so this
    // is where a leak would show. A leak would silently drain the tenant's
    // available balance one request at a time until the TTL swept it.
    const held = await fundedDb
      .prepare(
        "SELECT COUNT(*) AS n FROM wallet_reservations WHERE tenant_id = ? AND status = 'active'",
      )
      .bind("tenant-wallet-funded")
      .first<{ n: number }>();
    expect(Number(held?.n ?? -1)).toBe(0);

    // …and the balance is untouched, because a hold never debits.
    const wallet = await fundedDb
      .prepare("SELECT balance_credits FROM wallets WHERE tenant_id = ?")
      .bind("tenant-wallet-funded")
      .first<{ balance_credits: number }>();
    expect(Number(wallet?.balance_credits ?? -1)).toBe(1_000_000);
  });

  it("the no-oversell guard rejects an overspend against the DO balance", async () => {
    // A wallet funded to exactly ONE credit affords exactly one concurrent
    // admission (`DEFAULT_WALLET_HOLD_CREDITS = 1`). Two live holds would be an
    // oversell; the storage guard's in-statement predicate — run over the tenant
    // OBJECT — refuses the second. Driven by leaving the first request's hold
    // OUTSTANDING (a stranded `active` reservation) and then admitting again.
    const tenantId = "tenant-wallet-oversell";
    const secret = "fg_durable_oversell_wal";
    const keyHash = await hashVirtualApiKeySecret(secret);
    const keyPrefix = virtualApiKeyPrefix(secret);
    const last4 = virtualApiKeyLast4(secret);
    await env.CONTROL_DB.prepare(INSERT_ADMISSION_DIRECTORY_SQL)
      .bind(keyHash, "key_oversell", tenantId, keyPrefix, last4)
      .run();
    const objectDb = await tenantResourceDb(tenantId);
    await objectDb
      .prepare(INSERT_ADMISSION_KEY_SQL)
      .bind(
        "key_oversell",
        "ws-adm",
        tenantId,
        "proj-adm",
        "key_oversell",
        keyPrefix,
        keyHash,
        last4,
        JSON.stringify(AGENT_SCOPES),
        null,
      )
      .run();
    // One credit funded, and a live hold that already commits it (far-future
    // expiry, so it is not swept before the second admission reads it).
    await objectDb.prepare(INSERT_WALLET_SQL).bind(tenantId, tenantId, 1).run();
    await objectDb
      .prepare(
        "INSERT OR REPLACE INTO wallet_reservations (id, tenant_id, amount_credits, status, " +
          "created_at_unix, updated_at_unix, expires_at_unix) " +
          "VALUES ('res_outstanding', ?, 1, 'active', 0, 0, ?)",
      )
      .bind(tenantId, 4_000_000_000)
      .run();

    const refused = await submit(secret);
    expect(refused.status).toBe(429);
    expect(await errorCode(refused)).toBe("wallet_balance_exhausted");
  });
});

describe("api_keys.request_limit_per_minute — the column the resolver used to drop", () => {
  it("REFUSES the second request from a credential whose row caps it at 1", async () => {
    const first = await submit(KEY_ROW_RPM);
    expect(first.status).toBe(202);

    const second = await submit(KEY_ROW_RPM);
    expect(second.status).toBe(429);
    expect(await errorCode(second)).toBe("rate_limit_exceeded");

    // A READ is charged against the same window too, so it stays refused.
    const read = await get("/v1/agent-jobs/job-nope", bearer(KEY_ROW_RPM));
    expect(read.status).toBe(429);
  });
});

describe("quota_policies.enabled = 0 in the tenant's OWN object", () => {
  it("REFUSES with 403 quota_scope_disabled, not a 429", async () => {
    const response = await submit(KEY_DISABLED_SCOPE);
    expect(response.status).toBe(403);
    expect(await errorCode(response)).toBe("quota_scope_disabled");
  });
});

describe("the durable sources are the ones in play", () => {
  it("governs a tenant that appears in NO dev var — the tenant OBJECT is the source", async () => {
    // `FG_DEV_QUOTA_POLICIES` is not bound in this harness at all, and none of
    // the tenants above appear in `vitest.config.ts`. The refusals therefore
    // cannot have come from the var source. Track A hard-cut: the durable
    // `quota_policies` rows live in each tenant's OWN object, so the count is
    // taken there — the control mirror no longer holds them.
    expect((env as unknown as Record<string, unknown>).FG_DEV_QUOTA_POLICIES).toBeUndefined();
    for (const tenantId of ["tenant-budget-over", "tenant-budget-under", "tenant-scope-disabled"]) {
      const row = await (await tenantResourceDb(tenantId))
        .prepare("SELECT COUNT(*) AS n FROM quota_policies WHERE scope_id = ?")
        .bind(tenantId)
        .first<{ n: number }>();
      expect(Number(row?.n ?? 0)).toBe(1);
    }
  });

  it("leaves every ungoverned durable tenant admitted", async () => {
    // `tenant-a` (every other spec in this directory) has no policy row, no
    // rollup and no wallet. It must be unaffected.
    const { KEY_LIVE } = await import("./setup.js");
    const response = await submit(KEY_LIVE);
    expect(response.status).toBe(202);
  });
});
