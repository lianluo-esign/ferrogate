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
 *  - `d1QuotaPolicySource` — `quota_policies` + `plans` in `CONTROL_DB`,
 *    the source that WINS over `FG_DEV_QUOTA_POLICIES` whenever the control
 *    database is bound;
 *  - `d1SpendSource` — `usage_monthly_rollups.cost_usd` and
 *    `wallets.balance_credits` minus live holds, in `DB`;
 *  - `d1WalletAdmission` — `@ferrogate/storage`'s `D1WalletStore`, the atomic
 *    no-oversell reservation;
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
import { bearer, errorCode, get, post, setupDurablePorts } from "./setup.js";

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
/** A `quota_policies` row in CONTROL_DB with `enabled = 0`. */
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
    await env.DB.prepare(INSERT_ADMISSION_KEY_SQL)
      .bind(
        row.id,
        "ws-adm",
        row.tenantId,
        "proj-adm",
        row.id,
        virtualApiKeyPrefix(row.secret),
        await hashVirtualApiKeySecret(row.secret),
        virtualApiKeyLast4(row.secret),
        JSON.stringify(AGENT_SCOPES),
        row.requestLimitPerMinute ?? null,
      )
      .run();
  }

  // CONTROL_DB: the quota chain. Both budget tenants get the SAME $10 cap, so
  // the only difference between the two outcomes below is the rollup row.
  await env.CONTROL_DB.prepare(INSERT_POLICY_SQL)
    .bind("qp_budget_over", "tenant-budget-over", null, 10, 1)
    .run();
  await env.CONTROL_DB.prepare(INSERT_POLICY_SQL)
    .bind("qp_budget_under", "tenant-budget-under", null, 10, 1)
    .run();
  await env.CONTROL_DB.prepare(INSERT_POLICY_SQL)
    .bind("qp_scope_disabled", "tenant-scope-disabled", null, null, 0)
    .run();

  // DB: the spend rollups. `>=` refuses AT the cap, so 10 of a $10 budget is a
  // refusal and 1 is not.
  const period = currentPeriodMonth();
  await env.DB.prepare(INSERT_ROLLUP_SQL)
    .bind(`${period}:tenant:tenant-budget-over`, period, "tenant-budget-over", 10)
    .run();
  await env.DB.prepare(INSERT_ROLLUP_SQL)
    .bind(`${period}:tenant:tenant-budget-under`, period, "tenant-budget-under", 1)
    .run();

  // DB: the prepaid wallets. A tenant with NO row is never denied, which is
  // what every other tenant in this harness relies on.
  await env.DB.prepare(INSERT_WALLET_SQL)
    .bind("tenant-wallet-empty", "tenant-wallet-empty", 0)
    .run();
  await env.DB.prepare(INSERT_WALLET_SQL)
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

describe("the monthly USD budget, off usage_monthly_rollups", () => {
  it("REFUSES a tenant whose committed spend has reached its cap", async () => {
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
});

describe("the prepaid wallet, off wallets + wallet_reservations", () => {
  it("REFUSES a tenant whose wallet is funded to zero", async () => {
    const response = await submit(KEY_EMPTY_WALLET);
    expect(response.status).toBe(429);
    expect(await errorCode(response)).toBe("wallet_balance_exhausted");
  });

  it("ADMITS a funded tenant, and releases the hold it took", async () => {
    const response = await submit(KEY_FUNDED_WALLET);
    expect(response.status).toBe(202);

    // The hold is a HOLD, not a debit: `contractAuth`'s `finally` releases it,
    // so no `active` reservation may survive the request. A leak here would
    // silently drain the tenant's available balance one request at a time until
    // the TTL swept it — the failure mode `WALLET_HOLD_TTL_SECONDS` exists to
    // bound, and which this assertion refuses to rely on.
    const held = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM wallet_reservations WHERE tenant_id = ? AND status = 'active'",
    )
      .bind("tenant-wallet-funded")
      .first<{ n: number }>();
    expect(Number(held?.n ?? -1)).toBe(0);

    // …and the balance is untouched, because a hold never debits.
    const wallet = await env.DB.prepare("SELECT balance_credits FROM wallets WHERE tenant_id = ?")
      .bind("tenant-wallet-funded")
      .first<{ balance_credits: number }>();
    expect(Number(wallet?.balance_credits ?? -1)).toBe(1_000_000);
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

describe("quota_policies.enabled = 0 in the CONTROL database", () => {
  it("REFUSES with 403 quota_scope_disabled, not a 429", async () => {
    const response = await submit(KEY_DISABLED_SCOPE);
    expect(response.status).toBe(403);
    expect(await errorCode(response)).toBe("quota_scope_disabled");
  });
});

describe("the durable sources are the ones in play", () => {
  it("governs a tenant that appears in NO dev var — CONTROL_DB is the source", async () => {
    // `FG_DEV_QUOTA_POLICIES` is not bound in this harness at all, and none of
    // the tenants above appear in `vitest.config.ts`. The refusals therefore
    // cannot have come from the var source.
    expect((env as unknown as Record<string, unknown>).FG_DEV_QUOTA_POLICIES).toBeUndefined();
    const rows = await env.CONTROL_DB.prepare(
      "SELECT COUNT(*) AS n FROM quota_policies WHERE scope_id LIKE 'tenant-%'",
    ).first<{ n: number }>();
    expect(Number(rows?.n ?? 0)).toBeGreaterThanOrEqual(3);
  });

  it("leaves every ungoverned durable tenant admitted", async () => {
    // `tenant-a` (every other spec in this directory) has no policy row, no
    // rollup and no wallet. It must be unaffected.
    const { KEY_LIVE } = await import("./setup.js");
    const response = await submit(KEY_LIVE);
    expect(response.status).toBe(202);
  });
});
