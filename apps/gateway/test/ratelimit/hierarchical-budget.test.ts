/**
 * #679 — nested budgets (`org → project → workspace → key`) and the shared
 * counter that has to survive concurrency.
 *
 * Two defects are pinned here, and they are independent:
 *
 * **1. Only ONE rung of the ladder was ever enforced.** `resolveEffectiveQuota`
 * collapses the chain to the tightest configured NUMBER
 * (`monthlyBudgetUsd`) plus the one scope it came from
 * (`monthlyBudgetScope`), and `rateLimit()` measured that single scope's
 * aggregate spend. So `project = $5,000` with `key = $100` resolves to `$100`
 * at the KEY scope, and the project's $5,000 cap is never evaluated at all:
 * fifty keys spend $5,000 each and the project spends $250,000. A budget that
 * nests cannot be one number, because each rung is measured against a
 * DIFFERENT aggregate rollup.
 *
 * **2. The check was a read-modify-write on D1.** `SELECT cost_usd` → compare →
 * admit. Requests that arrive together all read the same pre-spend value and
 * are all admitted; D1 cannot serialise them, which is why the shared counter
 * has to be a Durable Object (the same argument `wallet.ts` and
 * `durable-object.ts` already make for credits and tokens).
 *
 * Nothing here is mocked. `env.DB` is miniflare's real SQLite tenant database
 * with the DEPLOYED migration applied, `env.CONTROL_DB` holds the real
 * `quota_policies` rows, `env.RATE_LIMIT` is the real Durable Object namespace
 * from `wrangler.toml`, and `SELF` is `src/worker.ts` — i.e. `rateLimit()` with
 * NO arguments, so every default asserted here is the deployed one.
 */
import { SELF, env } from "cloudflare:test";
import { QuotaScopeSelector } from "@ferrogate/policy";
import { periodMonthFromUnix, usageMonthlyRollupId } from "@ferrogate/storage";
import { afterEach, beforeAll, beforeEach, describe, expect, test } from "vitest";
import { resetSharedApiKeyCache } from "../../src/keys/index.js";
import {
  DEFAULT_BUDGET_HOLD_USD,
  budgetHoldUsdFromEnv,
  counterKeyForScope,
  limiterForEnv,
} from "../../src/ratelimit/index.js";
import { resetApiKeysTable, seedApiKey, testSecret } from "../keys/seed.js";
import { tenantObjectDb } from "../tenant-object.js";

const controlDb = (env as unknown as { CONTROL_DB: D1Database }).CONTROL_DB;
const vars = env as unknown as Record<string, string | undefined>;

const MODELS = "https://gateway.test/v1/models";

/** The four rungs of one request's chain, seeded onto a real `api_keys` row. */
const ORG = "tenant_hb";
const PROJECT = "project_hb";
const WORKSPACE = "workspace_hb";
const KEY_ID = "key_hb";

/** `usage_monthly_rollups` is keyed on the CURRENT calendar month. */
const MONTH = periodMonthFromUnix(Math.floor(Date.now() / 1000));

interface ErrorEnvelope {
  readonly error: { readonly code: string; readonly message: string; readonly type: string };
}

/**
 * The rollup rows live in the TENANT'S OWN Durable Object: since the Zero-D1
 * cutover `defaultSpendSource` (src/ratelimit/middleware.ts) reads
 * `usage_monthly_rollups` through `tenantDatabaseOf(c).handle()`, so a row
 * seeded into the shared `env.DB` is one the deployed Worker never sees.
 */
async function seedRollup(scopeType: string, scopeId: string, costUsd: number): Promise<void> {
  await tenantObjectDb(ORG)
    .prepare(
      "INSERT OR REPLACE INTO usage_monthly_rollups " +
        "(id, period_month, scope_type, scope_id, cost_usd, updated_at_unix) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(
      usageMonthlyRollupId(MONTH, scopeType as "tenant", scopeId),
      MONTH,
      scopeType,
      scopeId,
      costUsd,
      0,
    )
    .run();
}

/**
 * A `quota_policies` row. Track A hard-cut: the shared control mirror was
 * removed, so `SELF` reads every scope in the chain from the tenant's OWN
 * object. All scopes here belong to `ORG`, so all rows go into `ORG`'s object.
 */
async function seedBudget(
  scopeType: string,
  scopeId: string,
  monthlyBudgetUsd: number,
): Promise<void> {
  await tenantObjectDb(ORG)
    .prepare(
      "INSERT OR REPLACE INTO quota_policies " +
        "(id, scope_type, scope_id, monthly_budget_usd, enabled) VALUES (?, ?, ?, ?, 1)",
    )
    .bind(`${scopeType}:${scopeId}`, scopeType, scopeId, monthlyBudgetUsd)
    .run();
}

/** The credential under test: one real row carrying the whole four-level chain. */
async function seedChainKey(): Promise<string> {
  return await seedApiKey({
    id: KEY_ID,
    secret: testSecret("hierarchical-budget"),
    tenantId: ORG,
    projectId: PROJECT,
    workspaceId: WORKSPACE,
    scopes: [],
  });
}

async function get(secret: string): Promise<Response> {
  return await SELF.fetch(MODELS, { headers: { Authorization: `Bearer ${secret}` } });
}

const SAVED_VARS = new Map<string, string | undefined>();

beforeAll(async () => {
  // `test/setup-d1.ts` seeds roster rows only for the `[vars]` fixture tenants;
  // `tenant_hb` is this file's own. Without a `tenant_databases` row the
  // dispatching router's fallback arm answers `not_found` and every
  // authenticated request is 503 `quota_resolution_unavailable`.
  // `migration_state = 'done'` is required: the column DEFAULTs to 'shared'
  // (pre-cutover), which routes the tenant to the legacy shared `env.DB`
  // instead of its object.
  await controlDb
    .prepare(
      "INSERT OR REPLACE INTO tenant_databases " +
        "(tenant_id, storage_backend, provisioning_status, migration_state) " +
        "VALUES (?, 'durable_object', 'ready', 'done')",
    )
    .bind(ORG)
    .run();
});

beforeEach(async () => {
  SAVED_VARS.set("GATEWAY_BUDGET_HOLD_USD", vars.GATEWAY_BUDGET_HOLD_USD);
  await resetApiKeysTable();
  resetSharedApiKeyCache();
  // The object's rows survive this pool's per-test isolated-storage rollback
  // (`ctx.storage.sql` is not part of it), so the truncation is explicit.
  await tenantObjectDb(ORG).prepare("DELETE FROM usage_monthly_rollups").run();
  await tenantObjectDb(ORG).prepare("DELETE FROM quota_policies").run();
});

afterEach(() => {
  const saved = SAVED_VARS.get("GATEWAY_BUDGET_HOLD_USD");
  // biome-ignore lint/performance/noDelete: removes the own-property key entirely; assigning undefined would leave an enumerable undefined-valued key and change JSON serialization, the 'in' operator, and Object.keys semantics
  if (saved === undefined) delete vars.GATEWAY_BUDGET_HOLD_USD;
  else vars.GATEWAY_BUDGET_HOLD_USD = saved;
});

// ---------------------------------------------------------------------------
// Defect 1 — every rung of the ladder, not just the tightest number
// ---------------------------------------------------------------------------

describe("the deployed app: a nested budget binds at EVERY level", () => {
  test("a project that has spent its cap refuses a key that is under its own", async () => {
    const secret = await seedChainKey();
    // "This project gets $5,000/month, split however its keys like."
    await seedBudget("project", PROJECT, 5_000);
    // …and this key is allowed $100 of it.
    await seedBudget("key", KEY_ID, 100);
    // The project's SIBLING keys have already spent the whole project budget.
    await seedRollup("project", PROJECT, 5_000);
    // This key itself has spent nothing.
    await seedRollup("key", KEY_ID, 0);

    // Before #679 the merge collapsed to $100 at the KEY scope, the key's own
    // rollup read 0, and the request was served — the project cap was never
    // evaluated.
    const response = await get(secret);
    expect(response.status).toBe(429);
    const body = (await response.json()) as ErrorEnvelope;
    expect(body.error.code).toBe("monthly_budget_exceeded");
  });

  test("an ORG that has spent its cap refuses a key under an untouched project", async () => {
    const secret = await seedChainKey();
    await seedBudget("tenant", ORG, 1_000);
    await seedBudget("project", PROJECT, 50);
    await seedRollup("tenant", ORG, 1_000);

    const response = await get(secret);
    expect(response.status).toBe(429);
    expect(((await response.json()) as ErrorEnvelope).error.code).toBe("monthly_budget_exceeded");
  });

  test("a key that has spent ITS rung is refused while the project has room", async () => {
    // The other direction, so the ladder cannot be satisfied by only ever
    // checking the broadest rung either.
    const secret = await seedChainKey();
    await seedBudget("project", PROJECT, 5_000);
    await seedBudget("key", KEY_ID, 100);
    await seedRollup("project", PROJECT, 120);
    await seedRollup("key", KEY_ID, 100);

    expect((await get(secret)).status).toBe(429);
  });

  test("with every rung under its cap the request is served", async () => {
    const secret = await seedChainKey();
    await seedBudget("tenant", ORG, 10_000);
    await seedBudget("project", PROJECT, 5_000);
    await seedBudget("workspace", WORKSPACE, 1_000);
    await seedBudget("key", KEY_ID, 100);
    await seedRollup("tenant", ORG, 9_000);
    await seedRollup("project", PROJECT, 4_000);
    await seedRollup("workspace", WORKSPACE, 900);
    await seedRollup("key", KEY_ID, 10);

    expect((await get(secret)).status).toBe(200);
  });

  test("a key policy CANNOT grant itself more than the org allows", async () => {
    const secret = await seedChainKey();
    // The org ceiling is $100; the key writes itself a $9,999 budget and has
    // spent $150 of it. The key rung is clamped to the org's $100, so its own
    // spend already breaches — even though the ORG rollup is untouched (the
    // spend was recorded against the key alone).
    await seedBudget("tenant", ORG, 100);
    await seedBudget("key", KEY_ID, 9_999);
    await seedRollup("key", KEY_ID, 150);

    const response = await get(secret);
    expect(response.status).toBe(429);
    expect(((await response.json()) as ErrorEnvelope).error.code).toBe("monthly_budget_exceeded");
  });

  test("a scope with NO budget row imposes nothing, however much it has spent", async () => {
    const secret = await seedChainKey();
    await seedBudget("key", KEY_ID, 100);
    await seedRollup("project", PROJECT, 1_000_000);
    expect((await get(secret)).status).toBe(200);
  });

  test("another org's spend never enters this chain's ladder", async () => {
    const secret = await seedChainKey();
    await seedBudget("tenant", ORG, 10);
    await seedRollup("tenant", "tenant_someone_else", 1_000);
    await seedRollup("project", "project_someone_else", 1_000);
    expect((await get(secret)).status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// Defect 2 — the shared counter, serialised by a Durable Object
// ---------------------------------------------------------------------------

describe("the monthly budget counter is a Durable Object, not a D1 read", () => {
  /** A counter key nobody else uses, so a hold never leaks between tests. */
  let unique = 0;
  const freshScope = (): QuotaScopeSelector =>
    new QuotaScopeSelector("project", `hb_burst_${unique++}`);

  test("12 concurrent reservations against a budget affording 3 admit EXACTLY 3", async () => {
    // THE PROPERTY. This is the race a D1 read cannot close: twelve readers see
    // the same `cost_usd` and twelve requests are admitted against a budget
    // with room for three. The DO holds one instance per counter key and runs
    // its methods one at a time, so the twelfth reserve sees the eleven before
    // it.
    const limiter = limiterForEnv(env as never);
    const counterKey = counterKeyForScope(freshScope(), "irrelevant");

    const outcomes = await Promise.all(
      Array.from({ length: 12 }, () => limiter.reserveMonthlyBudget(counterKey, 0, 30, 10)),
    );

    expect(outcomes.filter((o) => o.outcome === "reserved")).toHaveLength(3);
    expect(outcomes.filter((o) => o.outcome === "insufficient")).toHaveLength(9);
  });

  test("committed spend already recorded in D1 counts against the same ledger", async () => {
    const limiter = limiterForEnv(env as never);
    const counterKey = counterKeyForScope(freshScope(), "irrelevant");
    // $28 of the $30 budget is already settled: one $1 hold fits, the next does
    // not, and the third does not either.
    const outcomes = await Promise.all(
      Array.from({ length: 3 }, () => limiter.reserveMonthlyBudget(counterKey, 28, 30, 1)),
    );
    expect(outcomes.filter((o) => o.outcome === "reserved")).toHaveLength(2);
  });

  test("releasing a hold returns the room to the next caller", async () => {
    const limiter = limiterForEnv(env as never);
    const counterKey = counterKeyForScope(freshScope(), "irrelevant");
    const held = await limiter.reserveMonthlyBudget(counterKey, 0, 10, 10);
    expect(held.outcome).toBe("reserved");
    expect((await limiter.reserveMonthlyBudget(counterKey, 0, 10, 1)).outcome).toBe("insufficient");

    if (held.outcome === "reserved") await held.reservation.release();
    expect((await limiter.reserveMonthlyBudget(counterKey, 0, 10, 10)).outcome).toBe("reserved");
  });

  test("the ledger of one scope is not the ledger of another", async () => {
    const limiter = limiterForEnv(env as never);
    const a = counterKeyForScope(freshScope(), "irrelevant");
    const b = counterKeyForScope(freshScope(), "irrelevant");
    expect((await limiter.reserveMonthlyBudget(a, 0, 10, 10)).outcome).toBe("reserved");
    expect((await limiter.reserveMonthlyBudget(b, 0, 10, 10)).outcome).toBe("reserved");
  });

  test("a monthly-token-budget hold does not consume the USD budget of the same key", async () => {
    // Both ledgers live on the DO instance for `key:{id}`. They are different
    // money in different units and must be different fields.
    const limiter = limiterForEnv(env as never);
    const counterKey = counterKeyForScope(new QuotaScopeSelector("key", "hb_units"), "hb_units");
    expect((await limiter.reserveTokenBudget(counterKey, 0, 1_000, 1_000)).outcome).toBe(
      "reserved",
    );
    expect((await limiter.reserveMonthlyBudget(counterKey, 0, 10, 10)).outcome).toBe("reserved");
  });
});

/**
 * MOUNT GATE. Delete the `reserveMonthlyBudget` block from `rateLimit`
 * (`src/ratelimit/middleware.ts`) and this goes red while everything else in
 * the file stays green — the D1 read on its own admits this request.
 */
describe("the budget reservation is MOUNTED in the deployed app", () => {
  test("a request that does not FIT the remaining budget is refused before dispatch", async () => {
    const secret = await seedChainKey();
    await seedBudget("tenant", ORG, 10);
    // $9.50 spent of $10 is UNDER the cap, so the read-based check (step 2)
    // admits it. Only the reservation can refuse it: 9.5 + 1 > 10.
    await seedRollup("tenant", ORG, 9.5);
    vars.GATEWAY_BUDGET_HOLD_USD = "1";

    const response = await get(secret);
    expect(response.status).toBe(429);
    expect(((await response.json()) as ErrorEnvelope).error.code).toBe("monthly_budget_exceeded");
  });

  test("a served request RELEASES its hold, so the next one is not starved", async () => {
    const secret = await seedChainKey();
    await seedBudget("tenant", ORG, 10);
    await seedRollup("tenant", ORG, 8);
    vars.GATEWAY_BUDGET_HOLD_USD = "1";

    // Three sequential requests each fit in the $2 of headroom only because
    // each one lets its hold go on the way out — JS has no `Drop`, so this is
    // `rateLimit`'s `finally`.
    expect((await get(secret)).status).toBe(200);
    expect((await get(secret)).status).toBe(200);
    expect((await get(secret)).status).toBe(200);
  });

  test("no budget policy ⇒ no hold, so an unbudgeted caller is never gated", async () => {
    const secret = await seedChainKey();
    vars.GATEWAY_BUDGET_HOLD_USD = "1000000";
    expect((await get(secret)).status).toBe(200);
  });

  test("a hold size that is not a positive finite number is ignored, not applied", () => {
    expect(budgetHoldUsdFromEnv({})).toBe(DEFAULT_BUDGET_HOLD_USD);
    expect(budgetHoldUsdFromEnv({ GATEWAY_BUDGET_HOLD_USD: "0" })).toBe(DEFAULT_BUDGET_HOLD_USD);
    expect(budgetHoldUsdFromEnv({ GATEWAY_BUDGET_HOLD_USD: "-3" })).toBe(DEFAULT_BUDGET_HOLD_USD);
    expect(budgetHoldUsdFromEnv({ GATEWAY_BUDGET_HOLD_USD: "banana" })).toBe(
      DEFAULT_BUDGET_HOLD_USD,
    );
    expect(budgetHoldUsdFromEnv({ GATEWAY_BUDGET_HOLD_USD: "0.25" })).toBe(0.25);
  });
});
