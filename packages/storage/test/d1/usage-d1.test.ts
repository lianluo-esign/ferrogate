/**
 * The usage/metering capture leg of the main path, against REAL D1.
 *
 * This is where `UsageSink.record` lands. The properties under test are that
 * the three writes are ONE batch (a rollup can never reference a missing
 * attribution row) and that counters accumulate rather than overwrite.
 */
import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import {
  D1UsageLedger,
  type TenantDatabaseHandle,
  type UsageAggregateWrite,
  periodMonthFromUnix,
} from "../../src/index.js";
import { TENANT_A, TENANT_B, resetTenantData, setupDatabases } from "./harness.js";

// 2026-07-15T00:00:00Z — inside a known calendar month so the period key is
// asserted against a literal rather than against the code that produced it.
const NOW = 1_784_073_600;
const PERIOD = "2026-07";

let handleA: TenantDatabaseHandle;
let handleB: TenantDatabaseHandle;

beforeAll(async () => {
  const router = await setupDatabases();
  handleA = await router.forTenant(TENANT_A);
  handleB = await router.forTenant(TENANT_B);
});

beforeEach(async () => {
  await resetTenantData(env.TENANT_DB_A);
  await resetTenantData(env.TENANT_DB_B);
});

function call(overrides: Partial<UsageAggregateWrite> = {}): UsageAggregateWrite {
  return {
    context: { id: "ctx_1", organizationId: "org_1", projectId: "proj_1", apiKeyId: "key_1" },
    logicalModel: "best-reasoning",
    provider: "anthropic",
    promptTokens: 100,
    completionTokens: 40,
    totalTokens: 140,
    costUsd: 0.002,
    isError: false,
    occurredAtUnix: NOW,
    scopes: [
      { scopeType: "tenant", scopeId: TENANT_A },
      { scopeType: "key", scopeId: "key_1" },
    ],
    ...overrides,
  };
}

describe("D1UsageLedger — capture", () => {
  test("the period key is derived from the timestamp, matching the shared helper", () => {
    expect(periodMonthFromUnix(NOW)).toBe(PERIOD);
  });

  test("one call writes the context, the aggregate and every scope's rollup", async () => {
    const ledger = new D1UsageLedger(handleA);
    await ledger.persistUsageAggregate(call());

    const ctx = await handleA.db
      .prepare("SELECT id, organization_id, api_key_id FROM tenant_contexts WHERE id = 'ctx_1'")
      .first<{ id: string; organization_id: string; api_key_id: string }>();
    expect(ctx?.organization_id).toBe("org_1");
    expect(ctx?.api_key_id).toBe("key_1");

    const agg = await handleA.db
      .prepare("SELECT total_tokens FROM usage_aggregate_rollups WHERE tenant_context_id = 'ctx_1'")
      .first<{ total_tokens: number }>();
    expect(agg?.total_tokens).toBe(140);

    const tenantRollup = await ledger.getUsageMonthlyRollup(PERIOD, "tenant", TENANT_A);
    expect(tenantRollup?.promptTokens).toBe(100);
    expect(tenantRollup?.completionTokens).toBe(40);
    expect(tenantRollup?.costUsd).toBeCloseTo(0.002, 10);
    expect(tenantRollup?.requestCount).toBe(1);
    expect(tenantRollup?.errorCount).toBe(0);

    const keyRollup = await ledger.getUsageMonthlyRollup(PERIOD, "key", "key_1");
    expect(keyRollup?.requestCount).toBe(1);
  });

  test("repeated calls ACCUMULATE rather than overwrite", async () => {
    const ledger = new D1UsageLedger(handleA);
    await ledger.persistUsageAggregate(call());
    await ledger.persistUsageAggregate(call());
    await ledger.persistUsageAggregate(call({ isError: true }));

    const rollup = await ledger.getUsageMonthlyRollup(PERIOD, "tenant", TENANT_A);
    expect(rollup?.totalTokens).toBe(420);
    expect(rollup?.requestCount).toBe(3);
    expect(rollup?.errorCount).toBe(1);
    expect(rollup?.costUsd).toBeCloseTo(0.006, 10);
  });

  test("CONCURRENT captures lose no request", async () => {
    const ledger = new D1UsageLedger(handleA);
    await Promise.all(Array.from({ length: 25 }, () => ledger.persistUsageAggregate(call())));
    const rollup = await ledger.getUsageMonthlyRollup(PERIOD, "tenant", TENANT_A);
    expect(rollup?.requestCount).toBe(25);
    expect(rollup?.totalTokens).toBe(25 * 140);
  });

  test("different months are different rows", async () => {
    const ledger = new D1UsageLedger(handleA);
    await ledger.persistUsageAggregate(call());
    // 2026-08-15T00:00:00Z
    await ledger.persistUsageAggregate(call({ occurredAtUnix: 1_786_752_000 }));

    expect((await ledger.getUsageMonthlyRollup(PERIOD, "tenant", TENANT_A))?.requestCount).toBe(1);
    expect((await ledger.getUsageMonthlyRollup("2026-08", "tenant", TENANT_A))?.requestCount).toBe(
      1,
    );
  });

  test("a call folded into NO scope is refused, because no budget check could see it", async () => {
    const ledger = new D1UsageLedger(handleA);
    await expect(ledger.persistUsageAggregate(call({ scopes: [] }))).rejects.toThrow(
      /at least one scope/,
    );
  });

  test("an invalid scope_type is rejected by the schema CHECK, not silently stored", async () => {
    const ledger = new D1UsageLedger(handleA);
    await expect(
      ledger.persistUsageAggregate(
        // Deliberately bypassing the TS union to hit the DB constraint: the
        // CHECK is the second line of defence, and a typo'd scope would
        // otherwise create a rollup no budget check ever reads.
        call({ scopes: [{ scopeType: "organisation" as never, scopeId: "x" }] }),
      ),
    ).rejects.toThrow();
    // The batch is atomic, so the CONTEXT row did not land either.
    expect(
      await handleA.db.prepare("SELECT id FROM tenant_contexts WHERE id = 'ctx_1'").first(),
    ).toBeNull();
  });

  test("usage is per-tenant-database", async () => {
    await new D1UsageLedger(handleA).persistUsageAggregate(call());
    expect(
      await new D1UsageLedger(handleB).getUsageMonthlyRollup(PERIOD, "tenant", TENANT_A),
    ).toBeUndefined();
  });

  test("an unknown rollup reads back as undefined", async () => {
    const ledger = new D1UsageLedger(handleA);
    expect(await ledger.getUsageMonthlyRollup(PERIOD, "project", "nope")).toBeUndefined();
  });
});

/**
 * PLATFORM LIMIT PIN — kept as a PORT-TODO in `src/d1/usage-d1.ts`.
 *
 * The Rust/Postgres shape put the `billing_events` exactly-once claim and this
 * usage accumulate in ONE transaction. On D1 they live in two different
 * databases (control vs tenant) and there is no cross-database transaction, no
 * two-phase commit, and no distributed-transaction API. These tests pin BOTH
 * halves of the honest approximation so it cannot silently be described as
 * exactly-once.
 */
describe("D1UsageLedger — the cross-database platform limit", () => {
  test("a batch may not mix statements from two databases", async () => {
    // If workerd ever grew a cross-database batch, this expectation flips and
    // the PORT-TODO in src/d1/usage-d1.ts becomes closable.
    await expect(
      env.TENANT_DB_A.batch([
        env.TENANT_DB_A.prepare("DELETE FROM usage_monthly_rollups WHERE id = 'x'"),
        env.CONTROL_DB.prepare("DELETE FROM billing_events WHERE billing_event_id = 'x'"),
      ]),
    ).rejects.toThrow();
  });

  test("the accumulate is ADDITIVE, so replaying one settled call double-counts it", async () => {
    const ledger = new D1UsageLedger(handleA);
    // Byte-identical write, twice — exactly what an at-least-once delivery does.
    await ledger.persistUsageAggregate(call());
    await ledger.persistUsageAggregate(call());
    const rollup = await ledger.getUsageMonthlyRollup(PERIOD, "tenant", TENANT_A);
    // NOT 140. This is the documented non-idempotence: de-duplication is the
    // caller's job via D1BillingEventLedger's control-database claim.
    expect(rollup?.totalTokens).toBe(280);
    expect(rollup?.requestCount).toBe(2);
  });
});

/**
 * `sum_api_key_committed_tokens` (#330) — the `committed` operand of
 * `RateLimiter.reserveTokenBudget`, which enforces
 * `api_keys.monthly_token_budget`.
 *
 * The number has to be RIGHT in a specific way: it must include every model and
 * provider the key spent through, exclude other keys, and answer `0` (not
 * `undefined`) for a key with no usage. A caller that had to tell "no rows"
 * from "no tokens" apart would eventually read the absent case as unlimited.
 */
describe("D1UsageLedger — sumApiKeyCommittedTokens", () => {
  test("answers 0 for a key with no usage at all", async () => {
    expect(await new D1UsageLedger(handleA).sumApiKeyCommittedTokens("key_never_used")).toBe(0);
  });

  test("sums every (model, provider) aggregate attributed to the key", async () => {
    const ledger = new D1UsageLedger(handleA);
    await ledger.persistUsageAggregate(call());
    await ledger.persistUsageAggregate(
      call({ logicalModel: "fast-chat", provider: "openai", totalTokens: 60 }),
    );
    // 140 + 60. A per-(context, model, provider) breakdown that summed only one
    // row would answer 140 and silently under-charge the budget.
    expect(await ledger.sumApiKeyCommittedTokens("key_1")).toBe(200);
  });

  test("accumulates across repeated calls on the same aggregate row", async () => {
    const ledger = new D1UsageLedger(handleA);
    await ledger.persistUsageAggregate(call());
    await ledger.persistUsageAggregate(call());
    expect(await ledger.sumApiKeyCommittedTokens("key_1")).toBe(280);
  });

  test("excludes another API key's spend in the same tenant database", async () => {
    const ledger = new D1UsageLedger(handleA);
    await ledger.persistUsageAggregate(call());
    await ledger.persistUsageAggregate(
      call({
        context: { id: "ctx_2", organizationId: "org_1", apiKeyId: "key_2" },
        totalTokens: 999,
        scopes: [{ scopeType: "key", scopeId: "key_2" }],
      }),
    );
    // The control that makes the join meaningful: `key_2`'s 999 tokens are in
    // the SAME table and are excluded purely by `tenant_contexts.api_key_id`.
    expect(await ledger.sumApiKeyCommittedTokens("key_1")).toBe(140);
    expect(await ledger.sumApiKeyCommittedTokens("key_2")).toBe(999);
  });

  test("is scoped to the tenant's own database", async () => {
    await new D1UsageLedger(handleA).persistUsageAggregate(call());
    expect(await new D1UsageLedger(handleB).sumApiKeyCommittedTokens("key_1")).toBe(0);
  });

  test("ignores an aggregate whose context carries no api key", async () => {
    const ledger = new D1UsageLedger(handleA);
    await ledger.persistUsageAggregate(
      call({
        context: { id: "ctx_anon", organizationId: "org_1" },
        totalTokens: 500,
        scopes: [{ scopeType: "tenant", scopeId: TENANT_A }],
      }),
    );
    await ledger.persistUsageAggregate(call());
    expect(await ledger.sumApiKeyCommittedTokens("key_1")).toBe(140);
  });
});
