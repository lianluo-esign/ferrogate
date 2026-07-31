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
