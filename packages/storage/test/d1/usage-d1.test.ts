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
  MemoryMetadataRollupStore,
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

/**
 * `usage_metadata_rollups` (#171/#226) — the ONLY aggregation dimension
 * orthogonal to the tenant/project/workspace/key scope chain, and therefore the
 * only way to answer "what did feature X / customer Y cost".
 *
 * The interesting claim is not that a row appears. It is that the metadata
 * attribution and the spend it explains are ONE commit: a world where the
 * monthly rollup landed and the metadata breakdown did not is a world where the
 * breakdown silently disagrees with the invoice, and nothing surfaces it.
 */
describe("D1UsageLedger — metadata rollups", () => {
  const metadata = new Map([
    ["feature", "search"],
    ["customer", "acme"],
  ]);

  test("one settled call increments ONE row per metadata pair", async () => {
    const ledger = new D1UsageLedger(handleA);
    await ledger.persistUsageAggregate(call({ metadata }));
    const rows = await ledger.listUsageMetadataRollups("feature", "org_1");
    expect(rows).toHaveLength(1);
    expect(rows[0]?.metadataValue).toBe("search");
    expect(rows[0]?.totalTokens).toBe(140);
    expect(rows[0]?.promptTokens).toBe(100);
    expect(rows[0]?.completionTokens).toBe(40);
    expect(rows[0]?.costUsd).toBeCloseTo(0.002, 10);
    expect(rows[0]?.requestCount).toBe(1);
    expect(rows[0]?.errorCount).toBe(0);
    expect(rows[0]?.periodMonth).toBe(PERIOD);
    // The second pair is its own row under its own key.
    const customers = await ledger.listUsageMetadataRollups("customer", "org_1");
    expect(customers.map((row) => row.metadataValue)).toEqual(["acme"]);
  });

  test("accumulates additively across calls, like every other counter", async () => {
    const ledger = new D1UsageLedger(handleA);
    await ledger.persistUsageAggregate(call({ metadata }));
    await ledger.persistUsageAggregate(call({ metadata, isError: true }));
    const [row] = await ledger.listUsageMetadataRollups("feature", "org_1");
    expect(row?.totalTokens).toBe(280);
    expect(row?.requestCount).toBe(2);
    expect(row?.errorCount).toBe(1);
  });

  test("a call with no metadata writes no metadata rows at all", async () => {
    const ledger = new D1UsageLedger(handleA);
    await ledger.persistUsageAggregate(call());
    expect(await ledger.listUsageMetadataRollups("feature")).toEqual([]);
  });

  test("orders period ASC, value ASC — and AGREES with the in-memory twin", async () => {
    // The two backends are asserted to be interchangeable specifications of the
    // same behavior, so an ORDER BY that disagrees with the reference store is a
    // real divergence, not a cosmetic one. Two periods are needed to see it: a
    // single-period fixture cannot tell ASC from DESC.
    const ledger = new D1UsageLedger(handleA);
    const june = 1_781_395_200; // 2026-06-10
    await ledger.persistUsageAggregate(
      call({ metadata: new Map([["feature", "search"]]), occurredAtUnix: june }),
    );
    await ledger.persistUsageAggregate(
      call({ metadata: new Map([["feature", "chat"]]), occurredAtUnix: NOW }),
    );
    await ledger.persistUsageAggregate(
      call({ metadata: new Map([["feature", "aaa"]]), occurredAtUnix: NOW }),
    );
    const durable = await ledger.listUsageMetadataRollups("feature", "org_1");
    expect(durable.map((r) => `${r.periodMonth}/${r.metadataValue}`)).toEqual([
      "2026-06/search",
      "2026-07/aaa",
      "2026-07/chat",
    ]);

    const memory = new MemoryMetadataRollupStore();
    const delta = {
      promptTokens: 100,
      completionTokens: 40,
      totalTokens: 140,
      costUsd: 0.002,
      isError: false,
    };
    memory.incrementUsageMetadataRollups(
      "org_1",
      new Map([["feature", "search"]]),
      periodMonthFromUnix(june),
      delta,
      june,
    );
    for (const value of ["chat", "aaa"]) {
      memory.incrementUsageMetadataRollups(
        "org_1",
        new Map([["feature", value]]),
        PERIOD,
        delta,
        NOW,
      );
    }
    expect(
      memory
        .listUsageMetadataRollups("feature", "org_1")
        .map((r) => `${r.periodMonth}/${r.metadataValue}`),
    ).toEqual(durable.map((r) => `${r.periodMonth}/${r.metadataValue}`));
  });

  test("different values of one key are different rows", async () => {
    const ledger = new D1UsageLedger(handleA);
    await ledger.persistUsageAggregate(call({ metadata: new Map([["feature", "search"]]) }));
    await ledger.persistUsageAggregate(call({ metadata: new Map([["feature", "chat"]]) }));
    const rows = await ledger.listUsageMetadataRollups("feature", "org_1");
    // ORDER BY period_month DESC, metadata_value ASC.
    expect(rows.map((row) => row.metadataValue)).toEqual(["chat", "search"]);
  });

  test("the organization filter is a tenancy boundary, not a convenience", async () => {
    const ledger = new D1UsageLedger(handleA);
    await ledger.persistUsageAggregate(call({ metadata: new Map([["feature", "search"]]) }));
    await ledger.persistUsageAggregate(
      call({
        context: { id: "ctx_other", organizationId: "org_2", apiKeyId: "key_9" },
        metadata: new Map([["feature", "secret-project"]]),
      }),
    );
    // org_1 must not be able to see org_2's breakdown...
    expect(
      (await ledger.listUsageMetadataRollups("feature", "org_1")).map((r) => r.metadataValue),
    ).toEqual(["search"]);
    // ...while the unfiltered platform-operator read sees both.
    expect((await ledger.listUsageMetadataRollups("feature")).map((r) => r.metadataValue)).toEqual([
      "search",
      "secret-project",
    ]);
  });

  test('an org-less context is the distinct "" organization, not a NULL that collides', async () => {
    const ledger = new D1UsageLedger(handleA);
    await ledger.persistUsageAggregate(
      call({
        context: { id: "ctx_legacy" },
        metadata: new Map([["feature", "search"]]),
        totalTokens: 7,
      }),
    );
    await ledger.persistUsageAggregate(call({ metadata: new Map([["feature", "search"]]) }));
    const legacy = await ledger.listUsageMetadataRollups("feature", "");
    const scoped = await ledger.listUsageMetadataRollups("feature", "org_1");
    expect(legacy).toHaveLength(1);
    expect(scoped).toHaveLength(1);
    // Two DIFFERENT rows for the same key/value: the org is part of the id.
    expect(legacy[0]?.totalTokens).toBe(7);
    expect(scoped[0]?.totalTokens).toBe(140);
  });

  test("metadata rollups ride the SAME batch as the spend (statement count)", async () => {
    // The mutation this test exists to catch is moving the metadata upsert into
    // a second `batch()`. One `batch()` carrying context + aggregate + 2 scopes
    // + 2 metadata pairs = 6 statements; a split writes 4 then 2.
    const batchSizes: number[] = [];
    const spy = new Proxy(handleA.db, {
      get(target, property, receiver) {
        if (property === "batch") {
          return (statements: D1PreparedStatement[]) => {
            batchSizes.push(statements.length);
            return target.batch(statements);
          };
        }
        return Reflect.get(target, property, receiver) as unknown;
      },
    });
    const spied: TenantDatabaseHandle = { ...handleA, db: spy as D1Database };
    await new D1UsageLedger(spied).persistUsageAggregate(call({ metadata }));
    expect(batchSizes).toEqual([6]);
  });

  test("a rejected spend rolls the metadata attribution back with it", async () => {
    // The independent half of the same claim, and the one that states the
    // CONSEQUENCE: an invalid `scope_type` violates the CHECK on
    // `usage_monthly_rollups`, so the batch is rejected. A metadata write in a
    // separate batch survives that rejection and leaves attribution for spend
    // that was never recorded.
    await expect(
      new D1UsageLedger(handleA).persistUsageAggregate(
        call({
          metadata: new Map([["feature", "doomed"]]),
          scopes: [{ scopeType: "not_a_scope" as never, scopeId: "x" }],
        }),
      ),
    ).rejects.toThrow();
    expect(
      (await new D1UsageLedger(handleA).listUsageMetadataRollups("feature")).map(
        (row) => row.metadataValue,
      ),
    ).not.toContain("doomed");
  });
});
