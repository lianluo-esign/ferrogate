/**
 * `src/batch/governance.ts` — the admission ladder #698 exists to add, executed.
 *
 * ## Why this file had to be written before the slice could ship
 *
 * `createBatchGovernance` is the ONLY reason the issue is more than "run the
 * JSONL", and it was reached by zero tests in the whole gateway suite: its one
 * caller is `resolveDeps`'s default `governanceFor`, and every test in
 * `batch-executor.test.ts` injects a `governance:` stub. A probe that threw on
 * the function's first statement was never hit by any of the 185 files. So
 * `spent >= limit` could have been `<=`, the fail-closed
 * `quota_resolution_unavailable` arms could have returned ALLOWED, and
 * `batchScopeChain` could have dropped the key and the project, with the whole
 * repo green.
 *
 * ## What is real here and what is a seam
 *
 * The policy and residency sources are the PRODUCTION ones resolved from `env`
 * — with no `CONTROL_DB` bound they read `GATEWAY_QUOTA_POLICIES` /
 * `GATEWAY_RESIDENCY_POLICIES`, which is the documented var posture, so
 * `resolveEffectiveQuota`, `monthlyBudgetCharges` and `residencyViolations` all
 * run for real. Only `SpendSource` is injected, because the alternative is a
 * tenant D1 with `usage_monthly_rollups` rows and the thing under test is the
 * LADDER, not the SQL (`ratelimit/`'s own suites own that).
 *
 * Every assertion below is written so that inverting the rung it covers turns
 * it red; the ones where that is not obvious say so in a comment.
 */
import type { StoredBatch } from "@ferrogate/storage";
import { describe, expect, test } from "vitest";
import { batchScopeChain, createBatchGovernance } from "../src/batch/index.js";
import type { PhysicalRoute } from "../src/inference/ports.js";
import type { SpendSource } from "../src/ratelimit/index.js";

const TENANT = "tenant_gov";
const KEY = "key_gov";
const PROJECT = "proj_gov";
const NOW = 1_700_000_000;

function batchRow(overrides: Partial<StoredBatch> = {}): StoredBatch {
  return {
    id: "batch_gov",
    tenantId: TENANT,
    inputFileId: "file-in",
    endpoint: "/v1/chat/completions",
    completionWindow: "24h",
    status: "validating",
    requestCounts: { total: 0, completed: 0, failed: 0 },
    metadata: {},
    createdAtUnix: NOW,
    expiresAtUnix: NOW + 24 * 60 * 60,
    apiKeyId: KEY,
    projectId: PROJECT,
    ...overrides,
  };
}

const ROUTE: PhysicalRoute = {
  logicalModel: "demo-chat",
  provider: "openai",
  providerModel: "gpt-4o-mini",
  providerKind: "openai-compatible",
  enabled: true,
  baseUrl: "https://upstream.test/v1",
  region: "us-east-1",
};

interface SpendCall {
  readonly kind: string;
  readonly id: string;
  readonly periodMonth: string;
}

function spendSource(
  options: {
    readonly spentUsd?: number | undefined;
    readonly spendFails?: boolean | undefined;
    readonly walletCredits?: number | null | undefined;
    readonly walletFails?: boolean | undefined;
  } = {},
): { source: SpendSource; calls: SpendCall[] } {
  const calls: SpendCall[] = [];
  return {
    calls,
    source: {
      async committedSpendUsd(kind, id, periodMonth) {
        calls.push({ kind, id, periodMonth });
        if (options.spendFails === true) return { ok: false, detail: "d1 unavailable" };
        return { ok: true, committedSpendUsd: options.spentUsd ?? 0 };
      },
      async walletBalanceCredits() {
        if (options.walletFails === true) return { ok: false, detail: "wallets unreadable" };
        return {
          ok: true,
          availableCredits: options.walletCredits === undefined ? null : options.walletCredits,
        };
      },
    },
  };
}

/** A var-posture env: no CONTROL_DB, so both sources read their JSON vars. */
function env(vars: Record<string, string> = {}): Record<string, unknown> {
  return { ...vars };
}

function governance(
  envVars: Record<string, string>,
  spend: SpendSource,
  batch: StoredBatch = batchRow(),
) {
  return createBatchGovernance(env(envVars), batch, {
    spend: async () => spend,
    nowUnix: () => NOW,
  });
}

const TENANT_BUDGET = JSON.stringify([
  { scope_type: "tenant", scope_id: TENANT, monthly_budget_usd: 10 },
]);

describe("batchScopeChain — the only surviving record of WHO is spending", () => {
  test("carries the key and the project, and drops empties rather than sending ''", () => {
    expect(batchScopeChain(batchRow())).toEqual({
      tenantId: TENANT,
      projectId: PROJECT,
      keyId: KEY,
    });
    // An empty string is a REAL value to a scope lookup — it would resolve a
    // policy row keyed `key:` instead of falling back to the tenant rung.
    expect(batchScopeChain(batchRow({ apiKeyId: "", projectId: "" }))).toEqual({
      tenantId: TENANT,
    });
    expect(batchScopeChain(batchRow({ apiKeyId: undefined, projectId: undefined }))).toEqual({
      tenantId: TENANT,
    });
  });
});

describe("admitSpend — the monthly budget rung", () => {
  test("allows a tenant inside its budget and charges the RIGHT scope", async () => {
    const spend = spendSource({ spentUsd: 4 });
    const result = await governance(
      { GATEWAY_QUOTA_POLICIES: TENANT_BUDGET },
      spend.source,
    ).admitSpend();

    expect(result).toEqual({ ok: true });
    // The rung was actually read — an `admitSpend` that returned ok without
    // consulting the rollup would leave this empty.
    expect(spend.calls).toEqual([{ kind: "tenant", id: TENANT, periodMonth: "2023-11" }]);
  });

  test("refuses AT the limit, not past it — the request path's `>=`", async () => {
    const atLimit = await governance(
      { GATEWAY_QUOTA_POLICIES: TENANT_BUDGET },
      spendSource({ spentUsd: 10 }).source,
    ).admitSpend();
    expect(atLimit).toMatchObject({ ok: false, code: "monthly_budget_exceeded" });

    // And a cent under is still admitted, so the assertion above is pinning the
    // boundary rather than "any spend refuses".
    const under = await governance(
      { GATEWAY_QUOTA_POLICIES: TENANT_BUDGET },
      spendSource({ spentUsd: 9.99 }).source,
    ).admitSpend();
    expect(under).toEqual({ ok: true });
  });

  test("enforces the KEY's budget, which only the persisted scope chain can reach", async () => {
    // The rung that a tenant-only chain silently degrades to nothing: the key
    // is over its own $1 cap while the tenant is far inside its $10 one.
    const policies = JSON.stringify([
      { scope_type: "tenant", scope_id: TENANT, monthly_budget_usd: 10 },
      { scope_type: "key", scope_id: KEY, monthly_budget_usd: 1 },
    ]);
    const spend = spendSource({ spentUsd: 2 });

    const result = await governance(
      { GATEWAY_QUOTA_POLICIES: policies },
      spend.source,
    ).admitSpend();

    expect(result).toMatchObject({ ok: false, code: "monthly_budget_exceeded" });
    expect(spend.calls.map((call) => `${call.kind}:${call.id}`)).toContain(`key:${KEY}`);
  });

  test("a disabled scope anywhere in the chain is a hard deny", async () => {
    const result = await governance(
      {
        GATEWAY_QUOTA_POLICIES: JSON.stringify([
          { scope_type: "tenant", scope_id: TENANT, monthly_budget_usd: 10, enabled: false },
        ]),
      },
      spendSource().source,
    ).admitSpend();

    expect(result).toMatchObject({ ok: false, code: "quota_scope_disabled" });
  });
});

describe("admitSpend — the prepaid wallet rung", () => {
  test("no wallet is never a denial; a wallet at zero is", async () => {
    const noWallet = await governance(
      { GATEWAY_QUOTA_POLICIES: TENANT_BUDGET },
      spendSource({ walletCredits: null }).source,
    ).admitSpend();
    expect(noWallet).toEqual({ ok: true });

    const exhausted = await governance(
      { GATEWAY_QUOTA_POLICIES: TENANT_BUDGET },
      spendSource({ walletCredits: 0 }).source,
    ).admitSpend();
    expect(exhausted).toMatchObject({ ok: false, code: "wallet_balance_exhausted" });

    const funded = await governance(
      { GATEWAY_QUOTA_POLICIES: TENANT_BUDGET },
      spendSource({ walletCredits: 5 }).source,
    ).admitSpend();
    expect(funded).toEqual({ ok: true });
  });
});

describe("admitSpend — fail CLOSED, because an unreadable rollup proves nothing", () => {
  test("a spend-source construction failure refuses instead of admitting", async () => {
    const gate = createBatchGovernance(env({ GATEWAY_QUOTA_POLICIES: TENANT_BUDGET }), batchRow(), {
      spend: async () => {
        throw new Error("tenant database unreachable");
      },
      nowUnix: () => NOW,
    });

    expect(await gate.admitSpend()).toMatchObject({
      ok: false,
      code: "quota_resolution_unavailable",
    });
  });

  test("an unreadable monthly rollup refuses", async () => {
    const result = await governance(
      { GATEWAY_QUOTA_POLICIES: TENANT_BUDGET },
      spendSource({ spendFails: true }).source,
    ).admitSpend();
    expect(result).toMatchObject({ ok: false, code: "quota_resolution_unavailable" });
  });

  test("an unreadable wallet refuses", async () => {
    const result = await governance(
      { GATEWAY_QUOTA_POLICIES: TENANT_BUDGET },
      spendSource({ walletFails: true }).source,
    ).admitSpend();
    expect(result).toMatchObject({ ok: false, code: "quota_resolution_unavailable" });
  });
});

describe("admitRoute — #681 residency, off the request path", () => {
  test("a route outside the tenant's allowed regions may not carry its prompts", async () => {
    const gate = governance(
      {
        GATEWAY_RESIDENCY_POLICIES: JSON.stringify([
          { tenant_id: TENANT, residency_regions: ["eu-west-1"] },
        ]),
      },
      spendSource().source,
    );

    expect(await gate.admitRoute(ROUTE)).toMatchObject({
      ok: false,
      code: "residency_policy_not_satisfiable",
    });
    // The SAME route inside the allowlist passes, so the refusal above is the
    // policy talking and not a blanket deny.
    expect(await gate.admitRoute({ ...ROUTE, region: "eu-west-1" })).toEqual({ ok: true });
  });

  test("a tenant with no policy is unconstrained", async () => {
    const gate = governance({}, spendSource().source);
    expect(await gate.admitRoute(ROUTE)).toEqual({ ok: true });
  });

  test("an UNREADABLE policy refuses — 'we could not tell' is not permission", async () => {
    const gate = governance(
      {
        GATEWAY_RESIDENCY_POLICIES: JSON.stringify([
          // A non-string region is refused by the parser rather than dropped.
          { tenant_id: TENANT, residency_regions: ["eu-west-1", 3] },
        ]),
      },
      spendSource().source,
    );

    expect(await gate.admitRoute(ROUTE)).toMatchObject({
      ok: false,
      code: "residency_policy_unavailable",
    });
  });
});
