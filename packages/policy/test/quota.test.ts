import { describe, expect, test } from "vitest";
import {
  type QuotaScopeKind,
  QuotaScopeSelector,
  type StoredPlan,
  type StoredQuotaPolicy,
  allowsModel,
  isDenied,
  resolveEffectiveQuota,
} from "../src/index.js";

function policy(
  scopeType: QuotaScopeKind,
  scopeId: string,
  modelAllowlist: string[],
  rpmLimit: number | undefined,
  tpmLimit: number | undefined,
  monthlyBudgetUsd: number | undefined,
  enabled: boolean,
  extra: Partial<StoredQuotaPolicy> = {},
): StoredQuotaPolicy {
  return {
    id: `${scopeType}:${scopeId}`,
    scopeType,
    scopeId,
    modelAllowlist,
    rpmLimit,
    tpmLimit,
    monthlyBudgetUsd,
    alertThresholdPcts: [],
    enabled,
    createdAtUnix: 1,
    updatedAtUnix: 1,
    ...extra,
  };
}

function egressPolicy(
  scopeType: QuotaScopeKind,
  scopeId: string,
  monthlyEgressBytesBudget: number | undefined,
  downloadRpmLimit: number | undefined,
): StoredQuotaPolicy {
  return policy(scopeType, scopeId, [], undefined, undefined, undefined, true, {
    monthlyEgressBytesBudget,
    downloadRpmLimit,
  });
}

function lookupFrom(policies: StoredQuotaPolicy[]) {
  const map = new Map<string, StoredQuotaPolicy>();
  for (const p of policies) map.set(`${p.scopeType}:${p.scopeId}`, p);
  return (kind: QuotaScopeKind, id: string) => map.get(`${kind}:${id}`);
}

function samplePlan(): StoredPlan {
  return {
    id: "plan-pro",
    name: "Pro",
    slug: "pro",
    mcpEnabled: true,
    selfHostedWorkersEnabled: true,
    adminConsoleSeats: 5,
    defaultModelAllowlist: ["fast-chat", "smart-chat"],
    defaultRpmLimit: 600,
    defaultTpmLimit: 100_000,
    defaultMonthlyBudgetUsd: 250,
    defaultAgentCostBudgetUsd: 180,
    createdAtUnix: 1,
    updatedAtUnix: 1,
    assetHostingEnabled: true,
    defaultAssetStorageQuotaBytes: 1_000_000,
    defaultAssetMaxObjectBytes: 250_000,
    extensionToolsEnabled: true,
    defaultMonthlyEgressBytesBudget: 5_000_000,
    defaultDownloadRpmLimit: 120,
  };
}

describe("resolveEffectiveQuota", () => {
  test("missing policy everywhere is unrestricted", () => {
    const q = resolveEffectiveQuota(
      { tenantId: "t1", projectId: "p1", workspaceId: "w1", keyId: "k1" },
      lookupFrom([]),
    );
    expect(isDenied(q)).toBe(false);
    expect(q.modelAllowlist).toBeUndefined();
    expect(q.rpmLimit).toBeUndefined();
    expect(allowsModel(q, "anything")).toBe(true);
  });

  test("nearest scope overrides but cannot exceed an ancestor cap (min-across)", () => {
    const raise = resolveEffectiveQuota(
      { tenantId: "t1", workspaceId: "w1" },
      lookupFrom([
        policy("tenant", "t1", [], 1_000, undefined, undefined, true),
        policy("workspace", "w1", [], 5_000, undefined, undefined, true),
      ]),
    );
    expect(raise.rpmLimit).toBe(1_000);

    const tighten = resolveEffectiveQuota(
      { tenantId: "t1", workspaceId: "w1" },
      lookupFrom([
        policy("tenant", "t1", [], 1_000, undefined, undefined, true),
        policy("workspace", "w1", [], 200, undefined, undefined, true),
      ]),
    );
    expect(tighten.rpmLimit).toBe(200);
  });

  test("model allowlist is the intersection across scopes", () => {
    const q = resolveEffectiveQuota(
      { tenantId: "t1", keyId: "k1" },
      lookupFrom([
        policy(
          "tenant",
          "t1",
          ["fast-chat", "smart-chat", "vision"],
          undefined,
          undefined,
          undefined,
          true,
        ),
        policy("key", "k1", ["fast-chat", "vision"], undefined, undefined, undefined, true),
      ]),
    );
    expect(allowsModel(q, "fast-chat")).toBe(true);
    expect(allowsModel(q, "vision")).toBe(true);
    expect(allowsModel(q, "smart-chat")).toBe(false);
    expect(q.modelAllowlist).toHaveLength(2);
  });

  test("a contradictory intersection denies every model", () => {
    const q = resolveEffectiveQuota(
      { tenantId: "t1", keyId: "k1" },
      lookupFrom([
        policy("tenant", "t1", ["fast-chat"], undefined, undefined, undefined, true),
        policy("key", "k1", ["smart-chat"], undefined, undefined, undefined, true),
      ]),
    );
    expect(allowsModel(q, "fast-chat")).toBe(false);
    expect(allowsModel(q, "smart-chat")).toBe(false);
  });

  test("a disabled policy anywhere in the chain is a hard deny", () => {
    const q = resolveEffectiveQuota(
      { tenantId: "t1", projectId: "p1" },
      lookupFrom([
        policy("tenant", "t1", [], 1_000, undefined, undefined, true),
        policy("project", "p1", [], undefined, undefined, undefined, false),
      ]),
    );
    expect(isDenied(q)).toBe(true);
    expect(q.deniedBy).toBe("project");
  });

  test("winning scope recorded per dimension; rpm and tpm winners can differ", () => {
    const q = resolveEffectiveQuota(
      { tenantId: "t1", workspaceId: "w1", keyId: "k1" },
      lookupFrom([
        policy("tenant", "t1", [], 1_000, 10_000, undefined, true),
        policy("workspace", "w1", [], 200, 50_000, undefined, true),
        policy("key", "k1", [], 500, 5_000, undefined, true),
      ]),
    );
    expect(q.rpmLimit).toBe(200);
    expect(q.rpmLimitScope?.equals(new QuotaScopeSelector("workspace", "w1"))).toBe(true);
    expect(q.tpmLimit).toBe(5_000);
    expect(q.tpmLimitScope?.equals(new QuotaScopeSelector("key", "k1"))).toBe(true);
  });

  test("a tie between a broader scope and the key is awarded to the key", () => {
    const q = resolveEffectiveQuota(
      { tenantId: "t1", keyId: "k1" },
      lookupFrom([
        policy("tenant", "t1", [], 100, undefined, 10, true),
        policy("key", "k1", [], 100, undefined, 10, true),
      ]),
    );
    expect(q.rpmLimitScope?.equals(new QuotaScopeSelector("key", "k1"))).toBe(true);
    expect(q.monthlyBudgetScope?.equals(new QuotaScopeSelector("key", "k1"))).toBe(true);
  });

  test("counter_key is namespaced for every scope including key (cross-tenant DoS guard)", () => {
    expect(new QuotaScopeSelector("key", "k1").counterKey("vk-abc")).toBe("key:vk-abc");
    expect(new QuotaScopeSelector("workspace", "w1").counterKey("vk-abc")).toBe("workspace:w1");
    expect(new QuotaScopeSelector("tenant", "t1").counterKey("vk-abc")).toBe("tenant:t1");
    expect(new QuotaScopeSelector("project", "p1").counterKey("vk-abc")).toBe("project:p1");
    // A virtual key id "tenant:victim" hashes to "key:tenant:victim", never "tenant:victim".
    expect(new QuotaScopeSelector("key", "k1").counterKey("tenant:victim")).toBe(
      "key:tenant:victim",
    );
    expect(new QuotaScopeSelector("key", "k1").counterKey("tenant:victim")).not.toBe(
      new QuotaScopeSelector("tenant", "t1").counterKey("anything"),
    );
  });

  test("an absent scope in the request chain is simply skipped", () => {
    const q = resolveEffectiveQuota(
      { tenantId: "t1", keyId: "k1" },
      lookupFrom([
        policy("tenant", "t1", [], 100, undefined, undefined, true),
        policy("workspace", "w1", [], 1, undefined, undefined, true),
      ]),
    );
    expect(q.rpmLimit).toBe(100);
  });

  test("plan supplies floors keyed on the tenant scope when no policy sets them", () => {
    const q = resolveEffectiveQuota({ tenantId: "t1", keyId: "k1" }, lookupFrom([]), samplePlan());
    expect(q.rpmLimit).toBe(600);
    expect(q.tpmLimit).toBe(100_000);
    expect(q.monthlyBudgetUsd).toBe(250);
    const tenant = new QuotaScopeSelector("tenant", "t1");
    expect(q.rpmLimitScope?.equals(tenant)).toBe(true);
    expect(q.monthlyBudgetScope?.equals(tenant)).toBe(true);
    expect(allowsModel(q, "fast-chat")).toBe(true);
    expect(allowsModel(q, "vision")).toBe(false);
  });

  test("plan defaults are overridden per-dimension by an explicit policy", () => {
    const q = resolveEffectiveQuota(
      { tenantId: "t1" },
      lookupFrom([policy("tenant", "t1", [], 50, undefined, 10, true)]),
      samplePlan(),
    );
    expect(q.rpmLimit).toBe(50);
    expect(q.monthlyBudgetUsd).toBe(10);
    // tpm + allowlist untouched by the policy → plan defaults still apply.
    expect(q.tpmLimit).toBe(100_000);
    expect(allowsModel(q, "fast-chat")).toBe(true);
    expect(allowsModel(q, "vision")).toBe(false);
  });

  test("#428 agent-cost budget: min-across-the-chain, then plan default, then explicit override", () => {
    const merged = resolveEffectiveQuota(
      { tenantId: "t1", keyId: "k1" },
      lookupFrom([
        policy("tenant", "t1", [], undefined, undefined, undefined, true, {
          agentCostBudgetUsd: 500,
        }),
        policy("key", "k1", [], undefined, undefined, undefined, true, { agentCostBudgetUsd: 120 }),
      ]),
    );
    expect(merged.agentCostBudgetUsd).toBe(120);
    expect(merged.agentCostBudgetScope?.equals(new QuotaScopeSelector("key", "k1"))).toBe(true);

    const planned = resolveEffectiveQuota({ tenantId: "t1" }, lookupFrom([]), samplePlan());
    expect(planned.agentCostBudgetUsd).toBe(180);
    expect(planned.agentCostBudgetScope?.equals(new QuotaScopeSelector("tenant", "t1"))).toBe(true);
  });

  test("#262 egress budget + download rpm follow min-across; workspace cannot widen tenant ceiling", () => {
    const q = resolveEffectiveQuota(
      { tenantId: "t1", workspaceId: "w1", keyId: "k1" },
      lookupFrom([
        egressPolicy("tenant", "t1", 10_000_000, 600),
        egressPolicy("workspace", "w1", 2_000_000, undefined),
        egressPolicy("key", "k1", undefined, 30),
      ]),
    );
    expect(q.monthlyEgressBytesBudget).toBe(2_000_000);
    expect(q.monthlyEgressBytesScope?.equals(new QuotaScopeSelector("workspace", "w1"))).toBe(true);
    expect(q.downloadRpmLimit).toBe(30);
    expect(q.downloadRpmLimitScope?.equals(new QuotaScopeSelector("key", "k1"))).toBe(true);

    const clamped = resolveEffectiveQuota(
      { tenantId: "t1", workspaceId: "w1" },
      lookupFrom([
        egressPolicy("tenant", "t1", 1_000_000, undefined),
        egressPolicy("workspace", "w1", 9_000_000, undefined),
      ]),
    );
    expect(clamped.monthlyEgressBytesBudget).toBe(1_000_000);
    expect(clamped.monthlyEgressBytesScope?.equals(new QuotaScopeSelector("tenant", "t1"))).toBe(
      true,
    );
  });

  test("#259 asset byte quotas are TENANT-scoped only; a nearer scope cannot set them", () => {
    // Rust: `if policy.scope_type == QuotaScopeKind::Tenant { ... }`. The asset
    // quotas are NOT min-across-the-chain like rpm/tpm — they are read off the
    // tenant policy alone. A workspace or key policy carrying these columns must
    // be ignored outright, or a tenant could widen its own storage ceiling by
    // writing a workspace-level policy.
    const q = resolveEffectiveQuota(
      { tenantId: "t1", workspaceId: "w1", keyId: "k1" },
      lookupFrom([
        policy("tenant", "t1", [], undefined, undefined, undefined, true, {
          assetStorageQuotaBytes: 1_000,
          assetMaxObjectBytes: 100,
        }),
        policy("workspace", "w1", [], undefined, undefined, undefined, true, {
          assetStorageQuotaBytes: 9_999_999,
          assetMaxObjectBytes: 888_888,
        }),
        policy("key", "k1", [], undefined, undefined, undefined, true, {
          assetStorageQuotaBytes: 7_777_777,
          assetMaxObjectBytes: 666_666,
        }),
      ]),
    );
    expect(q.assetStorageQuotaBytes).toBe(1_000);
    expect(q.assetMaxObjectBytes).toBe(100);
  });

  test("#259 with no tenant policy, a nearer scope still cannot supply the asset quotas", () => {
    const q = resolveEffectiveQuota(
      { tenantId: "t1", workspaceId: "w1" },
      lookupFrom([
        policy("workspace", "w1", [], undefined, undefined, undefined, true, {
          assetStorageQuotaBytes: 9_999_999,
          assetMaxObjectBytes: 888_888,
        }),
      ]),
    );
    expect(q.assetStorageQuotaBytes).toBeUndefined();
    expect(q.assetMaxObjectBytes).toBeUndefined();
  });

  test("#259 the plan supplies the asset floors, and a tenant policy overrides them", () => {
    const floors = resolveEffectiveQuota({ tenantId: "t1" }, lookupFrom([]), samplePlan());
    expect(floors.assetStorageQuotaBytes).toBe(1_000_000);
    expect(floors.assetMaxObjectBytes).toBe(250_000);

    const overridden = resolveEffectiveQuota(
      { tenantId: "t1" },
      lookupFrom([
        policy("tenant", "t1", [], undefined, undefined, undefined, true, {
          assetStorageQuotaBytes: 4_096,
          assetMaxObjectBytes: 512,
        }),
      ]),
      samplePlan(),
    );
    expect(overridden.assetStorageQuotaBytes).toBe(4_096);
    expect(overridden.assetMaxObjectBytes).toBe(512);

    // A tenant policy that sets only the cumulative cap leaves the per-object
    // ceiling on the plan default — the two dimensions are independent (#259).
    const partial = resolveEffectiveQuota(
      { tenantId: "t1" },
      lookupFrom([
        policy("tenant", "t1", [], undefined, undefined, undefined, true, {
          assetStorageQuotaBytes: 4_096,
        }),
      ]),
      samplePlan(),
    );
    expect(partial.assetStorageQuotaBytes).toBe(4_096);
    expect(partial.assetMaxObjectBytes).toBe(250_000);
  });

  test("a disabled policy still denies even with a plan present", () => {
    const q = resolveEffectiveQuota(
      { tenantId: "t1" },
      lookupFrom([policy("tenant", "t1", [], undefined, undefined, undefined, false)]),
      samplePlan(),
    );
    expect(isDenied(q)).toBe(true);
    expect(q.rpmLimit).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// #679 — the nested budget lattice
// ---------------------------------------------------------------------------

/**
 * `org → project → workspace → key`, where **org is `tenant`**: the schema's
 * `scope_type` enum is `('tenant','project','workspace','key')` and `tenant` IS
 * the organization (Rust called the column `organization_id`). No new scope kind
 * is introduced by #679 — the lattice already exists, what was missing is that
 * only ONE level of it was ever enforceable.
 *
 * ## Why a single `min` is not a nested budget
 *
 * `monthlyBudgetUsd` is the tightest CONFIGURED NUMBER across the chain, and
 * `monthlyBudgetScope` names the one scope it came from. The gateway then
 * measures that one scope's aggregate spend and admits. So with
 * `project = $5,000` and `key = $100`, the min is `$100` at the KEY scope, and
 * the only rollup consulted is that key's: fifty keys under the project each
 * spend $100 and the project's $5,000 cap is never once evaluated.
 *
 * A nested budget cannot be collapsed to one number, because each level is
 * measured against a DIFFERENT aggregate. So the merge now also reports the
 * whole ladder — {@link EffectiveQuota.monthlyBudgets} — one entry per scope
 * that configures a budget, each clamped by its ancestors, broadest first. The
 * caller enforces EVERY entry against that entry's own scope, and the tightest
 * one that actually binds is the one that refuses.
 */
describe("resolveEffectiveQuota — nested monthly budgets (#679)", () => {
  const FULL_CHAIN = { tenantId: "t1", projectId: "p1", workspaceId: "w1", keyId: "k1" };

  function budgetPolicy(
    scopeType: QuotaScopeKind,
    scopeId: string,
    monthlyBudgetUsd: number,
  ): StoredQuotaPolicy {
    return policy(scopeType, scopeId, [], undefined, undefined, monthlyBudgetUsd, true);
  }

  /** `[kind, id, limitUsd, source]` per rung, in the order the merge reports them. */
  function ladder(
    quota: ReturnType<typeof resolveEffectiveQuota>,
  ): [QuotaScopeKind, string, number, string][] {
    return (quota.monthlyBudgets ?? []).map((constraint) => [
      constraint.scope.kind,
      constraint.scope.id,
      constraint.limitUsd,
      constraint.source,
    ]);
  }

  interface LatticeCase {
    readonly name: string;
    /** `[scope kind, monthly budget usd]`, all on the FULL chain's ids. */
    readonly budgets: [QuotaScopeKind, number][];
    readonly expected: [QuotaScopeKind, string, number, string][];
  }

  const SCOPE_IDS: Record<QuotaScopeKind, string> = {
    tenant: "t1",
    project: "p1",
    workspace: "w1",
    key: "k1",
  };

  const cases: LatticeCase[] = [
    { name: "no budget anywhere ⇒ no rung to enforce", budgets: [], expected: [] },
    {
      name: "one rung: an org budget stands alone",
      budgets: [["tenant", 5_000]],
      expected: [["tenant", "t1", 5_000, "policy"]],
    },
    {
      name: "THE ISSUE: a project budget survives a smaller key budget",
      // "this project gets $5k/month, split however its keys like" — the key's
      // own $100 cap must not erase the project's $5,000 aggregate cap.
      budgets: [
        ["project", 5_000],
        ["key", 100],
      ],
      expected: [
        ["project", "p1", 5_000, "policy"],
        ["key", "k1", 100, "policy"],
      ],
    },
    {
      name: "an inner scope CANNOT grant itself more than its parent allows",
      budgets: [
        ["tenant", 1_000],
        ["key", 9_999],
      ],
      // The key rung is clamped to the org ceiling: a $9,999 key policy under a
      // $1,000 org is worth $1,000, measured against the key's own spend.
      expected: [
        ["tenant", "t1", 1_000, "policy"],
        ["key", "k1", 1_000, "policy"],
      ],
    },
    {
      name: "the full ladder, tightening at every rung",
      budgets: [
        ["tenant", 5_000],
        ["project", 3_000],
        ["workspace", 1_000],
        ["key", 250],
      ],
      expected: [
        ["tenant", "t1", 5_000, "policy"],
        ["project", "p1", 3_000, "policy"],
        ["workspace", "w1", 1_000, "policy"],
        ["key", "k1", 250, "policy"],
      ],
    },
    {
      name: "the full ladder INVERTED — every widening rung clamps to the org",
      budgets: [
        ["tenant", 100],
        ["project", 200],
        ["workspace", 300],
        ["key", 400],
      ],
      expected: [
        ["tenant", "t1", 100, "policy"],
        ["project", "p1", 100, "policy"],
        ["workspace", "w1", 100, "policy"],
        ["key", "k1", 100, "policy"],
      ],
    },
    {
      name: "a widening MIDDLE rung cannot re-open room a narrower key kept shut",
      budgets: [
        ["tenant", 1_000],
        ["project", 9_999],
        ["key", 50],
      ],
      expected: [
        ["tenant", "t1", 1_000, "policy"],
        ["project", "p1", 1_000, "policy"],
        ["key", "k1", 50, "policy"],
      ],
    },
    {
      name: "levels with no policy are simply absent from the ladder",
      budgets: [
        ["project", 300],
        ["key", 100],
      ],
      expected: [
        ["project", "p1", 300, "policy"],
        ["key", "k1", 100, "policy"],
      ],
    },
    {
      name: "a ZERO budget is a real rung (spend nothing), not an absent one",
      budgets: [
        ["tenant", 100],
        ["key", 0],
      ],
      expected: [
        ["tenant", "t1", 100, "policy"],
        ["key", "k1", 0, "policy"],
      ],
    },
    {
      name: "a zero ORG budget clamps every rung beneath it to zero",
      budgets: [
        ["tenant", 0],
        ["workspace", 500],
      ],
      expected: [
        ["tenant", "t1", 0, "policy"],
        ["workspace", "w1", 0, "policy"],
      ],
    },
  ];

  for (const testCase of cases) {
    test(testCase.name, () => {
      const quota = resolveEffectiveQuota(
        FULL_CHAIN,
        lookupFrom(testCase.budgets.map(([kind, usd]) => budgetPolicy(kind, SCOPE_IDS[kind], usd))),
      );
      expect(ladder(quota)).toEqual(testCase.expected);
    });
  }

  test("the ladder is ordered broadest-first, which is the order it must be enforced in", () => {
    const quota = resolveEffectiveQuota(
      FULL_CHAIN,
      lookupFrom([
        budgetPolicy("key", "k1", 250),
        budgetPolicy("tenant", "t1", 5_000),
        budgetPolicy("workspace", "w1", 1_000),
        budgetPolicy("project", "p1", 3_000),
      ]),
    );
    // Note the lookup order above is deliberately shuffled: the ladder's order
    // comes from the CHAIN, never from the order rows happen to be read in.
    expect((quota.monthlyBudgets ?? []).map((c) => c.scope.kind)).toEqual([
      "tenant",
      "project",
      "workspace",
      "key",
    ]);
  });

  test("a rung governs a scope that is absent from the request chain never appears", () => {
    const quota = resolveEffectiveQuota(
      { tenantId: "t1", keyId: "k1" },
      lookupFrom([budgetPolicy("tenant", "t1", 100), budgetPolicy("workspace", "w1", 1)]),
    );
    expect(ladder(quota)).toEqual([["tenant", "t1", 100, "policy"]]);
  });

  test("the plan FLOOR is a tenant-scoped rung when no policy configures a budget", () => {
    const quota = resolveEffectiveQuota(
      { tenantId: "t1", keyId: "k1" },
      lookupFrom([]),
      samplePlan(),
    );
    expect(ladder(quota)).toEqual([["tenant", "t1", 250, "plan"]]);
  });

  test("the plan floor stays a FLOOR: any explicit policy budget replaces it", () => {
    // Deliberate, pre-existing semantics (`quota.rs`: a field takes the plan
    // default only when no policy set it). Pinned here so a future change to it
    // is a decision, not a drift: a key policy today REPLACES the plan's
    // tenant-wide default rather than nesting under it.
    const quota = resolveEffectiveQuota(
      { tenantId: "t1", keyId: "k1" },
      lookupFrom([budgetPolicy("key", "k1", 10)]),
      samplePlan(),
    );
    expect(ladder(quota)).toEqual([["key", "k1", 10, "policy"]]);
  });

  test("a disabled scope denies outright and publishes no ladder to enforce", () => {
    const quota = resolveEffectiveQuota(
      FULL_CHAIN,
      lookupFrom([
        budgetPolicy("tenant", "t1", 5_000),
        policy("project", "p1", [], undefined, undefined, 100, false),
      ]),
    );
    expect(isDenied(quota)).toBe(true);
    expect(quota.monthlyBudgets ?? []).toEqual([]);
  });

  test("the single-number fields keep their exact previous meaning", () => {
    // BACK-COMPAT. `monthlyBudgetUsd` is still the tightest configured number
    // and `monthlyBudgetScope` still the scope it came from — with a widening
    // key that is the TENANT, not the key, and `monthlyBudgetScope()` in the
    // gateway still measures the tenant's aggregate. The ladder is additive.
    const quota = resolveEffectiveQuota(
      { tenantId: "t1", keyId: "k1" },
      lookupFrom([budgetPolicy("tenant", "t1", 10), budgetPolicy("key", "k1", 50)]),
    );
    expect(quota.monthlyBudgetUsd).toBe(10);
    expect(quota.monthlyBudgetScope?.equals(new QuotaScopeSelector("tenant", "t1"))).toBe(true);
    expect(ladder(quota)).toEqual([
      ["tenant", "t1", 10, "policy"],
      ["key", "k1", 10, "policy"],
    ]);
  });
});
