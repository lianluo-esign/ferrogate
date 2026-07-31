/**
 * Counter-key namespacing + the multi-level merge → window derivation.
 *
 * These are pure-function tests (no DO binding), so they run in the app's own
 * vitest project. The DO-backed behavior lives in `harness/*.spec.ts`.
 *
 * The security property under test: a counter key is an isolation boundary, and
 * a tenant-controllable `api_key_id` must not be able to name another tenant's
 * aggregate window.
 */
import {
  QuotaScopeSelector,
  type StoredPlan,
  type StoredQuotaPolicy,
  resolveEffectiveQuota,
} from "@ferrogate/policy";
import { describe, expect, test } from "vitest";
import {
  CounterKeyNamespaceError,
  assertNamespacedCounterKey,
  counterKeyForScope,
  isNamespacedCounterKey,
  parseCounterKey,
  perKeyCounterKey,
  requestWindows,
  tokenBudgetCounterKey,
  tpmWindow,
  walletCounterKey,
} from "../../src/ratelimit/index.js";

function policy(
  scopeType: StoredQuotaPolicy["scopeType"],
  scopeId: string,
  fields: Partial<StoredQuotaPolicy> = {},
): StoredQuotaPolicy {
  return {
    id: `${scopeType}:${scopeId}`,
    scopeType,
    scopeId,
    modelAllowlist: [],
    alertThresholdPcts: [],
    enabled: true,
    createdAtUnix: 0,
    updatedAtUnix: 0,
    ...fields,
  };
}

/** Build the `lookup` closure `resolveEffectiveQuota` takes. */
function lookupOf(...policies: StoredQuotaPolicy[]) {
  const index = new Map(policies.map((p) => [`${p.scopeType}:${p.scopeId}`, p]));
  return (kind: StoredQuotaPolicy["scopeType"], id: string): StoredQuotaPolicy | undefined =>
    index.get(`${kind}:${id}`);
}

describe("counter-key namespacing (cross-tenant DoS defense)", () => {
  test("every scope kind is {kind}:{id}", () => {
    expect(counterKeyForScope(new QuotaScopeSelector("tenant", "t1"), "k1")).toBe("tenant:t1");
    expect(counterKeyForScope(new QuotaScopeSelector("project", "p1"), "k1")).toBe("project:p1");
    expect(counterKeyForScope(new QuotaScopeSelector("workspace", "w1"), "k1")).toBe(
      "workspace:w1",
    );
  });

  test("a key-scope winner is key:{api_key_id}, never the raw id", () => {
    // The `key` selector's own scopeId is the POLICY row's subject; the counter
    // must be the presented credential. Both halves matter.
    const scope = new QuotaScopeSelector("key", "policy_row_subject");
    expect(counterKeyForScope(scope, "k1")).toBe("key:k1");
    expect(perKeyCounterKey("k1")).toBe("key:k1");
  });

  test("an api_key_id crafted to look like a tenant scope cannot collide", () => {
    const attackerKeyId = "tenant:victim";
    const attacker = counterKeyForScope(
      new QuotaScopeSelector("key", attackerKeyId),
      attackerKeyId,
    );
    const victim = counterKeyForScope(new QuotaScopeSelector("tenant", "victim"), "any_key");

    expect(attacker).toBe("key:tenant:victim");
    expect(victim).toBe("tenant:victim");
    expect(attacker).not.toBe(victim);

    // …and re-parsing the attacker's key keeps the colon INSIDE the id half, so
    // it can never be re-read as a tenant scope downstream.
    expect(parseCounterKey(attacker)).toEqual({ kind: "key", id: "tenant:victim" });
  });

  test("the same trick against project/workspace aggregates also fails", () => {
    for (const kind of ["project", "workspace", "tenant"] as const) {
      const crafted = `${kind}:victim`;
      const attacker = counterKeyForScope(new QuotaScopeSelector("key", crafted), crafted);
      const victim = counterKeyForScope(new QuotaScopeSelector(kind, "victim"), "k");
      expect(attacker).not.toBe(victim);
    }
  });

  test("token-budget and wallet counter keys are namespaced too", () => {
    expect(tokenBudgetCounterKey("tenant:victim")).toBe("key:tenant:victim");
    expect(walletCounterKey("t1")).toBe("tenant:t1");
  });
});

describe("assertNamespacedCounterKey (boundary guard)", () => {
  test("accepts every legal scope namespace", () => {
    for (const key of ["tenant:t1", "project:p1", "workspace:w1", "key:k1", "key:tenant:x"]) {
      expect(isNamespacedCounterKey(key)).toBe(true);
      expect(() => assertNamespacedCounterKey(key)).not.toThrow();
    }
  });

  test("rejects a raw api_key_id and every other unnamespaced string", () => {
    for (const key of ["k1", "", ":", ":t1", "tenant:", "org:t1", "TENANT:t1", "tenantx:t1"]) {
      expect(isNamespacedCounterKey(key)).toBe(false);
      expect(() => assertNamespacedCounterKey(key)).toThrow(CounterKeyNamespaceError);
    }
  });
});

describe("requestWindows — port of AuthContext::request_windows", () => {
  test("no limits anywhere ⇒ no windows (unlimited, not denied)", () => {
    const quota = resolveEffectiveQuota({ tenantId: "t1", keyId: "k1" }, lookupOf());
    expect(requestWindows("k1", quota)).toEqual([]);
  });

  test("the TOK-12 per-key limit alone counts at key:{id}", () => {
    const quota = resolveEffectiveQuota({ tenantId: "t1", keyId: "k1" }, lookupOf());
    expect(requestWindows("k1", quota, 5)).toEqual([{ counterKey: "key:k1", limit: 5 }]);
  });

  test("a tenant-scope rpm cap is ONE aggregate window shared by every key", () => {
    const lookup = lookupOf(policy("tenant", "t1", { rpmLimit: 30 }));
    const a = resolveEffectiveQuota({ tenantId: "t1", keyId: "k1" }, lookup);
    const b = resolveEffectiveQuota({ tenantId: "t1", keyId: "k2" }, lookup);
    expect(requestWindows("k1", a)).toEqual([{ counterKey: "tenant:t1", limit: 30 }]);
    // Same counter key for a different credential — that is the aggregate.
    expect(requestWindows("k2", b)).toEqual([{ counterKey: "tenant:t1", limit: 30 }]);
  });

  test("per-key limit AND a tenant cap are two independent windows", () => {
    const lookup = lookupOf(policy("tenant", "t1", { rpmLimit: 30 }));
    const quota = resolveEffectiveQuota({ tenantId: "t1", keyId: "k1" }, lookup);
    expect(requestWindows("k1", quota, 5)).toEqual([
      { counterKey: "key:k1", limit: 5 },
      { counterKey: "tenant:t1", limit: 30 },
    ]);
  });

  test("two sources landing on the same counter key collapse to the tighter", () => {
    // A key-scope policy wins the merge ⇒ counter is `key:k1`, which is also
    // where the TOK-12 per-key limit counts. Rust: `existing.1.min(limit)`.
    const lookup = lookupOf(policy("key", "k1", { rpmLimit: 9 }));
    const quota = resolveEffectiveQuota({ tenantId: "t1", keyId: "k1" }, lookup);
    expect(requestWindows("k1", quota, 4)).toEqual([{ counterKey: "key:k1", limit: 4 }]);
    // …and the other way round.
    expect(requestWindows("k1", quota, 20)).toEqual([{ counterKey: "key:k1", limit: 9 }]);
  });

  test("multi-level merge: the TIGHTEST limit wins, counted at ITS scope", () => {
    const lookup = lookupOf(
      policy("tenant", "t1", { rpmLimit: 10 }),
      policy("project", "p1", { rpmLimit: 4 }),
      policy("workspace", "w1", { rpmLimit: 7 }),
      policy("key", "k1", { rpmLimit: 6 }),
    );
    const quota = resolveEffectiveQuota(
      { tenantId: "t1", projectId: "p1", workspaceId: "w1", keyId: "k1" },
      lookup,
    );
    expect(quota.rpmLimit).toBe(4);
    expect(requestWindows("k1", quota)).toEqual([{ counterKey: "project:p1", limit: 4 }]);
  });

  test("a tie is awarded to the MOST SPECIFIC scope (per-key counting kept)", () => {
    const lookup = lookupOf(
      policy("tenant", "t1", { rpmLimit: 5 }),
      policy("key", "k1", { rpmLimit: 5 }),
    );
    const quota = resolveEffectiveQuota({ tenantId: "t1", keyId: "k1" }, lookup);
    expect(requestWindows("k1", quota)).toEqual([{ counterKey: "key:k1", limit: 5 }]);
  });

  test("the plan FLOOR applies only when no policy set the field", () => {
    const plan: StoredPlan = {
      id: "free",
      name: "free",
      slug: "free",
      mcpEnabled: false,
      selfHostedWorkersEnabled: false,
      defaultModelAllowlist: [],
      defaultRpmLimit: 2,
      createdAtUnix: 0,
      updatedAtUnix: 0,
      assetHostingEnabled: false,
      extensionToolsEnabled: false,
    };
    const floor = resolveEffectiveQuota({ tenantId: "t1", keyId: "k1" }, lookupOf(), plan);
    expect(requestWindows("k1", floor)).toEqual([{ counterKey: "tenant:t1", limit: 2 }]);

    // A policy — even a LOOSER one — beats the plan default outright.
    const withPolicy = resolveEffectiveQuota(
      { tenantId: "t1", keyId: "k1" },
      lookupOf(policy("tenant", "t1", { rpmLimit: 50 })),
      plan,
    );
    expect(requestWindows("k1", withPolicy)).toEqual([{ counterKey: "tenant:t1", limit: 50 }]);
  });

  test("attacker and victim resolve to DIFFERENT windows end to end", () => {
    const lookup = lookupOf(
      policy("tenant", "tenant_victim", { rpmLimit: 2 }),
      policy("key", "tenant:tenant_victim", { rpmLimit: 50 }),
    );
    const victim = resolveEffectiveQuota(
      { tenantId: "tenant_victim", keyId: "key_victim" },
      lookup,
    );
    const attacker = resolveEffectiveQuota(
      { tenantId: "tenant_attacker", keyId: "tenant:tenant_victim" },
      lookup,
    );
    expect(requestWindows("key_victim", victim)).toEqual([
      { counterKey: "tenant:tenant_victim", limit: 2 },
    ]);
    expect(requestWindows("tenant:tenant_victim", attacker)).toEqual([
      { counterKey: "key:tenant:tenant_victim", limit: 50 },
    ]);
  });
});

describe("tpmWindow — port of AuthContext::tpm_window", () => {
  test("no tpm limit ⇒ null", () => {
    const quota = resolveEffectiveQuota({ tenantId: "t1", keyId: "k1" }, lookupOf());
    expect(tpmWindow("k1", quota)).toBeNull();
  });

  test("counts at the scope that won the min", () => {
    const lookup = lookupOf(
      policy("tenant", "t1", { tpmLimit: 5000 }),
      policy("project", "p1", { tpmLimit: 900 }),
    );
    const quota = resolveEffectiveQuota({ tenantId: "t1", projectId: "p1", keyId: "k1" }, lookup);
    expect(tpmWindow("k1", quota)).toEqual({ counterKey: "project:p1", limit: 900 });
  });

  test("PORT-DEVIATION: the scope-less plan fallback is namespaced, not raw", () => {
    // Rust `tpm_window` falls back to the BARE `api_key_id` here, unlike
    // `request_windows`. That is reachable — a plan default with no tenant id
    // in the chain — and is exactly the cross-tenant collision the namespacing
    // exists to prevent. See the doc comment on `tpmWindow`.
    const plan: StoredPlan = {
      id: "free",
      name: "free",
      slug: "free",
      mcpEnabled: false,
      selfHostedWorkersEnabled: false,
      defaultModelAllowlist: [],
      defaultTpmLimit: 100,
      createdAtUnix: 0,
      updatedAtUnix: 0,
      assetHostingEnabled: false,
      extensionToolsEnabled: false,
    };
    // No tenantId ⇒ `resolveEffectiveQuota` sets tpmLimit with NO scope.
    const quota = resolveEffectiveQuota({ keyId: "tenant:victim" }, lookupOf(), plan);
    expect(quota.tpmLimit).toBe(100);
    expect(quota.tpmLimitScope).toBeUndefined();

    const window = tpmWindow("tenant:victim", quota);
    expect(window).toEqual({ counterKey: "key:tenant:victim", limit: 100 });
    // The Rust value would have been the raw `"tenant:victim"` — the victim's
    // aggregate window.
    expect(window?.counterKey).not.toBe("tenant:victim");
  });
});
