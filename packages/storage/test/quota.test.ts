import { describe, expect, test } from "vitest";
import {
  StorageError,
  type StoredQuotaPolicy,
  accumulateOverviewUsage,
  emptyOverviewUsageTotals,
  quotaScopeKindFromString,
  storedQuotaPolicySchema,
  validateQuotaPolicy,
} from "../src/index.js";

function tenantPolicy(overrides: Partial<StoredQuotaPolicy> = {}): StoredQuotaPolicy {
  return storedQuotaPolicySchema.parse({
    id: "tenant:t1",
    scopeType: "tenant",
    scopeId: "t1",
    ...overrides,
  });
}

describe("storedQuotaPolicySchema", () => {
  test("applies serde defaults (enabled true, empty allowlist)", () => {
    const policy = tenantPolicy();
    expect(policy.enabled).toBe(true);
    expect(policy.modelAllowlist).toEqual([]);
    expect(policy.alertThresholdPcts).toEqual([]);
  });

  test("rejects a negative rpm limit", () => {
    expect(() => tenantPolicy({ rpmLimit: -1 })).toThrow();
  });
});

describe("validateQuotaPolicy — tenant-only asset ceilings", () => {
  test("tenant scope may carry asset byte ceilings", () => {
    expect(() =>
      validateQuotaPolicy(tenantPolicy({ assetStorageQuotaBytes: 1000, assetMaxObjectBytes: 100 })),
    ).not.toThrow();
  });

  test("a workspace scope with assetStorageQuotaBytes is a runtime error", () => {
    const policy = storedQuotaPolicySchema.parse({
      id: "workspace:ws1",
      scopeType: "workspace",
      scopeId: "ws1",
      assetStorageQuotaBytes: 1000,
    });
    expect(() => validateQuotaPolicy(policy)).toThrowError(StorageError);
  });

  test("a key scope with assetMaxObjectBytes is a runtime error", () => {
    const policy = storedQuotaPolicySchema.parse({
      id: "key:k1",
      scopeType: "key",
      scopeId: "k1",
      assetMaxObjectBytes: 100,
    });
    try {
      validateQuotaPolicy(policy);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(StorageError);
      expect((err as StorageError).kind).toBe("runtime");
    }
  });
});

describe("scope kind parsing + overview accumulate", () => {
  test("unknown scope token is undefined", () => {
    expect(quotaScopeKindFromString("tenant")).toBe("tenant");
    expect(quotaScopeKindFromString("bogus")).toBeUndefined();
  });

  test("overview totals fold rollup rows additively", () => {
    const totals = emptyOverviewUsageTotals();
    accumulateOverviewUsage(totals, {
      id: "2026-07:tenant:t1",
      periodMonth: "2026-07",
      scopeType: "tenant",
      scopeId: "t1",
      promptTokens: 10,
      completionTokens: 5,
      totalTokens: 15,
      // #667 — subsets of the two counts above, so the overview totals below
      // are unchanged by their presence. Stated rather than defaulted because
      // `StoredUsageMonthlyRollup` requires them: a reader that omitted the
      // columns would otherwise silently report every rollup as uncached.
      cachedInputTokens: 8,
      cacheWriteTokens: 0,
      reasoningTokens: 3,
      costUsd: 0.5,
      requestCount: 2,
      errorCount: 1,
      updatedAtUnix: 0,
    });
    expect(totals.totalTokens).toBe(15);
    expect(totals.costUsd).toBeCloseTo(0.5);
    expect(totals.requestCount).toBe(2);
  });
});
