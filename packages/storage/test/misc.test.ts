import { describe, expect, test } from "vitest";
import {
  MemoryAgentBurnStore,
  MemoryBudgetAlertStore,
  MemoryMetadataRollupStore,
  MemoryPresenceStore,
  budgetAlertNotificationId,
  lifecycleStatusAllowsRecovery,
  lifecycleStatusAllowsRequests,
  parseLifecycleStatus,
  parseLifecycleStatusStrict,
} from "../src/index.js";

describe("lifecycle status (#514)", () => {
  test("read side fails OPEN: empty/unknown/legacy tokens are active", () => {
    expect(parseLifecycleStatus("")).toBe("active");
    expect(parseLifecycleStatus("suspend")).toBe("active"); // typo → not a deny
    expect(parseLifecycleStatus(" SUSPENDED ")).toBe("suspended");
  });

  test("write side is STRICT: a typo is rejected (undefined)", () => {
    expect(parseLifecycleStatusStrict("suspend")).toBeUndefined();
    expect(parseLifecycleStatusStrict("suspended")).toBe("suspended");
  });

  test("all three non-active states deny requests", () => {
    for (const s of ["suspended", "disabled", "deleted"] as const) {
      expect(lifecycleStatusAllowsRequests(s)).toBe(false);
    }
    expect(lifecycleStatusAllowsRequests("active")).toBe(true);
  });

  test("recovery admits disabled and only disabled among the deny states", () => {
    expect(lifecycleStatusAllowsRecovery("disabled")).toBe(true);
    expect(lifecycleStatusAllowsRecovery("suspended")).toBe(false);
    expect(lifecycleStatusAllowsRecovery("deleted")).toBe(false);
  });
});

describe("MemoryPresenceStore — monotonic coalesced upsert (§1.5.6)", () => {
  test("a delayed older touch never regresses last-seen; count coalesces", () => {
    const store = new MemoryPresenceStore();
    store.touchObservedAgentPresence({ tenantId: "t1", apiKeyId: "k", seenAtUnix: 100 });
    store.touchObservedAgentPresence({ tenantId: "t1", apiKeyId: "k", seenAtUnix: 50 }); // older
    const rows = store.listObservedAgentPresenceSince("t1", 0);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.lastSeenAtUnix).toBe(100);
    expect(rows[0]?.firstSeenAtUnix).toBe(50);
    expect(rows[0]?.requestCount).toBe(2);
  });

  test("tenant scope is an isolation boundary", () => {
    const store = new MemoryPresenceStore();
    store.touchObservedAgentPresence({ tenantId: "t1", apiKeyId: "k", seenAtUnix: 100 });
    store.touchObservedAgentPresence({ tenantId: "t2", apiKeyId: "k", seenAtUnix: 100 });
    expect(store.listObservedAgentPresenceSince("t1", 0)).toHaveLength(1);
    expect(store.listObservedAgentPresenceSince(undefined, 0)).toHaveLength(2);
  });
});

describe("MemoryAgentBurnStore — atomic accumulate (#428)", () => {
  test("concurrent adds fold into one row and return the running total", () => {
    const store = new MemoryAgentBurnStore();
    expect(store.addAgentBurn("t1", "agent", "2026-07", 1.5, 0)).toBeCloseTo(1.5);
    expect(store.addAgentBurn("t1", "agent", "2026-07", 2.5, 1)).toBeCloseTo(4.0);
    expect(store.getAgentBurn("t1", "agent", "2026-07")).toBeCloseTo(4.0);
  });

  test("list is biggest-first and tenant-scoped", () => {
    const store = new MemoryAgentBurnStore();
    store.addAgentBurn("t1", "a", "p", 1, 0);
    store.addAgentBurn("t1", "b", "p", 5, 0);
    store.addAgentBurn("t2", "c", "p", 9, 0);
    expect(store.listAgentCostBurn("t1", "p").map((r) => r.agentKey)).toEqual(["b", "a"]);
    expect(store.listAgentCostBurn(undefined, "p")).toHaveLength(3);
  });
});

describe("MemoryBudgetAlertStore — idempotency ledger (#170)", () => {
  test("recording the same tier twice fires once", () => {
    const store = new MemoryBudgetAlertStore();
    const id = budgetAlertNotificationId("tenant", "t1", "2026-07", 90);
    const notification = {
      id,
      scopeType: "tenant" as const,
      scopeId: "t1",
      periodMonth: "2026-07",
      thresholdPct: 90,
      notifiedAtUnix: 0,
    };
    expect(store.budgetAlertAlreadyNotified(id)).toBe(false);
    store.recordBudgetAlertNotification(notification);
    store.recordBudgetAlertNotification({ ...notification, notifiedAtUnix: 999 });
    expect(store.budgetAlertAlreadyNotified(id)).toBe(true);
    const listed = store.listBudgetAlertNotifications("tenant", "t1", "2026-07");
    expect(listed).toHaveLength(1);
    expect(listed[0]?.notifiedAtUnix).toBe(0); // first write wins (DO NOTHING)
  });
});

describe("MemoryMetadataRollupStore — fan-out + org isolation (#171/#226)", () => {
  test("one event with N pairs increments N rows, scoped to the org", () => {
    const store = new MemoryMetadataRollupStore();
    const delta = {
      promptTokens: 10,
      completionTokens: 0,
      totalTokens: 10,
      costUsd: 0.1,
      isError: false,
    };
    store.incrementUsageMetadataRollups(
      "org1",
      new Map([
        ["customer", "acme"],
        ["arm", "b"],
      ]),
      "2026-07",
      delta,
      0,
    );
    expect(store.listUsageMetadataRollups("customer", "org1")).toHaveLength(1);
    // another org's rollup is invisible to org1's scoped read
    store.incrementUsageMetadataRollups("org2", new Map([["customer", "acme"]]), "2026-07", delta, 0);
    expect(store.listUsageMetadataRollups("customer", "org1")).toHaveLength(1);
    expect(store.listUsageMetadataRollups("customer", undefined)).toHaveLength(2);
  });
});
