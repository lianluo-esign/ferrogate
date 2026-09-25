import { DurableObjectD1Database } from "@ferrogate/storage";
import type { TenantDataStub } from "@ferrogate/storage";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PLATFORM_PLAN_MAX_AGE_MS, platformPlanFromKv } from "../../src/ratelimit/plan-source.js";
import { quotaPolicySourceFromEnv, rowToStoredPlan } from "../../src/ratelimit/quota.js";
import type { QuotaBindings } from "../../src/ratelimit/quota.js";
import { d1TokenBudgetSource } from "../../src/ratelimit/token-budget.js";

afterEach(() => vi.restoreAllMocks());

function fixture() {
  let now = 1_800_000_000_000;
  vi.spyOn(Date, "now").mockImplementation(() => now);
  const calls: string[] = [];
  let enabled = 1;
  let tokenLimit: number | null = null;
  let fail = false;
  const result = (results: unknown[]) => ({
    results,
    changes: 0,
    rowsRead: results.length,
    rowsWritten: 0,
    lastRowId: 0,
    databaseSize: 0,
  });
  const tenant = {
    async query() {
      calls.push("probe");
      return result([{ name: "spend_throttles" }]);
    },
    async batch(request: { statements: { sql: string }[] }) {
      calls.push("tenant");
      if (fail) throw new Error("tenant unavailable");
      return request.statements.map(({ sql }) =>
        result(
          sql.includes("quota_policies")
            ? [{ id: "quota", scope_type: "tenant", scope_id: "a", enabled, rpm_limit: 12 }]
            : sql.includes("FROM api_keys")
              ? [{ monthly_token_budget: tokenLimit }]
              : [],
        ),
      );
    },
  } as unknown as TenantDataStub;
  const control = {
    async query() {
      throw new Error("unexpected control query");
    },
    async batch() {
      calls.push("control");
      return [result([])];
    },
  };
  const env = {
    CONTROL_DATA: { idFromName: (id: string) => id, get: () => control },
  } as unknown as QuotaBindings;
  const subject = { apiKeyId: "same-key", chain: { tenantId: "a", keyId: "same-key" } };
  const source = (scope = "default", id = "a") => {
    const db = new DurableObjectD1Database(id, tenant).asD1Database();
    return quotaPolicySourceFromEnv(
      env,
      async (requested) => {
        if (requested !== id) throw new Error("wrong tenant");
        return db;
      },
      scope,
    );
  };
  return {
    env,
    calls,
    subject,
    source,
    setDisabled: () => {
      enabled = 0;
    },
    setTokenLimit: (limit: number) => {
      tokenLimit = limit;
    },
    setFail: () => {
      fail = true;
    },
    advance: (ms: number) => {
      now += ms;
    },
    now: () => now,
  };
}

describe("request-local quota sources share only completed scoped snapshots", () => {
  it("three request-local DO facades cost one tenant batch and one platform read, no schema probe", async () => {
    const f = fixture();
    for (let n = 0; n < 3; n++) expect((await f.source().policiesFor(f.subject)).ok).toBe(true);
    expect(f.calls).toEqual(["tenant", "control"]);
  });

  it("separates tenant, jurisdiction, key and environment", async () => {
    const f = fixture();
    await f.source().policiesFor(f.subject);
    await f.source("eu").policiesFor(f.subject);
    await f
      .source("default", "b")
      .policiesFor({ ...f.subject, chain: { ...f.subject.chain, tenantId: "b" } });
    await f.source().policiesFor({ ...f.subject, apiKeyId: "different" });
    const otherEnv = { ...f.env };
    const resolveOther = async (): Promise<D1Database> => {
      throw new Error("other environment read");
    };
    expect(
      (await quotaPolicySourceFromEnv(otherEnv, resolveOther, "default").policiesFor(f.subject)).ok,
    ).toBe(false);
    expect(f.calls.filter((call) => call === "tenant")).toHaveLength(4);
  });

  it("validates the current request resolver before a cache hit", async () => {
    const f = fixture();
    await f.source().policiesFor(f.subject);
    const failed = quotaPolicySourceFromEnv(
      f.env,
      async () => {
        throw new Error("wrong address");
      },
      "default",
    );
    expect(await failed.policiesFor(f.subject)).toMatchObject({
      ok: false,
      detail: expect.stringContaining("wrong address"),
    });
  });

  it("re-reads a disabled policy at the five-second boundary", async () => {
    const f = fixture();
    await f.source().policiesFor(f.subject);
    f.setDisabled();
    f.advance(5_000);
    const changed = await f.source().policiesFor(f.subject);
    expect(changed.ok && changed.lookup("tenant", "a")?.enabled).toBe(false);
    expect(f.calls).toEqual(["tenant", "control", "tenant", "control"]);
  });

  it("does not serve stale policies during a DB failure or cache failures", async () => {
    const f = fixture();
    await f.source().policiesFor(f.subject);
    f.advance(5_000);
    f.setFail();
    expect((await f.source().policiesFor(f.subject)).ok).toBe(false);
    expect((await f.source().policiesFor(f.subject)).ok).toBe(false);
    expect(f.calls.filter((call) => call === "tenant")).toHaveLength(3);
  });

  it("a valid plan KV snapshot removes the platform RPC as well", async () => {
    const f = fixture();
    const kv = { get: vi.fn(async () => snapshot(f.now())) } as unknown as KVNamespace;
    Object.assign(f.env, { PLATFORM_CONFIG: kv });
    for (let n = 0; n < 3; n++) {
      const value = await f.source().policiesFor(f.subject);
      expect(value.ok && value.plan?.defaultRpmLimit).toBe(7);
    }
    expect(f.calls).toEqual(["tenant"]);
    expect(kv.get).toHaveBeenCalledTimes(1);
  });

  it("refreshes a key budget downshift with the same scoped quota batch", async () => {
    const f = fixture();
    const first = await f.source().policiesFor(f.subject);
    expect(first.ok && first.keyTokenBudget).toEqual({ apiKeyId: "same-key", limit: undefined });
    f.setTokenLimit(0);
    f.advance(5_000);
    const changed = await f.source().policiesFor(f.subject);
    expect(changed.ok && changed.keyTokenBudget).toEqual({ apiKeyId: "same-key", limit: 0 });
  });
});

describe("token budget config reuse keeps usage live", () => {
  it("does no database read for a known unbudgeted key", async () => {
    const db = {
      prepare: vi.fn(() => {
        throw new Error("unexpected read");
      }),
    } as unknown as D1Database;
    const source = d1TokenBudgetSource(db, { apiKeyId: "key", limit: undefined });
    expect(await source.forApiKey("key", "tenant")).toEqual({
      ok: true,
      budget: undefined,
      committedTokens: 0,
    });
    expect(db.prepare).not.toHaveBeenCalled();
    expect((await source.forApiKey("another-key", "tenant")).ok).toBe(false);
  });

  it("reads current committed tokens for every admission with a budget", async () => {
    let committed = 5;
    const db = {
      prepare: vi.fn((sql: string) => {
        expect(sql).toContain("SUM(r.total_tokens)");
        return { bind: () => ({ first: async () => ({ committed }) }) };
      }),
    } as unknown as D1Database;
    const source = d1TokenBudgetSource(db, { apiKeyId: "key", limit: 10 });
    expect(await source.forApiKey("key", "tenant")).toMatchObject({
      budget: 10,
      committedTokens: 5,
    });
    committed = 11;
    expect(await source.forApiKey("key", "tenant")).toMatchObject({
      budget: 10,
      committedTokens: 11,
    });
    expect(db.prepare).toHaveBeenCalledTimes(2);
  });
});

function snapshot(now: number, rpm = 7) {
  return JSON.stringify({
    schema_version: 1,
    published_at_ms: now,
    plans: [rowToStoredPlan({ id: "plan", default_rpm_limit: rpm })],
    tenants: [
      { id: "a", plan_id: "plan" },
      { id: "no-plan", plan_id: "" },
    ],
  });
}

describe("bounded platform plan cache", () => {
  it("refreshes a reduced plan after the memory TTL", async () => {
    let now = 1_800_000_000_000;
    let raw = snapshot(now);
    const kv = { get: vi.fn(async () => raw) } as unknown as KVNamespace;
    expect((await platformPlanFromKv(kv, "a", () => now))?.plan?.defaultRpmLimit).toBe(7);
    now += 5_000;
    raw = snapshot(now, 2);
    expect((await platformPlanFromKv(kv, "a", () => now))?.plan?.defaultRpmLimit).toBe(2);
    expect(await platformPlanFromKv(kv, "missing", () => now)).toBeUndefined();
    expect((await platformPlanFromKv(kv, "no-plan", () => now))?.plan).toBeUndefined();
  });

  it.each([null, "broken", "{}", JSON.stringify({ schema_version: 2 }), snapshot(0)])(
    "falls back for missing, malformed or expired data: %s",
    async (raw) => {
      const kv = { get: async () => raw } as unknown as KVNamespace;
      expect(await platformPlanFromKv(kv, "a")).toBeUndefined();
    },
  );

  it("does not extend snapshot lifetime by stacking memory and quota TTLs", async () => {
    const f = fixture();
    const original = f.now();
    const kv = { get: async () => snapshot(original) } as unknown as KVNamespace;
    Object.assign(f.env, { PLATFORM_CONFIG: kv });
    f.advance(PLATFORM_PLAN_MAX_AGE_MS - 1);
    await f.source().policiesFor(f.subject);
    f.advance(1);
    const value = await f.source().policiesFor(f.subject);
    expect(value.ok && value.plan).toBeUndefined();
    expect(f.calls).toEqual(["tenant", "tenant", "control"]);
  });

  it("KV outage after expiry falls back, including when the previous snapshot was valid", async () => {
    let now = 1_800_000_000_000;
    let fail = false;
    const kv = {
      get: async () => {
        if (fail) throw new Error("KV down");
        return snapshot(now);
      },
    } as unknown as KVNamespace;
    expect(await platformPlanFromKv(kv, "a", () => now)).toBeDefined();
    fail = true;
    now += 5_000;
    expect(await platformPlanFromKv(kv, "a", () => now)).toBeUndefined();
  });
});
