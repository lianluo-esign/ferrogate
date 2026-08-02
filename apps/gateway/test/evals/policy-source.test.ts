/**
 * THE OPT-IN SOURCE (#692) — the tenant fence, the memo `peek` rests on, and the
 * fail direction.
 *
 * A source is exactly the kind of module whose tests pass while the fence is
 * missing, so each case names the mutation it holds.
 */
import { describe, expect, it } from "vitest";

import {
  type OnlineEvalDatabase,
  cachedOnlineEvalPolicySource,
  d1OnlineEvalPolicySource,
  onlineEvalPolicySourceFromVars,
} from "../../src/evals/index.js";

const CRITERIA = [{ id: "grounded", definition: "Is it supported by the context?" }];

function fakeDb(rows: Record<string, Record<string, unknown>>, options: { throws?: string } = {}) {
  const bound: unknown[][] = [];
  const db: OnlineEvalDatabase = {
    prepare(sql: string) {
      return {
        bind(...values: unknown[]) {
          bound.push([sql, ...values]);
          return {
            async first<T = Record<string, unknown>>(): Promise<T | null> {
              if (options.throws !== undefined) throw new Error(options.throws);
              return (rows[String(values[0])] ?? null) as T | null;
            },
          };
        },
      };
    },
  };
  return { db, bound };
}

const ENABLED_ROW = {
  online_eval_enabled: 1,
  online_eval_sample_rate: 0.25,
  online_eval_sampling_unit: "conversation",
  online_eval_judge_model: "judge-model",
  online_eval_criteria_json: JSON.stringify(CRITERIA),
};

describe("the D1 source binds the tenant, and only the tenant scope", () => {
  it("selects on scope_type = 'tenant' AND a BOUND scope_id", async () => {
    // MUTATION: drop `AND scope_id = ?` and this goes red — which matters,
    // because without it one tenant's opt-in would cause another tenant's
    // prompts to be copied to a judge.
    const { db, bound } = fakeDb({ tenant_a: ENABLED_ROW });

    const resolved = await d1OnlineEvalPolicySource(db).policyFor("tenant_a");

    expect(resolved).toEqual({
      ok: true,
      policy: {
        enabled: true,
        sampleRate: 0.25,
        samplingUnit: "conversation",
        judgeModel: "judge-model",
        criteria: CRITERIA,
        regressionDrop: 0.1,
        regressionMinSamples: 20,
      },
    });
    expect(String(bound[0]?.[0])).toContain("scope_type = 'tenant' AND scope_id = ?");
    expect(bound[0]?.[1]).toBe("tenant_a");
  });

  it("reads a tenant with no row as 'did not opt in'", async () => {
    const { db } = fakeDb({});
    expect(await d1OnlineEvalPolicySource(db).policyFor("tenant_b")).toEqual({
      ok: true,
      policy: null,
    });
  });

  it("reads a schema that PREDATES the migration as 'did not opt in'", async () => {
    // Unlike #681's version of this arm it cannot widen anything: the fail
    // direction here is already "sample nothing".
    const { db } = fakeDb({}, { throws: "D1_ERROR: no such column: online_eval_enabled" });
    expect(await d1OnlineEvalPolicySource(db).policyFor("tenant_a")).toEqual({
      ok: true,
      policy: null,
    });
  });

  it("reports an unreadable database rather than answering 'no policy'", async () => {
    // `ok: false` and `policy: null` both end in "nothing was sampled", and
    // they must stay distinguishable: one is a tenant that never asked, the
    // other is a bug an operator has to fix.
    const { db } = fakeDb({}, { throws: "D1_ERROR: network" });
    expect(await d1OnlineEvalPolicySource(db).policyFor("tenant_a")).toMatchObject({ ok: false });
  });

  it("refuses a row that opted in and then said nothing usable", async () => {
    const { db } = fakeDb({
      tenant_a: { online_eval_enabled: 1, online_eval_criteria_json: "not json" },
    });
    expect(await d1OnlineEvalPolicySource(db).policyFor("tenant_a")).toMatchObject({ ok: false });
  });
});

describe("the memo is the tenant fence's second half, and what `peek` reads", () => {
  it("never answers tenant B from tenant A's entry", async () => {
    // MUTATION: key the cache on a constant and this goes red — with tenant
    // A's opt-in applied to tenant B, tenant B's prompts would be copied to a
    // judge tenant B never agreed to.
    const { db } = fakeDb({ tenant_a: ENABLED_ROW });
    const source = cachedOnlineEvalPolicySource(d1OnlineEvalPolicySource(db));

    expect((await source.policyFor("tenant_a")).ok).toBe(true);
    expect(await source.policyFor("tenant_b")).toEqual({ ok: true, policy: null });
    expect(source.peek("tenant_b")).toEqual({ ok: true, policy: null });
  });

  it("answers `peek` only after the async read warmed it", () => {
    const { db } = fakeDb({ tenant_a: ENABLED_ROW });
    const source = cachedOnlineEvalPolicySource(d1OnlineEvalPolicySource(db));
    // The cold-isolate hole, pinned: the request path takes NO I/O, so before
    // the first `policyFor` there is nothing to answer with and the request is
    // not sampled. A `peek` that fell back to a synchronous default would be a
    // policy decision taken without reading the policy.
    expect(source.peek("tenant_a")).toBeUndefined();
  });

  it("expires an entry, so an opt-OUT takes effect within the TTL", async () => {
    let now = 1_000;
    const { db } = fakeDb({ tenant_a: ENABLED_ROW });
    const source = cachedOnlineEvalPolicySource(d1OnlineEvalPolicySource(db), {
      ttlMs: 30_000,
      now: () => now,
    });
    await source.policyFor("tenant_a");
    expect(source.peek("tenant_a")).toMatchObject({ ok: true });
    now += 30_001;
    expect(source.peek("tenant_a")).toBeUndefined();
  });

  it("never caches a failure", async () => {
    const { db } = fakeDb({}, { throws: "D1_ERROR: network" });
    const source = cachedOnlineEvalPolicySource(d1OnlineEvalPolicySource(db));
    await source.policyFor("tenant_a");
    expect(source.peek("tenant_a")).toBeUndefined();
  });
});

describe("the var source", () => {
  it("answers from memory, so a deployment without a control database samples from the first request", async () => {
    const source = onlineEvalPolicySourceFromVars({
      GATEWAY_ONLINE_EVAL_POLICIES: JSON.stringify([
        {
          tenant_id: "tenant_a",
          enabled: true,
          sample_rate: 1,
          judge_model: "judge-model",
          criteria: CRITERIA,
        },
      ]),
    });

    expect(source.peek("tenant_a")).toMatchObject({ ok: true });
    expect((await source.policyFor("tenant_a")).ok).toBe(true);
    expect(source.peek("tenant_zzz")).toEqual({ ok: true, policy: null });
  });

  it("turns a malformed ENTRY into a visible failure for that tenant only", async () => {
    // Dropping the entry instead would silently NOT sample a tenant who asked
    // to be sampled, with nothing anywhere to show the typo.
    const source = onlineEvalPolicySourceFromVars({
      GATEWAY_ONLINE_EVAL_POLICIES: JSON.stringify([
        { tenant_id: "tenant_a", enabled: true, sample_rate: 5, judge_model: "j", criteria: [] },
        {
          tenant_id: "tenant_b",
          enabled: true,
          sample_rate: 1,
          judge_model: "judge-model",
          criteria: CRITERIA,
        },
      ]),
    });

    expect(await source.policyFor("tenant_a")).toMatchObject({ ok: false });
    expect((await source.policyFor("tenant_b")).ok).toBe(true);
  });
});
