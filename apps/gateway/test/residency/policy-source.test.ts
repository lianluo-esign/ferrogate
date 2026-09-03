/**
 * The residency policy SOURCE (#681) — the tenant fence, the cache, and the one
 * failure this control is allowed to read as "not governed".
 *
 * Each case names the mutation it is holding, because a policy source is
 * exactly the kind of module whose tests pass while the fence is missing.
 */
import { describe, expect, it } from "vitest";

import {
  type ResidencyDatabase,
  cachedResidencyPolicySource,
  d1ResidencyPolicySource,
  jurisdictionForPolicyAndAddress,
  residencyPolicySourceFromVars,
} from "../../src/residency/index.js";

/** A `ResidencyDatabase` that records every bound value and answers a table. */
function fakeDb(rows: Record<string, Record<string, unknown>>, options: { throws?: string } = {}) {
  const bound: unknown[][] = [];
  const db: ResidencyDatabase = {
    prepare(sql: string) {
      return {
        bind(...values: unknown[]) {
          bound.push([sql, ...values]);
          return {
            async first<T = Record<string, unknown>>(): Promise<T | null> {
              if (options.throws !== undefined) throw new Error(options.throws);
              const key = String(values[0]);
              return (rows[key] ?? null) as T | null;
            },
          };
        },
      };
    },
  };
  return { db, bound };
}

describe("the D1 source binds the tenant, and only the tenant scope", () => {
  it("selects on scope_type = 'tenant' AND a BOUND scope_id", async () => {
    // MUTATION: drop `AND scope_id = ?` from `SELECT_TENANT_POLICY` and this
    // goes red — which matters, because without it one tenant's EU-only policy
    // would be applied to whichever row the table happened to return first.
    const { db, bound } = fakeDb({
      tenant_eu: { residency_regions_json: '["eu-west-1"]', require_zero_data_retention: 0 },
    });

    const resolved = await d1ResidencyPolicySource(db).policyFor("tenant_eu");

    expect(resolved).toEqual({
      ok: true,
      policy: {
        regionGated: true,
        allowedRegions: ["eu-west-1"],
        requireZeroDataRetention: false,
        logResidency: "unconstrained",
      },
    });
    expect(String(bound[0]?.[0])).toContain("scope_type = 'tenant' AND scope_id = ?");
    expect(bound[0]?.[1]).toBe("tenant_eu");
  });

  it("reads a SQLite 1/0 flag as a boolean", async () => {
    const { db } = fakeDb({
      tenant_eu: { residency_regions_json: '["eu-west-1"]', require_zero_data_retention: 1 },
    });
    const resolved = await d1ResidencyPolicySource(db).policyFor("tenant_eu");
    expect(resolved.ok && resolved.policy?.requireZeroDataRetention).toBe(true);
  });

  it("carries the recorded jurisdiction and placement hint when present", async () => {
    const { db } = fakeDb({
      tenant_eu: {
        residency_regions_json: '["eu-west-1"]',
        require_zero_data_retention: 0,
        jurisdiction: "eu",
        location_hint: "weur",
      },
    });
    expect(await d1ResidencyPolicySource(db).policyFor("tenant_eu")).toMatchObject({
      ok: true,
      jurisdiction: "eu",
      locationHint: "weur",
    });
  });

  it("answers 'not governed' for a tenant with no row", async () => {
    const { db } = fakeDb({});
    expect(await d1ResidencyPolicySource(db).policyFor("tenant_us")).toEqual({
      ok: true,
      policy: null,
    });
  });

  it("reads a schema that PREDATES the migration as 'not governed'", async () => {
    // The one fail-open arm, and it is a complete reading of a known state: a
    // `quota_policies` without the column is physically incapable of holding a
    // policy. Without it, deploying this Worker before applying
    // `0007_residency_policy.sql` would 503 every request on every deployment
    // with a bound CONTROL_DB.
    const { db } = fakeDb({}, { throws: "D1_ERROR: no such column: residency_regions_json" });
    expect(await d1ResidencyPolicySource(db).policyFor("tenant_eu")).toEqual({
      ok: true,
      policy: null,
    });
  });

  it("reports any OTHER database failure as an outage, never as 'not governed'", async () => {
    const { db } = fakeDb({}, { throws: "D1_ERROR: network error" });
    const resolved = await d1ResidencyPolicySource(db).policyFor("tenant_eu");
    expect(resolved.ok).toBe(false);
  });

  it("reports an UNREADABLE row as an outage rather than as 'not governed'", async () => {
    // The direction that matters: reading a mistyped residency column as "no
    // policy" serves the request, possibly out of region, and succeeds.
    const { db } = fakeDb({
      tenant_eu: { residency_regions_json: "eu-west-1", require_zero_data_retention: 0 },
    });
    const resolved = await d1ResidencyPolicySource(db).policyFor("tenant_eu");
    expect(resolved.ok).toBe(false);
    expect(resolved.ok === false && resolved.detail).toContain("residency_regions");
  });
});

describe("the relocated quota_policies seek keeps placement on control (Track A)", () => {
  it("reads the policy from the tenant object but the placement roster from control", async () => {
    const control = fakeDb({ tenant_eu: { jurisdiction: "eu", location_hint: "weur" } });
    const tenant = fakeDb({
      tenant_eu: { residency_regions_json: '["eu-west-1"]', require_zero_data_retention: 0 },
    });

    const resolved = await d1ResidencyPolicySource(
      control.db,
      async () => tenant.db,
    ).policyFor("tenant_eu");

    expect(resolved).toMatchObject({
      ok: true,
      policy: { allowedRegions: ["eu-west-1"] },
      jurisdiction: "eu",
      locationHint: "weur",
    });
    // The per-tenant governance row moves to the tenant's OWN object…
    expect(tenant.bound).toHaveLength(1);
    expect(String(tenant.bound[0]?.[0])).toContain("quota_policies");
    expect(String(tenant.bound[0]?.[0])).toContain("scope_id = ?");
    // …but `tenant_databases` is account-global control state, not a per-tenant
    // mirror, so that seek deliberately STAYS on control.
    expect(control.bound).toHaveLength(1);
    expect(String(control.bound[0]?.[0])).toContain("tenant_databases");
    expect(String(control.bound[0]?.[0])).not.toContain("quota_policies");
  });

  it("reads a resolver refusal as an outage (fail-closed), never as 'not governed'", async () => {
    const control = fakeDb({ tenant_eu: { jurisdiction: "eu" } });

    const resolved = await d1ResidencyPolicySource(control.db, async () => {
      throw new Error("tenant tenant_eu has no resolvable tenant database: unbound");
    }).policyFor("tenant_eu");

    // Fail CLOSED: an unreadable residency policy read as "not governed" would
    // serve possibly out of region. The placement seek is never reached.
    expect(resolved.ok).toBe(false);
    expect(control.bound).toHaveLength(0);
  });
});

describe("residency and the object namespace cannot disagree", () => {
  it("refuses a policy jurisdiction different from the recorded object", () => {
    expect(() => jurisdictionForPolicyAndAddress("eu", "us")).toThrow(
      /changing the jurisdiction requires a data migration/,
    );
  });
});

describe("the cache is keyed by tenant and never caches an outage", () => {
  it("never answers tenant B from tenant A's entry", async () => {
    // MUTATION: key the cache on a constant and this goes red — tenant_us
    // would be refused under tenant_eu's EU-only policy.
    const { db } = fakeDb({
      tenant_eu: { residency_regions_json: '["eu-west-1"]', require_zero_data_retention: 0 },
    });
    const source = cachedResidencyPolicySource(d1ResidencyPolicySource(db));

    const eu = await source.policyFor("tenant_eu");
    const us = await source.policyFor("tenant_us");

    expect(eu.ok && eu.policy?.allowedRegions).toEqual(["eu-west-1"]);
    expect(us).toEqual({ ok: true, policy: null });
  });

  it("re-asks after an outage instead of pinning the tenant to it", async () => {
    let calls = 0;
    const source = cachedResidencyPolicySource({
      async policyFor() {
        calls += 1;
        return { ok: false, detail: "boom" };
      },
    });
    await source.policyFor("tenant_eu");
    await source.policyFor("tenant_eu");
    expect(calls).toBe(2);
  });

  it("expires an entry once the TTL has passed", async () => {
    let calls = 0;
    let now = 0;
    const source = cachedResidencyPolicySource(
      {
        async policyFor() {
          calls += 1;
          return { ok: true, policy: null };
        },
      },
      { ttlMs: 1_000, now: () => now },
    );
    await source.policyFor("tenant_eu");
    await source.policyFor("tenant_eu");
    expect(calls).toBe(1);
    now = 2_000;
    await source.policyFor("tenant_eu");
    expect(calls).toBe(2);
  });
});

describe("the var source", () => {
  it("governs only the tenants it names", async () => {
    const source = residencyPolicySourceFromVars({
      GATEWAY_RESIDENCY_POLICIES: JSON.stringify([
        { tenant_id: "tenant_eu", residency_regions: ["eu-west-1"] },
      ]),
    });
    expect((await source.policyFor("tenant_us")).ok).toBe(true);
    const eu = await source.policyFor("tenant_eu");
    expect(eu.ok && eu.policy?.allowedRegions).toEqual(["eu-west-1"]);
  });

  it("keeps an UNPARSEABLE entry as a refusal for that tenant, not as a drop", async () => {
    // Dropping the entry would serve exactly the tenant whose control was
    // mistyped, which is the failure mode this whole slice is about.
    const source = residencyPolicySourceFromVars({
      GATEWAY_RESIDENCY_POLICIES: JSON.stringify([
        { tenant_id: "tenant_eu", residency_regions: "eu-west-1" },
        { tenant_id: "tenant_us", residency_regions: ["us-east-1"] },
      ]),
    });
    expect((await source.policyFor("tenant_eu")).ok).toBe(false);
    // …and it is confined to that tenant.
    expect((await source.policyFor("tenant_us")).ok).toBe(true);
  });

  it("treats a tenant that names no control at all as ungoverned", async () => {
    const source = residencyPolicySourceFromVars({
      GATEWAY_RESIDENCY_POLICIES: JSON.stringify([{ tenant_id: "tenant_eu" }]),
    });
    expect(await source.policyFor("tenant_eu")).toEqual({ ok: true, policy: null });
  });
});
