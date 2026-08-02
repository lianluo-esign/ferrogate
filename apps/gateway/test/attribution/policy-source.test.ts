/**
 * The durable side of #678: what the gateway reads, what it fences on, and the
 * three ways a read can fail.
 *
 * `enforcement.test.ts` drives the whole deployed chain and proves the
 * BEHAVIOUR. This file drives `src/attribution/source.ts` directly, because
 * three of its properties are invisible from the outside: the exact SQL (a
 * predicate that stopped binding the tenant would still serve every happy-path
 * request), the outage-versus-unmigrated distinction (both are exceptions from
 * D1 and they must not answer alike), and the cache key (a memo keyed too
 * coarsely leaks one tenant's defaults onto another's spend, and does so only
 * on the SECOND request in a warm isolate).
 */
import { describe, expect, it } from "vitest";

import {
  type AttributionPolicySource,
  cachedAttributionPolicySource,
  d1AttributionPolicySource,
} from "../../src/attribution/index.js";

/** A `D1Database` stand-in that records what it was asked and answers a script. */
function fakeDb(answer: (tenantId: string) => Record<string, unknown> | null | Error): {
  readonly db: Parameters<typeof d1AttributionPolicySource>[0];
  readonly calls: { sql: string; params: unknown[] }[];
} {
  const calls: { sql: string; params: unknown[] }[] = [];
  return {
    calls,
    db: {
      prepare(sql: string) {
        return {
          bind(...params: unknown[]) {
            return {
              async first<T = Record<string, unknown>>(): Promise<T | null> {
                calls.push({ sql, params });
                const result = answer(String(params[0]));
                if (result instanceof Error) throw result;
                return result as T | null;
              },
            };
          },
        };
      },
    },
  };
}

const TENANT_A_ROW = {
  required_tags_json: JSON.stringify(["team"]),
  on_missing_tags: "default_from_key",
};

describe("d1AttributionPolicySource", () => {
  it("binds the tenant, and only ever looks at the tenant scope", async () => {
    const { db, calls } = fakeDb(() => TENANT_A_ROW);

    const resolved = await d1AttributionPolicySource(db).policyFor("tenant_a");

    expect(resolved).toEqual({
      ok: true,
      policy: { requiredTagKeys: ["team"], onMissing: "default_from_key" },
    });
    // The fence, read literally. `scope_type` is a literal in the statement and
    // `scope_id` is a BOUND parameter carrying the authenticated tenant — never
    // interpolated, never a LIKE, and never absent.
    expect(calls).toHaveLength(1);
    expect(calls[0]?.sql).toContain("scope_type = 'tenant'");
    expect(calls[0]?.sql).toContain("scope_id = ?");
    expect(calls[0]?.params).toEqual(["tenant_a"]);
  });

  it("reads a row with no action as NOT enforced", async () => {
    const { db } = fakeDb(() => ({
      required_tags_json: JSON.stringify(["team"]),
      on_missing_tags: null,
    }));

    // Half a policy is not a policy: the operator must name the branch.
    expect(await d1AttributionPolicySource(db).policyFor("tenant_a")).toEqual({
      ok: true,
      policy: null,
    });
  });

  it("reports a genuine D1 failure as an OUTAGE, never as 'not enforced'", async () => {
    const { db } = fakeDb(() => new Error("D1_ERROR: network error"));

    const resolved = await d1AttributionPolicySource(db).policyFor("tenant_a");

    // Admitting here would open exactly the window this control closes.
    expect(resolved.ok).toBe(false);
  });

  it("reads a schema that predates the migration as 'not enforced'", async () => {
    const { db } = fakeDb(
      () => new Error("D1_ERROR: no such column: required_tags_json at offset 7: SQLITE_ERROR"),
    );

    // Not a guess: a table with no such column cannot be holding a policy. This
    // is what stops a Worker rolled out ahead of its migration from 503-ing
    // every inference request for a feature nobody switched on.
    expect(await d1AttributionPolicySource(db).policyFor("tenant_a")).toEqual({
      ok: true,
      policy: null,
    });
  });
});

describe("cachedAttributionPolicySource — the tenant fence in a warm isolate", () => {
  /** Answers a DIFFERENT policy per tenant, and counts reads. */
  function perTenant(): { readonly source: AttributionPolicySource; readonly reads: string[] } {
    const reads: string[] = [];
    return {
      reads,
      source: {
        async policyFor(tenantId: string) {
          reads.push(tenantId);
          return tenantId === "tenant_a"
            ? { ok: true, policy: { requiredTagKeys: ["team"], onMissing: "reject" as const } }
            : { ok: true, policy: null };
        },
      },
    };
  }

  it("never answers tenant B from tenant A's entry", async () => {
    const { source, reads } = perTenant();
    const cached = cachedAttributionPolicySource(source);

    const a = await cached.policyFor("tenant_a");
    const b = await cached.policyFor("tenant_b");

    expect(a).toEqual({
      ok: true,
      policy: { requiredTagKeys: ["team"], onMissing: "reject" },
    });
    // The whole point: tenant A being resolved first must not decide tenant B.
    expect(b).toEqual({ ok: true, policy: null });
    expect(reads).toEqual(["tenant_a", "tenant_b"]);
  });

  it("serves a repeat from the entry, and expires it", async () => {
    const { source, reads } = perTenant();
    let now = 1_000;
    const cached = cachedAttributionPolicySource(source, { ttlMs: 100, now: () => now });

    await cached.policyFor("tenant_a");
    await cached.policyFor("tenant_a");
    expect(reads).toEqual(["tenant_a"]);

    now += 101;
    await cached.policyFor("tenant_a");
    // Short TTL on purpose: this is a control an operator turns ON during an
    // incident, and a warm isolate must not obey minutes late.
    expect(reads).toEqual(["tenant_a", "tenant_a"]);
  });

  it("does not cache an OUTAGE", async () => {
    let attempts = 0;
    const flaky: AttributionPolicySource = {
      async policyFor() {
        attempts += 1;
        return attempts === 1 ? { ok: false, detail: "boom" } : { ok: true, policy: null };
      },
    };
    const cached = cachedAttributionPolicySource(flaky);

    expect((await cached.policyFor("tenant_a")).ok).toBe(false);
    // Caching the failure would turn a one-request blip into a TTL-long refusal
    // window for the whole tenant.
    expect(await cached.policyFor("tenant_a")).toEqual({ ok: true, policy: null });
  });
});
