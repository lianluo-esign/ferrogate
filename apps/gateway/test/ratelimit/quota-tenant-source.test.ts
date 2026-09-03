/**
 * THE RELOCATED QUOTA READ (Track A red line) — which DATABASE each admission
 * leg reads from.
 *
 * `quota_policies` and `spend_throttles` are per-scope TENANT data, so their
 * authoritative home is the tenant's OWN object, not the shared control. The
 * `GATEWAY_QUOTA_POLICY_SOURCE = "tenant_object"` posture routes those two legs
 * to the tenant object while the account-global `plans` floor stays on control.
 *
 * This is exactly the kind of split that passes a per-leg suite while pointing
 * a leg at the wrong database — the admission path would still look durable and
 * every operator quota would silently stop applying. So each case asserts on the
 * DATABASE that received the SQL, not merely that a snapshot came back.
 *
 * The default/OFF posture (no resolver) and an ownerless subject (no tenantId)
 * both keep every leg on control, byte-for-byte the pre-relocation behavior —
 * the property that lets this ship code-ready and inert until an operator
 * backfills the tenant objects and flips the flag.
 */
import { describe, expect, it } from "vitest";

import { d1QuotaPolicySource } from "../../src/ratelimit/quota.js";
import type { QuotaSubject } from "../../src/ratelimit/quota.js";

/** Which leg a statement is, decided from its SQL text. */
function legOf(sql: string): "quota_policies" | "spend_throttles" | "plans" | "probe" | "other" {
  if (sql.includes("sqlite_master")) return "probe";
  if (sql.includes("FROM quota_policies")) return "quota_policies";
  if (sql.includes("FROM spend_throttles")) return "spend_throttles";
  if (sql.includes("FROM plans")) return "plans";
  return "other";
}

interface FakeD1 {
  readonly db: D1Database;
  /** One entry per `batch()`, each the legs it carried, in order. */
  readonly batches: string[][];
  /** The probe (`sqlite_master`) reads issued against this handle. */
  readonly probes: number;
}

/**
 * A recording D1 double sufficient for {@link d1QuotaPolicySource}: it issues a
 * `sqlite_master` probe (`.first()`), builds statements (`.prepare().bind()`),
 * and runs them (`.batch()`). `throttleProvisioned` decides the probe's answer,
 * which is per-HANDLE in production — the whole point being that control and the
 * tenant object are probed independently.
 */
function fakeD1(options: { throttleProvisioned: boolean }): FakeD1 {
  const state = { batches: [] as string[][], probes: 0 };
  const db = {
    prepare(sql: string) {
      return {
        bind(..._values: unknown[]) {
          return {
            sql,
            async first<T = Record<string, unknown>>(): Promise<T | null> {
              state.probes += 1;
              return (options.throttleProvisioned ? { name: "spend_throttles" } : null) as T | null;
            },
          };
        },
      };
    },
    async batch(statements: { sql: string }[]) {
      state.batches.push(statements.map((s) => legOf(s.sql)));
      return statements.map(() => ({ results: [] as unknown[] }));
    },
  };
  return {
    db: db as unknown as D1Database,
    get batches() {
      return state.batches;
    },
    get probes() {
      return state.probes;
    },
  };
}

const NEVER = () => 0; // the injected clock; no throttle rows are seeded

function subject(chain: QuotaSubject["chain"]): QuotaSubject {
  return { apiKeyId: "ak_test", chain };
}

describe("d1QuotaPolicySource routes each leg to the right database", () => {
  it("OFF (no resolver): every leg reads control in ONE batch", async () => {
    // MUTATION: route quota_policies to a tenant handle without the posture set
    // and this goes red — the default deployment must not change database.
    const control = fakeD1({ throttleProvisioned: true });

    const snapshot = await d1QuotaPolicySource(control.db, NEVER).policiesFor(
      subject({ tenantId: "tenant_a", keyId: "key_a" }),
    );

    expect(snapshot.ok).toBe(true);
    // Exactly one round trip, carrying all three legs — the historical
    // single-transaction admission read.
    expect(control.batches).toEqual([["quota_policies", "spend_throttles", "plans"]]);
    expect(control.probes).toBe(1);
  });

  it("ON (resolver): tenant-scoped legs read the tenant object, plan stays on control", async () => {
    // MUTATION: leave quota_policies on control while claiming to route it and
    // this goes red — the relocation is exactly the tenant-scoped legs moving.
    const control = fakeD1({ throttleProvisioned: false });
    const tenant = fakeD1({ throttleProvisioned: true });

    const snapshot = await d1QuotaPolicySource(
      control.db,
      NEVER,
      async () => tenant.db,
    ).policiesFor(subject({ tenantId: "tenant_a", keyId: "key_a" }));

    expect(snapshot.ok).toBe(true);
    // quota_policies + spend_throttles on the tenant object...
    expect(tenant.batches).toEqual([["quota_policies", "spend_throttles"]]);
    // ...the plan floor alone on control (`plans` has no per-tenant snapshot).
    expect(control.batches).toEqual([["plans"]]);
    // The throttle probe ran against the TENANT handle, never control.
    expect(tenant.probes).toBe(1);
    expect(control.probes).toBe(0);
  });

  it("ON but ownerless subject (no tenantId): falls back to control", async () => {
    // A platform-operator credential has no single tenant object; its key-scoped
    // rows were never relocated, so it must stay on control even under the flag.
    const control = fakeD1({ throttleProvisioned: true });
    let resolverCalled = false;

    const snapshot = await d1QuotaPolicySource(control.db, NEVER, async () => {
      resolverCalled = true;
      return control.db;
    }).policiesFor(subject({ keyId: "key_only" }));

    expect(snapshot.ok).toBe(true);
    expect(resolverCalled).toBe(false);
    // No tenant ⇒ no plan leg; just quota_policies + throttle, on control.
    expect(control.batches).toEqual([["quota_policies", "spend_throttles"]]);
  });

  it("ON and the tenant handle cannot be resolved: 503, never a control read", async () => {
    // MUTATION: fall through to control on a resolver failure and this goes red.
    // Answering from the wrong authority would apply the wrong caps to live
    // traffic — the failure a limiter must refuse, not paper over.
    const control = fakeD1({ throttleProvisioned: true });

    const snapshot = await d1QuotaPolicySource(control.db, NEVER, async () => {
      throw new Error("tenant object unreachable");
    }).policiesFor(subject({ tenantId: "tenant_a", keyId: "key_a" }));

    expect(snapshot.ok).toBe(false);
    expect(snapshot.ok === false && snapshot.detail).toContain(
      "routed tenant quota database unavailable",
    );
    // Not one statement reached control.
    expect(control.batches).toEqual([]);
    expect(control.probes).toBe(0);
  });
});
