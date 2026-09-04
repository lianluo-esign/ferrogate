/**
 * Track A G2 (stop-control-write) for the typed `quota_policies` enforcement row,
 * driven through the EXPORTED Worker with the D1 store live so BOTH write legs
 * run: the shared CONTROL facade (`db()`) and the owning tenant's OWN object
 * (`tenantObjectDb`).
 *
 * `CONTROL_QUOTA_POLICY_SOURCE` gates the CONTROL leg only. Flipped to
 * `"tenant_object"` (mutated on the shared `env` at runtime, the same override
 * pattern `siem-export.test.ts` uses for `SIEM_EXPORT_SINKS`, restored in
 * `afterEach`) the control row is NOT written on create and NOT removed on delete
 * — the tenant object's own row becomes the sole authority. The default topology
 * (dual-write) is asserted first so the flipped assertions are not vacuously
 * green against a leg that never wrote at all.
 *
 * This pins the WRITER half of the gate; the flip itself is GATED on every
 * admission reader (`{GATEWAY,AGENT_RUNTIME,MCP}_QUOTA_POLICY_SOURCE`) moving to
 * the object first, because quota is a limiter that fails OPEN on a missing row.
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";
import { registerObjectTenants, tenantObjectDb } from "./tenant-object.js";

const KEY = operatorKey.secret;
const TENANT_A_KEY = "tenant-a-secret";
const POLICIES = `${BASE}/admin/v1/quota-policies`;
const SCOPE = { type: "tenant", id: "tenant_a" } as const;
const SCOPED = `${POLICIES}/${SCOPE.type}/${SCOPE.id}`;

interface MutableEnv {
  CONTROL_QUOTA_POLICY_SOURCE?: string;
}

/** The policy body the operator POSTs — attributed to the tenant it governs. */
const BODY = {
  scope_type: SCOPE.type,
  scope_id: SCOPE.id,
  tenant_id: SCOPE.id,
  rpm_limit: 60,
  monthly_token_budget: 1_000,
};

/** The typed enforcement row of the scope, straight out of a given handle. */
async function typedRow(handle: D1Database): Promise<Record<string, unknown> | null> {
  return handle
    .prepare("SELECT * FROM quota_policies WHERE scope_type = ? AND scope_id = ?")
    .bind(SCOPE.type, SCOPE.id)
    .first<Record<string, unknown>>();
}

const controlRow = (): Promise<Record<string, unknown> | null> => typedRow(db());
const objectRow = (): Promise<Record<string, unknown> | null> => typedRow(tenantObjectDb(SCOPE.id));

function routeSource(value: string | undefined): void {
  (env as unknown as MutableEnv).CONTROL_QUOTA_POLICY_SOURCE = value;
}

beforeAll(async () => {
  await applySchema();
});

beforeEach(async () => {
  await resetD1();
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [tenantKey(TENANT_A_KEY, "tenant_a")],
  });
  await registerObjectTenants(["tenant_a"]);
  routeSource("control");
});

afterEach(() => {
  // Restore the committed default so `env-var-drift.test.ts` (shared isolate)
  // still reads the deploy value, exactly as `siem-export.test.ts` restores
  // `SIEM_EXPORT_SINKS`.
  routeSource("control");
});

describe("quota_policies CONTROL_QUOTA_POLICY_SOURCE (Track A G2 writer)", () => {
  it("DEFAULT: create dual-writes the control row AND the tenant-object row", async () => {
    const res = await SELF.fetch(POLICIES, jsonRequest(KEY, "POST", BODY));
    expect(res.status).toBe(201);

    expect(await controlRow()).toMatchObject({ scope_id: "tenant_a", rpm_limit: 60 });
    expect(await objectRow()).toMatchObject({ scope_id: "tenant_a", rpm_limit: 60 });
  });

  it("ROUTED: create writes ONLY the tenant object — the control leg is skipped", async () => {
    routeSource("tenant_object");

    const res = await SELF.fetch(POLICIES, jsonRequest(KEY, "POST", BODY));
    expect(res.status).toBe(201);

    // THE RED LINE: the shared control facade holds NO typed row — the mirror the
    // dual-write used to keep is gone. (The table still exists in this slice; the
    // DROP is a later, gated step, so this asserts absence, not a missing table.)
    expect(await controlRow()).toBeNull();
    // …and the owning tenant's own object is the sole authority.
    expect(await objectRow()).toMatchObject({ scope_id: "tenant_a", rpm_limit: 60 });
  });

  it("ROUTED: delete removes the tenant-object row and LEAVES the control row", async () => {
    // Seed under the default so BOTH legs hold a row, then flip and delete: the
    // control delete is gated OFF, so only the tenant object's row is removed.
    const created = await SELF.fetch(POLICIES, jsonRequest(KEY, "POST", BODY));
    expect(created.status).toBe(201);
    expect(await controlRow()).not.toBeNull();
    expect(await objectRow()).not.toBeNull();

    routeSource("tenant_object");
    const deleted = await SELF.fetch(SCOPED, { method: "DELETE", headers: bearer(KEY) });
    expect(deleted.status).toBe(200);

    // The tenant object (sole authority under the flag) no longer bites…
    expect(await objectRow()).toBeNull();
    // …but the control leg was skipped, so its pre-existing row is untouched.
    expect(await controlRow()).not.toBeNull();
  });

  it("a malformed value reads as the safe default — control is still written", async () => {
    routeSource("Tenant_Object"); // not the exact literal; must NOT stop the write

    const res = await SELF.fetch(POLICIES, jsonRequest(KEY, "POST", BODY));
    expect(res.status).toBe(201);
    expect(await controlRow()).not.toBeNull();
    expect(await objectRow()).not.toBeNull();
  });
});
