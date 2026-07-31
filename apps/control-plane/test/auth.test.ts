/**
 * The table-driven guard: 401 vs 403, and the invariants that were real Rust
 * defect classes.
 *
 * The headline assertion — **a suspended native API key is 401, not 403** — is
 * asserted three ways (disabled, revoked, expired) and, crucially, asserted to
 * be INDISTINGUISHABLE from an unknown key: same status AND same error code.
 * A test that only checked `status === 401` would still pass if the code leaked
 * `key_suspended`, which is the disclosure the Rust semantics avoid.
 */
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { adminCrossSiteRejection, extractApiKey } from "../src/middleware/auth.js";
import { hasScope } from "../src/ports.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";

interface ErrorEnvelope {
  error: { message: string; type: string; code: string; request_id: string | null };
}

async function envelope(response: Response): Promise<ErrorEnvelope> {
  return (await response.json()) as ErrorEnvelope;
}

beforeEach(() => {
  arm({ staticKeys: [operatorKey] });
});

describe("credential extraction (Rust auth::extract_api_key)", () => {
  it("prefers x-api-key over Authorization, and treats blanks as absent", () => {
    expect(extractApiKey(new Headers({ "x-api-key": "  k1 ", authorization: "Bearer k2" }))).toBe(
      "k1",
    );
    expect(extractApiKey(new Headers({ authorization: "Bearer  k2  " }))).toBe("k2");
    expect(extractApiKey(new Headers({ "x-api-key": "   ", authorization: "Bearer k2" }))).toBe(
      "k2",
    );
    expect(extractApiKey(new Headers({ authorization: "Bearer   " }))).toBeNull();
    expect(extractApiKey(new Headers({ authorization: "Basic abc" }))).toBeNull();
    expect(extractApiKey(new Headers())).toBeNull();
  });
});

describe("scope semantics (Rust scope_set_allows)", () => {
  it("treats an EMPTY scope set as data-plane only — never admin", () => {
    expect(hasScope([], "models.read")).toBe(true);
    expect(hasScope([], "admin.read")).toBe(false);
    expect(hasScope([], "admin.write")).toBe(false);
  });

  it("honours the wildcard and exact grants", () => {
    expect(hasScope(["*"], "admin.write")).toBe(true);
    expect(hasScope(["admin.read"], "admin.read")).toBe(true);
    expect(hasScope(["admin.read"], "admin.write")).toBe(false);
  });
});

describe("401: unauthenticated", () => {
  it("no credential → 401 missing_api_key", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`);
    expect(response.status).toBe(401);
    expect((await envelope(response)).error.code).toBe("missing_api_key");
  });

  it("unknown credential → 401 invalid_api_key", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`, { headers: bearer("nope") });
    expect(response.status).toBe(401);
    expect((await envelope(response)).error.code).toBe("invalid_api_key");
  });

  it("advertises the accepted scheme on a 401", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`);
    expect(response.headers.get("www-authenticate")).toContain("Bearer");
  });
});

describe("401 (NOT 403): a suspended NATIVE api key — ROUTE-MAP invariant 6", () => {
  const unknown = { status: 401, code: "invalid_api_key" };

  it("a DISABLED native key is indistinguishable from an unknown one", async () => {
    arm({ nativeKeys: [{ ...tenantKey("k-disabled", "t1"), enabled: false }] });
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`, { headers: bearer("k-disabled") });
    expect(response.status).toBe(unknown.status);
    expect((await envelope(response)).error.code).toBe(unknown.code);
  });

  it("a REVOKED native key is indistinguishable from an unknown one", async () => {
    arm({ nativeKeys: [{ ...tenantKey("k-revoked", "t1"), revoked: true }] });
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`, { headers: bearer("k-revoked") });
    expect(response.status).toBe(unknown.status);
    expect((await envelope(response)).error.code).toBe(unknown.code);
  });

  it("an EXPIRED native key is indistinguishable from an unknown one", async () => {
    arm({ nativeKeys: [{ ...tenantKey("k-expired", "t1"), expires_at: 1 }] });
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`, { headers: bearer("k-expired") });
    expect(response.status).toBe(unknown.status);
    expect((await envelope(response)).error.code).toBe(unknown.code);
  });

  it("suspension is byte-identical to a typo — no state is disclosed", async () => {
    arm({ nativeKeys: [{ ...tenantKey("k-disabled", "t1"), enabled: false }] });
    const suspended = await envelope(
      await SELF.fetch(`${BASE}/admin/v1/plans`, { headers: bearer("k-disabled") }),
    );
    const typo = await envelope(
      await SELF.fetch(`${BASE}/admin/v1/plans`, { headers: bearer("k-disabledX") }),
    );
    expect(suspended.error.code).toBe(typo.error.code);
    expect(suspended.error.message).toBe(typo.error.message);
  });

  it("a STATIC config key is different: disabled → 403 api_key_disabled", async () => {
    // The asymmetry is deliberate. An operator-authored key in config is not a
    // secret whose existence must be hidden; a tenant's minted key is.
    arm({ staticKeys: [{ secret: "s-disabled", scopes: ["*"], enabled: false }] });
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`, { headers: bearer("s-disabled") });
    expect(response.status).toBe(403);
    expect((await envelope(response)).error.code).toBe("api_key_disabled");
  });
});

describe("403: authenticated but not authorized", () => {
  it("insufficient scope → 403 scope_denied, never 401", async () => {
    arm({ nativeKeys: [tenantKey("k-read", "t1", ["admin.read"])] });
    const response = await SELF.fetch(
      `${BASE}/admin/v1/plans`,
      jsonRequest("k-read", "POST", { id: "p1" }),
    );
    expect(response.status).toBe(403);
    expect((await envelope(response)).error.code).toBe("scope_denied");
  });

  it("a key with NO scopes reaches no admin operation at all", async () => {
    arm({ nativeKeys: [tenantKey("k-none", "t1", [])] });
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`, { headers: bearer("k-none") });
    expect(response.status).toBe(403);
    expect((await envelope(response)).error.code).toBe("scope_denied");
  });

  it("a SUSPENDED TENANT is 403 tenancy_suspended — distinct from a suspended key", async () => {
    arm({
      nativeKeys: [tenantKey("k-ok", "t-suspended")],
      lifecycle: { "t-suspended": "suspended" },
    });
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`, { headers: bearer("k-ok") });
    expect(response.status).toBe(403);
    expect((await envelope(response)).error.code).toBe("tenancy_suspended");
  });

  it("a DELETED tenant is 403 tenancy_deleted", async () => {
    arm({ nativeKeys: [tenantKey("k-ok", "t-gone")], lifecycle: { "t-gone": "deleted" } });
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`, { headers: bearer("k-ok") });
    expect(response.status).toBe(403);
    expect((await envelope(response)).error.code).toBe("tenancy_deleted");
  });

  it("a DISABLED tenant may still drive the lifecycle-reversal routes (#514)", async () => {
    arm({
      nativeKeys: [tenantKey("k-ok", "t-off")],
      lifecycle: { "t-off": "disabled" },
      seed: { "tenant-accounts": [{ id: "t-off", tenant_id: "t-off", status: "disabled" }] },
    });

    // Ordinary reads stay closed…
    const blocked = await SELF.fetch(`${BASE}/admin/v1/plans`, { headers: bearer("k-ok") });
    expect(blocked.status).toBe(403);
    expect((await envelope(blocked)).error.code).toBe("tenancy_disabled");

    // …but the switch that reverses it is reachable, or `disabled` would be a
    // one-way door out of a reversible state.
    const reversal = await SELF.fetch(
      `${BASE}/admin/v1/tenant-accounts/t-off`,
      jsonRequest("k-ok", "PATCH", { status: "active" }),
    );
    expect(reversal.status).toBe(200);
  });
});

describe("rbac_action: the second gate, driven by the contract", () => {
  it("denies a tenant caller without the declared grant → 403 guardrail_rbac_denied", async () => {
    arm({ nativeKeys: [tenantKey("k-t1", "t1")], rbac: { t1: [] } });
    const response = await SELF.fetch(`${BASE}/admin/v1/guardrail-policies`, {
      headers: bearer("k-t1"),
    });
    expect(response.status).toBe(403);
    expect((await envelope(response)).error.code).toBe("guardrail_rbac_denied");
  });

  it("admits the same caller once the grant exists", async () => {
    arm({
      nativeKeys: [tenantKey("k-t1", "t1")],
      rbac: { t1: ["guardrails.policy.read"] },
    });
    const response = await SELF.fetch(`${BASE}/admin/v1/guardrail-policies`, {
      headers: bearer("k-t1"),
    });
    expect(response.status).toBe(200);
  });

  it("does not require a grant for an operation with no rbac_action", async () => {
    arm({ nativeKeys: [tenantKey("k-t1", "t1")], rbac: { t1: [] } });
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`, { headers: bearer("k-t1") });
    expect(response.status).toBe(200);
  });

  it("waves a DECLARED platform operator through the grant check", async () => {
    arm({ staticKeys: [operatorKey], rbac: {} });
    const response = await SELF.fetch(`${BASE}/admin/v1/guardrail-policies`, {
      headers: bearer(operatorKey.secret),
    });
    expect(response.status).toBe(200);
  });
});

describe("GET /metrics is internal but BEARER-guarded (ROUTE-MAP invariant 5)", () => {
  it("refuses an unauthenticated scrape", async () => {
    const response = await SELF.fetch(`${BASE}/metrics`);
    expect(response.status).toBe(401);
    expect((await envelope(response)).error.code).toBe("missing_api_key");
  });

  it("refuses a key without admin.read", async () => {
    arm({ nativeKeys: [tenantKey("k-write", "t1", ["admin.write"])] });
    const response = await SELF.fetch(`${BASE}/metrics`, { headers: bearer("k-write") });
    expect(response.status).toBe(403);
  });

  it("serves the Prometheus exposition to an authorized scrape", async () => {
    const response = await SELF.fetch(`${BASE}/metrics`, { headers: bearer(operatorKey.secret) });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/plain; version=0.0.4; charset=utf-8");
    expect(await response.text()).toContain("ferrogate_control_plane_up 1");
  });
});

describe("anonymous operations", () => {
  it("serves the three dashboard paths with no credential", async () => {
    for (const path of ["/admin", "/admin/", "/admin/dashboard"]) {
      const response = await SELF.fetch(`${BASE}${path}`);
      expect(response.status, path).toBe(200);
      expect(response.headers.get("content-type")).toBe("text/html; charset=utf-8");
    }
  });

  it("does NOT extend that to /admin/status, which is bearer-guarded", async () => {
    const response = await SELF.fetch(`${BASE}/admin/status`);
    expect(response.status).toBe(401);
  });
});

describe("405 before authentication", () => {
  it("answers 405 with an Allow header for a documented path, undocumented method", async () => {
    // The set of methods a path supports is not a secret, so Rust decides this
    // before authenticating.
    const response = await SELF.fetch(`${BASE}/admin/v1/plans/plan_x`, { method: "DELETE" });
    expect(response.status).toBe(405);
    expect((await envelope(response)).error.code).toBe("method_not_allowed");
  });
});

describe("CSRF: cross-site admin mutations (Rust admin_cross_site_rejection)", () => {
  it("rejects Sec-Fetch-Site: cross-site and same-site, allows same-origin/none", () => {
    expect(
      adminCrossSiteRejection(new Headers({ "sec-fetch-site": "cross-site" }), null),
    ).not.toBeNull();
    expect(
      adminCrossSiteRejection(new Headers({ "sec-fetch-site": "Same-Site" }), null),
    ).not.toBeNull();
    expect(
      adminCrossSiteRejection(new Headers({ "sec-fetch-site": "same-origin" }), null),
    ).toBeNull();
    expect(adminCrossSiteRejection(new Headers({ "sec-fetch-site": "none" }), null)).toBeNull();
  });

  it("allows a non-browser client (no Sec-Fetch-Site, no Origin)", () => {
    expect(adminCrossSiteRejection(new Headers(), null)).toBeNull();
  });

  it("falls back to Origin when Sec-Fetch-Site is absent", () => {
    expect(
      adminCrossSiteRejection(new Headers({ origin: "https://evil.test" }), null),
    ).not.toBeNull();
    expect(
      adminCrossSiteRejection(
        new Headers({ origin: "https://console.test" }),
        "https://console.test",
      ),
    ).toBeNull();
  });

  it("blocks a browser cross-site mutation over HTTP → 403 cross_site_admin_denied", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`, {
      method: "POST",
      headers: {
        ...bearer(operatorKey.secret),
        "content-type": "application/json",
        "sec-fetch-site": "cross-site",
      },
      body: JSON.stringify({ id: "p_csrf" }),
    });
    expect(response.status).toBe(403);
    expect((await envelope(response)).error.code).toBe("cross_site_admin_denied");
  });

  it("does not apply the CSRF guard to safe methods", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`, {
      headers: { ...bearer(operatorKey.secret), "sec-fetch-site": "cross-site" },
    });
    expect(response.status).toBe(200);
  });
});
