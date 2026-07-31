/**
 * Contract-driven auth middleware, driven through the real Worker via `SELF`.
 *
 * Every assertion below is on a status/code pair the Rust tree produced, and the
 * two invariants that were real Rust defect classes get positive AND negative
 * controls so a regression cannot pass by accident:
 *
 *  - a SUSPENDED native API key answers 401 `invalid_api_key`, indistinguishable
 *    from an unknown key, and explicitly NOT 403;
 *  - an `internal` operation is unreachable with a tenant bearer, including a
 *    wildcard platform-operator key — proven against a positive control where the
 *    correct worker transport credential gets *past* the guard.
 *
 * Fixtures (keys, tenancy, worker registry) come from `vitest.config.ts`.
 */
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const BASE = "https://ferrogate.test";

interface ErrorEnvelope {
  error: { message: string; type: string; code: string; request_id: string | null };
}

async function envelope(res: Response): Promise<ErrorEnvelope> {
  return (await res.json()) as ErrorEnvelope;
}

function bearer(key: string): HeadersInit {
  return { authorization: `Bearer ${key}` };
}

describe("anonymous operations", () => {
  it("serves GET /healthz with no credential at all", async () => {
    const res = await SELF.fetch(`${BASE}/healthz`);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ status: "ok", service: "ferrogate-gateway" });
  });

  it("serves GET /readyz with no credential at all", async () => {
    const res = await SELF.fetch(`${BASE}/readyz`);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ status: "ready" });
  });

  it("does not leak anonymity to a neighbouring operation", async () => {
    // /v1/tools is bearer; only the 6 contract anonymous ops skip auth.
    expect((await SELF.fetch(`${BASE}/v1/tools`)).status).toBe(401);
  });
});

describe("bearer authentication", () => {
  it("401s a request with no Authorization header", async () => {
    const res = await SELF.fetch(`${BASE}/v1/tools`);
    expect(res.status).toBe(401);
    const body = await envelope(res);
    expect(body.error.code).toBe("missing_api_key");
    expect(body.error.type).toBe("ferrogate_error");
  });

  it("401s a blank bearer token", async () => {
    const res = await SELF.fetch(`${BASE}/v1/tools`, { headers: { authorization: "Bearer   " } });
    expect(res.status).toBe(401);
    expect((await envelope(res)).error.code).toBe("missing_api_key");
  });

  it("401s an unknown bearer token", async () => {
    const res = await SELF.fetch(`${BASE}/v1/tools`, { headers: bearer("fg_not_a_real_key") });
    expect(res.status).toBe(401);
    expect((await envelope(res)).error.code).toBe("invalid_api_key");
  });

  it("accepts the x-api-key header as well as Authorization: Bearer", async () => {
    const res = await SELF.fetch(`${BASE}/v1/tools`, {
      headers: { "x-api-key": "fg_tenant_tools" },
    });
    // 501 == the guard passed and the (not-yet-ported) handler answered.
    expect(res.status).toBe(501);
  });

  it("lets a correctly scoped key through to its handler", async () => {
    const res = await SELF.fetch(`${BASE}/v1/tools`, { headers: bearer("fg_tenant_tools") });
    expect(res.status).toBe(501);
    expect((await envelope(res)).error.code).toBe("not_implemented");
  });
});

describe("suspended native API key is 401, not 403", () => {
  // ROUTE-MAP invariant 6 / inventory-edge-control §5.2. In Rust the durable
  // authenticator returns None for a suspended key, so it lands on exactly the
  // same 401 `invalid_api_key` an unknown key gets. Key state is not disclosed.
  it("answers 401 invalid_api_key for a suspended key", async () => {
    const res = await SELF.fetch(`${BASE}/v1/tools`, { headers: bearer("fg_tenant_suspended") });
    expect(res.status).toBe(401);
    expect((await envelope(res)).error.code).toBe("invalid_api_key");
  });

  it("does NOT answer 403 for a suspended key", async () => {
    const res = await SELF.fetch(`${BASE}/v1/tools`, { headers: bearer("fg_tenant_suspended") });
    expect(res.status).not.toBe(403);
  });

  it("is byte-identical to the unknown-key response", async () => {
    const suspended = await envelope(
      await SELF.fetch(`${BASE}/v1/tools`, { headers: bearer("fg_tenant_suspended") }),
    );
    const unknown = await envelope(
      await SELF.fetch(`${BASE}/v1/tools`, { headers: bearer("fg_no_such_key") }),
    );
    expect(suspended.error.code).toBe(unknown.error.code);
    expect(suspended.error.message).toBe(unknown.error.message);
  });

  it("still reports a STATIC config key's state as 403 (the other half of the split)", async () => {
    const disabled = await SELF.fetch(`${BASE}/v1/tools`, {
      headers: bearer("fg_static_disabled"),
    });
    expect(disabled.status).toBe(403);
    expect((await envelope(disabled)).error.code).toBe("api_key_disabled");

    const expired = await SELF.fetch(`${BASE}/v1/tools`, { headers: bearer("fg_static_expired") });
    expect(expired.status).toBe(403);
    expect((await envelope(expired)).error.code).toBe("api_key_expired");
  });
});

describe("insufficient scope is 403", () => {
  it("403s an authenticated key that lacks the operation scope", async () => {
    // fg_tenant_readonly holds skills.read; GET /v1/tools requires tools.read.
    const res = await SELF.fetch(`${BASE}/v1/tools`, { headers: bearer("fg_tenant_readonly") });
    expect(res.status).toBe(403);
    const body = await envelope(res);
    expect(body.error.code).toBe("scope_denied");
    expect(body.error.message).toContain("tools.read");
  });

  it("lets the same key through on an operation it IS scoped for", async () => {
    // Positive control: the 403 above is about scope, not about the key.
    const res = await SELF.fetch(`${BASE}/v1/skills`, { headers: bearer("fg_tenant_readonly") });
    expect(res.status).toBe(501);
  });

  it("honours a static operator key's implicit wildcard scope", async () => {
    const res = await SELF.fetch(`${BASE}/v1/tools`, { headers: bearer("fg_root") });
    expect(res.status).toBe(501);
  });

  it("lets an unscoped durable key reach a data-plane operation", async () => {
    const res = await SELF.fetch(`${BASE}/v1/tools`, { headers: bearer("fg_tenant_unscoped") });
    expect(res.status).toBe(501);
  });
});

describe("tenancy suspension is 403 (distinct from key suspension)", () => {
  it("403s tenancy_suspended for a healthy key on a suspended tenant", async () => {
    const res = await SELF.fetch(`${BASE}/v1/tools`, { headers: bearer("fg_tenant_b_tools") });
    expect(res.status).toBe(403);
    expect((await envelope(res)).error.code).toBe("tenancy_suspended");
  });
});

describe("internal auth is not satisfiable by a tenant bearer", () => {
  // ROUTE-MAP invariant 2. The 6 /v1/self-hosted-workers/* callbacks belong to
  // apps/agent-runtime, so no handler is mounted here — which makes this a clean
  // test of the guard alone: rejected requests stop at 401, and a request that
  // passes the guard falls through to 404.
  const heartbeat = `${BASE}/v1/self-hosted-workers/heartbeat`;
  const body = JSON.stringify({
    identity: {
      tenant_id: "tenant_a",
      workspace_id: "workspace_1",
      worker_id: "worker_1",
      token_id: "fingerprint_1",
    },
    status: "idle",
  });

  it("rejects a tenant bearer key", async () => {
    const res = await SELF.fetch(heartbeat, {
      method: "POST",
      headers: { ...bearer("fg_tenant_tools"), "content-type": "application/json" },
      body,
    });
    expect(res.status).toBe(401);
    expect((await envelope(res)).error.code).toBe("invalid_self_hosted_worker_identity");
  });

  it("rejects even a wildcard platform-operator key", async () => {
    const res = await SELF.fetch(heartbeat, {
      method: "POST",
      headers: { ...bearer("fg_root"), "content-type": "application/json" },
      body,
    });
    expect(res.status).toBe(401);
    expect((await envelope(res)).error.code).toBe("invalid_self_hosted_worker_identity");
  });

  it("rejects an unregistered worker identity", async () => {
    const res = await SELF.fetch(heartbeat, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-ferrogate-worker-token": "worker_secret_1",
      },
      body: JSON.stringify({
        identity: {
          tenant_id: "tenant_a",
          workspace_id: "workspace_1",
          worker_id: "worker_99",
          token_id: "fingerprint_1",
        },
      }),
    });
    expect(res.status).toBe(401);
    expect((await envelope(res)).error.code).toBe("invalid_self_hosted_worker_identity");
  });

  it("rejects a registered worker presenting the wrong transport secret", async () => {
    const res = await SELF.fetch(heartbeat, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ferrogate-worker-token": "wrong_secret" },
      body,
    });
    expect(res.status).toBe(401);
  });

  it("POSITIVE CONTROL: the worker's own transport credential gets past the guard", async () => {
    // 404, not 401: the guard admitted the request and apps/agent-runtime owns
    // the handler. Without this control the 401s above would also pass if the
    // middleware simply rejected everything.
    const res = await SELF.fetch(heartbeat, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-ferrogate-worker-token": "worker_secret_1",
      },
      body,
    });
    expect(res.status).toBe(404);
    expect((await envelope(res)).error.code).toBe("not_found");
  });
});

describe("contract dispatch", () => {
  it("405s a documented path reached with an undocumented method", async () => {
    const res = await SELF.fetch(`${BASE}/v1/tools`, {
      method: "POST",
      headers: bearer("fg_root"),
    });
    expect(res.status).toBe(405);
    expect((await envelope(res)).error.code).toBe("method_not_allowed");
  });

  it("405s before authenticating (the contract decides dispatch first)", async () => {
    const res = await SELF.fetch(`${BASE}/v1/tools`, { method: "POST" });
    expect(res.status).toBe(405);
  });

  it("404s an undocumented path", async () => {
    const res = await SELF.fetch(`${BASE}/v1/not/a/route`);
    expect(res.status).toBe(404);
    expect((await envelope(res)).error.code).toBe("not_found");
  });

  it("guards a path-parameterised operation", async () => {
    const res = await SELF.fetch(`${BASE}/v1/skills/skill_1`);
    expect(res.status).toBe(401);
    const authorized = await SELF.fetch(`${BASE}/v1/skills/skill_1`, {
      headers: bearer("fg_tenant_readonly"),
    });
    expect(authorized.status).toBe(501);
  });
});

describe("error envelope", () => {
  it("uses the Rust wire shape and echoes the request id", async () => {
    const res = await SELF.fetch(`${BASE}/v1/tools`, {
      headers: { "x-request-id": "req_fixed_1" },
    });
    expect(res.status).toBe(401);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(res.headers.get("x-request-id")).toBe("req_fixed_1");
    expect(res.headers.get("x-trace-id")).toBe("req_fixed_1");
    expect(await res.json()).toEqual({
      error: {
        message: "missing API key; use Authorization: Bearer or x-api-key",
        type: "ferrogate_error",
        code: "missing_api_key",
        request_id: "req_fixed_1",
      },
    });
  });

  it("advertises the accepted scheme on a 401", async () => {
    const res = await SELF.fetch(`${BASE}/v1/tools`);
    expect(res.headers.get("www-authenticate")).toContain("Bearer");
  });

  it("mints a request id when the caller supplies none", async () => {
    const res = await SELF.fetch(`${BASE}/v1/tools`);
    expect(res.headers.get("x-request-id")).toBeTruthy();
  });
});
