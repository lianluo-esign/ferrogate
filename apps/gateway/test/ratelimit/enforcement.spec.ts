/**
 * End-to-end enforcement through `SELF` — the whole chain, in `workerd`:
 *
 *   HTTP → contractAuth → rateLimit → resolveEffectiveQuota (@ferrogate/policy)
 *        → counterKey() → Durable Object → 429 in the Rust error envelope.
 *
 * The Worker under test is `harness/worker.ts`, which is the REAL
 * `createGatewayApp` composition root with the REAL `GATEWAY_ROUTE_MODULES`
 * imported from `src/index.ts`, plus `rateLimitRouteModule()` — the exact
 * wiring documented for the integrate step. It is not a bespoke router built
 * for the suite.
 *
 * `GET /v1/models` is the drive route: a contract `bearer` operation requiring
 * `models.read`, answering `200 {object:"list",data:[]}` with the empty model
 * registry the harness config supplies. Any 429 therefore comes from the
 * limiter and nowhere else.
 */
import { SELF } from "cloudflare:test";
import { describe, expect, test } from "vitest";

const MODELS = "https://gateway.test/v1/models";

async function get(key: string): Promise<Response> {
  return await SELF.fetch(MODELS, { headers: { Authorization: `Bearer ${key}` } });
}

/** Statuses of `n` sequential requests with one credential. */
async function statuses(key: string, n: number): Promise<number[]> {
  const out: number[] = [];
  for (let i = 0; i < n; i += 1) out.push((await get(key)).status);
  return out;
}

describe("admission", () => {
  test("under the limit the request is served normally", async () => {
    const response = await get("fg_rl_a1");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ object: "list", data: [] });
  });

  test("over the limit → 429 in the Rust error envelope", async () => {
    // tenant_rl has rpm_limit 3; the 200 above already spent one.
    const seen = await statuses("fg_rl_a1", 4);
    expect(seen).toEqual([200, 200, 429, 429]);

    const denied = await get("fg_rl_a1");
    expect(denied.status).toBe(429);
    expect(denied.headers.get("content-type")).toContain("application/json");
    const body = (await denied.json()) as {
      error: { message: string; type: string; code: string; request_id: string | null };
    };
    expect(body.error.type).toBe("ferrogate_error");
    expect(body.error.code).toBe("rate_limit_exceeded");
    // Rust `require_request_budget` message, verbatim.
    expect(body.error.message).toBe(
      `API key request rate limit is exhausted for request ${body.error.request_id}`,
    );
    // Rust attaches NO Retry-After to its 429s (`write_json_error` writes
    // content-type/length + the request/trace ids + CORS, nothing else).
    expect(denied.headers.get("retry-after")).toBeNull();
    expect(denied.headers.get("x-request-id")).not.toBeNull();
  });

  test("a tenant-scope cap is ONE aggregate window across every key under it", async () => {
    // `key_a1` above already exhausted tenant_rl's window of 3. A DIFFERENT
    // credential in the same tenant must find it already spent — that is the
    // aggregate semantics `QuotaScopeSelector` selects the tenant scope for.
    expect((await get("fg_rl_a2")).status).toBe(429);
  });

  test("an unauthenticated request is refused by auth, not counted", async () => {
    const response = await SELF.fetch(MODELS);
    expect(response.status).toBe(401);
  });

  test("an anonymous operation is never rate limited", async () => {
    for (let i = 0; i < 8; i += 1) {
      expect((await SELF.fetch("https://gateway.test/healthz")).status).toBe(200);
    }
  });
});

describe("multi-level quota merge picks the tightest limit", () => {
  test("project rpm 4 beats tenant 10 / workspace 7 / key 6", async () => {
    // If the merge picked ANY other scope the 5th request would still pass.
    expect(await statuses("fg_rl_multi", 6)).toEqual([200, 200, 200, 200, 429, 429]);
  });
});

describe("plan floor", () => {
  test("a tenant with no policy row takes the plan default (rpm 2)", async () => {
    expect(await statuses("fg_rl_free", 3)).toEqual([200, 200, 429]);
  });
});

describe("per-credential TOK-12 limit", () => {
  test("applies even when no quota policy exists for the tenant", async () => {
    expect(await statuses("fg_rl_perkey", 3)).toEqual([200, 200, 429]);
  });
});

describe("a disabled quota policy is 403, not 429", () => {
  test("quota_scope_disabled fails closed on the FIRST request", async () => {
    const response = await get("fg_rl_disabled");
    expect(response.status).toBe(403);
    const body = (await response.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("quota_scope_disabled");
    expect(body.error.message).toBe(
      "quota policy at scope tenant disables this request's tenant/project/workspace/key chain",
    );
  });
});

describe("CROSS-TENANT COUNTER COLLISION IS IMPOSSIBLE", () => {
  test("a key whose id is 'tenant:<victim>' cannot drain the victim's window", async () => {
    // The attacker's api key id is the literal string `tenant:tenant_victim` —
    // byte-identical to the counter key the victim tenant's aggregate RPM
    // window uses. Its own key-scope policy grants rpm 50, so it can issue far
    // more requests than the victim's rpm 2 window would survive.
    //
    // Without the `"key:"` namespace these 6 requests would land in
    // `tenant:tenant_victim` and the victim's very next request would be 429.
    expect(await statuses("fg_rl_attacker", 6)).toEqual([200, 200, 200, 200, 200, 200]);

    // The victim's window must be untouched: exactly its own 2, then 429.
    expect(await statuses("fg_rl_victim", 3)).toEqual([200, 200, 429]);
  });

  test("and the victim being throttled does not throttle the attacker", async () => {
    // The converse direction: separate windows in BOTH directions, so the
    // namespacing is not accidentally one-way.
    expect((await get("fg_rl_victim")).status).toBe(429);
    expect((await get("fg_rl_attacker")).status).toBe(200);
  });
});
