/**
 * ANTI-UNMOUNT for the PRE-AUTH ingress steps, through `SELF.fetch`.
 *
 * `test/routes/network.test.ts` and `test/routes/trace.test.ts` already cover
 * the policy, the decision and the mount — but both drive `createGatewayApp`
 * (or the pure functions) directly. That leaves one gap open, and it is exactly
 * the gap this wave exists to close: a correct composition FUNCTION that the
 * deployed entry module never reaches with the right arguments. `src/index.ts`
 * and `src/worker.ts` are owned by the integrate step and cannot be edited
 * here, so the only way to know they are wired is to send a request through
 * them.
 *
 * Every assertion below therefore goes through `SELF.fetch`, i.e.
 * `src/worker.ts` → `src/index.ts` → `createGatewayApp` → `middleware/*`,
 * against the real `wrangler.toml` bindings. `env` from `cloudflare:test` is
 * the same object the Worker reads, so a var set here is a var the deployment
 * has; each test restores it.
 *
 * The three steps covered, and the Rust origin of each:
 *
 *  1. **IP allowlist** — `AppState::check_network_access` (`state.rs:5011`,
 *     issue #166): `403 ip_denied`, and BEFORE the credential lookup.
 *  2. **Unauthenticated per-source-IP flood limit** — same function:
 *     `429 unauthenticated_rate_limited`.
 *  3. **W3C trace-context ingress** — `server/mod.rs:156
 *     ingress_trace_context`: a valid inbound `traceparent` donates its trace
 *     id to `x-trace-id` and to the error envelope's correlation headers.
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";
import { CLIENT_IP_HEADER } from "../../src/middleware/network.js";

const BASE = "https://gw.test";
const mutable = env as unknown as Record<string, unknown>;

/** Vars this file sets. Cleared after every case so nothing bleeds. */
const NETWORK_VARS = [
  "GATEWAY_IP_ALLOWLIST",
  "GATEWAY_TRUST_FORWARDED_FOR",
  "GATEWAY_TRUSTED_PROXY_HOPS",
  "GATEWAY_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE",
] as const;

afterEach(() => {
  for (const name of NETWORK_VARS) delete mutable[name];
});

interface Envelope {
  error: { message: string; type: string; code: string; request_id: string | null };
}

async function envelope(res: Response): Promise<Envelope> {
  return (await res.json()) as Envelope;
}

function get(path: string, headers: Record<string, string> = {}): Promise<Response> {
  return SELF.fetch(`${BASE}${path}`, { headers });
}

// ---------------------------------------------------------------------------
// 1. IP allowlist
// ---------------------------------------------------------------------------

describe("the deployed Worker enforces the IP allowlist", () => {
  it("refuses an off-list IP on an ANONYMOUS operation", async () => {
    // `/healthz` is contract-anonymous and answers 200 to anyone. With the gate
    // unmounted from the exported app this is 200 and the test fails.
    mutable.GATEWAY_IP_ALLOWLIST = '["203.0.113.0/24"]';
    const res = await get("/healthz", { [CLIENT_IP_HEADER]: "198.51.100.9" });
    expect(res.status).toBe(403);
    const body = await envelope(res);
    expect(body.error.code).toBe("ip_denied");
    expect(body.error.type).toBe("ferrogate_error");
    // The refusal still carries a correlation id: the gate sits after
    // `requestId`, which is why an operator can find it in a log at all.
    expect(res.headers.get("x-request-id")).not.toBeNull();
  });

  it("admits an on-list IP", async () => {
    mutable.GATEWAY_IP_ALLOWLIST = '["203.0.113.0/24"]';
    expect((await get("/healthz", { [CLIENT_IP_HEADER]: "203.0.113.9" })).status).toBe(200);
  });

  it("runs BEFORE auth: a credential-less request is 403 ip_denied, never 401", async () => {
    // This is the Rust reason the gate exists — a credential-stuffing scan must
    // not pay the virtual-key/D1 lookup. Moving the gate behind `contractAuth`
    // still satisfies the allowlist but turns this into `401 missing_api_key`.
    mutable.GATEWAY_IP_ALLOWLIST = '["203.0.113.0/24"]';
    const res = await get("/v1/tools", { [CLIENT_IP_HEADER]: "198.51.100.9" });
    expect(res.status).toBe(403);
    expect((await envelope(res)).error.code).toBe("ip_denied");
  });

  it("still authenticates normally once the IP is admitted", async () => {
    mutable.GATEWAY_IP_ALLOWLIST = '["203.0.113.0/24"]';
    const res = await get("/v1/tools", { [CLIENT_IP_HEADER]: "203.0.113.9" });
    expect(res.status).toBe(401);
    expect((await envelope(res)).error.code).toBe("missing_api_key");
  });

  it("is inert with the var unset — the shipped default is unchanged", async () => {
    expect((await get("/healthz", { [CLIENT_IP_HEADER]: "198.51.100.9" })).status).toBe(200);
  });

  it("a spoofed X-Forwarded-For cannot bypass it", async () => {
    mutable.GATEWAY_IP_ALLOWLIST = '["203.0.113.0/24"]';
    const res = await get("/healthz", {
      [CLIENT_IP_HEADER]: "198.51.100.9",
      "x-forwarded-for": "203.0.113.9",
    });
    // `CF-Connecting-IP` is edge-set and unspoofable; the forwarded chain is
    // only consulted when the operator explicitly trusts it.
    expect(res.status).toBe(403);
  });

  it("a DECLARED but unparsable allowlist answers 503, not an open gateway", async () => {
    mutable.GATEWAY_IP_ALLOWLIST = '["10.0.0.0/8","garbage"]';
    const res = await get("/healthz", { [CLIENT_IP_HEADER]: "203.0.113.9" });
    expect(res.status).toBe(503);
    expect((await envelope(res)).error.code).toBe("network_access_misconfigured");
  });
});

// ---------------------------------------------------------------------------
// 2. Unauthenticated per-IP flood limit
// ---------------------------------------------------------------------------

describe("the deployed Worker rate-limits an unauthenticated flood", () => {
  it("answers 429 unauthenticated_rate_limited past the window, PRE-auth", async () => {
    mutable.GATEWAY_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE = "3";
    // A source no other case in this file uses: the production limiter is
    // isolate-scoped by design, so a shared IP would carry counts between cases.
    const ip = "198.51.100.77";
    const statuses: number[] = [];
    for (let attempt = 0; attempt < 5; attempt += 1) {
      statuses.push((await get("/v1/tools", { [CLIENT_IP_HEADER]: ip })).status);
    }
    // The first three are admitted and reach the auth guard (401, no
    // credential); the rest are refused before it.
    expect(statuses.slice(0, 3)).toEqual([401, 401, 401]);
    expect(statuses.slice(3)).toEqual([429, 429]);

    const refused = await get("/v1/tools", { [CLIENT_IP_HEADER]: ip });
    expect((await envelope(refused)).error.code).toBe("unauthenticated_rate_limited");
  });

  it("charges each source IP its own window", async () => {
    mutable.GATEWAY_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE = "1";
    expect((await get("/healthz", { [CLIENT_IP_HEADER]: "198.51.100.81" })).status).toBe(200);
    expect((await get("/healthz", { [CLIENT_IP_HEADER]: "198.51.100.81" })).status).toBe(429);
    // A different source is unaffected.
    expect((await get("/healthz", { [CLIENT_IP_HEADER]: "198.51.100.82" })).status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// 3. W3C trace-context ingress
// ---------------------------------------------------------------------------

describe("the deployed Worker adopts an inbound traceparent", () => {
  const TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736";
  const VALID = `00-${TRACE_ID}-00f067aa0ba902b7-01`;

  it("propagates the caller's trace id onto `x-trace-id`", async () => {
    const res = await get("/healthz", { traceparent: VALID });
    expect(res.status).toBe(200);
    // Without ingress adoption this is the gateway's own minted request id and
    // the caller's distributed trace is SEVERED at this hop.
    expect(res.headers.get("x-trace-id")).toBe(TRACE_ID);
    // The request id stays the gateway's own — the two are different facts.
    expect(res.headers.get("x-request-id")).not.toBe(TRACE_ID);
  });

  it("propagates it onto an ERROR envelope's headers too", async () => {
    // An error is the response a caller most needs to correlate.
    const res = await get("/v1/tools", { traceparent: VALID });
    expect(res.status).toBe(401);
    expect(res.headers.get("x-trace-id")).toBe(TRACE_ID);
  });

  it("falls back to the request id for a MALFORMED traceparent", async () => {
    for (const bogus of [
      "not-a-traceparent",
      // uppercase hex is invalid per the W3C spec
      `00-${TRACE_ID.toUpperCase()}-00f067aa0ba902b7-01`,
      // version `ff` is reserved
      `ff-${TRACE_ID}-00f067aa0ba902b7-01`,
      // all-zero trace id is the spec's "invalid" sentinel
      "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
    ]) {
      const res = await get("/healthz", { traceparent: bogus });
      const requestId = res.headers.get("x-request-id");
      // A hostile header can never REMOVE a correlation id — only fail to add one.
      expect(`${bogus}: ${res.headers.get("x-trace-id")}`).toBe(`${bogus}: ${requestId}`);
    }
  });

  it("uses the request id when there is no traceparent at all", async () => {
    const res = await get("/healthz");
    expect(res.headers.get("x-trace-id")).toBe(res.headers.get("x-request-id"));
  });
});
