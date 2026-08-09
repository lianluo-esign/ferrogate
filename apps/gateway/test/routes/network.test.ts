/**
 * The PRE-AUTHENTICATION network gate — `src/middleware/network.ts`, the port
 * of Rust `AppState::check_network_access` (issue #166).
 *
 * Three levels, and the third is the one that matters most:
 *
 *  1. the policy PARSER, including every way a var can be unusable — because
 *     the fail-closed choice (a declared-but-unreadable allowlist answers 503
 *     rather than degrading to "no allowlist") is the whole security value;
 *  2. the DECISION function against the real `@ferrogate/config` primitives —
 *     CIDR containment, the anti-spoof `X-Forwarded-For`-from-the-right walk,
 *     and the fixed-window flood limiter;
 *  3. the MOUNT, through `createGatewayApp` — the composition root the deployed
 *     Worker is built from. This repo has twice shipped a module that was fully
 *     implemented, fully tested and never mounted, so the assertions here are
 *     written to go RED if `app.use("*", networkAccess())` is removed, and the
 *     ORDER assertion ("an anonymous request from a denied IP answers 403
 *     `ip_denied`, never 401 `missing_api_key`") goes red if it is merely moved
 *     behind `contractAuth`. Both mutations were run.
 */
import { UnauthenticatedIpRateLimiter } from "@ferrogate/config";
import { describe, expect, it } from "vitest";

import {
  CLIENT_IP_HEADER,
  checkNetworkAccess,
  networkAccess,
  networkAccessPolicy,
  networkAccessPolicyFromEnv,
  peerAddressOf,
  splitAllowlistVar,
} from "../../src/middleware/network.js";
import { createGatewayApp } from "../../src/routes/index.js";

const BASE = "https://gw.test";

interface Envelope {
  error: { message: string; type: string; code: string; request_id: string | null };
}

async function envelope(res: Response): Promise<Envelope> {
  return (await res.json()) as Envelope;
}

function headers(entries: Record<string, string>): Headers {
  return new Headers(entries);
}

/** A gate with an isolated limiter + fixed clock, so cases cannot bleed. */
function gatedApp(now = 60) {
  const limiter = new UnauthenticatedIpRateLimiter();
  const { app } = createGatewayApp({
    networkAccess: networkAccess({ limiter, now: () => now }),
  });
  return {
    call: (
      path: string,
      env: Record<string, string>,
      ip?: string,
      extra?: Record<string, string>,
    ) =>
      app.request(
        `${BASE}${path}`,
        { headers: { ...(ip === undefined ? {} : { [CLIENT_IP_HEADER]: ip }), ...extra } },
        env,
      ),
  };
}

// ---------------------------------------------------------------------------
// 1. the policy parser
// ---------------------------------------------------------------------------

describe("splitAllowlistVar", () => {
  it("reads the canonical JSON array", () => {
    expect(splitAllowlistVar('["10.0.0.0/8", "192.168.1.1"]')).toEqual([
      "10.0.0.0/8",
      "192.168.1.1",
    ]);
  });

  it("reads a bare comma-separated list, which is not valid JSON", () => {
    expect(splitAllowlistVar("10.0.0.0/8, 192.168.1.1")).toEqual(["10.0.0.0/8", "192.168.1.1"]);
    expect(splitAllowlistVar("10.0.0.0/8")).toEqual(["10.0.0.0/8"]);
  });

  it("is empty only for an empty var", () => {
    expect(splitAllowlistVar("")).toEqual([]);
    expect(splitAllowlistVar("   ")).toEqual([]);
    // A broken JSON array must NOT come back empty — that is the difference
    // between a closed gateway and an open one.
    expect(splitAllowlistVar("[10.0.0.0/8").length).toBeGreaterThan(0);
  });
});

describe("networkAccessPolicy", () => {
  it("is fully open when nothing is declared", () => {
    const policy = networkAccessPolicy({});
    expect(policy.allowlist).toEqual([]);
    expect(policy.trustForwardedFor).toBe(false);
    expect(policy.trustedProxyHops).toBe(1);
    expect(policy.unauthenticatedRateLimitPerMinute).toBeUndefined();
    expect(policy.misconfiguration).toBeNull();
  });

  it("parses a usable allowlist", () => {
    const policy = networkAccessPolicy({ GATEWAY_IP_ALLOWLIST: '["10.0.0.0/8","2001:db8::/32"]' });
    expect(policy.allowlist).toHaveLength(2);
    expect(policy.misconfiguration).toBeNull();
  });

  it("an UNPARSABLE entry is a misconfiguration, never a dropped restriction", () => {
    const policy = networkAccessPolicy({ GATEWAY_IP_ALLOWLIST: '["10.0.0.0/8","not-an-ip"]' });
    expect(policy.misconfiguration).toContain("GATEWAY_IP_ALLOWLIST");
    expect(policy.misconfiguration).toContain("not-an-ip");
  });

  it("a prefix wider than the family maximum is refused (`validate_network_access`)", () => {
    expect(networkAccessPolicy({ GATEWAY_IP_ALLOWLIST: "10.0.0.0/33" }).misconfiguration).toContain(
      "exceeds maximum /32",
    );
  });

  it("a declared allowlist that names nothing usable is a misconfiguration", () => {
    expect(networkAccessPolicy({ GATEWAY_IP_ALLOWLIST: "," }).misconfiguration).toContain(
      "no usable CIDR entry",
    );
  });

  it("rejects a zero / negative / non-numeric flood limit — Rust fails config validation on 0", () => {
    for (const value of ["0", "-1", "abc", "1.5"]) {
      const policy = networkAccessPolicy({
        GATEWAY_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE: value,
      });
      expect(policy.misconfiguration).toContain("must be a positive integer");
      expect(policy.unauthenticatedRateLimitPerMinute).toBeUndefined();
    }
    const ok = networkAccessPolicy({ GATEWAY_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE: "120" });
    expect(ok.unauthenticatedRateLimitPerMinute).toBe(120);
    expect(ok.misconfiguration).toBeNull();
  });

  it("only the exact string `true` trusts the forwarded chain", () => {
    expect(networkAccessPolicy({ GATEWAY_TRUST_FORWARDED_FOR: "true" }).trustForwardedFor).toBe(
      true,
    );
    for (const value of ["ture", "1", "yes", "", "TRUE "]) {
      const policy = networkAccessPolicy({ GATEWAY_TRUST_FORWARDED_FOR: value });
      expect(policy.trustForwardedFor).toBe(value.trim().toLowerCase() === "true");
    }
    expect(networkAccessPolicy({ GATEWAY_TRUST_FORWARDED_FOR: "yes" }).trustForwardedFor).toBe(
      false,
    );
  });

  it("rejects a non-positive hop count", () => {
    expect(networkAccessPolicy({ GATEWAY_TRUSTED_PROXY_HOPS: "0" }).misconfiguration).toContain(
      "GATEWAY_TRUSTED_PROXY_HOPS",
    );
    expect(networkAccessPolicy({ GATEWAY_TRUSTED_PROXY_HOPS: "2" }).trustedProxyHops).toBe(2);
  });

  it("memoizes on the VALUES, so a changed var is never stale", () => {
    const first = networkAccessPolicyFromEnv({ GATEWAY_IP_ALLOWLIST: "10.0.0.0/8" });
    const again = networkAccessPolicyFromEnv({ GATEWAY_IP_ALLOWLIST: "10.0.0.0/8" });
    expect(again).toBe(first);
    const changed = networkAccessPolicyFromEnv({ GATEWAY_IP_ALLOWLIST: "10.0.0.0/9" });
    expect(changed).not.toBe(first);
    expect(changed.allowlist).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// 2. the decision
// ---------------------------------------------------------------------------

describe("peerAddressOf", () => {
  it("reads the edge-set CF-Connecting-IP", () => {
    expect(peerAddressOf(headers({ [CLIENT_IP_HEADER]: "203.0.113.7" }))).toBe("203.0.113.7");
  });

  it("is null when absent or not an IP literal", () => {
    expect(peerAddressOf(headers({}))).toBeNull();
    expect(peerAddressOf(headers({ [CLIENT_IP_HEADER]: "not-an-ip" }))).toBeNull();
    expect(peerAddressOf(headers({ [CLIENT_IP_HEADER]: "  " }))).toBeNull();
  });
});

describe("checkNetworkAccess — Rust `check_network_access`", () => {
  const limiter = () => new UnauthenticatedIpRateLimiter();

  it("allows everything with no policy", () => {
    expect(checkNetworkAccess(headers({}), networkAccessPolicy({}), limiter(), 0)).toBe("allowed");
  });

  it("admits an IP inside the allowlist and denies one outside", () => {
    const policy = networkAccessPolicy({ GATEWAY_IP_ALLOWLIST: '["203.0.113.0/24"]' });
    expect(
      checkNetworkAccess(headers({ [CLIENT_IP_HEADER]: "203.0.113.9" }), policy, limiter(), 0),
    ).toBe("allowed");
    expect(
      checkNetworkAccess(headers({ [CLIENT_IP_HEADER]: "198.51.100.9" }), policy, limiter(), 0),
    ).toBe("ip_denied");
  });

  it("DENIES a request with no resolvable IP whenever an allowlist exists (fail closed)", () => {
    const policy = networkAccessPolicy({ GATEWAY_IP_ALLOWLIST: '["203.0.113.0/24"]' });
    expect(checkNetworkAccess(headers({}), policy, limiter(), 0)).toBe("ip_denied");
  });

  it("never matches across address families", () => {
    const v6 = networkAccessPolicy({ GATEWAY_IP_ALLOWLIST: '["::/0"]' });
    expect(
      checkNetworkAccess(headers({ [CLIENT_IP_HEADER]: "203.0.113.9" }), v6, limiter(), 0),
    ).toBe("ip_denied");
    expect(
      checkNetworkAccess(headers({ [CLIENT_IP_HEADER]: "2001:db8::1" }), v6, limiter(), 0),
    ).toBe("allowed");
  });

  it("ignores X-Forwarded-For unless the chain is explicitly trusted", () => {
    const policy = networkAccessPolicy({ GATEWAY_IP_ALLOWLIST: '["203.0.113.0/24"]' });
    // A client that simply CLAIMS an allowlisted address is still denied.
    expect(
      checkNetworkAccess(
        headers({ [CLIENT_IP_HEADER]: "198.51.100.9", "x-forwarded-for": "203.0.113.9" }),
        policy,
        limiter(),
        0,
      ),
    ).toBe("ip_denied");
  });

  it("with the chain trusted, selects the hop from the RIGHT and fails closed when short", () => {
    const policy = networkAccessPolicy({
      GATEWAY_IP_ALLOWLIST: '["203.0.113.0/24"]',
      GATEWAY_TRUST_FORWARDED_FOR: "true",
      GATEWAY_TRUSTED_PROXY_HOPS: "2",
    });
    // hops=2 ⇒ the second-from-the-right entry is the client.
    expect(
      checkNetworkAccess(
        headers({
          [CLIENT_IP_HEADER]: "198.51.100.9",
          "x-forwarded-for": "9.9.9.9, 203.0.113.9, 198.51.100.1",
        }),
        policy,
        limiter(),
        0,
      ),
    ).toBe("allowed");
    // A spoofed LEFTMOST entry cannot bypass the allowlist.
    expect(
      checkNetworkAccess(
        headers({
          [CLIENT_IP_HEADER]: "198.51.100.9",
          "x-forwarded-for": "203.0.113.9, 8.8.8.8, 198.51.100.1",
        }),
        policy,
        limiter(),
        0,
      ),
    ).toBe("ip_denied");
    // Chain shorter than the hop count ⇒ falls back to the peer, which is not
    // allowlisted ⇒ denied.
    expect(
      checkNetworkAccess(
        headers({ [CLIENT_IP_HEADER]: "198.51.100.9", "x-forwarded-for": "203.0.113.9" }),
        policy,
        limiter(),
        0,
      ),
    ).toBe("ip_denied");
  });

  it("charges the fixed one-minute window per source IP", () => {
    const policy = networkAccessPolicy({ GATEWAY_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE: "2" });
    const shared = limiter();
    const call = (ip: string, nowSeconds: number) =>
      checkNetworkAccess(headers({ [CLIENT_IP_HEADER]: ip }), policy, shared, nowSeconds);
    expect(call("203.0.113.1", 60)).toBe("allowed");
    expect(call("203.0.113.1", 61)).toBe("allowed");
    expect(call("203.0.113.1", 62)).toBe("rate_limited");
    // A DIFFERENT source has its own window.
    expect(call("203.0.113.2", 62)).toBe("allowed");
    // The next minute resets it.
    expect(call("203.0.113.1", 120)).toBe("allowed");
  });

  it("exempts a request with no resolvable IP from the flood limit (nothing to key on)", () => {
    const policy = networkAccessPolicy({ GATEWAY_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE: "1" });
    const shared = limiter();
    expect(checkNetworkAccess(headers({}), policy, shared, 60)).toBe("allowed");
    expect(checkNetworkAccess(headers({}), policy, shared, 60)).toBe("allowed");
  });

  it("a misconfiguration short-circuits before any IP is even resolved", () => {
    const policy = networkAccessPolicy({ GATEWAY_IP_ALLOWLIST: "nope" });
    expect(
      checkNetworkAccess(headers({ [CLIENT_IP_HEADER]: "203.0.113.9" }), policy, limiter(), 0),
    ).toBe("misconfigured");
  });
});

// ---------------------------------------------------------------------------
// 3. the MOUNT, through the composition root
// ---------------------------------------------------------------------------

describe("the gate is mounted by createGatewayApp", () => {
  const ALLOWLIST = { GATEWAY_IP_ALLOWLIST: '["203.0.113.0/24"]' };

  it("denies an ANONYMOUS operation from an off-list IP — proves it is mounted", async () => {
    // `/healthz` is contract-anonymous: it answers 200 for anyone. If the gate
    // is not mounted this is 200 and the test fails.
    const res = await gatedApp().call("/healthz", ALLOWLIST, "198.51.100.9");
    expect(res.status).toBe(403);
    const body = await envelope(res);
    expect(body.error.code).toBe("ip_denied");
    expect(body.error.message).toBe("source IP is not permitted");
    expect(body.error.type).toBe("ferrogate_error");
    // The refusal still carries a correlation id: the gate sits AFTER
    // `requestId`, which is the only reason an operator can find it in a log.
    expect(res.headers.get("x-request-id")).not.toBeNull();
  });

  it("serves the same operation normally from an ALLOWED IP", async () => {
    const res = await gatedApp().call("/healthz", ALLOWLIST, "203.0.113.9");
    expect(res.status).toBe(200);
  });

  it("is inert when no var is set — an unconfigured deployment is unchanged", async () => {
    const res = await gatedApp().call("/healthz", {}, "198.51.100.9");
    expect(res.status).toBe(200);
  });

  it("runs BEFORE the auth guard: a credential-less request is 403 ip_denied, not 401", async () => {
    // `/v1/tools` requires a bearer token. Without the gate — or with the gate
    // mounted after `contractAuth` — this is `401 missing_api_key`, and that is
    // the whole Rust reason the gate exists: a credential-stuffing scan must
    // never reach the virtual-key/storage lookup.
    const res = await gatedApp().call("/v1/tools", ALLOWLIST, "198.51.100.9");
    expect(res.status).toBe(403);
    expect((await envelope(res)).error.code).toBe("ip_denied");
  });

  it("still authenticates normally once the IP is admitted", async () => {
    const res = await gatedApp().call("/v1/tools", ALLOWLIST, "203.0.113.9");
    expect(res.status).toBe(401);
    expect((await envelope(res)).error.code).toBe("missing_api_key");
  });

  it("answers 429 unauthenticated_rate_limited past the window, pre-auth", async () => {
    const app = gatedApp();
    const env = { GATEWAY_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE: "2" };
    expect((await app.call("/healthz", env, "203.0.113.5")).status).toBe(200);
    expect((await app.call("/healthz", env, "203.0.113.5")).status).toBe(200);
    const third = await app.call("/healthz", env, "203.0.113.5");
    expect(third.status).toBe(429);
    const body = await envelope(third);
    expect(body.error.code).toBe("unauthenticated_rate_limited");
    expect(body.error.message).toBe("too many requests from this source; try again later");
  });

  it("a declared-but-unusable var answers 503, NOT a silently open gateway", async () => {
    const res = await gatedApp().call(
      "/healthz",
      { GATEWAY_IP_ALLOWLIST: '["10.0.0.0/8","garbage"]' },
      "203.0.113.9",
    );
    // 200 here would mean a typo in the allowlist opened the gateway; 403 would
    // be indistinguishable from a legitimate deny. Neither is acceptable.
    expect(res.status).toBe(503);
    const body = await envelope(res);
    expect(body.error.code).toBe("network_access_misconfigured");
    expect(body.error.message).toContain("garbage");
  });
});
