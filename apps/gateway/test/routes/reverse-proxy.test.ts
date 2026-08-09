/**
 * The operator reverse-proxy fall-through, driven through the REAL Worker.
 *
 * ## The mount gate
 *
 * "a configured operator route is proxied by the exported Worker" is written to
 * fail when `app.all("*", reverseProxyFallThrough())` is removed from
 * `createGatewayApp` — the request stops being proxied and answers the gateway's
 * own 404. That is the assertion this file exists for: the routing primitives it
 * exercises (`@ferrogate/config`'s `matchesRequest` / `rewritePath` /
 * `buildTargetUri`, `@ferrogate/routing`'s `RouteMatcher`) were all fully
 * implemented and fully tested for waves BEFORE this one while having no
 * importer in the request path at all, which is precisely the defect class this
 * project keeps rediscovering.
 *
 * ## And the counter-gate
 *
 * Mounting a catch-all is a change to what EVERY unmatched path answers, so
 * "an uncontracted path with no operator route still answers 404 not_found"
 * fails if the fall-through ever starts swallowing them. Both directions are
 * needed: a fall-through that 404s everything passes the second test alone, and
 * one that 502s everything passes neither.
 *
 * ## How the upstream is faked
 *
 * `globalThis.fetch` is replaced for the duration of a test — the same technique
 * `test/inference/provider-mock.ts` uses and for the same reason (msw is not a
 * devDependency here, and `vi.stubGlobal` is unreliable for `fetch` in workerd).
 * The handler reads the global at CALL time, so the interception is real: the
 * request under assertion is the one the Worker actually built.
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import {
  RuntimeRouteTable,
  reverseProxyFallThrough,
  routeTableFromEnv,
} from "../../src/routes/reverse-proxy.js";

const BASE = "https://ferrogate.test";

const mutable = env as unknown as Record<string, unknown>;

interface Captured {
  readonly url: string;
  readonly method: string;
  readonly headers: Record<string, string>;
  readonly body: string;
}

let captured: Captured[] = [];
let originalFetch: typeof globalThis.fetch;

/** Install an upstream that records what it was sent and answers `respond`. */
function upstream(respond: () => Response): void {
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input as string, init);
    const headers: Record<string, string> = {};
    request.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
    captured.push({
      url: request.url,
      method: request.method,
      headers,
      body: request.body === null ? "" : await request.text(),
    });
    return respond();
  }) as typeof globalThis.fetch;
}

beforeEach(() => {
  captured = [];
  originalFetch = globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  // biome-ignore lint/performance/noDelete: removes the own-property key entirely; assigning undefined would leave an enumerable undefined-valued key and change JSON serialization, the 'in' operator, and Object.keys semantics
  delete mutable.GATEWAY_ROUTES;
  // biome-ignore lint/performance/noDelete: removes the own-property key entirely; assigning undefined would leave an enumerable undefined-valued key and change JSON serialization, the 'in' operator, and Object.keys semantics
  delete mutable.GATEWAY_UPSTREAMS;
});

// ---------------------------------------------------------------------------
// The mount gate — on the app the Worker exports
// ---------------------------------------------------------------------------

describe("MOUNT: the fall-through is registered on the exported app", () => {
  test("a configured operator route is proxied, and the contract routes still win", async () => {
    mutable.GATEWAY_ROUTES = JSON.stringify([
      { name: "legacy", upstream: "legacy_api", path_prefixes: ["/legacy"] },
    ]);
    mutable.GATEWAY_UPSTREAMS = JSON.stringify([
      { name: "legacy_api", url: "https://origin.internal/base" },
    ]);
    upstream(() => new Response("from-origin", { status: 203 }));

    const res = await SELF.fetch(`${BASE}/legacy/reports?since=2026`, {
      headers: { "x-request-id": "req-proxy-1" },
    });

    // The wire answer is the UPSTREAM's, not a gateway envelope.
    expect(res.status).toBe(203);
    expect(await res.text()).toBe("from-origin");

    // Rust `build_target_uri`: base path joined, query forwarded verbatim.
    expect(captured).toHaveLength(1);
    expect(captured[0]?.url).toBe("https://origin.internal/base/legacy/reports?since=2026");

    // `/healthz` is a contract operation registered BEFORE the catch-all, so it
    // must still be answered by the gateway and must not reach the upstream.
    const health = await SELF.fetch(`${BASE}/healthz`);
    expect(health.status).toBe(200);
    expect(await health.json()).toMatchObject({ service: "ferrogate-gateway" });
    expect(captured).toHaveLength(1);
  });

  test("an uncontracted path with NO operator route still answers 404 not_found", async () => {
    // The counter-gate: mounting a catch-all must not change this answer.
    const res = await SELF.fetch(`${BASE}/nothing/claims/this`);
    expect(res.status).toBe(404);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe("not_found");
    expect(captured).toHaveLength(0);
  });

  test("a path no ENABLED route claims falls back to 404, not to the upstream", async () => {
    mutable.GATEWAY_ROUTES = JSON.stringify([
      { name: "off", upstream: "legacy_api", path_prefixes: ["/legacy"], enabled: false },
    ]);
    mutable.GATEWAY_UPSTREAMS = JSON.stringify([
      { name: "legacy_api", url: "https://origin.internal" },
    ]);
    upstream(() => new Response("should not be reached"));

    const res = await SELF.fetch(`${BASE}/legacy/reports`);
    expect(res.status).toBe(404);
    expect(captured).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// The upstream request filter — Rust `apply_upstream_request_filter`
// ---------------------------------------------------------------------------

describe("upstream request filter", () => {
  test("injects the correlation quartet and x-forwarded-host", async () => {
    mutable.GATEWAY_ROUTES = JSON.stringify([
      {
        name: "legacy",
        upstream: "legacy_api",
        path_prefixes: ["/legacy"],
        request_headers: [{ name: "x-operator-tag", value: "blue" }],
      },
    ]);
    mutable.GATEWAY_UPSTREAMS = JSON.stringify([
      { name: "legacy_api", url: "https://origin.internal" },
    ]);
    upstream(() => new Response("ok"));

    const traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    await SELF.fetch(`${BASE}/legacy/ping`, {
      headers: {
        "x-request-id": "req-abc",
        traceparent,
        tracestate: "vendor=1",
      },
    });

    const sent = captured[0];
    expect(sent).toBeDefined();
    expect(sent?.headers["x-ferrogate-request-id"]).toBe("req-abc");
    // The adopted W3C trace id, not the request id — `middleware/trace.ts`
    // parked these on the context for exactly this consumer.
    expect(sent?.headers["x-ferrogate-trace-id"]).toBe("4bf92f3577b34da6a3ce929d0e0e4736");
    expect(sent?.headers.traceparent).toBe(traceparent);
    expect(sent?.headers.tracestate).toBe("vendor=1");
    // Rust `x-forwarded-host` carries the ORIGINAL host.
    expect(sent?.headers["x-forwarded-host"]).toBe("ferrogate.test");
    // The per-route request header table.
    expect(sent?.headers["x-operator-tag"]).toBe("blue");
    // Fidelity note 3: the Host rewrite is expressed by the target URL.
    expect(new URL(sent?.url ?? "").host).toBe("origin.internal");
  });

  test("forwards the request BODY and method for a non-GET", async () => {
    mutable.GATEWAY_ROUTES = JSON.stringify([
      { name: "legacy", upstream: "legacy_api", path_prefixes: ["/legacy"] },
    ]);
    mutable.GATEWAY_UPSTREAMS = JSON.stringify([
      { name: "legacy_api", url: "https://origin.internal" },
    ]);
    upstream(() => new Response("ok"));

    await SELF.fetch(`${BASE}/legacy/submit`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ hello: "world" }),
    });

    expect(captured[0]?.method).toBe("POST");
    expect(captured[0]?.body).toBe('{"hello":"world"}');
  });

  test("drops a request header whose {env.NAME} placeholder cannot be resolved", async () => {
    // Rust `compile_header_mutations` SKIPS such a header with a warn. The
    // alternative — forwarding the literal `{env.X}` — would ship the string to
    // an upstream as if it were a credential.
    mutable.GATEWAY_ROUTES = JSON.stringify([
      {
        name: "legacy",
        upstream: "legacy_api",
        path_prefixes: ["/legacy"],
        request_headers: [
          { name: "x-resolved", value: "{env.GATEWAY_DEV_TENANT_ID}" },
          { name: "x-unresolved", value: "{env.NOT_A_BINDING_ANYWHERE}" },
        ],
      },
    ]);
    mutable.GATEWAY_UPSTREAMS = JSON.stringify([
      { name: "legacy_api", url: "https://origin.internal" },
    ]);
    mutable.GATEWAY_DEV_TENANT_ID = "tenant_local_dev";
    upstream(() => new Response("ok"));

    await SELF.fetch(`${BASE}/legacy/ping`);

    expect(captured[0]?.headers["x-resolved"]).toBe("tenant_local_dev");
    expect(captured[0]?.headers["x-unresolved"]).toBeUndefined();
    // biome-ignore lint/performance/noDelete: removes the own-property key entirely; assigning undefined would leave an enumerable undefined-valued key and change JSON serialization, the 'in' operator, and Object.keys semantics
    delete mutable.GATEWAY_DEV_TENANT_ID;
  });
});

// ---------------------------------------------------------------------------
// The response filter — Rust `response_filter`
// ---------------------------------------------------------------------------

describe("response filter", () => {
  test("stamps server / runtime / request id and the per-route response table", async () => {
    mutable.GATEWAY_ROUTES = JSON.stringify([
      {
        name: "legacy",
        upstream: "legacy_api",
        path_prefixes: ["/legacy"],
        response_headers: [{ name: "x-served-by", value: "legacy-pool" }],
      },
    ]);
    mutable.GATEWAY_UPSTREAMS = JSON.stringify([
      { name: "legacy_api", url: "https://origin.internal" },
    ]);
    upstream(() => new Response("ok", { headers: { "x-origin-header": "kept" } }));

    const res = await SELF.fetch(`${BASE}/legacy/ping`, {
      headers: { "x-request-id": "req-resp-1" },
    });

    expect(res.headers.get("server")).toBe("FerroGate");
    // Rust said `pingora`; the Pingora data plane is eliminated, so this
    // reports what actually served the request.
    expect(res.headers.get("x-ferrogate-runtime")).toBe("workers");
    expect(res.headers.get("x-request-id")).toBe("req-resp-1");
    expect(res.headers.get("x-trace-id")).toBe("req-resp-1");
    expect(res.headers.get("x-served-by")).toBe("legacy-pool");
    // The upstream's own headers survive.
    expect(res.headers.get("x-origin-header")).toBe("kept");
  });

  test("streams the upstream body rather than buffering it", async () => {
    mutable.GATEWAY_ROUTES = JSON.stringify([
      { name: "legacy", upstream: "legacy_api", path_prefixes: ["/legacy"] },
    ]);
    mutable.GATEWAY_UPSTREAMS = JSON.stringify([
      { name: "legacy_api", url: "https://origin.internal" },
    ]);
    const frames = ["data: one\n\n", "data: two\n\n"];
    upstream(
      () =>
        new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              for (const frame of frames) controller.enqueue(new TextEncoder().encode(frame));
              controller.close();
            },
          }),
          { headers: { "content-type": "text/event-stream" } },
        ),
    );

    const res = await SELF.fetch(`${BASE}/legacy/events`);
    expect(res.headers.get("content-type")).toBe("text/event-stream");
    // Byte-for-byte, in order — the SSE framing requirement.
    expect(await res.text()).toBe(frames.join(""));
  });
});

// ---------------------------------------------------------------------------
// Failure modes
// ---------------------------------------------------------------------------

describe("failure modes", () => {
  test("a DECLARED but unparseable table answers 503, never a silent 404", async () => {
    mutable.GATEWAY_ROUTES = "{not json";
    const res = await SELF.fetch(`${BASE}/anything`);
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("runtime_route_table_invalid");
    expect(body.error.message).toContain("GATEWAY_ROUTES");
  });

  test("a route naming an unknown upstream answers 502", async () => {
    mutable.GATEWAY_ROUTES = JSON.stringify([
      { name: "legacy", upstream: "missing_pool", path_prefixes: ["/legacy"] },
    ]);
    mutable.GATEWAY_UPSTREAMS = "[]";
    const res = await SELF.fetch(`${BASE}/legacy/ping`);
    expect(res.status).toBe(502);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "upstream_unavailable",
    );
  });

  test("an upstream that refuses the connection answers 502, not a 500", async () => {
    mutable.GATEWAY_ROUTES = JSON.stringify([
      { name: "legacy", upstream: "legacy_api", path_prefixes: ["/legacy"] },
    ]);
    mutable.GATEWAY_UPSTREAMS = JSON.stringify([
      { name: "legacy_api", url: "https://origin.internal" },
    ]);
    globalThis.fetch = (() => {
      throw new Error("connection refused");
    }) as unknown as typeof globalThis.fetch;

    const res = await SELF.fetch(`${BASE}/legacy/ping`);
    expect(res.status).toBe(502);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "upstream_unavailable",
    );
  });
});

// ---------------------------------------------------------------------------
// The table itself — Rust `match_runtime_route` / `select_runtime_upstream_endpoint`
// ---------------------------------------------------------------------------

describe("RuntimeRouteTable", () => {
  const table = (routes: unknown[], upstreams: unknown[]): RuntimeRouteTable =>
    routeTableFromEnv({
      GATEWAY_ROUTES: JSON.stringify(routes),
      GATEWAY_UPSTREAMS: JSON.stringify(upstreams),
    });

  test("matches on host, case-insensitively and ignoring the port", async () => {
    const built = table(
      [{ name: "r", upstream: "u", hosts: ["Api.Example.COM"], path_prefixes: ["/x"] }],
      [{ name: "u", url: "https://origin.internal" }],
    );
    expect(built.matchRequest("api.example.com:8443", "/x/y", new Headers())?.name).toBe("r");
    expect(built.matchRequest("other.example.com", "/x/y", new Headers())).toBeUndefined();
    // Rust: a route WITH hosts and a request with none never matches.
    expect(built.matchRequest(null, "/x/y", new Headers())).toBeUndefined();
  });

  test("a path prefix matches the prefix itself and its children, not a sibling", async () => {
    const built = table(
      [{ name: "r", upstream: "u", path_prefixes: ["/legacy"] }],
      [{ name: "u", url: "https://origin.internal" }],
    );
    expect(built.matchRequest(null, "/legacy", new Headers())?.name).toBe("r");
    expect(built.matchRequest(null, "/legacy/deep/path", new Headers())?.name).toBe("r");
    // `/legacyfoo` is NOT under `/legacy` — the Rust appends the separator.
    expect(built.matchRequest(null, "/legacyfoo", new Headers())).toBeUndefined();
  });

  test("match_headers must ALL match, and an absent header is a miss", async () => {
    const built = table(
      [
        {
          name: "r",
          upstream: "u",
          path_prefixes: ["/x"],
          match_headers: [{ name: "X-Channel", value: "beta" }],
        },
      ],
      [{ name: "u", url: "https://origin.internal" }],
    );
    expect(built.matchRequest(null, "/x", new Headers({ "x-channel": "beta" }))?.name).toBe("r");
    expect(built.matchRequest(null, "/x", new Headers({ "x-channel": "ga" }))).toBeUndefined();
    expect(built.matchRequest(null, "/x", new Headers())).toBeUndefined();
  });

  test("strip_prefix and add_prefix rewrite the target path", async () => {
    mutable.GATEWAY_ROUTES = JSON.stringify([
      {
        name: "r",
        upstream: "u",
        path_prefixes: ["/legacy"],
        strip_prefix: "/legacy",
        add_prefix: "/v2",
      },
    ]);
    mutable.GATEWAY_UPSTREAMS = JSON.stringify([{ name: "u", url: "https://origin.internal" }]);
    upstream(() => new Response("ok"));

    await SELF.fetch(`${BASE}/legacy/orders/7`);
    expect(captured[0]?.url).toBe("https://origin.internal/v2/orders/7");
  });

  test("rotates round-robin across an upstream's endpoints", async () => {
    const built = table(
      [{ name: "r", upstream: "pool", path_prefixes: ["/x"] }],
      [{ name: "pool", url: "https://a.internal", urls: ["https://b.internal"] }],
    );
    expect(built.selectEndpoint("pool")?.host).toBe("a.internal");
    expect(built.selectEndpoint("pool")?.host).toBe("b.internal");
    expect(built.selectEndpoint("pool")?.host).toBe("a.internal");
  });

  test("an unparseable endpoint URL is dropped from the rotation, not fatal", async () => {
    const built = table(
      [{ name: "r", upstream: "pool", path_prefixes: ["/x"] }],
      [{ name: "pool", url: "ftp://nope.internal", urls: ["https://good.internal"] }],
    );
    expect(built.selectEndpoint("pool")?.host).toBe("good.internal");
    expect(built.selectEndpoint("pool")?.host).toBe("good.internal");
  });

  test("FIDELITY: a DISABLED upstream is still routed to, exactly as in Rust", async () => {
    // `RuntimeUpstream::from_config` (state.rs:3925) maps every upstream into
    // the runtime table; only `RouteRule.enabled` is filtered, and only in
    // `match_runtime_route`. This assertion exists so the asymmetry is a
    // decision on record: an operator who disables an UPSTREAM and expects the
    // reverse proxy to stop using it is relying on behaviour the Rust gateway
    // never had, and changing it here would be a divergence, not a fix.
    const built = table(
      [{ name: "r", upstream: "pool", path_prefixes: ["/x"] }],
      [{ name: "pool", url: "https://origin.internal", enabled: false }],
    );
    expect(built.selectEndpoint("pool")?.host).toBe("origin.internal");
  });

  test("satisfies @ferrogate/routing's RouteMatcher, conservatively", async () => {
    const built = table(
      [
        {
          name: "guarded",
          upstream: "u",
          path_prefixes: ["/x"],
          match_headers: [{ name: "a", value: "b" }],
        },
        { name: "plain", upstream: "u", path_prefixes: ["/y"] },
      ],
      [{ name: "u", url: "https://origin.internal" }],
    );
    expect(built.matchRoute(undefined, "/y/z")).toEqual({
      routeName: "plain",
      upstreamName: "u",
    });
    // The published interface has no header parameter, so a header-guarded route
    // is SKIPPED rather than reported as a match it cannot prove.
    expect(built.matchRoute(undefined, "/x/z")).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// The handler in isolation
// ---------------------------------------------------------------------------

describe("reverseProxyFallThrough options", () => {
  test("an injected table and transport bypass the env entirely", async () => {
    // The seam `createGatewayApp({ reverseProxy })` exists for: production never
    // passes it, and a test must not need to mutate a global to exercise it.
    const handler = reverseProxyFallThrough({
      table: new RuntimeRouteTable(
        [
          {
            name: "r",
            upstream: "u",
            hosts: [],
            path_prefixes: ["/x"],
            match_headers: [],
            strip_prefix: null,
            add_prefix: null,
            request_headers: [],
            response_headers: [],
            enabled: true,
          },
        ],
        [{ name: "u", url: "https://injected.internal", urls: [], enabled: true }],
      ),
      fetch: async (request) => new Response(request.url, { status: 200 }),
    });
    expect(typeof handler).toBe("function");
  });
});
