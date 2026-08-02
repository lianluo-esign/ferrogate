/**
 * The OPERATOR REVERSE-PROXY FALL-THROUGH — Rust `AppState::match_runtime_route`
 * (`state_routing.rs:816`) + `server/proxy.rs`'s upstream/response filters.
 *
 * ## What was missing, and why it mattered
 *
 * In Rust a request that matches no route group does not 404. It falls through
 * to the operator's `[[routes]]` host/path table, resolves an `[[upstreams]]`
 * entry, and Pingora proxies it. That is the difference between "an LLM API" and
 * "a gateway": every non-`/v1/**` surface an operator puts behind FerroGate goes
 * through this path. Until this module existed the TS tree answered
 * `404 not_found` to all of it, and — the reason it went unnoticed — everything
 * around it was already ported and had NO IMPORTER:
 *
 *   - `packages/config` validates `routes` + `upstreams` and ships
 *     `normalizeHost` / `parseUpstreamEndpoint` / `rewritePath` /
 *     `buildTargetUri` / `matchesRequest` in `src/routing.ts`, whose only
 *     callers were its own tests and one validator;
 *   - `@ferrogate/routing` exports `RouteMatch` + `RouteMatcher` — an interface
 *     pair with no implementation anywhere;
 *   - `middleware/trace.ts` parks the adopted `traceparent` / `tracestate` on
 *     the request context "for a dispatcher the day it lands", and nothing read
 *     them.
 *
 * This module is the first real importer of all three. {@link ConfigRouteMatcher}
 * is the concrete `RouteMatcher` the `@ferrogate/routing` docstring says belongs
 * in `apps/gateway`, and every routing primitive below is delegated to
 * `@ferrogate/config` rather than re-derived, so the CLI's `ferrogate check` and
 * the data plane can never disagree about what a route means.
 *
 * ## Where the table comes from on this platform
 *
 * Rust read a TOML/Caddyfile document off disk. A Worker has no disk, so the
 * table is two JSON vars — `GATEWAY_ROUTES` and `GATEWAY_UPSTREAMS` — parsed
 * with the SAME `routeRuleSchema` / `upstreamSchema` the operator document is
 * validated by. Unset ⇒ this whole module is inert and `app.notFound` keeps
 * answering, which is exactly the behaviour of a Rust gateway with an empty
 * `[[routes]]` table.
 *
 * A var that is PRESENT but unparseable answers **503
 * `runtime_route_table_invalid`**, never "no routes". Rust refuses to boot on a
 * bad config; a Worker has no boot to refuse at, and silently degrading a typo
 * into "route table empty" would send an operator's production traffic to a 404
 * with nothing in the logs. This is the same posture `middleware/network.ts`
 * already takes for a malformed `GATEWAY_IP_ALLOWLIST`.
 *
 * ## Deliberate fidelity notes (read before "fixing" any of these)
 *
 * **1. `Upstream.enabled` is NOT consulted, because Rust does not consult it
 * here.** `RuntimeUpstream::from_config` (`state.rs:3925`) maps EVERY upstream
 * into the runtime table; only `RouteRule.enabled` is filtered, and it is
 * filtered in `match_runtime_route`. An operator who disables an upstream and
 * expects the reverse proxy to stop using it is relying on behaviour the Rust
 * gateway never had. Pinned by a test so the asymmetry is a decision on record
 * rather than an oversight.
 *
 * **2. Endpoint rotation is round-robin over an ISOLATE-LOCAL counter.** Rust
 * used a per-process `AtomicU64` — also not global — so the shape is faithful,
 * but a Worker runs N isolates and each keeps its own cursor. The consequence is
 * stated rather than hidden: the distribution over a fleet is still uniform in
 * expectation, but two consecutive requests from one client can land on the same
 * endpoint more often than a single shared cursor would allow. There is no
 * per-request health signal in Rust's selection either — `select_runtime_upstream_endpoint`
 * is pure rotation — so nothing is lost relative to the port target.
 *
 * **3. The `Host` rewrite is done by the URL, not by a header.** Rust inserted
 * `Host: <endpoint.authority>` explicitly because Pingora would otherwise pass
 * the downstream `Host` through. On Workers the outbound `Host` is derived from
 * the request URL and a `host` header set on a `Request` is ignored, so building
 * the target as `scheme://authority<path?query>` IS the rewrite — same bytes on
 * the wire, one fewer moving part. `x-forwarded-host` still carries the ORIGINAL
 * host, exactly as in Rust, and that one really is a header.
 *
 * **4. The body is streamed, never buffered.** `new Response(upstream.body, …)`
 * hands the upstream's own `ReadableStream` to the client, so SSE framing and
 * chunk boundaries survive byte-for-byte — the same requirement the inference
 * path has.
 *
 * ## What is NOT ported here
 *
 * Upstream HEALTH. Rust's selection is pure rotation (see note 2), so there is
 * nothing to port on that axis; the circuit-breaker/failover ladder that DOES
 * exist lives in `src/inference/` and applies to provider dispatch, not to
 * operator routes. A request to a dead endpoint answers `502 upstream_unavailable`
 * and the next request rotates onward, which is the Rust behaviour.
 */
import {
  type RouteRule,
  type Upstream,
  type UpstreamEndpoint,
  buildTargetUri,
  endpointUrls,
  matchesRequest,
  normalizeHost,
  parseUpstreamEndpoint,
  resolveEnvPlaceholders,
  rewritePath,
  routeRuleSchema,
  upstreamSchema,
} from "@ferrogate/config";
import type { RouteMatch, RouteMatcher } from "@ferrogate/routing";
import type { Context, MiddlewareHandler } from "hono";
import { HttpError } from "../middleware/errors.js";
import type { GatewayEnv } from "../ports.js";

/** Vars this module reads. Both absent ⇒ inert. */
export interface ReverseProxyBindings {
  /** JSON array of `[[routes]]` entries (`routeRuleSchema`). */
  readonly GATEWAY_ROUTES?: string;
  /** JSON array of `[[upstreams]]` entries (`upstreamSchema`). */
  readonly GATEWAY_UPSTREAMS?: string;
}

/** Raised when a declared table cannot be parsed. Rendered as 503. */
export class RuntimeRouteTableInvalid extends Error {
  override readonly name = "RuntimeRouteTableInvalid";
}

// ---------------------------------------------------------------------------
// The runtime table
// ---------------------------------------------------------------------------

/** Rust `RuntimeUpstream`: one upstream's parsed endpoints, in declared order. */
interface RuntimeUpstream {
  readonly name: string;
  readonly endpoints: readonly UpstreamEndpoint[];
}

/**
 * Rust `AppState`'s `runtime_routes` + `runtime_upstreams` + `upstream_counters`,
 * as one immutable object per environment.
 */
export class RuntimeRouteTable implements RouteMatcher {
  readonly #routes: readonly RouteRule[];
  readonly #upstreams: ReadonlyMap<string, RuntimeUpstream>;
  /** Rust `upstream_counters`: one rotation cursor per upstream NAME. */
  readonly #cursors = new Map<string, number>();

  constructor(routes: readonly RouteRule[], upstreams: readonly Upstream[]) {
    // Rust filters `enabled` inside `match_runtime_route`, i.e. on every
    // request, not at build time. Doing it here is equivalent because the table
    // is immutable, and it keeps the hot path from re-testing a constant.
    this.#routes = routes.filter((route) => route.enabled);
    const compiled = new Map<string, RuntimeUpstream>();
    for (const upstream of upstreams) {
      // NOT filtered on `upstream.enabled` — see fidelity note 1 in the header.
      const endpoints: UpstreamEndpoint[] = [];
      for (const raw of endpointUrls(upstream)) {
        try {
          endpoints.push(parseUpstreamEndpoint(raw));
        } catch (error) {
          // Rust `expect()`s here, because `Config::validate()` already rejected
          // a malformed endpoint before the process started. There is no such
          // gate on this platform, so a bad URL must not take the isolate down:
          // it is DROPPED from the rotation and, if it was the only one, the
          // upstream has no endpoints and every route pointing at it answers
          // 502 — a loud, per-request failure instead of a dead Worker.
          void error;
        }
      }
      compiled.set(upstream.name, { name: upstream.name, endpoints });
    }
    this.#upstreams = compiled;
  }

  /** True when there is nothing to fall through to — the shipped default. */
  get empty(): boolean {
    return this.#routes.length === 0;
  }

  /**
   * `@ferrogate/routing`'s `RouteMatcher`. Rust `match_runtime_route`, minus the
   * header matchers — which that interface has no parameter for. Prefer
   * {@link matchRequest} inside the data plane; this exists so the table
   * satisfies the published port, and it is deliberately CONSERVATIVE: a route
   * carrying `match_headers` is skipped here rather than reported as a match it
   * has not proven.
   */
  matchRoute(host: string | undefined, path: string): RouteMatch | undefined {
    const rule = this.#routes.find(
      (route) =>
        route.match_headers.length === 0 &&
        matchesRequest(route, host === undefined ? null : normalizeHost(host), path, {}),
    );
    return rule === undefined
      ? undefined
      : { routeName: rule.name, upstreamName: rule.upstream };
  }

  /** Rust `match_runtime_route`: FIRST enabled route that matches, in order. */
  matchRequest(host: string | null, path: string, headers: Headers): RouteRule | undefined {
    const headerBag: Record<string, string | undefined> = {};
    for (const [name, value] of headers) headerBag[name] = value;
    const normalized = host === null ? null : normalizeHost(host);
    return this.#routes.find((route) => matchesRequest(route, normalized, path, headerBag));
  }

  /**
   * Rust `select_runtime_upstream_endpoint`: `counter.fetch_add(1) % len`.
   *
   * `undefined` when the upstream is unknown or has no usable endpoint — the
   * caller turns that into 502, matching Rust's `missing_ctx_error` 502 class.
   */
  selectEndpoint(upstreamName: string): UpstreamEndpoint | undefined {
    const upstream = this.#upstreams.get(upstreamName);
    if (upstream === undefined || upstream.endpoints.length === 0) return undefined;
    const next = this.#cursors.get(upstreamName) ?? 0;
    this.#cursors.set(upstreamName, next + 1);
    return upstream.endpoints[next % upstream.endpoints.length];
  }
}

function parseTable<T>(
  raw: string | undefined,
  varName: string,
  parseEntry: (entry: unknown) => T,
): T[] {
  if (raw === undefined || raw.trim() === "") return [];
  let decoded: unknown;
  try {
    decoded = JSON.parse(raw);
  } catch {
    throw new RuntimeRouteTableInvalid(`${varName} is not valid JSON`);
  }
  if (!Array.isArray(decoded)) {
    throw new RuntimeRouteTableInvalid(`${varName} must be a JSON array`);
  }
  return decoded.map((entry, index) => {
    try {
      return parseEntry(entry);
    } catch (error) {
      const detail = error instanceof Error ? error.message.split("\n")[0] : "invalid entry";
      throw new RuntimeRouteTableInvalid(`${varName}[${index}] is invalid: ${detail}`);
    }
  });
}

/**
 * Build (and memoize) the table for one environment.
 *
 * The cache is keyed on the env OBJECT — one per Worker invocation context —
 * but it also stores the two raw var strings and rebuilds when either differs.
 * That second half is not decoration: the rotation cursors live on the table, so
 * a stale table would keep rotating over a stale endpoint list, and a test that
 * rewrites `env.GATEWAY_ROUTES` between cases would silently keep the first
 * case's routes.
 */
const TABLES = new WeakMap<
  object,
  {
    readonly routes: string | undefined;
    readonly upstreams: string | undefined;
    readonly built: RuntimeRouteTable | RuntimeRouteTableInvalid;
  }
>();

export function routeTableFromEnv(env: ReverseProxyBindings): RuntimeRouteTable {
  const key = env as unknown as object;
  const cacheable = typeof key === "object" && key !== null;
  const cached = cacheable ? TABLES.get(key) : undefined;
  if (
    cached !== undefined &&
    cached.routes === env.GATEWAY_ROUTES &&
    cached.upstreams === env.GATEWAY_UPSTREAMS
  ) {
    if (cached.built instanceof RuntimeRouteTableInvalid) throw cached.built;
    return cached.built;
  }

  let built: RuntimeRouteTable | RuntimeRouteTableInvalid;
  try {
    built = new RuntimeRouteTable(
      parseTable(env.GATEWAY_ROUTES, "GATEWAY_ROUTES", (entry) => routeRuleSchema.parse(entry)),
      parseTable(env.GATEWAY_UPSTREAMS, "GATEWAY_UPSTREAMS", (entry) =>
        upstreamSchema.parse(entry),
      ),
    );
  } catch (error) {
    built =
      error instanceof RuntimeRouteTableInvalid
        ? error
        : new RuntimeRouteTableInvalid("route table could not be built");
  }
  if (cacheable) {
    TABLES.set(key, {
      routes: env.GATEWAY_ROUTES,
      upstreams: env.GATEWAY_UPSTREAMS,
      built,
    });
  }
  if (built instanceof RuntimeRouteTableInvalid) throw built;
  return built;
}

// ---------------------------------------------------------------------------
// Header mutation tables
// ---------------------------------------------------------------------------

/**
 * Rust `compile_header_mutations`: apply each configured mutation, SKIPPING any
 * whose value carries an unresolvable `{env.NAME}` placeholder.
 *
 * Skipping — rather than failing the request or writing the literal — is the
 * Rust behaviour verbatim (`warn!("skipping precompiled header with unresolved
 * environment placeholder")`), and it is the safe one: the alternative is
 * forwarding the string `{env.UPSTREAM_TOKEN}` to an upstream as if it were a
 * credential.
 */
function applyHeaderMutations(
  target: Headers,
  mutations: readonly { name: string; value: string }[],
  env: Record<string, string | undefined>,
): void {
  for (const mutation of mutations) {
    let value: string;
    try {
      value = resolveEnvPlaceholders(mutation.value, env);
    } catch {
      continue;
    }
    try {
      target.set(mutation.name, value);
    } catch {
      // An invalid header NAME. Rust `expect()`s (config validation caught it);
      // here it is dropped rather than thrown, for the reason in the endpoint
      // parse above.
    }
  }
}

/** Only string-valued bindings can be a `{env.NAME}` source. */
function stringBindings(env: unknown): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  if (typeof env !== "object" || env === null) return out;
  for (const [name, value] of Object.entries(env as Record<string, unknown>)) {
    if (typeof value === "string") out[name] = value;
  }
  return out;
}

// ---------------------------------------------------------------------------
// The handler
// ---------------------------------------------------------------------------

/** Response headers Rust's `response_filter` always attaches. */
export const PROXY_SERVER_HEADER = "FerroGate";

/** Injection/testing seam. Production passes nothing. */
export interface ReverseProxyOptions {
  /** Override the table. Defaults to {@link routeTableFromEnv}. */
  readonly table?: RuntimeRouteTable | ((env: ReverseProxyBindings) => RuntimeRouteTable);
  /** Override the outbound transport. Defaults to the global `fetch`. */
  readonly fetch?: (request: Request) => Promise<Response>;
  /** Runtime identity echoed on every proxied response. */
  readonly runtimeName?: string;
}

/**
 * The catch-all. Registered LAST in `createGatewayApp`, after every contract
 * route and after `/health`, because Hono runs matched handlers in REGISTRATION
 * order and an earlier `app.all("*")` would shadow all 271 operations.
 *
 * With no matching operator route it calls `c.notFound()`, so the gateway's own
 * `404 not_found` envelope is still what an undocumented path gets — mounting
 * this must not change the answer for any path the contract does not name AND
 * the operator has not claimed.
 */
export function reverseProxyFallThrough(
  options: ReverseProxyOptions = {},
): MiddlewareHandler<GatewayEnv> {
  return async (c) => {
    const env = (c.env ?? {}) as ReverseProxyBindings;

    let table: RuntimeRouteTable;
    try {
      table =
        options.table === undefined
          ? routeTableFromEnv(env)
          : typeof options.table === "function"
            ? options.table(env)
            : options.table;
    } catch (error) {
      // A DECLARED but unusable table. 503, never a silent 404 — see the header.
      throw new HttpError(
        503,
        "runtime_route_table_invalid",
        error instanceof Error ? error.message : "runtime route table is invalid",
      );
    }
    if (table.empty) return c.notFound();

    const url = new URL(c.req.url);
    const originalHost = c.req.header("host") ?? url.host;
    const route = table.matchRequest(originalHost, url.pathname, c.req.raw.headers);
    if (route === undefined) return c.notFound();

    const endpoint = table.selectEndpoint(route.upstream);
    if (endpoint === undefined) {
      // Rust's `missing_ctx_error` answers a 502-class failure for exactly this
      // shape: a matched route whose upstream cannot be resolved.
      throw new HttpError(
        502,
        "upstream_unavailable",
        `route ${route.name} names upstream ${route.upstream}, which has no usable endpoint`,
      );
    }

    // Rust `build_target_uri(endpoint, rewrite_path(path), query)`. The query is
    // forwarded verbatim; `url.search` already carries the leading `?`.
    const pathQuery = buildTargetUri(
      endpoint,
      rewritePath(route, url.pathname),
      url.search.replace(/^\?/, ""),
    );
    const target = `${endpoint.scheme}://${endpoint.authority}${pathQuery}`;

    // Rust `apply_upstream_request_filter`.
    const outboundHeaders = new Headers(c.req.raw.headers);
    // `Host` comes from the target URL on this platform — fidelity note 3.
    outboundHeaders.delete("host");
    outboundHeaders.set("x-ferrogate-request-id", c.get("requestId"));
    const traceId = c.get("traceId");
    if (traceId !== undefined && traceId !== null && traceId !== "") {
      outboundHeaders.set("x-ferrogate-trace-id", traceId);
    }
    const traceparent = c.get("traceparent");
    if (traceparent !== null && traceparent !== undefined) {
      outboundHeaders.set("traceparent", traceparent);
    }
    const tracestate = c.get("tracestate");
    if (tracestate !== null && tracestate !== undefined) {
      outboundHeaders.set("tracestate", tracestate);
    }
    outboundHeaders.set("x-forwarded-host", originalHost);
    const bindings = stringBindings(c.env);
    applyHeaderMutations(outboundHeaders, route.request_headers, bindings);

    const method = c.req.method;
    const outbound = new Request(target, {
      method,
      headers: outboundHeaders,
      // GET/HEAD may not carry a body; everything else streams the original.
      body: method === "GET" || method === "HEAD" ? undefined : c.req.raw.body,
      redirect: "manual",
    });

    const send = options.fetch ?? ((request: Request) => fetch(request));
    let upstream: Response;
    try {
      upstream = await send(outbound);
    } catch (error) {
      throw new HttpError(
        502,
        "upstream_unavailable",
        `upstream ${route.upstream} did not answer: ${
          error instanceof Error ? error.message : "transport failure"
        }`,
      );
    }

    // Rust `response_filter`. The BODY is passed through as a stream so upstream
    // framing survives byte-for-byte.
    const responseHeaders = new Headers(upstream.headers);
    responseHeaders.set("server", PROXY_SERVER_HEADER);
    responseHeaders.set("x-ferrogate-runtime", options.runtimeName ?? RUNTIME_IDENTITY);
    responseHeaders.set("x-request-id", c.get("requestId"));
    if (traceId !== undefined && traceId !== null && traceId !== "") {
      responseHeaders.set("x-trace-id", traceId);
    }
    applyHeaderMutations(responseHeaders, route.response_headers, bindings);

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: responseHeaders,
    });
  };
}

/**
 * Rust answered `x-ferrogate-runtime: pingora`. The Pingora data plane is
 * eliminated, so reporting `pingora` here would be a lie an operator's
 * dashboards would believe; this matches `RUNTIME_NAME` in `./index.ts`, which
 * `/healthz` already reports.
 */
const RUNTIME_IDENTITY = "workers";
