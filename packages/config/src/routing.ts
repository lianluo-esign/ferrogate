/**
 * Port of `ferrogate-config`'s `config/routing.rs` (inventory §5.4, "Routing"):
 * upstream-endpoint parsing and route-rule path rewriting / target-URI building.
 *
 * PORT-TODO(inventory §5.2/§5.8) — PACKAGE RELOCATION ONLY, BEHAVIOR IS CLOSED.
 * `build_target_uri`/`normalize_host` are the
 * data-plane leg the Rust crate note flags for relocation to the gateway app
 * (#560); they are ported here to preserve the public surface and are re-used
 * by the Hono data plane.
 */

/** Structural view of a `RouteRule` — only the fields the routing math reads. */
export interface RouteRuleLike {
  hosts?: string[];
  path_prefixes?: string[];
  match_headers?: { name: string; value: string }[];
  strip_prefix?: string | null;
  add_prefix?: string | null;
}

/** A parsed upstream endpoint (scheme / authority / base path). */
export interface UpstreamEndpoint {
  scheme: string;
  host: string;
  port: number;
  authority: string;
  basePath: string;
}

/** `host[:port]` -> `host`, trimmed and ASCII-lowercased. */
export function normalizeHost(host: string): string {
  const colon = host.indexOf(":");
  const bare = colon === -1 ? host : host.slice(0, colon);
  return bare.trim().toLowerCase();
}

/** Parse an upstream URL into its endpoint pieces. Throws on any malformed input. */
export function parseUpstreamEndpoint(raw: string): UpstreamEndpoint {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`invalid upstream URL ${raw}`);
  }
  const scheme = url.protocol.replace(/:$/, "").toLowerCase();
  if (scheme !== "http" && scheme !== "https") {
    throw new Error("upstream URL scheme must be http or https");
  }
  const host = url.hostname;
  if (host.length === 0) {
    throw new Error("upstream URL must include authority");
  }
  const port = url.port !== "" ? Number.parseInt(url.port, 10) : scheme === "https" ? 443 : 80;
  const defaultPort =
    (scheme === "https" && port === 443) || (scheme === "http" && port === 80);
  const authority = defaultPort ? host : `${host}:${port}`;
  const basePath = url.pathname.replace(/\/+$/, "");
  return { scheme, host, port, authority, basePath };
}

/** Apply a route's `strip_prefix` / `add_prefix` to an incoming path. */
export function rewritePath(route: RouteRuleLike, originalPath: string): string {
  let path = originalPath;
  const strip = route.strip_prefix ?? undefined;
  if (strip !== undefined && strip !== null) {
    if (path === strip) {
      path = "/";
    } else if (path.startsWith(`${strip.replace(/\/+$/, "")}/`)) {
      path = path.slice(strip.length);
      path = ensureLeadingSlash(path);
    }
  }
  const add = route.add_prefix ?? undefined;
  if (add !== undefined && add !== null) {
    path = joinUrlPath(add, path);
  }
  return ensureLeadingSlash(path);
}

/** Build the target path+query, then a full `scheme://authority<path?query>` string. */
export function buildTargetUri(
  endpoint: UpstreamEndpoint,
  rewrittenPath: string,
  query?: string | null,
): string {
  let path = joinUrlPath(endpoint.basePath, rewrittenPath);
  if (query !== undefined && query !== null && query.length > 0) {
    path += `?${query}`;
  }
  return path;
}

/** Full absolute target URL: `scheme://authority<path?query>`. */
export function buildTargetUrl(
  upstreamUrl: string,
  route: RouteRuleLike,
  originalPath: string,
  query?: string | null,
): string {
  const endpoint = parseUpstreamEndpoint(upstreamUrl);
  const pathQuery = buildTargetUri(endpoint, rewritePath(route, originalPath), query);
  return `${endpoint.scheme}://${endpoint.authority}${pathQuery}`;
}

/**
 * Whether a route matches a request. Ported from `RouteRule::matches_request`
 * (Rust `#[cfg(test)]`, kept here as a reusable data-plane primitive).
 */
export function matchesRequest(
  route: RouteRuleLike,
  host: string | null,
  path: string,
  headers: Record<string, string | undefined>,
): boolean {
  const hosts = route.hosts ?? [];
  if (hosts.length > 0) {
    if (host === null) return false;
    if (!hosts.some((configured) => configured.toLowerCase() === host.toLowerCase())) {
      return false;
    }
  }
  const prefixes = route.path_prefixes ?? [];
  const pathMatches =
    prefixes.length === 0 ||
    prefixes.some(
      (prefix) => path === prefix || path.startsWith(`${prefix.replace(/\/+$/, "")}/`),
    );
  if (!pathMatches) return false;

  const matchers = route.match_headers ?? [];
  return matchers.every((matcher) => {
    const lower = matcher.name.toLowerCase();
    for (const [key, value] of Object.entries(headers)) {
      if (key.toLowerCase() === lower) return value === matcher.value;
    }
    return false;
  });
}

function ensureLeadingSlash(path: string): string {
  return path.startsWith("/") ? path : `/${path}`;
}

function joinUrlPath(left: string, right: string): string {
  const l = left.replace(/\/+$/, "");
  const r = right.replace(/^\/+/, "");
  if (l === "" && r === "") return "/";
  if (l === "") return `/${r}`;
  if (r === "") return l;
  return `${l}/${r}`;
}
