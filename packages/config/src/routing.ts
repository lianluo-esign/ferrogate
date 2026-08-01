/**
 * Port of `ferrogate-config`'s `config/routing.rs` (inventory §5.4, "Routing"):
 * upstream-endpoint parsing and route-rule path rewriting / target-URI building.
 *
 * PORT-TODO(inventory §5.2/§5.8) — PACKAGE RELOCATION ONLY, BEHAVIOR IS CLOSED.
 * `build_target_uri`/`normalize_host` are the
 * data-plane leg the Rust crate note flags for relocation to the gateway app
 * (#560); they are ported here to preserve the public surface and are re-used
 * by the Hono data plane.
 *
 * "BEHAVIOR IS CLOSED" was NOT true when it was written, and the way it was
 * false is worth keeping: two of the three Rust functions here were ported as
 * their happy path only, so the module read as complete and the marker read as
 * bookkeeping.
 *   - `build_target_uri` was `join_url_path` WITHOUT the `path.parse::<Uri>()`
 *     that follows it in Rust, so it could not fail and never returned
 *     `invalid target path`;
 *   - `parse_upstream_endpoint` folded Rust's "invalid URL" and "must include
 *     scheme" into one message, because `new URL()` cannot tell them apart.
 * Both are closed now, against the byte tables and the scheme rule `http::Uri`
 * actually uses, and pinned by `test/routing-snapshot-secrets.test.ts`. What is
 * left under this marker is genuinely only the FILE MOVE.
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

/**
 * The prefix `http::uri::Scheme2::parse` accepts before it will report a scheme
 * at all. The `//` is LOAD-BEARING, not decoration: that parser scans scheme
 * characters (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`) to a `:` and then
 * `break`s back to `Scheme2::None` unless the next two bytes are `//`. So Rust
 * reads `api.example.com:8080` as authority-form WITH A PORT — not as a scheme
 * named `api.example.com` — and reports the missing scheme. A `^[A-Za-z][...]*:`
 * test would misclassify exactly that host:port case as a bad scheme instead.
 */
const SCHEME_PREFIX = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//;

/**
 * Parse an upstream URL into its endpoint pieces. Throws on any malformed input.
 *
 * ERROR IDENTITY, not just "it throws". Rust runs `raw.parse::<Uri>()` and only
 * THEN asks for the scheme, so it distinguishes three failures that an operator
 * sees verbatim through `validate_upstreams`:
 *
 *   - `invalid upstream URL {raw}`      — `Uri::from_str` itself refused it;
 *   - `upstream URL must include scheme` — it parsed, but as authority-form
 *     (`api.example.com/v1`) or origin-form (`/v1`), where `scheme_str()` is
 *     `None`;
 *   - `upstream URL must include authority` / `... scheme must be http or https`.
 *
 * `new URL()` collapses the first two: it throws for ANY schemeless input, so
 * `api.example.com/v1` used to be reported as "invalid upstream URL", telling an
 * operator the URL was malformed rather than that it was missing `https://`.
 * The scheme test therefore runs FIRST, on the raw string, exactly where Rust's
 * `scheme_str()` sits in the chain. A blank string is the one input `Uri` itself
 * rejects, so it keeps the "invalid upstream URL" wording.
 */
export function parseUpstreamEndpoint(raw: string): UpstreamEndpoint {
  if (raw.length === 0) {
    throw new Error(`invalid upstream URL ${raw}`);
  }
  if (!SCHEME_PREFIX.test(raw)) {
    throw new Error("upstream URL must include scheme");
  }
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
  const defaultPort = (scheme === "https" && port === 443) || (scheme === "http" && port === 80);
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

/**
 * The byte sets `http::uri::PathAndQuery::from_shared` accepts, transcribed from
 * `http`'s match arms. They are asymmetric, which is why one predicate will not
 * do for both halves:
 *
 *   path : 0x21 | 0x24..=0x3B | 0x3D | 0x40..=0x5F | 0x61..=0x7A | 0x7C | 0x7E
 *   query: 0x21 | 0x24..=0x3B | 0x3D | 0x3F..=0x7E
 *
 * So a query may carry `` ` ``/`{`/`}`/`?` that a path may not, and NEITHER may
 * carry a control byte, a space, `"`, `<`, `>`, DEL, or any byte above 0x7F
 * (i.e. any non-ASCII character, since those are multi-byte in UTF-8).
 */
function isUriPathByte(byte: number): boolean {
  return (
    byte === 0x21 ||
    (byte >= 0x24 && byte <= 0x3b) ||
    byte === 0x3d ||
    (byte >= 0x40 && byte <= 0x5f) ||
    (byte >= 0x61 && byte <= 0x7a) ||
    byte === 0x7c ||
    byte === 0x7e
  );
}

function isUriQueryByte(byte: number): boolean {
  return (
    byte === 0x21 ||
    (byte >= 0x24 && byte <= 0x3b) ||
    byte === 0x3d ||
    (byte >= 0x3f && byte <= 0x7e)
  );
}

const TARGET_PATH_ENCODER = new TextEncoder();

/**
 * `Uri::from_str` over an origin-form target, reduced to what
 * {@link buildTargetUri} needs: validate, and truncate at a fragment.
 *
 * Returns the accepted `path[?query]`, or `null` if `http::Uri` would refuse it.
 */
function parseTargetPathQuery(pathQuery: string): string | null {
  const bytes = TARGET_PATH_ENCODER.encode(pathQuery);
  let index = 0;
  // --- path: runs until `?` (query) or `#` (fragment) ---
  for (; index < bytes.length; index += 1) {
    const byte = bytes[index]!;
    if (byte === 0x3f /* ? */ || byte === 0x23 /* # */) break;
    if (!isUriPathByte(byte)) return null;
  }
  if (index < bytes.length && bytes[index] !== 0x23) {
    // `?` — the query runs to a `#` under the wider query byte set.
    for (index += 1; index < bytes.length; index += 1) {
      const byte = bytes[index]!;
      if (byte === 0x23 /* # */) break;
      if (!isUriQueryByte(byte)) return null;
    }
  }
  // Everything accepted so far is ASCII by construction (both byte sets stop
  // below 0x80), so the byte offset IS the string index. Anything from `#` on is
  // the fragment, which `PathAndQuery` drops.
  return pathQuery.slice(0, index);
}

/**
 * Build the target path+query for an upstream request.
 *
 * Rust is `path.parse::<Uri>().with_context(|| format!("invalid target path
 * {path}"))` — the join is only half of it, and the parse is the half that was
 * MISSING here. This used to be a pure string concatenation that returned
 * whatever it was handed, so a joined target Rust REFUSES (an `add_prefix` or an
 * upstream base path carrying a space, a control byte, `<`, `>`, `"`, `` ` ``,
 * `{`, `}`, or any non-ASCII character) was forwarded instead, and `fetch()`
 * downstream silently percent-encoded it into a DIFFERENT request than the one
 * the operator configured. Rust fails the call; now so does this.
 *
 * The fragment rule is Rust's too, and it is not cosmetic: `PathAndQuery` breaks
 * at `#` and drops the remainder, so a `#` in the joined target truncates the
 * upstream request target rather than being sent.
 *
 * @throws if the assembled target is not a valid `http::Uri` origin-form target.
 */
export function buildTargetUri(
  endpoint: UpstreamEndpoint,
  rewrittenPath: string,
  query?: string | null,
): string {
  let path = joinUrlPath(endpoint.basePath, rewrittenPath);
  if (query !== undefined && query !== null && query.length > 0) {
    path += `?${query}`;
  }
  const parsed = parseTargetPathQuery(path);
  if (parsed === null) throw new Error(`invalid target path ${path}`);
  return parsed;
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
    prefixes.some((prefix) => path === prefix || path.startsWith(`${prefix.replace(/\/+$/, "")}/`));
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
