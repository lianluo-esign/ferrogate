/**
 * SSRF-safe networking helpers — port of `ferrogate-guardrails::net`.
 *
 * `isDisallowedDetectorIp` is the private/reserved-address denylist, ported
 * verbatim (v4 + v6) from `net.rs`. `isDisallowedDetectorHost` and
 * {@link detectorEndpointRejection} lift it to the endpoint-URL layer, which is
 * where the whole SSRF defense has to live on workerd.
 *
 * ## What the Rust did, and what this can and cannot do
 *
 * The Rust crate defended detector egress in TWO places:
 *
 *  1. `validate_custom_http_endpoint` — a *config-time* check on the endpoint
 *     URL (http(s) only, host required, no userinfo/password/query/fragment;
 *     unless `allow_private_network`, reject `localhost` and IP literals in the
 *     denylist). That check is ported here in full.
 *  2. `GuardrailDnsResolver` — a custom reqwest DNS resolver that resolved the
 *     hostname and dropped every disallowed address *before the socket was
 *     opened*, so `evil.example.com. A 127.0.0.1` was refused at connect time.
 *
 * PORT-TODO(L: inventory-policy-core §guardrails/net) — PLATFORM LIMIT, NOT CLOSED.
 *
 * The exact limitation: **workerd exposes no DNS resolver hook and no
 * resolved-address callback.** The Rust `GuardrailDnsResolver` is a custom
 * `reqwest` resolver: it saw the `SocketAddr` list `getaddrinfo` produced and
 * dropped every disallowed address BEFORE the socket was opened, so
 * `evil.example.com. A 127.0.0.1` was refused at connect time. On Workers,
 * `fetch()` performs its own resolution inside the runtime; there is no
 * `Resolver` trait, no `lookup` interception, no way to read the resolved IP
 * from JS, and `connect()` (the `cloudflare:sockets` API) takes a hostname and
 * resolves it internally too. So a hostname that RESOLVES to a private IP
 * cannot be blocked pre-connect from this code. That residual gap is REAL, is
 * not closed by anything in this file, and can only be closed at the Worker
 * egress boundary (an account-level egress policy or a governed
 * container/sandbox hop).
 *
 * The closest behavior implemented instead is the whole LITERAL surface — the
 * part an operator, or an attacker who can write a detector config, actually
 * controls — plus two deliberate tightenings that compensate for the missing
 * resolver. All of it is enumerated below and pinned by `test/net.test.ts`,
 * whose `PLATFORM LIMIT` block asserts the SHAPE of the residual gap (a public
 * hostname is accepted whatever it resolves to) rather than describing it, so
 * the literal-surface defense can never be mistaken for a complete SSRF
 * defense. What is closed:
 *
 *  - scheme allowlist (`http:`/`https:` only — no `file:`, `data:`, `gopher:`,
 *    `blob:`, `ftp:`, ...);
 *  - credentials-in-URL rejected (`http://user:pass@host/`), plus query and
 *    fragment, exactly as the Rust did;
 *  - IP literals in the denylist rejected for BOTH families, including
 *    IPv4-mapped IPv6 (`::ffff:127.0.0.1`) and the `inet_aton`-style IPv4
 *    obfuscations (`0177.0.0.1` octal, `0x7f.0.0.1` hex, `2130706433` integer,
 *    `127.1` short form). The Rust never had to parse those itself — its
 *    `Ipv4Addr::from_str` rejects them, but `getaddrinfo` inside the resolver
 *    accepted them and the resolver then filtered the resulting `127.0.0.1`.
 *    With the resolver gone, parsing them HERE is what preserves that behavior.
 *
 * Two deliberate deltas from the Rust, both strictly tightening, both
 * compensating for the missing resolver:
 *
 *  - `*.localhost` and a trailing-root-dot `localhost.` are rejected as well as
 *    the bare `localhost` the Rust matched (RFC 6761 reserves the whole zone to
 *    loopback, and the Rust resolver would have filtered them at connect time).
 *  - the host is checked in both its raw and its WHATWG-canonicalized form, so
 *    an obfuscation that only one of the two normalizes is still caught.
 *
 * NON-delta, called out because it is easy to "harden" by mistake: the Rust
 * placed NO restriction on the endpoint port, so neither does this. A detector
 * on `https://guard.example.com:8443/analyze` is legal, and adding a
 * standard-ports-only rule here would be a behavior change, not a port.
 *
 * `filterResolvedDetectorAddresses` is ported for parity/testing but is NOT
 * wired into the request path — there is no resolved-address list to filter.
 */

/** A resolved socket address (host IP + port), the twin of Rust `SocketAddr`. */
export interface DetectorAddress {
  ip: string;
  port: number;
}

/** Drop disallowed IPs from a resolved set unless private networking is allowed. */
export function filterResolvedDetectorAddresses(
  addresses: DetectorAddress[],
  allowPrivateNetwork: boolean,
): DetectorAddress[] {
  return addresses.filter((a) => allowPrivateNetwork || !isDisallowedDetectorIp(a.ip));
}

/** Whether an IP (v4 or v6 literal) is in the private/reserved denylist. */
export function isDisallowedDetectorIp(ip: string): boolean {
  const v4 = parseIpv4(ip);
  if (v4) {
    return isDisallowedV4(v4);
  }
  const v6 = parseIpv6(ip);
  if (v6) {
    return isDisallowedV6(v6);
  }
  // Not a parseable IP literal: treat as not-an-IP (host validation handles it).
  return false;
}

function parseIpv4(ip: string): [number, number, number, number] | undefined {
  const parts = ip.split(".");
  if (parts.length !== 4) {
    return undefined;
  }
  const octets = parts.map((p) => (/^\d{1,3}$/.test(p) ? Number.parseInt(p, 10) : Number.NaN));
  if (octets.some((o) => Number.isNaN(o) || o < 0 || o > 255)) {
    return undefined;
  }
  return [octets[0] as number, octets[1] as number, octets[2] as number, octets[3] as number];
}

function isDisallowedV4([a, b]: [number, number, number, number]): boolean {
  const isPrivate = a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  const isLoopback = a === 127;
  const isLinkLocal = a === 169 && b === 254;
  const isUnspecified = a === 0 && b === 0; // 0.0.0.0/8 unspecified block start
  const isMulticast = a >= 224 && a <= 239;
  const isBroadcast = a === 255 && b === 255; // 255.255.255.255 broadcast
  const isDocumentation =
    (a === 192 && b === 0) || // 192.0.2.0/24 (and 192.0.0.0/24 below)
    (a === 198 && b === 51) ||
    (a === 203 && b === 0);
  return (
    isPrivate ||
    isLoopback ||
    isLinkLocal ||
    isUnspecified ||
    isMulticast ||
    isBroadcast ||
    isDocumentation ||
    (a === 100 && b >= 64 && b <= 127) || // CGNAT 100.64.0.0/10
    (a === 192 && b === 0) || // 192.0.0.0/24
    (a === 198 && (b === 18 || b === 19)) || // benchmarking 198.18.0.0/15
    a >= 240 // reserved/experimental 240.0.0.0/4
  );
}

function parseIpv6(ip: string): number[] | undefined {
  let host = ip;
  if (host.startsWith("[") && host.endsWith("]")) {
    host = host.slice(1, -1);
  }
  if (!host.includes(":")) {
    return undefined;
  }
  // Handle embedded IPv4 tail (e.g. ::ffff:1.2.3.4).
  let tailSegments: number[] = [];
  const lastColon = host.lastIndexOf(":");
  const tail = host.slice(lastColon + 1);
  const v4Tail = parseIpv4(tail);
  if (v4Tail) {
    tailSegments = [(v4Tail[0] << 8) | v4Tail[1], (v4Tail[2] << 8) | v4Tail[3]];
    host = `${host.slice(0, lastColon)}:0:0`;
  }

  const doubleColon = host.split("::");
  if (doubleColon.length > 2) {
    return undefined;
  }
  const parseGroups = (part: string): number[] | undefined => {
    if (part === "") {
      return [];
    }
    const groups: number[] = [];
    for (const g of part.split(":")) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) {
        return undefined;
      }
      groups.push(Number.parseInt(g, 16));
    }
    return groups;
  };

  let segments: number[];
  if (doubleColon.length === 2) {
    const head = parseGroups(doubleColon[0] as string);
    const tailPart = parseGroups(doubleColon[1] as string);
    if (!head || !tailPart) {
      return undefined;
    }
    const missing = 8 - head.length - tailPart.length;
    if (missing < 0) {
      return undefined;
    }
    segments = [...head, ...new Array<number>(missing).fill(0), ...tailPart];
  } else {
    const groups = parseGroups(host);
    if (!groups) {
      return undefined;
    }
    segments = groups;
  }
  if (v4Tail) {
    segments = [...segments.slice(0, 6), ...tailSegments];
  }
  return segments.length === 8 ? segments : undefined;
}

/* ------------------------------------------------------------------------- *
 * Endpoint-URL validation (the workerd stand-in for the Rust DNS resolver).
 * ------------------------------------------------------------------------- */

/**
 * The only schemes a guardrail detector endpoint may use, matching the Rust
 * `matches!(endpoint.scheme(), "http" | "https")`.
 */
export const ALLOWED_DETECTOR_ENDPOINT_SCHEMES: readonly string[] = ["http:", "https:"];

/** Why an endpoint URL was refused. `undefined` from the checker means "accepted". */
export type DetectorEndpointRejection =
  | "invalid_url"
  | "scheme_not_allowed"
  | "missing_host"
  | "credentials_in_url"
  | "query_or_fragment"
  | "private_network_host";

/**
 * Validate a detector endpoint and return the rejection reason, or `undefined`
 * when it is acceptable. Callers map the reason onto their own error type (see
 * `custom_http.validateCustomHttpEndpoint`, which owns the ported messages).
 *
 * Accepts a `URL` or a raw string; a string that does not parse yields
 * `"invalid_url"` rather than throwing.
 */
export function detectorEndpointRejection(
  endpoint: string | URL,
  allowPrivateNetwork: boolean,
): DetectorEndpointRejection | undefined {
  let url: URL;
  if (endpoint instanceof URL) {
    url = endpoint;
  } else {
    try {
      url = new URL(endpoint);
    } catch {
      return "invalid_url";
    }
  }
  if (!ALLOWED_DETECTOR_ENDPOINT_SCHEMES.includes(url.protocol)) {
    return "scheme_not_allowed";
  }
  if (url.hostname === "") {
    return "missing_host";
  }
  if (url.username !== "" || url.password !== "") {
    return "credentials_in_url";
  }
  if (url.search !== "" || url.hash !== "") {
    return "query_or_fragment";
  }
  // NOTE: no port restriction — the Rust had none. See the module doc.
  if (!allowPrivateNetwork && isDisallowedDetectorHost(url.hostname)) {
    return "private_network_host";
  }
  return undefined;
}

/**
 * Whether a URL *host* must be refused as a detector endpoint: `localhost`
 * (and its RFC 6761 zone), or an IP literal in the denylist written in any
 * form a resolver would have accepted.
 */
export function isDisallowedDetectorHost(host: string): boolean {
  for (const candidate of hostCandidates(host)) {
    const bare = stripBrackets(candidate).toLowerCase();
    if (bare === "") {
      return true;
    }
    const withoutRootDot = bare.endsWith(".") ? bare.slice(0, -1) : bare;
    if (withoutRootDot === "localhost" || withoutRootDot.endsWith(".localhost")) {
      return true;
    }
    if (isDisallowedDetectorIp(bare)) {
      return true;
    }
    const loose = parseLooseIpv4(withoutRootDot);
    if (loose && isDisallowedV4(loose)) {
      return true;
    }
  }
  return false;
}

/**
 * The host as written, plus — for a non-ASCII host only — its WHATWG-
 * canonicalized form.
 *
 * The denylist decision is deliberately made by OUR OWN parsers
 * (`parseIpv6` + `parseLooseIpv4` + the `localhost` zone), not by the runtime's
 * URL implementation. Today `new URL()` happens to fold every `inet_aton`
 * spelling, but that is an implementation detail of ada/workerd, not a security
 * contract — leaning on it would make this check silently evaporate if the
 * parser changed, and would leave the raw-string entry point unguarded.
 *
 * The one thing our parsers genuinely cannot do is Unicode host folding
 * (IDNA/NFKC, e.g. the fullwidth digits in `１２７.0.0.1`), so the URL parser is
 * borrowed for exactly that case and nothing else.
 */
function hostCandidates(host: string): string[] {
  const candidates = [host];
  const hasNonAscii = [...host].some((ch) => (ch.codePointAt(0) ?? 0) > 0x7f);
  if (hasNonAscii && !/[/\\?#@\s]/.test(host)) {
    try {
      const canonical = new URL(`http://${host}`).hostname;
      if (canonical !== host) {
        candidates.push(canonical);
      }
    } catch {
      // Not canonicalizable: the raw form is all we have.
    }
  }
  return candidates;
}

function stripBrackets(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

/**
 * Parse an IPv4 host the permissive `inet_aton`/`getaddrinfo` way: 1–4 parts,
 * each decimal, octal (`0` prefix) or hex (`0x` prefix), with the final part
 * absorbing the remaining low-order bytes. `2130706433`, `0177.0.0.1`,
 * `0x7f.0.0.1` and `127.1` all yield `127.0.0.1` here.
 *
 * This is deliberately NOT what `isDisallowedDetectorIp` uses — that one keeps
 * Rust `Ipv4Addr::from_str` semantics (strict dotted-quad). This looser parse
 * exists only for host validation, standing in for the resolver the Rust had.
 */
export function parseLooseIpv4(host: string): [number, number, number, number] | undefined {
  if (host === "" || !/^[0-9a-zA-Z.]+$/.test(host)) {
    return undefined;
  }
  const text = host.endsWith(".") ? host.slice(0, -1) : host;
  const parts = text.split(".");
  if (parts.length === 0 || parts.length > 4) {
    return undefined;
  }
  const numbers: number[] = [];
  for (const part of parts) {
    const value = parseLooseIpv4Part(part);
    if (value === undefined) {
      return undefined;
    }
    numbers.push(value);
  }
  const last = numbers.pop() as number;
  if (numbers.some((n) => n > 0xff)) {
    return undefined;
  }
  if (last >= 256 ** (4 - numbers.length)) {
    return undefined;
  }
  let value = last;
  numbers.forEach((n, index) => {
    value += n * 256 ** (3 - index);
  });
  return [
    (value / 0x1000000) & 0xff,
    (value / 0x10000) & 0xff,
    (value / 0x100) & 0xff,
    value & 0xff,
  ];
}

function parseLooseIpv4Part(part: string): number | undefined {
  if (/^0[xX][0-9a-fA-F]+$/.test(part)) {
    return Number.parseInt(part.slice(2), 16);
  }
  if (/^0[xX]$/.test(part)) {
    return 0;
  }
  if (/^0[0-7]+$/.test(part)) {
    return Number.parseInt(part, 8);
  }
  if (/^(?:0|[1-9]\d*)$/.test(part)) {
    return Number.parseInt(part, 10);
  }
  return undefined;
}

function isDisallowedV6(segments: number[]): boolean {
  const s0 = segments[0] as number;
  // v4-mapped ::ffff:a.b.c.d → evaluate as v4.
  const isV4Mapped = segments.slice(0, 5).every((s) => s === 0) && segments[5] === 0xffff;
  if (isV4Mapped) {
    const s6 = segments[6] as number;
    const s7 = segments[7] as number;
    return isDisallowedV4([(s6 >> 8) & 0xff, s6 & 0xff, (s7 >> 8) & 0xff, s7 & 0xff]);
  }
  const isLoopback = segments.slice(0, 7).every((s) => s === 0) && segments[7] === 1;
  const isUnspecified = segments.every((s) => s === 0);
  const isMulticast = (s0 & 0xff00) === 0xff00;
  return (
    isLoopback ||
    isUnspecified ||
    isMulticast ||
    (s0 & 0xfe00) === 0xfc00 || // ULA fc00::/7
    (s0 & 0xffc0) === 0xfe80 || // link-local fe80::/10
    (s0 & 0xffc0) === 0xfec0 || // site-local fec0::/10
    (s0 === 0x2001 && segments[1] === 0x0db8) // documentation 2001:db8::/32
  );
}
