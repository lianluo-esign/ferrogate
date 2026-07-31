/**
 * SSRF-safe networking helpers — port of `ferrogate-guardrails::net`.
 *
 * `isDisallowedDetectorIp` is the private/reserved-address denylist, ported
 * verbatim (v4 + v6). It is used to validate a detector *endpoint config* value
 * (reject `localhost`/private-range literals in the URL host).
 *
 * PORT-TODO(inventory §3.4d / §3.8 — "no clean CF equivalent"): the Rust crate
 * additionally installs a custom reqwest DNS resolver
 * (`GuardrailDnsResolver`) that filters resolved IPs *before connecting*.
 * Workers `fetch` exposes no DNS-resolution seam and cannot reach RFC1918/
 * loopback anyway, so DNS-level filtering is dropped; host/IP-literal validation
 * plus the Worker egress boundary stand in. `filterResolvedDetectorAddresses` is
 * ported for parity/testing but is not wired into the request path.
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
