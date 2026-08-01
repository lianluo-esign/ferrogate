/**
 * Port of `ferrogate-config`'s `config/network_access.rs` (inventory §5.4,
 * "Network access", issue #166): pre-authentication IP/CIDR allowlisting,
 * client-IP resolution (anti-spoof `X-Forwarded-For`-from-the-right), and the
 * per-source-IP flood limiter.
 *
 * PORT-TODO(inventory §5.8) — PLATFORM LIMIT, NOT CLOSED (two distinct ones).
 *
 * 1. NO PEER ADDRESS. The Rust gate started from the TCP peer address it read
 *    off the pingora socket. A Worker never sees a socket: workerd hands the
 *    handler a `Request` and nothing else, so there is no `peer_addr` to read.
 *    CLOSEST BEHAVIOR IMPLEMENTED: `resolveClientIp` keeps the Rust signature
 *    and semantics exactly (including the anti-spoof XFF-from-the-RIGHT hop
 *    selection and the fail-closed short-chain path); the CALLER substitutes
 *    Cloudflare's `CF-Connecting-IP` header — which the edge sets and strips
 *    from client input — for `peerAddr`. That header is the only value on this
 *    platform with the same trust property as the Rust peer address.
 *
 * 2. NO SHARED MUTABLE STATE. `UnauthenticatedIpRateLimiter`'s Map is
 *    ISOLATE-LOCAL and always will be: Workers isolates share no memory, are
 *    created/evicted per colo without coordination, and the only cross-isolate
 *    counters (Durable Objects, the Rate Limiting binding) are ASYNC, so they
 *    cannot be hidden behind this synchronous `allow()`.
 *    CLOSEST BEHAVIOR IMPLEMENTED: the Rust fixed-window arithmetic and the
 *    {@link MAX_TRACKED_SOURCE_IPS} memory-exhaustion guard are ported verbatim
 *    and kept synchronous, so a Durable Object can host ONE instance of this
 *    class and get the exact Rust decision; used directly in a Worker it
 *    throttles per isolate, which is a weaker bound, not a different rule.
 *
 * The CIDR matcher itself (`IpCidr`, v4/v6, no cross-family match) is a pure
 * port with no platform caveat. Pinned by `platform-limits.test.ts`.
 */

/** A parsed IPv4/IPv6 CIDR. A bare IP (no `/n`) is an exact match (/32 or /128). */
export class IpCidr {
  private readonly network: bigint;
  private readonly prefixLen: number;
  private readonly isV6: boolean;

  private constructor(network: bigint, prefixLen: number, isV6: boolean) {
    this.network = network;
    this.prefixLen = prefixLen;
    this.isV6 = isV6;
  }

  /** Parse a CIDR/IP entry. Throws (with the Rust message) on any malformed input. */
  static parse(raw: string): IpCidr {
    const trimmed = raw.trim();
    if (trimmed.length === 0) throw new Error("empty CIDR/IP entry");
    const slash = trimmed.indexOf("/");
    const ipPart = slash === -1 ? trimmed : trimmed.slice(0, slash);
    const prefixPart = slash === -1 ? null : trimmed.slice(slash + 1);

    const parsed = parseIp(ipPart);
    if (parsed === null) throw new Error(`invalid IP address: ${ipPart}`);
    const maxPrefix = parsed.isV6 ? 128 : 32;

    let prefixLen: number;
    if (prefixPart === null) {
      prefixLen = maxPrefix;
    } else {
      if (!/^\d+$/.test(prefixPart)) throw new Error(`invalid prefix length: ${prefixPart}`);
      prefixLen = Number.parseInt(prefixPart, 10);
    }
    if (prefixLen > maxPrefix) {
      throw new Error(
        `prefix length /${prefixLen} exceeds maximum /${maxPrefix} for ${ipPart}`,
      );
    }
    return new IpCidr(parsed.value, prefixLen, parsed.isV6);
  }

  /** Whether `candidate` (a raw IP string) falls inside this range. */
  contains(candidate: string): boolean {
    const parsed = parseIp(candidate);
    if (parsed === null) return false;
    if (parsed.isV6 !== this.isV6) return false; // no cross-family match
    const bits = this.isV6 ? 128 : 32;
    const shift = BigInt(bits - this.prefixLen);
    const full = this.isV6 ? (1n << 128n) - 1n : (1n << 32n) - 1n;
    const mask = shift >= BigInt(bits) ? 0n : (full << shift) & full;
    return (this.network & mask) === (parsed.value & mask);
  }
}

/** `str::parse::<IpAddr>()` — is this string a bare IPv4/IPv6 literal? */
export function isIpAddress(raw: string): boolean {
  return parseIp(raw) !== null;
}

/** Parse a v4 or v6 address into a numeric value, or `null` if malformed. */
function parseIp(raw: string): { value: bigint; isV6: boolean } | null {
  const s = raw.trim();
  if (s.includes(":")) {
    const value = parseIpv6(s);
    return value === null ? null : { value, isV6: true };
  }
  const value = parseIpv4(s);
  return value === null ? null : { value, isV6: false };
}

/**
 * Rust `Ipv4Addr::from_str`. Four decimal octets, each 1–3 digits and <= 255,
 * with **no leading zeros**: std refuses `010.0.0.1` deliberately, because an
 * octal-looking octet is read as 10 by one parser and 8 by another, and that
 * disagreement is the classic allowlist-bypass / SSRF primitive. This is the
 * parser behind BOTH {@link IpCidr} (the pre-auth allowlist) and
 * {@link resolveClientIp}'s `X-Forwarded-For` / `X-Real-IP` scan, so accepting
 * a spelling Rust rejects would mean an attacker-supplied `010.0.0.1` is taken
 * as a client identity here and discarded there.
 */
function parseIpv4(s: string): bigint | null {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    if (part.length > 1 && part.startsWith("0")) return null;
    const octet = Number.parseInt(part, 10);
    if (octet > 255) return null;
    value = (value << 8n) | BigInt(octet);
  }
  return value;
}

function parseIpv6(s: string): bigint | null {
  // Reject a scope id / anything but hex groups and a single `::`.
  const doubleColon = s.indexOf("::");
  if (doubleColon !== s.lastIndexOf("::")) return null;

  let head: string[];
  let tail: string[];
  if (doubleColon === -1) {
    head = s.split(":");
    tail = [];
  } else {
    head = s.slice(0, doubleColon).split(":").filter((g) => g !== "");
    tail = s.slice(doubleColon + 2).split(":").filter((g) => g !== "");
  }

  // Expand a trailing embedded IPv4 (`::ffff:1.2.3.4`) into two hex groups.
  const expandV4 = (groups: string[]): string[] | null => {
    if (groups.length === 0) return groups;
    const last = groups[groups.length - 1]!;
    if (last.includes(".")) {
      const v4 = parseIpv4(last);
      if (v4 === null) return null;
      const hi = (v4 >> 16n) & 0xffffn;
      const lo = v4 & 0xffffn;
      return [...groups.slice(0, -1), hi.toString(16), lo.toString(16)];
    }
    return groups;
  };
  const expandedHead = expandV4(head);
  const expandedTail = expandV4(tail);
  if (expandedHead === null || expandedTail === null) return null;
  head = expandedHead;
  tail = expandedTail;

  const groupCount = head.length + tail.length;
  if (doubleColon === -1) {
    if (groupCount !== 8) return null;
  } else if (groupCount > 7) {
    return null;
  }
  const zeros = 8 - groupCount;
  const groups = [...head, ...Array(zeros).fill("0"), ...tail];
  if (groups.length !== 8) return null;

  let value = 0n;
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
    value = (value << 16n) | BigInt(Number.parseInt(group, 16));
  }
  return value;
}

/** A header source: fetch `Headers`, or a plain (any-case) record. */
export type HeaderSource = Headers | Record<string, string | undefined>;

function headerValue(headers: HeaderSource, name: string): string | undefined {
  if (typeof (headers as Headers).get === "function") {
    return (headers as Headers).get(name) ?? undefined;
  }
  const lower = name.toLowerCase();
  for (const [key, value] of Object.entries(headers as Record<string, string | undefined>)) {
    if (key.toLowerCase() === lower) return value ?? undefined;
  }
  return undefined;
}

/**
 * Resolves the client IP for allowlist/rate-limit decisions: the raw peer
 * address, or (only when explicitly trusted) the entry `trustedProxyHops`
 * positions from the RIGHT of `X-Forwarded-For`, falling back to `X-Real-IP`.
 *
 * Selection is from the right, not the left (appending proxies), and it fails
 * closed when the chain is shorter than the hop count — a spoofed leftmost
 * entry can never bypass the allowlist. `trustedProxyHops` is clamped to >= 1.
 */
export function resolveClientIp(
  headers: HeaderSource,
  peerAddr: string | null,
  trustForwardedFor: boolean,
  trustedProxyHops: number,
): string | null {
  if (trustForwardedFor) {
    const hops = Math.max(1, trustedProxyHops);
    const forwarded = headerValue(headers, "x-forwarded-for");
    if (forwarded !== undefined) {
      const entries = forwarded
        .split(",")
        .map((e) => e.trim())
        .filter((e) => e.length > 0);
      const idx = entries.length - hops;
      if (idx >= 0 && idx < entries.length) {
        const entry = entries[idx]!;
        if (parseIp(entry) !== null) return entry;
      }
    }
    const realIp = headerValue(headers, "x-real-ip");
    if (realIp !== undefined) {
      const trimmed = realIp.trim();
      if (parseIp(trimmed) !== null) return trimmed;
    }
  }
  return peerAddr;
}

/**
 * Pragmatic bound on how many distinct source IPs the pre-auth limiter tracks.
 * Once exceeded, the map is cleared rather than grown further, so a spoofed
 * flood cannot turn the limiter into a memory-exhaustion vector.
 */
export const MAX_TRACKED_SOURCE_IPS = 100_000;

/**
 * Fixed-window (per-minute), per-source-IP request counter used to throttle
 * floods before any virtual-key/storage lookup. A coarse single-node flood
 * gate, not a billing-accurate quota.
 */
export class UnauthenticatedIpRateLimiter {
  private readonly windows = new Map<string, [number, number]>();

  /**
   * `true` if `ip` is still within `limit` requests for the current
   * `nowMinute` window (a monotonically increasing minute counter, e.g.
   * `unixSeconds / 60`).
   */
  allow(ip: string, nowMinute: number, limit: number): boolean {
    if (this.windows.size >= MAX_TRACKED_SOURCE_IPS && !this.windows.has(ip)) {
      this.windows.clear();
    }
    let entry = this.windows.get(ip);
    if (entry === undefined || entry[0] !== nowMinute) {
      entry = [nowMinute, 0];
      this.windows.set(ip, entry);
    }
    entry[1] += 1;
    return entry[1] <= limit;
  }
}
