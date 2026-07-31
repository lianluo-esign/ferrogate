import { describe, expect, test } from "vitest";
import { IpCidr, resolveClientIp, UnauthenticatedIpRateLimiter } from "../src/network-access.js";

describe("IpCidr", () => {
  test("bare IPv4 is an exact match", () => {
    const cidr = IpCidr.parse("203.0.113.7");
    expect(cidr.contains("203.0.113.7")).toBe(true);
    expect(cidr.contains("203.0.113.8")).toBe(false);
  });

  test("IPv4 CIDR range masks correctly", () => {
    const cidr = IpCidr.parse("10.0.0.0/8");
    expect(cidr.contains("10.1.2.3")).toBe(true);
    expect(cidr.contains("11.0.0.1")).toBe(false);
  });

  test("/0 matches everything, /32 is exact", () => {
    expect(IpCidr.parse("0.0.0.0/0").contains("255.255.255.255")).toBe(true);
    const exact = IpCidr.parse("203.0.113.7/32");
    expect(exact.contains("203.0.113.7")).toBe(true);
    expect(exact.contains("203.0.113.6")).toBe(false);
  });

  test("IPv6 CIDR and no cross-family match", () => {
    const cidr = IpCidr.parse("2001:db8::/32");
    expect(cidr.contains("2001:db8::1")).toBe(true);
    expect(cidr.contains("2001:db9::1")).toBe(false);
    expect(IpCidr.parse("10.0.0.0/8").contains("::1")).toBe(false);
  });

  test("rejects invalid ip / prefix / empty", () => {
    expect(() => IpCidr.parse("not-an-ip")).toThrow();
    expect(() => IpCidr.parse("10.0.0.0/33")).toThrow();
    expect(() => IpCidr.parse("10.0.0.0/abc")).toThrow();
    expect(() => IpCidr.parse("   ")).toThrow();
  });
});

describe("resolveClientIp", () => {
  const peer = "127.0.0.1";
  test("ignores forwarded headers when not trusted", () => {
    expect(resolveClientIp({ "x-forwarded-for": "198.51.100.9" }, peer, false, 1)).toBe(peer);
  });

  test("uses the rightmost untrusted XFF entry with one hop (anti-spoof)", () => {
    const resolved = resolveClientIp({ "x-forwarded-for": "10.0.0.1, 203.0.113.66" }, peer, true, 1);
    expect(resolved).toBe("203.0.113.66");
    expect(resolved).not.toBe("10.0.0.1");
  });

  test("selects the client by hop count through a proxy chain", () => {
    expect(
      resolveClientIp({ "x-forwarded-for": "203.0.113.7, 198.51.100.9, 192.0.2.10" }, peer, true, 2),
    ).toBe("198.51.100.9");
  });

  test("fails closed to X-Real-IP / peer when the chain is shorter than the hop count", () => {
    expect(
      resolveClientIp({ "x-forwarded-for": "203.0.113.7", "x-real-ip": "198.51.100.9" }, peer, true, 2),
    ).toBe("198.51.100.9");
    expect(resolveClientIp({ "x-forwarded-for": "203.0.113.7" }, peer, true, 2)).toBe(peer);
  });

  test("reads a fetch Headers object case-insensitively", () => {
    const headers = new Headers({ "X-Forwarded-For": "203.0.113.7, 198.51.100.9" });
    expect(resolveClientIp(headers, peer, true, 1)).toBe("198.51.100.9");
  });
});

describe("UnauthenticatedIpRateLimiter", () => {
  test("allows up to the limit then denies, resets on a new window", () => {
    const limiter = new UnauthenticatedIpRateLimiter();
    for (let i = 0; i < 5; i += 1) expect(limiter.allow("203.0.113.1", 100, 5)).toBe(true);
    expect(limiter.allow("203.0.113.1", 100, 5)).toBe(false);
    expect(limiter.allow("203.0.113.1", 101, 5)).toBe(true);
  });

  test("tracks sources independently", () => {
    const limiter = new UnauthenticatedIpRateLimiter();
    for (let i = 0; i < 5; i += 1) limiter.allow("203.0.113.1", 100, 5);
    expect(limiter.allow("203.0.113.1", 100, 5)).toBe(false);
    expect(limiter.allow("203.0.113.2", 100, 5)).toBe(true);
  });
});
