import { describe, expect, test } from "vitest";
import { filterResolvedDetectorAddresses, isDisallowedDetectorIp } from "../src/index.js";

describe("isDisallowedDetectorIp (v4)", () => {
  test.each([
    ["10.0.0.1", true],
    ["172.16.5.5", true],
    ["192.168.1.1", true],
    ["127.0.0.1", true],
    ["169.254.1.1", true],
    ["100.64.0.1", true], // CGNAT
    ["198.18.0.1", true], // benchmarking
    ["240.0.0.1", true], // reserved
    ["224.0.0.1", true], // multicast
    ["8.8.8.8", false],
    ["1.1.1.1", false],
    ["93.184.216.34", false],
  ])("%s → disallowed=%s", (ip, expected) => {
    expect(isDisallowedDetectorIp(ip)).toBe(expected);
  });
});

describe("isDisallowedDetectorIp (v6)", () => {
  test.each([
    ["::1", true], // loopback
    ["::", true], // unspecified
    ["fc00::1", true], // ULA
    ["fe80::1", true], // link-local
    ["fec0::1", true], // site-local
    ["2001:db8::1", true], // documentation
    ["ff02::1", true], // multicast
    ["::ffff:10.0.0.1", true], // v4-mapped private
    ["2606:4700:4700::1111", false], // public (Cloudflare)
  ])("%s → disallowed=%s", (ip, expected) => {
    expect(isDisallowedDetectorIp(ip)).toBe(expected);
  });
});

describe("filterResolvedDetectorAddresses", () => {
  test("drops disallowed unless private networking is allowed", () => {
    const addresses = [
      { ip: "8.8.8.8", port: 443 },
      { ip: "10.0.0.1", port: 443 },
    ];
    expect(filterResolvedDetectorAddresses(addresses, false)).toEqual([{ ip: "8.8.8.8", port: 443 }]);
    expect(filterResolvedDetectorAddresses(addresses, true)).toHaveLength(2);
  });
});
