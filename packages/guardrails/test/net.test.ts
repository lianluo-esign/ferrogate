import { describe, expect, test } from "vitest";
import {
  CustomHttpDetector,
  DetectorError,
  DetectorSecret,
  HttpJsonTransport,
  detectorEndpointRejection,
  filterResolvedDetectorAddresses,
  isDisallowedDetectorHost,
  isDisallowedDetectorIp,
  parseLooseIpv4,
  validateCustomHttpEndpoint,
} from "../src/index.js";

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

/* --------------------------------------------------------------------------
 * Endpoint-URL SSRF validation — the workerd stand-in for the Rust
 * `GuardrailDnsResolver`. See the `net.ts` module doc for the residual gap
 * (a hostname that RESOLVES to a private IP still cannot be blocked here).
 * ------------------------------------------------------------------------ */

/** Hostile endpoints that MUST be refused, with the reason each is refused for. */
const HOSTILE_ENDPOINTS: [string, string][] = [
  // --- loopback, in every spelling a resolver would have accepted ---
  ["http://127.0.0.1/analyze", "private_network_host"],
  ["http://127.0.0.1:8080/analyze", "private_network_host"],
  ["http://127.255.255.254/analyze", "private_network_host"],
  ["http://localhost/analyze", "private_network_host"],
  ["http://LOCALHOST/analyze", "private_network_host"],
  ["http://localhost.:9000/analyze", "private_network_host"], // trailing root dot
  ["http://api.localhost/analyze", "private_network_host"], // RFC 6761 zone
  ["http://0177.0.0.1/analyze", "private_network_host"], // octal
  ["http://0x7f.0.0.1/analyze", "private_network_host"], // hex
  ["http://2130706433/analyze", "private_network_host"], // 32-bit integer
  ["http://127.1/analyze", "private_network_host"], // short form
  ["http://0/analyze", "private_network_host"], // 0.0.0.0
  ["http://0.0.0.0/analyze", "private_network_host"],
  // --- RFC1918 ---
  ["http://10.0.0.1/analyze", "private_network_host"],
  ["http://10.255.255.255/analyze", "private_network_host"],
  ["http://172.16.0.1/analyze", "private_network_host"],
  ["http://172.31.255.254/analyze", "private_network_host"],
  ["http://192.168.1.1/analyze", "private_network_host"],
  // --- link-local, incl. the cloud metadata endpoint ---
  ["http://169.254.169.254/latest/meta-data", "private_network_host"],
  ["http://169.254.0.1/analyze", "private_network_host"],
  // --- CGNAT 100.64.0.0/10 ---
  ["http://100.64.0.1/analyze", "private_network_host"],
  ["http://100.127.255.254/analyze", "private_network_host"],
  // --- IPv6 ---
  ["http://[::1]/analyze", "private_network_host"],
  ["http://[::]/analyze", "private_network_host"],
  ["http://[fc00::1]/analyze", "private_network_host"], // ULA
  ["http://[fd12:3456::1]/analyze", "private_network_host"], // ULA (fd half of fc00::/7)
  ["http://[fe80::1]/analyze", "private_network_host"], // link-local
  ["http://[::ffff:127.0.0.1]/analyze", "private_network_host"], // v4-mapped loopback
  ["http://[::ffff:169.254.169.254]/analyze", "private_network_host"], // v4-mapped metadata
  // --- credentials in URL (rejected even though the host is public) ---
  ["http://user:pass@guard.example.com/analyze", "credentials_in_url"],
  ["https://user:pass@guard.example.com/analyze", "credentials_in_url"],
  ["https://user@guard.example.com/analyze", "credentials_in_url"],
  ["http://user:pass@127.0.0.1/analyze", "credentials_in_url"],
  // --- scheme allowlist ---
  ["file:///etc/passwd", "scheme_not_allowed"],
  ["gopher://guard.example.com/analyze", "scheme_not_allowed"],
  ["ftp://guard.example.com/analyze", "scheme_not_allowed"],
  ["data:text/plain,hello", "scheme_not_allowed"],
  ["ws://guard.example.com/analyze", "scheme_not_allowed"],
  // --- query / fragment (ported verbatim from the Rust) ---
  ["https://guard.example.com/analyze?x=1", "query_or_fragment"],
  ["https://guard.example.com/analyze#frag", "query_or_fragment"],
  // --- not a URL at all ---
  ["guard.example.com/analyze", "invalid_url"],
  ["", "invalid_url"],
];

/** Endpoints that MUST keep working — over-blocking is a real outage. */
const LEGITIMATE_ENDPOINTS: string[] = [
  "https://guard.example.com/analyze",
  "http://guard.example.com/analyze",
  // Non-standard ports are legal: the Rust placed NO port restriction.
  "https://guard.example.com:8443/analyze",
  "http://guard.example.com:9000/v1/analyze/prompt",
  "https://presidio.internal-corp.example.net/analyze",
  "https://8.8.8.8/analyze",
  "https://1.1.1.1/analyze",
  "https://[2606:4700:4700::1111]/analyze",
  // Adjacent-but-public ranges: just outside each blocked block.
  "https://172.15.0.1/analyze", // below 172.16/12
  "https://172.32.0.1/analyze", // above 172.16/12
  "https://100.63.255.255/analyze", // below CGNAT 100.64/10
  "https://100.128.0.1/analyze", // above CGNAT 100.64/10
  "https://192.167.1.1/analyze", // below 192.168/16
  "https://11.0.0.1/analyze", // above 10/8
  "https://126.0.0.1/analyze", // below 127/8
  "https://128.0.0.1/analyze", // above 127/8
  // A hostname that merely CONTAINS a blocked label is not itself blocked.
  "https://localhost.guard.example.com/analyze",
  "https://not-localhost.example.com/analyze",
];

describe("detectorEndpointRejection — hostile endpoints", () => {
  test.each(HOSTILE_ENDPOINTS)("rejects %s (%s)", (endpoint, reason) => {
    expect(detectorEndpointRejection(endpoint, false)).toBe(reason);
  });

  test("every hostile private-network endpoint is refused for that exact reason", () => {
    // Guards the table itself: if a spelling silently reclassified as e.g.
    // `invalid_url`, the SSRF check would not be what refused it.
    const privateOnes = HOSTILE_ENDPOINTS.filter(([, r]) => r === "private_network_host");
    expect(privateOnes.length).toBeGreaterThan(20);
    for (const [endpoint] of privateOnes) {
      expect(detectorEndpointRejection(endpoint, false)).toBe("private_network_host");
    }
  });
});

describe("detectorEndpointRejection — legitimate endpoints", () => {
  test.each(LEGITIMATE_ENDPOINTS)("accepts %s", (endpoint) => {
    expect(detectorEndpointRejection(endpoint, false)).toBeUndefined();
  });
});

describe("detectorEndpointRejection — allowPrivateNetwork escape hatch", () => {
  test("opens the private-host gate and nothing else", () => {
    expect(detectorEndpointRejection("http://127.0.0.1:8080/analyze", true)).toBeUndefined();
    expect(detectorEndpointRejection("http://localhost:8080/analyze", true)).toBeUndefined();
    expect(detectorEndpointRejection("http://[::1]/analyze", true)).toBeUndefined();
    // Structural rules survive the escape hatch.
    expect(detectorEndpointRejection("file:///etc/passwd", true)).toBe("scheme_not_allowed");
    expect(detectorEndpointRejection("http://u:p@127.0.0.1/a", true)).toBe("credentials_in_url");
    expect(detectorEndpointRejection("http://127.0.0.1/a?x=1", true)).toBe("query_or_fragment");
  });
});

describe("parseLooseIpv4 (inet_aton forms the Rust resolver used to absorb)", () => {
  test.each([
    ["127.0.0.1", [127, 0, 0, 1]],
    ["0177.0.0.1", [127, 0, 0, 1]], // octal first part
    ["0x7f.0.0.1", [127, 0, 0, 1]], // hex first part
    ["0x7f000001", [127, 0, 0, 1]], // hex integer
    ["2130706433", [127, 0, 0, 1]], // decimal integer
    ["127.1", [127, 0, 0, 1]], // 2-part short form
    ["127.0.1", [127, 0, 0, 1]], // 3-part short form
    ["0", [0, 0, 0, 0]],
    ["8.8.8.8", [8, 8, 8, 8]],
    ["3232235777", [192, 168, 1, 1]],
  ])("%s → %s", (host, expected) => {
    expect(parseLooseIpv4(host)).toEqual(expected);
  });

  test.each([
    "guard.example.com",
    "example",
    "1.1.1.1.1", // too many parts
    "256.0.0.1", // octet overflow
    "127.0.0.256", // final part overflow for 4 parts
    "4294967296", // >32 bits
    "09.0.0.1", // invalid octal
    "12.34.-5.6",
    "",
    "::1",
    "127.0.0.1:80",
  ])("%s is not an IPv4 host", (host) => {
    expect(parseLooseIpv4(host)).toBeUndefined();
  });
});

describe("isDisallowedDetectorHost", () => {
  test.each([
    "127.0.0.1",
    "0177.0.0.1", // caught by the loose parse, not by Ipv4Addr-parity parsing
    "2130706433",
    "0x7f.0.0.1",
    "127.1",
    "127.0.0.1.", // trailing root dot
    "localhost",
    "LocalHost",
    "localhost.",
    "db.localhost",
    "10.1.2.3",
    "172.20.0.1",
    "192.168.0.5",
    "169.254.169.254",
    "100.100.0.1",
    "[::1]",
    "::1",
    "[fc00::1]",
    "[::ffff:127.0.0.1]",
    "::ffff:7f00:1",
  ])("blocks %s", (host) => {
    expect(isDisallowedDetectorHost(host)).toBe(true);
  });

  test.each([
    "guard.example.com",
    "localhost.guard.example.com",
    "8.8.8.8",
    "1.1.1.1",
    "172.15.0.1",
    "100.63.0.1",
    "[2606:4700:4700::1111]",
  ])("allows %s", (host) => {
    expect(isDisallowedDetectorHost(host)).toBe(false);
  });

  test("non-ASCII host folding is borrowed from the URL parser", () => {
    // Our own parsers are ASCII-only by design; IDNA/NFKC folding is the one
    // thing they delegate. Circled digits fold to `127.0.0.1`.
    expect(isDisallowedDetectorHost("①②⑦.0.0.1")).toBe(true);
    // ...and folding must not turn a public host private: ⑧ → 128.0.0.1.
    expect(isDisallowedDetectorHost("①②⑧.0.0.1")).toBe(false);
    expect(isDisallowedDetectorHost("guärd.example.com")).toBe(false);
  });

  test("strict IP parsing stays Rust-faithful, obfuscation is handled at host level", () => {
    // `isDisallowedDetectorIp` is the ported `is_disallowed_detector_ip`: it
    // keeps `Ipv4Addr::from_str` semantics and does NOT see obfuscated forms.
    expect(isDisallowedDetectorIp("0177.0.0.1")).toBe(false);
    expect(isDisallowedDetectorIp("2130706433")).toBe(false);
    // The host-level check is what closes them, standing in for the resolver.
    expect(isDisallowedDetectorHost("0177.0.0.1")).toBe(true);
    expect(isDisallowedDetectorHost("2130706433")).toBe(true);
  });
});

/* --------------------------------------------------------------------------
 * The same table, driven through the REAL production entry points rather than
 * a bespoke checker — `CustomHttpDetector.new` (built-in HTTP detector) and
 * `HttpJsonTransport.build` (Presidio / LLM-Guard adapters).
 * ------------------------------------------------------------------------ */

function customHttpConfig(endpoint: string, allowPrivateNetwork = false) {
  return {
    id: "custom",
    endpoint,
    timeoutMs: 2_000,
    maxConcurrency: 4,
    circuitFailureThreshold: 3,
    circuitCooldownMs: 30_000,
    maxRetries: 1,
    maxPayloadBytes: 1_000_000,
    maxResponseBytes: 256_000,
    allowPrivateNetwork,
    supportedSources: ["user" as const],
  };
}

describe("CustomHttpDetector.new refuses hostile endpoints (production path)", () => {
  test.each(HOSTILE_ENDPOINTS)("refuses %s", (endpoint) => {
    let thrown: unknown;
    try {
      CustomHttpDetector.new(customHttpConfig(endpoint));
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(DetectorError);
    expect((thrown as DetectorError).kind).toBe("invalid_configuration");
  });

  test.each(LEGITIMATE_ENDPOINTS)("constructs against %s", (endpoint) => {
    expect(() => CustomHttpDetector.new(customHttpConfig(endpoint))).not.toThrow();
  });

  test("private endpoints require the explicit allow_private_network opt-in", () => {
    expect(() => CustomHttpDetector.new(customHttpConfig("http://127.0.0.1:8080/analyze"))).toThrow(
      /allow_private_network/,
    );
    expect(() =>
      CustomHttpDetector.new(customHttpConfig("http://127.0.0.1:8080/analyze", true)),
    ).not.toThrow();
  });
});

/**
 * `URL.canParse` is newer than this workspace's `lib: ES2022` target, so the
 * same predicate is spelled with the constructor. Keeping it typed (rather than
 * casting `URL` to `any`) means a future lib bump does not hide a drift here.
 */
function urlParses(value: string): boolean {
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

describe("HttpJsonTransport.build refuses hostile endpoints (adapter path)", () => {
  test.each(HOSTILE_ENDPOINTS.filter(([e]) => urlParses(e)))("refuses %s", (endpoint) => {
    expect(() =>
      HttpJsonTransport.build(new URL(endpoint), 2_000, false, undefined, 256_000),
    ).toThrow(DetectorError);
  });

  test("accepts a public detector endpoint on a non-standard port", () => {
    expect(() =>
      HttpJsonTransport.build(
        new URL("https://presidio.example.com:8443/analyze"),
        2_000,
        false,
        DetectorSecret.new("token"),
        256_000,
      ),
    ).not.toThrow();
  });
});

describe("validateCustomHttpEndpoint messages stay ported", () => {
  test("private-network vs structural rejections keep distinct Rust messages", () => {
    expect(() => validateCustomHttpEndpoint("http://10.0.0.1/analyze", false)).toThrow(
      "guardrail detector private-network endpoint requires explicit allow_private_network",
    );
    expect(() => validateCustomHttpEndpoint("http://user:pass@example.com/analyze", false)).toThrow(
      "guardrail detector endpoint must be an http(s) URL without credentials, query, or fragment",
    );
    expect(() => validateCustomHttpEndpoint("not-a-url", false)).toThrow(
      "guardrail detector endpoint is not a valid URL",
    );
  });
});

/**
 * PLATFORM LIMIT PIN — kept as a PORT-TODO in `src/net.ts`.
 *
 * workerd exposes no DNS resolver hook, so a hostname that RESOLVES to a
 * private IP cannot be blocked pre-connect. These assertions state the shape of
 * the gap precisely, so nobody later mistakes the literal-surface defense for a
 * complete SSRF defense — and so that if workerd ever grows a resolver hook,
 * the compensating tightenings can be re-derived from what is written here.
 */
describe("PLATFORM LIMIT — no DNS resolver hook (guardrails/net)", () => {
  test("a public hostname is ACCEPTED regardless of what it resolves to", () => {
    // This is the gap itself, asserted rather than described. A name whose A
    // record is 127.0.0.1 is indistinguishable from any other public name at
    // this layer, because nothing in the runtime will tell us the address.
    expect(detectorEndpointRejection("https://evil.example.com/analyze", false)).toBeUndefined();
    expect(isDisallowedDetectorHost("evil.example.com")).toBe(false);
  });

  test("…while the IP LITERAL it would resolve to is refused, in every spelling", () => {
    // The compensation: the Rust `Ipv4Addr::from_str` rejected the inet_aton
    // forms and the RESOLVER then filtered the resulting 127.0.0.1. With the
    // resolver gone, parsing them here is what preserves that behavior.
    for (const host of ["127.0.0.1", "0177.0.0.1", "0x7f.0.0.1", "2130706433", "127.1"]) {
      expect(isDisallowedDetectorHost(host)).toBe(true);
    }
    expect(isDisallowedDetectorHost("::ffff:127.0.0.1")).toBe(true);
  });

  test("the resolved-address filter is ported but has NOTHING to filter", () => {
    // `filterResolvedDetectorAddresses` is a faithful port of the resolver's
    // predicate, kept for parity and for a future host that CAN supply a
    // resolved set. It is not wired into the request path, because there is no
    // resolved set on Workers — nothing calls it with real data.
    expect(
      filterResolvedDetectorAddresses(
        [
          { ip: "127.0.0.1", port: 443 },
          { ip: "93.184.216.34", port: 443 },
        ],
        false,
      ),
    ).toEqual([{ ip: "93.184.216.34", port: 443 }]);
  });

  test("the two compensating tightenings over the Rust are still in force", () => {
    // RFC 6761 reserves the whole `localhost` zone to loopback; the Rust
    // matched only the bare name and let its resolver catch the rest.
    expect(isDisallowedDetectorHost("localhost")).toBe(true);
    expect(isDisallowedDetectorHost("localhost.")).toBe(true);
    expect(isDisallowedDetectorHost("api.localhost")).toBe(true);
  });

  test("NON-tightening: the port is still unrestricted, exactly as in Rust", () => {
    // Called out because it is easy to "harden" by mistake. Adding a
    // standard-ports-only rule would be a behavior change, not a port.
    expect(
      detectorEndpointRejection("https://guard.example.com:8443/analyze", false),
    ).toBeUndefined();
  });
});
