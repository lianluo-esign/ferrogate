import { describe, expect, test } from "vitest";
import {
  type RouteRuleLike,
  buildTargetUri,
  buildTargetUrl,
  matchesRequest,
  normalizeHost,
  parseUpstreamEndpoint,
  rewritePath,
} from "../src/routing.js";
import { parseConfig } from "../src/schema/config.js";
import { defaultConfig } from "../src/schema/config.js";
import { resolveEnvPlaceholders } from "../src/secrets.js";
import { configSnapshotId } from "../src/snapshot.js";
import { validateConfig } from "../src/validate.js";
import { x402ConfirmationWindowSecs, x402HoldTtlFloorSecs } from "../src/x402-hold.js";

describe("routing", () => {
  test("normalizeHost strips port, trims and lowercases", () => {
    expect(normalizeHost(" Example.COM:8080 ")).toBe("example.com");
  });

  test("parseUpstreamEndpoint drops default ports and trims base path", () => {
    expect(parseUpstreamEndpoint("https://api.example.com:443/v1/")).toMatchObject({
      scheme: "https",
      authority: "api.example.com",
      basePath: "/v1",
    });
    expect(parseUpstreamEndpoint("http://h:8080").authority).toBe("h:8080");
    expect(() => parseUpstreamEndpoint("ftp://x")).toThrow(/scheme/);
  });

  test("rewritePath applies strip_prefix then add_prefix", () => {
    const route: RouteRuleLike = { strip_prefix: "/api", add_prefix: "/v1" };
    expect(rewritePath(route, "/api/chat")).toBe("/v1/chat");
    // strip "/api" -> "/", then join add_prefix "/v1" with "/" -> "/v1" (Rust join_url_path).
    expect(rewritePath(route, "/api")).toBe("/v1");
    expect(rewritePath({}, "/x")).toBe("/x");
  });

  test("buildTargetUrl joins base path + rewritten path + query", () => {
    const route: RouteRuleLike = { strip_prefix: "/api" };
    expect(buildTargetUrl("https://up.example.com/base", route, "/api/chat", "a=1")).toBe(
      "https://up.example.com/base/chat?a=1",
    );
  });

  test("matchesRequest honors hosts, prefixes and header matchers", () => {
    const route: RouteRuleLike = {
      hosts: ["Example.com"],
      path_prefixes: ["/v1"],
      match_headers: [{ name: "X-Env", value: "prod" }],
    };
    expect(matchesRequest(route, "example.com", "/v1/chat", { "x-env": "prod" })).toBe(true);
    expect(matchesRequest(route, "other.com", "/v1/chat", { "x-env": "prod" })).toBe(false);
    expect(matchesRequest(route, "example.com", "/v2", { "x-env": "prod" })).toBe(false);
    expect(matchesRequest(route, "example.com", "/v1", { "x-env": "dev" })).toBe(false);
  });
});

/**
 * `build_target_uri` is `join` + `path.parse::<Uri>()`, and only the join was
 * ported. Table-driven on ERROR IDENTITY and on the accepted string, because a
 * bare `toThrow()` here would pass against a function that threw for the wrong
 * reason — and because the two byte sets are asymmetric, so a single "is this
 * URI-safe?" predicate would be wrong for one half or the other.
 */
describe("build_target_uri parses the assembled target, it does not just concatenate", () => {
  const endpoint = parseUpstreamEndpoint("https://up.example.com/base");

  test.each([
    ["a space in the joined path", "/a b", undefined, "/base/a b"],
    ["a control byte in the joined path", "/a\u0001b", undefined, "/base/a\u0001b"],
    ["a DEL byte in the joined path", "/a\u007fb", undefined, "/base/a\u007fb"],
    ["a non-ASCII character in the joined path", "/café", undefined, "/base/café"],
    ["a brace in the joined path", "/a{b}", undefined, "/base/a{b}"],
    ["an angle bracket in the joined path", "/a<b>", undefined, "/base/a<b>"],
    ["a double quote in the joined path", '/a"b', undefined, '/base/a"b'],
    ["a backtick in the joined path", "/a`b", undefined, "/base/a`b"],
    ["a space in the query", "/ok", "a=1 2", "/base/ok?a=1 2"],
    ["a non-ASCII character in the query", "/ok", "a=café", "/base/ok?a=café"],
    ["an angle bracket in the query", "/ok", "a=<b>", "/base/ok?a=<b>"],
  ])("refuses %s with the Rust message", (_label, path, query, reported) => {
    expect(() => buildTargetUri(endpoint, path, query)).toThrow(`invalid target path ${reported}`);
  });

  test.each([
    ["ordinary path + query", "/chat", "a=1", "/base/chat?a=1"],
    ["percent-encoding is opaque, not decoded", "/a%20b", undefined, "/base/a%20b"],
    // 0x7C `|` and 0x5C `\` sit INSIDE the path set; a naive "URI-safe" filter
    // drops both, so they are pinned as ACCEPTED.
    ["a pipe and a backslash in the path", "/a|b\\c", undefined, "/base/a|b\\c"],
    // The query set is wider than the path set: `{`/`}`/`` ` ``/`?` are legal here.
    ["braces and a backtick in the query", "/ok", "a={x}`y", "/base/ok?a={x}`y"],
    ["a second question mark in the query", "/ok", "a=1?b=2", "/base/ok?a=1?b=2"],
  ])("accepts %s", (_label, path, query, expected) => {
    expect(buildTargetUri(endpoint, path, query)).toBe(expected);
  });

  test("truncates at a fragment, exactly as PathAndQuery drops it", () => {
    expect(buildTargetUri(endpoint, "/chat#frag")).toBe("/base/chat");
    expect(buildTargetUri(endpoint, "/chat", "a=1#frag")).toBe("/base/chat?a=1");
  });

  test("buildTargetUrl carries the refusal up to the absolute URL", () => {
    expect(() => buildTargetUrl("https://up.example.com/base", {}, "/a b")).toThrow(
      "invalid target path /base/a b",
    );
  });
});

/**
 * `parse_upstream_endpoint`'s THREE distinct Rust failures, which `new URL()`
 * had collapsed into two. The schemeless case is the one that regressed: Rust
 * parses `api.example.com/v1` as authority-form and reports the missing scheme,
 * which is the actionable message; `new URL()` throws and it was reported as a
 * malformed URL.
 */
describe("parse_upstream_endpoint error identity", () => {
  test.each([
    ["authority-form", "api.example.com/v1"],
    ["bare host", "api.example.com"],
    ["host:port, which is NOT a scheme", "api.example.com:8080"],
    ["origin-form", "/v1/chat"],
    ["protocol-relative", "//api.example.com/v1"],
  ])("%s reports the missing scheme, not a malformed URL", (_label, raw) => {
    expect(() => parseUpstreamEndpoint(raw)).toThrow("upstream URL must include scheme");
  });

  test("only an input Uri itself refuses keeps the malformed wording", () => {
    expect(() => parseUpstreamEndpoint("")).toThrow("invalid upstream URL ");
    expect(() => parseUpstreamEndpoint("http://")).toThrow("invalid upstream URL http://");
  });

  test("a non-http scheme is still the scheme-kind refusal", () => {
    expect(() => parseUpstreamEndpoint("ftp://x")).toThrow(
      "upstream URL scheme must be http or https",
    );
  });

  /**
   * The message is operator-facing: `validate_upstreams` splices it into the
   * `field ...` chain, so the identity has to survive that hop, not just the
   * throw. This is the assertion that fails if the fix lives only in the helper.
   */
  test("validate_upstreams reports the missing scheme through the field chain", () => {
    const config = parseConfig({
      upstreams: [{ name: "u", url: "api.example.com/v1" }],
      routes: [{ name: "r", upstream: "u" }],
    });
    expect(() => validateConfig(config)).toThrow(
      "field upstreams[0].urls[0]: upstream u has invalid endpoint api.example.com/v1: " +
        "upstream URL must include scheme",
    );
  });
});

describe("configSnapshotId", () => {
  test("is stable for equal config and changes when it changes", () => {
    const a = defaultConfig();
    expect(configSnapshotId(a)).toBe(configSnapshotId(defaultConfig()));
    expect(configSnapshotId(a)).toHaveLength(16);
    const b = { ...a, listen: "127.0.0.1:9090" };
    expect(configSnapshotId(a)).not.toBe(configSnapshotId(b));
  });
});

describe("resolveEnvPlaceholders", () => {
  test("interpolates {env.NAME} from the supplied env", () => {
    expect(resolveEnvPlaceholders("Bearer {env.SECRET}", { SECRET: "s3cr3t" })).toBe(
      "Bearer s3cr3t",
    );
  });

  test("reports a missing variable by name only, never the value", () => {
    expect(() => resolveEnvPlaceholders("{env.MISSING}", {})).toThrow(/MISSING/);
  });

  test("rejects unterminated / invalid placeholder names", () => {
    expect(() => resolveEnvPlaceholders("{env.NAME", {})).toThrow(/unterminated/);
    expect(() => resolveEnvPlaceholders("{env.bad-name}", {})).toThrow(/invalid/);
  });
});

describe("x402 hold-TTL floor", () => {
  test("window = deadline + delay + one tick; floor = window + 1", () => {
    const reconciler = {
      tick_interval_secs: 30,
      confirmation_deadline_secs: 900,
      reconcile_check_delay_secs: 60,
    };
    expect(x402ConfirmationWindowSecs(reconciler)).toBe(990n);
    expect(x402HoldTtlFloorSecs(reconciler)).toBe(991n);
  });

  test("saturates instead of wrapping on overflow", () => {
    const huge = 1n << 62n; // near i64::MAX; the sum overflows
    const floor = x402HoldTtlFloorSecs({
      tick_interval_secs: huge,
      confirmation_deadline_secs: huge,
      reconcile_check_delay_secs: huge,
    });
    expect(floor).toBe((1n << 63n) - 1n);
  });
});
