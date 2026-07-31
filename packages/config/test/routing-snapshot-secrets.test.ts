import { describe, expect, test } from "vitest";
import {
  buildTargetUrl,
  matchesRequest,
  normalizeHost,
  parseUpstreamEndpoint,
  rewritePath,
  type RouteRuleLike,
} from "../src/routing.js";
import { configSnapshotId } from "../src/snapshot.js";
import { defaultConfig } from "../src/schema/config.js";
import { resolveEnvPlaceholders } from "../src/secrets.js";
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
    expect(resolveEnvPlaceholders("Bearer {env.SECRET}", { SECRET: "s3cr3t" })).toBe("Bearer s3cr3t");
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
    const reconciler = { tick_interval_secs: 30, confirmation_deadline_secs: 900, reconcile_check_delay_secs: 60 };
    expect(x402ConfirmationWindowSecs(reconciler)).toBe(990n);
    expect(x402HoldTtlFloorSecs(reconciler)).toBe(991n);
  });

  test("saturates instead of wrapping on overflow", () => {
    const huge = (1n << 62n); // near i64::MAX; the sum overflows
    const floor = x402HoldTtlFloorSecs({
      tick_interval_secs: huge,
      confirmation_deadline_secs: huge,
      reconcile_check_delay_secs: huge,
    });
    expect(floor).toBe((1n << 63n) - 1n);
  });
});
