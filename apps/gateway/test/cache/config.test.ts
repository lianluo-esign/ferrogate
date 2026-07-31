/**
 * `[cache]` off Worker vars — `src/cache/config.ts`.
 *
 * Two properties, and both are about a config section that `packages/config`
 * has validated since wave 1 while NOTHING read it:
 *
 *  1. the section is actually READ — every field, including the four-level
 *     `ai_cache_enabled` opt-out ladder (`state_routing.rs:223`);
 *  2. every way a var can be unusable turns the cache OFF and reports why,
 *     rather than degrading to a cache with the operator's restriction dropped.
 *     Dropping `GATEWAY_CACHE_DISABLED_MODELS` would start caching a model the
 *     operator excluded, which is the failure this direction prevents.
 */
import { describe, expect, it } from "vitest";
import {
  CACHE_DISABLED_POLICY,
  aiCacheEnabled,
  parseNameList,
  responseCachePolicy,
  responseCachePolicyFromEnv,
} from "../../src/cache/config.js";

describe("responseCachePolicy", () => {
  it("is DISABLED with nothing declared — Rust `CacheConfig::default().enabled == false`", () => {
    const policy = responseCachePolicy({});
    expect(policy.enabled).toBe(false);
    expect(policy.misconfiguration).toBeNull();
    // The Rust defaults survive even while off, so switching the cache on
    // without naming a ttl gets 300s / 1000 records, not 0.
    expect(policy.ttlSeconds).toBe(300);
    expect(policy.maxRecords).toBe(1000);
    expect(policy.mode).toBe("exact_match");
  });

  it("only the exact string `true` switches it on", () => {
    for (const value of ["", "false", "1", "yes", "ture", "TRUE"]) {
      expect(responseCachePolicy({ GATEWAY_CACHE_ENABLED: value }).enabled).toBe(
        value.trim().toLowerCase() === "true",
      );
    }
    expect(responseCachePolicy({ GATEWAY_CACHE_ENABLED: "true" }).enabled).toBe(true);
  });

  it("reads ttl_secs, max_records and mode", () => {
    const policy = responseCachePolicy({
      GATEWAY_CACHE_ENABLED: "true",
      GATEWAY_CACHE_TTL_SECONDS: "45",
      GATEWAY_CACHE_MAX_RECORDS: "7",
      GATEWAY_CACHE_MODE: "semantic",
    });
    expect(policy.ttlSeconds).toBe(45);
    expect(policy.maxRecords).toBe(7);
    // `semantic` is ACCEPTED and runs the exact-match layer; the semantic layer
    // itself is the PORT-TODO in `cache/metrics.ts`. Rejecting the mode would
    // turn an operator's forward-looking setting into an outage.
    expect(policy.mode).toBe("semantic");
    expect(policy.misconfiguration).toBeNull();
  });

  it("an unusable value DISABLES the cache and says which var", () => {
    for (const [name, env] of [
      ["GATEWAY_CACHE_TTL_SECONDS", { GATEWAY_CACHE_TTL_SECONDS: "0" }],
      ["GATEWAY_CACHE_TTL_SECONDS", { GATEWAY_CACHE_TTL_SECONDS: "-5" }],
      ["GATEWAY_CACHE_TTL_SECONDS", { GATEWAY_CACHE_TTL_SECONDS: "abc" }],
      ["GATEWAY_CACHE_MAX_RECORDS", { GATEWAY_CACHE_MAX_RECORDS: "1.5" }],
      ["GATEWAY_CACHE_MODE", { GATEWAY_CACHE_MODE: "fuzzy" }],
      ["GATEWAY_CACHE_DISABLED_MODELS", { GATEWAY_CACHE_DISABLED_MODELS: "[oops" }],
      ["GATEWAY_CACHE_DISABLED_API_KEYS", { GATEWAY_CACHE_DISABLED_API_KEYS: "[1,2]" }],
      ["GATEWAY_CACHE_DISABLED_PROFILES", { GATEWAY_CACHE_DISABLED_PROFILES: '{"a":1}' }],
    ] as const) {
      const policy = responseCachePolicy({ GATEWAY_CACHE_ENABLED: "true", ...env });
      expect(`${name}: ${policy.enabled}`).toBe(`${name}: false`);
      expect(policy.misconfiguration).toContain(name);
    }
  });

  it("does not diagnose a broken var while the cache is switched OFF", () => {
    // `ai_cache_enabled` returns false on the global switch before it reads
    // anything else; reporting a `bypass` on an inert deployment would be noise.
    const policy = responseCachePolicy({ GATEWAY_CACHE_TTL_SECONDS: "nonsense" });
    expect(policy.enabled).toBe(false);
    expect(policy.misconfiguration).toBeNull();
  });

  it("memoizes on the VALUES, so a changed var is never stale", () => {
    const first = responseCachePolicyFromEnv({ GATEWAY_CACHE_ENABLED: "true" });
    expect(responseCachePolicyFromEnv({ GATEWAY_CACHE_ENABLED: "true" })).toBe(first);
    const changed = responseCachePolicyFromEnv({
      GATEWAY_CACHE_ENABLED: "true",
      GATEWAY_CACHE_TTL_SECONDS: "9",
    });
    expect(changed).not.toBe(first);
    expect(changed.ttlSeconds).toBe(9);
  });
});

describe("parseNameList", () => {
  it("accepts a JSON array and a bare comma list", () => {
    expect(parseNameList('["gpt-4o", "claude"]')).toEqual(["gpt-4o", "claude"]);
    expect(parseNameList("gpt-4o, claude")).toEqual(["gpt-4o", "claude"]);
    expect(parseNameList("gpt-4o")).toEqual(["gpt-4o"]);
    expect(parseNameList("  ")).toEqual([]);
  });

  it("returns null — never an empty list — for a declared-but-broken value", () => {
    // An empty list would silently DROP the operator's opt-out.
    expect(parseNameList("[nope")).toBeNull();
    expect(parseNameList("[1]")).toBeNull();
    expect(parseNameList('{"a":1}')).toBeNull();
  });
});

describe("aiCacheEnabled — Rust `AppState::ai_cache_enabled`", () => {
  const on = responseCachePolicy({
    GATEWAY_CACHE_ENABLED: "true",
    GATEWAY_CACHE_DISABLED_MODELS: "no-cache-model",
    GATEWAY_CACHE_DISABLED_API_KEYS: "key_no_cache",
    GATEWAY_CACHE_DISABLED_PROFILES: "profile_no_cache",
  });
  const input = { apiKeyId: "key_ok", logicalModel: "gpt-4o-mini", profileId: null };

  it("admits when every level agrees", () => {
    expect(aiCacheEnabled(on, input)).toBe(true);
  });

  it("the GLOBAL switch alone denies", () => {
    expect(aiCacheEnabled(CACHE_DISABLED_POLICY, input)).toBe(false);
  });

  it("the MODEL row denies", () => {
    expect(aiCacheEnabled(on, { ...input, logicalModel: "no-cache-model" })).toBe(false);
  });

  it("the API-KEY row denies", () => {
    expect(aiCacheEnabled(on, { ...input, apiKeyId: "key_no_cache" })).toBe(false);
  });

  it("the gateway-config PROFILE denies (`x-ferrogate-config`)", () => {
    expect(aiCacheEnabled(on, { ...input, profileId: "profile_no_cache" })).toBe(false);
    // An unrelated profile changes nothing.
    expect(aiCacheEnabled(on, { ...input, profileId: "profile_other" })).toBe(true);
  });

  it("an absent api-key id or profile never turns caching ON by itself", () => {
    const off = responseCachePolicy({});
    expect(aiCacheEnabled(off, { apiKeyId: null, logicalModel: "m", profileId: null })).toBe(false);
  });
});
