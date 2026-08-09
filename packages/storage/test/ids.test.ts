import { describe, expect, test } from "vitest";
import {
  agentCostBurnKey,
  periodMonthFromUnix,
  providerIsDurable,
  providerIsImplemented,
  quotaPolicyId,
  saturatingAdd,
  sha256Hex,
  siteDomainVerificationKey,
  storedAssetId,
  storedAssetVariantId,
} from "../src/index.js";

describe("deterministic ids", () => {
  test("storedAssetId composes the owning tuple", () => {
    expect(storedAssetId("t1", "tool", "cli", "1.0.0")).toBe("t1:tool:cli:1.0.0");
  });

  test("variant id falls back to the plain id for the default variant", () => {
    expect(storedAssetVariantId("t1", "tool", "cli", "1.0.0", "")).toBe("t1:tool:cli:1.0.0");
    expect(storedAssetVariantId("t1", "tool", "cli", "1.0.0", "linux-x86_64")).toBe(
      "t1:tool:cli:1.0.0:v:linux-x86_64",
    );
  });

  test("quotaPolicyId is scope-keyed", () => {
    expect(quotaPolicyId("workspace", "ws1")).toBe("workspace:ws1");
  });

  test("length-prefixed composite keys cannot alias", () => {
    // ("ab","c") vs ("a","bc") would collide without length prefixes.
    expect(agentCostBurnKey("ab", "c", "p")).not.toBe(agentCostBurnKey("a", "bc", "p"));
    expect(siteDomainVerificationKey("ab", "c")).not.toBe(siteDomainVerificationKey("a", "bc"));
  });
});

describe("periodMonthFromUnix", () => {
  test("epoch is 1970-01", () => {
    expect(periodMonthFromUnix(0)).toBe("1970-01");
  });

  test("a known 2026 timestamp maps to its UTC month", () => {
    // 2026-07-31T00:00:00Z
    expect(periodMonthFromUnix(Date.UTC(2026, 6, 31) / 1000)).toBe("2026-07");
  });

  test("just before a month boundary stays in the earlier month (UTC)", () => {
    // 2026-02-28T23:59:59Z
    expect(periodMonthFromUnix(Date.UTC(2026, 1, 28, 23, 59, 59) / 1000)).toBe("2026-02");
  });
});

describe("provider predicates", () => {
  test("memory is not durable; others are", () => {
    expect(providerIsDurable("memory")).toBe(false);
    expect(providerIsDurable("cloudflare_d1")).toBe(true);
  });

  test("only the implemented set returns true", () => {
    expect(providerIsImplemented("cloudflare_d1")).toBe(true);
    expect(providerIsImplemented("turso_libsql")).toBe(false);
    expect(providerIsImplemented("mysql")).toBe(false);
  });
});

describe("helpers", () => {
  test("saturatingAdd clamps at the safe-integer ceiling", () => {
    expect(saturatingAdd(1, 2)).toBe(3);
    expect(saturatingAdd(Number.MAX_SAFE_INTEGER, 10)).toBe(Number.MAX_SAFE_INTEGER);
  });

  test("sha256Hex matches a known digest", async () => {
    const hex = await sha256Hex(new TextEncoder().encode("abc"));
    expect(hex).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });
});
