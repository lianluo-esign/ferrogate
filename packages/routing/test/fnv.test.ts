import { fnv1a64, rolloutBucket } from "@ferrogate/routing";
import { describe, expect, test } from "vitest";

describe("fnv1a64", () => {
  // Canonical FNV-1a64 vectors — guards the constants & wrapping arithmetic so
  // the bucketing stays byte-identical to the Rust crate.
  test("known vectors", () => {
    expect(fnv1a64(new Uint8Array())).toBe(0xcbf2_9ce4_8422_2325n); // offset basis
    expect(fnv1a64(new TextEncoder().encode("a"))).toBe(0xaf63_dc4c_8601_ec8cn);
    expect(fnv1a64(new TextEncoder().encode("foobar"))).toBe(0x8594_4171_f739_67e8n);
  });

  test("stays within 64 bits (wrapping_mul parity)", () => {
    const h = fnv1a64(new TextEncoder().encode("some longer string to churn the mul"));
    expect(h).toBeGreaterThanOrEqual(0n);
    expect(h).toBeLessThanOrEqual(0xffff_ffff_ffff_ffffn);
  });
});

describe("rolloutBucket", () => {
  test("always in 0..=99", () => {
    for (let i = 0; i < 500; i++) {
      const b = rolloutBucket("canary", `key-${i}`);
      expect(b).toBeGreaterThanOrEqual(0);
      expect(b).toBeLessThanOrEqual(99);
      expect(Number.isInteger(b)).toBe(true);
    }
  });

  test("deterministic per (salt, key)", () => {
    expect(rolloutBucket("canary", "sticky")).toBe(rolloutBucket("canary", "sticky"));
  });

  // Edge: the salt decorrelates splits — same key, different salt → (usually)
  // different bucket. Assert at least one key differs across the two salts.
  test("salt decorrelates buckets", () => {
    const differs = Array.from({ length: 100 }, (_, i) => `key-${i}`).some(
      (k) => rolloutBucket("canary", k) !== rolloutBucket("shadow", k),
    );
    expect(differs).toBe(true);
  });

  // Edge: the 0x00 separator makes framing unambiguous — "a" + "\0" + "b" must
  // not collide with "" + "\0" + "ab" style concatenations across salt/key.
  test("separator prevents salt/key boundary collisions", () => {
    expect(rolloutBucket("ab", "c")).not.toBe(rolloutBucket("a", "bc"));
  });
});
