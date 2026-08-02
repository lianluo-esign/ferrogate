/**
 * The required Cloudflare token permission groups (slice S3) — ported from
 * `crates/ferrogate-cloudflare/src/scopes.rs`.
 *
 * This table is the machine-adjacent source of truth `preflight()` names when a
 * token authenticates but is under-scoped. Its whole value is that an operator
 * with a token missing "Workers R2 Storage" learns THAT, once, from a CLI
 * command — instead of learning "a call failed", at first use, in production.
 *
 * The rows are pinned verbatim because they are Cloudflare dashboard strings: a
 * typo here is un-actionable advice, and there is no way to notice it from
 * inside the type system.
 */
import { describe, expect, test } from "vitest";
import { REQUIRED_TOKEN_PERMISSION_GROUPS, requiredGroupNames } from "../src/scopes.js";

describe("REQUIRED_TOKEN_PERMISSION_GROUPS", () => {
  test("is the Rust table, in issue-declared order, verbatim", () => {
    expect(REQUIRED_TOKEN_PERMISSION_GROUPS.map((g) => [g.name, g.access])).toEqual([
      ["AI Gateway", "Read, Edit"],
      ["Secrets Store", "Read, Write"],
      ["D1", "Read, Edit"],
      ["Workers Scripts", "Edit"],
      ["Workers R2 Storage", "Read, Edit"],
      ["API Tokens", "Write"],
      ["Cloudflare Pages", "Edit"],
      ["Workflows (Workers Scripts)", "Write, Edit"],
    ]);
  });

  test("every row explains which subsystem consumes it", () => {
    for (const group of REQUIRED_TOKEN_PERMISSION_GROUPS) {
      expect(group.usedBy.length).toBeGreaterThan(0);
    }
  });

  test("API Tokens: Write is present — minting scoped R2 credentials needs it", () => {
    // Easy to drop, and its absence is invisible until a mint fails in prod.
    const group = REQUIRED_TOKEN_PERMISSION_GROUPS.find((g) => g.name === "API Tokens");
    expect(group?.access).toBe("Write");
  });

  test("requiredGroupNames projects the names in table order", () => {
    expect(requiredGroupNames()).toEqual(REQUIRED_TOKEN_PERMISSION_GROUPS.map((g) => g.name));
  });

  test("names are unique — a duplicate would double-report in the error message", () => {
    const names = requiredGroupNames();
    expect(new Set(names).size).toBe(names.length);
  });
});
