import { describe, expect, it } from "vitest";

import { jsonValueSchema } from "../src/index";

describe("jsonValueSchema", () => {
  it("accepts scalars, null, arrays, and nested objects", () => {
    expect(jsonValueSchema.parse(null)).toBeNull();
    expect(jsonValueSchema.parse("s")).toBe("s");
    expect(jsonValueSchema.parse(42)).toBe(42);
    expect(jsonValueSchema.parse(true)).toBe(true);
    const nested = { a: [1, "b", null, { c: true }] };
    expect(jsonValueSchema.parse(nested)).toEqual(nested);
  });

  it("rejects non-JSON values (edge case)", () => {
    expect(jsonValueSchema.safeParse(undefined).success).toBe(false);
    expect(jsonValueSchema.safeParse(() => 1).success).toBe(false);
    expect(jsonValueSchema.safeParse(Symbol("x")).success).toBe(false);
  });
});
