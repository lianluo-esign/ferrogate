import { describe, expect, test } from "vitest";
import {
  toolCallSchema,
  toolDefSchema,
  toolResultSchema,
} from "@ferrogate/schemas";

describe("toolDefSchema", () => {
  test("accepts a full definition with a JSON-Schema input_schema", () => {
    const def = toolDefSchema.parse({
      name: "search",
      description: "search the web",
      input_schema: { type: "object", properties: { q: { type: "string" } } },
    });
    expect(def.name).toBe("search");
    expect(def.description).toBe("search the web");
  });

  // description is skip_serializing_if=None in Rust → optional here.
  test("accepts a definition without description", () => {
    const def = toolDefSchema.parse({ name: "noop", input_schema: {} });
    expect(def.description).toBeUndefined();
  });

  test("requires name and input_schema", () => {
    expect(toolDefSchema.safeParse({ description: "x", input_schema: {} }).success).toBe(false);
    expect(toolDefSchema.safeParse({ name: "x" }).success).toBe(false);
  });

  // Edge: input_schema is an arbitrary JSON value, not restricted to objects.
  test("input_schema tolerates any JSON value", () => {
    expect(toolDefSchema.safeParse({ name: "x", input_schema: [1, 2, 3] }).success).toBe(true);
    expect(toolDefSchema.safeParse({ name: "x", input_schema: "raw" }).success).toBe(true);
    expect(toolDefSchema.safeParse({ name: "x", input_schema: null }).success).toBe(true);
  });
});

describe("toolCallSchema", () => {
  test("accepts an id/name/arguments triple", () => {
    const call = toolCallSchema.parse({ id: "c1", name: "search", arguments: { q: "hi" } });
    expect(call.id).toBe("c1");
    expect(call.arguments).toEqual({ q: "hi" });
  });

  test("requires all three fields", () => {
    expect(toolCallSchema.safeParse({ id: "c1", name: "search" }).success).toBe(false);
  });
});

describe("toolResultSchema", () => {
  test("accepts a result with is_error", () => {
    const res = toolResultSchema.parse({
      tool_call_id: "c1",
      content: { text: "done" },
      is_error: false,
    });
    expect(res.is_error).toBe(false);
    expect(res.tool_call_id).toBe("c1");
  });

  // Edge: is_error is a required boolean (not defaulted).
  test("requires is_error", () => {
    expect(
      toolResultSchema.safeParse({ tool_call_id: "c1", content: "x" }).success,
    ).toBe(false);
  });

  test("rejects a non-boolean is_error", () => {
    expect(
      toolResultSchema.safeParse({ tool_call_id: "c1", content: "x", is_error: "nope" }).success,
    ).toBe(false);
  });
});
