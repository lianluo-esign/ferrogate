import { describe, expect, it } from "vitest";

import { toolCallSchema, toolDefSchema, toolResultSchema } from "../src/index";

describe("ToolDef", () => {
  it("parses with an arbitrary JSON input_schema; description optional", () => {
    const def = toolDefSchema.parse({
      name: "search",
      input_schema: { type: "object", properties: { q: { type: "string" } } },
    });
    expect(def.name).toBe("search");
    expect(def.description).toBeUndefined();
  });

  it("omits description on serialize when absent (skip_serializing_if parity)", () => {
    const def = toolDefSchema.parse({ name: "s", input_schema: {} });
    expect(JSON.stringify(def)).not.toContain("description");
    const withDesc = toolDefSchema.parse({ name: "s", description: "d", input_schema: {} });
    expect(withDesc.description).toBe("d");
  });

  it("requires name and input_schema (edge case)", () => {
    expect(toolDefSchema.safeParse({ input_schema: {} }).success).toBe(false);
    expect(toolDefSchema.safeParse({ name: "s" }).success).toBe(false);
  });
});

describe("ToolCall", () => {
  it("accepts arbitrary JSON arguments (array, scalars, null, nested)", () => {
    const call = toolCallSchema.parse({
      id: "call-1",
      name: "run",
      arguments: [1, "a", null, { nested: true }],
    });
    expect(call.id).toBe("call-1");
    expect(call.arguments).toEqual([1, "a", null, { nested: true }]);
  });
});

describe("ToolResult", () => {
  it("requires is_error (no serde default)", () => {
    expect(toolResultSchema.safeParse({ tool_call_id: "1", content: "ok" }).success).toBe(false);
    const result = toolResultSchema.parse({
      tool_call_id: "1",
      content: { ok: true },
      is_error: false,
    });
    expect(result.is_error).toBe(false);
    expect(result.content).toEqual({ ok: true });
  });
});
