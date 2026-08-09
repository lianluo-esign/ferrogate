import { describe, expect, test } from "vitest";

import { ToolCallAccumulator } from "../../src/streaming/toolcalls.js";
const nn = <T>(v: T): NonNullable<T> => v as NonNullable<T>;

describe("ToolCallAccumulator", () => {
  test("concatenates argument fragments across deltas", () => {
    const accumulator = new ToolCallAccumulator();
    accumulator.applyToolCallDeltas([
      { index: 0, id: "call_1", function: { name: "lookup", arguments: '{"q":' } },
    ]);
    accumulator.applyToolCallDeltas([{ index: 0, function: { arguments: '"x"}' } }]);
    expect(accumulator.snapshot()).toEqual([
      { index: 0, id: "call_1", name: "lookup", arguments: '{"q":"x"}' },
    ]);
  });

  test("reports the fragment carried by each individual delta", () => {
    const accumulator = new ToolCallAccumulator();
    const first = accumulator.applyToolCallDeltas([
      { index: 0, id: "call_1", function: { name: "lookup" } },
    ]);
    expect((first[0] as NonNullable<(typeof first)[0]>).argumentsDelta).toBe("");
    expect((first[0] as NonNullable<(typeof first)[0]>).opened).toBe(true);
    const second = accumulator.applyToolCallDeltas([{ index: 0, function: { arguments: "{}" } }]);
    expect((second[0] as NonNullable<(typeof second)[0]>).argumentsDelta).toBe("{}");
    expect((second[0] as NonNullable<(typeof second)[0]>).opened).toBe(false);
  });

  test("keys by the explicit index, so parallel calls do not merge", () => {
    const accumulator = new ToolCallAccumulator();
    accumulator.applyToolCallDeltas([
      { index: 1, id: "b", function: { name: "beta", arguments: "B" } },
      { index: 0, id: "a", function: { name: "alpha", arguments: "A" } },
    ]);
    accumulator.applyToolCallDeltas([{ index: 1, function: { arguments: "B2" } }]);
    // Snapshot order is ascending index (Rust BTreeMap), not arrival order.
    expect(accumulator.snapshot().map((call) => call.index)).toEqual([0, 1]);
    expect(nn(accumulator.get(1)).arguments).toBe("BB2");
    expect(nn(accumulator.get(0)).arguments).toBe("A");
  });

  test("falls back to the array position when index is omitted", () => {
    const accumulator = new ToolCallAccumulator();
    accumulator.applyToolCallDeltas([
      { id: "a", function: { name: "alpha", arguments: "A" } },
      { id: "b", function: { name: "beta", arguments: "B" } },
    ]);
    expect(accumulator.snapshot().map((call) => call.id)).toEqual(["a", "b"]);
  });

  test("baseIndex shifts the positional fallback (responses normalizer)", () => {
    const accumulator = new ToolCallAccumulator();
    const updates = accumulator.applyToolCallDeltas(
      [{ function: { arguments: "A" } }, { function: { arguments: "B" } }],
      3,
    );
    expect(updates.map((update) => update.index)).toEqual([3, 4]);
  });

  test("the deprecated function_call shape accumulates under the choice index", () => {
    const accumulator = new ToolCallAccumulator();
    accumulator.applyFunctionCallDelta({ name: "legacy", arguments: '{"a' }, 0);
    const update = accumulator.applyFunctionCallDelta({ arguments: '":1}' }, 0);
    expect((update as NonNullable<typeof update>).argumentsDelta).toBe('":1}');
    expect(accumulator.get(0)).toEqual({
      index: 0,
      id: undefined,
      name: "legacy",
      arguments: '{"a":1}',
    });
  });

  test("renders the OpenAI tool_calls array with empty-string defaults", () => {
    const accumulator = new ToolCallAccumulator();
    accumulator.applyToolCallDeltas([{ index: 0, function: { arguments: "{}" } }]);
    expect(accumulator.toOpenAiToolCalls()).toEqual([
      { id: "", type: "function", function: { name: "", arguments: "{}" } },
    ]);
  });

  test("a non-array tool_calls value is ignored, not thrown on", () => {
    const accumulator = new ToolCallAccumulator();
    expect(accumulator.applyToolCallDeltas(undefined)).toEqual([]);
    expect(accumulator.applyToolCallDeltas("nope")).toEqual([]);
    expect(accumulator.isEmpty).toBe(true);
  });

  test("empty argument fragments never widen the accumulated string", () => {
    const accumulator = new ToolCallAccumulator();
    accumulator.applyToolCallDeltas([{ index: 0, function: { arguments: "" } }]);
    expect(nn(accumulator.get(0)).arguments).toBe("");
    expect(accumulator.size).toBe(1);
  });
});
