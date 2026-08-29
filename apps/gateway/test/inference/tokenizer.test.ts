/**
 * The local BPE tokenizer (`src/inference/tokenizer.ts`, #976 Phase B1).
 *
 * These counts are pinned against the real `gpt-tokenizer` `o200k_base` encoding
 * — the same table the buffered fallback bills off — so a silent encoding swap
 * (or a bundler that resolves the type shim instead of the JS at runtime) is a
 * test failure, not a quiet mis-bill. The values were taken from the shipped
 * package directly, not hand-estimated.
 */
import { describe, expect, it } from "vitest";

import { countTokens, encodingForModel } from "../../src/inference/tokenizer.js";

describe("countTokens (o200k_base)", () => {
  it.each([
    ["hello world", 2],
    ["The quick brown fox jumps over the lazy dog.", 10],
    ["hi", 1],
    ["hello", 1],
    ["", 0],
    ["hi\nthere", 3],
  ])("counts %j as %i tokens", (text, expected) => {
    // The `model` argument only selects the encoding; the count is the text's.
    expect(countTokens(text, "gpt-4o")).toBe(expected);
  });

  it("is model-agnostic in B1 — every model counts on the same encoding", () => {
    const text = "The quick brown fox jumps over the lazy dog.";
    for (const model of ["gpt-4o", "gpt-5", "claude-3-5-sonnet", "gemini-2.0-flash", ""]) {
      expect(countTokens(text, model)).toBe(10);
    }
  });
});

describe("encodingForModel", () => {
  it("answers o200k_base for every model (B1 ships exactly one encoding)", () => {
    for (const model of ["gpt-4o", "gpt-3.5-turbo", "claude-3-opus", "llama-3", ""]) {
      expect(encodingForModel(model)).toBe("o200k_base");
    }
  });
});
