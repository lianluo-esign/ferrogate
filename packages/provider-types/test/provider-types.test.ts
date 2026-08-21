import { describe, expect, it } from "vitest";
import { PROVIDER_TYPE_IDS, inferProviderTypeIdFromKind, isProviderTypeId } from "../src/index.js";

describe("provider type ids", () => {
  it("keeps the public provider type set stable", () => {
    expect(PROVIDER_TYPE_IDS).toEqual([
      "openai",
      "anthropic",
      "gemini",
      "minimax",
      "deepseek",
      "grok",
    ]);
    for (const value of PROVIDER_TYPE_IDS) expect(isProviderTypeId(value)).toBe(true);
    expect(isProviderTypeId("openai-compatible")).toBe(false);
  });

  it.each([
    ["openai", "openai"],
    ["openai-compatible", "openai"],
    ["azure-openai", "openai"],
    ["anthropic", "anthropic"],
    ["claude", "anthropic"],
    ["google", "gemini"],
    ["vertex-ai", "gemini"],
    ["deepseek", "deepseek"],
    ["minimax", "minimax"],
    ["xai", "grok"],
  ] as const)("maps adapter kind %s to provider type %s", (kind, providerTypeId) => {
    expect(inferProviderTypeIdFromKind(kind)).toBe(providerTypeId);
  });
});
