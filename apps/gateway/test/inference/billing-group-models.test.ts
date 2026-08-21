import { describe, expect, it } from "vitest";
import { BillingGroupModelResolver, InMemoryModelResolver } from "../../src/inference/index.js";
import type { PhysicalRoute } from "../../src/inference/index.js";

const ROUTES: readonly PhysicalRoute[] = [
  {
    logicalModel: "shared-model",
    providerId: "provider-openai",
    provider: "main",
    providerModel: "gpt-upstream",
    providerKind: "openai",
    baseUrl: "https://openai.test/v1",
    enabled: true,
    priority: 0,
  },
  {
    logicalModel: "shared-model",
    providerId: "provider-anthropic",
    provider: "main",
    providerModel: "claude-upstream",
    providerKind: "anthropic",
    baseUrl: "https://anthropic.test/v1",
    enabled: true,
    priority: 10,
  },
  {
    logicalModel: "openai-only",
    providerId: "provider-openai",
    provider: "secondary",
    providerModel: "gpt-only-upstream",
    providerKind: "openai",
    baseUrl: "https://openai.test/v1",
    enabled: true,
  },
];

describe("BillingGroupModelResolver", () => {
  it("filters listing, resolution, and failover candidates by exact provider id", () => {
    const models = new BillingGroupModelResolver(new InMemoryModelResolver(ROUTES), [
      "provider-anthropic",
    ]);

    expect(models.catalog().map((route) => route.logicalModel)).toEqual(["shared-model"]);
    expect(models.resolve("shared-model")?.providerModel).toBe("claude-upstream");
    expect(models.candidates("shared-model").map((route) => route.providerId)).toEqual([
      "provider-anthropic",
    ]);
    expect(models.resolve("openai-only")).toBeNull();
  });

  it("does not confuse a provider name or family with the provider id", () => {
    const source = new InMemoryModelResolver(ROUTES);

    expect(new BillingGroupModelResolver(source, ["main"]).catalog()).toEqual([]);
    expect(new BillingGroupModelResolver(source, ["openai"]).catalog()).toEqual([]);
  });

  it("fails closed when the group has no provider edges", () => {
    const models = new BillingGroupModelResolver(new InMemoryModelResolver(ROUTES), []);

    expect(models.catalog()).toEqual([]);
    expect(models.resolve("shared-model")).toBeNull();
    expect(models.candidates("shared-model")).toEqual([]);
  });
});
