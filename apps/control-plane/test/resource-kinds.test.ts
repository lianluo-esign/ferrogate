import { describe, expect, it } from "vitest";
import {
  CONTROL_PLANE_RESOURCE_KINDS,
  CONTROL_RESOURCE_KIND_TABLE,
  TENANT_RESOURCE_KINDS,
  resourceKindPlacement,
} from "../src/store/resource-kinds.js";

describe("control-plane resource kind registry", () => {
  it("keeps tenant and platform placements disjoint and fails closed for unknown kinds", () => {
    const allKinds = CONTROL_PLANE_RESOURCE_KINDS.map((entry) => entry.kind);
    expect(new Set(allKinds).size).toBe(allKinds.length);
    expect(TENANT_RESOURCE_KINDS).toContain("agent-workflows");
    expect(TENANT_RESOURCE_KINDS).not.toContain("plans");
    expect(resourceKindPlacement("agent-workflows")).toBe("tenant_private");
    expect(resourceKindPlacement("plans")).toBe("platform_shared");
    expect(resourceKindPlacement("support-chat-conversations")).toBe("platform_shared");
    expect(resourceKindPlacement("support-chat-presence")).toBe("platform_shared");
    expect(CONTROL_RESOURCE_KIND_TABLE).toBe("tenant_resources");
    expect(() => resourceKindPlacement("future-unclassified-kind")).toThrow(
      "unknown control-plane resource kind",
    );
  });
});
