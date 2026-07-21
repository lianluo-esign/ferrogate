import { describe, expect, it } from "vitest";
import { RESOURCE_ROUTES } from "@/resources";
import { RESOURCE_ROUTE_PATHS } from "@/resources/route-paths";

describe("resource route registry", () => {
  it("keeps the initial lightweight path registry equal to the lazy config registry", () => {
    expect(RESOURCE_ROUTES.map((route) => route.path).sort()).toEqual(
      Object.values(RESOURCE_ROUTE_PATHS).sort(),
    );
  });
});
