import { describe, expect, it } from "vitest";
import { ARTIFACTS } from "../artifacts.mjs";

describe("Python admin SDK artifact", () => {
  it("registers an OpenAPI-derived operation catalog", () => {
    expect(ARTIFACTS).toContainEqual(
      expect.objectContaining({
        slug: "sdks/python",
        spec: "docs/openapi/admin-api.openapi.json",
        output: "sdks/python/ferrogate_admin/api.generated.py",
      }),
    );
  });
});
