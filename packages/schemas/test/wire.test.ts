import { describe, expect, test } from "vitest";
import {
  OPENAPI_OPERATION_COUNT,
  assertScopeParity,
  errorEnvelopeSchema,
  jsonValueSchema,
  scopeSchema,
  wireSchemas,
} from "@ferrogate/schemas";

describe("scopeSchema", () => {
  test("requires a non-empty tenant and allows optional project/workspace", () => {
    expect(scopeSchema.parse({ tenant: "t" })).toEqual({ tenant: "t" });
    expect(scopeSchema.safeParse({ tenant: "" }).success).toBe(false); // min(1)
    expect(scopeSchema.parse({ tenant: "t", project: "p", workspace: "w" })).toEqual({
      tenant: "t",
      project: "p",
      workspace: "w",
    });
  });

  test("assertScopeParity keeps the wire schema assignable to core Scope", () => {
    expect(assertScopeParity({ tenant: "t", project: "p" })).toEqual({
      tenant: "t",
      project: "p",
    });
  });
});

describe("errorEnvelopeSchema", () => {
  test("requires code+message and allows an optional requestId", () => {
    expect(errorEnvelopeSchema.parse({ code: "x", message: "y" })).toEqual({
      code: "x",
      message: "y",
    });
    expect(
      errorEnvelopeSchema.parse({ code: "x", message: "y", requestId: "r" }).requestId,
    ).toBe("r");
    expect(errorEnvelopeSchema.safeParse({ code: "x" }).success).toBe(false);
  });
});

describe("jsonValueSchema", () => {
  test("accepts scalars, null, arrays, and nested objects", () => {
    for (const v of ["s", 1, true, null, [1, "a", null], { a: { b: [1] } }]) {
      expect(jsonValueSchema.safeParse(v).success).toBe(true);
    }
  });

  // Edge: values with no JSON representation are rejected.
  test("rejects undefined and functions", () => {
    expect(jsonValueSchema.safeParse(undefined).success).toBe(false);
    expect(jsonValueSchema.safeParse(() => 1).success).toBe(false);
  });
});

describe("wireSchemas registry", () => {
  test("exposes the OpenAPI operation count", () => {
    expect(OPENAPI_OPERATION_COUNT).toBe(251);
  });

  test("resolves the seeded cross-plane + ferrogate-core schemas by name", () => {
    for (const key of [
      "scope",
      "errorEnvelope",
      "approvalPolicy",
      "tenantContext",
      "workspaceScope",
      "requestContext",
      "toolDef",
      "toolCall",
      "toolResult",
      "gatewayError",
    ]) {
      expect(typeof wireSchemas[key]?.safeParse).toBe("function");
    }
  });

  test("registry entries actually validate (e.g. tenantContext)", () => {
    expect(wireSchemas.tenantContext?.safeParse({ organization_id: "org" }).success).toBe(true);
    expect(wireSchemas.gatewayError?.safeParse({ code: "c", message: "m" }).success).toBe(true);
  });

  // The 249 remaining per-operation bodies of the 251-op contract are ported by
  // the request-path cluster and registered here — see inventory §1.3/§1.4.
  test.todo("registers all 251 OpenAPI operation request/response bodies");
});
