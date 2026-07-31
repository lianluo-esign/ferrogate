import { describe, expect, test } from "vitest";
import { z } from "zod";
import {
  OPENAPI_OPERATION_COUNT,
  assertScopeParity,
  errorEnvelopeSchema,
  jsonValueSchema,
  registerWireSchema,
  registerWireSchemas,
  registeredWireSchemaNames,
  resolveWireSchema,
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

});

/**
 * The registration MECHANISM, which is this package's half of inventory
 * §1.3/§1.4. The 249 remaining per-operation bodies are owned by the surfaces
 * that serve them (`apps/gateway`, `apps/control-plane`, `apps/mcp`) — defining
 * them here would invert the dependency and guarantee drift. What this package
 * owes is a registry that cannot silently swap a route's validator, and that is
 * what these tests hold.
 */
describe("registerWireSchema", () => {
  const unique = () => `op_${Math.random().toString(36).slice(2)}`;

  test("registers and resolves a schema by operationId", () => {
    const name = unique();
    const schema = z.object({ model: z.string() });
    registerWireSchema(name, schema);
    expect(resolveWireSchema(name)).toBe(schema);
    expect(resolveWireSchema(name)?.safeParse({ model: "gpt" }).success).toBe(true);
    expect(resolveWireSchema(name)?.safeParse({}).success).toBe(false);
  });

  test("a DIFFERENT schema on an existing name is REFUSED, not overwritten", () => {
    const name = unique();
    const first = z.object({ a: z.string() });
    registerWireSchema(name, first);
    expect(() => registerWireSchema(name, z.object({ b: z.number() }))).toThrow(
      /already registered/,
    );
    // The original validator is still in place — the whole point. A silent
    // overwrite would make a route validate against another route's body.
    expect(resolveWireSchema(name)).toBe(first);
  });

  test("re-registering the IDENTICAL schema is a no-op", () => {
    // A composition root imported twice must not be an error.
    const name = unique();
    const schema = z.string();
    registerWireSchema(name, schema);
    expect(() => registerWireSchema(name, schema)).not.toThrow();
  });

  test("an empty name is refused", () => {
    expect(() => registerWireSchema("", z.string())).toThrow(/must not be empty/);
    expect(() => registerWireSchema("   ", z.string())).toThrow(/must not be empty/);
  });

  test("registerWireSchemas fails on the first collision", () => {
    const keep = unique();
    registerWireSchema(keep, z.string());
    expect(() => registerWireSchemas({ [keep]: z.number() })).toThrow(/already registered/);
  });

  test("the seeded cross-plane names are discoverable", () => {
    const names = registeredWireSchemaNames();
    expect(names).toEqual([...names].sort());
    for (const seeded of ["scope", "errorEnvelope", "tenantContext", "gatewayError"]) {
      expect(names).toContain(seeded);
    }
  });
});
