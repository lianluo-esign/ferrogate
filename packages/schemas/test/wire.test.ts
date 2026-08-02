import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
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

/**
 * WIRE-PARITY PIN for the corrected error envelope.
 *
 * This schema used to declare a flat `{ code, message, requestId? }` that
 * matched no response FerroGate emits. The fixtures below are the real emitted
 * bodies, copied from the shipped producers, so the test fails if the schema
 * drifts back — including the two easy-to-miss cases (`request_id: null` and
 * `request_id` absent) that a "tidier" `z.string()` would silently reject.
 */
describe("errorEnvelopeSchema — the shape the gateway actually writes", () => {
  test("accepts the envelope every FerroGate surface emits", () => {
    const emitted = {
      error: {
        message: "invalid api key",
        type: "ferrogate_error",
        code: "invalid_api_key",
        request_id: "fg-0123456789abcdef",
      },
    };
    expect(errorEnvelopeSchema.parse(emitted)).toEqual(emitted);
  });

  test("request_id null and request_id absent are both real emissions", () => {
    // Rust `request_id: Option<String>` has no `skip_serializing_if`, so `None`
    // is written as an explicit null, not an absent key.
    expect(
      errorEnvelopeSchema.safeParse({
        error: { message: "m", type: "ferrogate_error", code: "c", request_id: null },
      }).success,
    ).toBe(true);
    // Mid-stream SSE error frames carry no id at all — the id already left in
    // the response headers before the stream opened.
    expect(
      errorEnvelopeSchema.safeParse({
        error: { message: "blocked", type: "ferrogate_error", code: "guardrail_blocked" },
      }).success,
    ).toBe(true);
  });

  test("the OLD flat shape is refused — it is not a FerroGate response", () => {
    expect(errorEnvelopeSchema.safeParse({ code: "x", message: "y" }).success).toBe(false);
    expect(
      errorEnvelopeSchema.safeParse({ code: "x", message: "y", requestId: "r" }).success,
    ).toBe(false);
  });

  test("`type` is the discriminating literal, and `message`/`code` are required", () => {
    expect(
      errorEnvelopeSchema.safeParse({
        error: { message: "m", type: "openai_error", code: "c" },
      }).success,
    ).toBe(false);
    expect(
      errorEnvelopeSchema.safeParse({ error: { type: "ferrogate_error", code: "c" } }).success,
    ).toBe(false);
    expect(
      errorEnvelopeSchema.safeParse({ error: { message: "m", type: "ferrogate_error" } }).success,
    ).toBe(false);
    // A bare `{ error: "..." }` (the OpenAI-ish string form) is not this envelope.
    expect(errorEnvelopeSchema.safeParse({ error: "boom" }).success).toBe(false);
  });

  test("an unknown sibling key does not make a consumer reject the error", () => {
    const parsed = errorEnvelopeSchema.parse({
      error: {
        message: "m",
        type: "ferrogate_error",
        code: "c",
        request_id: "r",
        param: "model",
      },
    });
    expect(parsed.error.code).toBe("c");
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

/**
 * ANTI-DRIFT GATE for the third copy of 257.
 *
 * `OPENAPI_OPERATION_COUNT` here, `EXPECTED_OPERATION_COUNT` in
 * `apps/gateway/src/contract.ts` and `EXPECTED_TOTAL_OPERATION_COUNT` in
 * `apps/control-plane/src/contract.ts` are three independent declarations of
 * one number. Collapsing them into a single import is an `apps/*` edit, but
 * THIS copy no longer has to be taken on faith: it is checked against the
 * committed contract document itself, so adding or removing an operation
 * fails here instead of leaving a leaf package quietly counting a document it
 * disagrees with.
 *
 * Read off disk rather than `import`ed: a static import would pull a 79 KB JSON
 * into every bundle that touches this package, for a value only a test needs.
 */
describe("OPENAPI_OPERATION_COUNT is checked against the committed contract", () => {
  test("it equals `operations.length` in docs/openapi/runtime-api-contract.json", () => {
    const contractPath = fileURLToPath(
      new URL("../../../docs/openapi/runtime-api-contract.json", import.meta.url),
    );
    const contract = JSON.parse(readFileSync(contractPath, "utf8")) as {
      operations: unknown[];
    };
    // Fail loudly if the path ever stops resolving, rather than comparing
    // against `undefined` and passing for the wrong reason.
    expect(Array.isArray(contract.operations)).toBe(true);
    expect(contract.operations.length).toBe(OPENAPI_OPERATION_COUNT);
  });
});

describe("wireSchemas registry", () => {
  test("exposes the OpenAPI operation count", () => {
    expect(OPENAPI_OPERATION_COUNT).toBe(257);
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

/**
 * The FACTUAL CLAIM the surviving PORT-TODO in `src/index.ts` makes, asserted
 * rather than asserted-in-prose: this package seeds exactly the cross-plane
 * envelopes plus the `ferrogate-core` primitives, and nothing else. The 247
 * remaining contract operations are registered by `apps/*` at their own
 * composition time (nothing does so yet — that is the open half of the marker).
 *
 * If someone "closes" the marker by dumping per-operation bodies in here, this
 * exact-set assertion fails, which is the intent: a shared leaf package that
 * knows every route's body is the dependency inversion the marker forbids.
 */
describe("PORT-TODO STATE PIN — the registry seeds only cross-plane shapes", () => {
  test("the baseline registration set is exactly these ten names", () => {
    // This test process imports no app, so this IS the package's own baseline.
    expect(registeredWireSchemaNames().filter((n) => !n.startsWith("op_"))).toEqual([
      "approvalPolicy",
      "errorEnvelope",
      "gatewayError",
      "requestContext",
      "scope",
      "tenantContext",
      "toolCall",
      "toolDef",
      "toolResult",
      "workspaceScope",
    ]);
  });

  test("the baseline is far short of the contract, and says so in numbers", () => {
    const seeded = registeredWireSchemaNames().filter((n) => !n.startsWith("op_")).length;
    expect(seeded).toBe(10);
    expect(OPENAPI_OPERATION_COUNT - seeded).toBe(247);
  });
});
