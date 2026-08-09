/**
 * The JSON Schema Draft 2020-12 validator behind the deterministic detector's
 * `JsonConstraints`, and the RFC 6901 pointer path.
 *
 * The stakes: this decides whether a request/response body SATISFIES an
 * operator's constraint. A keyword that is silently unimplemented does not
 * fail — it ADMITS, so a constraint the operator believes is enforced is not.
 * Every keyword below therefore has a case that must be REJECTED, not only one
 * that is accepted; an accept-only test would pass against a validator that
 * always returns `true`.
 */
import { describe, expect, test } from "vitest";
import {
  evaluateSchema,
  isValidSchema,
  jsonPointerExists,
  resolveJsonPointer,
} from "../src/index.js";

describe("RFC 6901 pointers", () => {
  const doc = { a: { "b/c": [1, { "~x": true }] }, "": "empty-key" };

  test("resolves nested objects, arrays and the escapes", () => {
    expect(resolveJsonPointer(doc, "")).toBe(doc);
    expect(resolveJsonPointer(doc, "/a/b~1c/0")).toBe(1);
    expect(resolveJsonPointer(doc, "/a/b~1c/1/~0x")).toBe(true);
    expect(resolveJsonPointer(doc, "/")).toBe("empty-key");
  });

  test("an absent path, a bad index and a non-rooted pointer are undefined", () => {
    expect(resolveJsonPointer(doc, "/a/nope")).toBeUndefined();
    expect(resolveJsonPointer(doc, "/a/b~1c/9")).toBeUndefined();
    expect(resolveJsonPointer(doc, "/a/b~1c/x")).toBeUndefined();
    expect(resolveJsonPointer(doc, "a/b")).toBeUndefined();
  });

  test("jsonPointerExists tracks resolution", () => {
    expect(jsonPointerExists(doc, "/a/b~1c/0")).toBe(true);
    expect(jsonPointerExists(doc, "/a/zzz")).toBe(false);
  });
});

describe("isValidSchema — the construction-time gate", () => {
  test("accepts booleans and objects, rejects other JSON", () => {
    expect(isValidSchema(true)).toBe(true);
    expect(isValidSchema(false)).toBe(true);
    expect(isValidSchema({})).toBe(true);
    expect(isValidSchema(null)).toBe(false);
    expect(isValidSchema([])).toBe(false);
    expect(isValidSchema(7)).toBe(false);
  });

  test("rejects an unknown `type`", () => {
    expect(isValidSchema({ type: "int" })).toBe(false);
    expect(isValidSchema({ type: ["string", "blob"] })).toBe(false);
    expect(isValidSchema({ type: ["string", "null"] })).toBe(true);
  });

  test("rejects an uncompilable `pattern` at CONFIG time, not at request time", () => {
    expect(isValidSchema({ pattern: "([a-z]" })).toBe(false);
    expect(isValidSchema({ patternProperties: { "([": {} } })).toBe(false);
    expect(isValidSchema({ pattern: "^[a-z]+$" })).toBe(true);
  });

  test("recurses into sub-schema positions", () => {
    expect(isValidSchema({ properties: { a: { type: "nope" } } })).toBe(false);
    expect(isValidSchema({ allOf: [{ type: "string" }, { type: "nope" }] })).toBe(false);
    expect(isValidSchema({ items: { type: "nope" } })).toBe(false);
    expect(isValidSchema({ not: { pattern: "([" } })).toBe(false);
    expect(isValidSchema({ $defs: { a: { type: "nope" } } })).toBe(false);
  });
});

describe("evaluateSchema — type", () => {
  test("every JSON type", () => {
    expect(evaluateSchema({ type: "null" }, null)).toBe(true);
    expect(evaluateSchema({ type: "null" }, 0)).toBe(false);
    expect(evaluateSchema({ type: "object" }, {})).toBe(true);
    expect(evaluateSchema({ type: "object" }, [])).toBe(false);
    expect(evaluateSchema({ type: "object" }, null)).toBe(false);
    expect(evaluateSchema({ type: "array" }, [])).toBe(true);
    expect(evaluateSchema({ type: "string" }, "x")).toBe(true);
    expect(evaluateSchema({ type: "boolean" }, false)).toBe(true);
  });

  test("Draft rule: 1.0 IS an integer, 1.5 is not", () => {
    expect(evaluateSchema({ type: "integer" }, 1.0)).toBe(true);
    expect(evaluateSchema({ type: "integer" }, 1.5)).toBe(false);
  });

  test("a union type passes if ANY member matches", () => {
    const schema = { type: ["string", "null"] };
    expect(evaluateSchema(schema, null)).toBe(true);
    expect(evaluateSchema(schema, "x")).toBe(true);
    expect(evaluateSchema(schema, 1)).toBe(false);
  });
});

describe("evaluateSchema — enum / const", () => {
  test("enum compares by VALUE, not identity", () => {
    expect(evaluateSchema({ enum: [{ a: [1] }] }, { a: [1] })).toBe(true);
    expect(evaluateSchema({ enum: [{ a: [1] }] }, { a: [2] })).toBe(false);
  });

  test("const rejects a differing value including a superset object", () => {
    expect(evaluateSchema({ const: { a: 1 } }, { a: 1 })).toBe(true);
    expect(evaluateSchema({ const: { a: 1 } }, { a: 1, b: 2 })).toBe(false);
  });

  test("an array and an object with the same keys are NOT equal", () => {
    expect(evaluateSchema({ const: [] }, {})).toBe(false);
    expect(evaluateSchema({ const: {} }, [])).toBe(false);
  });
});

describe("evaluateSchema — numbers", () => {
  test("minimum / maximum are inclusive", () => {
    expect(evaluateSchema({ minimum: 5 }, 5)).toBe(true);
    expect(evaluateSchema({ minimum: 5 }, 4.999)).toBe(false);
    expect(evaluateSchema({ maximum: 5 }, 5)).toBe(true);
    expect(evaluateSchema({ maximum: 5 }, 5.001)).toBe(false);
  });

  test("exclusiveMinimum / exclusiveMaximum are not", () => {
    expect(evaluateSchema({ exclusiveMinimum: 5 }, 5)).toBe(false);
    expect(evaluateSchema({ exclusiveMinimum: 5 }, 5.001)).toBe(true);
    expect(evaluateSchema({ exclusiveMaximum: 5 }, 5)).toBe(false);
    expect(evaluateSchema({ exclusiveMaximum: 5 }, 4.999)).toBe(true);
  });

  test("multipleOf survives IEEE-754 (a literal % test would reject 0.3/0.1)", () => {
    expect(evaluateSchema({ multipleOf: 0.1 }, 0.3)).toBe(true);
    expect(evaluateSchema({ multipleOf: 3 }, 9)).toBe(true);
    expect(evaluateSchema({ multipleOf: 3 }, 10)).toBe(false);
  });

  test("numeric keywords do not constrain non-numbers", () => {
    expect(evaluateSchema({ minimum: 5 }, "abc")).toBe(true);
  });
});

describe("evaluateSchema — strings", () => {
  test("pattern is a partial match, as in JSON Schema (unanchored)", () => {
    expect(evaluateSchema({ pattern: "b" }, "abc")).toBe(true);
    expect(evaluateSchema({ pattern: "^b" }, "abc")).toBe(false);
  });

  test("minLength/maxLength count CODE POINTS, not UTF-16 units", () => {
    // "𝒜" is one code point but two UTF-16 units; `.length` would say 2.
    expect(evaluateSchema({ maxLength: 1 }, "𝒜")).toBe(true);
    expect(evaluateSchema({ minLength: 2 }, "𝒜")).toBe(false);
  });
});

describe("evaluateSchema — objects", () => {
  test("required", () => {
    expect(evaluateSchema({ required: ["a"] }, { a: undefined })).toBe(true); // key present
    expect(evaluateSchema({ required: ["a"] }, { b: 1 })).toBe(false);
  });

  test("properties constrains only declared, PRESENT keys", () => {
    const schema = { properties: { a: { type: "string" } } };
    expect(evaluateSchema(schema, { a: "x" })).toBe(true);
    expect(evaluateSchema(schema, { a: 1 })).toBe(false);
    expect(evaluateSchema(schema, { b: 1 })).toBe(true);
  });

  test("additionalProperties: false rejects an undeclared key", () => {
    const schema = { properties: { a: {} }, additionalProperties: false };
    expect(evaluateSchema(schema, { a: 1 })).toBe(true);
    expect(evaluateSchema(schema, { a: 1, b: 2 })).toBe(false);
  });

  test("additionalProperties as a SCHEMA constrains the undeclared keys", () => {
    const schema = { properties: { a: {} }, additionalProperties: { type: "number" } };
    expect(evaluateSchema(schema, { a: "any", b: 2 })).toBe(true);
    expect(evaluateSchema(schema, { a: "any", b: "no" })).toBe(false);
  });

  test("a patternProperties match is NOT 'additional'", () => {
    const schema = {
      patternProperties: { "^x_": { type: "number" } },
      additionalProperties: false,
    };
    expect(evaluateSchema(schema, { x_1: 1 })).toBe(true);
    expect(evaluateSchema(schema, { x_1: "no" })).toBe(false);
    expect(evaluateSchema(schema, { y_1: 1 })).toBe(false);
  });

  test("propertyNames constrains the KEYS", () => {
    const schema = { propertyNames: { pattern: "^[a-z]+$" } };
    expect(evaluateSchema(schema, { abc: 1 })).toBe(true);
    expect(evaluateSchema(schema, { ABC: 1 })).toBe(false);
  });

  test("minProperties / maxProperties", () => {
    expect(evaluateSchema({ minProperties: 2 }, { a: 1 })).toBe(false);
    expect(evaluateSchema({ maxProperties: 1 }, { a: 1, b: 2 })).toBe(false);
  });

  test("dependentRequired fires only when the trigger key is present", () => {
    const schema = { dependentRequired: { card: ["billing_address"] } };
    expect(evaluateSchema(schema, { name: "x" })).toBe(true);
    expect(evaluateSchema(schema, { card: "4111" })).toBe(false);
    expect(evaluateSchema(schema, { card: "4111", billing_address: "here" })).toBe(true);
  });

  test("dependentSchemas applies a whole schema when the trigger is present", () => {
    const schema = { dependentSchemas: { card: { required: ["cvc"] } } };
    expect(evaluateSchema(schema, { other: 1 })).toBe(true);
    expect(evaluateSchema(schema, { card: 1 })).toBe(false);
    expect(evaluateSchema(schema, { card: 1, cvc: 2 })).toBe(true);
  });
});

describe("evaluateSchema — arrays", () => {
  test("minItems / maxItems", () => {
    expect(evaluateSchema({ minItems: 2 }, [1])).toBe(false);
    expect(evaluateSchema({ maxItems: 1 }, [1, 2])).toBe(false);
  });

  test("uniqueItems compares by value", () => {
    expect(evaluateSchema({ uniqueItems: true }, [{ a: 1 }, { a: 2 }])).toBe(true);
    expect(evaluateSchema({ uniqueItems: true }, [{ a: 1 }, { a: 1 }])).toBe(false);
  });

  test("items constrains every element", () => {
    expect(evaluateSchema({ items: { type: "number" } }, [1, 2])).toBe(true);
    expect(evaluateSchema({ items: { type: "number" } }, [1, "x"])).toBe(false);
  });

  test("prefixItems is positional, and items covers the REST", () => {
    const schema = { prefixItems: [{ type: "string" }, { type: "number" }], items: false };
    expect(evaluateSchema(schema, ["a", 1])).toBe(true);
    expect(evaluateSchema(schema, [1, 1])).toBe(false);
    // `items: false` after the prefix ⇒ no extra elements allowed.
    expect(evaluateSchema(schema, ["a", 1, "extra"])).toBe(false);
  });

  test("a Draft-7 tuple `items: [...]` is honoured as a prefix, not ignored", () => {
    const schema = { items: [{ type: "string" }, { type: "number" }] };
    expect(evaluateSchema(schema, ["a", 1])).toBe(true);
    expect(evaluateSchema(schema, ["a", "b"])).toBe(false);
  });

  test("contains with minContains / maxContains", () => {
    const schema = { contains: { type: "number" } };
    expect(evaluateSchema(schema, ["a", 1])).toBe(true);
    expect(evaluateSchema(schema, ["a", "b"])).toBe(false);
    expect(evaluateSchema({ ...schema, minContains: 2 }, ["a", 1])).toBe(false);
    expect(evaluateSchema({ ...schema, maxContains: 1 }, [1, 2])).toBe(false);
  });
});

describe("evaluateSchema — boolean applicators", () => {
  test("allOf requires every branch", () => {
    const schema = { allOf: [{ type: "string" }, { minLength: 2 }] };
    expect(evaluateSchema(schema, "ab")).toBe(true);
    expect(evaluateSchema(schema, "a")).toBe(false);
  });

  test("anyOf requires at least one", () => {
    const schema = { anyOf: [{ type: "string" }, { type: "number" }] };
    expect(evaluateSchema(schema, 1)).toBe(true);
    expect(evaluateSchema(schema, true)).toBe(false);
  });

  test("oneOf requires EXACTLY one — two matches is a failure", () => {
    const schema = { oneOf: [{ type: "number" }, { type: "integer" }] };
    expect(evaluateSchema(schema, 1)).toBe(false); // matches both
    expect(evaluateSchema(schema, 1.5)).toBe(true); // number only
  });

  test("not inverts", () => {
    expect(evaluateSchema({ not: { type: "string" } }, 1)).toBe(true);
    expect(evaluateSchema({ not: { type: "string" } }, "x")).toBe(false);
  });

  test("if/then/else picks a branch", () => {
    const schema = {
      if: { properties: { kind: { const: "a" } }, required: ["kind"] },
      // biome-ignore lint/suspicious/noThenProperty: `then` is a JSON Schema if/then/else keyword here, not a thenable — this plain data object is never awaited
      then: { required: ["a_field"] },
      else: { required: ["other_field"] },
    };
    expect(evaluateSchema(schema, { kind: "a", a_field: 1 })).toBe(true);
    expect(evaluateSchema(schema, { kind: "a" })).toBe(false);
    expect(evaluateSchema(schema, { kind: "b", other_field: 1 })).toBe(true);
    expect(evaluateSchema(schema, { kind: "b" })).toBe(false);
  });

  test("`true` admits everything and `false` admits nothing", () => {
    expect(evaluateSchema(true, { anything: 1 })).toBe(true);
    expect(evaluateSchema(false, { anything: 1 })).toBe(false);
  });
});

describe("evaluateSchema — $ref", () => {
  const root = {
    $defs: { positive: { type: "integer", exclusiveMinimum: 0 } },
    properties: { count: { $ref: "#/$defs/positive" } },
  };

  test("a local $ref resolves against the ROOT schema, through recursion", () => {
    expect(evaluateSchema(root, { count: 3 })).toBe(true);
    expect(evaluateSchema(root, { count: 0 })).toBe(false);
    expect(evaluateSchema(root, { count: 1.5 })).toBe(false);
  });

  test("$ref sits ALONGSIDE sibling keywords (Draft 2020-12), both apply", () => {
    const schema = {
      $defs: { str: { type: "string" } },
      $ref: "#/$defs/str",
      minLength: 3,
    };
    expect(evaluateSchema(schema, "abcd")).toBe(true);
    expect(evaluateSchema(schema, "ab")).toBe(false);
    expect(evaluateSchema(schema, 1234)).toBe(false);
  });

  /**
   * DOCUMENTED GAP #1 — a remote `$ref` is not fetched, because a validator
   * that reaches the network inside a guardrail evaluation is an SSRF surface
   * (see `src/net.ts`). It FAILS CLOSED so a constraint the operator believes
   * is enforced can never silently admit everything.
   */
  test("a remote or unresolvable $ref FAILS CLOSED", () => {
    expect(evaluateSchema({ $ref: "https://example.com/schema.json" }, "anything")).toBe(false);
    expect(evaluateSchema({ $ref: "#/$defs/missing" }, "anything")).toBe(false);
  });
});

/**
 * DOCUMENTED GAP #2 — `format` is an ANNOTATION in Draft 2020-12, which is what
 * the Rust `jsonschema` crate does without `should_validate_formats`. It must
 * neither reject nor be mistaken for a validation.
 */
describe("evaluateSchema — format is an annotation, not an assertion", () => {
  test("a value violating its declared format is still valid", () => {
    expect(evaluateSchema({ type: "string", format: "email" }, "not-an-email")).toBe(true);
  });

  test("…so an operator who needs it must write a pattern", () => {
    const schema = { type: "string", pattern: "^[^@\\s]+@[^@\\s]+$" };
    expect(evaluateSchema(schema, "not-an-email")).toBe(false);
    expect(evaluateSchema(schema, "a@b")).toBe(true);
  });
});

describe("an unknown keyword is ignored, not treated as a rejection", () => {
  test("x-vendor extensions do not fail a document", () => {
    expect(evaluateSchema({ "x-ferrogate-note": "hi", type: "string" }, "x")).toBe(true);
  });
});
