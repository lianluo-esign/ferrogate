/**
 * JSON pointer (RFC 6901) resolution + a JSON Schema Draft 2020-12 validator
 * for the deterministic detector's `JsonConstraints`.
 *
 * The Rust crate delegates to the `jsonschema` crate. This workspace admits no
 * JSON-Schema dependency (Wrangler is the only bundler and the port adds no
 * build step), so the vocabulary is implemented here directly.
 *
 * ## Coverage — the whole ASSERTION vocabulary of Draft 2020-12
 *
 * Applicators: `allOf`, `anyOf`, `oneOf`, `not`, `if`/`then`/`else`,
 * `properties`, `patternProperties`, `additionalProperties` (schema or
 * `false`), `propertyNames`, `dependentSchemas`, `prefixItems`, `items`,
 * `contains` (+ `minContains`/`maxContains`), and local `$ref`/`$defs`
 * (`#/...` JSON-pointer form).
 *
 * Assertions: `type` (incl. the Draft rule that an integral-valued number IS an
 * `integer`), `enum`, `const`, `multipleOf`, `minimum`, `maximum`,
 * `exclusiveMinimum`, `exclusiveMaximum`, `minLength`, `maxLength` (counted in
 * CODE POINTS, not UTF-16 units, per the spec), `pattern`, `minItems`,
 * `maxItems`, `uniqueItems`, `minProperties`, `maxProperties`, `required`,
 * `dependentRequired`.
 *
 * ## The two deliberate, documented gaps
 *
 * 1. **Remote/absolute `$ref` is not resolved** — `$ref` to another document
 *    would require a fetch, and a validator that reaches the network from
 *    inside a guardrail evaluation is an SSRF surface (see `./net.ts`). An
 *    unresolvable `$ref` FAILS CLOSED (the value is rejected) rather than being
 *    skipped, so a schema the operator believes is constraining can never
 *    silently admit everything.
 * 2. **`format` is an annotation, not an assertion**, which is the Draft
 *    2020-12 default and what the `jsonschema` crate does without
 *    `should_validate_formats`.
 *
 * Both are behaviors, not omissions, and `test/jsonschema.test.ts` pins them.
 *
 * `required_keys` / `forbidden_keys` (the RFC 6901 pointer path) are ported
 * verbatim from the Rust and are exact.
 */

/** Resolve an RFC 6901 JSON pointer against `doc`; `undefined` if absent. */
export function resolveJsonPointer(doc: unknown, pointer: string): unknown {
  if (pointer === "") {
    return doc;
  }
  if (!pointer.startsWith("/")) {
    return undefined;
  }
  let current: unknown = doc;
  for (const rawToken of pointer.slice(1).split("/")) {
    const token = rawToken.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(current)) {
      if (!/^\d+$/.test(token)) {
        return undefined;
      }
      const index = Number.parseInt(token, 10);
      if (index >= current.length) {
        return undefined;
      }
      current = current[index];
    } else if (current !== null && typeof current === "object") {
      const obj = current as Record<string, unknown>;
      if (!(token in obj)) {
        return undefined;
      }
      current = obj[token];
    } else {
      return undefined;
    }
  }
  return current;
}

/** Whether `pointer` exists (has a value) in `doc`. */
export function jsonPointerExists(doc: unknown, pointer: string): boolean {
  return resolveJsonPointer(doc, pointer) !== undefined;
}

const KNOWN_TYPES = ["null", "boolean", "object", "array", "number", "integer", "string"];

/**
 * Schema validity gate, run at detector CONSTRUCTION where Rust calls
 * `jsonschema::validator_for`. Rejects a schema that is not an object/boolean,
 * whose `type` is not a known JSON type, or whose `pattern` /
 * `patternProperties` key is not a compilable regular expression — a schema
 * that cannot compile must be refused when it is configured, not silently
 * treated as "matches nothing" at evaluation time.
 */
export function isValidSchema(schema: unknown): boolean {
  if (typeof schema === "boolean") {
    return true;
  }
  if (schema === null || typeof schema !== "object" || Array.isArray(schema)) {
    return false;
  }
  const s = schema as Record<string, unknown>;

  const type = s["type"];
  if (type !== undefined) {
    const types = Array.isArray(type) ? type : [type];
    if (!types.every((t) => typeof t === "string" && KNOWN_TYPES.includes(t))) {
      return false;
    }
  }

  if (typeof s["pattern"] === "string" && !compiles(s["pattern"])) {
    return false;
  }
  const patternProperties = s["patternProperties"];
  if (isPlainObject(patternProperties)) {
    if (!Object.keys(patternProperties).every(compiles)) {
      return false;
    }
  }

  // Recurse into every sub-schema position so an invalid nested schema is
  // caught at construction rather than at the first request that reaches it.
  for (const key of ["not", "if", "then", "else", "contains", "propertyNames", "items"]) {
    if (key in s && !isValidSchema(s[key])) {
      return false;
    }
  }
  if (s["additionalProperties"] !== undefined && s["additionalProperties"] !== false) {
    if (!isValidSchema(s["additionalProperties"])) {
      return false;
    }
  }
  for (const key of ["allOf", "anyOf", "oneOf", "prefixItems"]) {
    const list = s[key];
    if (Array.isArray(list) && !list.every(isValidSchema)) {
      return false;
    }
  }
  for (const key of ["properties", "patternProperties", "dependentSchemas", "$defs"]) {
    const map = s[key];
    if (isPlainObject(map) && !Object.values(map).every(isValidSchema)) {
      return false;
    }
  }
  return true;
}

function compiles(pattern: string): boolean {
  try {
    new RegExp(pattern, "u");
    return true;
  } catch {
    try {
      // A pattern that is valid ECMAScript but not valid in unicode mode (e.g.
      // a bare `\p`) still compiles without `u`; the `jsonschema` crate's Rust
      // `regex` is likewise more permissive than ES unicode mode.
      new RegExp(pattern);
      return true;
    } catch {
      return false;
    }
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function regex(pattern: string): RegExp | undefined {
  try {
    return new RegExp(pattern, "u");
  } catch {
    try {
      return new RegExp(pattern);
    } catch {
      return undefined;
    }
  }
}

/** Code-point length — `minLength`/`maxLength` count characters, not UTF-16 units. */
function codePointLength(value: string): number {
  let count = 0;
  for (const _ of value) count += 1;
  return count;
}

/**
 * Validate `value` against `schema`.
 *
 * `root` is the document `$ref` pointers resolve against; it defaults to
 * `schema`, so a top-level call needs only two arguments and a recursive call
 * threads the original root.
 */
export function evaluateSchema(schema: unknown, value: unknown, root: unknown = schema): boolean {
  if (typeof schema === "boolean") {
    return schema;
  }
  if (!isPlainObject(schema)) {
    // A non-schema (null, array, number) constrains nothing, matching the
    // pre-existing behavior this replaced.
    return true;
  }
  const s = schema;

  // --- $ref -----------------------------------------------------------------
  // Draft 2020-12 allows `$ref` to sit alongside other keywords, so this is an
  // additional constraint rather than a replacement.
  const ref = s["$ref"];
  if (typeof ref === "string") {
    if (!ref.startsWith("#")) {
      // Remote reference: unresolvable without network I/O. FAIL CLOSED.
      return false;
    }
    const target = resolveJsonPointer(root, ref.slice(1));
    if (target === undefined) {
      return false;
    }
    if (!evaluateSchema(target, value, root)) {
      return false;
    }
  }

  // --- type -----------------------------------------------------------------
  const type = s["type"];
  if (type !== undefined) {
    const types = Array.isArray(type) ? type : [type];
    if (!types.some((t) => typeof t === "string" && matchesType(t, value))) {
      return false;
    }
  }

  // --- enum / const ---------------------------------------------------------
  if (Array.isArray(s["enum"]) && !s["enum"].some((candidate) => deepEqual(candidate, value))) {
    return false;
  }
  if ("const" in s && !deepEqual(s["const"], value)) {
    return false;
  }

  // --- boolean applicators --------------------------------------------------
  const allOf = s["allOf"];
  if (Array.isArray(allOf) && !allOf.every((sub) => evaluateSchema(sub, value, root))) {
    return false;
  }
  const anyOf = s["anyOf"];
  if (Array.isArray(anyOf) && !anyOf.some((sub) => evaluateSchema(sub, value, root))) {
    return false;
  }
  const oneOf = s["oneOf"];
  if (Array.isArray(oneOf)) {
    const matches = oneOf.filter((sub) => evaluateSchema(sub, value, root)).length;
    if (matches !== 1) {
      return false;
    }
  }
  if ("not" in s && evaluateSchema(s["not"], value, root)) {
    return false;
  }
  if ("if" in s) {
    const branch = evaluateSchema(s["if"], value, root) ? "then" : "else";
    if (branch in s && !evaluateSchema(s[branch], value, root)) {
      return false;
    }
  }

  // --- numbers --------------------------------------------------------------
  if (typeof value === "number") {
    if (typeof s["minimum"] === "number" && value < s["minimum"]) return false;
    if (typeof s["maximum"] === "number" && value > s["maximum"]) return false;
    if (typeof s["exclusiveMinimum"] === "number" && value <= s["exclusiveMinimum"]) return false;
    if (typeof s["exclusiveMaximum"] === "number" && value >= s["exclusiveMaximum"]) return false;
    const multipleOf = s["multipleOf"];
    if (typeof multipleOf === "number" && multipleOf > 0) {
      const quotient = value / multipleOf;
      // Tolerance, not `%`: `0.3 % 0.1` is 0.09999999999999998 in IEEE-754, so
      // a literal remainder test rejects values every implementation accepts.
      if (Math.abs(quotient - Math.round(quotient)) > 1e-9) return false;
    }
  }

  // --- strings --------------------------------------------------------------
  if (typeof value === "string") {
    const length = codePointLength(value);
    if (typeof s["minLength"] === "number" && length < s["minLength"]) return false;
    if (typeof s["maxLength"] === "number" && length > s["maxLength"]) return false;
    const pattern = s["pattern"];
    if (typeof pattern === "string") {
      const compiled = regex(pattern);
      // An uncompilable pattern reached evaluation only if the schema bypassed
      // `isValidSchema`; fail closed rather than admit.
      if (compiled === undefined || !compiled.test(value)) return false;
    }
  }

  // --- objects --------------------------------------------------------------
  if (isPlainObject(value)) {
    const obj = value;
    const keys = Object.keys(obj);

    if (typeof s["minProperties"] === "number" && keys.length < s["minProperties"]) return false;
    if (typeof s["maxProperties"] === "number" && keys.length > s["maxProperties"]) return false;

    const required = s["required"];
    if (Array.isArray(required) && !required.every((k) => typeof k === "string" && k in obj)) {
      return false;
    }

    const dependentRequired = s["dependentRequired"];
    if (isPlainObject(dependentRequired)) {
      for (const [trigger, needed] of Object.entries(dependentRequired)) {
        if (trigger in obj && Array.isArray(needed)) {
          if (!needed.every((k) => typeof k === "string" && k in obj)) return false;
        }
      }
    }

    const dependentSchemas = s["dependentSchemas"];
    if (isPlainObject(dependentSchemas)) {
      for (const [trigger, sub] of Object.entries(dependentSchemas)) {
        if (trigger in obj && !evaluateSchema(sub, obj, root)) return false;
      }
    }

    const propertyNames = s["propertyNames"];
    if (propertyNames !== undefined) {
      if (!keys.every((k) => evaluateSchema(propertyNames, k, root))) return false;
    }

    const properties = isPlainObject(s["properties"]) ? s["properties"] : undefined;
    if (properties !== undefined) {
      for (const [key, sub] of Object.entries(properties)) {
        if (key in obj && !evaluateSchema(sub, obj[key], root)) return false;
      }
    }

    const patternProperties = isPlainObject(s["patternProperties"])
      ? s["patternProperties"]
      : undefined;
    const patternMatched = new Set<string>();
    if (patternProperties !== undefined) {
      for (const [rawPattern, sub] of Object.entries(patternProperties)) {
        const compiled = regex(rawPattern);
        if (compiled === undefined) return false;
        for (const key of keys) {
          if (compiled.test(key)) {
            patternMatched.add(key);
            if (!evaluateSchema(sub, obj[key], root)) return false;
          }
        }
      }
    }

    // `additionalProperties` applies to keys matched by NEITHER `properties`
    // NOR `patternProperties` — a key covered by a pattern is not "additional".
    if ("additionalProperties" in s) {
      const additional = s["additionalProperties"];
      const declared = new Set(properties === undefined ? [] : Object.keys(properties));
      for (const key of keys) {
        if (declared.has(key) || patternMatched.has(key)) continue;
        if (additional === false) return false;
        if (!evaluateSchema(additional, obj[key], root)) return false;
      }
    }
  }

  // --- arrays ---------------------------------------------------------------
  if (Array.isArray(value)) {
    if (typeof s["minItems"] === "number" && value.length < s["minItems"]) return false;
    if (typeof s["maxItems"] === "number" && value.length > s["maxItems"]) return false;

    if (s["uniqueItems"] === true) {
      for (let i = 0; i < value.length; i += 1) {
        for (let j = i + 1; j < value.length; j += 1) {
          if (deepEqual(value[i], value[j])) return false;
        }
      }
    }

    const prefixItems = s["prefixItems"];
    let prefixLength = 0;
    if (Array.isArray(prefixItems)) {
      prefixLength = Math.min(prefixItems.length, value.length);
      for (let i = 0; i < prefixLength; i += 1) {
        if (!evaluateSchema(prefixItems[i], value[i], root)) return false;
      }
    }

    if ("items" in s) {
      const items = s["items"];
      // Draft 2020-12: `items` applies to the elements AFTER `prefixItems`. A
      // Draft-7-style tuple `items: [...]` is honoured as a prefix so an older
      // operator schema is not silently unconstrained.
      if (Array.isArray(items)) {
        for (let i = 0; i < Math.min(items.length, value.length); i += 1) {
          if (!evaluateSchema(items[i], value[i], root)) return false;
        }
      } else {
        for (let i = prefixLength; i < value.length; i += 1) {
          if (!evaluateSchema(items, value[i], root)) return false;
        }
      }
    }

    if ("contains" in s) {
      const count = value.filter((item) => evaluateSchema(s["contains"], item, root)).length;
      const minContains = typeof s["minContains"] === "number" ? s["minContains"] : 1;
      if (count < minContains) return false;
      if (typeof s["maxContains"] === "number" && count > s["maxContains"]) return false;
    }
  }

  return true;
}

function matchesType(type: string, value: unknown): boolean {
  switch (type) {
    case "null":
      return value === null;
    case "boolean":
      return typeof value === "boolean";
    case "object":
      return isPlainObject(value);
    case "array":
      return Array.isArray(value);
    case "number":
      return typeof value === "number";
    case "integer":
      // Draft 2020-12: `1.0` IS an integer — "a number with a zero fractional
      // part", not "a value spelled without a decimal point".
      return typeof value === "number" && Number.isInteger(value);
    case "string":
      return typeof value === "string";
    default:
      return false;
  }
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) {
    return true;
  }
  if (typeof a !== typeof b || a === null || b === null) {
    return false;
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((item, i) => deepEqual(item, b[i]));
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    return false;
  }
  if (typeof a === "object" && typeof b === "object") {
    const ak = Object.keys(a as object);
    const bk = Object.keys(b as object);
    return (
      ak.length === bk.length &&
      ak.every(
        (k) =>
          k in (b as object) &&
          deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]),
      )
    );
  }
  return false;
}
