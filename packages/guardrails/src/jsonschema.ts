/**
 * JSON pointer (RFC 6901) resolution + a compact JSON Schema validity/validation
 * helper for the deterministic detector's `JsonConstraints`.
 *
 * The Rust crate uses the `jsonschema` crate for full Draft support. There is no
 * declared JSON-Schema dependency in this workspace and the port adds no build
 * step, so this implements the closest correct behavior: RFC 6901 pointers are
 * ported verbatim, and JSON Schema support covers the common keywords used by
 * operator constraints (type, required, properties, enum, const, min/max,
 * minLength/maxLength, items, additionalProperties).
 *
 * PORT-TODO(inventory §3.4a / §3.8): swap `evaluateSchema` for `ajv` or
 * `@cfworker/json-schema` (workerd-friendly) once a JSON-Schema dependency is
 * admitted, for full Draft 2020-12 fidelity. `required_keys`/`forbidden_keys`
 * (the pointer path) are already fully faithful.
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

/**
 * Best-effort JSON Schema validity gate (used at detector construction, where
 * Rust calls `jsonschema::validator_for`). Rejects a schema that is not an
 * object/boolean or whose `type` is not a known JSON type.
 */
export function isValidSchema(schema: unknown): boolean {
  if (typeof schema === "boolean") {
    return true;
  }
  if (schema === null || typeof schema !== "object" || Array.isArray(schema)) {
    return false;
  }
  const type = (schema as Record<string, unknown>)["type"];
  if (type !== undefined) {
    const known = ["null", "boolean", "object", "array", "number", "integer", "string"];
    const types = Array.isArray(type) ? type : [type];
    if (!types.every((t) => typeof t === "string" && known.includes(t))) {
      return false;
    }
  }
  return true;
}

/**
 * Validate `value` against `schema` (subset). Returns `true` when valid. See the
 * module PORT-TODO for the fidelity boundary.
 */
export function evaluateSchema(schema: unknown, value: unknown): boolean {
  if (typeof schema === "boolean") {
    return schema;
  }
  if (schema === null || typeof schema !== "object" || Array.isArray(schema)) {
    return true;
  }
  const s = schema as Record<string, unknown>;

  const type = s["type"];
  if (type !== undefined) {
    const types = Array.isArray(type) ? type : [type];
    if (!types.some((t) => typeof t === "string" && matchesType(t, value))) {
      return false;
    }
  }

  if (Array.isArray(s["enum"]) && !s["enum"].some((candidate) => deepEqual(candidate, value))) {
    return false;
  }
  if ("const" in s && !deepEqual(s["const"], value)) {
    return false;
  }

  if (typeof value === "number") {
    if (typeof s["minimum"] === "number" && value < s["minimum"]) {
      return false;
    }
    if (typeof s["maximum"] === "number" && value > s["maximum"]) {
      return false;
    }
  }
  if (typeof value === "string") {
    if (typeof s["minLength"] === "number" && value.length < s["minLength"]) {
      return false;
    }
    if (typeof s["maxLength"] === "number" && value.length > s["maxLength"]) {
      return false;
    }
  }

  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>;
    const required = s["required"];
    if (Array.isArray(required) && !required.every((k) => typeof k === "string" && k in obj)) {
      return false;
    }
    const properties = s["properties"];
    if (properties !== null && typeof properties === "object" && !Array.isArray(properties)) {
      for (const [key, sub] of Object.entries(properties as Record<string, unknown>)) {
        if (key in obj && !evaluateSchema(sub, obj[key])) {
          return false;
        }
      }
    }
    if (s["additionalProperties"] === false) {
      const known = new Set(
        properties !== null && typeof properties === "object"
          ? Object.keys(properties as Record<string, unknown>)
          : [],
      );
      if (Object.keys(obj).some((k) => !known.has(k))) {
        return false;
      }
    }
  }

  if (Array.isArray(value) && s["items"] !== undefined && !Array.isArray(s["items"])) {
    if (!value.every((item) => evaluateSchema(s["items"], item))) {
      return false;
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
      return value !== null && typeof value === "object" && !Array.isArray(value);
    case "array":
      return Array.isArray(value);
    case "number":
      return typeof value === "number";
    case "integer":
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
  if (typeof a === "object" && typeof b === "object") {
    const ak = Object.keys(a as object);
    const bk = Object.keys(b as object);
    return (
      ak.length === bk.length &&
      ak.every((k) =>
        deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]),
      )
    );
  }
  return false;
}
