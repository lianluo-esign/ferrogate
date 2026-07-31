/**
 * A `serde_json::Value` twin plus the typed accessors the Rust adapters use.
 *
 * The Rust crate treats every provider request/response `body` as an opaque
 * `serde_json::Value` and reads fields with `Value::get` / `Value::as_str` /
 * `Value::as_u64` / `Value::as_array` / `Value::as_object`. These helpers
 * reproduce those accessors with the same fail-soft semantics (a wrong-typed or
 * absent field yields `undefined`, never a throw).
 */

/** JSON value model, the twin of `serde_json::Value`. */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type JsonObject = { [key: string]: Json };

export const isObject = (value: Json | undefined): value is JsonObject =>
  typeof value === "object" && value !== null && !Array.isArray(value);

export const isArray = (value: Json | undefined): value is Json[] => Array.isArray(value);

/** `Value::get(key)` — `undefined` unless `value` is an object holding `key`. */
export const getField = (value: Json | undefined, key: string): Json | undefined =>
  isObject(value) ? value[key] : undefined;

/** `Value::as_str`. */
export const asStr = (value: Json | undefined): string | undefined =>
  typeof value === "string" ? value : undefined;

/** `Value::as_array`. */
export const asArray = (value: Json | undefined): Json[] | undefined =>
  isArray(value) ? value : undefined;

/** `Value::as_object`. */
export const asObject = (value: Json | undefined): JsonObject | undefined =>
  isObject(value) ? value : undefined;

/** `Value::as_u64` — a non-negative integer number only. */
export const asU64 = (value: Json | undefined): number | undefined =>
  typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : undefined;

/** `Value::as_i64` — any integer number. */
export const asI64 = (value: Json | undefined): number | undefined =>
  typeof value === "number" && Number.isInteger(value) ? value : undefined;

/** `serde_json::to_string(value)` — compact JSON, matching Rust's `Value::to_string`. */
export const jsonToString = (value: Json): string => JSON.stringify(value);

/**
 * `serde_json::from_slice::<Value>` — parse bytes/string to `Json`, or
 * `undefined` on any decode failure (`.ok()` in Rust).
 */
export function parseJson(body: string | Uint8Array): Json | undefined {
  const text = typeof body === "string" ? body : new TextDecoder().decode(body);
  try {
    return JSON.parse(text) as Json;
  } catch {
    return undefined;
  }
}

/**
 * `value.as_str().and_then(from_str).unwrap_or_else(|| value.clone())` — if the
 * value is a JSON-encoded string, its parse; otherwise the value unchanged.
 */
export function parseJsonStringOrClone(value: Json): Json {
  if (typeof value === "string") {
    const parsed = parseJson(value);
    if (parsed !== undefined) return parsed;
  }
  return value;
}
