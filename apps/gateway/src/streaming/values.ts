/**
 * Tiny structural accessors over parsed provider JSON.
 *
 * Provider stream payloads are `serde_json::Value` in the Rust tree — the
 * gateway never deserializes them into typed structs, it reaches into them with
 * `.get(..).and_then(Value::as_str)` chains (see `messages_stream.rs` /
 * `responses_stream.rs`). These helpers are the TypeScript twins of those
 * combinators: every one returns `undefined` rather than throwing, so a
 * malformed or unexpected upstream frame degrades exactly as the Rust code did
 * (silently skipped) instead of tearing down a live stream.
 */

/** A JSON object with unvalidated members. */
export type JsonRecord = Record<string, unknown>;

/** Rust `Value::as_object` — arrays and `null` are not objects. */
export function asRecord(value: unknown): JsonRecord | undefined {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    return value as JsonRecord;
  }
  return undefined;
}

/** Rust `Value::as_str`. */
export function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

/** Rust `Value::as_array`. */
export function asArray(value: unknown): unknown[] | undefined {
  return Array.isArray(value) ? value : undefined;
}

/**
 * Rust `Value::as_u64` — a non-negative integer. JSON floats and negatives are
 * rejected, matching `serde_json`, so a provider reporting `"prompt_tokens":
 * 1.5` is ignored rather than silently metered.
 */
export function asUint(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    return value;
  }
  return undefined;
}

/** `value.get(key)` on an object, `undefined` otherwise. */
export function get(value: unknown, key: string): unknown {
  return asRecord(value)?.[key];
}

/** Chained `get`, e.g. `getPath(frame, "message", "usage")`. */
export function getPath(value: unknown, ...keys: readonly string[]): unknown {
  let current = value;
  for (const key of keys) {
    current = get(current, key);
    if (current === undefined) {
      return undefined;
    }
  }
  return current;
}

/** `get` + `as_str`. */
export function getString(value: unknown, key: string): string | undefined {
  return asString(get(value, key));
}

/** `get` + `as_u64`. */
export function getUint(value: unknown, key: string): number | undefined {
  return asUint(get(value, key));
}

/** `get` + `as_array`. */
export function getArray(value: unknown, key: string): unknown[] | undefined {
  return asArray(get(value, key));
}

/** The first element of an array-valued member (Rust `.first()`). */
export function firstOf(value: unknown): unknown {
  const array = asArray(value);
  return array === undefined ? undefined : array[0];
}

/** Rust `.filter(|value| !value.is_null())` — treats a missing key as absent. */
export function nonNull(value: unknown): unknown {
  return value === null || value === undefined ? undefined : value;
}
