/**
 * Shared D1 row plumbing: error wrapping and the SQLite affinity decoders.
 *
 * SQLite has no BOOLEAN and no NULL-vs-undefined distinction, so every read
 * path has to translate `0/1 → boolean` and `null → undefined` explicitly.
 * Doing it in one place keeps a decoder from drifting away from its writer —
 * the failure mode being a column that silently reads back as `undefined`
 * forever (which is exactly what bit the Rust Postgres backend when
 * `allowed_models_json` was added to the struct but not to the table).
 */
import { StorageError } from "../errors.js";

/**
 * Wrap any D1 driver failure as a `StorageError`, so callers switch on one
 * taxonomy. The message is passed through the DSN/secret scrubber by
 * `StorageError.runtime`'s siblings; D1 messages carry no DSN, but a bound
 * parameter can appear in a constraint violation, so the text is kept terse.
 */
export function d1Error(operation: string, error: unknown): StorageError {
  const detail = error instanceof Error ? error.message : String(error);
  return StorageError.runtime(`cloudflare d1: ${operation} failed: ${detail}`);
}

/** `0/1` (or a real boolean, which miniflare may hand back) → boolean. */
export function boolFromSqlite(value: unknown): boolean {
  return value === 1 || value === true || value === "1";
}

/** boolean → the `0/1` INTEGER the schema stores. */
export function boolToSqlite(value: boolean): number {
  return value ? 1 : 0;
}

/** `null` → `undefined`, so a nullable column matches the optional TS field. */
export function optionalNumber(value: unknown): number | undefined {
  return value === null || value === undefined ? undefined : Number(value);
}

/** `null` → `undefined` for a nullable TEXT column. */
export function optionalText(value: unknown): string | undefined {
  return value === null || value === undefined ? undefined : String(value);
}

/** `undefined` → `null`, the shape `.bind()` needs for a nullable column. */
export function bindOptional<T>(value: T | undefined): T | null {
  return value === undefined ? null : value;
}
