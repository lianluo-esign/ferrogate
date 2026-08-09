/**
 * Schema helpers shared across the `Config` schema tree.
 */
import type { z } from "zod";

/**
 * Default an object field to its own fully-defaulted value on omission.
 *
 * Zod's `.default({})` returns the literal `{}` WITHOUT applying the object's
 * inner field defaults, which would diverge from Rust's `#[serde(default)]`
 * (that calls `Struct::default()`, populating every field). This defaults an
 * omitted field to `schema.parse({})` instead, so every nested default matches
 * the Rust `Default` impl.
 */
export function sectionDefault<T extends z.ZodType<Record<string, unknown>>>(
  schema: T,
): z.ZodDefault<T> {
  return schema.default(() => schema.parse({}) as z.input<T>);
}
