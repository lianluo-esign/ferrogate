/**
 * JSON value model — the TS twin of Rust `serde_json::Value`.
 *
 * The Rust `ferrogate-core` crate types `ToolDef.input_schema`,
 * `ToolCall.arguments`, and `ToolResult.content` as arbitrary `serde_json::Value`.
 * Those are exactly "any valid JSON", so we model them with a recursive Zod
 * schema instead of `z.unknown()` — it keeps the required-ness (the fields are
 * NOT `Option`, so the key must be present) while still accepting `null`,
 * scalars, arrays, and nested objects.
 */
import { z } from "zod";

/** Any valid JSON value (mirrors `serde_json::Value`). */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

/** Recursive Zod schema accepting any valid JSON value. */
export const jsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.null(),
    z.boolean(),
    z.number(),
    z.string(),
    z.array(jsonValueSchema),
    z.record(z.string(), jsonValueSchema),
  ]),
);
