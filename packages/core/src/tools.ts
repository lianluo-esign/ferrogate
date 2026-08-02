/**
 * Canonical tool primitives — port of `ferrogate-core`'s `ToolDef`, `ToolCall`,
 * and `ToolResult`, shared by every provider adapter.
 *
 * Wire keys are snake_case (`input_schema`, `tool_call_id`, `is_error`) to match
 * the serde representation. `input_schema` / `arguments` / `content` are
 * arbitrary `serde_json::Value` → {@link jsonValueSchema} (present but any JSON).
 * `ToolDef.description` carries `skip_serializing_if = Option::is_none` in Rust,
 * so it is omitted when absent — `.optional()` reproduces that on parse, and
 * `JSON.stringify` drops `undefined` on serialize.
 */
import { z } from "zod";

import { jsonValueSchema } from "./json.js";

/** Canonical tool definition shared by provider adapters. */
export const toolDefSchema = z.object({
  name: z.string(),
  description: z.string().optional(),
  input_schema: jsonValueSchema,
});
export type ToolDef = z.infer<typeof toolDefSchema>;

/** Canonical tool call emitted by a model response. */
export const toolCallSchema = z.object({
  id: z.string(),
  name: z.string(),
  arguments: jsonValueSchema,
});
export type ToolCall = z.infer<typeof toolCallSchema>;

/** Canonical tool result appended to a follow-up model request. */
export const toolResultSchema = z.object({
  tool_call_id: z.string(),
  content: jsonValueSchema,
  is_error: z.boolean(),
});
export type ToolResult = z.infer<typeof toolResultSchema>;
