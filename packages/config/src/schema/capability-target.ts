/**
 * `ferrogate_runtime::target_capability` — the canonical target-level capability
 * selectors an `agent_runtime.managed_worker.target_grants` entry carries.
 *
 * These types are OWNED by `@ferrogate/runtime` (wave 2). They are inlined here,
 * read verbatim from `crates/ferrogate-runtime/src/target_capability.rs`, for the
 * same reason `schema/enums.ts` inlines its sibling-owned enums: `Config::validate()`
 * runs `selector.supports_action(action)` and `selector.validate()` at LOAD time,
 * so `@ferrogate/config` cannot gate a config without the selector model. Re-export
 * from `@ferrogate/runtime` once that package lands.
 */
import { z } from "zod";

/** `ClassOnlyPolicyMode` (`#[default] Deny`). */
export const classOnlyPolicyModeSchema = z.enum(["deny", "legacy_class_wide"]).default("deny");
export type ClassOnlyPolicyMode = z.infer<typeof classOnlyPolicyModeSchema>;

/** `TargetOperation`. */
export const targetOperationSchema = z.enum(["read", "write", "delete", "execute"]);
export type TargetOperation = z.infer<typeof targetOperationSchema>;

/** `McpRisk`. */
export const mcpRiskSchema = z.enum(["read", "write"]);
export type McpRisk = z.infer<typeof mcpRiskSchema>;

/**
 * `JsonShape` — an internally-tagged (`#[serde(tag = "kind")]`) recursive enum.
 * `Object.fields` is a `BTreeMap<String, JsonShape>` with `#[serde(default)]`.
 */
export type JsonShape =
  | { kind: "null" }
  | { kind: "boolean" }
  | { kind: "number" }
  | { kind: "string" }
  | { kind: "array"; items: JsonShape }
  | { kind: "object"; fields: Record<string, JsonShape> };

export const jsonShapeSchema: z.ZodType<JsonShape> = z.lazy(() =>
  z.discriminatedUnion("kind", [
    z.object({ kind: z.literal("null") }),
    z.object({ kind: z.literal("boolean") }),
    z.object({ kind: z.literal("number") }),
    z.object({ kind: z.literal("string") }),
    z.object({ kind: z.literal("array"), items: jsonShapeSchema }),
    z.object({
      kind: z.literal("object"),
      fields: z.record(z.string(), jsonShapeSchema).default({}),
    }),
  ]),
) as z.ZodType<JsonShape>;

/**
 * `CapabilityTargetSelector` — internally tagged on `kind`. `#[serde(default)]`
 * fields carry their Rust defaults (`default_path_glob()` is `"/**"`).
 */
export const capabilityTargetSelectorSchema = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("mcp"),
    server: z.string(),
    tool: z.string(),
    risk: mcpRiskSchema,
    argument_schema: jsonShapeSchema,
    allow_extra_arguments: z.boolean().default(false),
  }),
  z.object({
    kind: z.literal("filesystem"),
    workspace_root: z.string(),
    path_glob: z.string(),
    operations: z.array(targetOperationSchema),
  }),
  z.object({
    kind: z.literal("network"),
    scheme: z.string(),
    host: z.string(),
    port: z.number().int().min(0).max(65_535),
    method: z.string().nullable().default(null),
    path_glob: z.string().default("/**"),
    allowed_ips: z.array(z.string()).default([]),
    allow_redirects: z.boolean().default(false),
  }),
  z.object({
    kind: z.literal("secret"),
    reference_namespace: z.string(),
    reference_name: z.string(),
    destination_adapter: z.string(),
    destination_action: z.string(),
  }),
  z.object({
    kind: z.literal("cli"),
    executable: z.string(),
    argv: z.array(z.string()),
    environment: z.record(z.string(), z.string()).default({}),
    cwd_glob: z.string(),
    max_timeout_millis: z.number().int(),
    max_stdout_bytes: z.number().int(),
    max_stderr_bytes: z.number().int(),
  }),
]);
export type CapabilityTargetSelector = z.infer<typeof capabilityTargetSelectorSchema>;
