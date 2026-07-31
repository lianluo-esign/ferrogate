/**
 * Enum vocabularies used across the `Config` schema. The snake_case values
 * mirror the Rust `#[serde(rename_all = "snake_case")]` wire form exactly.
 *
 * PORT-TODO(inventory §5.3): several of these enums are OWNED by sibling crates
 * being ported in wave 2 (`ModelCapability`/`RoutingStrategy` →
 * `@ferrogate/providers`, `StorageProviderKind`/`PostgresTlsMode` →
 * `@ferrogate/storage`, `ContentSource` → `@ferrogate/guardrails`,
 * `McpTransport`/`McpAuthType` → `@ferrogate/mcp`). Their values are inlined
 * here (read verbatim from the crates) so `@ferrogate/config` type-checks
 * standalone; re-export from those packages once they land.
 */
import { z } from "zod";

// --- @ferrogate/providers ---------------------------------------------------
export const routingStrategySchema = z
  .enum(["priority", "lowest_cost", "lowest_latency", "balanced"])
  .default("priority");
export type RoutingStrategy = z.infer<typeof routingStrategySchema>;

export const modelCapabilitySchema = z.enum([
  "chat",
  "streaming",
  "vision",
  "images",
  "embeddings",
  "tools",
  "structured_output",
]);
export type ModelCapability = z.infer<typeof modelCapabilitySchema>;

// --- @ferrogate/storage -----------------------------------------------------
export const storageProviderKindSchema = z.enum([
  "memory",
  "supabase",
  "turso_libsql",
  "postgres",
  "mysql",
  "cloudflare_d1",
]);
export type StorageProviderKind = z.infer<typeof storageProviderKindSchema>;

/** Mirrors `ferrogate_storage::DEFAULT_DURABLE_PROVIDER_ORDER`. */
export const DEFAULT_DURABLE_PROVIDER_ORDER: StorageProviderKind[] = ["supabase", "postgres"];

export const postgresTlsModeSchema = z
  .enum(["disable", "prefer", "require", "verify_ca", "verify_full"])
  .default("disable");
export type PostgresTlsMode = z.infer<typeof postgresTlsModeSchema>;

// --- @ferrogate/guardrails --------------------------------------------------
export const contentSourceSchema = z.enum([
  "system",
  "developer",
  "user",
  "assistant",
  "tool_schema",
  "tool_arguments",
  "tool_result",
  "metadata",
  "text_attachment",
]);
export type ContentSource = z.infer<typeof contentSourceSchema>;

/** Mirrors `ferrogate_guardrails::all_content_sources()` (every variant). */
export const ALL_CONTENT_SOURCES: ContentSource[] = [
  "system",
  "developer",
  "user",
  "assistant",
  "tool_schema",
  "tool_arguments",
  "tool_result",
  "metadata",
  "text_attachment",
];

// --- @ferrogate/mcp ---------------------------------------------------------
export const mcpTransportSchema = z.enum(["streamable_http", "sse", "stdio"]);
export type McpTransport = z.infer<typeof mcpTransportSchema>;

export const mcpAuthTypeSchema = z
  .enum([
    "none",
    "shared_headers",
    "oauth",
    "per_user_oauth",
    "per_user_headers",
    "original_bearer",
    "ferrogate_signed_jwt",
  ])
  .default("none");
export type McpAuthType = z.infer<typeof mcpAuthTypeSchema>;

// --- config-owned enums (this crate) ---------------------------------------
export const assetBucketBackendSchema = z.enum(["s3", "workers-static-assets"]).default("s3");
export type AssetBucketBackend = z.infer<typeof assetBucketBackendSchema>;

export const storageMigrationModeSchema = z.enum(["auto", "validate_only", "disabled"]).default("auto");
export type StorageMigrationMode = z.infer<typeof storageMigrationModeSchema>;

export const cacheModeSchema = z.enum(["exact_match", "semantic"]).default("exact_match");
export type CacheMode = z.infer<typeof cacheModeSchema>;

export const accessLogModeSchema = z.enum(["off", "error", "sampled", "all"]).default("error");
export type AccessLogMode = z.infer<typeof accessLogModeSchema>;

export const guardrailStageSchema = z.enum(["request", "response"]).default("request");
export type GuardrailStage = z.infer<typeof guardrailStageSchema>;

export const guardrailEffectSchema = z.enum(["deny", "redact"]).default("deny");
export type GuardrailEffect = z.infer<typeof guardrailEffectSchema>;

export const guardrailProviderKindSchema = z
  .enum(["none", "custom_http", "presidio", "llm_guard_prompt_injection"])
  .default("none");
export type GuardrailProviderKind = z.infer<typeof guardrailProviderKindSchema>;

export const guardrailProviderErrorModeSchema = z
  .enum(["block", "record", "fallback_detector"])
  .default("block");
export type GuardrailProviderErrorMode = z.infer<typeof guardrailProviderErrorModeSchema>;

export const agentRuntimeProviderSchema = z.enum(["managed_worker", "external"]).default("managed_worker");
export type AgentRuntimeProvider = z.infer<typeof agentRuntimeProviderSchema>;

export const providerCloudflareAiGatewayModeSchema = z.enum(["compat", "unified"]).default("compat");
export type ProviderCloudflareAiGatewayMode = z.infer<typeof providerCloudflareAiGatewayModeSchema>;

export const observabilityProviderSchema = z.enum(["vector", "otlp", "cloudflare", "none"]).default("vector");
export type ObservabilityProvider = z.infer<typeof observabilityProviderSchema>;

export const analyticsProviderSchema = z.enum(["vector", "clickhouse", "none"]).default("vector");
export type AnalyticsProvider = z.infer<typeof analyticsProviderSchema>;

export const meteringExportProviderSchema = z.enum(["legacy", "openmeter"]).default("legacy");
export type MeteringExportProvider = z.infer<typeof meteringExportProviderSchema>;

/** Rust serializes these under aliased names (`api_key_id`, `organization_id`, ...). */
export const meteringExportSubjectSchema = z
  .enum(["api_key_id", "organization_id", "project_id", "user_id"])
  .default("api_key_id");
export type MeteringExportSubject = z.infer<typeof meteringExportSubjectSchema>;

export const agentWorkflowNodeKindSchema = z
  .enum(["model", "tool", "router", "human", "checkpoint"])
  .default("model");
export type AgentWorkflowNodeKind = z.infer<typeof agentWorkflowNodeKindSchema>;

export const promptTemplateStatusSchema = z.enum(["draft", "active", "archived"]).default("active");
export type PromptTemplateStatus = z.infer<typeof promptTemplateStatusSchema>;

export const promptTemplateTargetSchema = z.enum(["chat_completions", "responses"]).default("chat_completions");
export type PromptTemplateTarget = z.infer<typeof promptTemplateTargetSchema>;

export const promptTemplateVersionStatusSchema = z.enum(["draft", "active", "archived"]).default("active");
export type PromptTemplateVersionStatus = z.infer<typeof promptTemplateVersionStatusSchema>;

export const extensionKindSchema = z.enum(["request_hook", "tool_provider", "event_sink"]);
export type ExtensionKind = z.infer<typeof extensionKindSchema>;

export const skillPackageCapabilityKindSchema = z.enum([
  "plugin",
  "tool",
  "mcp_server",
  "mcp_tool",
  "prompt_template",
  "agent_workflow",
]);
export type SkillPackageCapabilityKind = z.infer<typeof skillPackageCapabilityKindSchema>;

export const agentUpstreamProtocolSchema = z.enum(["a2a"]).default("a2a");
export type AgentUpstreamProtocol = z.infer<typeof agentUpstreamProtocolSchema>;

export const agentUpstreamCapabilitySchema = z.enum(["invoke", "read", "stream", "discover"]);
export type AgentUpstreamCapability = z.infer<typeof agentUpstreamCapabilitySchema>;

export const managedWorkerCapabilityActionSchema = z.enum([
  "tool",
  "mcp_tool",
  "cli",
  "skill",
  "filesystem",
  "browser",
  "rest",
  "secret",
  "memory_read",
  "memory_write",
  "network_egress",
]);
export type ManagedWorkerCapabilityAction = z.infer<typeof managedWorkerCapabilityActionSchema>;
