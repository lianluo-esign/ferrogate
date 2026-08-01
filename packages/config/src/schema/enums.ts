/**
 * Enum vocabularies used across the `Config` schema. The snake_case values
 * mirror the Rust `#[serde(rename_all = "snake_case")]` wire form exactly.
 *
 * The enums OWNED by a sibling package are now IMPORTED from it rather than
 * re-typed here, so the vocabularies cannot drift apart:
 *   - `ModelCapability`/`RoutingStrategy` → `@ferrogate/providers`
 *   - `StorageProviderKind`/`PostgresTlsMode` → `@ferrogate/storage`
 *   - `ContentSource` → `@ferrogate/guardrails`
 *
 * That relocation was not cosmetic: the previously-inlined `ContentSource` copy
 * had already lost the `unknown` variant, which silently narrowed the DEFAULT
 * `guardrails[].sources` set so an unclassified content segment would not be
 * scanned. Copies of a vocabulary drift; imports do not.
 *
 * PORT-TODO(P: inventory §5.3) — PACKAGE RELOCATION, NOT CLOSABLE YET (one leg).
 * `McpTransport`/`McpAuthType` are owned by `ferrogate-mcp`, and there is no
 * `@ferrogate/mcp` PACKAGE to import them from — the MCP port lives in the
 * `apps/mcp` Worker, and a `packages/*` library must not depend on an app (that
 * edge points the wrong way and would drag a Worker entry point into every
 * consumer of the config schema). They stay inlined here, read verbatim from
 * `crates/ferrogate-mcp`, until an `@ferrogate/mcp` library exists; pinned by
 * `test/sibling-enum-parity.test.ts`.
 */
import { z } from "zod";
import { contentSourceSchema as guardrailsContentSourceSchema } from "@ferrogate/guardrails";
import { ALL_CONTENT_SOURCES as GUARDRAILS_ALL_CONTENT_SOURCES } from "@ferrogate/guardrails";
import {
  modelCapabilitySchema as providersModelCapabilitySchema,
  routingStrategySchema as providersRoutingStrategySchema,
} from "@ferrogate/providers";
import {
  DEFAULT_DURABLE_PROVIDER_ORDER as STORAGE_DEFAULT_DURABLE_PROVIDER_ORDER,
  type PostgresTlsMode as StoragePostgresTlsMode,
  type StorageProviderKind as StorageStorageProviderKind,
} from "@ferrogate/storage/provider";

// --- @ferrogate/providers ---------------------------------------------------
// The enum is the owner's; only the Rust `#[serde(default)]` lives here, since
// the default is a property of the `Config` field, not of the vocabulary.
export const routingStrategySchema = providersRoutingStrategySchema.default("priority");
export type RoutingStrategy = z.infer<typeof routingStrategySchema>;

export const modelCapabilitySchema = providersModelCapabilitySchema;
export type ModelCapability = z.infer<typeof modelCapabilitySchema>;

// --- @ferrogate/storage -----------------------------------------------------
// `@ferrogate/storage` models these as TS unions (no Zod), so the schema is
// built here from a tuple that the compiler proves is EXACTLY the owner's
// union: adding or removing a variant over there fails this build instead of
// silently letting the config vocabulary drift.
type Exhaustive<Owner extends string, Local extends string> = [
  Exclude<Owner, Local>,
  Exclude<Local, Owner>,
] extends [never, never]
  ? true
  : never;

const STORAGE_PROVIDER_KINDS = [
  "memory",
  "supabase",
  "turso_libsql",
  "postgres",
  "mysql",
  "cloudflare_d1",
] as const;
const _storageKindsExhaustive: Exhaustive<
  StorageStorageProviderKind,
  (typeof STORAGE_PROVIDER_KINDS)[number]
> = true;
void _storageKindsExhaustive;
export const storageProviderKindSchema = z.enum(STORAGE_PROVIDER_KINDS);
export type StorageProviderKind = z.infer<typeof storageProviderKindSchema>;

/** `ferrogate_storage::DEFAULT_DURABLE_PROVIDER_ORDER`, owned by `@ferrogate/storage`. */
export const DEFAULT_DURABLE_PROVIDER_ORDER: StorageProviderKind[] = [
  ...STORAGE_DEFAULT_DURABLE_PROVIDER_ORDER,
];

const POSTGRES_TLS_MODES = ["disable", "prefer", "require", "verify_ca", "verify_full"] as const;
const _postgresTlsModesExhaustive: Exhaustive<
  StoragePostgresTlsMode,
  (typeof POSTGRES_TLS_MODES)[number]
> = true;
void _postgresTlsModesExhaustive;
export const postgresTlsModeSchema = z.enum(POSTGRES_TLS_MODES).default("disable");
export type PostgresTlsMode = z.infer<typeof postgresTlsModeSchema>;

// --- @ferrogate/guardrails --------------------------------------------------
export const contentSourceSchema = guardrailsContentSourceSchema;
export type ContentSource = z.infer<typeof contentSourceSchema>;

/** `ferrogate_guardrails::all_content_sources()` — every variant, owner-defined. */
export const ALL_CONTENT_SOURCES: ContentSource[] = [...GUARDRAILS_ALL_CONTENT_SOURCES];

// --- ferrogate-mcp (no `@ferrogate/mcp` package to import from — see header) -
export const mcpTransportSchema = z.enum(["streamable_http", "sse", "stdio"]);
export type McpTransport = z.infer<typeof mcpTransportSchema>;

/**
 * `McpAuthType`. Rust carries `#[serde(alias = "headers")]` on `SharedHeaders`,
 * so a legacy `auth_type = "headers"` deserializes to `shared_headers` — the
 * preprocess reproduces that alias.
 */
export const mcpAuthTypeSchema = z
  .preprocess(
    (value) => (value === "headers" ? "shared_headers" : value),
    z.enum([
      "none",
      "shared_headers",
      "oauth",
      "per_user_oauth",
      "per_user_headers",
      "original_bearer",
      "ferrogate_signed_jwt",
    ]),
  )
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
