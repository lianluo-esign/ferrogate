/**
 * Config section schemas — the `*Config` structs of `ferrogate-config`'s
 * `config/types.rs` (inventory §5.3). `#[serde(default)]` → `.default(...)`,
 * `Option<T>` → `.nullable().default(null)`, so an omitted section/field
 * deserializes to exactly the Rust default.
 */
import { z } from "zod";
import { approvalPolicySchema } from "@ferrogate/core";
import {
  accessLogModeSchema,
  agentRuntimeProviderSchema,
  analyticsProviderSchema,
  assetBucketBackendSchema,
  cacheModeSchema,
  managedWorkerCapabilityActionSchema,
  meteringExportProviderSchema,
  meteringExportSubjectSchema,
  observabilityProviderSchema,
  postgresTlsModeSchema,
  storageMigrationModeSchema,
  storageProviderKindSchema,
  DEFAULT_DURABLE_PROVIDER_ORDER,
} from "./enums.js";
import { capabilityTargetSelectorSchema, classOnlyPolicyModeSchema } from "./capability-target.js";
import { sectionDefault } from "./util.js";

const optString = z.string().nullable().default(null);
const optNumber = z.number().int().nullable().default(null);
const optBool = z.boolean().nullable().default(null);

/** Deployment-wide authentication posture (issue #542). Default: auth required. */
export const authConfigSchema = z
  .object({ disabled: z.boolean().default(false) })
  .strict();
export type AuthConfig = z.infer<typeof authConfigSchema>;

/** Deployment-wide tenant-identity semantics (issue #515). */
export const tenancyConfigSchema = z
  .object({
    implicit_platform_operator: z.boolean().default(false),
    require_registered_tenant: z.boolean().default(false),
  })
  .strict();
export type TenancyConfig = z.infer<typeof tenancyConfigSchema>;

export const schedulerConfigSchema = z.object({
  enabled: z.boolean().default(false),
  tick_interval_secs: z.number().int().default(5),
  max_catchup_fires: z.number().int().default(1),
  default_timezone: z.string().default("UTC"),
});
export type SchedulerConfig = z.infer<typeof schedulerConfigSchema>;

export const assetLifecycleConfigSchema = z.object({
  enabled: z.boolean().default(false),
  tick_interval_secs: z.number().int().default(3600),
  dry_run: z.boolean().default(true),
  default_keep_last_n: optNumber,
  default_max_age_secs: optNumber,
  retention_min_age_secs: z.number().int().default(86400),
  gc_enabled: z.boolean().default(false),
  gc_grace_secs: z.number().int().default(86400),
  max_gc_deletes_per_tick: z.number().int().default(100),
  default_request_log_max_age_secs: optNumber,
  default_audit_event_max_age_secs: optNumber,
  default_response_body_max_age_secs: optNumber,
  max_log_deletes_per_tick: z.number().int().default(5000),
});
export type AssetLifecycleConfig = z.infer<typeof assetLifecycleConfigSchema>;

export const x402SweeperConfigSchema = z.object({
  enabled: z.boolean().default(false),
  tick_interval_secs: z.number().int().default(30),
  max_expiries_per_tick: z.number().int().default(100),
  hold_ttl_grace_secs: z.number().int().default(0),
});
export type X402SweeperConfig = z.infer<typeof x402SweeperConfigSchema>;

export const x402ReconcilerConfigSchema = z.object({
  enabled: z.boolean().default(false),
  tick_interval_secs: z.number().int().default(30),
  max_reconciles_per_tick: z.number().int().default(100),
  reconcile_check_delay_secs: z.number().int().default(60),
  confirmation_deadline_secs: z.number().int().default(900),
  hold_ttl_secs: z.number().int().default(3600),
});
export type X402ReconcilerConfig = z.infer<typeof x402ReconcilerConfigSchema>;

export const assetBucketConfigSchema = z.object({
  enabled: z.boolean().default(false),
  backend: assetBucketBackendSchema,
  endpoint: optString,
  bucket: optString,
  region: optString,
  access_key_id: optString,
  secret_access_key_env: optString,
  presign_ttl_secs: optNumber,
  presign_max_object_bytes: optNumber,
  max_gateway_buffer_bytes: optNumber,
  max_total_gateway_buffer_bytes: optNumber,
  buffer_admission_wait_ms: optNumber,
  cf_account_id: optString,
  cf_api_token: optString,
  cf_script_name: optString,
});
export type AssetBucketConfig = z.infer<typeof assetBucketConfigSchema>;

/** `builds_s3_client()` = enabled && backend == s3 (issue #485). */
export function buildsS3Client(bucket: AssetBucketConfig): boolean {
  return bucket.enabled && bucket.backend === "s3";
}

export const networkAccessConfigSchema = z.object({
  ip_allowlist: z.array(z.string()).default([]),
  trust_forwarded_for: z.boolean().default(false),
  trusted_proxy_hops: optNumber,
  unauthenticated_rate_limit_per_minute: optNumber,
});
export type NetworkAccessConfig = z.infer<typeof networkAccessConfigSchema>;

export const adminConfigSchema = z.object({
  listen: optString,
  cors_allowed_origin: optString,
});
export type AdminConfig = z.infer<typeof adminConfigSchema>;

export const adminApiConfigSchema = z.object({
  listen: z.string().default("127.0.0.1:8095"),
  gateway_url: z.string().default("http://127.0.0.1:8080"),
  upstream_timeout_millis: z.number().int().default(30000),
  cors_allowed_origin: optString,
  tls_cert_path: optString,
  tls_key_path: optString,
});
export type AdminApiConfig = z.infer<typeof adminApiConfigSchema>;

export const authServiceConfigSchema = z.object({
  enabled: z.boolean().default(false),
  endpoint: z.string().default("http://127.0.0.1:8090"),
  timeout_millis: z.number().int().default(500),
  max_retries: z.number().int().default(0),
  retry_backoff_millis: z.number().int().default(50),
});
export type AuthServiceConfig = z.infer<typeof authServiceConfigSchema>;

export const billingServiceConfigSchema = z.object({
  enabled: z.boolean().default(false),
  endpoint: z.string().default("http://127.0.0.1:8092"),
  timeout_millis: z.number().int().default(1000),
  token: optString,
  token_env: optString,
});
export type BillingServiceConfig = z.infer<typeof billingServiceConfigSchema>;

export const clusterSnapshotKeySchema = z.object({
  key_id: z.string(),
  public_key: z.string(),
});
export type ClusterSnapshotKey = z.infer<typeof clusterSnapshotKeySchema>;

export const clusterConfigSchema = z.object({
  enabled: z.boolean().default(false),
  cluster_id: z.string().default("default"),
  node_id: z.string().default("auto"),
  node_region: optString,
  node_zone: optString,
  state_backend: z.string().default("local"),
  file_state_path: optString,
  counter_backend: z.string().default("local"),
  redis_url: optString,
  counter_timeout_millis: z.number().int().default(500),
  heartbeat_interval_secs: z.number().int().default(10),
  config_poll_interval_secs: z.number().int().default(5),
  snapshot_signing_key: optString,
  snapshot_signing_key_id: optString,
  snapshot_trusted_keys: z.array(clusterSnapshotKeySchema).default([]),
  snapshot_tenant_id: optString,
  snapshot_deployment_id: optString,
  snapshot_max_age_secs: z.number().int().default(3600),
});
export type ClusterConfig = z.infer<typeof clusterConfigSchema>;

export const managedWorkerCapabilityTargetGrantSchema = z.object({
  selector_id: z.string(),
  permission_key: z.string(),
  action: managedWorkerCapabilityActionSchema,
  selector: capabilityTargetSelectorSchema,
});

export const agentRuntimeExternalConfigSchema = z.object({
  command: z.string().default(""),
  args: z.array(z.string()).default([]),
  timeout_millis: optNumber,
});
export type AgentRuntimeExternalConfig = z.infer<typeof agentRuntimeExternalConfigSchema>;

export const agentRuntimeManagedWorkerConfigSchema = z.object({
  external_action_authorizer_http_listen: optString,
  external_action_authorizer_socket: optString,
  external_action_authorizer_max_requests: optNumber,
  allowed_actions: z.array(managedWorkerCapabilityActionSchema).default([]),
  approval_required_actions: z.array(managedWorkerCapabilityActionSchema).default([]),
  allow_direct_network_egress: z.boolean().default(false),
  target_grants: z.array(managedWorkerCapabilityTargetGrantSchema).default([]),
  class_only_policy_mode: classOnlyPolicyModeSchema,
  policy_revision: z.string().default("config-v1"),
});
export type AgentRuntimeManagedWorkerConfig = z.infer<typeof agentRuntimeManagedWorkerConfigSchema>;

export const agentRuntimeConfigSchema = z.object({
  enabled: z.boolean().default(false),
  provider: agentRuntimeProviderSchema,
  max_turns: z.number().int().default(4),
  timeout_millis: z.number().int().default(30000),
  external: sectionDefault(agentRuntimeExternalConfigSchema),
  managed_worker: sectionDefault(agentRuntimeManagedWorkerConfigSchema),
});
export type AgentRuntimeConfig = z.infer<typeof agentRuntimeConfigSchema>;

export const tlsAcmeConfigSchema = z.object({
  enabled: z.boolean().default(false),
  domains: z.array(z.string()).default([]),
  email: optString,
  directory_url: z.string().default("https://acme-v02.api.letsencrypt.org/directory"),
  challenge: z.string().default("dns-01"),
  http_challenge_listen: z.string().default("0.0.0.0:80"),
  storage_dir: z.string().default(".ferrogate/acme"),
  terms_agreed: z.boolean().default(false),
  dns_provider: optString,
  dns_config: z.record(z.string(), z.string()).default({}),
  dns_hook_set: optString,
  dns_hook_cleanup: optString,
  dns_propagation_delay_secs: z.number().int().default(30),
  renewal_window_secs: z.number().int().default(30 * 24 * 60 * 60),
  renewal_check_interval_secs: z.number().int().default(12 * 60 * 60),
  renewal_retry_interval_secs: z.number().int().default(30 * 60),
  auto_graceful_reload: z.boolean().default(true),
});
export type TlsAcmeConfig = z.infer<typeof tlsAcmeConfigSchema>;

/**
 * PORT-TODO(inventory §5.8) — PLATFORM LIMIT, NOT CLOSED. Deliberately
 * SCHEMA-ONLY: these two sections are decoded, and NOTHING validates them.
 *
 * Cloudflare terminates TLS at the edge BEFORE the Worker is invoked. There is
 * no listener socket to bind, no cert/private key for the runtime to load (the
 * Rust pre-flight is pingora's `load_certs_and_key_files`), no `:80` listener a
 * Worker can own for an ACME HTTP-01 challenge, no ACME storage directory (no
 * filesystem), and no DNS-01 hook process to exec. So `validate_tls`,
 * `validate_acme_tls`, `validate_acme_dns01_tls`, `validate_acme_http01_tls` and
 * `validate_manual_tls_files` were REMOVED rather than half-ported — see the
 * `src/validate.ts` header and the removal marker at their old call site.
 *
 * CLOSEST BEHAVIOR IMPLEMENTED: the SCHEMAS stay, with the Rust field names and
 * defaults, purely so a legacy TOML or Caddyfile that still carries `[tls]` /
 * `[tls.acme]` decodes and round-trips instead of failing to parse during
 * migration. The consequence is that a `[tls]` block Rust would REFUSE (e.g.
 * `enabled` with no `cert_path`) is ACCEPTED here — it is inert config, not a
 * promise.
 *
 * ...but it no longer passes in SILENCE, which was the real objection. The
 * `validateMcpTlsConfig` precedent in `validate/entities.ts` says an operator
 * must never be told a security-relevant setting is honored when nothing reads
 * it. Rejecting outright (that precedent's remedy) is not available here: it
 * would break the Caddyfile migration path, where `fromGatewayConfig` emits
 * `[tls]` from a `tls`/`tls_acme` directive and Rust accepts the same document.
 * So the load WARNS instead — `inertTlsWarnings` in `../validate/sections.ts`,
 * surfaced by `loadConfigFromObject`/`fromCaddyfileStr`, saying in words that
 * the section is inert and that Cloudflare owns the certificate. Pinned by
 * `platform-limits.test.ts` > "tls/acme", including through the loader so an
 * unmounted warning fails the suite.
 *
 * REVIEWER: warn-vs-reject is still the judgment call to second-guess; the
 * migration-path breakage is the whole reason it is a warning.
 */
export const tlsConfigSchema = z.object({
  enabled: z.boolean().default(false),
  cert_path: optString,
  key_path: optString,
  http2: z.boolean().default(false),
  acme: sectionDefault(tlsAcmeConfigSchema),
});
export type TlsConfig = z.infer<typeof tlsConfigSchema>;

/** `TlsConfig::is_enabled()`. */
export function tlsIsEnabled(tls: TlsConfig): boolean {
  return tls.enabled || tls.cert_path !== null || tls.key_path !== null || tls.acme.enabled;
}

export const telemetryConfigSchema = z.object({
  service_name: z.string().default("ferrogate"),
  log_bodies: z.boolean().default(false),
  access_log: accessLogModeSchema,
  access_log_sample_rate: z.number().int().default(100),
  access_log_error_rate_limit_per_sec: z.number().int().default(100),
  otlp_endpoint: optString,
});
export type TelemetryConfig = z.infer<typeof telemetryConfigSchema>;

export const billingAlertsConfigSchema = z.object({
  webhook_url: optString,
  webhook_timeout_secs: z.number().int().default(5),
  webhook_signing_secret: optString,
});
export type BillingAlertsConfig = z.infer<typeof billingAlertsConfigSchema>;

export const observabilityConfigSchema = z.object({
  enabled: z.boolean().default(false),
  provider: observabilityProviderSchema,
  otlp_endpoint: optString,
  cloudflare_collector_token_ref: optString,
  cloudflare_default_tenant: optString,
  prometheus_metrics_path: z.string().default("/metrics"),
  export_timeout_secs: z.number().int().default(3),
  observed_activity_running_ttl_secs: z.number().int().default(60),
});
export type ObservabilityConfig = z.infer<typeof observabilityConfigSchema>;

export const analyticsConfigSchema = z.object({
  enabled: z.boolean().default(false),
  provider: analyticsProviderSchema,
  required: z.boolean().default(false),
  vector_endpoint: optString,
  clickhouse_url: optString,
  clickhouse_url_env: optString,
  export_timeout_secs: z.number().int().default(3),
  batch_max_events: z.number().int().default(500),
  flush_interval_millis: z.number().int().default(1000),
  queue_capacity: z.number().int().default(10000),
  request_log_retention_records: z.number().int().default(10000),
  audit_event_retention_records: z.number().int().default(10000),
  guardrail_evaluation_retention_records: z.number().int().default(10000),
  billing_event_retention_records: z.number().int().default(10000),
});
export type AnalyticsConfig = z.infer<typeof analyticsConfigSchema>;

export const meteringConfigSchema = z.object({
  export_enabled: z.boolean().default(false),
  export_provider: meteringExportProviderSchema,
  export_endpoint: z.string().default("https://api.token4ai.cloud/v1/metering/events"),
  export_token_env: optString,
  export_token: optString,
  export_timeout_secs: z.number().int().default(3),
  export_event_type: z.string().default("ai.tokens"),
  export_source: z.string().default("ferrogate"),
  export_subject: meteringExportSubjectSchema,
});
export type MeteringConfig = z.infer<typeof meteringConfigSchema>;

export const cacheConfigSchema = z.object({
  enabled: z.boolean().default(false),
  mode: cacheModeSchema,
  ttl_secs: z.number().int().default(300),
  max_records: z.number().int().default(1000),
  semantic_similarity_threshold: z.number().default(0.92),
});
export type CacheConfig = z.infer<typeof cacheConfigSchema>;

export const storageConfigSchema = z.object({
  provider: storageProviderKindSchema.default("memory"),
  required: z.boolean().default(false),
  provider_order: z.array(storageProviderKindSchema).default(DEFAULT_DURABLE_PROVIDER_ORDER),
  libsql_url: optString,
  libsql_auth_token: optString,
  libsql_auth_token_env: optString,
  postgres_dsn: optString,
  postgres_dsn_env: optString,
  supabase_dsn_env: optString,
  postgres_pool_size: z.number().int().default(4),
  postgres_pool_acquire_timeout_millis: z.number().int().default(1000),
  postgres_tls_mode: postgresTlsModeSchema,
  postgres_tls_ca_cert_path: optString,
  postgres_connect_timeout_secs: z.number().int().default(5),
  postgres_statement_timeout_millis: z.number().int().default(30000),
  postgres_schema: optString,
  postgres_search_path: z.array(z.string()).default([]),
  d1_control_database_id: optString,
  d1_tenant_databases: z.record(z.string(), z.string()).default({}),
  migration_mode: storageMigrationModeSchema,
  admin_list_default_limit: z.number().int().default(100),
  admin_list_max_limit: z.number().int().default(1000),
});
export type StorageConfig = z.infer<typeof storageConfigSchema>;

export const reliabilityConfigSchema = z.object({
  provider_circuit_breaker_failure_threshold: optNumber,
  provider_circuit_breaker_cooldown_secs: optNumber,
  provider_dispatch_timeout_secs: optNumber,
  provider_dispatch_max_retries: optNumber,
  provider_response_body_max_bytes: optNumber,
  tool_approval_timeout_secs: z.number().int().default(30),
  mcp_dispatch_timeout_secs: z.number().int().default(30),
  mcp_dispatch_max_concurrency: z.number().int().default(32),
  graceful_shutdown_grace_period_secs: optNumber,
  graceful_shutdown_timeout_secs: optNumber,
  graceful_upgrade_pid_file: optString,
  graceful_upgrade_sock: optString,
  graceful_upgrade_sock_retries: optNumber,
});
export type ReliabilityConfig = z.infer<typeof reliabilityConfigSchema>;

// #312: centralized request-body size caps. Defaults = the pre-centralization literals.
export const DEFAULT_INFERENCE_BODY_MAX_BYTES = 1024 * 1024;
export const DEFAULT_ADMIN_BODY_MAX_BYTES = 64 * 1024;
export const DEFAULT_ADMIN_SMALL_BODY_MAX_BYTES = 16 * 1024;
export const DEFAULT_ADMIN_CONFIG_BODY_MAX_BYTES = 256 * 1024;
export const DEFAULT_TOOL_BODY_MAX_BYTES = 64 * 1024;
export const DEFAULT_ASSET_CONTROL_BODY_MAX_BYTES = 64 * 1024;
export const DEFAULT_AGENT_INGRESS_BODY_MAX_BYTES = 128 * 1024;
export const DEFAULT_WORKER_TRANSPORT_BODY_MAX_BYTES = 1024 * 1024;
export const DEFAULT_GUARDRAIL_POLICY_BODY_MAX_BYTES = 1024 * 1024;

export const limitsConfigSchema = z.object({
  inference_body_max_bytes: optNumber,
  admin_body_max_bytes: optNumber,
  admin_small_body_max_bytes: optNumber,
  admin_config_body_max_bytes: optNumber,
  tool_body_max_bytes: optNumber,
  asset_control_body_max_bytes: optNumber,
  agent_ingress_body_max_bytes: optNumber,
  worker_transport_body_max_bytes: optNumber,
  guardrail_policy_body_max_bytes: optNumber,
});
export type LimitsConfig = z.infer<typeof limitsConfigSchema>;

/** The `LimitsConfig::*_body_max_bytes()` accessors, applying the defaults. */
export const limits = {
  inference: (c: LimitsConfig) => c.inference_body_max_bytes ?? DEFAULT_INFERENCE_BODY_MAX_BYTES,
  admin: (c: LimitsConfig) => c.admin_body_max_bytes ?? DEFAULT_ADMIN_BODY_MAX_BYTES,
  adminSmall: (c: LimitsConfig) => c.admin_small_body_max_bytes ?? DEFAULT_ADMIN_SMALL_BODY_MAX_BYTES,
  adminConfig: (c: LimitsConfig) => c.admin_config_body_max_bytes ?? DEFAULT_ADMIN_CONFIG_BODY_MAX_BYTES,
  tool: (c: LimitsConfig) => c.tool_body_max_bytes ?? DEFAULT_TOOL_BODY_MAX_BYTES,
  assetControl: (c: LimitsConfig) => c.asset_control_body_max_bytes ?? DEFAULT_ASSET_CONTROL_BODY_MAX_BYTES,
  agentIngress: (c: LimitsConfig) => c.agent_ingress_body_max_bytes ?? DEFAULT_AGENT_INGRESS_BODY_MAX_BYTES,
  workerTransport: (c: LimitsConfig) =>
    c.worker_transport_body_max_bytes ?? DEFAULT_WORKER_TRANSPORT_BODY_MAX_BYTES,
  guardrailPolicy: (c: LimitsConfig) =>
    c.guardrail_policy_body_max_bytes ?? DEFAULT_GUARDRAIL_POLICY_BODY_MAX_BYTES,
};

// Re-export approval policy schema surface used by extensions.
export { approvalPolicySchema };
