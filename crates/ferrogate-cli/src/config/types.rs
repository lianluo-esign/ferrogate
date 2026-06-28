// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(crate) use ferrogate_core::ApprovalPolicy;
pub(crate) use ferrogate_mcp::{
    McpAuthType, McpHeaderConfig, McpServerConfig, McpTlsConfig, McpTransport,
};
use ferrogate_providers::RoutingStrategy;
use ferrogate_storage::{MySqlTlsMode, PostgresTlsMode, StorageProviderKind};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Config {
    #[serde(default = "default_listen")]
    pub(crate) listen: String,
    #[serde(default)]
    pub(crate) admin: AdminConfig,
    #[serde(default)]
    pub(crate) tls: TlsConfig,
    #[serde(default)]
    pub(crate) auth_service: AuthServiceConfig,
    #[serde(default)]
    pub(crate) providers: Vec<Provider>,
    #[serde(default)]
    pub(crate) models: Vec<Model>,
    #[serde(default)]
    pub(crate) api_keys: Vec<ApiKey>,
    #[serde(default)]
    pub(crate) policies: Vec<PolicyRule>,
    #[serde(default)]
    pub(crate) gateway_configs: Vec<GatewayConfigProfile>,
    #[serde(default)]
    pub(crate) agent_workflows: Vec<AgentWorkflowPolicy>,
    #[serde(default)]
    pub(crate) skill_packages: Vec<SkillPackage>,
    #[serde(default)]
    pub(crate) prompt_templates: Vec<PromptTemplate>,
    #[serde(default)]
    pub(crate) guardrails: Vec<GuardrailRule>,
    #[serde(default)]
    pub(crate) plugins: Vec<PluginConfig>,
    #[serde(default)]
    pub(crate) extensions: Vec<ExtensionConfig>,
    #[serde(default)]
    pub(crate) mcp_servers: Vec<McpServerConfig>,
    #[serde(default)]
    pub(crate) agent_upstreams: Vec<AgentUpstreamConfig>,
    #[serde(default)]
    pub(crate) telemetry: TelemetryConfig,
    #[serde(default)]
    pub(crate) observability: ObservabilityConfig,
    #[serde(default)]
    pub(crate) analytics: AnalyticsConfig,
    #[serde(default)]
    pub(crate) metering: MeteringConfig,
    #[serde(default)]
    pub(crate) cache: CacheConfig,
    #[serde(default)]
    pub(crate) storage: StorageConfig,
    #[serde(default)]
    pub(crate) reliability: ReliabilityConfig,
    #[serde(default)]
    pub(crate) agent_runtime: AgentRuntimeConfig,
    #[serde(default)]
    pub(crate) cluster: ClusterConfig,
    #[serde(default)]
    pub(crate) upstreams: Vec<Upstream>,
    #[serde(default)]
    pub(crate) routes: Vec<RouteRule>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct AdminConfig {
    #[serde(default)]
    pub(crate) listen: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct AuthServiceConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default = "default_auth_service_endpoint")]
    pub(crate) endpoint: String,
    #[serde(default = "default_auth_service_timeout_millis")]
    pub(crate) timeout_millis: u64,
    #[serde(default)]
    pub(crate) max_retries: u32,
    #[serde(default = "default_auth_service_retry_backoff_millis")]
    pub(crate) retry_backoff_millis: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct ClusterConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default = "default_cluster_id")]
    pub(crate) cluster_id: String,
    #[serde(default = "default_cluster_node_id")]
    pub(crate) node_id: String,
    #[serde(default)]
    pub(crate) node_region: Option<String>,
    #[serde(default)]
    pub(crate) node_zone: Option<String>,
    #[serde(default = "default_cluster_state_backend")]
    pub(crate) state_backend: String,
    #[serde(default)]
    pub(crate) file_state_path: Option<String>,
    #[serde(default = "default_cluster_counter_backend")]
    pub(crate) counter_backend: String,
    #[serde(default)]
    pub(crate) redis_url: Option<String>,
    #[serde(default = "default_cluster_counter_timeout_millis")]
    pub(crate) counter_timeout_millis: u64,
    #[serde(default = "default_cluster_heartbeat_interval_secs")]
    pub(crate) heartbeat_interval_secs: u64,
    #[serde(default = "default_cluster_config_poll_interval_secs")]
    pub(crate) config_poll_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct AgentRuntimeConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) provider: AgentRuntimeProvider,
    #[serde(default = "default_agent_runtime_max_turns")]
    pub(crate) max_turns: u32,
    #[serde(default = "default_agent_runtime_timeout_millis")]
    pub(crate) timeout_millis: u64,
    #[serde(default)]
    pub(crate) external: AgentRuntimeExternalConfig,
    #[serde(default)]
    pub(crate) managed_worker: AgentRuntimeManagedWorkerConfig,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgentRuntimeProvider {
    #[default]
    ManagedWorker,
    External,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct AgentRuntimeExternalConfig {
    #[serde(default)]
    pub(crate) command: String,
    #[serde(default)]
    pub(crate) args: Vec<String>,
    #[serde(default)]
    pub(crate) timeout_millis: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct AgentRuntimeManagedWorkerConfig {
    #[serde(default)]
    pub(crate) external_action_authorizer_socket: Option<String>,
    #[serde(default)]
    pub(crate) external_action_authorizer_max_requests: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct TlsConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) cert_path: Option<String>,
    #[serde(default)]
    pub(crate) key_path: Option<String>,
    #[serde(default)]
    pub(crate) http2: bool,
    #[serde(default)]
    pub(crate) acme: TlsAcmeConfig,
}

impl TlsConfig {
    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled || self.cert_path.is_some() || self.key_path.is_some() || self.acme.enabled
    }

    pub(crate) fn manual_cert_and_key(&self) -> Option<(&str, &str)> {
        Some((self.cert_path.as_deref()?, self.key_path.as_deref()?))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct TlsAcmeConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) domains: Vec<String>,
    #[serde(default)]
    pub(crate) email: Option<String>,
    #[serde(default = "default_acme_directory_url")]
    pub(crate) directory_url: String,
    #[serde(default = "default_acme_challenge")]
    pub(crate) challenge: String,
    #[serde(default = "default_http_challenge_listen")]
    pub(crate) http_challenge_listen: String,
    #[serde(default = "default_acme_storage_dir")]
    pub(crate) storage_dir: String,
    #[serde(default)]
    pub(crate) terms_agreed: bool,
    #[serde(default)]
    pub(crate) dns_provider: Option<String>,
    #[serde(default)]
    pub(crate) dns_config: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) dns_hook_set: Option<String>,
    #[serde(default)]
    pub(crate) dns_hook_cleanup: Option<String>,
    #[serde(default = "default_dns_propagation_delay_secs")]
    pub(crate) dns_propagation_delay_secs: u64,
    #[serde(default = "default_acme_renewal_window_secs")]
    pub(crate) renewal_window_secs: u64,
    #[serde(default = "default_acme_renewal_check_interval_secs")]
    pub(crate) renewal_check_interval_secs: u64,
    #[serde(default = "default_acme_renewal_retry_interval_secs")]
    pub(crate) renewal_retry_interval_secs: u64,
    #[serde(default = "default_true")]
    pub(crate) auto_graceful_reload: bool,
}

impl Default for TlsAcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            domains: Vec::new(),
            email: None,
            directory_url: default_acme_directory_url(),
            challenge: default_acme_challenge(),
            http_challenge_listen: default_http_challenge_listen(),
            storage_dir: default_acme_storage_dir(),
            terms_agreed: false,
            dns_provider: None,
            dns_config: BTreeMap::new(),
            dns_hook_set: None,
            dns_hook_cleanup: None,
            dns_propagation_delay_secs: default_dns_propagation_delay_secs(),
            renewal_window_secs: default_acme_renewal_window_secs(),
            renewal_check_interval_secs: default_acme_renewal_check_interval_secs(),
            renewal_retry_interval_secs: default_acme_renewal_retry_interval_secs(),
            auto_graceful_reload: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Provider {
    pub(crate) name: String,
    #[serde(default = "default_provider_kind")]
    pub(crate) kind: String,
    pub(crate) base_url: String,
    #[serde(default)]
    pub(crate) api_key_env: Option<String>,
    #[serde(default)]
    pub(crate) openrouter_http_referer: Option<String>,
    #[serde(default)]
    pub(crate) openrouter_x_title: Option<String>,
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Model {
    /// Logical model name exposed by FerroGate clients.
    pub(crate) name: String,
    /// Provider name from [[providers]].
    pub(crate) provider: String,
    /// Actual model name sent to the upstream provider.
    pub(crate) provider_model: String,
    #[serde(default)]
    pub(crate) routing_strategy: RoutingStrategy,
    #[serde(default)]
    pub(crate) fallbacks: Vec<ModelFallback>,
    #[serde(default)]
    pub(crate) visible_organization_ids: Vec<String>,
    #[serde(default)]
    pub(crate) visible_project_ids: Vec<String>,
    #[serde(default)]
    pub(crate) capabilities: Vec<String>,
    #[serde(default)]
    pub(crate) context_window: Option<u32>,
    #[serde(default)]
    pub(crate) input_price_per_1m: Option<f64>,
    #[serde(default)]
    pub(crate) output_price_per_1m: Option<f64>,
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) cache_enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ModelFallback {
    pub(crate) provider: String,
    pub(crate) provider_model: String,
    #[serde(default)]
    pub(crate) input_price_per_1m: Option<f64>,
    #[serde(default)]
    pub(crate) output_price_per_1m: Option<f64>,
    #[serde(default)]
    pub(crate) priority: Option<u32>,
    #[serde(default)]
    pub(crate) weight: Option<u32>,
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ApiKey {
    /// Stable non-secret identifier used in logs and audit records.
    pub(crate) id: String,
    pub(crate) name: String,
    /// Environment variable containing the secret value. Preferred for real use.
    #[serde(default)]
    pub(crate) key_env: Option<String>,
    /// Plain value for local development only. Do not use in production.
    #[serde(default)]
    pub(crate) key: Option<String>,
    /// Hashed key value for durable config. Use `ferrogate hash-key --secret ...` to generate.
    #[serde(default)]
    pub(crate) key_hash: Option<String>,
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) scopes: Vec<String>,
    #[serde(default)]
    pub(crate) allowed_models: Vec<String>,
    #[serde(default)]
    pub(crate) denied_models: Vec<String>,
    #[serde(default)]
    pub(crate) allowed_providers: Vec<String>,
    #[serde(default)]
    pub(crate) denied_providers: Vec<String>,
    #[serde(default)]
    pub(crate) organization_id: Option<String>,
    #[serde(default)]
    pub(crate) team_id: Option<String>,
    #[serde(default)]
    pub(crate) project_id: Option<String>,
    #[serde(default)]
    pub(crate) user_id: Option<String>,
    #[serde(default)]
    pub(crate) monthly_token_budget: Option<u64>,
    #[serde(default)]
    pub(crate) request_limit_per_minute: Option<u64>,
    #[serde(default)]
    pub(crate) expires_at_unix: Option<u64>,
    #[serde(default)]
    pub(crate) log_bodies: Option<bool>,
    #[serde(default)]
    pub(crate) cache_enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct PolicyRule {
    pub(crate) name: String,
    #[serde(default = "default_policy_effect")]
    pub(crate) effect: String,
    #[serde(default)]
    pub(crate) organization_ids: Vec<String>,
    #[serde(default)]
    pub(crate) project_ids: Vec<String>,
    #[serde(default)]
    pub(crate) api_key_ids: Vec<String>,
    #[serde(default)]
    pub(crate) models: Vec<String>,
    #[serde(default)]
    pub(crate) providers: Vec<String>,
    #[serde(default = "default_policy_code")]
    pub(crate) code: String,
    #[serde(default = "default_policy_message")]
    pub(crate) message: String,
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GatewayConfigProfile {
    pub(crate) id: String,
    pub(crate) name: String,
    #[serde(default = "default_gateway_config_revision")]
    pub(crate) revision: u32,
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) api_key_ids: Vec<String>,
    #[serde(default)]
    pub(crate) cache_enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentWorkflowPolicy {
    pub(crate) id: String,
    pub(crate) name: String,
    #[serde(default = "default_gateway_config_revision")]
    pub(crate) version: u32,
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) organization_ids: Vec<String>,
    #[serde(default)]
    pub(crate) project_ids: Vec<String>,
    #[serde(default)]
    pub(crate) api_key_ids: Vec<String>,
    pub(crate) nodes: Vec<AgentWorkflowNode>,
    #[serde(default)]
    pub(crate) edges: Vec<AgentWorkflowEdge>,
    #[serde(default)]
    pub(crate) max_model_calls: Option<u32>,
    #[serde(default)]
    pub(crate) max_tool_calls: Option<u32>,
    #[serde(default)]
    pub(crate) max_parallelism: Option<u32>,
    #[serde(default)]
    pub(crate) max_iterations: Option<u32>,
    #[serde(default)]
    pub(crate) timeout_millis: Option<u64>,
    #[serde(default)]
    pub(crate) token_budget: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentWorkflowNode {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) kind: AgentWorkflowNodeKind,
    #[serde(default)]
    pub(crate) model: Option<String>,
    #[serde(default)]
    pub(crate) providers: Vec<String>,
    #[serde(default)]
    pub(crate) tool: Option<String>,
    #[serde(default)]
    pub(crate) max_iterations: Option<u32>,
    #[serde(default)]
    pub(crate) token_budget: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgentWorkflowNodeKind {
    #[default]
    Model,
    Tool,
    Router,
    Human,
    Checkpoint,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentWorkflowEdge {
    pub(crate) from: String,
    pub(crate) to: String,
    #[serde(default)]
    pub(crate) condition: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PromptTemplate {
    pub(crate) id: String,
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) status: PromptTemplateStatus,
    #[serde(default)]
    pub(crate) target: PromptTemplateTarget,
    pub(crate) model: String,
    #[serde(default)]
    pub(crate) variables: Vec<PromptTemplateVariable>,
    pub(crate) versions: Vec<PromptTemplateVersion>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PromptTemplateStatus {
    Draft,
    #[default]
    Active,
    Archived,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PromptTemplateTarget {
    #[default]
    ChatCompletions,
    Responses,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PromptTemplateVariable {
    pub(crate) name: String,
    #[serde(default = "default_true")]
    pub(crate) required: bool,
    #[serde(default)]
    pub(crate) default: Option<String>,
    #[serde(default)]
    pub(crate) description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PromptTemplateVersion {
    #[serde(default = "default_gateway_config_revision")]
    pub(crate) revision: u32,
    #[serde(default)]
    pub(crate) status: PromptTemplateVersionStatus,
    pub(crate) messages: Vec<PromptTemplateMessage>,
    #[serde(default)]
    pub(crate) temperature: Option<f64>,
    #[serde(default)]
    pub(crate) top_p: Option<f64>,
    #[serde(default)]
    pub(crate) max_tokens: Option<u32>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PromptTemplateVersionStatus {
    Draft,
    #[default]
    Active,
    Archived,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PromptTemplateMessage {
    pub(crate) role: String,
    pub(crate) content: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuardrailRule {
    pub(crate) id: String,
    pub(crate) name: String,
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
    #[serde(default = "default_guardrail_stage")]
    pub(crate) stage: GuardrailStage,
    #[serde(default)]
    pub(crate) organization_ids: Vec<String>,
    #[serde(default)]
    pub(crate) project_ids: Vec<String>,
    #[serde(default)]
    pub(crate) api_key_ids: Vec<String>,
    #[serde(default)]
    pub(crate) models: Vec<String>,
    #[serde(default)]
    pub(crate) providers: Vec<String>,
    #[serde(default)]
    pub(crate) keywords: Vec<String>,
    #[serde(default)]
    pub(crate) regex: Vec<String>,
    #[serde(default)]
    pub(crate) max_input_bytes: Option<usize>,
    #[serde(default = "default_guardrail_effect")]
    pub(crate) effect: GuardrailEffect,
    #[serde(default = "default_guardrail_code")]
    pub(crate) code: String,
    #[serde(default = "default_guardrail_message")]
    pub(crate) message: String,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuardrailStage {
    #[default]
    Request,
    Response,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuardrailEffect {
    #[default]
    Deny,
    Redact,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExtensionKind {
    RequestHook,
    ToolProvider,
    EventSink,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub(crate) struct ExtensionConfig {
    pub(crate) id: String,
    pub(crate) kind: ExtensionKind,
    #[serde(default = "default_plugin_manifest_version")]
    pub(crate) version: String,
    #[serde(default)]
    pub(crate) manifest: PluginManifest,
    #[serde(default)]
    pub(crate) compatibility: PluginCompatibility,
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
    #[serde(default = "default_extension_source")]
    pub(crate) source: String,
    #[serde(default = "default_extension_order")]
    pub(crate) order: u32,
    #[serde(default)]
    pub(crate) approval_policy: ApprovalPolicy,
    #[serde(default)]
    pub(crate) permissions: ExtensionPermissions,
    #[serde(default)]
    pub(crate) config: BTreeMap<String, toml::Value>,
}

pub(crate) type PluginConfig = ExtensionConfig;

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub(crate) struct PluginManifest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) capabilities: Vec<String>,
    #[serde(default)]
    pub(crate) required_permissions: ExtensionPermissions,
    #[serde(default)]
    pub(crate) hooks: Vec<String>,
    #[serde(default)]
    pub(crate) config_schema: Option<toml::Value>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct PluginCompatibility {
    #[serde(default)]
    pub(crate) min_gateway_version: Option<String>,
    #[serde(default)]
    pub(crate) max_gateway_version: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub(crate) struct SkillPackage {
    pub(crate) id: String,
    pub(crate) name: String,
    #[serde(default = "default_skill_package_version")]
    pub(crate) version: String,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) compatibility: SkillPackageCompatibility,
    #[serde(default)]
    pub(crate) permissions: ExtensionPermissions,
    #[serde(default)]
    pub(crate) capabilities: Vec<SkillPackageCapability>,
    #[serde(default)]
    pub(crate) resources: SkillPackageResources,
    #[serde(default)]
    pub(crate) api_key_ids: Vec<String>,
    #[serde(default)]
    pub(crate) metadata: BTreeMap<String, toml::Value>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub(crate) struct SkillPackageResources {
    #[serde(default)]
    pub(crate) plugins: Vec<PluginConfig>,
    #[serde(default)]
    pub(crate) mcp_servers: Vec<McpServerConfig>,
    #[serde(default)]
    pub(crate) prompt_templates: Vec<PromptTemplate>,
    #[serde(default)]
    pub(crate) agent_workflows: Vec<AgentWorkflowPolicy>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct SkillPackageCompatibility {
    #[serde(default)]
    pub(crate) min_gateway_version: Option<String>,
    #[serde(default)]
    pub(crate) agent_runtimes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct SkillPackageCapability {
    pub(crate) kind: SkillPackageCapabilityKind,
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SkillPackageCapabilityKind {
    Plugin,
    Tool,
    McpServer,
    McpTool,
    PromptTemplate,
    AgentWorkflow,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub(crate) struct ExtensionPermissions {
    #[serde(default)]
    pub(crate) tools: Vec<String>,
    #[serde(default)]
    pub(crate) network: Vec<String>,
    #[serde(default)]
    pub(crate) filesystem: bool,
    #[serde(default)]
    pub(crate) shell: bool,
    #[serde(default)]
    pub(crate) tenant_scope: bool,
    #[serde(default)]
    pub(crate) secrets: bool,
    #[serde(default)]
    pub(crate) admin_mutation: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct TelemetryConfig {
    #[serde(default = "default_service_name")]
    pub(crate) service_name: String,
    #[serde(default)]
    pub(crate) log_bodies: bool,
    #[serde(default)]
    pub(crate) access_log: AccessLogMode,
    #[serde(default = "default_access_log_sample_rate")]
    pub(crate) access_log_sample_rate: u64,
    #[serde(default = "default_access_log_error_rate_limit_per_sec")]
    pub(crate) access_log_error_rate_limit_per_sec: u64,
    #[serde(default)]
    pub(crate) otlp_endpoint: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ObservabilityConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) provider: ObservabilityProvider,
    #[serde(default)]
    pub(crate) otlp_endpoint: Option<String>,
    #[serde(default = "default_observability_prometheus_metrics_path")]
    pub(crate) prometheus_metrics_path: String,
    #[serde(default = "default_observability_export_timeout_secs")]
    pub(crate) export_timeout_secs: u64,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ObservabilityProvider {
    #[default]
    Vector,
    Otlp,
    None,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct AnalyticsConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) provider: AnalyticsProvider,
    #[serde(default)]
    pub(crate) required: bool,
    #[serde(default)]
    pub(crate) vector_endpoint: Option<String>,
    #[serde(default)]
    pub(crate) clickhouse_url: Option<String>,
    #[serde(default)]
    pub(crate) clickhouse_url_env: Option<String>,
    #[serde(default = "default_analytics_export_timeout_secs")]
    pub(crate) export_timeout_secs: u64,
    #[serde(default = "default_analytics_batch_max_events")]
    pub(crate) batch_max_events: usize,
    #[serde(default = "default_analytics_flush_interval_millis")]
    pub(crate) flush_interval_millis: u64,
    #[serde(default = "default_analytics_queue_capacity")]
    pub(crate) queue_capacity: usize,
    #[serde(default = "default_request_log_retention_records")]
    pub(crate) request_log_retention_records: usize,
    #[serde(default = "default_audit_event_retention_records")]
    pub(crate) audit_event_retention_records: usize,
    #[serde(default = "default_billing_event_retention_records")]
    pub(crate) billing_event_retention_records: usize,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AnalyticsProvider {
    #[default]
    Vector,
    Clickhouse,
    None,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct MeteringConfig {
    #[serde(default)]
    pub(crate) export_enabled: bool,
    #[serde(default)]
    pub(crate) export_provider: MeteringExportProvider,
    #[serde(default = "default_metering_export_endpoint")]
    pub(crate) export_endpoint: String,
    #[serde(default)]
    pub(crate) export_token_env: Option<String>,
    #[serde(default)]
    pub(crate) export_token: Option<String>,
    #[serde(default = "default_metering_export_timeout_secs")]
    pub(crate) export_timeout_secs: u64,
    #[serde(default = "default_metering_export_event_type")]
    pub(crate) export_event_type: String,
    #[serde(default = "default_metering_export_source")]
    pub(crate) export_source: String,
    #[serde(default)]
    pub(crate) export_subject: MeteringExportSubject,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MeteringExportProvider {
    #[default]
    Legacy,
    Openmeter,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MeteringExportSubject {
    #[default]
    #[serde(rename = "api_key_id")]
    ApiKey,
    #[serde(rename = "organization_id")]
    Organization,
    #[serde(rename = "project_id")]
    Project,
    #[serde(rename = "user_id")]
    User,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct CacheConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) mode: CacheMode,
    #[serde(default = "default_cache_ttl_secs")]
    pub(crate) ttl_secs: u64,
    #[serde(default = "default_cache_max_records")]
    pub(crate) max_records: usize,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CacheMode {
    #[default]
    ExactMatch,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AccessLogMode {
    Off,
    #[default]
    Error,
    Sampled,
    All,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct StorageConfig {
    #[serde(default)]
    pub(crate) provider: StorageProviderKind,
    #[serde(default)]
    pub(crate) required: bool,
    #[serde(default = "default_storage_provider_order")]
    pub(crate) provider_order: Vec<StorageProviderKind>,
    #[serde(default)]
    pub(crate) libsql_url: Option<String>,
    #[serde(default)]
    pub(crate) libsql_auth_token: Option<String>,
    #[serde(default)]
    pub(crate) libsql_auth_token_env: Option<String>,
    #[serde(default)]
    pub(crate) postgres_dsn: Option<String>,
    #[serde(default)]
    pub(crate) postgres_dsn_env: Option<String>,
    #[serde(default)]
    pub(crate) supabase_dsn_env: Option<String>,
    #[serde(default = "default_postgres_pool_size")]
    pub(crate) postgres_pool_size: usize,
    #[serde(default)]
    pub(crate) postgres_tls_mode: PostgresTlsMode,
    #[serde(default)]
    pub(crate) postgres_tls_ca_cert_path: Option<String>,
    #[serde(default = "default_postgres_connect_timeout_secs")]
    pub(crate) postgres_connect_timeout_secs: u64,
    #[serde(default = "default_postgres_statement_timeout_millis")]
    pub(crate) postgres_statement_timeout_millis: u64,
    #[serde(default)]
    pub(crate) postgres_schema: Option<String>,
    #[serde(default)]
    pub(crate) postgres_search_path: Vec<String>,
    #[serde(default)]
    pub(crate) mysql_dsn: Option<String>,
    #[serde(default)]
    pub(crate) mysql_dsn_env: Option<String>,
    #[serde(default = "default_mysql_pool_size")]
    pub(crate) mysql_pool_size: usize,
    #[serde(default)]
    pub(crate) mysql_tls_mode: MySqlTlsMode,
    #[serde(default)]
    pub(crate) mysql_tls_ca_cert_path: Option<String>,
    #[serde(default = "default_mysql_connect_timeout_secs")]
    pub(crate) mysql_connect_timeout_secs: u64,
    #[serde(default = "default_storage_migration_mode")]
    pub(crate) migration_mode: StorageMigrationMode,
    #[serde(default = "default_admin_list_limit")]
    pub(crate) admin_list_default_limit: usize,
    #[serde(default = "default_admin_list_max_limit")]
    pub(crate) admin_list_max_limit: usize,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StorageMigrationMode {
    #[default]
    Auto,
    ValidateOnly,
    Disabled,
}

impl StorageMigrationMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            StorageMigrationMode::Auto => "auto",
            StorageMigrationMode::ValidateOnly => "validate_only",
            StorageMigrationMode::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ReliabilityConfig {
    #[serde(default)]
    pub(crate) provider_circuit_breaker_failure_threshold: Option<u32>,
    #[serde(default)]
    pub(crate) provider_circuit_breaker_cooldown_secs: Option<u64>,
    #[serde(default)]
    pub(crate) provider_dispatch_timeout_secs: Option<u64>,
    #[serde(default)]
    pub(crate) provider_dispatch_max_retries: Option<u32>,
    #[serde(default)]
    pub(crate) provider_response_body_max_bytes: Option<usize>,
    #[serde(default = "default_tool_approval_timeout_secs")]
    pub(crate) tool_approval_timeout_secs: u64,
    #[serde(default = "default_mcp_dispatch_timeout_secs")]
    pub(crate) mcp_dispatch_timeout_secs: u64,
    #[serde(default = "default_mcp_dispatch_max_concurrency")]
    pub(crate) mcp_dispatch_max_concurrency: usize,
    #[serde(default)]
    pub(crate) graceful_shutdown_grace_period_secs: Option<u64>,
    #[serde(default)]
    pub(crate) graceful_shutdown_timeout_secs: Option<u64>,
    #[serde(default)]
    pub(crate) graceful_upgrade_pid_file: Option<String>,
    #[serde(default)]
    pub(crate) graceful_upgrade_sock: Option<String>,
    #[serde(default)]
    pub(crate) graceful_upgrade_sock_retries: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Upstream {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) url: Option<String>,
    #[serde(default)]
    pub(crate) urls: Vec<String>,
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct AgentUpstreamConfig {
    pub(crate) id: String,
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
    #[serde(default = "default_agent_upstream_protocol")]
    pub(crate) protocol: AgentUpstreamProtocol,
    pub(crate) endpoint: String,
    #[serde(default)]
    pub(crate) auth: AgentUpstreamAuth,
    #[serde(default)]
    pub(crate) tenant_ids: Vec<String>,
    #[serde(default)]
    pub(crate) capabilities: Vec<AgentUpstreamCapability>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgentUpstreamProtocol {
    #[default]
    A2a,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgentUpstreamAuth {
    #[default]
    None,
    Bearer {
        token: Option<String>,
    },
    Header {
        name: String,
        value: Option<String>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgentUpstreamCapability {
    Invoke,
    Read,
    Stream,
    Discover,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct RouteRule {
    pub(crate) name: String,
    pub(crate) upstream: String,
    #[serde(default)]
    pub(crate) hosts: Vec<String>,
    #[serde(default)]
    pub(crate) path_prefixes: Vec<String>,
    #[serde(default)]
    pub(crate) match_headers: Vec<HeaderMatcher>,
    #[serde(default)]
    pub(crate) strip_prefix: Option<String>,
    #[serde(default)]
    pub(crate) add_prefix: Option<String>,
    #[serde(default)]
    pub(crate) request_headers: Vec<HeaderMutation>,
    #[serde(default)]
    pub(crate) response_headers: Vec<HeaderMutation>,
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct HeaderMutation {
    pub(crate) name: String,
    pub(crate) value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct HeaderMatcher {
    pub(crate) name: String,
    pub(crate) value: String,
}

fn default_listen() -> String {
    "127.0.0.1:8080".to_string()
}

fn default_auth_service_endpoint() -> String {
    "http://127.0.0.1:8090".to_string()
}

fn default_auth_service_timeout_millis() -> u64 {
    500
}

fn default_auth_service_retry_backoff_millis() -> u64 {
    50
}

fn default_provider_kind() -> String {
    "openai".to_string()
}

fn default_service_name() -> String {
    "ferrogate".to_string()
}

fn default_true() -> bool {
    true
}

fn default_agent_upstream_protocol() -> AgentUpstreamProtocol {
    AgentUpstreamProtocol::A2a
}

fn default_cluster_id() -> String {
    "default".to_string()
}

fn default_cluster_node_id() -> String {
    "auto".to_string()
}

fn default_cluster_state_backend() -> String {
    "local".to_string()
}

fn default_cluster_counter_backend() -> String {
    "local".to_string()
}

fn default_cluster_counter_timeout_millis() -> u64 {
    500
}

fn default_cluster_heartbeat_interval_secs() -> u64 {
    10
}

fn default_cluster_config_poll_interval_secs() -> u64 {
    5
}

fn default_agent_runtime_max_turns() -> u32 {
    4
}

fn default_agent_runtime_timeout_millis() -> u64 {
    30_000
}

fn default_skill_package_version() -> String {
    "0.1.0".into()
}

fn default_acme_directory_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

fn default_acme_challenge() -> String {
    "dns-01".to_string()
}

fn default_http_challenge_listen() -> String {
    "0.0.0.0:80".to_string()
}

fn default_acme_storage_dir() -> String {
    ".ferrogate/acme".to_string()
}

fn default_dns_propagation_delay_secs() -> u64 {
    30
}

fn default_acme_renewal_window_secs() -> u64 {
    30 * 24 * 60 * 60
}

fn default_acme_renewal_check_interval_secs() -> u64 {
    12 * 60 * 60
}

fn default_acme_renewal_retry_interval_secs() -> u64 {
    30 * 60
}

fn default_policy_effect() -> String {
    "deny".to_string()
}

fn default_policy_code() -> String {
    "policy_denied".to_string()
}

fn default_policy_message() -> String {
    "request denied by policy".to_string()
}

fn default_gateway_config_revision() -> u32 {
    1
}

fn default_guardrail_stage() -> GuardrailStage {
    GuardrailStage::Request
}

fn default_guardrail_effect() -> GuardrailEffect {
    GuardrailEffect::Deny
}

fn default_guardrail_code() -> String {
    "guardrail_denied".to_string()
}

fn default_guardrail_message() -> String {
    "request blocked by guardrail".to_string()
}

fn default_extension_source() -> String {
    "builtin".to_string()
}

fn default_extension_order() -> u32 {
    100
}

fn default_plugin_manifest_version() -> String {
    "0.1.0".to_string()
}

fn default_access_log_sample_rate() -> u64 {
    100
}

fn default_access_log_error_rate_limit_per_sec() -> u64 {
    100
}

fn default_metering_export_endpoint() -> String {
    "https://api.token4ai.cloud/v1/metering/events".to_string()
}

fn default_metering_export_timeout_secs() -> u64 {
    3
}

fn default_metering_export_event_type() -> String {
    "ai.tokens".to_string()
}

fn default_metering_export_source() -> String {
    "ferrogate".to_string()
}

fn default_observability_prometheus_metrics_path() -> String {
    "/metrics".to_string()
}

fn default_observability_export_timeout_secs() -> u64 {
    3
}

fn default_analytics_export_timeout_secs() -> u64 {
    3
}

fn default_analytics_batch_max_events() -> usize {
    500
}

fn default_analytics_flush_interval_millis() -> u64 {
    1_000
}

fn default_analytics_queue_capacity() -> usize {
    10_000
}

fn default_cache_ttl_secs() -> u64 {
    300
}

fn default_cache_max_records() -> usize {
    1_000
}

fn default_tool_approval_timeout_secs() -> u64 {
    30
}

fn default_mcp_dispatch_timeout_secs() -> u64 {
    30
}

fn default_mcp_dispatch_max_concurrency() -> usize {
    32
}

fn default_storage_provider_order() -> Vec<StorageProviderKind> {
    ferrogate_storage::DEFAULT_DURABLE_PROVIDER_ORDER.to_vec()
}

fn default_storage_migration_mode() -> StorageMigrationMode {
    StorageMigrationMode::Auto
}

fn default_postgres_pool_size() -> usize {
    4
}

fn default_mysql_pool_size() -> usize {
    4
}

fn default_postgres_connect_timeout_secs() -> u64 {
    5
}

fn default_mysql_connect_timeout_secs() -> u64 {
    5
}

fn default_postgres_statement_timeout_millis() -> u64 {
    30_000
}

fn default_request_log_retention_records() -> usize {
    10_000
}

fn default_audit_event_retention_records() -> usize {
    10_000
}

fn default_billing_event_retention_records() -> usize {
    10_000
}

fn default_admin_list_limit() -> usize {
    100
}

fn default_admin_list_max_limit() -> usize {
    1_000
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: default_service_name(),
            log_bodies: false,
            access_log: AccessLogMode::default(),
            access_log_sample_rate: default_access_log_sample_rate(),
            access_log_error_rate_limit_per_sec: default_access_log_error_rate_limit_per_sec(),
            otlp_endpoint: None,
        }
    }
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: ObservabilityProvider::Vector,
            otlp_endpoint: None,
            prometheus_metrics_path: default_observability_prometheus_metrics_path(),
            export_timeout_secs: default_observability_export_timeout_secs(),
        }
    }
}

impl Default for AnalyticsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: AnalyticsProvider::Vector,
            required: false,
            vector_endpoint: None,
            clickhouse_url: None,
            clickhouse_url_env: None,
            export_timeout_secs: default_analytics_export_timeout_secs(),
            batch_max_events: default_analytics_batch_max_events(),
            flush_interval_millis: default_analytics_flush_interval_millis(),
            queue_capacity: default_analytics_queue_capacity(),
            request_log_retention_records: default_request_log_retention_records(),
            audit_event_retention_records: default_audit_event_retention_records(),
            billing_event_retention_records: default_billing_event_retention_records(),
        }
    }
}

impl Default for MeteringConfig {
    fn default() -> Self {
        Self {
            export_enabled: false,
            export_provider: MeteringExportProvider::default(),
            export_endpoint: default_metering_export_endpoint(),
            export_token_env: None,
            export_token: None,
            export_timeout_secs: default_metering_export_timeout_secs(),
            export_event_type: default_metering_export_event_type(),
            export_source: default_metering_export_source(),
            export_subject: MeteringExportSubject::default(),
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: CacheMode::ExactMatch,
            ttl_secs: default_cache_ttl_secs(),
            max_records: default_cache_max_records(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            provider: StorageProviderKind::Memory,
            required: false,
            provider_order: default_storage_provider_order(),
            libsql_url: None,
            libsql_auth_token: None,
            libsql_auth_token_env: None,
            postgres_dsn: None,
            postgres_dsn_env: None,
            supabase_dsn_env: None,
            postgres_pool_size: default_postgres_pool_size(),
            postgres_tls_mode: PostgresTlsMode::default(),
            postgres_tls_ca_cert_path: None,
            postgres_connect_timeout_secs: default_postgres_connect_timeout_secs(),
            postgres_statement_timeout_millis: default_postgres_statement_timeout_millis(),
            postgres_schema: None,
            postgres_search_path: Vec::new(),
            mysql_dsn: None,
            mysql_dsn_env: None,
            mysql_pool_size: default_mysql_pool_size(),
            mysql_tls_mode: MySqlTlsMode::default(),
            mysql_tls_ca_cert_path: None,
            mysql_connect_timeout_secs: default_mysql_connect_timeout_secs(),
            migration_mode: default_storage_migration_mode(),
            admin_list_default_limit: default_admin_list_limit(),
            admin_list_max_limit: default_admin_list_max_limit(),
        }
    }
}

impl Default for ReliabilityConfig {
    fn default() -> Self {
        Self {
            provider_circuit_breaker_failure_threshold: None,
            provider_circuit_breaker_cooldown_secs: None,
            provider_dispatch_timeout_secs: None,
            provider_dispatch_max_retries: None,
            provider_response_body_max_bytes: None,
            tool_approval_timeout_secs: default_tool_approval_timeout_secs(),
            mcp_dispatch_timeout_secs: default_mcp_dispatch_timeout_secs(),
            mcp_dispatch_max_concurrency: default_mcp_dispatch_max_concurrency(),
            graceful_shutdown_grace_period_secs: None,
            graceful_shutdown_timeout_secs: None,
            graceful_upgrade_pid_file: None,
            graceful_upgrade_sock: None,
            graceful_upgrade_sock_retries: None,
        }
    }
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cluster_id: default_cluster_id(),
            node_id: default_cluster_node_id(),
            node_region: None,
            node_zone: None,
            state_backend: default_cluster_state_backend(),
            file_state_path: None,
            counter_backend: default_cluster_counter_backend(),
            redis_url: None,
            counter_timeout_millis: default_cluster_counter_timeout_millis(),
            heartbeat_interval_secs: default_cluster_heartbeat_interval_secs(),
            config_poll_interval_secs: default_cluster_config_poll_interval_secs(),
        }
    }
}

impl Default for AuthServiceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_auth_service_endpoint(),
            timeout_millis: default_auth_service_timeout_millis(),
            max_retries: 0,
            retry_backoff_millis: default_auth_service_retry_backoff_millis(),
        }
    }
}

impl Default for AgentRuntimeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: AgentRuntimeProvider::ManagedWorker,
            max_turns: default_agent_runtime_max_turns(),
            timeout_millis: default_agent_runtime_timeout_millis(),
            external: AgentRuntimeExternalConfig::default(),
            managed_worker: AgentRuntimeManagedWorkerConfig::default(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            admin: AdminConfig::default(),
            tls: TlsConfig::default(),
            auth_service: AuthServiceConfig::default(),
            providers: Vec::new(),
            models: Vec::new(),
            api_keys: Vec::new(),
            policies: Vec::new(),
            gateway_configs: Vec::new(),
            agent_workflows: Vec::new(),
            skill_packages: Vec::new(),
            prompt_templates: Vec::new(),
            guardrails: Vec::new(),
            plugins: Vec::new(),
            extensions: Vec::new(),
            mcp_servers: Vec::new(),
            agent_upstreams: Vec::new(),
            telemetry: TelemetryConfig::default(),
            observability: ObservabilityConfig::default(),
            analytics: AnalyticsConfig::default(),
            metering: MeteringConfig::default(),
            cache: CacheConfig::default(),
            storage: StorageConfig::default(),
            reliability: ReliabilityConfig::default(),
            agent_runtime: AgentRuntimeConfig::default(),
            cluster: ClusterConfig::default(),
            upstreams: Vec::new(),
            routes: Vec::new(),
        }
    }
}
