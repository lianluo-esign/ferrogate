// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(crate) use ferrogate_core::ApprovalPolicy;
use ferrogate_guardrails::{all_content_sources, ContentSource};
pub(crate) use ferrogate_mcp::{
    McpAuthType, McpHeaderConfig, McpOauthConfig, McpServerConfig, McpTlsConfig, McpTransport,
};
use ferrogate_providers::RoutingStrategy;
use ferrogate_storage::{PostgresTlsMode, StorageProviderKind};

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
    pub(crate) billing_service: BillingServiceConfig,
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
    pub(crate) billing_alerts: BillingAlertsConfig,
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
    #[serde(default)]
    pub(crate) network_access: NetworkAccessConfig,
    #[serde(default)]
    pub(crate) asset_bucket: AssetBucketConfig,
}

/// S3-compatible object-storage bucket for `/v1/assets/*` content (issue
/// #176). Optional and additive: `enabled = false` (the default) keeps
/// every asset's bytes inline in `stored_assets.content`, the original
/// #176 design -- unset entirely, this whole feature is a no-op. Supabase
/// Storage exposes an S3-compatible endpoint using the same SigV4 auth
/// scheme AWS S3 does, so this also works against a real AWS S3 bucket or
/// any other S3-compatible service (MinIO, etc.), not only Supabase.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct AssetBucketConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    /// `scheme://host[:port]`, no trailing slash, no bucket/key suffix --
    /// e.g. `https://<project>.supabase.co/storage/v1/s3`.
    #[serde(default)]
    pub(crate) endpoint: Option<String>,
    #[serde(default)]
    pub(crate) bucket: Option<String>,
    #[serde(default)]
    pub(crate) region: Option<String>,
    /// Not a secret itself -- paired with `secret_access_key_env` for the
    /// actual secret, mirroring `Provider::aws_access_key_id`'s split.
    #[serde(default)]
    pub(crate) access_key_id: Option<String>,
    #[serde(default)]
    pub(crate) secret_access_key_env: Option<String>,
}

/// Pre-authentication network controls (issue #166), applied to every
/// request before virtual-key/storage lookups. All fields are additive and
/// default to the pre-#166 behavior (no allowlist, no pre-auth throttling).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct NetworkAccessConfig {
    /// CIDR ranges (or bare IPs) allowed to reach the gateway. Empty means
    /// "no restriction" — every source IP is allowed, matching prior
    /// behavior.
    #[serde(default)]
    pub(crate) ip_allowlist: Vec<String>,
    /// Whether to trust `X-Forwarded-For`/`X-Real-IP` over the raw TCP peer
    /// address when resolving the client IP for allowlist/rate-limit
    /// decisions. Only enable this when FerroGate sits behind trusted reverse
    /// proxies and is reachable only through them — otherwise any client can
    /// spoof its apparent source IP. Defaults to `false` (trust only the raw
    /// peer address).
    #[serde(default)]
    pub(crate) trust_forwarded_for: bool,
    /// Number of trusted reverse proxies in front of the gateway. When
    /// `trust_forwarded_for` is set, the client IP is taken this many entries
    /// from the RIGHT of `X-Forwarded-For` (each trusted proxy appends exactly
    /// one entry), so client-supplied leftmost entries cannot spoof the source
    /// IP. Defaults to `1` (a single fronting load balancer) when trusting
    /// forwarded headers; set higher for a chain of N proxies.
    #[serde(default)]
    pub(crate) trusted_proxy_hops: Option<u32>,
    /// Maximum requests per source IP per minute before authentication is
    /// even attempted. `None` (the default) disables pre-auth throttling.
    #[serde(default)]
    pub(crate) unauthenticated_rate_limit_per_minute: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct AdminConfig {
    #[serde(default)]
    pub(crate) listen: Option<String>,
    /// Origin reflected back as `Access-Control-Allow-Origin` on every
    /// locally-handled admin API response (including an `OPTIONS` preflight),
    /// so a separately-deployed admin console frontend can call `/admin/v1/*`
    /// cross-origin without an Ingress/reverse-proxy CORS layer in front.
    /// Unset disables CORS headers entirely. Applied once at process start;
    /// changing it requires a restart (not picked up by `/admin/v1/config/reload`).
    #[serde(default)]
    pub(crate) cors_allowed_origin: Option<String>,
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

/// Gateway-side client config for the standalone billing service (issue #131).
/// When `enabled`, the gateway reports each settled usage event to the billing
/// service's `POST /v1/billing/charge` over REST (fire-and-forget, so the hot
/// path is never blocked on the billing round-trip).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct BillingServiceConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default = "default_billing_service_endpoint")]
    pub(crate) endpoint: String,
    #[serde(default = "default_billing_service_timeout_millis")]
    pub(crate) timeout_millis: u64,
    /// Optional service-to-service bearer token sent to the billing service.
    #[serde(default)]
    pub(crate) token: Option<String>,
    /// Optional env var name holding the billing service bearer token.
    #[serde(default)]
    pub(crate) token_env: Option<String>,
}

impl Default for BillingServiceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_billing_service_endpoint(),
            timeout_millis: default_billing_service_timeout_millis(),
            token: None,
            token_env: None,
        }
    }
}

fn default_billing_service_endpoint() -> String {
    "http://127.0.0.1:8092".to_string()
}

fn default_billing_service_timeout_millis() -> u64 {
    1_000
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
    /// Ed25519 signing key (base64 standard, 32-byte seed) THIS node uses to
    /// sign the file-backed control-plane snapshots it publishes. When set,
    /// `publish_from_config` embeds a signed envelope in the snapshot; when
    /// unset, snapshots are published unsigned (legacy behavior). Issue #206.
    #[serde(default)]
    pub(crate) snapshot_signing_key: Option<String>,
    /// Key id advertised in signed snapshots this node publishes; peers look it
    /// up in their `snapshot_trusted_keys`. Required when `snapshot_signing_key`
    /// is set.
    #[serde(default)]
    pub(crate) snapshot_signing_key_id: Option<String>,
    /// Trusted Ed25519 verifying keys (key_id -> base64 standard 32-byte public
    /// key). When non-empty, a loaded file-backed snapshot MUST carry a valid
    /// signature from one of these keys (matching identity + a strictly newer
    /// revision + unexpired) before it is activated; a snapshot that fails
    /// verification is rejected and the running config (last known good) is
    /// retained. Empty = verification disabled (legacy behavior).
    #[serde(default)]
    pub(crate) snapshot_trusted_keys: Vec<ClusterSnapshotKey>,
    /// Tenant identity the snapshot signature must bind to. Required when
    /// signing or verification is enabled.
    #[serde(default)]
    pub(crate) snapshot_tenant_id: Option<String>,
    /// Deployment identity the snapshot signature must bind to. Required when
    /// signing or verification is enabled.
    #[serde(default)]
    pub(crate) snapshot_deployment_id: Option<String>,
    /// TTL (seconds) applied to signed snapshots this node publishes:
    /// `not_after_unix = now + this`. Peers reject a snapshot once expired.
    #[serde(default = "default_cluster_snapshot_max_age_secs")]
    pub(crate) snapshot_max_age_secs: u64,
}

/// A trusted Ed25519 verifying key for signed control-plane snapshots (#206).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct ClusterSnapshotKey {
    pub(crate) key_id: String,
    /// Base64 (standard alphabet) of the 32-byte Ed25519 public key.
    pub(crate) public_key: String,
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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct AgentRuntimeManagedWorkerConfig {
    #[serde(default)]
    pub(crate) external_action_authorizer_http_listen: Option<String>,
    #[serde(default)]
    pub(crate) external_action_authorizer_socket: Option<String>,
    #[serde(default)]
    pub(crate) external_action_authorizer_max_requests: Option<usize>,
    #[serde(default)]
    pub(crate) allowed_actions: Vec<ManagedWorkerCapabilityActionConfig>,
    #[serde(default)]
    pub(crate) approval_required_actions: Vec<ManagedWorkerCapabilityActionConfig>,
    #[serde(default)]
    pub(crate) allow_direct_network_egress: bool,
    #[serde(default)]
    pub(crate) target_grants: Vec<ManagedWorkerCapabilityTargetGrantConfig>,
    #[serde(default)]
    pub(crate) class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode,
    #[serde(default = "default_managed_worker_policy_revision")]
    pub(crate) policy_revision: String,
}

impl Default for AgentRuntimeManagedWorkerConfig {
    fn default() -> Self {
        Self {
            external_action_authorizer_http_listen: None,
            external_action_authorizer_socket: None,
            external_action_authorizer_max_requests: None,
            allowed_actions: Vec::new(),
            approval_required_actions: Vec::new(),
            allow_direct_network_egress: false,
            target_grants: Vec::new(),
            class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::Deny,
            policy_revision: default_managed_worker_policy_revision(),
        }
    }
}

fn default_managed_worker_policy_revision() -> String {
    "config-v1".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct ManagedWorkerCapabilityTargetGrantConfig {
    pub(crate) selector_id: String,
    pub(crate) permission_key: String,
    pub(crate) action: ManagedWorkerCapabilityActionConfig,
    pub(crate) selector: ferrogate_runtime::CapabilityTargetSelector,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ManagedWorkerCapabilityActionConfig {
    Tool,
    McpTool,
    Cli,
    Skill,
    Filesystem,
    Browser,
    Rest,
    Secret,
    MemoryRead,
    MemoryWrite,
    NetworkEgress,
}

impl ManagedWorkerCapabilityActionConfig {
    pub(crate) fn as_str(self) -> &'static str {
        self.as_policy_action().as_str()
    }

    pub(crate) fn as_policy_action(self) -> ferrogate_runtime::CapabilityAction {
        match self {
            Self::Tool => ferrogate_runtime::CapabilityAction::Tool,
            Self::McpTool => ferrogate_runtime::CapabilityAction::McpTool,
            Self::Cli => ferrogate_runtime::CapabilityAction::Cli,
            Self::Skill => ferrogate_runtime::CapabilityAction::Skill,
            Self::Filesystem => ferrogate_runtime::CapabilityAction::Filesystem,
            Self::Browser => ferrogate_runtime::CapabilityAction::Browser,
            Self::Rest => ferrogate_runtime::CapabilityAction::Rest,
            Self::Secret => ferrogate_runtime::CapabilityAction::Secret,
            Self::MemoryRead => ferrogate_runtime::CapabilityAction::MemoryRead,
            Self::MemoryWrite => ferrogate_runtime::CapabilityAction::MemoryWrite,
            Self::NetworkEgress => ferrogate_runtime::CapabilityAction::NetworkEgress,
        }
    }
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
    /// Secret-manager reference (`env://NAME` or `vault://mount/path#field`,
    /// issue #163), resolved once at config load/reload time and cached —
    /// see `AppState::resolved_provider_secrets`. Takes precedence over
    /// `api_key_env` when both are set and resolution succeeds.
    #[serde(default)]
    pub(crate) secret_ref: Option<String>,
    #[serde(default)]
    pub(crate) openrouter_http_referer: Option<String>,
    #[serde(default)]
    pub(crate) openrouter_x_title: Option<String>,
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
    /// Physical region this provider is hosted in (issue #173), e.g.
    /// "eu-west-1" -- additive and `#[serde(default)]` so existing configs
    /// deserialize unchanged. Enforced against a tenant's region
    /// allowlist (`ApiKey::region_allowlist`) at routing time via
    /// `AppState::candidate_model_routes`; unset means the provider isn't
    /// eligible for a region-constrained tenant (fails closed, not open).
    #[serde(default)]
    pub(crate) region: Option<String>,
    /// AWS access key id for the `bedrock` provider kind (issue #172) --
    /// not a secret itself (safe to store in plain config), paired with
    /// `aws_secret_access_key_env` for the actual secret. `region` above
    /// (already used for #173's data-residency routing) doubles as the
    /// AWS region a Bedrock provider targets, rather than adding a
    /// duplicate field.
    #[serde(default)]
    pub(crate) aws_access_key_id: Option<String>,
    /// Environment variable holding the AWS secret access key. This
    /// resolves AWS credentials from the environment only (not through
    /// the vault-backed `secret_ref` mechanism `api_key_env` has), since
    /// Bedrock needs two independent secrets (secret key + optional
    /// session token) rather than the single generic `api_key` that
    /// mechanism was built for -- a deliberate scope-narrowing for
    /// issue #172's first cut, not a design dead-end.
    #[serde(default)]
    pub(crate) aws_secret_access_key_env: Option<String>,
    /// Environment variable holding a temporary AWS session token (STS
    /// assumed-role credentials). Omit for long-lived IAM user access
    /// keys.
    #[serde(default)]
    pub(crate) aws_session_token_env: Option<String>,
    /// GCP project id for the `vertex` provider kind (issue #172). Like
    /// `aws_access_key_id`, not a secret -- safe to store in plain
    /// config. `region` above doubles as the GCP location (e.g.
    /// `us-central1`) a Vertex AI provider targets, the same reuse
    /// `aws_access_key_id`'s doc comment already established for AWS.
    #[serde(default)]
    pub(crate) gcp_project_id: Option<String>,
    /// Environment variable holding a pre-minted GCP OAuth2 access token
    /// (scope `cloud-platform`). FerroGate does not mint or refresh this
    /// token itself -- see `GcpProviderCredentials`'s doc comment in
    /// `ferrogate-providers` for why -- so it must be kept fresh by an
    /// external process (e.g. a `gcloud auth application-default
    /// print-access-token` cron, or an ADC-aware sidecar).
    #[serde(default)]
    pub(crate) gcp_access_token_env: Option<String>,
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
    /// Regions this key's requests may route to (issue #173), e.g.
    /// ["eu-west-1"] -- empty means unrestricted, mirroring
    /// `allowed_models`/`allowed_providers`. Enforced in
    /// `AppState::candidate_model_routes` against each `ModelRoute`'s
    /// `region` (sourced from `Provider::region`); a route with no
    /// declared region is ineligible once this is non-empty (fail closed,
    /// not open).
    #[serde(default)]
    pub(crate) region_allowlist: Vec<String>,
    #[serde(default)]
    pub(crate) organization_id: Option<String>,
    #[serde(default)]
    pub(crate) team_id: Option<String>,
    #[serde(default)]
    pub(crate) project_id: Option<String>,
    #[serde(default)]
    pub(crate) workspace_id: Option<String>,
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
    #[serde(default = "all_content_sources")]
    pub(crate) sources: Vec<ContentSource>,
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
    #[serde(default)]
    pub(crate) provider: GuardrailProviderKind,
    #[serde(default)]
    pub(crate) provider_endpoint: Option<String>,
    #[serde(default = "default_guardrail_provider_timeout_ms")]
    pub(crate) provider_timeout_ms: u64,
    #[serde(flatten)]
    pub(crate) provider_runtime: GuardrailProviderRuntimeConfig,
    #[serde(default = "default_guardrail_effect")]
    pub(crate) effect: GuardrailEffect,
    #[serde(default = "default_guardrail_code")]
    pub(crate) code: String,
    #[serde(default = "default_guardrail_message")]
    pub(crate) message: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuardrailProviderRuntimeConfig {
    #[serde(default)]
    pub(crate) provider_on_error: GuardrailProviderErrorMode,
    #[serde(default = "default_guardrail_provider_max_concurrency")]
    pub(crate) provider_max_concurrency: usize,
    #[serde(default = "default_guardrail_provider_circuit_failure_threshold")]
    pub(crate) provider_circuit_failure_threshold: u32,
    #[serde(default = "default_guardrail_provider_circuit_cooldown_ms")]
    pub(crate) provider_circuit_cooldown_ms: u64,
    #[serde(default)]
    pub(crate) provider_max_retries: u8,
    #[serde(default = "default_guardrail_provider_max_payload_bytes")]
    pub(crate) provider_max_payload_bytes: usize,
    #[serde(default = "default_guardrail_provider_max_response_bytes")]
    pub(crate) provider_max_response_bytes: usize,
    #[serde(default)]
    pub(crate) provider_allow_private_network: bool,
    #[serde(default)]
    pub(crate) provider_secret_ref: Option<String>,
}

impl Default for GuardrailProviderRuntimeConfig {
    fn default() -> Self {
        Self {
            provider_on_error: GuardrailProviderErrorMode::Block,
            provider_max_concurrency: default_guardrail_provider_max_concurrency(),
            provider_circuit_failure_threshold:
                default_guardrail_provider_circuit_failure_threshold(),
            provider_circuit_cooldown_ms: default_guardrail_provider_circuit_cooldown_ms(),
            provider_max_retries: 0,
            provider_max_payload_bytes: default_guardrail_provider_max_payload_bytes(),
            provider_max_response_bytes: default_guardrail_provider_max_response_bytes(),
            provider_allow_private_network: false,
            provider_secret_ref: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuardrailProviderErrorMode {
    #[default]
    Block,
    Record,
    FallbackDetector,
}

/// Selects how a [`GuardrailRule`] decides whether text matches: in-process
/// keyword/regex/length checks (`None`, the default) or delegation to an
/// external detector reachable over HTTP (`CustomHttp`) — e.g. a dedicated
/// PII/jailbreak/toxicity classifier that can't be expressed as a regex.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuardrailProviderKind {
    #[default]
    None,
    CustomHttp,
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

/// Outbound notification channel for proactive budget-threshold alerting
/// (issue #170) -- fired once per `StoredQuotaPolicy::alert_threshold_pcts`
/// tier per scope per billing period, strictly before the unconditional
/// `monthly_budget_exceeded` 429 hard-deny at 100%. Webhook is the only
/// channel implemented today; `webhook_url` is the documented extension
/// point other channels (email/Slack) would plug into alongside.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct BillingAlertsConfig {
    /// POST target for budget-threshold-crossing notifications. `None`
    /// (the default) disables dispatch entirely -- threshold crossings are
    /// still detected and recorded (so a later-configured webhook doesn't
    /// replay history), just not delivered anywhere.
    #[serde(default)]
    pub(crate) webhook_url: Option<String>,
    #[serde(default = "default_billing_alerts_webhook_timeout_secs")]
    pub(crate) webhook_timeout_secs: u64,
    /// HMAC-SHA256 secret for signing budget-alert webhooks (issue #228). When
    /// set, each delivery carries `X-FerroGate-Timestamp` and
    /// `X-FerroGate-Signature: sha256=<hex of HMAC(secret, "<timestamp>.<body>")>`
    /// so a receiver can authenticate the alert and reject replays; `None`
    /// leaves alerts unsigned (legacy). Prefer an env placeholder so the secret
    /// is not stored in plaintext config.
    #[serde(default)]
    pub(crate) webhook_signing_secret: Option<String>,
}

fn default_billing_alerts_webhook_timeout_secs() -> u64 {
    5
}

impl Default for BillingAlertsConfig {
    fn default() -> Self {
        Self {
            webhook_url: None,
            webhook_timeout_secs: default_billing_alerts_webhook_timeout_secs(),
            webhook_signing_secret: None,
        }
    }
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
    #[serde(default = "default_guardrail_evaluation_retention_records")]
    pub(crate) guardrail_evaluation_retention_records: usize,
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
    #[serde(default = "default_postgres_pool_acquire_timeout_millis")]
    pub(crate) postgres_pool_acquire_timeout_millis: u64,
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

fn default_cluster_snapshot_max_age_secs() -> u64 {
    3_600
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

fn default_guardrail_provider_timeout_ms() -> u64 {
    2_000
}

fn default_guardrail_provider_max_concurrency() -> usize {
    16
}

fn default_guardrail_provider_circuit_failure_threshold() -> u32 {
    3
}

fn default_guardrail_provider_circuit_cooldown_ms() -> u64 {
    30_000
}

fn default_guardrail_provider_max_payload_bytes() -> usize {
    1024 * 1024
}

fn default_guardrail_provider_max_response_bytes() -> usize {
    256 * 1024
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

fn default_postgres_pool_acquire_timeout_millis() -> u64 {
    1_000
}

fn default_postgres_connect_timeout_secs() -> u64 {
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

fn default_guardrail_evaluation_retention_records() -> usize {
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
            guardrail_evaluation_retention_records: default_guardrail_evaluation_retention_records(
            ),
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
            postgres_pool_acquire_timeout_millis: default_postgres_pool_acquire_timeout_millis(),
            postgres_tls_mode: PostgresTlsMode::default(),
            postgres_tls_ca_cert_path: None,
            postgres_connect_timeout_secs: default_postgres_connect_timeout_secs(),
            postgres_statement_timeout_millis: default_postgres_statement_timeout_millis(),
            postgres_schema: None,
            postgres_search_path: Vec::new(),
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
            snapshot_signing_key: None,
            snapshot_signing_key_id: None,
            snapshot_trusted_keys: Vec::new(),
            snapshot_tenant_id: None,
            snapshot_deployment_id: None,
            snapshot_max_age_secs: default_cluster_snapshot_max_age_secs(),
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
            billing_service: BillingServiceConfig::default(),
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
            billing_alerts: BillingAlertsConfig::default(),
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
            network_access: NetworkAccessConfig::default(),
            asset_bucket: AssetBucketConfig::default(),
        }
    }
}
