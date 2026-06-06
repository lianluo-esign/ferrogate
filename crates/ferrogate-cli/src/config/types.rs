use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use ferrogate_providers::RoutingStrategy;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Config {
    #[serde(default = "default_listen")]
    pub(crate) listen: String,
    #[serde(default)]
    pub(crate) admin: AdminConfig,
    #[serde(default)]
    pub(crate) tls: TlsConfig,
    #[serde(default)]
    pub(crate) providers: Vec<Provider>,
    #[serde(default)]
    pub(crate) models: Vec<Model>,
    #[serde(default)]
    pub(crate) api_keys: Vec<ApiKey>,
    #[serde(default)]
    pub(crate) policies: Vec<PolicyRule>,
    #[serde(default)]
    pub(crate) telemetry: TelemetryConfig,
    #[serde(default)]
    pub(crate) storage: StorageConfig,
    #[serde(default)]
    pub(crate) reliability: ReliabilityConfig,
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
    #[serde(default = "default_cluster_heartbeat_interval_secs")]
    pub(crate) heartbeat_interval_secs: u64,
    #[serde(default = "default_cluster_config_poll_interval_secs")]
    pub(crate) config_poll_interval_secs: u64,
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
    #[serde(default = "default_request_log_retention_records")]
    pub(crate) request_log_retention_records: usize,
    #[serde(default = "default_audit_event_retention_records")]
    pub(crate) audit_event_retention_records: usize,
    #[serde(default = "default_billing_event_retention_records")]
    pub(crate) billing_event_retention_records: usize,
    #[serde(default = "default_admin_list_limit")]
    pub(crate) admin_list_default_limit: usize,
    #[serde(default = "default_admin_list_max_limit")]
    pub(crate) admin_list_max_limit: usize,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
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

fn default_provider_kind() -> String {
    "openai".to_string()
}

fn default_service_name() -> String {
    "ferrogate".to_string()
}

fn default_true() -> bool {
    true
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

fn default_cluster_heartbeat_interval_secs() -> u64 {
    10
}

fn default_cluster_config_poll_interval_secs() -> u64 {
    5
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

fn default_access_log_sample_rate() -> u64 {
    100
}

fn default_access_log_error_rate_limit_per_sec() -> u64 {
    100
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

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            request_log_retention_records: default_request_log_retention_records(),
            audit_event_retention_records: default_audit_event_retention_records(),
            billing_event_retention_records: default_billing_event_retention_records(),
            admin_list_default_limit: default_admin_list_limit(),
            admin_list_max_limit: default_admin_list_max_limit(),
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
            heartbeat_interval_secs: default_cluster_heartbeat_interval_secs(),
            config_poll_interval_secs: default_cluster_config_poll_interval_secs(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            admin: AdminConfig::default(),
            tls: TlsConfig::default(),
            providers: Vec::new(),
            models: Vec::new(),
            api_keys: Vec::new(),
            policies: Vec::new(),
            telemetry: TelemetryConfig::default(),
            storage: StorageConfig::default(),
            reliability: ReliabilityConfig::default(),
            cluster: ClusterConfig::default(),
            upstreams: Vec::new(),
            routes: Vec::new(),
        }
    }
}
