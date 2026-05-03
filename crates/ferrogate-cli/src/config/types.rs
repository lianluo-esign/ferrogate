use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Config {
    #[serde(default = "default_listen")]
    pub(crate) listen: String,
    #[serde(default)]
    pub(crate) admin: AdminConfig,
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
    pub(crate) upstreams: Vec<Upstream>,
    #[serde(default)]
    pub(crate) routes: Vec<RouteRule>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct AdminConfig {
    #[serde(default)]
    pub(crate) listen: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Provider {
    pub(crate) name: String,
    #[serde(default = "default_provider_kind")]
    pub(crate) kind: String,
    pub(crate) base_url: String,
    #[serde(default)]
    pub(crate) api_key_env: Option<String>,
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
    pub(crate) allowed_providers: Vec<String>,
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
    pub(crate) otlp_endpoint: Option<String>,
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

fn default_policy_effect() -> String {
    "deny".to_string()
}

fn default_policy_code() -> String {
    "policy_denied".to_string()
}

fn default_policy_message() -> String {
    "request denied by policy".to_string()
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: default_service_name(),
            log_bodies: false,
            otlp_endpoint: None,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            admin: AdminConfig::default(),
            providers: Vec::new(),
            models: Vec::new(),
            api_keys: Vec::new(),
            policies: Vec::new(),
            telemetry: TelemetryConfig::default(),
            upstreams: Vec::new(),
            routes: Vec::new(),
        }
    }
}
