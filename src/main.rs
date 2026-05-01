use anyhow::{bail, Context, Result};
use axum::{
    extract::{Extension, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Debug, Parser)]
#[command(name = "ferrogate")]
#[command(
    author,
    version,
    about = "FerroGate, the open-source Rust API Gateway and AI Gateway"
)]
struct Cli {
    #[arg(
        short,
        long,
        env = "FERROGATE_CONFIG",
        default_value = "ferrogate.toml"
    )]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Start the FerroGate server.
    Serve,
    /// Validate configuration and print a summary.
    Check,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Config {
    #[serde(default = "default_listen")]
    listen: String,
    #[serde(default)]
    providers: Vec<Provider>,
    #[serde(default)]
    models: Vec<Model>,
    #[serde(default)]
    api_keys: Vec<ApiKey>,
    #[serde(default)]
    telemetry: TelemetryConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Provider {
    name: String,
    #[serde(default = "default_provider_kind")]
    kind: String,
    base_url: String,
    #[serde(default)]
    api_key_env: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Model {
    /// Logical model name exposed by FerroGate clients.
    name: String,
    /// Provider name from [[providers]].
    provider: String,
    /// Actual model name sent to the upstream provider.
    provider_model: String,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    context_window: Option<u32>,
    #[serde(default)]
    input_price_per_1m: Option<f64>,
    #[serde(default)]
    output_price_per_1m: Option<f64>,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ApiKey {
    /// Stable non-secret identifier used in logs and audit records.
    id: String,
    name: String,
    /// Environment variable containing the secret value. Preferred for real use.
    #[serde(default)]
    key_env: Option<String>,
    /// Plain value for local development only. Do not use in production.
    #[serde(default)]
    key: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    allowed_models: Vec<String>,
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default)]
    team_id: Option<String>,
    #[serde(default)]
    project_id: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    monthly_token_budget: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct TelemetryConfig {
    #[serde(default = "default_service_name")]
    service_name: String,
    #[serde(default)]
    log_bodies: bool,
}

#[derive(Debug, Clone)]
struct AppState {
    config: Arc<Config>,
    providers: Arc<HashMap<String, Provider>>,
    models: Arc<HashMap<String, Model>>,
    request_ids: Arc<AtomicU64>,
}

#[derive(Debug, Clone)]
struct AuthContext {
    api_key_id: Option<String>,
    scopes: HashSet<String>,
    allowed_models: HashSet<String>,
    organization_id: Option<String>,
    team_id: Option<String>,
    project_id: Option<String>,
    user_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct HealthResponse<'a> {
    status: &'a str,
    service: &'a str,
    version: &'a str,
}

#[derive(Debug, Serialize)]
struct AdminStatus<'a> {
    service: &'a str,
    version: &'a str,
    providers: usize,
    enabled_providers: usize,
    models: usize,
    enabled_models: usize,
    api_keys: usize,
    auth_required: bool,
}

#[derive(Debug, Serialize)]
struct OpenAiModelList {
    object: &'static str,
    data: Vec<OpenAiModel>,
}

#[derive(Debug, Serialize)]
struct OpenAiModel {
    id: String,
    object: &'static str,
    created: u64,
    owned_by: String,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionRequest {
    model: String,
    #[serde(default)]
    stream: bool,
    #[serde(flatten)]
    extra: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: ErrorObject,
}

#[derive(Debug, Serialize)]
struct ErrorObject {
    message: String,
    #[serde(rename = "type")]
    kind: &'static str,
    code: &'static str,
    request_id: Option<String>,
}

fn default_listen() -> String {
    "127.0.0.1:8080".to_string()
}

fn default_provider_kind() -> String {
    "openai-compatible".to_string()
}

fn default_service_name() -> String {
    "ferrogate".to_string()
}

fn default_true() -> bool {
    true
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: default_service_name(),
            log_bodies: false,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            providers: Vec::new(),
            models: Vec::new(),
            api_keys: Vec::new(),
            telemetry: TelemetryConfig::default(),
        }
    }
}

impl Config {
    fn load(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let config: Self = toml::from_str(&raw)
            .with_context(|| format!("failed to parse config file {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        self.listen
            .parse::<SocketAddr>()
            .with_context(|| format!("invalid listen address: {}", self.listen))?;

        let mut provider_names = HashSet::new();
        for provider in &self.providers {
            if provider.name.trim().is_empty() {
                bail!("provider name cannot be empty");
            }
            if !provider_names.insert(provider.name.as_str()) {
                bail!("duplicate provider name: {}", provider.name);
            }
            if provider.base_url.trim().is_empty() {
                bail!("provider {} base_url cannot be empty", provider.name);
            }
        }

        let mut model_names = HashSet::new();
        for model in &self.models {
            if model.name.trim().is_empty() {
                bail!("model name cannot be empty");
            }
            if !model_names.insert(model.name.as_str()) {
                bail!("duplicate model name: {}", model.name);
            }
            if !provider_names.contains(model.provider.as_str()) {
                bail!(
                    "model {} references unknown provider {}",
                    model.name,
                    model.provider
                );
            }
            if model.provider_model.trim().is_empty() {
                bail!("model {} provider_model cannot be empty", model.name);
            }
        }

        let mut key_ids = HashSet::new();
        for key in &self.api_keys {
            if key.id.trim().is_empty() {
                bail!("api key id cannot be empty");
            }
            if !key_ids.insert(key.id.as_str()) {
                bail!("duplicate api key id: {}", key.id);
            }
            if key.key.is_none() && key.key_env.is_none() {
                bail!("api key {} must set key_env or key", key.id);
            }
            for model in &key.allowed_models {
                if !model_names.contains(model.as_str()) {
                    bail!("api key {} allows unknown model {}", key.id, model);
                }
            }
        }

        Ok(())
    }
}

impl AppState {
    fn new(config: Config) -> Self {
        let providers = config
            .providers
            .iter()
            .cloned()
            .map(|provider| (provider.name.clone(), provider))
            .collect();
        let models = config
            .models
            .iter()
            .cloned()
            .map(|model| (model.name.clone(), model))
            .collect();

        Self {
            config: Arc::new(config),
            providers: Arc::new(providers),
            models: Arc::new(models),
            request_ids: Arc::new(AtomicU64::new(1)),
        }
    }

    fn next_request_id(&self) -> String {
        let id = self.request_ids.fetch_add(1, Ordering::Relaxed);
        format!("fg_{id:016x}")
    }

    fn auth_required(&self) -> bool {
        !self.config.api_keys.is_empty()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;

    match cli.command.unwrap_or(Commands::Serve) {
        Commands::Serve => serve(config).await,
        Commands::Check => {
            println!(
                "FerroGate config OK: listen={}, providers={}, models={}, api_keys={}, auth_required={}",
                config.listen,
                config.providers.len(),
                config.models.len(),
                config.api_keys.len(),
                !config.api_keys.is_empty()
            );
            Ok(())
        }
    }
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();
}

async fn serve(config: Config) -> Result<()> {
    let addr: SocketAddr = config
        .listen
        .parse()
        .with_context(|| format!("invalid listen address: {}", config.listen))?;
    let state = AppState::new(config);
    let app = build_router(state);

    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "FerroGate is listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/models", get(models))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/admin/status", get(admin_status))
        .layer(middleware::from_fn_with_state(state.clone(), request_id))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn request_id(State(state): State<AppState>, mut request: Request, next: Next) -> Response {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| state.next_request_id());

    request.extensions_mut().insert(request_id.clone());
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

async fn healthz() -> Json<HealthResponse<'static>> {
    Json(HealthResponse {
        status: "ok",
        service: "ferrogate",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn admin_status(
    State(state): State<AppState>,
    Extension(request_id): Extension<String>,
    headers: HeaderMap,
) -> Response {
    let auth = match authenticate(&state, &headers, &request_id) {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    if state.auth_required() && !auth.scopes.contains("admin.read") {
        return api_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "admin.read scope is required",
            request_id,
        );
    }

    let response = AdminStatus {
        service: "ferrogate",
        version: env!("CARGO_PKG_VERSION"),
        providers: state.config.providers.len(),
        enabled_providers: state.config.providers.iter().filter(|p| p.enabled).count(),
        models: state.config.models.len(),
        enabled_models: state.config.models.iter().filter(|m| m.enabled).count(),
        api_keys: state.config.api_keys.len(),
        auth_required: state.auth_required(),
    };
    Json(response).into_response()
}

async fn models(
    State(state): State<AppState>,
    Extension(request_id): Extension<String>,
    headers: HeaderMap,
) -> Response {
    let auth = match authenticate(&state, &headers, &request_id) {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    if state.auth_required() && !auth.scopes.contains("models.read") {
        return api_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "models.read scope is required",
            request_id,
        );
    }

    let mut data: Vec<_> = state
        .config
        .models
        .iter()
        .filter(|model| model.enabled)
        .filter(|model| auth.can_use_model(&model.name))
        .map(|model| OpenAiModel {
            id: model.name.clone(),
            object: "model",
            created: 0,
            owned_by: model.provider.clone(),
        })
        .collect();
    data.sort_by(|left, right| left.id.cmp(&right.id));

    Json(OpenAiModelList {
        object: "list",
        data,
    })
    .into_response()
}

async fn chat_completions(
    State(state): State<AppState>,
    Extension(request_id): Extension<String>,
    headers: HeaderMap,
    Json(payload): Json<ChatCompletionRequest>,
) -> Response {
    let auth = match authenticate(&state, &headers, &request_id) {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    if state.auth_required() && !auth.scopes.contains("chat.completions") {
        return api_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "chat.completions scope is required",
            request_id,
        );
    }

    if !auth.can_use_model(&payload.model) {
        return api_error(
            StatusCode::FORBIDDEN,
            "model_not_allowed",
            format!("model {} is not allowed for this API key", payload.model),
            request_id,
        );
    }

    let Some(model) = state.models.get(&payload.model) else {
        return api_error(
            StatusCode::NOT_FOUND,
            "model_not_found",
            format!("model {} is not configured", payload.model),
            request_id,
        );
    };

    if !model.enabled {
        return api_error(
            StatusCode::NOT_FOUND,
            "model_disabled",
            format!("model {} is disabled", payload.model),
            request_id,
        );
    }

    let Some(provider) = state.providers.get(&model.provider) else {
        return api_error(
            StatusCode::BAD_GATEWAY,
            "provider_not_found",
            format!("provider {} is not configured", model.provider),
            request_id,
        );
    };

    let api_key_id = auth.api_key_id.as_deref().unwrap_or("anonymous");
    info!(
        request_id = %request_id,
        api_key_id,
        organization_id = ?auth.organization_id,
        team_id = ?auth.team_id,
        project_id = ?auth.project_id,
        user_id = ?auth.user_id,
        logical_model = %model.name,
        provider = %provider.name,
        provider_model = %model.provider_model,
        stream = payload.stream,
        "chat completions request accepted by gateway pipeline"
    );

    let mut response = Json(json!({
        "error": {
            "message": "upstream proxying is not implemented yet; the request passed authentication, tenant context resolution, and model routing",
            "type": "not_implemented_error",
            "code": "upstream_proxy_not_implemented",
            "request_id": request_id,
            "routing": {
                "logical_model": model.name,
                "provider": provider.name,
                "provider_model": model.provider_model,
                "provider_kind": provider.kind,
                "provider_base_url": provider.base_url,
                "stream": payload.stream,
                "extra_fields_present": !payload.extra.is_null()
            }
        }
    }))
    .into_response();
    *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
    response
}

impl AuthContext {
    fn anonymous() -> Self {
        Self {
            api_key_id: None,
            scopes: HashSet::new(),
            allowed_models: HashSet::new(),
            organization_id: None,
            team_id: None,
            project_id: None,
            user_id: None,
        }
    }

    fn can_use_model(&self, model: &str) -> bool {
        self.allowed_models.is_empty() || self.allowed_models.contains(model)
    }
}

fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    request_id: &str,
) -> std::result::Result<AuthContext, Response> {
    if !state.auth_required() {
        return Ok(AuthContext::anonymous());
    }

    let Some(secret) = extract_api_key(headers) else {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "missing_api_key",
            "missing bearer token or x-api-key header",
            request_id.to_string(),
        ));
    };

    for configured_key in &state.config.api_keys {
        if !configured_key.enabled {
            continue;
        }
        let Some(expected) = configured_key.secret_value() else {
            continue;
        };
        if constant_time_eq(secret.as_bytes(), expected.as_bytes()) {
            if configured_key.key.is_some() {
                warn!(
                    api_key_id = %configured_key.id,
                    "api key uses inline key value; prefer key_env outside local development"
                );
            }
            return Ok(AuthContext {
                api_key_id: Some(configured_key.id.clone()),
                scopes: configured_key.scopes.iter().cloned().collect(),
                allowed_models: configured_key.allowed_models.iter().cloned().collect(),
                organization_id: configured_key.organization_id.clone(),
                team_id: configured_key.team_id.clone(),
                project_id: configured_key.project_id.clone(),
                user_id: configured_key.user_id.clone(),
            });
        }
    }

    Err(api_error(
        StatusCode::UNAUTHORIZED,
        "invalid_api_key",
        "invalid API key",
        request_id.to_string(),
    ))
}

impl ApiKey {
    fn secret_value(&self) -> Option<String> {
        if let Some(env_name) = &self.key_env {
            if let Ok(value) = std::env::var(env_name) {
                return Some(value);
            }
        }
        self.key.clone()
    }
}

fn extract_api_key(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
    {
        if !value.trim().is_empty() {
            return Some(value.trim().to_string());
        }
    }

    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    value
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn api_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
    request_id: String,
) -> Response {
    let body = ErrorBody {
        error: ErrorObject {
            message: message.into(),
            kind: "ferrogate_error",
            code,
            request_id: Some(request_id),
        },
    };
    (status, Json(body)).into_response()
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_uses_localhost_8080() {
        let config = Config::default();
        assert_eq!(config.listen, "127.0.0.1:8080");
        assert!(config.providers.is_empty());
        assert!(config.models.is_empty());
        assert!(config.api_keys.is_empty());
    }

    #[test]
    fn parses_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ferrogate.toml");
        std::fs::write(
            &path,
            r#"
listen = "0.0.0.0:8080"

[[providers]]
name = "openai"
base_url = "https://api.openai.com/v1"
api_key_env = "OPENAI_API_KEY"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat", "streaming"]
context_window = 128000
input_price_per_1m = 0.15
output_price_per_1m = 0.60

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "dev-secret"
scopes = ["models.read", "chat.completions", "admin.read"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
team_id = "team_platform"
project_id = "project_gateway"
"#,
        )
        .unwrap();

        let config = Config::load(&path).unwrap();
        assert_eq!(config.listen, "0.0.0.0:8080");
        assert_eq!(config.providers.len(), 1);
        assert_eq!(config.providers[0].name, "openai");
        assert_eq!(config.models.len(), 1);
        assert_eq!(config.models[0].name, "fast-chat");
        assert_eq!(config.api_keys.len(), 1);
        assert_eq!(config.api_keys[0].id, "key_dev");
    }

    #[test]
    fn rejects_model_with_unknown_provider() {
        let config = Config {
            models: vec![Model {
                name: "fast-chat".into(),
                provider: "missing".into(),
                provider_model: "gpt-4o-mini".into(),
                capabilities: vec![],
                context_window: None,
                input_price_per_1m: None,
                output_price_per_1m: None,
                enabled: true,
            }],
            ..Config::default()
        };

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("unknown provider"));
    }

    #[test]
    fn extracts_bearer_and_x_api_key() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer secret".parse().unwrap());
        assert_eq!(extract_api_key(&headers).as_deref(), Some("secret"));

        headers.insert("x-api-key", "other".parse().unwrap());
        assert_eq!(extract_api_key(&headers).as_deref(), Some("other"));
    }

    #[test]
    fn auth_context_model_allowlist() {
        let auth = AuthContext {
            api_key_id: Some("key".into()),
            scopes: HashSet::new(),
            allowed_models: HashSet::from(["fast-chat".into()]),
            organization_id: None,
            team_id: None,
            project_id: None,
            user_id: None,
        };
        assert!(auth.can_use_model("fast-chat"));
        assert!(!auth.can_use_model("expensive-model"));
    }
}
