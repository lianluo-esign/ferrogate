use anyhow::{bail, Context, Result as AnyResult};
use async_trait::async_trait;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode, Uri};
use pingora::{
    http::{RequestHeader, ResponseHeader},
    prelude::HttpPeer,
    proxy::{http_proxy_service, ProxyHttp, Session},
    server::{configuration::Opt as PingoraOpt, Server},
    Result as PingoraResult,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
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
    /// Start the FerroGate Pingora gateway server.
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
    #[serde(default)]
    upstreams: Vec<Upstream>,
    #[serde(default)]
    routes: Vec<RouteRule>,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Upstream {
    name: String,
    url: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RouteRule {
    name: String,
    upstream: String,
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default)]
    path_prefixes: Vec<String>,
    #[serde(default)]
    strip_prefix: Option<String>,
    #[serde(default)]
    add_prefix: Option<String>,
    #[serde(default)]
    request_headers: Vec<HeaderMutation>,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct HeaderMutation {
    name: String,
    value: String,
}

#[derive(Debug, Clone)]
struct AppState {
    config: Arc<Config>,
    providers: Arc<HashMap<String, Provider>>,
    models: Arc<HashMap<String, Model>>,
    upstreams: Arc<HashMap<String, Upstream>>,
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

#[derive(Debug, Default, Clone)]
struct ProxyContext {
    request_id: String,
    route: Option<RouteRule>,
    upstream: Option<Upstream>,
    target_path_query: Option<String>,
    original_host: Option<String>,
}

#[derive(Debug, Clone)]
struct FerroGateway {
    state: AppState,
}

#[derive(Debug, Clone)]
struct UpstreamEndpoint {
    scheme: String,
    host: String,
    port: u16,
    authority: String,
    base_path: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse<'a> {
    status: &'a str,
    service: &'a str,
    version: &'a str,
    runtime: &'a str,
}

#[derive(Debug, Serialize)]
struct AdminStatus<'a> {
    service: &'a str,
    version: &'a str,
    runtime: &'a str,
    providers: usize,
    enabled_providers: usize,
    models: usize,
    enabled_models: usize,
    api_keys: usize,
    upstreams: usize,
    enabled_upstreams: usize,
    routes: usize,
    enabled_routes: usize,
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
    "openai".to_string()
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
            upstreams: Vec::new(),
            routes: Vec::new(),
        }
    }
}

impl Config {
    fn load(path: &PathBuf) -> AnyResult<Self> {
        if !path.exists() {
            warn!(
                config = %path.display(),
                "configuration file not found; using built-in defaults"
            );
            return Ok(Self::default());
        }

        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let config: Self = toml::from_str(&raw)
            .with_context(|| format!("failed to parse config file {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> AnyResult<()> {
        self.listen
            .parse::<std::net::SocketAddr>()
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
        }

        let mut key_ids = HashSet::new();
        for key in &self.api_keys {
            if key.id.trim().is_empty() {
                bail!("api key id cannot be empty");
            }
            if !key_ids.insert(key.id.as_str()) {
                bail!("duplicate api key id: {}", key.id);
            }
            for allowed_model in &key.allowed_models {
                if !model_names.contains(allowed_model.as_str()) {
                    bail!("api key {} allows unknown model {}", key.id, allowed_model);
                }
            }
        }

        let mut upstream_names = HashSet::new();
        for upstream in &self.upstreams {
            if upstream.name.trim().is_empty() {
                bail!("upstream name cannot be empty");
            }
            if !upstream_names.insert(upstream.name.as_str()) {
                bail!("duplicate upstream name: {}", upstream.name);
            }
            parse_upstream_endpoint(&upstream.url)
                .with_context(|| format!("upstream {} has invalid url", upstream.name))?;
        }

        let mut route_names = HashSet::new();
        for route in &self.routes {
            if route.name.trim().is_empty() {
                bail!("route name cannot be empty");
            }
            if !route_names.insert(route.name.as_str()) {
                bail!("duplicate route name: {}", route.name);
            }
            if !upstream_names.contains(route.upstream.as_str()) {
                bail!(
                    "route {} references unknown upstream {}",
                    route.name,
                    route.upstream
                );
            }
            for prefix in route.path_prefixes.iter().chain(route.strip_prefix.iter()) {
                if !prefix.starts_with('/') {
                    bail!("route {} path prefix must start with /", route.name);
                }
            }
            if let Some(add_prefix) = &route.add_prefix {
                if !add_prefix.starts_with('/') {
                    bail!("route {} add_prefix must start with /", route.name);
                }
            }
            for header in &route.request_headers {
                HeaderName::from_bytes(header.name.as_bytes()).with_context(|| {
                    format!(
                        "route {} has invalid header name {}",
                        route.name, header.name
                    )
                })?;
                HeaderValue::from_str(&header.value).with_context(|| {
                    format!(
                        "route {} has invalid header value for {}",
                        route.name, header.name
                    )
                })?;
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
        let upstreams = config
            .upstreams
            .iter()
            .cloned()
            .map(|upstream| (upstream.name.clone(), upstream))
            .collect();

        Self {
            config: Arc::new(config),
            providers: Arc::new(providers),
            models: Arc::new(models),
            upstreams: Arc::new(upstreams),
            request_ids: Arc::new(AtomicU64::new(1)),
        }
    }

    fn next_request_id(&self) -> String {
        let next = self.request_ids.fetch_add(1, Ordering::Relaxed);
        format!("fg-{next:016x}")
    }

    fn auth_required(&self) -> bool {
        !self.config.api_keys.is_empty()
    }
}

fn main() -> AnyResult<()> {
    init_tracing();
    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;

    match cli.command.unwrap_or(Commands::Serve) {
        Commands::Serve => serve(config),
        Commands::Check => {
            println!(
                "FerroGate config OK: listen={}, runtime=pingora, upstreams={}, routes={}, providers={}, models={}, api_keys={}, auth_required={}",
                config.listen,
                config.upstreams.len(),
                config.routes.len(),
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
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .try_init();
}

fn serve(config: Config) -> AnyResult<()> {
    let listen = config.listen.clone();
    let state = AppState::new(config);
    let gateway = FerroGateway { state };

    let mut server =
        Server::new(Some(PingoraOpt::default())).context("failed to create Pingora server")?;
    server.bootstrap();

    let mut service = http_proxy_service(&server.configuration, gateway);
    service.add_tcp(&listen);
    server.add_service(service);

    info!(listen = %listen, runtime = "pingora", "FerroGate Pingora gateway listening");
    server.run_forever();
}

#[async_trait]
impl ProxyHttp for FerroGateway {
    type CTX = ProxyContext;

    fn new_ctx(&self) -> Self::CTX {
        ProxyContext::default()
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<bool>
    where
        Self::CTX: Send + Sync,
    {
        ctx.request_id = self.state.next_request_id();
        let req = session.req_header();
        let path = req.uri.path().to_string();

        if path == "/healthz" {
            let body = HealthResponse {
                status: "ok",
                service: env!("CARGO_PKG_NAME"),
                version: env!("CARGO_PKG_VERSION"),
                runtime: "pingora",
            };
            write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await?;
            return Ok(true);
        }

        if path == "/v1/models" {
            match authenticate(&self.state, &req.headers, "models.read", &ctx.request_id) {
                Ok(_) => {
                    let data = self
                        .state
                        .config
                        .models
                        .iter()
                        .filter(|model| model.enabled)
                        .map(|model| OpenAiModel {
                            id: model.name.clone(),
                            object: "model",
                            created: 0,
                            owned_by: model.provider.clone(),
                        })
                        .collect();
                    write_json_response(
                        session,
                        StatusCode::OK,
                        &OpenAiModelList {
                            object: "list",
                            data,
                        },
                        &ctx.request_id,
                    )
                    .await?;
                }
                Err(error) => {
                    write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
                        &ctx.request_id,
                    )
                    .await?
                }
            }
            return Ok(true);
        }

        if path == "/v1/chat/completions" {
            self.handle_chat_completions(session, ctx, req.headers.clone())
                .await?;
            return Ok(true);
        }

        if path == "/admin/status" {
            match authenticate(&self.state, &req.headers, "admin.read", &ctx.request_id) {
                Ok(_) => {
                    let status = AdminStatus {
                        service: env!("CARGO_PKG_NAME"),
                        version: env!("CARGO_PKG_VERSION"),
                        runtime: "pingora",
                        providers: self.state.config.providers.len(),
                        enabled_providers: self
                            .state
                            .config
                            .providers
                            .iter()
                            .filter(|p| p.enabled)
                            .count(),
                        models: self.state.config.models.len(),
                        enabled_models: self
                            .state
                            .config
                            .models
                            .iter()
                            .filter(|m| m.enabled)
                            .count(),
                        api_keys: self.state.config.api_keys.len(),
                        upstreams: self.state.config.upstreams.len(),
                        enabled_upstreams: self
                            .state
                            .config
                            .upstreams
                            .iter()
                            .filter(|u| u.enabled)
                            .count(),
                        routes: self.state.config.routes.len(),
                        enabled_routes: self
                            .state
                            .config
                            .routes
                            .iter()
                            .filter(|r| r.enabled)
                            .count(),
                        auth_required: self.state.auth_required(),
                    };
                    write_json_response(session, StatusCode::OK, &status, &ctx.request_id).await?;
                }
                Err(error) => {
                    write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
                        &ctx.request_id,
                    )
                    .await?
                }
            }
            return Ok(true);
        }

        let host = req
            .headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let normalized_host = host
            .as_deref()
            .map(normalize_host)
            .filter(|value| !value.is_empty());

        let Some(route) = self
            .state
            .config
            .routes
            .iter()
            .filter(|route| route.enabled)
            .find(|route| route.matches(normalized_host.as_deref(), &path))
            .cloned()
        else {
            write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "route_not_found",
                format!("no route matched {} {}", req.method, path),
                &ctx.request_id,
            )
            .await?;
            return Ok(true);
        };

        let Some(upstream) = self.state.upstreams.get(&route.upstream).cloned() else {
            write_json_error(
                session,
                StatusCode::BAD_GATEWAY,
                "upstream_not_found",
                format!(
                    "route {} references missing upstream {}",
                    route.name, route.upstream
                ),
                &ctx.request_id,
            )
            .await?;
            return Ok(true);
        };

        if !upstream.enabled {
            write_json_error(
                session,
                StatusCode::BAD_GATEWAY,
                "upstream_disabled",
                format!("upstream {} is disabled", upstream.name),
                &ctx.request_id,
            )
            .await?;
            return Ok(true);
        }

        match build_target_path_query(&upstream, &route, &path, req.uri.query()) {
            Ok(path_query) => {
                ctx.original_host = host;
                ctx.target_path_query = Some(path_query);
                ctx.route = Some(route);
                ctx.upstream = Some(upstream);
                Ok(false)
            }
            Err(error) => {
                write_json_error(
                    session,
                    StatusCode::BAD_GATEWAY,
                    "target_url_error",
                    error.to_string(),
                    &ctx.request_id,
                )
                .await?;
                Ok(true)
            }
        }
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<Box<HttpPeer>> {
        let upstream = ctx.upstream.as_ref().expect("matched upstream exists");
        let endpoint = parse_upstream_endpoint(&upstream.url).expect("validated upstream url");
        let tls = endpoint.scheme == "https";
        let peer = HttpPeer::new(
            (endpoint.host.as_str(), endpoint.port),
            tls,
            endpoint.host.clone(),
        );
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()>
    where
        Self::CTX: Send + Sync,
    {
        let upstream = ctx.upstream.as_ref().expect("matched upstream exists");
        let route = ctx.route.as_ref().expect("matched route exists");
        let endpoint = parse_upstream_endpoint(&upstream.url).expect("validated upstream url");
        let target = ctx
            .target_path_query
            .as_deref()
            .expect("target path query exists");
        let uri: Uri = target.parse().expect("valid target path query");
        upstream_request.set_uri(uri);
        upstream_request.insert_header(header::HOST, endpoint.authority)?;
        upstream_request.insert_header("x-ferrogate-request-id", ctx.request_id.as_str())?;
        if let Some(original_host) = &ctx.original_host {
            upstream_request.insert_header("x-forwarded-host", original_host.as_str())?;
        }
        for header in &route.request_headers {
            let name =
                HeaderName::from_bytes(header.name.as_bytes()).expect("validated header name");
            let value = HeaderValue::from_str(&header.value).expect("validated header value");
            upstream_request.insert_header(name, value)?;
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()>
    where
        Self::CTX: Send + Sync,
    {
        upstream_response.insert_header("server", "FerroGate")?;
        upstream_response.insert_header("x-ferrogate-runtime", "pingora")?;
        upstream_response.insert_header("x-request-id", ctx.request_id.as_str())?;
        Ok(())
    }

    async fn logging(
        &self,
        session: &mut Session,
        error: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        let response_code = session
            .response_written()
            .map_or(0, |resp| resp.status.as_u16());
        if let Some(error) = error {
            warn!(request_id = %ctx.request_id, response_code, error = ?error, "Pingora request failed");
        } else {
            info!(request_id = %ctx.request_id, response_code, "Pingora request completed");
        }
    }
}

impl FerroGateway {
    async fn handle_chat_completions(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: HeaderMap,
    ) -> PingoraResult<()> {
        let auth = match authenticate(&self.state, &headers, "chat.completions", &ctx.request_id) {
            Ok(auth) => auth,
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            }
        };

        let body = read_request_body(session, 1024 * 1024).await?;
        let request: ChatCompletionRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => {
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_json",
                    format!("invalid JSON body: {error}"),
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            }
        };

        if !auth.can_use_model(&request.model) {
            write_json_error(
                session,
                StatusCode::FORBIDDEN,
                "model_not_allowed",
                format!("API key is not allowed to use model {}", request.model),
                &ctx.request_id,
            )
            .await?;
            return Ok(());
        }

        let Some(model) = self.state.models.get(&request.model) else {
            write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "model_not_found",
                format!("unknown model {}", request.model),
                &ctx.request_id,
            )
            .await?;
            return Ok(());
        };

        let Some(provider) = self.state.providers.get(&model.provider) else {
            write_json_error(
                session,
                StatusCode::BAD_GATEWAY,
                "provider_not_found",
                format!("provider {} not found", model.provider),
                &ctx.request_id,
            )
            .await?;
            return Ok(());
        };

        let response = json!({
            "error": {
                "message": "chat completion proxying is not implemented yet; Pingora runtime, auth, tenant context, and model routing are ready",
                "type": "ferrogate_not_implemented",
                "code": "provider_proxy_pending",
                "request_id": ctx.request_id,
            },
            "routing": {
                "provider": provider.name,
                "provider_kind": provider.kind,
                "provider_model": model.provider_model,
                "stream": request.stream,
                "extra_fields_seen": request.extra.as_object().map(|o| o.len()).unwrap_or(0),
                "api_key_id": auth.api_key_id,
                "organization_id": auth.organization_id,
                "team_id": auth.team_id,
                "project_id": auth.project_id,
                "user_id": auth.user_id,
            }
        });
        write_json_response(
            session,
            StatusCode::NOT_IMPLEMENTED,
            &response,
            &ctx.request_id,
        )
        .await
    }
}

impl AuthContext {
    fn has_scope(&self, scope: &str) -> bool {
        self.scopes.is_empty() || self.scopes.contains(scope)
    }

    fn can_use_model(&self, model: &str) -> bool {
        self.allowed_models.is_empty() || self.allowed_models.contains(model)
    }
}

#[derive(Debug)]
struct AuthError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    required_scope: &str,
    _request_id: &str,
) -> std::result::Result<AuthContext, AuthError> {
    if !state.auth_required() {
        return Ok(AuthContext {
            api_key_id: None,
            scopes: HashSet::new(),
            allowed_models: HashSet::new(),
            organization_id: None,
            team_id: None,
            project_id: None,
            user_id: None,
        });
    }

    let Some(provided_key) = extract_api_key(headers) else {
        return Err(AuthError {
            status: StatusCode::UNAUTHORIZED,
            code: "missing_api_key",
            message: "missing API key; use Authorization: Bearer or x-api-key".into(),
        });
    };

    for configured_key in &state.config.api_keys {
        if !configured_key.enabled {
            continue;
        }
        if let Some(secret) = configured_key.secret_value() {
            if constant_time_eq(provided_key.as_bytes(), secret.as_bytes()) {
                let auth = AuthContext {
                    api_key_id: Some(configured_key.id.clone()),
                    scopes: configured_key.scopes.iter().cloned().collect(),
                    allowed_models: configured_key.allowed_models.iter().cloned().collect(),
                    organization_id: configured_key.organization_id.clone(),
                    team_id: configured_key.team_id.clone(),
                    project_id: configured_key.project_id.clone(),
                    user_id: configured_key.user_id.clone(),
                };
                if !auth.has_scope(required_scope) {
                    return Err(AuthError {
                        status: StatusCode::FORBIDDEN,
                        code: "scope_denied",
                        message: format!("API key does not have required scope {required_scope}"),
                    });
                }
                return Ok(auth);
            }
        }
    }

    Err(AuthError {
        status: StatusCode::UNAUTHORIZED,
        code: "invalid_api_key",
        message: "invalid API key".into(),
    })
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

async fn read_request_body(session: &mut Session, max_bytes: usize) -> PingoraResult<Bytes> {
    let mut body = Vec::new();
    while let Some(chunk) = session.as_downstream_mut().read_request_body().await? {
        if body.len() + chunk.len() > max_bytes {
            break;
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(body))
}

async fn write_json_response<T: Serialize>(
    session: &mut Session,
    status: StatusCode,
    value: &T,
    request_id: &str,
) -> PingoraResult<()> {
    let body = serde_json::to_vec(value).expect("JSON serialization should not fail");
    let mut response = ResponseHeader::build(status, Some(4))?;
    response.insert_header(header::CONTENT_TYPE, "application/json")?;
    response.insert_header(header::CONTENT_LENGTH, body.len().to_string())?;
    response.insert_header("x-request-id", request_id)?;
    response.insert_header("x-ferrogate-runtime", "pingora")?;
    session
        .write_response_header(Box::new(response), false)
        .await?;
    session
        .write_response_body(Some(Bytes::from(body)), true)
        .await
}

async fn write_json_error(
    session: &mut Session,
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
    request_id: &str,
) -> PingoraResult<()> {
    let body = ErrorBody {
        error: ErrorObject {
            message: message.into(),
            kind: "ferrogate_error",
            code,
            request_id: Some(request_id.to_string()),
        },
    };
    write_json_response(session, status, &body, request_id).await
}

impl RouteRule {
    fn matches(&self, host: Option<&str>, path: &str) -> bool {
        if !self.hosts.is_empty() {
            let Some(host) = host else {
                return false;
            };
            if !self
                .hosts
                .iter()
                .any(|configured| configured.eq_ignore_ascii_case(host))
            {
                return false;
            }
        }

        self.path_prefixes.is_empty()
            || self.path_prefixes.iter().any(|prefix| {
                path == prefix || path.starts_with(&format!("{}/", prefix.trim_end_matches('/')))
            })
    }

    fn rewrite_path(&self, original_path: &str) -> String {
        let mut path = original_path.to_string();
        if let Some(strip_prefix) = &self.strip_prefix {
            if path == *strip_prefix {
                path = "/".to_string();
            } else if path.starts_with(&format!("{}/", strip_prefix.trim_end_matches('/'))) {
                path = path[strip_prefix.len()..].to_string();
                path = ensure_leading_slash(&path);
            }
        }
        if let Some(add_prefix) = &self.add_prefix {
            path = join_url_path(add_prefix, &path);
        }
        ensure_leading_slash(&path)
    }
}

fn normalize_host(host: &str) -> String {
    host.split(':')
        .next()
        .unwrap_or(host)
        .trim()
        .to_ascii_lowercase()
}

fn parse_upstream_endpoint(raw: &str) -> AnyResult<UpstreamEndpoint> {
    let uri: Uri = raw
        .parse()
        .with_context(|| format!("invalid upstream URL {raw}"))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| anyhow::anyhow!("upstream URL must include scheme"))?
        .to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        bail!("upstream URL scheme must be http or https");
    }
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("upstream URL must include authority"))?;
    let host = authority.host().to_string();
    let port = authority
        .port_u16()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    let default_port = (scheme == "https" && port == 443) || (scheme == "http" && port == 80);
    let authority = if default_port {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let base_path = uri.path().trim_end_matches('/').to_string();
    Ok(UpstreamEndpoint {
        scheme,
        host,
        port,
        authority,
        base_path,
    })
}

#[cfg(test)]
fn build_target_url(
    upstream: &Upstream,
    route: &RouteRule,
    original_path: &str,
    query: Option<&str>,
) -> AnyResult<String> {
    let endpoint = parse_upstream_endpoint(&upstream.url)?;
    let path_query = build_target_path_query(upstream, route, original_path, query)?;
    Ok(format!(
        "{}://{}{}",
        endpoint.scheme, endpoint.authority, path_query
    ))
}

fn build_target_path_query(
    upstream: &Upstream,
    route: &RouteRule,
    original_path: &str,
    query: Option<&str>,
) -> AnyResult<String> {
    let endpoint = parse_upstream_endpoint(&upstream.url)?;
    let rewritten = route.rewrite_path(original_path);
    let mut path = join_url_path(&endpoint.base_path, &rewritten);
    if let Some(query) = query {
        if !query.is_empty() {
            path.push('?');
            path.push_str(query);
        }
    }
    let _: Uri = path
        .parse()
        .with_context(|| format!("invalid target path {path}"))?;
    Ok(path)
}

fn ensure_leading_slash(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn join_url_path(left: &str, right: &str) -> String {
    let left = left.trim_end_matches('/');
    let right = right.trim_start_matches('/');
    match (left.is_empty(), right.is_empty()) {
        (true, true) => "/".to_string(),
        (true, false) => format!("/{right}"),
        (false, true) => left.to_string(),
        (false, false) => format!("{left}/{right}"),
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
        assert!(config.upstreams.is_empty());
        assert!(config.routes.is_empty());
    }

    #[test]
    fn parses_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ferrogate.toml");
        std::fs::write(
            &path,
            r#"
listen = "0.0.0.0:8080"

[[upstreams]]
name = "example"
url = "https://example.com/base"

[[routes]]
name = "example"
upstream = "example"
path_prefixes = ["/proxy"]
strip_prefix = "/proxy"

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
        assert_eq!(config.upstreams.len(), 1);
        assert_eq!(config.routes.len(), 1);
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

    #[test]
    fn route_matches_host_and_path_prefix() {
        let route = RouteRule {
            name: "api".into(),
            upstream: "backend".into(),
            hosts: vec!["api.example.com".into()],
            path_prefixes: vec!["/api".into()],
            strip_prefix: None,
            add_prefix: None,
            request_headers: vec![],
            enabled: true,
        };

        assert!(route.matches(Some("api.example.com"), "/api/users"));
        assert!(!route.matches(Some("www.example.com"), "/api/users"));
        assert!(!route.matches(Some("api.example.com"), "/admin"));
    }

    #[test]
    fn route_rewrites_path_with_strip_and_add_prefix() {
        let route = RouteRule {
            name: "api".into(),
            upstream: "backend".into(),
            hosts: vec![],
            path_prefixes: vec!["/proxy".into()],
            strip_prefix: Some("/proxy".into()),
            add_prefix: Some("/v1".into()),
            request_headers: vec![],
            enabled: true,
        };

        assert_eq!(route.rewrite_path("/proxy/users"), "/v1/users");
        assert_eq!(route.rewrite_path("/proxy"), "/v1");
    }

    #[test]
    fn builds_target_url_with_query() {
        let upstream = Upstream {
            name: "backend".into(),
            url: "https://example.com/base".into(),
            enabled: true,
        };
        let route = RouteRule {
            name: "api".into(),
            upstream: "backend".into(),
            hosts: vec![],
            path_prefixes: vec!["/proxy".into()],
            strip_prefix: Some("/proxy".into()),
            add_prefix: None,
            request_headers: vec![],
            enabled: true,
        };

        let url = build_target_url(&upstream, &route, "/proxy/users", Some("page=1")).unwrap();
        assert_eq!(url, "https://example.com/base/users?page=1");
    }

    #[test]
    fn parses_upstream_endpoint_defaults_ports() {
        let https = parse_upstream_endpoint("https://example.com/base").unwrap();
        assert_eq!(https.scheme, "https");
        assert_eq!(https.host, "example.com");
        assert_eq!(https.port, 443);
        assert_eq!(https.authority, "example.com");
        assert_eq!(https.base_path, "/base");

        let http = parse_upstream_endpoint("http://127.0.0.1:18080").unwrap();
        assert_eq!(http.scheme, "http");
        assert_eq!(http.port, 18080);
        assert_eq!(http.authority, "127.0.0.1:18080");
    }

    #[test]
    fn rejects_route_with_unknown_upstream() {
        let config = Config {
            routes: vec![RouteRule {
                name: "api".into(),
                upstream: "missing".into(),
                hosts: vec![],
                path_prefixes: vec!["/".into()],
                strip_prefix: None,
                add_prefix: None,
                request_headers: vec![],
                enabled: true,
            }],
            ..Config::default()
        };

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("unknown upstream"));
    }
}
