// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Tenant and RBAC service boundaries.
//!
//! This crate owns the optional external auth/control-plane process. The
//! gateway should consume the REST API decision output, not embed role,
//! permission, or binding evaluation in the request hot path.

use anyhow::{anyhow, Context};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use blake2::{Blake2b512, Digest};
use ferrogate_core::{TenantContext, WorkspaceScope};
use ferrogate_storage::{
    RuntimeStorageRepositories, StoredAdminUser, StoredAdminUserMembership,
    StoredAdminUserRefreshToken, StoredApiKey, StoredProject, StoredTenantAccount, StoredWorkspace,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const VIRTUAL_API_KEY_PREFIX_CHARS: usize = 16;
/// Read/write deadline per connection so a slow or idle client cannot park a
/// handler thread forever (slowloris mitigation, issue #147 — ported from the
/// billing service's #138 fix).
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);
/// Upper bound on concurrently-served connections so an anonymous flood
/// cannot exhaust threads/memory (issue #147).
const MAX_CONCURRENT_CONNECTIONS: usize = 512;
/// Admin console session access-token lifetime (issue #157). Short-lived by
/// design: the refresh token (durable, revocable) is what actually gates a
/// browser session's lifetime.
const ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS: u64 = 60 * 60;
/// Admin console refresh-token lifetime.
const ADMIN_SESSION_REFRESH_TOKEN_TTL_SECS: u64 = 60 * 60 * 24 * 30;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthServiceData {
    #[serde(default)]
    pub tenants: Vec<TenantRecord>,
    #[serde(default)]
    pub api_keys: Vec<AuthApiKey>,
    #[serde(default)]
    pub roles: Vec<Role>,
    #[serde(default)]
    pub bindings: Vec<PolicyBinding>,
}

impl AuthServiceData {
    pub fn load_yaml(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read auth service data {}", path.display()))?;
        serde_yaml::from_str(&contents)
            .with_context(|| format!("failed to parse auth service data {}", path.display()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantRecord {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub context: TenantContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthApiKey {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub tenant: TenantContext,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permission {
    pub action: String,
    pub resource: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub permissions: Vec<Permission>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBinding {
    pub id: String,
    pub role_id: String,
    pub tenant: TenantContext,
    pub subject: PolicySubject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicySubject {
    User { user_id: String },
    ServiceAccount { service_account_id: String },
    ApiKey { api_key_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthDecision {
    pub tenant: TenantContext,
    pub subject: PolicySubject,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub allowed_models: Vec<String>,
    #[serde(default)]
    pub allowed_providers: Vec<String>,
    #[serde(default)]
    pub monthly_token_budget: Option<u64>,
    #[serde(default)]
    pub request_limit_per_minute: Option<u64>,
}

pub trait ApiKeyAuthenticator: Send + Sync {
    fn authenticate(&self, presented_key: &str) -> Option<AuthDecision>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualApiKeyMaterial {
    pub key_prefix: String,
    pub key_hash: String,
    pub last4: String,
}

pub fn virtual_api_key_material(secret: &str) -> Option<VirtualApiKeyMaterial> {
    let secret = secret.trim();
    if secret.is_empty() {
        return None;
    }
    Some(VirtualApiKeyMaterial {
        key_prefix: virtual_api_key_prefix(secret)?,
        key_hash: hash_virtual_api_key_secret(secret),
        last4: secret
            .chars()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect(),
    })
}

pub fn hash_virtual_api_key_secret(secret: &str) -> String {
    let digest = Sha256::digest(secret.trim().as_bytes());
    format!("sha256:{}", encode_hex(&digest))
}

#[derive(Clone)]
pub struct StorageApiKeyAuthenticator {
    repositories: Arc<RuntimeStorageRepositories>,
    now_unix_seconds: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl std::fmt::Debug for StorageApiKeyAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StorageApiKeyAuthenticator")
            .field("repositories", &"RuntimeStorageRepositories")
            .finish_non_exhaustive()
    }
}

impl StorageApiKeyAuthenticator {
    pub fn new(repositories: Arc<RuntimeStorageRepositories>) -> Self {
        Self {
            repositories,
            now_unix_seconds: Arc::new(now_unix_seconds),
        }
    }

    pub fn with_clock(
        repositories: Arc<RuntimeStorageRepositories>,
        now_unix_seconds: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            repositories,
            now_unix_seconds,
        }
    }
}

impl ApiKeyAuthenticator for StorageApiKeyAuthenticator {
    fn authenticate(&self, presented_key: &str) -> Option<AuthDecision> {
        let presented_key = presented_key.trim();
        let key_prefix = virtual_api_key_prefix(presented_key)?;
        let now_unix_seconds = (self.now_unix_seconds)();
        let candidates = self
            .repositories
            .find_api_key_records_by_prefix(&key_prefix)
            .ok()?;

        candidates.into_iter().find_map(|api_key| {
            if !api_key_record_is_active(&api_key, now_unix_seconds)
                || !api_key_record_last4_matches(&api_key, presented_key)
                || !verify_virtual_api_key_secret(presented_key, &api_key.key_hash)
            {
                return None;
            }

            Some(AuthDecision {
                tenant: api_key_tenant_context(&api_key),
                subject: PolicySubject::ApiKey {
                    api_key_id: api_key.id.clone(),
                },
                scopes: api_key.scopes,
                allowed_models: api_key.allowed_models,
                allowed_providers: api_key.allowed_providers,
                monthly_token_budget: api_key.monthly_token_budget,
                request_limit_per_minute: api_key.request_limit_per_minute,
            })
        })
    }
}

#[derive(Debug, Clone)]
pub struct RbacAuthService {
    data: AuthServiceData,
    roles_by_id: HashMap<String, Role>,
}

impl RbacAuthService {
    pub fn new(data: AuthServiceData) -> Self {
        let roles_by_id = data
            .roles
            .iter()
            .cloned()
            .map(|role| (role.id.clone(), role))
            .collect();
        Self { data, roles_by_id }
    }

    pub fn tenants(&self) -> &[TenantRecord] {
        &self.data.tenants
    }

    pub fn authorize(&self, request: &AuthorizeRequest) -> AuthorizationDecision {
        let allowed = self
            .data
            .bindings
            .iter()
            .filter(|binding| binding.subject == request.subject)
            .filter(|binding| tenant_matches(&binding.tenant, &request.tenant))
            .filter_map(|binding| self.roles_by_id.get(&binding.role_id))
            .flat_map(|role| role.permissions.iter())
            .any(|permission| {
                matches_pattern(&permission.action, &request.action)
                    && matches_pattern(&permission.resource, &request.resource)
            });

        AuthorizationDecision {
            allowed,
            tenant: request.tenant.clone(),
            reason: if allowed {
                "matched_rbac_binding".into()
            } else {
                "no_matching_rbac_binding".into()
            },
        }
    }
}

impl ApiKeyAuthenticator for RbacAuthService {
    fn authenticate(&self, presented_key: &str) -> Option<AuthDecision> {
        let api_key =
            self.data.api_keys.iter().find(|api_key| {
                api_key.enabled && api_key.secret.as_deref() == Some(presented_key)
            })?;

        Some(AuthDecision {
            tenant: api_key.tenant.clone(),
            subject: PolicySubject::ApiKey {
                api_key_id: api_key.id.clone(),
            },
            scopes: api_key.scopes.clone(),
            allowed_models: Vec::new(),
            allowed_providers: Vec::new(),
            monthly_token_budget: None,
            request_limit_per_minute: None,
        })
    }
}

#[derive(Clone)]
pub struct AuthService {
    rbac: RbacAuthService,
    api_key_authenticator: Arc<dyn ApiKeyAuthenticator>,
    admin_console: Option<Arc<AdminConsoleState>>,
    cors_allowed_origin: Option<String>,
}

impl std::fmt::Debug for AuthService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthService")
            .field("rbac", &self.rbac)
            .field("api_key_authenticator", &"dyn ApiKeyAuthenticator")
            .field("admin_console", &self.admin_console.is_some())
            .field("cors_allowed_origin", &self.cors_allowed_origin)
            .finish()
    }
}

impl AuthService {
    pub fn from_data(data: AuthServiceData) -> Self {
        let rbac = RbacAuthService::new(data);
        let api_key_authenticator = Arc::new(rbac.clone());
        Self {
            rbac,
            api_key_authenticator,
            admin_console: None,
            cors_allowed_origin: None,
        }
    }

    pub fn with_api_key_authenticator(
        data: AuthServiceData,
        api_key_authenticator: Arc<dyn ApiKeyAuthenticator>,
    ) -> Self {
        Self {
            rbac: RbacAuthService::new(data),
            api_key_authenticator,
            admin_console: None,
            cors_allowed_origin: None,
        }
    }

    /// Enables the admin-console register/login/session endpoints on this
    /// service (issue #157).
    pub fn with_admin_console(mut self, config: AdminConsoleConfig) -> Self {
        self.admin_console = Some(Arc::new(AdminConsoleState::new(config)));
        self
    }

    /// Reflects the given origin back on every response's
    /// `Access-Control-Allow-Origin` header, so a cross-origin admin console
    /// frontend (issue #158/#159) can call this service.
    pub fn with_cors_allowed_origin(mut self, origin: String) -> Self {
        self.cors_allowed_origin = Some(origin);
        self
    }

    pub fn tenants(&self) -> &[TenantRecord] {
        self.rbac.tenants()
    }

    pub fn authorize(&self, request: &AuthorizeRequest) -> AuthorizationDecision {
        self.rbac.authorize(request)
    }

    pub fn authenticate(&self, presented_key: &str) -> Option<AuthDecision> {
        self.api_key_authenticator.authenticate(presented_key)
    }
}

#[derive(Clone)]
pub struct AuthServiceConfig {
    pub listen: String,
    pub data: AuthServiceData,
    pub api_key_authenticator: Option<Arc<dyn ApiKeyAuthenticator>>,
    /// Enables the admin-console register/login/session endpoints (issue
    /// #157) when set. Requires durable storage -- there is no in-memory-only
    /// admin console, since a human's account must survive a process
    /// restart.
    pub admin_console: Option<AdminConsoleConfig>,
    /// Value reflected back as `Access-Control-Allow-Origin` on every
    /// response (including the OPTIONS preflight), so a separately-deployed
    /// admin console frontend (issue #158/#159) can call this service
    /// cross-origin. `None` disables CORS headers entirely.
    pub cors_allowed_origin: Option<String>,
}

impl std::fmt::Debug for AuthServiceConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthServiceConfig")
            .field("listen", &self.listen)
            .field("data", &self.data)
            .field(
                "api_key_authenticator",
                &self
                    .api_key_authenticator
                    .as_ref()
                    .map(|_| "dyn ApiKeyAuthenticator"),
            )
            .field(
                "admin_console",
                &self.admin_console.as_ref().map(|_| "AdminConsoleConfig"),
            )
            .field("cors_allowed_origin", &self.cors_allowed_origin)
            .finish()
    }
}

/// Durable-storage handle and JWT signing secret backing the admin-console
/// register/login/session endpoints.
///
/// `repositories` must point at the SAME Postgres/Supabase schema the
/// gateway's own control plane uses: registration provisions a
/// tenant/project/workspace and a gateway-facing virtual API key (issue
/// #157) that the gateway's Admin API must be able to read back. Pointing
/// this at a schema the gateway doesn't share (e.g. the auth service's own
/// dedicated `auth` schema default from issue #156) leaves the console fully
/// functional for its own register/login/session endpoints, but the minted
/// `gateway_api_key` will never authenticate against the gateway, since it
/// simply won't exist in the schema the gateway reads.
#[derive(Clone)]
pub struct AdminConsoleConfig {
    pub repositories: Arc<RuntimeStorageRepositories>,
    pub jwt_secret: String,
}

struct AdminConsoleState {
    repositories: Arc<RuntimeStorageRepositories>,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl AdminConsoleState {
    fn new(config: AdminConsoleConfig) -> Self {
        Self {
            repositories: config.repositories,
            encoding_key: EncodingKey::from_secret(config.jwt_secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AdminSessionClaims {
    sub: String,
    email: String,
    tenant_id: String,
    role: String,
    iat: u64,
    exp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminRegisterRequest {
    pub organization_name: String,
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminLoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminRefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminLogoutRequest {
    pub refresh_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminUserView {
    pub id: String,
    pub email: String,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminTenantView {
    pub id: String,
    pub name: String,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminSessionResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub user: AdminUserView,
    pub tenant: AdminTenantView,
    /// A freshly-minted, admin.read+admin.write-scoped virtual API key for
    /// the gateway's own Admin API, shown once (never recoverable after this
    /// response, matching the existing virtual-key create/rotate contract).
    pub gateway_api_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminMeResponse {
    pub user: AdminUserView,
    pub memberships: Vec<AdminTenantView>,
}

/// RAII counter guard that decrements the live-connection count on drop
/// (ported from the billing service's #138 fix for issue #147).
struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn serve(config: AuthServiceConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.listen)
        .with_context(|| format!("failed to bind ferrogate-auth on {}", config.listen))?;
    let mut service = match config.api_key_authenticator {
        Some(api_key_authenticator) => {
            AuthService::with_api_key_authenticator(config.data, api_key_authenticator)
        }
        None => AuthService::from_data(config.data),
    };
    if let Some(admin_console) = config.admin_console {
        service = service.with_admin_console(admin_console);
    }
    if let Some(origin) = config.cors_allowed_origin {
        service = service.with_cors_allowed_origin(origin);
    }
    let service = Arc::new(service);
    let live_connections = Arc::new(AtomicUsize::new(0));
    println!("ferrogate-auth listening on {}", config.listen);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // Shed load rather than spawn unbounded threads under a flood
                // (issue #147).
                if live_connections.load(Ordering::SeqCst) >= MAX_CONCURRENT_CONNECTIONS {
                    drop(stream);
                    continue;
                }
                live_connections.fetch_add(1, Ordering::SeqCst);
                let guard = ConnectionGuard(live_connections.clone());
                let service = service.clone();
                std::thread::spawn(move || {
                    let _guard = guard;
                    if let Err(error) = handle_connection(stream, &service) {
                        eprintln!("ferrogate-auth request failed: {error:#}");
                    }
                });
            }
            Err(error) => eprintln!("ferrogate-auth accept failed: {error}"),
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveApiKeyRequest {
    pub presented_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizeRequest {
    pub tenant: TenantContext,
    pub subject: PolicySubject,
    pub action: String,
    pub resource: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationDecision {
    pub allowed: bool,
    pub tenant: TenantContext,
    pub reason: String,
}

fn handle_connection(mut stream: TcpStream, service: &AuthService) -> anyhow::Result<()> {
    stream
        .set_read_timeout(Some(CONNECTION_TIMEOUT))
        .context("failed to set auth service read timeout")?;
    stream
        .set_write_timeout(Some(CONNECTION_TIMEOUT))
        .context("failed to set auth service write timeout")?;
    let request = read_http_request(&mut stream)?;
    let response = route_request(service, request);
    stream
        .write_all(&response.to_bytes(service.cors_allowed_origin.as_deref()))
        .context("failed to write auth service response")
}

fn route_request(service: &AuthService, request: HttpRequest) -> HttpResponse {
    // Answer the CORS preflight for any path uniformly; the actual
    // Allow-* headers are attached in `to_bytes` from `service.cors_allowed_origin`.
    if request.method == "OPTIONS" {
        return HttpResponse::no_content(204);
    }
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") | ("GET", "/v1/healthz") => HttpResponse::json(
            200,
            json!({
                "service": "ferrogate-auth",
                "status": "ok"
            }),
        ),
        ("GET", "/v1/tenants") => HttpResponse::json(200, json!({ "tenants": service.tenants() })),
        ("POST", "/v1/auth/resolve-api-key") => {
            let parsed = serde_json::from_slice::<ResolveApiKeyRequest>(&request.body);
            match parsed {
                Ok(payload) => match service.authenticate(&payload.presented_key) {
                    Some(decision) => HttpResponse::json(200, decision),
                    None => HttpResponse::json(
                        401,
                        json!({
                            "error": {
                                "code": "invalid_api_key",
                                "message": "api key was not recognized by ferrogate-auth"
                            }
                        }),
                    ),
                },
                Err(error) => bad_request(error),
            }
        }
        ("POST", "/v1/auth/authorize") => {
            let parsed = serde_json::from_slice::<AuthorizeRequest>(&request.body);
            match parsed {
                Ok(payload) => HttpResponse::json(200, service.authorize(&payload)),
                Err(error) => bad_request(error),
            }
        }
        ("POST", "/v1/admin/register") => with_admin_console(service, |console| {
            let parsed = serde_json::from_slice::<AdminRegisterRequest>(&request.body);
            match parsed {
                Ok(payload) => handle_admin_register(console, payload),
                Err(error) => bad_request(error),
            }
        }),
        ("POST", "/v1/admin/login") => with_admin_console(service, |console| {
            let parsed = serde_json::from_slice::<AdminLoginRequest>(&request.body);
            match parsed {
                Ok(payload) => handle_admin_login(console, payload),
                Err(error) => bad_request(error),
            }
        }),
        ("POST", "/v1/admin/refresh") => with_admin_console(service, |console| {
            let parsed = serde_json::from_slice::<AdminRefreshRequest>(&request.body);
            match parsed {
                Ok(payload) => handle_admin_refresh(console, payload),
                Err(error) => bad_request(error),
            }
        }),
        ("POST", "/v1/admin/logout") => with_admin_console(service, |console| {
            let parsed = serde_json::from_slice::<AdminLogoutRequest>(&request.body);
            match parsed {
                Ok(payload) => handle_admin_logout(console, payload),
                Err(error) => bad_request(error),
            }
        }),
        ("GET", "/v1/admin/me") => {
            with_admin_console(service, |console| match request.bearer_token() {
                Some(token) => handle_admin_me(console, token),
                None => unauthorized("missing bearer token"),
            })
        }
        _ => HttpResponse::json(
            404,
            json!({
                "error": {
                    "code": "not_found",
                    "message": "auth service endpoint not found"
                }
            }),
        ),
    }
}

/// Runs `handler` if the admin console feature is configured, otherwise
/// returns a clear 503 rather than a confusing 404 -- the route exists, it
/// just isn't enabled on this deployment (issue #157).
fn with_admin_console(
    service: &AuthService,
    handler: impl FnOnce(&AdminConsoleState) -> HttpResponse,
) -> HttpResponse {
    match service.admin_console.as_deref() {
        Some(console) => handler(console),
        None => HttpResponse::json(
            503,
            json!({
                "error": {
                    "code": "admin_console_not_configured",
                    "message": "the admin console is not enabled on this ferrogate-auth deployment; \
                                start it with --supabase-dsn and --admin-jwt-secret(-env)"
                }
            }),
        ),
    }
}

fn unauthorized(message: &str) -> HttpResponse {
    HttpResponse::json(
        401,
        json!({
            "error": {
                "code": "unauthorized",
                "message": message,
            }
        }),
    )
}

fn conflict(message: &str) -> HttpResponse {
    HttpResponse::json(
        409,
        json!({ "error": { "code": "conflict", "message": message } }),
    )
}

fn unprocessable(message: &str) -> HttpResponse {
    HttpResponse::json(
        422,
        json!({ "error": { "code": "invalid_request", "message": message } }),
    )
}

fn internal_error(message: &str) -> HttpResponse {
    HttpResponse::json(
        500,
        json!({ "error": { "code": "internal_error", "message": message } }),
    )
}

fn storage_error(error: &ferrogate_storage::StorageError) -> HttpResponse {
    HttpResponse::json(
        503,
        json!({ "error": { "code": "storage_unavailable", "message": error.to_string() } }),
    )
}

/// Handle a new organization signing itself up (issue #157): creates the
/// tenant/project/workspace hierarchy, the owning admin user, and a durable
/// gateway virtual API key, then issues a session -- all in one call so the
/// console has everything it needs to start managing its own tenant
/// immediately after registering.
fn handle_admin_register(
    console: &AdminConsoleState,
    payload: AdminRegisterRequest,
) -> HttpResponse {
    let email = payload.email.trim().to_ascii_lowercase();
    let organization_name = payload.organization_name.trim().to_string();
    let display_name = payload
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&email)
        .to_string();

    if !is_valid_email(&email) {
        return unprocessable("email must be a valid address");
    }
    if organization_name.is_empty() {
        return unprocessable("organization_name must not be empty");
    }
    if payload.password.len() < 8 {
        return unprocessable("password must be at least 8 characters");
    }
    match console.repositories.get_admin_user_by_email(&email) {
        Ok(Some(_)) => return conflict("an account with this email already exists"),
        Ok(None) => {}
        Err(error) => return storage_error(&error),
    }

    let password_hash = match hash_password(&payload.password) {
        Ok(hash) => hash,
        Err(error) => return internal_error(&error.to_string()),
    };

    let now = now_unix_seconds() as i64;
    let tenant_id = next_id("tenant");
    let project_id = next_id("project");
    let workspace_id = next_id("workspace");
    let user_id = next_id("user");

    let tenant_account = StoredTenantAccount {
        id: tenant_id.clone(),
        name: organization_name.clone(),
        slug: slugify_with_suffix(&organization_name, &tenant_id),
        status: "active".into(),
        created_at_unix: now,
        updated_at_unix: now,
    };
    if let Err(error) = console.repositories.upsert_tenant_account(tenant_account) {
        return storage_error(&error);
    }
    let project = StoredProject {
        id: project_id.clone(),
        tenant_id: tenant_id.clone(),
        name: "Default".into(),
        slug: "default".into(),
        status: "active".into(),
        created_at_unix: now,
        updated_at_unix: now,
    };
    if let Err(error) = console.repositories.upsert_project(project) {
        return storage_error(&error);
    }
    let workspace = StoredWorkspace {
        id: workspace_id.clone(),
        project_id: project_id.clone(),
        tenant_id: tenant_id.clone(),
        name: "Default".into(),
        slug: "default".into(),
        environment: "production".into(),
        status: "active".into(),
        created_at_unix: now,
        updated_at_unix: now,
    };
    if let Err(error) = console.repositories.upsert_workspace(workspace) {
        return storage_error(&error);
    }
    let user = StoredAdminUser {
        id: user_id.clone(),
        email: email.clone(),
        password_hash,
        display_name: display_name.clone(),
        superadmin: false,
        created_at_unix: now,
        updated_at_unix: now,
        last_login_at_unix: Some(now),
        disabled_at_unix: None,
    };
    if let Err(error) = console.repositories.upsert_admin_user(user) {
        return storage_error(&error);
    }
    let membership = StoredAdminUserMembership {
        id: next_id("membership"),
        user_id: user_id.clone(),
        tenant_id: tenant_id.clone(),
        role: "owner".into(),
        created_at_unix: now,
    };
    if let Err(error) = console
        .repositories
        .upsert_admin_user_membership(membership)
    {
        return storage_error(&error);
    }

    let gateway_api_key =
        match provision_gateway_api_key(console, &workspace_id, &project_id, &tenant_id) {
            Ok(secret) => secret,
            Err(error) => return internal_error(&error.to_string()),
        };

    match issue_session(console, &user_id, &email, &tenant_id, "owner") {
        Ok((access_token, refresh_token)) => HttpResponse::json(
            201,
            AdminSessionResponse {
                access_token,
                refresh_token,
                expires_in: ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS,
                user: AdminUserView {
                    id: user_id,
                    email,
                    display_name,
                },
                tenant: AdminTenantView {
                    id: tenant_id,
                    name: organization_name,
                    role: "owner".into(),
                },
                gateway_api_key,
            },
        ),
        Err(error) => internal_error(&error.to_string()),
    }
}

fn handle_admin_login(console: &AdminConsoleState, payload: AdminLoginRequest) -> HttpResponse {
    let email = payload.email.trim().to_ascii_lowercase();
    let user = match console.repositories.get_admin_user_by_email(&email) {
        Ok(Some(user)) => user,
        Ok(None) => return unauthorized("invalid email or password"),
        Err(error) => return storage_error(&error),
    };
    if user.disabled_at_unix.is_some() {
        return unauthorized("this account has been disabled");
    }
    if !verify_password(&payload.password, &user.password_hash) {
        return unauthorized("invalid email or password");
    }
    let memberships = match console
        .repositories
        .list_admin_user_memberships_by_user(&user.id)
    {
        Ok(memberships) => memberships,
        Err(error) => return storage_error(&error),
    };
    let Some(membership) = memberships.first() else {
        return unauthorized("this account has no tenant membership");
    };
    let tenant_account = match console
        .repositories
        .get_tenant_account(&membership.tenant_id)
    {
        Ok(Some(account)) => account,
        Ok(None) => return internal_error("tenant account for this membership no longer exists"),
        Err(error) => return storage_error(&error),
    };
    let workspace = match resolve_default_workspace(console, &membership.tenant_id) {
        Ok(Some(workspace)) => workspace,
        Ok(None) => return internal_error("no workspace found for this tenant"),
        Err(error) => return storage_error(&error),
    };

    // Mint a fresh gateway virtual key on every login rather than trying to
    // recover a prior one (secrets are never plaintext-recoverable after
    // creation, matching the existing virtual-key create/rotate contract).
    // Known simplification: earlier session keys are not auto-revoked here,
    // so multiple concurrent browser sessions each keep their own working
    // key; an operator can still revoke any of them via the existing
    // /admin/v1/virtual-keys API.
    let gateway_api_key = match provision_gateway_api_key(
        console,
        &workspace.id,
        &workspace.project_id,
        &workspace.tenant_id,
    ) {
        Ok(secret) => secret,
        Err(error) => return internal_error(&error.to_string()),
    };

    let mut updated_user = user.clone();
    updated_user.last_login_at_unix = Some(now_unix_seconds() as i64);
    if let Err(error) = console.repositories.upsert_admin_user(updated_user) {
        return storage_error(&error);
    }

    match issue_session(
        console,
        &user.id,
        &email,
        &membership.tenant_id,
        &membership.role,
    ) {
        Ok((access_token, refresh_token)) => HttpResponse::json(
            200,
            AdminSessionResponse {
                access_token,
                refresh_token,
                expires_in: ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS,
                user: AdminUserView {
                    id: user.id,
                    email,
                    display_name: user.display_name,
                },
                tenant: AdminTenantView {
                    id: tenant_account.id,
                    name: tenant_account.name,
                    role: membership.role.clone(),
                },
                gateway_api_key,
            },
        ),
        Err(error) => internal_error(&error.to_string()),
    }
}

fn handle_admin_refresh(console: &AdminConsoleState, payload: AdminRefreshRequest) -> HttpResponse {
    let token_hash = hash_virtual_api_key_secret(&payload.refresh_token);
    let stored = match console
        .repositories
        .get_admin_user_refresh_token_by_hash(&token_hash)
    {
        Ok(Some(token)) => token,
        Ok(None) => return unauthorized("invalid refresh token"),
        Err(error) => return storage_error(&error),
    };
    let now = now_unix_seconds() as i64;
    if stored.revoked_at_unix.is_some() || stored.expires_at_unix <= now {
        return unauthorized("refresh token has expired or been revoked");
    }
    let mut revoked = stored.clone();
    revoked.revoked_at_unix = Some(now);
    if let Err(error) = console
        .repositories
        .upsert_admin_user_refresh_token(revoked)
    {
        return storage_error(&error);
    }
    let user = match console.repositories.get_admin_user_by_id(&stored.user_id) {
        Ok(Some(user)) => user,
        Ok(None) => return unauthorized("account no longer exists"),
        Err(error) => return storage_error(&error),
    };
    if user.disabled_at_unix.is_some() {
        return unauthorized("this account has been disabled");
    }
    let memberships = match console
        .repositories
        .list_admin_user_memberships_by_user(&user.id)
    {
        Ok(memberships) => memberships,
        Err(error) => return storage_error(&error),
    };
    let Some(membership) = memberships.first() else {
        return unauthorized("this account has no tenant membership");
    };
    match issue_session(
        console,
        &user.id,
        &user.email,
        &membership.tenant_id,
        &membership.role,
    ) {
        Ok((access_token, refresh_token)) => HttpResponse::json(
            200,
            json!({
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS,
            }),
        ),
        Err(error) => internal_error(&error.to_string()),
    }
}

fn handle_admin_logout(console: &AdminConsoleState, payload: AdminLogoutRequest) -> HttpResponse {
    let token_hash = hash_virtual_api_key_secret(&payload.refresh_token);
    match console
        .repositories
        .get_admin_user_refresh_token_by_hash(&token_hash)
    {
        Ok(Some(mut stored)) => {
            if stored.revoked_at_unix.is_none() {
                stored.revoked_at_unix = Some(now_unix_seconds() as i64);
                if let Err(error) = console.repositories.upsert_admin_user_refresh_token(stored) {
                    return storage_error(&error);
                }
            }
            HttpResponse::json(200, json!({ "object": "logout", "revoked": true }))
        }
        Ok(None) => HttpResponse::json(200, json!({ "object": "logout", "revoked": false })),
        Err(error) => storage_error(&error),
    }
}

fn handle_admin_me(console: &AdminConsoleState, token: &str) -> HttpResponse {
    let claims = match decode_access_token(console, token) {
        Ok(claims) => claims,
        Err(_) => return unauthorized("invalid or expired access token"),
    };
    let user = match console.repositories.get_admin_user_by_id(&claims.sub) {
        Ok(Some(user)) => user,
        Ok(None) => return unauthorized("account no longer exists"),
        Err(error) => return storage_error(&error),
    };
    let memberships = match console
        .repositories
        .list_admin_user_memberships_by_user(&user.id)
    {
        Ok(memberships) => memberships,
        Err(error) => return storage_error(&error),
    };
    let mut tenant_views = Vec::with_capacity(memberships.len());
    for membership in memberships {
        match console
            .repositories
            .get_tenant_account(&membership.tenant_id)
        {
            Ok(Some(account)) => tenant_views.push(AdminTenantView {
                id: account.id,
                name: account.name,
                role: membership.role,
            }),
            Ok(None) => {}
            Err(error) => return storage_error(&error),
        }
    }
    HttpResponse::json(
        200,
        AdminMeResponse {
            user: AdminUserView {
                id: user.id,
                email: user.email,
                display_name: user.display_name,
            },
            memberships: tenant_views,
        },
    )
}

fn resolve_default_workspace(
    console: &AdminConsoleState,
    tenant_id: &str,
) -> Result<Option<StoredWorkspace>, ferrogate_storage::StorageError> {
    let workspaces = console.repositories.list_workspaces()?;
    Ok(workspaces
        .into_iter()
        .find(|workspace| workspace.tenant_id == tenant_id))
}

/// Create a durable, admin.read+admin.write-scoped virtual API key for the
/// gateway's own Admin API, reusing the exact secret format/hashing the
/// gateway's existing `/admin/v1/virtual-keys` endpoint already produces and
/// verifies (issue #157) -- the console is just another virtual-key holder,
/// not a special case in the gateway's auth path.
fn provision_gateway_api_key(
    console: &AdminConsoleState,
    workspace_id: &str,
    project_id: &str,
    tenant_id: &str,
) -> anyhow::Result<String> {
    let secret = generate_virtual_api_key_secret()?;
    let material = virtual_api_key_material(&secret)
        .ok_or_else(|| anyhow!("failed to derive virtual key material"))?;
    let scope = WorkspaceScope::new(tenant_id, project_id, workspace_id);
    let mut tenant = TenantContext::default();
    scope.apply_to(&mut tenant);
    let id = next_id("vk");
    tenant.api_key_id = Some(id.clone());
    let now = now_unix_seconds();
    let key = StoredApiKey {
        id,
        workspace_id: workspace_id.to_string(),
        tenant_id: tenant_id.to_string(),
        project_id: project_id.to_string(),
        name: "Admin console session".into(),
        key_prefix: material.key_prefix,
        key_hash: material.key_hash,
        last4: material.last4,
        enabled: true,
        scopes: vec!["admin.read".into(), "admin.write".into()],
        allowed_models: Vec::new(),
        allowed_providers: Vec::new(),
        tenant,
        monthly_token_budget: None,
        request_limit_per_minute: None,
        created_at_unix: now,
        updated_at_unix: now,
        rotated_at_unix: None,
        expires_at_unix: None,
        revoked_at_unix: None,
    };
    console.repositories.upsert_api_key_record(key)?;
    Ok(secret)
}

fn issue_session(
    console: &AdminConsoleState,
    user_id: &str,
    email: &str,
    tenant_id: &str,
    role: &str,
) -> anyhow::Result<(String, String)> {
    let access_token = issue_access_token(console, user_id, email, tenant_id, role)?;
    let refresh_secret = generate_refresh_token_secret()?;
    let now = now_unix_seconds() as i64;
    let refresh_token_row = StoredAdminUserRefreshToken {
        id: next_id("rt"),
        user_id: user_id.to_string(),
        token_hash: hash_virtual_api_key_secret(&refresh_secret),
        created_at_unix: now,
        expires_at_unix: now + ADMIN_SESSION_REFRESH_TOKEN_TTL_SECS as i64,
        revoked_at_unix: None,
    };
    console
        .repositories
        .upsert_admin_user_refresh_token(refresh_token_row)?;
    Ok((access_token, refresh_secret))
}

fn issue_access_token(
    console: &AdminConsoleState,
    user_id: &str,
    email: &str,
    tenant_id: &str,
    role: &str,
) -> anyhow::Result<String> {
    let now = now_unix_seconds();
    let claims = AdminSessionClaims {
        sub: user_id.to_string(),
        email: email.to_string(),
        tenant_id: tenant_id.to_string(),
        role: role.to_string(),
        iat: now,
        exp: now + ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS,
    };
    encode(&Header::default(), &claims, &console.encoding_key)
        .map_err(|error| anyhow!("failed to sign session token: {error}"))
}

fn decode_access_token(
    console: &AdminConsoleState,
    token: &str,
) -> anyhow::Result<AdminSessionClaims> {
    let data = decode::<AdminSessionClaims>(token, &console.decoding_key, &Validation::default())
        .map_err(|error| anyhow!("invalid session token: {error}"))?;
    Ok(data.claims)
}

/// Generate a fresh virtual-API-key secret in the exact `fg_<hex>` format the
/// gateway's own `/admin/v1/virtual-keys` endpoint produces, so a console
/// -provisioned key is indistinguishable from one an operator creates
/// directly. Public so `ferrogate-cli`'s virtual-key handler can call this
/// single implementation instead of maintaining its own copy.
pub fn generate_virtual_api_key_secret() -> anyhow::Result<String> {
    Ok(format!("fg_{}", generate_random_hex(24)?))
}

fn generate_refresh_token_secret() -> anyhow::Result<String> {
    generate_random_hex(32)
}

fn generate_random_hex(byte_len: usize) -> anyhow::Result<String> {
    let mut buffer = vec![0_u8; byte_len];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut buffer)
        .map_err(|_| anyhow!("failed to generate secure random bytes"))?;
    Ok(encode_hex(&buffer))
}

fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| anyhow!("failed to hash password: {error}"))
}

fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

fn next_id(kind: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("{kind}-{nanos}-{}", std::process::id())
}

/// Derive a URL-safe slug from an operator-supplied organization name, with a
/// short unique suffix appended so it satisfies the `tenants.slug` UNIQUE
/// constraint without a create-then-retry-on-conflict loop.
///
/// The suffix is a hash of `unique_seed` rather than a positional substring
/// of it: `unique_seed` is normally a `next_id()`-style
/// `"{kind}-{nanos}-{pid}"` string, and naively slicing its last N characters
/// lands on the constant `pid` segment (not the per-call `nanos` segment),
/// so every registration sharing an organization name within one process
/// lifetime collided on the exact same slug and got a permanent 409/503.
fn slugify_with_suffix(name: &str, unique_seed: &str) -> String {
    let normalized: String = name
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect();
    let base = normalized
        .split('-')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    let base = if base.is_empty() {
        "org".to_string()
    } else {
        base
    };
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(unique_seed, &mut hasher);
    let suffix = format!("{:016x}", std::hash::Hasher::finish(&hasher));
    format!("{base}-{suffix}")
}

fn is_valid_email(email: &str) -> bool {
    let mut parts = email.splitn(2, '@');
    let (Some(local), Some(domain)) = (parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

fn bad_request(error: serde_json::Error) -> HttpResponse {
    HttpResponse::json(
        400,
        json!({
            "error": {
                "code": "invalid_json",
                "message": error.to_string()
            }
        }),
    )
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    /// Header names lowercased for case-insensitive lookup.
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    fn bearer_token(&self) -> Option<&str> {
        self.header("authorization")?.strip_prefix("Bearer ")
    }
}

fn read_http_request(stream: &mut TcpStream) -> anyhow::Result<HttpRequest> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).context("failed to read request")?;
        if read == 0 {
            return Err(anyhow!("connection closed before request headers"));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_REQUEST_BYTES {
            return Err(anyhow!("request exceeds {MAX_REQUEST_BYTES} bytes"));
        }
        if let Some(index) = find_header_end(&buffer) {
            break index;
        }
    };

    let header_text = String::from_utf8_lossy(&buffer[..header_end]);
    let mut lines = header_text.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow!("missing request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP method"))?
        .to_string();
    let path = request_parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP path"))?
        .split('?')
        .next()
        .unwrap_or("/")
        .to_string();
    let headers: HashMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);

    let body_start = header_end + 4;
    let body_end = bounded_body_end(body_start, content_length, MAX_REQUEST_BYTES)?;
    while buffer.len() < body_end {
        let read = stream
            .read(&mut chunk)
            .context("failed to read request body")?;
        if read == 0 {
            return Err(anyhow!("connection closed before request body"));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_REQUEST_BYTES {
            return Err(anyhow!("request exceeds {MAX_REQUEST_BYTES} bytes"));
        }
    }

    Ok(HttpRequest {
        method,
        path,
        headers,
        body: buffer[body_start..body_end].to_vec(),
    })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Bound a declared `Content-Length` before it is used as a slice index, so a
/// malformed/huge header cannot overflow the `body_start + content_length`
/// addition or produce a `start > end` slice panic (issue #147, ported from
/// the billing service's #138 fix). Pure and independently testable.
fn bounded_body_end(
    body_start: usize,
    content_length: usize,
    max_request_bytes: usize,
) -> anyhow::Result<usize> {
    if content_length > max_request_bytes {
        return Err(anyhow!(
            "content-length {content_length} exceeds {max_request_bytes} bytes"
        ));
    }
    body_start
        .checked_add(content_length)
        .ok_or_else(|| anyhow!("content-length overflow"))
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json<T>(status: u16, body: T) -> Self
    where
        T: Serialize,
    {
        let body = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
        Self { status, body }
    }

    fn no_content(status: u16) -> Self {
        Self {
            status,
            body: Vec::new(),
        }
    }

    fn to_bytes(&self, cors_allowed_origin: Option<&str>) -> Vec<u8> {
        let status_text = match self.status {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            409 => "Conflict",
            422 => "Unprocessable Entity",
            503 => "Service Unavailable",
            _ => "Internal Server Error",
        };
        let cors_headers = cors_allowed_origin
            .map(|origin| {
                format!(
                    "access-control-allow-origin: {origin}\r\n\
                     access-control-allow-methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\n\
                     access-control-allow-headers: authorization, content-type\r\n\
                     access-control-max-age: 600\r\n"
                )
            })
            .unwrap_or_default();
        let headers = format!(
            "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{cors_headers}connection: close\r\n\r\n",
            self.status,
            status_text,
            self.body.len()
        );
        [headers.as_bytes(), &self.body].concat()
    }
}

fn tenant_matches(expected: &TenantContext, actual: &TenantContext) -> bool {
    tenant_field_matches(&expected.organization_id, &actual.organization_id)
        && tenant_field_matches(&expected.team_id, &actual.team_id)
        && tenant_field_matches(&expected.project_id, &actual.project_id)
        && tenant_field_matches(&expected.user_id, &actual.user_id)
        && tenant_field_matches(&expected.api_key_id, &actual.api_key_id)
}

fn tenant_field_matches(expected: &Option<String>, actual: &Option<String>) -> bool {
    expected.as_deref().is_none_or(|expected| {
        actual
            .as_deref()
            .is_some_and(|actual| expected == "*" || expected == actual)
    })
}

fn matches_pattern(expected: &str, actual: &str) -> bool {
    expected == "*" || expected == actual
}

fn default_true() -> bool {
    true
}

fn virtual_api_key_prefix(secret: &str) -> Option<String> {
    let secret = secret.trim();
    if secret.is_empty() {
        return None;
    }
    Some(secret.chars().take(VIRTUAL_API_KEY_PREFIX_CHARS).collect())
}

fn verify_virtual_api_key_secret(secret: &str, expected_hash: &str) -> bool {
    if let Some(expected) = expected_hash.strip_prefix("sha256:") {
        let digest = Sha256::digest(secret.as_bytes());
        return constant_time_eq(encode_hex(&digest).as_bytes(), expected.as_bytes());
    }
    if let Some(expected) = expected_hash.strip_prefix("blake2b:") {
        let digest = Blake2b512::digest(secret.as_bytes());
        return constant_time_eq(encode_hex(&digest).as_bytes(), expected.as_bytes());
    }
    false
}

fn api_key_record_is_active(api_key: &StoredApiKey, now_unix_seconds: u64) -> bool {
    api_key.enabled
        && api_key.revoked_at_unix.is_none()
        && api_key
            .expires_at_unix
            .is_none_or(|expires_at| expires_at > now_unix_seconds)
}

fn api_key_record_last4_matches(api_key: &StoredApiKey, presented_key: &str) -> bool {
    api_key.last4.is_empty() || presented_key.ends_with(&api_key.last4)
}

fn api_key_tenant_context(api_key: &StoredApiKey) -> TenantContext {
    let mut tenant = api_key.tenant.clone();
    if tenant.organization_id.is_none() && !api_key.tenant_id.is_empty() {
        tenant.organization_id = Some(api_key.tenant_id.clone());
    }
    if tenant.project_id.is_none() && !api_key.project_id.is_empty() {
        tenant.project_id = Some(api_key.project_id.clone());
    }
    if tenant.workspace_id.is_none() && !api_key.workspace_id.is_empty() {
        tenant.workspace_id = Some(api_key.workspace_id.clone());
    }
    tenant.api_key_id = Some(api_key.id.clone());
    tenant
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
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

#[cfg(test)]
mod tests {
    use super::*;
    use ferrogate_core::WorkspaceScope;
    use ferrogate_storage::{RuntimeControlPlaneState, RuntimeStorageBackend, StorageProviderKind};

    #[test]
    fn denies_when_no_binding_matches() {
        let service = RbacAuthService::new(AuthServiceData::default());
        let decision = service.authorize(&authorize_request());

        assert!(!decision.allowed);
        assert_eq!(decision.reason, "no_matching_rbac_binding");
    }

    #[test]
    fn allows_when_binding_role_permission_matches() {
        let service = RbacAuthService::new(AuthServiceData {
            roles: vec![Role {
                id: "role_chat".into(),
                name: "Chat caller".into(),
                permissions: vec![Permission {
                    action: "chat.completions".into(),
                    resource: "model:fast-chat".into(),
                }],
            }],
            bindings: vec![PolicyBinding {
                id: "binding_chat".into(),
                role_id: "role_chat".into(),
                tenant: tenant(),
                subject: PolicySubject::ApiKey {
                    api_key_id: "key".into(),
                },
            }],
            ..AuthServiceData::default()
        });

        let decision = service.authorize(&authorize_request());

        assert!(decision.allowed);
        assert_eq!(decision.reason, "matched_rbac_binding");
    }

    #[test]
    fn storage_authenticator_resolves_active_hashed_api_key() {
        let secret = "fg_live_1234567890abcdef";
        let repositories = storage_with_api_key(stored_api_key("key-live", secret, |key| {
            key.scopes = vec!["chat.completions".into()];
        }));
        let authenticator =
            StorageApiKeyAuthenticator::with_clock(repositories, Arc::new(|| 1_700_000_000));

        let decision = authenticator.authenticate(secret).unwrap();

        assert_eq!(decision.scopes, ["chat.completions"]);
        assert_eq!(
            decision.subject,
            PolicySubject::ApiKey {
                api_key_id: "key-live".into()
            }
        );
        assert_eq!(decision.tenant.organization_id.as_deref(), Some("tenant-1"));
        assert_eq!(decision.tenant.project_id.as_deref(), Some("project-1"));
        assert_eq!(decision.tenant.workspace_id.as_deref(), Some("workspace-1"));
        assert_eq!(decision.tenant.api_key_id.as_deref(), Some("key-live"));
    }

    #[test]
    fn storage_authenticator_rejects_wrong_disabled_revoked_and_expired_keys() {
        let secret = "fg_live_1234567890abcdef";
        let authenticator = StorageApiKeyAuthenticator::with_clock(
            storage_with_api_key(stored_api_key("key-disabled", secret, |key| {
                key.enabled = false;
            })),
            Arc::new(|| 1_700_000_000),
        );
        assert!(authenticator.authenticate(secret).is_none());

        let authenticator = StorageApiKeyAuthenticator::with_clock(
            storage_with_api_key(stored_api_key("key-revoked", secret, |key| {
                key.revoked_at_unix = Some(1_699_999_999);
            })),
            Arc::new(|| 1_700_000_000),
        );
        assert!(authenticator.authenticate(secret).is_none());

        let authenticator = StorageApiKeyAuthenticator::with_clock(
            storage_with_api_key(stored_api_key("key-expired", secret, |key| {
                key.expires_at_unix = Some(1_700_000_000);
            })),
            Arc::new(|| 1_700_000_000),
        );
        assert!(authenticator.authenticate(secret).is_none());

        let authenticator = StorageApiKeyAuthenticator::with_clock(
            storage_with_api_key(stored_api_key("key-live", secret, |_| {})),
            Arc::new(|| 1_700_000_000),
        );
        assert!(authenticator
            .authenticate("fg_live_wrong00000000")
            .is_none());
    }

    #[test]
    fn storage_authenticator_supports_existing_blake2b_hashes() {
        let secret = "fg_live_1234567890abcdef";
        let repositories = storage_with_api_key(stored_api_key("key-live", secret, |key| {
            let digest = Blake2b512::digest(secret.as_bytes());
            key.key_hash = format!("blake2b:{}", encode_hex(&digest));
        }));
        let authenticator =
            StorageApiKeyAuthenticator::with_clock(repositories, Arc::new(|| 1_700_000_000));

        assert!(authenticator.authenticate(secret).is_some());
    }

    fn authorize_request() -> AuthorizeRequest {
        AuthorizeRequest {
            tenant: tenant(),
            subject: PolicySubject::ApiKey {
                api_key_id: "key".into(),
            },
            action: "chat.completions".into(),
            resource: "model:fast-chat".into(),
        }
    }

    fn tenant() -> TenantContext {
        TenantContext {
            organization_id: Some("org".into()),
            team_id: Some("team".into()),
            project_id: Some("project".into()),
            workspace_id: None,
            user_id: None,
            api_key_id: Some("key".into()),
        }
    }

    fn storage_with_api_key(api_key: StoredApiKey) -> Arc<RuntimeStorageRepositories> {
        let mut control_plane = RuntimeControlPlaneState::new();
        control_plane.upsert_tenant_account(ferrogate_storage::StoredTenantAccount {
            id: "tenant-1".into(),
            name: "Tenant 1".into(),
            slug: "tenant-1".into(),
            status: "active".into(),
            created_at_unix: 1,
            updated_at_unix: 1,
        });
        control_plane.upsert_project(ferrogate_storage::StoredProject {
            id: "project-1".into(),
            tenant_id: "tenant-1".into(),
            name: "Project 1".into(),
            slug: "project-1".into(),
            status: "active".into(),
            created_at_unix: 1,
            updated_at_unix: 1,
        });
        control_plane.upsert_workspace(ferrogate_storage::StoredWorkspace {
            id: "workspace-1".into(),
            tenant_id: "tenant-1".into(),
            project_id: "project-1".into(),
            name: "Workspace 1".into(),
            slug: "workspace-1".into(),
            environment: "prod".into(),
            status: "active".into(),
            created_at_unix: 1,
            updated_at_unix: 1,
        });
        control_plane.upsert_api_key_record(api_key);
        Arc::new(RuntimeStorageRepositories::new(
            RuntimeStorageBackend::in_memory(vec![StorageProviderKind::Memory]),
            control_plane,
            0,
            0,
        ))
    }

    fn stored_api_key(
        id: &str,
        secret: &str,
        mutate: impl FnOnce(&mut StoredApiKey),
    ) -> StoredApiKey {
        let material = virtual_api_key_material(secret).unwrap();
        let scope = WorkspaceScope::new("tenant-1", "project-1", "workspace-1");
        let mut tenant = TenantContext::default();
        scope.apply_to(&mut tenant);
        tenant.api_key_id = Some(id.into());
        let mut key = StoredApiKey {
            id: id.into(),
            workspace_id: scope.workspace_id,
            tenant_id: scope.tenant_id,
            project_id: scope.project_id,
            name: "Live key".into(),
            key_prefix: material.key_prefix,
            key_hash: material.key_hash,
            last4: material.last4,
            enabled: true,
            scopes: Vec::new(),
            allowed_models: Vec::new(),
            allowed_providers: Vec::new(),
            tenant,
            monthly_token_budget: None,
            request_limit_per_minute: None,
            created_at_unix: 1,
            updated_at_unix: 1,
            rotated_at_unix: None,
            expires_at_unix: None,
            revoked_at_unix: None,
        };
        mutate(&mut key);
        key
    }
}

#[cfg(test)]
#[path = "hardening_test.rs"]
mod hardening_test;

#[cfg(test)]
#[path = "admin_console_test.rs"]
mod admin_console_test;
