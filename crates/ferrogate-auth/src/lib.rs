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
use blake2::{Blake2b512, Digest};
use ferrogate_core::TenantContext;
use ferrogate_storage::{RuntimeStorageRepositories, StoredApiKey};
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
}

impl std::fmt::Debug for AuthService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthService")
            .field("rbac", &self.rbac)
            .field("api_key_authenticator", &"dyn ApiKeyAuthenticator")
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
        }
    }

    pub fn with_api_key_authenticator(
        data: AuthServiceData,
        api_key_authenticator: Arc<dyn ApiKeyAuthenticator>,
    ) -> Self {
        Self {
            rbac: RbacAuthService::new(data),
            api_key_authenticator,
        }
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
            .finish()
    }
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
    let service = Arc::new(match config.api_key_authenticator {
        Some(api_key_authenticator) => {
            AuthService::with_api_key_authenticator(config.data, api_key_authenticator)
        }
        None => AuthService::from_data(config.data),
    });
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
        .write_all(&response.to_bytes())
        .context("failed to write auth service response")
}

fn route_request(service: &AuthService, request: HttpRequest) -> HttpResponse {
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
    body: Vec<u8>,
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

    let headers = String::from_utf8_lossy(&buffer[..header_end]);
    let mut lines = headers.lines();
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
    let content_length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
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

    fn to_bytes(&self) -> Vec<u8> {
        let status_text = match self.status {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            _ => "Internal Server Error",
        };
        let headers = format!(
            "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
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
