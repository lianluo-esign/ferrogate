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
use ferrogate_core::TenantContext;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    sync::Arc,
};

const MAX_REQUEST_BYTES: usize = 1024 * 1024;

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
}

pub trait ApiKeyAuthenticator {
    fn authenticate(&self, presented_key: &str) -> Option<AuthDecision>;
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
        })
    }
}

#[derive(Debug, Clone)]
pub struct AuthServiceConfig {
    pub listen: String,
    pub data: AuthServiceData,
}

pub fn serve(config: AuthServiceConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.listen)
        .with_context(|| format!("failed to bind ferrogate-auth on {}", config.listen))?;
    let service = Arc::new(RbacAuthService::new(config.data));
    println!("ferrogate-auth listening on {}", config.listen);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let service = service.clone();
                std::thread::spawn(move || {
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

fn handle_connection(mut stream: TcpStream, service: &RbacAuthService) -> anyhow::Result<()> {
    let request = read_http_request(&mut stream)?;
    let response = route_request(service, request);
    stream
        .write_all(&response.to_bytes())
        .context("failed to write auth service response")
}

fn route_request(service: &RbacAuthService, request: HttpRequest) -> HttpResponse {
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
    while buffer.len() < body_start + content_length {
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
        body: buffer[body_start..body_start + content_length].to_vec(),
    })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
