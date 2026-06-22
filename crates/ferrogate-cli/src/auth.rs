// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use blake2::{Blake2b512, Digest};
use http::{header, HeaderMap, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::json;
use std::{
    collections::HashSet,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{config::ApiKey, state::AppState};
use ferrogate_core::TenantContext;

#[derive(Debug, Clone)]
pub(crate) struct AuthContext {
    #[allow(dead_code)]
    pub(crate) api_key_id: Option<String>,
    pub(crate) scopes: HashSet<String>,
    pub(crate) allowed_models: HashSet<String>,
    pub(crate) denied_models: HashSet<String>,
    pub(crate) allowed_providers: HashSet<String>,
    pub(crate) denied_providers: HashSet<String>,
    pub(crate) monthly_token_budget: Option<u64>,
    pub(crate) request_limit_per_minute: Option<u64>,
    #[allow(dead_code)]
    pub(crate) organization_id: Option<String>,
    #[allow(dead_code)]
    pub(crate) team_id: Option<String>,
    #[allow(dead_code)]
    pub(crate) project_id: Option<String>,
    #[allow(dead_code)]
    pub(crate) user_id: Option<String>,
    pub(crate) log_bodies: bool,
    pub(crate) rbac_subject: Option<ferrogate_auth::PolicySubject>,
}

impl AuthContext {
    pub(crate) fn has_scope(&self, scope: &str) -> bool {
        self.scopes.is_empty() || self.scopes.contains(scope)
    }

    pub(crate) fn can_use_model(&self, model: &str) -> bool {
        !self.denied_models.contains(model)
            && (self.allowed_models.is_empty() || self.allowed_models.contains(model))
    }

    pub(crate) fn can_use_provider(&self, provider: &str) -> bool {
        !self.denied_providers.contains(provider)
            && (self.allowed_providers.is_empty() || self.allowed_providers.contains(provider))
    }

    pub(crate) fn tenant_context(&self) -> TenantContext {
        TenantContext {
            organization_id: self.organization_id.clone(),
            team_id: self.team_id.clone(),
            project_id: self.project_id.clone(),
            user_id: self.user_id.clone(),
            api_key_id: self.api_key_id.clone(),
        }
    }

    pub(crate) fn can_record_bodies(&self, global_log_bodies: bool) -> bool {
        global_log_bodies && self.log_bodies
    }
}

#[derive(Debug)]
pub(crate) struct AuthError {
    pub(crate) status: StatusCode,
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

pub(crate) fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    required_scope: &str,
    request_id: &str,
) -> std::result::Result<AuthContext, AuthError> {
    if !state.auth_required() {
        return Ok(AuthContext {
            api_key_id: None,
            scopes: HashSet::new(),
            allowed_models: HashSet::new(),
            denied_models: HashSet::new(),
            allowed_providers: HashSet::new(),
            denied_providers: HashSet::new(),
            monthly_token_budget: None,
            request_limit_per_minute: None,
            organization_id: None,
            team_id: None,
            project_id: None,
            user_id: None,
            log_bodies: false,
            rbac_subject: None,
        });
    }

    let Some(provided_key) = extract_api_key(headers) else {
        return Err(AuthError {
            status: StatusCode::UNAUTHORIZED,
            code: "missing_api_key",
            message: "missing API key; use Authorization: Bearer or x-api-key".into(),
        });
    };

    if state.config.auth_service.enabled {
        return authenticate_external(state, &provided_key, required_scope, request_id);
    }

    for configured_key in &state.config.api_keys {
        if configured_key.matches_presented_key(&provided_key) {
            if !configured_key.enabled {
                return Err(AuthError {
                    status: StatusCode::FORBIDDEN,
                    code: "api_key_disabled",
                    message: "API key is disabled".into(),
                });
            }
            if configured_key.is_expired(now_unix_seconds()) {
                return Err(AuthError {
                    status: StatusCode::FORBIDDEN,
                    code: "api_key_expired",
                    message: "API key is expired".into(),
                });
            }
            if configured_key.monthly_token_budget == Some(0) {
                return Err(AuthError {
                    status: StatusCode::TOO_MANY_REQUESTS,
                    code: "token_budget_exceeded",
                    message: "API key token budget is exhausted".into(),
                });
            }
            let auth = AuthContext {
                api_key_id: Some(configured_key.id.clone()),
                scopes: configured_key.scopes.iter().cloned().collect(),
                allowed_models: configured_key.allowed_models.iter().cloned().collect(),
                denied_models: configured_key.denied_models.iter().cloned().collect(),
                allowed_providers: configured_key.allowed_providers.iter().cloned().collect(),
                denied_providers: configured_key.denied_providers.iter().cloned().collect(),
                monthly_token_budget: configured_key.monthly_token_budget,
                request_limit_per_minute: configured_key.request_limit_per_minute,
                organization_id: configured_key.organization_id.clone(),
                team_id: configured_key.team_id.clone(),
                project_id: configured_key.project_id.clone(),
                user_id: configured_key.user_id.clone(),
                log_bodies: configured_key.log_bodies.unwrap_or(false),
                rbac_subject: None,
            };
            if !auth.has_scope(required_scope) {
                return Err(AuthError {
                    status: StatusCode::FORBIDDEN,
                    code: "scope_denied",
                    message: format!("API key does not have required scope {required_scope}"),
                });
            }
            if let Some(limit) = configured_key.request_limit_per_minute {
                match state.try_consume_api_key_request(&configured_key.id, limit) {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(AuthError {
                            status: StatusCode::TOO_MANY_REQUESTS,
                            code: "rate_limit_exceeded",
                            message: format!(
                                "API key request rate limit is exhausted for request {request_id}"
                            ),
                        });
                    }
                    Err(error) => {
                        return Err(AuthError {
                            status: StatusCode::SERVICE_UNAVAILABLE,
                            code: "governance_counter_unavailable",
                            message: format!("gateway counter backend is unavailable: {error}"),
                        });
                    }
                }
            }
            return Ok(auth);
        }
    }

    Err(AuthError {
        status: StatusCode::UNAUTHORIZED,
        code: "invalid_api_key",
        message: "invalid API key".into(),
    })
}

pub(crate) fn authorize_external_rbac(
    state: &AppState,
    auth: &AuthContext,
    action: &str,
    resource: &str,
) -> std::result::Result<(), AuthError> {
    if !state.config.auth_service.enabled {
        return Ok(());
    }
    let Some(subject) = auth.rbac_subject.clone() else {
        return Err(AuthError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "external_auth_unavailable",
            message: "external auth service did not return an RBAC subject".into(),
        });
    };
    let request = ferrogate_auth::AuthorizeRequest {
        tenant: auth.tenant_context(),
        subject,
        action: action.to_string(),
        resource: resource.to_string(),
    };
    let decision: ferrogate_auth::AuthorizationDecision =
        auth_service_post_json(state, "/v1/auth/authorize", &request)
            .map_err(external_authorize_error)?;
    if decision.allowed {
        return Ok(());
    }
    Err(AuthError {
        status: StatusCode::FORBIDDEN,
        code: "rbac_denied",
        message: format!(
            "external RBAC denied {action} on {resource}: {}",
            decision.reason
        ),
    })
}

fn authenticate_external(
    state: &AppState,
    provided_key: &str,
    required_scope: &str,
    request_id: &str,
) -> std::result::Result<AuthContext, AuthError> {
    let request = ferrogate_auth::ResolveApiKeyRequest {
        presented_key: provided_key.to_string(),
    };
    let decision: ferrogate_auth::AuthDecision =
        auth_service_post_json(state, "/v1/auth/resolve-api-key", &request)
            .map_err(|error| external_auth_error(error, request_id))?;
    let auth = AuthContext {
        api_key_id: decision.tenant.api_key_id.clone(),
        scopes: decision.scopes.into_iter().collect(),
        allowed_models: HashSet::new(),
        denied_models: HashSet::new(),
        allowed_providers: HashSet::new(),
        denied_providers: HashSet::new(),
        monthly_token_budget: None,
        request_limit_per_minute: None,
        organization_id: decision.tenant.organization_id,
        team_id: decision.tenant.team_id,
        project_id: decision.tenant.project_id,
        user_id: decision.tenant.user_id,
        log_bodies: false,
        rbac_subject: Some(decision.subject),
    };
    if !external_scope_allows(&auth.scopes, required_scope) {
        return Err(AuthError {
            status: StatusCode::FORBIDDEN,
            code: "scope_denied",
            message: format!("API key does not have required scope {required_scope}"),
        });
    }
    Ok(auth)
}

fn external_scope_allows(scopes: &HashSet<String>, required_scope: &str) -> bool {
    scopes.contains(required_scope) || scopes.contains("*")
}

fn external_auth_error(error: AuthServiceClientError, request_id: &str) -> AuthError {
    match error {
        AuthServiceClientError::HttpStatus { status: 401, body } => AuthError {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_api_key",
            message: sanitize_auth_error_body(&body),
        },
        AuthServiceClientError::HttpStatus { status: 403, body } => AuthError {
            status: StatusCode::FORBIDDEN,
            code: "external_auth_denied",
            message: sanitize_auth_error_body(&body),
        },
        other => AuthError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "external_auth_unavailable",
            message: format!(
                "external auth service is unavailable for request {request_id}: {other}"
            ),
        },
    }
}

fn external_authorize_error(error: AuthServiceClientError) -> AuthError {
    match error {
        AuthServiceClientError::HttpStatus { status, body } if status == 401 || status == 403 => {
            AuthError {
                status: StatusCode::FORBIDDEN,
                code: "rbac_denied",
                message: sanitize_auth_error_body(&body),
            }
        }
        other => AuthError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "external_auth_unavailable",
            message: format!("external auth service authorization failed: {other}"),
        },
    }
}

fn sanitize_auth_error_body(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .pointer("/error/message")
                .and_then(|message| message.as_str())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "external auth service rejected the request".into())
}

fn auth_service_post_json<T, R>(
    state: &AppState,
    path: &str,
    payload: &T,
) -> std::result::Result<R, AuthServiceClientError>
where
    T: serde::Serialize,
    R: DeserializeOwned,
{
    let body = serde_json::to_vec(payload)
        .map_err(|error| AuthServiceClientError::Request(error.to_string()))?;
    let endpoint = build_auth_service_target(&state.config.auth_service.endpoint, path)?;
    let timeout = Duration::from_millis(state.config.auth_service.timeout_millis);
    let attempts = state.config.auth_service.max_retries.saturating_add(1);
    let backoff = Duration::from_millis(state.config.auth_service.retry_backoff_millis);
    let mut last_retryable_error = None;
    for attempt in 0..attempts {
        match auth_service_post_json_once(&endpoint, &body, timeout) {
            Ok(response) => return Ok(response),
            Err(error) if error.is_retryable() && attempt + 1 < attempts => {
                last_retryable_error = Some(error);
                std::thread::sleep(backoff);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_retryable_error.unwrap_or_else(|| {
        AuthServiceClientError::Transport("auth service retry budget exhausted".into())
    }))
}

fn auth_service_post_json_once<R: DeserializeOwned>(
    endpoint: &AuthServiceTarget,
    body: &[u8],
    timeout: Duration,
) -> std::result::Result<R, AuthServiceClientError> {
    let address = endpoint
        .host_port
        .to_socket_addrs()
        .map_err(|error| AuthServiceClientError::Transport(error.to_string()))?
        .next()
        .ok_or_else(|| {
            AuthServiceClientError::Transport("auth service host resolved no addresses".into())
        })?;
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| AuthServiceClientError::Transport(error.to_string()))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| AuthServiceClientError::Transport(error.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| AuthServiceClientError::Transport(error.to_string()))?;
    write!(
        stream,
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        endpoint.path,
        endpoint.host_port,
        body.len()
    )
    .map_err(|error| AuthServiceClientError::Transport(error.to_string()))?;
    stream
        .write_all(body)
        .map_err(|error| AuthServiceClientError::Transport(error.to_string()))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| AuthServiceClientError::Transport(error.to_string()))?;
    parse_auth_service_response(&response)
}

fn parse_auth_service_response<R: DeserializeOwned>(
    response: &[u8],
) -> std::result::Result<R, AuthServiceClientError> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| AuthServiceClientError::Response("missing HTTP header terminator".into()))?;
    let headers = String::from_utf8_lossy(&response[..header_end]);
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| AuthServiceClientError::Response("missing HTTP status".into()))?;
    let body = String::from_utf8_lossy(&response[header_end + 4..]).into_owned();
    if !(200..300).contains(&status) {
        return Err(AuthServiceClientError::HttpStatus { status, body });
    }
    serde_json::from_str(&body).map_err(|error| AuthServiceClientError::Response(error.to_string()))
}

fn build_auth_service_target(
    endpoint: &str,
    path: &str,
) -> std::result::Result<AuthServiceTarget, AuthServiceClientError> {
    let trimmed = endpoint.trim().trim_end_matches('/');
    let rest = trimmed.strip_prefix("http://").ok_or_else(|| {
        AuthServiceClientError::Request("auth service endpoint must use http://".into())
    })?;
    let (host_port, base_path) = rest.split_once('/').unwrap_or((rest, ""));
    if host_port.trim().is_empty() {
        return Err(AuthServiceClientError::Request(
            "auth service endpoint host is empty".into(),
        ));
    }
    let path = if base_path.is_empty() {
        path.to_string()
    } else {
        format!(
            "/{}/{}",
            base_path.trim_matches('/'),
            path.trim_start_matches('/')
        )
    };
    Ok(AuthServiceTarget {
        host_port: host_port.to_string(),
        path,
    })
}

#[derive(Debug)]
struct AuthServiceTarget {
    host_port: String,
    path: String,
}

#[derive(Debug)]
enum AuthServiceClientError {
    Request(String),
    Transport(String),
    Response(String),
    HttpStatus { status: u16, body: String },
}

impl AuthServiceClientError {
    fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Transport(_)
                | Self::HttpStatus {
                    status: 500..=599,
                    ..
                }
        )
    }
}

impl std::fmt::Display for AuthServiceClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Request(message) => write!(formatter, "{message}"),
            Self::Transport(message) => write!(formatter, "{message}"),
            Self::Response(message) => write!(formatter, "{message}"),
            Self::HttpStatus { status, body } => {
                let summary = serde_json::from_str::<serde_json::Value>(body)
                    .unwrap_or_else(|_| json!({ "body": body }));
                write!(formatter, "auth service returned HTTP {status}: {summary}")
            }
        }
    }
}

impl ApiKey {
    fn matches_presented_key(&self, presented_key: &str) -> bool {
        if let Some(secret) = self.secret_value() {
            if constant_time_eq(presented_key.as_bytes(), secret.as_bytes()) {
                return true;
            }
        }
        self.key_hash
            .as_deref()
            .is_some_and(|hash| verify_api_key_secret(presented_key, hash))
    }

    fn secret_value(&self) -> Option<String> {
        if let Some(env_name) = &self.key_env {
            if let Ok(value) = std::env::var(env_name) {
                return Some(value);
            }
        }
        self.key.clone()
    }

    fn is_expired(&self, now_unix_seconds: u64) -> bool {
        self.expires_at_unix
            .is_some_and(|expires_at| expires_at <= now_unix_seconds)
    }
}

pub(crate) fn hash_api_key_secret(secret: &str) -> String {
    let digest = Blake2b512::digest(secret.as_bytes());
    format!("blake2b:{}", encode_hex(&digest))
}

fn verify_api_key_secret(secret: &str, expected_hash: &str) -> bool {
    constant_time_eq(
        hash_api_key_secret(secret).as_bytes(),
        expected_hash.as_bytes(),
    )
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

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(crate) fn extract_api_key(headers: &HeaderMap) -> Option<String> {
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

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
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
            denied_models: HashSet::new(),
            allowed_providers: HashSet::new(),
            denied_providers: HashSet::new(),
            monthly_token_budget: None,
            request_limit_per_minute: None,
            organization_id: None,
            team_id: None,
            project_id: None,
            user_id: None,
            log_bodies: false,
            rbac_subject: None,
        };
        assert!(auth.can_use_model("fast-chat"));
        assert!(!auth.can_use_model("expensive-model"));
        assert!(!auth.can_record_bodies(true));
    }

    #[test]
    fn auth_context_provider_allowlist() {
        let auth = AuthContext {
            api_key_id: Some("key".into()),
            scopes: HashSet::new(),
            allowed_models: HashSet::new(),
            denied_models: HashSet::new(),
            allowed_providers: HashSet::from(["openai".into()]),
            denied_providers: HashSet::new(),
            monthly_token_budget: Some(1_000),
            request_limit_per_minute: Some(60),
            organization_id: Some("org".into()),
            team_id: None,
            project_id: Some("project".into()),
            user_id: None,
            log_bodies: true,
            rbac_subject: None,
        };
        assert!(auth.can_use_provider("openai"));
        assert!(!auth.can_use_provider("anthropic"));
        assert!(auth.can_record_bodies(true));
        assert!(!auth.can_record_bodies(false));
    }

    #[test]
    fn auth_context_denylist_overrides_allowlist() {
        let auth = AuthContext {
            api_key_id: Some("key".into()),
            scopes: HashSet::new(),
            allowed_models: HashSet::from(["fast-chat".into()]),
            denied_models: HashSet::from(["fast-chat".into()]),
            allowed_providers: HashSet::from(["openai".into()]),
            denied_providers: HashSet::from(["openai".into()]),
            monthly_token_budget: None,
            request_limit_per_minute: None,
            organization_id: None,
            team_id: None,
            project_id: None,
            user_id: None,
            log_bodies: false,
            rbac_subject: None,
        };

        assert!(!auth.can_use_model("fast-chat"));
        assert!(!auth.can_use_provider("openai"));
    }

    #[test]
    fn external_scopes_must_explicitly_allow_required_scope() {
        assert!(!external_scope_allows(&HashSet::new(), "chat.completions"));
        assert!(external_scope_allows(
            &HashSet::from(["chat.completions".into()]),
            "chat.completions"
        ));
        assert!(external_scope_allows(
            &HashSet::from(["*".into()]),
            "chat.completions"
        ));
    }

    #[test]
    fn verifies_hashed_api_key_secret() {
        let hash = hash_api_key_secret("client-secret");
        let key = ApiKey {
            id: "key".into(),
            name: "Key".into(),
            key_env: None,
            key: None,
            key_hash: Some(hash.clone()),
            enabled: true,
            scopes: vec![],
            allowed_models: vec![],
            denied_models: vec![],
            allowed_providers: vec![],
            denied_providers: vec![],
            organization_id: None,
            team_id: None,
            project_id: None,
            user_id: None,
            monthly_token_budget: None,
            request_limit_per_minute: None,
            expires_at_unix: None,
            log_bodies: None,
            cache_enabled: None,
        };

        assert!(hash.starts_with("blake2b:"));
        assert!(key.matches_presented_key("client-secret"));
        assert!(!key.matches_presented_key("wrong-secret"));
    }
}
