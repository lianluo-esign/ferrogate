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
use ferrogate_auth::ApiKeyAuthenticator;
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
    /// Region(s) this key's requests may route to (issue #173). Empty
    /// means unrestricted, mirroring `allowed_models`/`allowed_providers`.
    pub(crate) region_allowlist: HashSet<String>,
    pub(crate) monthly_token_budget: Option<u64>,
    pub(crate) request_limit_per_minute: Option<u64>,
    #[allow(dead_code)]
    pub(crate) organization_id: Option<String>,
    #[allow(dead_code)]
    pub(crate) team_id: Option<String>,
    #[allow(dead_code)]
    pub(crate) project_id: Option<String>,
    pub(crate) workspace_id: Option<String>,
    #[allow(dead_code)]
    pub(crate) user_id: Option<String>,
    pub(crate) log_bodies: bool,
    pub(crate) rbac_subject: Option<ferrogate_auth::PolicySubject>,
    /// Resolved once per request in `finalize_auth`, merging every
    /// `quota_policies` scope in the tenant/project/workspace/key chain
    /// (P1-3). Model-allowlist and TPM checks that need the request body
    /// (unavailable at header-parse time) consult this instead of
    /// re-querying storage.
    pub(crate) effective_quota: ferrogate_policy::EffectiveQuota,
}

impl AuthContext {
    pub(crate) fn has_scope(&self, scope: &str) -> bool {
        self.scopes.is_empty() || self.scopes.contains(scope)
    }

    pub(crate) fn can_use_model(&self, model: &str) -> bool {
        !self.denied_models.contains(model)
            && (self.allowed_models.is_empty() || self.allowed_models.contains(model))
            && self.effective_quota.allows_model(model)
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
            workspace_id: self.workspace_id.clone(),
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
            region_allowlist: HashSet::new(),
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
            workspace_id: None,
            user_id: None,
            log_bodies: false,
            rbac_subject: None,
            effective_quota: ferrogate_policy::EffectiveQuota::default(),
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
        let auth = authenticate_external(state, &provided_key, required_scope, request_id)?;
        return finalize_auth(state, auth, request_id);
    }

    if let Some(auth) = authenticate_durable(state, &provided_key)? {
        if !auth.has_scope(required_scope) {
            return Err(AuthError {
                status: StatusCode::FORBIDDEN,
                code: "scope_denied",
                message: format!("API key does not have required scope {required_scope}"),
            });
        }
        return finalize_auth(state, auth, request_id);
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
                region_allowlist: configured_key.region_allowlist.iter().cloned().collect(),
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
                workspace_id: None,
                user_id: configured_key.user_id.clone(),
                log_bodies: configured_key.log_bodies.unwrap_or(false),
                rbac_subject: None,
                effective_quota: ferrogate_policy::EffectiveQuota::default(),
            };
            if !auth.has_scope(required_scope) {
                return Err(AuthError {
                    status: StatusCode::FORBIDDEN,
                    code: "scope_denied",
                    message: format!("API key does not have required scope {required_scope}"),
                });
            }
            return finalize_auth(state, auth, request_id);
        }
    }

    Err(AuthError {
        status: StatusCode::UNAUTHORIZED,
        code: "invalid_api_key",
        message: "invalid API key".into(),
    })
}

/// Resolve `presented_key` against the durable Supabase-backed virtual key
/// storage (`ferrogate-storage` / TOK-12). This is the primary key source;
/// the YAML `config.api_keys` loop above only runs as a compatibility
/// fallback when no durable key matches.
fn authenticate_durable(
    state: &AppState,
    provided_key: &str,
) -> std::result::Result<Option<AuthContext>, AuthError> {
    let Some(decision) = state
        .durable_api_key_authenticator()
        .authenticate(provided_key)
    else {
        return Ok(None);
    };
    if decision.monthly_token_budget == Some(0) {
        return Err(AuthError {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "token_budget_exceeded",
            message: "API key token budget is exhausted".into(),
        });
    }
    Ok(Some(AuthContext {
        // Durable/Supabase-backed keys don't carry a region allowlist yet
        // (issue #173's initial cut only wires it through the YAML
        // config.api_keys path) -- unrestricted here, not a silent
        // regression, since region enforcement is new and this path never
        // had it. Extending StoredApiKey/ApiKeyDecision with a
        // region_allowlist column is a straightforward follow-up.
        region_allowlist: HashSet::new(),
        api_key_id: decision.tenant.api_key_id.clone(),
        scopes: decision.scopes.into_iter().collect(),
        allowed_models: decision.allowed_models.into_iter().collect(),
        denied_models: HashSet::new(),
        allowed_providers: decision.allowed_providers.into_iter().collect(),
        denied_providers: HashSet::new(),
        monthly_token_budget: decision.monthly_token_budget,
        request_limit_per_minute: decision.request_limit_per_minute,
        organization_id: decision.tenant.organization_id,
        team_id: decision.tenant.team_id,
        project_id: decision.tenant.project_id,
        workspace_id: decision.tenant.workspace_id,
        user_id: decision.tenant.user_id,
        log_bodies: false,
        rbac_subject: None,
        effective_quota: ferrogate_policy::EffectiveQuota::default(),
    }))
}

/// Final, uniform governance step applied to every successfully identified
/// `AuthContext`, regardless of which auth source produced it (durable,
/// YAML, or external): resolve the multi-level `quota_policies` chain
/// (P1-3), fail closed on a disabled scope or a storage error, and enforce
/// one unified per-minute request budget that is the tighter of the key's
/// own `request_limit_per_minute` (TOK-12) and the resolved quota's
/// `rpm_limit` -- a single counter consumption per request either way.
fn finalize_auth(
    state: &AppState,
    mut auth: AuthContext,
    request_id: &str,
) -> std::result::Result<AuthContext, AuthError> {
    let quota = state
        .resolve_effective_quota(&auth.tenant_context())
        .map_err(|error| AuthError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "quota_resolution_unavailable",
            message: format!("quota policy lookup failed: {error}"),
        })?;
    if let Some(denied_by) = quota.denied_by {
        return Err(AuthError {
            status: StatusCode::FORBIDDEN,
            code: "quota_scope_disabled",
            message: format!(
                "quota policy at scope {} disables this request's tenant/project/workspace/key chain",
                denied_by.as_str()
            ),
        });
    }
    if let Some(budget) = quota.monthly_budget_usd {
        match state.monthly_budget_exceeded(&auth.tenant_context(), budget) {
            Ok(true) => {
                return Err(AuthError {
                    status: StatusCode::TOO_MANY_REQUESTS,
                    code: "monthly_budget_exceeded",
                    message: "quota policy monthly budget has been exhausted for this scope".into(),
                });
            }
            Ok(false) => {}
            Err(error) => {
                return Err(AuthError {
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    code: "quota_resolution_unavailable",
                    message: format!("monthly budget lookup failed: {error}"),
                });
            }
        }
    }
    // Prepaid-credit wallet balance (issue #169) -- distinct from and
    // enforced independently of the monthly_budget_usd check above: a
    // wallet tracks money actually paid, monthly_budget_usd is just a
    // configured throttle. Opt-in per tenant: `wallet_balance_exhausted`
    // returns false (never denies) when the tenant has no wallet row at
    // all, so this is purely additive for every tenant that hasn't
    // adopted prepaid billing.
    match state.wallet_balance_exhausted(&auth.tenant_context()) {
        Ok(true) => {
            return Err(AuthError {
                status: StatusCode::TOO_MANY_REQUESTS,
                code: "wallet_balance_exhausted",
                message: "prepaid credit balance has been exhausted for this tenant".into(),
            });
        }
        Ok(false) => {}
        Err(error) => {
            return Err(AuthError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "quota_resolution_unavailable",
                message: format!("wallet balance lookup failed: {error}"),
            });
        }
    }
    let rpm_limit = min_opt_u64(auth.request_limit_per_minute, quota.rpm_limit);
    if let Some(limit) = rpm_limit {
        require_request_budget(state, &auth, limit, request_id)?;
    }
    auth.effective_quota = quota;
    Ok(auth)
}

fn min_opt_u64(existing: Option<u64>, next: Option<u64>) -> Option<u64> {
    match (existing, next) {
        (Some(existing), Some(next)) => Some(existing.min(next)),
        (Some(existing), None) => Some(existing),
        (None, Some(next)) => Some(next),
        (None, None) => None,
    }
}

fn require_request_budget(
    state: &AppState,
    auth: &AuthContext,
    limit: u64,
    request_id: &str,
) -> std::result::Result<(), AuthError> {
    let Some(api_key_id) = auth.api_key_id.as_deref() else {
        return Ok(());
    };
    match state.try_consume_api_key_request(api_key_id, limit) {
        Ok(true) => Ok(()),
        Ok(false) => Err(AuthError {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "rate_limit_exceeded",
            message: format!("API key request rate limit is exhausted for request {request_id}"),
        }),
        Err(error) => Err(AuthError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "governance_counter_unavailable",
            message: format!("gateway counter backend is unavailable: {error}"),
        }),
    }
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
        region_allowlist: HashSet::new(),
        api_key_id: decision.tenant.api_key_id.clone(),
        scopes: decision.scopes.into_iter().collect(),
        allowed_models: decision.allowed_models.into_iter().collect(),
        denied_models: HashSet::new(),
        allowed_providers: decision.allowed_providers.into_iter().collect(),
        denied_providers: HashSet::new(),
        monthly_token_budget: decision.monthly_token_budget,
        request_limit_per_minute: decision.request_limit_per_minute,
        organization_id: decision.tenant.organization_id,
        team_id: decision.tenant.team_id,
        project_id: decision.tenant.project_id,
        workspace_id: decision.tenant.workspace_id,
        user_id: decision.tenant.user_id,
        log_bodies: false,
        rbac_subject: Some(decision.subject),
        effective_quota: ferrogate_policy::EffectiveQuota::default(),
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
    use crate::config::Config;
    use ferrogate_storage::{StoredApiKey, StoredProject, StoredTenantAccount, StoredWorkspace};

    fn decoy_yaml_key() -> ApiKey {
        ApiKey {
            region_allowlist: Vec::new(),
            id: "decoy".into(),
            name: "Decoy key".into(),
            key_env: None,
            key: Some("decoy-secret".into()),
            key_hash: None,
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
        }
    }

    /// Seeds a tenant -> project -> workspace chain and a durable virtual key
    /// bound to it, returning the plaintext secret. Mirrors exactly what the
    /// `/admin/v1/virtual-keys` create handler persists.
    fn seed_durable_virtual_key(
        state: &AppState,
        key_id: &str,
        secret: &str,
        mutate: impl FnOnce(&mut StoredApiKey),
    ) {
        state
            .upsert_tenant_account(StoredTenantAccount {
                id: "tenant-1".into(),
                name: "Tenant 1".into(),
                slug: "tenant-1".into(),
                status: "active".into(),
                plan_id: "free".into(),
                created_at_unix: 1,
                updated_at_unix: 1,
            })
            .unwrap();
        state
            .upsert_project(StoredProject {
                id: "project-1".into(),
                tenant_id: "tenant-1".into(),
                name: "Project 1".into(),
                slug: "project-1".into(),
                status: "active".into(),
                created_at_unix: 1,
                updated_at_unix: 1,
            })
            .unwrap();
        state
            .upsert_workspace(StoredWorkspace {
                id: "workspace-1".into(),
                project_id: "project-1".into(),
                tenant_id: "tenant-1".into(),
                name: "Workspace 1".into(),
                slug: "workspace-1".into(),
                environment: "prod".into(),
                status: "active".into(),
                created_at_unix: 1,
                updated_at_unix: 1,
            })
            .unwrap();

        let scope = ferrogate_core::WorkspaceScope::new("tenant-1", "project-1", "workspace-1");
        let mut tenant = TenantContext::default();
        scope.apply_to(&mut tenant);
        tenant.api_key_id = Some(key_id.into());
        let material = ferrogate_auth::virtual_api_key_material(secret).unwrap();
        let mut key = StoredApiKey {
            id: key_id.into(),
            workspace_id: scope.workspace_id,
            tenant_id: scope.tenant_id,
            project_id: scope.project_id,
            name: "Live key".into(),
            key_prefix: material.key_prefix,
            key_hash: material.key_hash,
            last4: material.last4,
            enabled: true,
            scopes: vec![],
            allowed_models: vec![],
            allowed_providers: vec![],
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
        state.upsert_virtual_api_key(key).unwrap();
    }

    fn bearer_headers(secret: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {secret}").parse().unwrap(),
        );
        headers
    }

    #[test]
    fn durable_virtual_key_authenticates_ahead_of_yaml_fallback_and_carries_attribution() {
        let secret = "fg_live_e2e_0123456789abcdef";
        let state = AppState::new(Config {
            api_keys: vec![decoy_yaml_key()],
            ..Config::default()
        });
        seed_durable_virtual_key(&state, "vk-1", secret, |key| {
            key.allowed_models = vec!["fast-chat".into()];
            key.monthly_token_budget = Some(500);
        });

        let auth = authenticate(&state, &bearer_headers(secret), "chat.completions", "req-1")
            .expect("durable key should authenticate");

        assert_eq!(auth.api_key_id.as_deref(), Some("vk-1"));
        assert_eq!(auth.organization_id.as_deref(), Some("tenant-1"));
        assert_eq!(auth.project_id.as_deref(), Some("project-1"));
        assert_eq!(auth.workspace_id.as_deref(), Some("workspace-1"));
        assert_eq!(auth.monthly_token_budget, Some(500));
        assert!(auth.can_use_model("fast-chat"));
        assert!(!auth.can_use_model("unlisted-model"));
        assert!(auth.tenant_context().workspace_id.as_deref() == Some("workspace-1"));
    }

    #[test]
    fn yaml_fallback_still_authenticates_when_no_durable_key_matches() {
        let state = AppState::new(Config {
            api_keys: vec![decoy_yaml_key()],
            ..Config::default()
        });
        // No durable key seeded at all; the decoy YAML key must still work.
        let auth = authenticate(
            &state,
            &bearer_headers("decoy-secret"),
            "chat.completions",
            "req-1",
        )
        .expect("yaml fallback should authenticate");
        assert_eq!(auth.api_key_id.as_deref(), Some("decoy"));
    }

    #[test]
    fn durable_virtual_key_rotation_invalidates_previous_secret() {
        let old_secret = "fg_live_rotate_old_0123456789";
        let new_secret = "fg_live_rotate_new_9876543210";
        let state = AppState::new(Config {
            api_keys: vec![decoy_yaml_key()],
            ..Config::default()
        });
        seed_durable_virtual_key(&state, "vk-rotate", old_secret, |_| {});

        assert!(authenticate(
            &state,
            &bearer_headers(old_secret),
            "chat.completions",
            "req-1"
        )
        .is_ok());

        // Simulate the admin rotate handler: same id, freshly derived material.
        let mut key = state.get_virtual_api_key("vk-rotate").unwrap().unwrap();
        let material = ferrogate_auth::virtual_api_key_material(new_secret).unwrap();
        key.key_prefix = material.key_prefix;
        key.key_hash = material.key_hash;
        key.last4 = material.last4;
        key.rotated_at_unix = Some(2);
        state.upsert_virtual_api_key(key).unwrap();

        assert!(authenticate(
            &state,
            &bearer_headers(old_secret),
            "chat.completions",
            "req-1"
        )
        .is_err());
        assert!(authenticate(
            &state,
            &bearer_headers(new_secret),
            "chat.completions",
            "req-1"
        )
        .is_ok());
    }

    #[test]
    fn durable_virtual_key_rejects_disabled_revoked_expired_and_exhausted_budget() {
        let state = AppState::new(Config {
            api_keys: vec![decoy_yaml_key()],
            ..Config::default()
        });

        let disabled_secret = "fg_live_disabled_0123456789ab";
        seed_durable_virtual_key(&state, "vk-disabled", disabled_secret, |key| {
            key.enabled = false;
        });
        assert!(authenticate(
            &state,
            &bearer_headers(disabled_secret),
            "chat.completions",
            "req-1"
        )
        .is_err());

        let revoked_secret = "fg_live_revoked_0123456789ab";
        seed_durable_virtual_key(&state, "vk-revoked", revoked_secret, |key| {
            key.revoked_at_unix = Some(1);
        });
        assert!(authenticate(
            &state,
            &bearer_headers(revoked_secret),
            "chat.completions",
            "req-1"
        )
        .is_err());

        let expired_secret = "fg_live_expired_0123456789ab";
        seed_durable_virtual_key(&state, "vk-expired", expired_secret, |key| {
            key.expires_at_unix = Some(0);
        });
        assert!(authenticate(
            &state,
            &bearer_headers(expired_secret),
            "chat.completions",
            "req-1"
        )
        .is_err());

        let exhausted_secret = "fg_live_exhausted_0123456789";
        seed_durable_virtual_key(&state, "vk-exhausted", exhausted_secret, |key| {
            key.monthly_token_budget = Some(0);
        });
        let error = authenticate(
            &state,
            &bearer_headers(exhausted_secret),
            "chat.completions",
            "req-1",
        )
        .unwrap_err();
        assert_eq!(error.code, "token_budget_exceeded");
    }

    #[test]
    fn durable_virtual_key_enforces_its_own_request_rate_limit() {
        let secret = "fg_live_rpm_0123456789abcdef01";
        let state = AppState::new(Config {
            api_keys: vec![decoy_yaml_key()],
            ..Config::default()
        });
        seed_durable_virtual_key(&state, "vk-rpm", secret, |key| {
            key.request_limit_per_minute = Some(1);
        });

        assert!(authenticate(&state, &bearer_headers(secret), "chat.completions", "req-1").is_ok());
        let error =
            authenticate(&state, &bearer_headers(secret), "chat.completions", "req-2").unwrap_err();
        assert_eq!(error.code, "rate_limit_exceeded");
    }

    #[test]
    fn quota_policy_disabled_at_any_scope_is_a_hard_deny() {
        use ferrogate_storage::{QuotaScopeKind, StoredQuotaPolicy};

        let secret = "fg_live_quota_deny_0123456789ab";
        let state = AppState::new(Config {
            api_keys: vec![decoy_yaml_key()],
            ..Config::default()
        });
        seed_durable_virtual_key(&state, "vk-quota-deny", secret, |_| {});
        state
            .upsert_quota_policy(StoredQuotaPolicy {
                id: "tenant:tenant-1".into(),
                scope_type: QuotaScopeKind::Tenant,
                scope_id: "tenant-1".into(),
                model_allowlist: vec![],
                rpm_limit: None,
                tpm_limit: None,
                monthly_budget_usd: None,
                alert_threshold_pcts: vec![],
                enabled: false,
                created_at_unix: 1,
                updated_at_unix: 1,
            })
            .unwrap();

        let error =
            authenticate(&state, &bearer_headers(secret), "chat.completions", "req-1").unwrap_err();
        assert_eq!(error.code, "quota_scope_disabled");
    }

    #[test]
    fn quota_policy_rpm_composes_with_the_keys_own_limit_as_a_single_counter() {
        use ferrogate_storage::{QuotaScopeKind, StoredQuotaPolicy};

        let secret = "fg_live_quota_rpm_0123456789ab";
        let state = AppState::new(Config {
            api_keys: vec![decoy_yaml_key()],
            ..Config::default()
        });
        // Key's own RPM cap is generous (10); the tenant-level quota policy
        // is much tighter (1) and must be the one that actually governs.
        seed_durable_virtual_key(&state, "vk-quota-rpm", secret, |key| {
            key.request_limit_per_minute = Some(10);
        });
        state
            .upsert_quota_policy(StoredQuotaPolicy {
                id: "tenant:tenant-1".into(),
                scope_type: QuotaScopeKind::Tenant,
                scope_id: "tenant-1".into(),
                model_allowlist: vec![],
                rpm_limit: Some(1),
                tpm_limit: None,
                monthly_budget_usd: None,
                alert_threshold_pcts: vec![],
                enabled: true,
                created_at_unix: 1,
                updated_at_unix: 1,
            })
            .unwrap();

        assert!(authenticate(&state, &bearer_headers(secret), "chat.completions", "req-1").is_ok());
        let error =
            authenticate(&state, &bearer_headers(secret), "chat.completions", "req-2").unwrap_err();
        assert_eq!(error.code, "rate_limit_exceeded");
    }

    #[test]
    fn quota_policy_model_allowlist_intersects_with_the_keys_own_allowlist() {
        use ferrogate_storage::{QuotaScopeKind, StoredQuotaPolicy};

        let secret = "fg_live_quota_models_0123456789";
        let state = AppState::new(Config {
            api_keys: vec![decoy_yaml_key()],
            ..Config::default()
        });
        seed_durable_virtual_key(&state, "vk-quota-models", secret, |key| {
            key.allowed_models = vec!["fast-chat".into(), "smart-chat".into()];
        });
        state
            .upsert_quota_policy(StoredQuotaPolicy {
                id: "tenant:tenant-1".into(),
                scope_type: QuotaScopeKind::Tenant,
                scope_id: "tenant-1".into(),
                model_allowlist: vec!["fast-chat".into()],
                rpm_limit: None,
                tpm_limit: None,
                monthly_budget_usd: None,
                alert_threshold_pcts: vec![],
                enabled: true,
                created_at_unix: 1,
                updated_at_unix: 1,
            })
            .unwrap();

        let auth = authenticate(&state, &bearer_headers(secret), "chat.completions", "req-1")
            .expect("request should authenticate");
        assert!(auth.can_use_model("fast-chat"));
        assert!(
            !auth.can_use_model("smart-chat"),
            "tenant quota policy must narrow the key's own allowlist, not widen it"
        );
    }

    #[test]
    fn quota_policy_monthly_budget_exceeded_hard_denies_further_requests() {
        use crate::config::{Model, Provider};
        use ferrogate_core::RequestContext;
        use ferrogate_providers::{ProviderUsage, RoutingStrategy};
        use ferrogate_storage::{QuotaScopeKind, StoredQuotaPolicy};

        let secret = "fg_live_quota_budget_0123456789";
        let state = AppState::new(Config {
            api_keys: vec![decoy_yaml_key()],
            providers: vec![Provider {
                region: None,
                aws_access_key_id: None,
                aws_secret_access_key_env: None,
                aws_session_token_env: None,
                gcp_project_id: None,
                gcp_access_token_env: None,
                name: "openai".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:10001/v1".into(),
                api_key_env: None,
                secret_ref: None,
                openrouter_http_referer: None,
                openrouter_x_title: None,
                enabled: true,
            }],
            models: vec![Model {
                name: "fast-chat".into(),
                provider: "openai".into(),
                provider_model: "gpt-4o-mini".into(),
                routing_strategy: RoutingStrategy::Priority,
                fallbacks: vec![],
                visible_organization_ids: vec![],
                visible_project_ids: vec![],
                capabilities: vec![],
                context_window: None,
                input_price_per_1m: Some(1.0),
                output_price_per_1m: Some(2.0),
                enabled: true,
                cache_enabled: None,
            }],
            ..Config::default()
        });
        seed_durable_virtual_key(&state, "vk-quota-budget", secret, |_| {});
        state
            .upsert_quota_policy(StoredQuotaPolicy {
                id: "tenant:tenant-1".into(),
                scope_type: QuotaScopeKind::Tenant,
                scope_id: "tenant-1".into(),
                model_allowlist: vec![],
                rpm_limit: None,
                tpm_limit: None,
                monthly_budget_usd: Some(0.001),
                alert_threshold_pcts: vec![],
                enabled: true,
                created_at_unix: 1,
                updated_at_unix: 1,
            })
            .unwrap();

        assert!(
            authenticate(&state, &bearer_headers(secret), "chat.completions", "req-1").is_ok(),
            "no spend has been recorded yet; the budget must not trip prematurely"
        );

        // Settle a real billing event against the key's own tenant/project/
        // workspace/key attribution so the P1-4 monthly rollup accumulates
        // enough cost ($0.003 at the configured $1/$2 per-1M pricing) to
        // exceed the $0.001 tenant-level budget cap.
        let request = RequestContext {
            request_id: "fg-budget-spend".into(),
            trace_id: None,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            route: Some("openai.chat.completions".into()),
            upstream: Some("openai".into()),
            tenant: TenantContext {
                organization_id: Some("tenant-1".into()),
                team_id: None,
                project_id: Some("project-1".into()),
                workspace_id: Some("workspace-1".into()),
                user_id: None,
                api_key_id: Some("vk-quota-budget".into()),
            },
        };
        state
            .record_billing_event(
                crate::state::BillingEventDraft {
                    request: &request,
                    logical_model: "fast-chat",
                    provider: "openai",
                    provider_model: "gpt-4o-mini",
                    status_code: 200,
                    latency_ms: Some(10),
                    metadata: None,
                },
                &ProviderUsage {
                    prompt_tokens: Some(1000),
                    completion_tokens: Some(1000),
                    total_tokens: Some(2000),
                },
            )
            .unwrap();

        let error =
            authenticate(&state, &bearer_headers(secret), "chat.completions", "req-2").unwrap_err();
        assert_eq!(error.code, "monthly_budget_exceeded");
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
            region_allowlist: HashSet::new(),
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
            workspace_id: None,
            user_id: None,
            log_bodies: false,
            rbac_subject: None,
            effective_quota: ferrogate_policy::EffectiveQuota::default(),
        };
        assert!(auth.can_use_model("fast-chat"));
        assert!(!auth.can_use_model("expensive-model"));
        assert!(!auth.can_record_bodies(true));
    }

    #[test]
    fn auth_context_provider_allowlist() {
        let auth = AuthContext {
            region_allowlist: HashSet::new(),
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
            workspace_id: None,
            user_id: None,
            log_bodies: true,
            rbac_subject: None,
            effective_quota: ferrogate_policy::EffectiveQuota::default(),
        };
        assert!(auth.can_use_provider("openai"));
        assert!(!auth.can_use_provider("anthropic"));
        assert!(auth.can_record_bodies(true));
        assert!(!auth.can_record_bodies(false));
    }

    #[test]
    fn auth_context_denylist_overrides_allowlist() {
        let auth = AuthContext {
            region_allowlist: HashSet::new(),
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
            workspace_id: None,
            user_id: None,
            log_bodies: false,
            rbac_subject: None,
            effective_quota: ferrogate_policy::EffectiveQuota::default(),
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
            region_allowlist: Vec::new(),
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
