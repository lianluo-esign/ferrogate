// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use blake2::{Blake2b512, Digest};
use http::{header, HeaderMap, StatusCode};
use std::{
    collections::HashSet,
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
        };

        assert!(!auth.can_use_model("fast-chat"));
        assert!(!auth.can_use_provider("openai"));
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
