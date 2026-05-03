use http::{header, HeaderMap, StatusCode};
use std::{
    collections::HashSet,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{config::ApiKey, state::AppState};

#[derive(Debug, Clone)]
pub(crate) struct AuthContext {
    #[allow(dead_code)]
    pub(crate) api_key_id: Option<String>,
    pub(crate) scopes: HashSet<String>,
    pub(crate) allowed_models: HashSet<String>,
    pub(crate) allowed_providers: HashSet<String>,
    pub(crate) monthly_token_budget: Option<u64>,
    #[allow(dead_code)]
    pub(crate) organization_id: Option<String>,
    #[allow(dead_code)]
    pub(crate) team_id: Option<String>,
    #[allow(dead_code)]
    pub(crate) project_id: Option<String>,
    #[allow(dead_code)]
    pub(crate) user_id: Option<String>,
}

impl AuthContext {
    pub(crate) fn has_scope(&self, scope: &str) -> bool {
        self.scopes.is_empty() || self.scopes.contains(scope)
    }

    pub(crate) fn can_use_model(&self, model: &str) -> bool {
        self.allowed_models.is_empty() || self.allowed_models.contains(model)
    }

    pub(crate) fn can_use_provider(&self, provider: &str) -> bool {
        self.allowed_providers.is_empty() || self.allowed_providers.contains(provider)
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
    _request_id: &str,
) -> std::result::Result<AuthContext, AuthError> {
    if !state.auth_required() {
        return Ok(AuthContext {
            api_key_id: None,
            scopes: HashSet::new(),
            allowed_models: HashSet::new(),
            allowed_providers: HashSet::new(),
            monthly_token_budget: None,
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
        if let Some(secret) = configured_key.secret_value() {
            if constant_time_eq(provided_key.as_bytes(), secret.as_bytes()) {
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
                    allowed_providers: configured_key.allowed_providers.iter().cloned().collect(),
                    monthly_token_budget: configured_key.monthly_token_budget,
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

    fn is_expired(&self, now_unix_seconds: u64) -> bool {
        self.expires_at_unix
            .is_some_and(|expires_at| expires_at <= now_unix_seconds)
    }
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
            allowed_providers: HashSet::new(),
            monthly_token_budget: None,
            organization_id: None,
            team_id: None,
            project_id: None,
            user_id: None,
        };
        assert!(auth.can_use_model("fast-chat"));
        assert!(!auth.can_use_model("expensive-model"));
    }

    #[test]
    fn auth_context_provider_allowlist() {
        let auth = AuthContext {
            api_key_id: Some("key".into()),
            scopes: HashSet::new(),
            allowed_models: HashSet::new(),
            allowed_providers: HashSet::from(["openai".into()]),
            monthly_token_budget: Some(1_000),
            organization_id: Some("org".into()),
            team_id: None,
            project_id: Some("project".into()),
            user_id: None,
        };
        assert!(auth.can_use_provider("openai"));
        assert!(!auth.can_use_provider("anthropic"));
    }
}
