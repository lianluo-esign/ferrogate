// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for CLI authentication, kept outside business logic.

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
        workspace_id: None,
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
fn yaml_key_carries_explicit_workspace_and_user_attribution() {
    let mut key = decoy_yaml_key();
    key.organization_id = Some("tenant-identity".into());
    key.project_id = Some("project-identity".into());
    key.workspace_id = Some("workspace-identity".into());
    key.user_id = Some("user-identity".into());
    let state = AppState::new(Config {
        api_keys: vec![key],
        ..Config::default()
    });

    let auth = authenticate(
        &state,
        &bearer_headers("decoy-secret"),
        "chat.completions",
        "req-identity",
    )
    .unwrap();

    assert_eq!(auth.organization_id.as_deref(), Some("tenant-identity"));
    assert_eq!(auth.project_id.as_deref(), Some("project-identity"));
    assert_eq!(auth.workspace_id.as_deref(), Some("workspace-identity"));
    assert_eq!(auth.user_id.as_deref(), Some("user-identity"));
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
            asset_storage_quota_bytes: None,
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
            asset_storage_quota_bytes: None,
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
            asset_storage_quota_bytes: None,
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
            asset_storage_quota_bytes: None,
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
        workspace_id: None,
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
