// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for the request-admission pipeline, kept outside
// business logic. Every case here drives a real `AppState`; the credential-only
// cases are the sibling `auth_test.rs`, under the same `auth` module. The two
// files were kept apart on the #553 stage 3b merge because each defines fixture
// helpers under names the other also uses.

use super::*;
use ferrogate_config::{ApiKey, Config};
use ferrogate_core::TenantContext;
use ferrogate_storage::{StoredApiKey, StoredProject, StoredTenantAccount, StoredWorkspace};
use http::header;

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

/// Synchronous shim over the now-`async` `super::authenticate` (issue #373).
/// Every test below drives the auth chain on a fresh current-thread runtime
/// via the same `block_on` helper already used for the storage setup calls,
/// so the test bodies stay synchronous and unchanged. Shadows the glob-
/// imported `authenticate` for unqualified calls in this module only.
fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    required_scope: &str,
    request_id: &str,
) -> Result<AuthContext, AuthError> {
    block_on(super::authenticate(
        state,
        headers,
        required_scope,
        request_id,
    ))
}

/// The ordinary static key most tests here need: it exists to make
/// `auth_required()` true and to be authenticated as the root/bootstrap key the
/// rest of this suite assumes.
///
/// It declares `platform_operator = true` since #540. Before the flip, "the
/// field is absent" and "this key is root" were the same fixture, so a helper
/// could be both at once; now they are different keys and the undeclared one is
/// [`undeclared_yaml_key`]. Anything that wants the undeclared shape must ask
/// for it by name -- otherwise the flip could be reverted and this file, which
/// is where it is pinned, would still be green.
fn decoy_yaml_key() -> ApiKey {
    ApiKey {
        platform_operator: Some(true),
        ..undeclared_yaml_key()
    }
}

/// The pre-#515 shape: a key that names no tenant and never says
/// `platform_operator`. What it is worth is now entirely `[tenancy]
/// implicit_platform_operator`'s answer -- refused by default, root only where
/// a deployment explicitly asks for the legacy behaviour.
fn undeclared_yaml_key() -> ApiKey {
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
        platform_operator: None,
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
    block_on(state.upsert_tenant_account(StoredTenantAccount {
        id: "tenant-1".into(),
        name: "Tenant 1".into(),
        slug: "tenant-1".into(),
        status: "active".into(),
        plan_id: "free".into(),
        created_at_unix: 1,
        updated_at_unix: 1,
    }))
    .unwrap();
    block_on(state.upsert_project(StoredProject {
        id: "project-1".into(),
        tenant_id: "tenant-1".into(),
        name: "Project 1".into(),
        slug: "project-1".into(),
        status: "active".into(),
        created_at_unix: 1,
        updated_at_unix: 1,
    }))
    .unwrap();
    block_on(state.upsert_workspace(StoredWorkspace {
        id: "workspace-1".into(),
        project_id: "project-1".into(),
        tenant_id: "tenant-1".into(),
        name: "Workspace 1".into(),
        slug: "workspace-1".into(),
        environment: "prod".into(),
        status: "active".into(),
        created_at_unix: 1,
        updated_at_unix: 1,
    }))
    .unwrap();

    let scope = ferrogate_core::WorkspaceScope::new("tenant-1", "project-1", "workspace-1");
    let mut tenant = TenantContext::default();
    scope.apply_to(&mut tenant);
    tenant.api_key_id = Some(key_id.into());
    let material = ferrogate_auth_service::virtual_api_key_material(secret).unwrap();
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
    block_on(state.upsert_virtual_api_key(key)).unwrap();
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
    let mut key = block_on(state.get_virtual_api_key("vk-rotate"))
        .unwrap()
        .unwrap();
    let material = ferrogate_auth_service::virtual_api_key_material(new_secret).unwrap();
    key.key_prefix = material.key_prefix;
    key.key_hash = material.key_hash;
    key.last4 = material.last4;
    key.rotated_at_unix = Some(2);
    block_on(state.upsert_virtual_api_key(key)).unwrap();

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
    block_on(state.upsert_quota_policy(StoredQuotaPolicy {
        id: "tenant:tenant-1".into(),
        scope_type: QuotaScopeKind::Tenant,
        scope_id: "tenant-1".into(),
        model_allowlist: vec![],
        rpm_limit: None,
        tpm_limit: None,
        monthly_budget_usd: None,
        asset_storage_quota_bytes: None,
        asset_max_object_bytes: None,
        agent_cost_budget_usd: None,
        alert_threshold_pcts: vec![],
        monthly_egress_bytes_budget: None,
        download_rpm_limit: None,
        enabled: false,
        created_at_unix: 1,
        updated_at_unix: 1,
    }))
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
    block_on(state.upsert_quota_policy(StoredQuotaPolicy {
        id: "tenant:tenant-1".into(),
        scope_type: QuotaScopeKind::Tenant,
        scope_id: "tenant-1".into(),
        model_allowlist: vec![],
        rpm_limit: Some(1),
        tpm_limit: None,
        monthly_budget_usd: None,
        asset_storage_quota_bytes: None,
        asset_max_object_bytes: None,
        agent_cost_budget_usd: None,
        alert_threshold_pcts: vec![],
        monthly_egress_bytes_budget: None,
        download_rpm_limit: None,
        enabled: true,
        created_at_unix: 1,
        updated_at_unix: 1,
    }))
    .unwrap();

    assert!(authenticate(&state, &bearer_headers(secret), "chat.completions", "req-1").is_ok());
    let error =
        authenticate(&state, &bearer_headers(secret), "chat.completions", "req-2").unwrap_err();
    assert_eq!(error.code, "rate_limit_exceeded");
}

#[test]
fn workspace_scoped_rpm_limit_is_shared_across_two_keys_under_the_workspace() {
    use ferrogate_storage::{QuotaScopeKind, StoredQuotaPolicy};

    // Two distinct durable virtual keys, both bound to workspace-1 (the fixed
    // tenant/project/workspace chain `seed_durable_virtual_key` seeds). The
    // ONLY rate cap is a workspace-scoped rpm_limit of 1 -- neither key has
    // its own request_limit_per_minute, and there is no tenant/project cap.
    let secret_a = "fg_live_ws_rpm_a_0123456789ab";
    let secret_b = "fg_live_ws_rpm_b_0123456789ab";
    let state = AppState::new(Config {
        api_keys: vec![decoy_yaml_key()],
        ..Config::default()
    });
    seed_durable_virtual_key(&state, "vk-ws-rpm-a", secret_a, |_| {});
    seed_durable_virtual_key(&state, "vk-ws-rpm-b", secret_b, |_| {});
    block_on(state.upsert_quota_policy(StoredQuotaPolicy {
        id: "workspace:workspace-1".into(),
        scope_type: QuotaScopeKind::Workspace,
        scope_id: "workspace-1".into(),
        model_allowlist: vec![],
        rpm_limit: Some(1),
        tpm_limit: None,
        monthly_budget_usd: None,
        asset_storage_quota_bytes: None,
        asset_max_object_bytes: None,
        agent_cost_budget_usd: None,
        alert_threshold_pcts: vec![],
        monthly_egress_bytes_budget: None,
        download_rpm_limit: None,
        enabled: true,
        created_at_unix: 1,
        updated_at_unix: 1,
    }))
    .unwrap();

    // Key A's first request consumes the single shared workspace slot.
    assert!(
        authenticate(
            &state,
            &bearer_headers(secret_a),
            "chat.completions",
            "req-a1"
        )
        .is_ok(),
        "first request under the workspace must be admitted"
    );
    // Key B is a DIFFERENT key, but the workspace rpm cap is the binding one,
    // so its request must count against the SAME window and be throttled.
    // Before the scope-keying fix this passed (per-key counter), bypassing the
    // aggregate workspace cap.
    let error = authenticate(
        &state,
        &bearer_headers(secret_b),
        "chat.completions",
        "req-b1",
    )
    .unwrap_err();
    assert_eq!(
        error.code, "rate_limit_exceeded",
        "a workspace-scoped rpm cap must aggregate across every key under the workspace"
    );
}

#[test]
fn broader_scope_rpm_cap_binds_even_when_a_key_sets_its_own_equal_limit() {
    use ferrogate_storage::{QuotaScopeKind, StoredQuotaPolicy};

    // Round-12 audit: previously a broader-scope aggregate cap only bound when
    // STRICTLY tighter than the key's own request_limit_per_minute, so a tenant
    // could set every key's own limit EQUAL to (or below) an operator's
    // workspace/tenant cap and have each key counted per-key -> N keys = N x the
    // cap. Now the per-key limit AND the aggregate are enforced as separate
    // windows, so the aggregate still binds across keys.
    let secret_a = "fg_live_agg_rpm_a_0123456789ab";
    let secret_b = "fg_live_agg_rpm_b_0123456789ab";
    let state = AppState::new(Config {
        api_keys: vec![decoy_yaml_key()],
        ..Config::default()
    });
    // Each key's own rpm limit EQUALS the aggregate cap (the pre-fix bypass).
    seed_durable_virtual_key(&state, "vk-agg-rpm-a", secret_a, |key| {
        key.request_limit_per_minute = Some(1);
    });
    seed_durable_virtual_key(&state, "vk-agg-rpm-b", secret_b, |key| {
        key.request_limit_per_minute = Some(1);
    });
    block_on(state.upsert_quota_policy(StoredQuotaPolicy {
        id: "workspace:workspace-1".into(),
        scope_type: QuotaScopeKind::Workspace,
        scope_id: "workspace-1".into(),
        model_allowlist: vec![],
        rpm_limit: Some(1),
        tpm_limit: None,
        monthly_budget_usd: None,
        asset_storage_quota_bytes: None,
        asset_max_object_bytes: None,
        agent_cost_budget_usd: None,
        alert_threshold_pcts: vec![],
        monthly_egress_bytes_budget: None,
        download_rpm_limit: None,
        enabled: true,
        created_at_unix: 1,
        updated_at_unix: 1,
    }))
    .unwrap();

    // Key A fills the shared workspace slot (and its own).
    assert!(
        authenticate(
            &state,
            &bearer_headers(secret_a),
            "chat.completions",
            "req-a1"
        )
        .is_ok(),
        "first request under the workspace must be admitted"
    );
    // Key B still has its OWN per-key slot free, but the workspace aggregate is
    // exhausted, so it must be throttled -- the N-key bypass is closed.
    let error = authenticate(
        &state,
        &bearer_headers(secret_b),
        "chat.completions",
        "req-b1",
    )
    .unwrap_err();
    assert_eq!(
        error.code, "rate_limit_exceeded",
        "an aggregate cap must bind across keys even when each key sets its own equal limit"
    );
}

#[test]
fn key_level_rpm_limit_still_throttles_each_key_independently() {
    // Regression guard for the common case: when the binding cap is the key's
    // own request_limit_per_minute (no broader scope cap), the two keys must
    // remain fully independent -- exhausting key A must not throttle key B.
    let secret_a = "fg_live_key_rpm_a_0123456789ab";
    let secret_b = "fg_live_key_rpm_b_0123456789ab";
    let state = AppState::new(Config {
        api_keys: vec![decoy_yaml_key()],
        ..Config::default()
    });
    seed_durable_virtual_key(&state, "vk-key-rpm-a", secret_a, |key| {
        key.request_limit_per_minute = Some(1);
    });
    seed_durable_virtual_key(&state, "vk-key-rpm-b", secret_b, |key| {
        key.request_limit_per_minute = Some(1);
    });

    // Key A: first ok, second throttled (its own per-key limit of 1).
    assert!(authenticate(
        &state,
        &bearer_headers(secret_a),
        "chat.completions",
        "req-a1"
    )
    .is_ok());
    let error = authenticate(
        &state,
        &bearer_headers(secret_a),
        "chat.completions",
        "req-a2",
    )
    .unwrap_err();
    assert_eq!(error.code, "rate_limit_exceeded");
    // Key B is untouched by key A's exhausted window: its own first request
    // must still be admitted.
    assert!(
        authenticate(
            &state,
            &bearer_headers(secret_b),
            "chat.completions",
            "req-b1"
        )
        .is_ok(),
        "a key-level rpm cap must stay byte-for-byte per-key, never shared"
    );
}

#[test]
fn workspace_scoped_tpm_window_is_one_shared_counter_across_two_keys() {
    use ferrogate_storage::{QuotaScopeKind, StoredQuotaPolicy};

    // TPM is enforced at dispatch (chat/embeddings) via `AuthContext::tpm_window`.
    // Two keys under workspace-1 with only a workspace-scoped tpm_limit must
    // resolve to the SAME counter key, so their token consumption shares one
    // window -- exercising exactly the derivation the dispatch path uses.
    let secret_a = "fg_live_ws_tpm_a_0123456789ab";
    let secret_b = "fg_live_ws_tpm_b_0123456789ab";
    let state = AppState::new(Config {
        api_keys: vec![decoy_yaml_key()],
        ..Config::default()
    });
    seed_durable_virtual_key(&state, "vk-ws-tpm-a", secret_a, |_| {});
    seed_durable_virtual_key(&state, "vk-ws-tpm-b", secret_b, |_| {});
    block_on(state.upsert_quota_policy(StoredQuotaPolicy {
        id: "workspace:workspace-1".into(),
        scope_type: QuotaScopeKind::Workspace,
        scope_id: "workspace-1".into(),
        model_allowlist: vec![],
        rpm_limit: None,
        tpm_limit: Some(100),
        monthly_budget_usd: None,
        asset_storage_quota_bytes: None,
        asset_max_object_bytes: None,
        agent_cost_budget_usd: None,
        alert_threshold_pcts: vec![],
        monthly_egress_bytes_budget: None,
        download_rpm_limit: None,
        enabled: true,
        created_at_unix: 1,
        updated_at_unix: 1,
    }))
    .unwrap();

    let auth_a = authenticate(
        &state,
        &bearer_headers(secret_a),
        "chat.completions",
        "req-a",
    )
    .expect("key A authenticates");
    let auth_b = authenticate(
        &state,
        &bearer_headers(secret_b),
        "chat.completions",
        "req-b",
    )
    .expect("key B authenticates");
    let (key_a, limit_a) = auth_a.tpm_window().expect("key A has a tpm window");
    let (key_b, limit_b) = auth_b.tpm_window().expect("key B has a tpm window");
    // Two different api keys, but the binding scope is the workspace, so both
    // derive one shared counter key.
    assert_eq!(key_a, "workspace:workspace-1");
    assert_eq!(key_b, "workspace:workspace-1");
    assert_eq!(limit_a, 100);
    assert_eq!(limit_b, 100);

    // Key A's request consumes the whole 100-token workspace window; key B's
    // next request (against the SAME derived key) must then be throttled.
    assert!(state
        .try_consume_api_key_tokens_per_minute(&key_a, limit_a, 100)
        .unwrap());
    assert!(
        !state
            .try_consume_api_key_tokens_per_minute(&key_b, limit_b, 1)
            .unwrap(),
        "a workspace-scoped tpm cap must aggregate token usage across every key under it"
    );
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
    block_on(state.upsert_quota_policy(StoredQuotaPolicy {
        id: "tenant:tenant-1".into(),
        scope_type: QuotaScopeKind::Tenant,
        scope_id: "tenant-1".into(),
        model_allowlist: vec!["fast-chat".into()],
        rpm_limit: None,
        tpm_limit: None,
        monthly_budget_usd: None,
        asset_storage_quota_bytes: None,
        asset_max_object_bytes: None,
        agent_cost_budget_usd: None,
        alert_threshold_pcts: vec![],
        monthly_egress_bytes_budget: None,
        download_rpm_limit: None,
        enabled: true,
        created_at_unix: 1,
        updated_at_unix: 1,
    }))
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
    use ferrogate_config::{Model, Provider};
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
            cloudflare_ai_gateway: None,
            enabled: true,
        }],
        models: vec![Model {
            name: "fast-chat".into(),
            provider: "openai".into(),
            provider_model: "gpt-4o-mini".into(),
            routing_strategy: RoutingStrategy::Priority,
            canary: None,
            shadow: None,
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
    block_on(state.upsert_quota_policy(StoredQuotaPolicy {
        id: "tenant:tenant-1".into(),
        scope_type: QuotaScopeKind::Tenant,
        scope_id: "tenant-1".into(),
        model_allowlist: vec![],
        rpm_limit: None,
        tpm_limit: None,
        monthly_budget_usd: Some(0.001),
        asset_storage_quota_bytes: None,
        asset_max_object_bytes: None,
        agent_cost_budget_usd: None,
        alert_threshold_pcts: vec![],
        monthly_egress_bytes_budget: None,
        download_rpm_limit: None,
        enabled: true,
        created_at_unix: 1,
        updated_at_unix: 1,
    }))
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
    block_on(state.record_billing_event(
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
    ))
    .unwrap();

    let error =
        authenticate(&state, &bearer_headers(secret), "chat.completions", "req-2").unwrap_err();
    assert_eq!(error.code, "monthly_budget_exceeded");
}

#[test]
fn tenant_scoped_monthly_budget_is_shared_across_two_keys_under_the_tenant() {
    use ferrogate_config::{Model, Provider};
    use ferrogate_core::RequestContext;
    use ferrogate_providers::{ProviderUsage, RoutingStrategy};
    use ferrogate_storage::{QuotaScopeKind, StoredQuotaPolicy};

    let secret_a = "fg_live_tbudget_a_0123456789ab";
    let secret_b = "fg_live_tbudget_b_0123456789ab";
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
            cloudflare_ai_gateway: None,
            enabled: true,
        }],
        models: vec![Model {
            name: "fast-chat".into(),
            provider: "openai".into(),
            provider_model: "gpt-4o-mini".into(),
            routing_strategy: RoutingStrategy::Priority,
            canary: None,
            shadow: None,
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
    // Two keys under the same tenant-1 chain; a TENANT-scoped monthly budget.
    seed_durable_virtual_key(&state, "vk-tbudget-a", secret_a, |_| {});
    seed_durable_virtual_key(&state, "vk-tbudget-b", secret_b, |_| {});
    block_on(state.upsert_quota_policy(StoredQuotaPolicy {
        id: "tenant:tenant-1".into(),
        scope_type: QuotaScopeKind::Tenant,
        scope_id: "tenant-1".into(),
        model_allowlist: vec![],
        rpm_limit: None,
        tpm_limit: None,
        monthly_budget_usd: Some(0.001),
        asset_storage_quota_bytes: None,
        asset_max_object_bytes: None,
        agent_cost_budget_usd: None,
        alert_threshold_pcts: vec![],
        monthly_egress_bytes_budget: None,
        download_rpm_limit: None,
        enabled: true,
        created_at_unix: 1,
        updated_at_unix: 1,
    }))
    .unwrap();

    // Spend all the tenant's budget through KEY A only ($0.003 > $0.001). This
    // increments the tenant-1 rollup as well as key A's own rollup.
    let request_a = RequestContext {
        request_id: "fg-tbudget-spend-a".into(),
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
            api_key_id: Some("vk-tbudget-a".into()),
        },
    };
    block_on(state.record_billing_event(
        crate::state::BillingEventDraft {
            request: &request_a,
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
    ))
    .unwrap();

    // Key B has spent nothing itself, but the tenant-scoped budget is the
    // binding cap, so its aggregate (tenant) spend is already exhausted. Before
    // the scope-keying fix, monthly_budget_exceeded checked key B's OWN spend
    // ($0) and admitted the request, letting a second key bypass the tenant
    // budget.
    let error = authenticate(
        &state,
        &bearer_headers(secret_b),
        "chat.completions",
        "req-b1",
    )
    .unwrap_err();
    assert_eq!(
        error.code, "monthly_budget_exceeded",
        "a tenant-scoped monthly budget must aggregate spend across every key under the tenant"
    );
}

/// #540, the flip itself. This test exists to be the thing that reds if the
/// default goes back, and it is deliberately written so that no amount of
/// fixture annotation can satisfy it: it constructs `Config::default()` and
/// reads the field, so the only way to make it pass is for the default to
/// actually be `false`. (It replaces #515's
/// `tenancy_config_defaults_are_legacy_compatible_and_explicit`, which pinned
/// the opposite value for the opposite reason -- that guard existed so stage 2
/// could not happen by accident, and this is stage 2.)
///
/// Its sibling assertion pins the OTHER half of "the default cannot grant
/// root": the config must be `false` AND the resolver must read that `false` as
/// "not an operator". Pinning only the field would leave
/// `resolve_platform_operator`'s `(None, None) => implicit_platform_operator`
/// arm free to be rewritten to `=> true` with every test still green.
#[test]
fn undeclared_platform_root_is_off_by_default_and_the_resolver_agrees() {
    let config = Config::default();

    assert!(
        !config.tenancy.implicit_platform_operator,
        "#515's non-negotiable: an omitted config field must not grant platform root. Flipping \
         this back is the whole regression -- every annotated fixture in the tree would keep \
         passing while it was broken"
    );
    assert!(
        !crate::auth::resolve_platform_operator(
            config.tenancy.implicit_platform_operator,
            None,
            None
        ),
        "the single classification chokepoint must resolve an undeclared credential to NOT an \
         operator under the default; the field being false is worth nothing if the resolver \
         ignores it"
    );

    assert!(
        !config.tenancy.require_registered_tenant,
        "#540 deliberately did not flip this one: a misspelled organization_id already fails \
         closed (the key is scoped to an island it can read nothing from), and whether a tenant \
         row exists is a fact about the control-plane store that no load-time check can warn \
         about first -- so turning it on by default would surface only as a 400 from a console \
         that could mint keys the day before"
    );
}

/// A config that omits `platform_operator` on a tenant-less key is told so, by
/// id -- the list the refusal and the legacy warning both read.
#[test]
fn config_load_names_every_key_that_relies_on_implicit_platform_root() {
    let mut operator = undeclared_yaml_key();
    operator.id = "bootstrap".into();
    let mut declared = undeclared_yaml_key();
    declared.id = "declared-root".into();
    declared.platform_operator = Some(true);
    let mut scoped = undeclared_yaml_key();
    scoped.id = "tenant-key".into();
    scoped.organization_id = Some("tenant-a".into());

    let config = Config {
        api_keys: vec![operator, declared, scoped],
        tenancy: ferrogate_config::TenancyConfig {
            implicit_platform_operator: true,
            ..Default::default()
        },
        ..Config::default()
    };

    assert_eq!(
        config.api_keys_without_tenant_identity(),
        vec!["bootstrap"],
        "only the key that declared neither identity has an undeclared tenant identity"
    );
    assert_eq!(
        config.warn_implicit_platform_operators(),
        vec!["bootstrap"],
        "and it is the one the legacy opt-in is silently promoting to root"
    );
}

/// #540, the upgrade path. A config whose keys still rely on the pre-#515 rule
/// does not boot and then 403 its own traffic -- it is refused where the
/// operator is already looking, by id, with both fixes and the escape hatch
/// spelled out. Same shape as #542's `ensure_auth_posture_is_declared`.
#[test]
fn config_validate_refuses_a_key_with_no_declared_tenant_identity() {
    let mut bootstrap = undeclared_yaml_key();
    bootstrap.id = "bootstrap".into();
    let mut scoped = undeclared_yaml_key();
    scoped.id = "tenant-key".into();
    scoped.key = Some("tenant-secret".into());
    scoped.organization_id = Some("tenant-a".into());

    let error = Config {
        api_keys: vec![bootstrap, scoped.clone()],
        ..Config::default()
    }
    .validate()
    .expect_err("#540: a key that declares no tenant identity must not load");
    let message = error.to_string();
    assert!(
        message.contains("bootstrap"),
        "the refusal must name the key that has to change: {message}"
    );
    assert!(
        !message.contains("tenant-key"),
        "a key that named its tenant is not part of the problem: {message}"
    );
    assert!(
        message.contains("platform_operator = true") && message.contains("organization_id"),
        "the refusal must print both fixes, not just the diagnosis: {message}"
    );
    assert!(
        message.contains("implicit_platform_operator = true"),
        "and the one-line way to get an existing deployment back up while annotating: {message}"
    );

    Config {
        api_keys: vec![scoped],
        ..Config::default()
    }
    .validate()
    .expect("a config whose every key declares an identity loads under the new default");
}

/// Captures everything written by `tracing` while `run` executes, on this
/// thread only. Needed because the migration warning's only user-visible form
/// IS a log line -- there is nothing else to assert on once you insist on
/// driving the real caller.
fn capture_tracing_output(run: impl FnOnce()) -> String {
    #[derive(Clone, Default)]
    struct SharedBuffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log buffer").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuffer {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    let buffer = SharedBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buffer.clone())
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .without_time()
        .finish();
    tracing::subscriber::with_default(subscriber, run);
    let captured = buffer.0.lock().expect("log buffer").clone();
    String::from_utf8(captured).expect("tracing output is utf-8")
}

/// #515 finding 5: the warning above is the entire user-visible artifact of the
/// migration window, and `Config::validate` is the ONLY thing that emits it in
/// production. Asserting on `warn_implicit_platform_operators()` directly (as
/// the two tests that cover it do) leaves the call site unpinned: delete the
/// single line in `validate` and the warning silently disappears for every real
/// deployment while every test stays green.
///
/// So drive the caller and assert on what it PRODUCED -- and on the guard
/// inside it, by validating the same key list under the #540 default, where the
/// same key is refused outright and the warning must NOT fire.
#[test]
fn config_validate_is_what_emits_the_implicit_platform_root_warning() {
    let mut bootstrap = undeclared_yaml_key();
    bootstrap.id = "bootstrap".into();
    let mut declared = undeclared_yaml_key();
    declared.id = "declared-root".into();
    declared.key = Some("declared-secret".into());
    declared.platform_operator = Some(true);
    let mut scoped = undeclared_yaml_key();
    scoped.id = "tenant-key".into();
    scoped.key = Some("tenant-secret".into());
    scoped.organization_id = Some("tenant-a".into());
    let api_keys = vec![bootstrap, declared, scoped];

    let legacy_opt_in = Config {
        api_keys: api_keys.clone(),
        tenancy: ferrogate_config::TenancyConfig {
            implicit_platform_operator: true,
            ..Default::default()
        },
        ..Config::default()
    };
    let warned = capture_tracing_output(|| {
        legacy_opt_in
            .validate()
            .expect("the legacy opt-in keeps this config loading");
    });
    assert!(
        warned.contains("bootstrap"),
        "Config::validate must name the key that holds platform root only by omission: {warned}"
    );
    assert!(
        warned.contains("implicit_platform_operator"),
        "the warning must point at the setting an operator has to remove: {warned}"
    );
    assert!(
        !warned.contains("declared-root") && !warned.contains("tenant-key"),
        "a key that declared either identity is not relying on the switch: {warned}"
    );

    // #540: under the default the same list does not get a warning and a
    // running gateway -- it gets no gateway. Asserting the log is empty would
    // pass on a build that simply deleted the warning, so assert what replaced
    // it as well.
    let mut error = None;
    let silent = capture_tracing_output(|| {
        error = Config {
            api_keys,
            ..Config::default()
        }
        .validate()
        .err();
    });
    assert!(
        error
            .as_ref()
            .is_some_and(|error| error.to_string().contains("bootstrap")),
        "under the default the undeclared key is refused, not warned about: {error:?}"
    );
    assert!(
        !silent.contains("implicit_platform_operator = true is set")
            && !silent.contains("are granted UNRESTRICTED"),
        "and nothing was promoted to root on the way out: {silent}"
    );
}

/// Root and a tenant are mutually exclusive, and a blank tenant id is a typo
/// rather than an identity -- both refused before the gateway ever starts.
#[test]
fn config_validation_rejects_contradictory_and_blank_tenant_identities() {
    let mut both = undeclared_yaml_key();
    both.platform_operator = Some(true);
    both.organization_id = Some("tenant-a".into());
    let error = Config {
        api_keys: vec![both],
        ..Config::default()
    }
    .validate()
    .expect_err("platform_operator = true must not be combined with organization_id");
    assert!(
        error.to_string().contains("platform_operator"),
        "unexpected error: {error}"
    );

    let mut blank = undeclared_yaml_key();
    blank.organization_id = Some("   ".into());
    let error = Config {
        api_keys: vec![blank],
        ..Config::default()
    }
    .validate()
    .expect_err("a blank organization_id is neither a tenant nor an operator");
    assert!(
        error.to_string().contains("organization_id"),
        "unexpected error: {error}"
    );
}

/// End to end over the static-config path: an undeclared key is refused by
/// DEFAULT since #540, and is root only where a deployment explicitly asked for
/// the pre-#515 rule.
///
/// The `AppState` is built straight from a `Config` literal rather than through
/// `Config::validate`, on purpose: this pins the request-time half in
/// isolation, so it stays a real assertion even if the load-time refusal is
/// ever moved or relaxed.
#[test]
fn static_config_key_without_any_declared_identity_is_governed_by_the_switch() {
    let strict = AppState::new(Config {
        api_keys: vec![undeclared_yaml_key()],
        ..Config::default()
    });
    let error = authenticate(
        &strict,
        &bearer_headers("decoy-secret"),
        "chat.completions",
        "req-1",
    )
    .expect_err("#540: by default a credential with no tenant identity fails closed");
    assert_eq!(error.code, "tenant_identity_required");
    assert_eq!(error.status, StatusCode::FORBIDDEN);

    let mut legacy_config = Config {
        api_keys: vec![undeclared_yaml_key()],
        ..Config::default()
    };
    legacy_config.tenancy.implicit_platform_operator = true;
    let legacy = AppState::new(legacy_config);
    let auth = authenticate(
        &legacy,
        &bearer_headers("decoy-secret"),
        "admin.read",
        "req-2",
    )
    .expect("the legacy opt-in must keep an un-annotated bootstrap key working");
    assert!(
        auth.is_platform_operator(),
        "the escape hatch has to actually restore the old behaviour, or nobody can use it to buy \
         time"
    );
}

/// The migration path an operator is told to take: annotate the key, and it
/// authenticates as root under BOTH settings.
#[test]
fn declared_platform_operator_authenticates_under_both_settings() {
    for implicit in [true, false] {
        let mut key = undeclared_yaml_key();
        key.platform_operator = Some(true);
        let mut config = Config {
            api_keys: vec![key],
            ..Config::default()
        };
        config.tenancy.implicit_platform_operator = implicit;
        let state = AppState::new(config);

        let auth = authenticate(
            &state,
            &bearer_headers("decoy-secret"),
            "admin.write",
            "req-1",
        )
        .expect("an explicitly declared operator key always authenticates");
        assert!(auth.is_platform_operator());
    }
}

/// A tenant-scoped static key is never root, under either setting, and carries
/// its tenant as both identity and attribution.
#[test]
fn tenant_scoped_static_key_is_never_platform_root() {
    for implicit in [true, false] {
        let mut key = undeclared_yaml_key();
        key.organization_id = Some("tenant-a".into());
        let mut config = Config {
            api_keys: vec![key],
            ..Config::default()
        };
        config.tenancy.implicit_platform_operator = implicit;
        let state = AppState::new(config);

        let auth = authenticate(
            &state,
            &bearer_headers("decoy-secret"),
            "chat.completions",
            "req-1",
        )
        .expect("a tenant-scoped key authenticates normally");
        assert!(!auth.is_platform_operator());
        assert_eq!(auth.organization_id.as_deref(), Some("tenant-a"));
        assert_eq!(auth.caller_scope(), CallerScope::Tenant("tenant-a"));
    }
}

/// #542, the contract: a deployment whose credentials all live in the control
/// plane -- no `[[api_keys]]`, no external auth service -- refuses a request
/// that presents nothing.
///
/// This is the inverted form of the test that pinned the hole. `auth_required()`
/// used to be `auth_service.enabled || !api_keys.is_empty()`, counting STATIC
/// config keys only, so exactly this deployment had authentication switched off:
/// `authenticate()` took the "auth disabled" early return, admitted a request
/// with NO credential, handed back the wildcard scope plus
/// `platform_operator: true`, and never consulted the durable authenticator at
/// all. The seeded virtual key below is what such a deployment's tenants
/// actually use, and it made no difference to whether anyone had to present one.
///
/// Restore either half of the old predicate and this goes red: the empty
/// `[[api_keys]]` section would switch authentication off and the empty header
/// map would be admitted instead of refused.
#[test]
fn a_storage_only_deployment_refuses_an_unauthenticated_request_issue_542() {
    let secret = "fg_live_e2e_0123456789abcdef";
    // No static api_keys and no auth service: under the pre-#542 predicate
    // this is the "auth is off" config.
    let state = AppState::new(Config::default());
    seed_durable_virtual_key(&state, "vk-542", secret, |_| {});

    // Note the headers: EMPTY. Nothing is presented.
    let error = authenticate(&state, &HeaderMap::new(), "chat.completions", "req-542")
        .expect_err("#542: an empty [[api_keys]] section must not switch authentication off");

    assert_eq!(error.status, StatusCode::UNAUTHORIZED);
    assert_eq!(error.code, "missing_api_key");
}

/// #542: the same deployment, with the virtual key actually presented. It
/// authenticates through the durable path, is attributed to the key, and is
/// tenant-scoped -- none of which happened before, because the durable
/// authenticator was never reached.
///
/// Restore the old predicate and this goes red on every assertion at once: the
/// early return produces `api_key_id: None`, `organization_id: None` and
/// `platform_operator: true`.
#[test]
fn a_storage_only_deployment_authenticates_and_attributes_its_virtual_key_issue_542() {
    let secret = "fg_live_e2e_0123456789abcdef";
    let state = AppState::new(Config::default());
    seed_durable_virtual_key(&state, "vk-542", secret, |_| {});

    let auth = authenticate(
        &state,
        &bearer_headers(secret),
        "chat.completions",
        "req-542",
    )
    .expect("#542: the durable key is the deployment's credential and must authenticate");

    assert_eq!(auth.api_key_id.as_deref(), Some("vk-542"));
    assert_eq!(auth.organization_id.as_deref(), Some("tenant-1"));
    assert_eq!(auth.caller_scope(), CallerScope::Tenant("tenant-1"));
    assert!(
        !auth.is_platform_operator(),
        "#542: a virtual key is minted under a tenant and can never be platform root"
    );
}

/// #542 ask 2: the open posture is still available -- but only to an operator
/// who wrote it down. `[auth] disabled = true` is the one thing that reaches the
/// wildcard/platform-root early return, and an omitted section is not it.
///
/// Delete the `disabled` read from `Config::auth_required` (make it return `true`
/// unconditionally) and this goes red; make it return `!auth.disabled ||
/// api_keys.is_empty()` -- i.e. let the omission back in -- and the two tests
/// above go red.
#[test]
fn auth_disabled_by_name_is_the_only_way_to_the_open_posture_issue_542() {
    let mut config = Config::default();
    config.auth.disabled = true;
    let state = AppState::new(config);
    seed_durable_virtual_key(&state, "vk-542", "fg_live_e2e_0123456789abcdef", |_| {});

    let auth = authenticate(&state, &HeaderMap::new(), "chat.completions", "req-542")
        .expect("[auth] disabled = true means every request is admitted");

    assert!(auth.is_platform_operator());
    assert!(auth.has_scope("anything.at.all"));
    assert!(auth.api_key_id.is_none());
}

/// #542: the predicate itself, stated once. Authentication is required by
/// default and is NOT a function of where -- or whether -- credentials happen to
/// be configured. Only the named switch turns it off, and it turns it off even
/// when static keys exist (that combination is refused at startup by
/// `lifecycle::ensure_auth_posture_is_declared`, precisely because it would
/// otherwise be silently open).
#[test]
fn auth_required_is_stated_not_inferred_from_configured_credentials_issue_542() {
    assert!(
        Config::default().auth_required(),
        "an empty config must require authentication, not switch it off"
    );

    let with_static_key = Config {
        api_keys: vec![decoy_yaml_key()],
        ..Config::default()
    };
    assert!(with_static_key.auth_required());

    let mut with_auth_service = Config::default();
    with_auth_service.auth_service.enabled = true;
    assert!(with_auth_service.auth_service.enabled && with_auth_service.auth_required());

    let mut disabled = Config::default();
    disabled.auth.disabled = true;
    assert!(!disabled.auth_required());

    let mut disabled_with_keys = Config {
        api_keys: vec![decoy_yaml_key()],
        ..Config::default()
    };
    disabled_with_keys.auth.disabled = true;
    assert!(
        !disabled_with_keys.auth_required(),
        "the named switch is the answer; a configured key does not quietly override it"
    );
}

#[test]
fn durable_virtual_key_is_never_platform_root() {
    let secret = "fg_live_e2e_0123456789abcdef";
    // #542: this test carried `api_keys: vec![decoy_yaml_key()]` for one reason
    // -- `auth_required()` was `auth_service.enabled || !api_keys.is_empty()`,
    // so without a static key authentication was off and `authenticate()`
    // returned the wildcard context before ever consulting the durable
    // authenticator. The decoy was compensating for the gap, not testing
    // anything, and its removal is what surfaced #542 in the first place. With
    // the predicate no longer counting credentials the decoy is gone, and this
    // test now fails if it ever comes back.
    let mut config = Config::default();
    config.tenancy.implicit_platform_operator = true;
    let state = AppState::new(config);
    seed_durable_virtual_key(&state, "vk-515", secret, |_| {});

    let auth = authenticate(&state, &bearer_headers(secret), "chat.completions", "req-1")
        .expect("durable key should authenticate");

    assert!(!auth.is_platform_operator());
    assert_eq!(auth.caller_scope(), CallerScope::Tenant("tenant-1"));
}
