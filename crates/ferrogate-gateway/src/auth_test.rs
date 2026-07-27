// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for the authorization vocabulary, the credential
// primitives and the external auth-service scope check -- the half of the
// former ferrogate-cli `auth_test.rs` that never builds an `AppState`.

use super::*;

#[test]
fn extracts_bearer_and_x_api_key() {
    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, "Bearer secret".parse().unwrap());
    assert_eq!(extract_api_key(&headers).as_deref(), Some("secret"));

    headers.insert("x-api-key", "other".parse().unwrap());
    assert_eq!(extract_api_key(&headers).as_deref(), Some("other"));
}

fn auth_with_scopes(scopes: &[&str]) -> AuthContext {
    AuthContext {
        region_allowlist: HashSet::new(),
        api_key_id: Some("key".into()),
        scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        allowed_models: HashSet::new(),
        denied_models: HashSet::new(),
        allowed_providers: HashSet::new(),
        denied_providers: HashSet::new(),
        monthly_token_budget: None,
        request_limit_per_minute: None,
        organization_id: None,
        platform_operator: false,
        team_id: None,
        project_id: None,
        workspace_id: None,
        user_id: None,
        log_bodies: false,
        rbac_subject: None,
        effective_quota: ferrogate_policy::EffectiveQuota::default(),
    }
}

#[test]
fn empty_scope_set_grants_data_plane_scopes_but_never_admin_scopes() {
    // Empty scopes is the data-plane convenience default ("all ordinary
    // scopes"), so ordinary scopes are granted...
    let empty = auth_with_scopes(&[]);
    assert!(empty.has_scope("chat.completions"));
    assert!(empty.has_scope("tools.execute"));
    // ...but a privileged admin scope is NEVER conferred implicitly (round-7:
    // a virtual key minted without scopes must not become a tenant admin).
    assert!(!empty.has_scope("admin.read"));
    assert!(!empty.has_scope("admin.write"));

    // An explicit scope set grants exactly what it lists.
    let explicit = auth_with_scopes(&["chat.completions"]);
    assert!(explicit.has_scope("chat.completions"));
    assert!(!explicit.has_scope("tools.execute"));
    assert!(!explicit.has_scope("admin.write"));

    // Admin scopes only via explicit grant.
    let admin = auth_with_scopes(&["admin.read", "admin.write"]);
    assert!(admin.has_scope("admin.read"));
    assert!(admin.has_scope("admin.write"));
    // An explicit admin key does not implicitly gain data-plane scopes.
    assert!(!admin.has_scope("chat.completions"));

    // The explicit "*" wildcard (operator-authored static config keys /
    // auth-disabled mode) grants EVERY scope, including admin.*.
    let wildcard = auth_with_scopes(&["*"]);
    assert!(wildcard.has_scope("chat.completions"));
    assert!(wildcard.has_scope("admin.read"));
    assert!(wildcard.has_scope("admin.write"));

    assert!(AuthContext::is_privileged_scope("admin.read"));
    assert!(!AuthContext::is_privileged_scope("chat.completions"));
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
        platform_operator: false,
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
        platform_operator: false,
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
        platform_operator: false,
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
    };

    assert!(hash.starts_with("blake2b:"));
    assert!(super::api_key_matches_presented_key(&key, "client-secret"));
    assert!(!super::api_key_matches_presented_key(&key, "wrong-secret"));
}

// --- issue #515: `organization_id` is a validated tenant identity, and
// --- platform root is a declared opt-in rather than an omitted field ---

fn auth_with_identity(organization_id: Option<&str>, platform_operator: bool) -> AuthContext {
    AuthContext {
        region_allowlist: HashSet::new(),
        api_key_id: Some("key".into()),
        scopes: HashSet::from([WILDCARD_SCOPE.to_string()]),
        allowed_models: HashSet::new(),
        denied_models: HashSet::new(),
        allowed_providers: HashSet::new(),
        denied_providers: HashSet::new(),
        monthly_token_budget: None,
        request_limit_per_minute: None,
        organization_id: organization_id.map(ToOwned::to_owned),
        platform_operator,
        team_id: None,
        project_id: None,
        workspace_id: None,
        user_id: None,
        log_bodies: false,
        rbac_subject: None,
        effective_quota: ferrogate_policy::EffectiveQuota::default(),
    }
}

/// The resolver is the ONE place a credential is classified. An explicit
/// declaration always wins; naming a tenant is never root; and the legacy
/// "declared nothing" shape is root only while the deprecated compatibility
/// switch is on.
#[test]
fn platform_operator_is_resolved_from_what_the_key_declares() {
    // Explicit opt-in wins, under either compatibility setting.
    assert!(resolve_platform_operator(false, Some(true), None));
    assert!(resolve_platform_operator(true, Some(true), None));

    // An explicit refusal also wins: a key pinned to `false` never becomes
    // root just because the deployment is still on the legacy default.
    assert!(!resolve_platform_operator(true, Some(false), None));
    assert!(!resolve_platform_operator(false, Some(false), None));

    // Naming a tenant is never root.
    assert!(!resolve_platform_operator(true, None, Some("tenant-a")));
    assert!(!resolve_platform_operator(false, None, Some("tenant-a")));

    // The legacy shape -- neither field -- is exactly what the switch governs.
    assert!(resolve_platform_operator(true, None, None));
    assert!(!resolve_platform_operator(false, None, None));
}

/// The scope check: root passes everything, a tenant passes only its own, and
/// a credential that never declared either identity is denied rather than
/// treated as root.
#[test]
fn tenant_scope_check_reads_the_declared_identity_not_a_missing_field() {
    let operator = auth_with_identity(None, true);
    assert!(authorize_tenant_scope(&operator, "tenant-a").is_ok());
    assert!(authorize_tenant_scope(&operator, "tenant-b").is_ok());
    assert!(operator.is_platform_operator());

    let tenant_a = auth_with_identity(Some("tenant-a"), false);
    assert!(authorize_tenant_scope(&tenant_a, "tenant-a").is_ok());
    assert_eq!(
        authorize_tenant_scope(&tenant_a, "tenant-b")
            .expect_err("cross-tenant access must be denied")
            .code,
        "tenant_scope_denied"
    );
    assert!(!tenant_a.is_platform_operator());

    // The shape #515 is about: no tenant, no opt-in. It must NOT inherit the
    // operator branch.
    let unclassified = auth_with_identity(None, false);
    assert!(!unclassified.is_platform_operator());
    assert_eq!(
        authorize_tenant_scope(&unclassified, "tenant-a")
            .expect_err("an unclassified credential must not reach any tenant")
            .code,
        "tenant_scope_denied"
    );
    assert_eq!(
        require_platform_operator(&unclassified)
            .expect_err("an unclassified credential must not hold operator-only routes")
            .code,
        "platform_operator_required"
    );
    assert!(require_platform_operator(&operator).is_ok());
    assert_eq!(
        require_platform_operator(&tenant_a)
            .expect_err("a tenant-scoped key must not mint platform credentials")
            .code,
        "platform_operator_required"
    );
}

/// #515 finding 2. Roughly a dozen admin reads take an `Option<&str>` tenant
/// argument where `None` means "every tenant", and every one of them used to be
/// fed `auth.organization_id.as_deref()` -- which hands the cross-tenant view to
/// anything that merely omitted the field. `tenant_filter()` is that argument
/// derived from the CLASSIFICATION, so `None` is reachable only by a declared
/// operator; pin all three answers here, since the call sites are one-liners
/// that a mutation can silently revert.
#[test]
fn tenant_filter_yields_the_cross_tenant_view_only_for_a_declared_operator() {
    assert_eq!(
        auth_with_identity(None, true).tenant_filter(),
        None,
        "a declared platform operator keeps the unfiltered, cross-tenant read"
    );
    assert_eq!(
        auth_with_identity(Some("tenant-a"), false).tenant_filter(),
        Some("tenant-a"),
        "a tenant-scoped caller is pinned to its own tenant"
    );
    assert_eq!(
        auth_with_identity(None, false).tenant_filter(),
        Some(""),
        "a credential that declared NEITHER identity must be narrowed to a tenant id no row can \
         equal -- not handed None, which is the every-tenant view"
    );
    // ...and the two spellings agree, so a site converted to either one behaves
    // the same for the unclassified shape.
    assert!(!auth_with_identity(None, false).is_platform_operator());
}

/// The list filter: same three identities, same three answers -- and the
/// unclassified one sees nothing rather than every tenant's rows.
#[test]
fn list_filter_reads_the_declared_identity_not_a_missing_field() {
    let rows = || vec![("tenant-a".to_string(), 1), ("tenant-b".to_string(), 2)];
    fn tenant_of(row: &(String, i32)) -> &str {
        row.0.as_str()
    }

    assert_eq!(
        filter_by_tenant_scope(&auth_with_identity(None, true), rows(), tenant_of).len(),
        2,
        "a declared platform operator lists every tenant's rows"
    );
    assert_eq!(
        filter_by_tenant_scope(
            &auth_with_identity(Some("tenant-a"), false),
            rows(),
            tenant_of
        ),
        vec![("tenant-a".to_string(), 1)]
    );
    assert!(
        filter_by_tenant_scope(&auth_with_identity(None, false), rows(), tenant_of).is_empty(),
        "a credential with no declared identity must not read every tenant's rows"
    );
}

/// The forced `?tenant=` path: a tenant-scoped caller's requested filter is
/// overwritten, an operator's passes through, and an unclassified caller is
/// pinned to a tenant id no row can match.
#[test]
fn forced_tenant_filter_reads_the_declared_identity_not_a_missing_field() {
    assert_eq!(
        enforce_tenant_filter(&auth_with_identity(None, true), Some("tenant-b".into())),
        Some("tenant-b".into()),
        "a declared operator may filter to any tenant"
    );
    assert_eq!(
        enforce_tenant_filter(&auth_with_identity(None, true), None),
        None,
        "a declared operator's unfiltered listing stays unfiltered"
    );
    assert_eq!(
        enforce_tenant_filter(
            &auth_with_identity(Some("tenant-a"), false),
            Some("tenant-b".into())
        ),
        Some("tenant-a".into()),
        "a tenant-scoped caller cannot ask for another tenant's rows"
    );
    assert_eq!(
        enforce_tenant_filter(&auth_with_identity(Some("tenant-a"), false), None),
        Some("tenant-a".into()),
        "nor can it omit the filter to read every tenant's rows"
    );
    assert_eq!(
        enforce_tenant_filter(&auth_with_identity(None, false), Some("tenant-b".into())),
        Some(UNSCOPED_TENANT_ID.to_string()),
        "an unclassified credential is pinned to a tenant id no row can match"
    );
    assert_eq!(
        enforce_tenant_filter(&auth_with_identity(None, false), None),
        Some(UNSCOPED_TENANT_ID.to_string()),
        "and cannot fall back to the unfiltered, every-tenant listing"
    );
}
