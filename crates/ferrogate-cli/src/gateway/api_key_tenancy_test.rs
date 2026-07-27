// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Unit coverage for the native api-key tenancy invariant
// (issue #340) -- the API-side rejection of the cross-project/cross-tenant
// project+workspace combinations the admin console blocks client-side.

use super::*;

fn api_key(
    organization_id: Option<&str>,
    project_id: Option<&str>,
    workspace_id: Option<&str>,
) -> ApiKey {
    api_key_with_operator(organization_id, project_id, workspace_id, None)
}

fn api_key_with_operator(
    organization_id: Option<&str>,
    project_id: Option<&str>,
    workspace_id: Option<&str>,
    platform_operator: Option<bool>,
) -> ApiKey {
    ApiKey {
        id: "key-1".into(),
        name: "Key one".into(),
        key_env: None,
        key: Some("secret".into()),
        key_hash: None,
        enabled: true,
        scopes: Vec::new(),
        allowed_models: Vec::new(),
        denied_models: Vec::new(),
        allowed_providers: Vec::new(),
        denied_providers: Vec::new(),
        region_allowlist: Vec::new(),
        organization_id: organization_id.map(ToOwned::to_owned),
        platform_operator,
        team_id: None,
        project_id: project_id.map(ToOwned::to_owned),
        workspace_id: workspace_id.map(ToOwned::to_owned),
        user_id: None,
        monthly_token_budget: None,
        request_limit_per_minute: None,
        expires_at_unix: None,
        log_bodies: None,
        cache_enabled: None,
    }
}

fn tenant(id: &str) -> StoredTenantAccount {
    StoredTenantAccount {
        id: id.into(),
        name: id.into(),
        slug: id.into(),
        status: "active".into(),
        plan_id: "free".into(),
        created_at_unix: 0,
        updated_at_unix: 0,
    }
}

fn project(id: &str, tenant_id: &str) -> StoredProject {
    StoredProject {
        id: id.into(),
        tenant_id: tenant_id.into(),
        name: id.into(),
        slug: id.into(),
        status: "active".into(),
        created_at_unix: 0,
        updated_at_unix: 0,
    }
}

fn workspace(id: &str, project_id: &str, tenant_id: &str) -> StoredWorkspace {
    StoredWorkspace {
        id: id.into(),
        project_id: project_id.into(),
        tenant_id: tenant_id.into(),
        name: id.into(),
        slug: id.into(),
        environment: "production".into(),
        status: "active".into(),
        created_at_unix: 0,
        updated_at_unix: 0,
    }
}

#[test]
fn refs_ignore_absent_and_blank_fields() {
    let key = api_key(Some("tenant-a"), Some("   "), None);
    let refs = ApiKeyTenancyRefs::from_key(&key);

    assert_eq!(refs.organization_id, Some("tenant-a"));
    assert_eq!(refs.project_id, None);
    assert_eq!(refs.workspace_id, None);
    // #515: a declared `organization_id` is itself a reference that has to be
    // resolved -- before this it was the one tenancy field the upsert copied
    // through with no lookup.
    assert!(refs.needs_lookup());
}

#[test]
fn a_key_with_no_tenancy_references_at_all_needs_no_lookup() {
    let key = api_key(None, None, None);
    let refs = ApiKeyTenancyRefs::from_key(&key);

    assert!(!refs.needs_lookup());
    assert_eq!(
        check_api_key_tenancy(refs, None, None, None, false),
        Ok(ApiKeyTenancyOutcome::default())
    );
}

#[test]
fn key_scoped_to_a_registered_tenant_only_resolves_that_tenant() {
    let key = api_key(Some("tenant-a"), None, None);
    let refs = ApiKeyTenancyRefs::from_key(&key);

    assert!(refs.needs_lookup());
    assert_eq!(
        check_api_key_tenancy(refs, Some(&tenant("tenant-a")), None, None, true),
        Ok(ApiKeyTenancyOutcome {
            owner_tenant_id: Some("tenant-a".into()),
            unresolved: Vec::new(),
        })
    );
}

#[test]
fn matching_project_and_workspace_are_accepted_and_resolve_the_tenant() {
    let key = api_key(Some("tenant-a"), Some("project-a"), Some("workspace-a"));
    let refs = ApiKeyTenancyRefs::from_key(&key);
    assert!(refs.needs_lookup());

    let resolved = check_api_key_tenancy(
        refs,
        Some(&tenant("tenant-a")),
        Some(&project("project-a", "tenant-a")),
        Some(&workspace("workspace-a", "project-a", "tenant-a")),
        true,
    );

    assert_eq!(
        resolved,
        Ok(ApiKeyTenancyOutcome {
            owner_tenant_id: Some("tenant-a".into()),
            unresolved: Vec::new(),
        })
    );
}

/// The exact combination reported against `74878a7`: project A paired with a
/// workspace that lives under project B (and therefore under tenant B).
#[test]
fn workspace_from_another_project_is_rejected() {
    let key = api_key(None, Some("project-a"), Some("workspace-b"));

    let error = check_api_key_tenancy(
        ApiKeyTenancyRefs::from_key(&key),
        None,
        Some(&project("project-a", "tenant-a")),
        Some(&workspace("workspace-b", "project-b", "tenant-b")),
        false,
    )
    .expect_err("cross-project workspace must be rejected");

    assert_eq!(
        error,
        ApiKeyTenancyRejection::WorkspaceProjectMismatch {
            workspace_id: "workspace-b".into(),
            workspace_project_id: "project-b".into(),
            project_id: "project-a".into(),
        }
    );
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    assert_eq!(error.code(), "invalid_api_key");
    assert!(error.message().contains("workspace-b"));
    assert!(error.message().contains("project-a"));
}

#[test]
fn project_owned_by_another_tenant_is_rejected() {
    let key = api_key(Some("tenant-a"), Some("project-b"), None);

    let error = check_api_key_tenancy(
        ApiKeyTenancyRefs::from_key(&key),
        Some(&tenant("tenant-a")),
        Some(&project("project-b", "tenant-b")),
        None,
        true,
    )
    .expect_err("cross-tenant project must be rejected");

    assert_eq!(
        error,
        ApiKeyTenancyRejection::TenantMismatch {
            reference: "project",
            reference_id: "project-b".into(),
            owner_tenant_id: "tenant-b".into(),
            organization_id: "tenant-a".into(),
        }
    );
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn workspace_owned_by_another_tenant_is_rejected_without_a_project() {
    let key = api_key(Some("tenant-a"), None, Some("workspace-b"));

    let error = check_api_key_tenancy(
        ApiKeyTenancyRefs::from_key(&key),
        Some(&tenant("tenant-a")),
        None,
        Some(&workspace("workspace-b", "project-b", "tenant-b")),
        true,
    )
    .expect_err("cross-tenant workspace must be rejected");

    assert_eq!(
        error,
        ApiKeyTenancyRejection::TenantMismatch {
            reference: "workspace",
            reference_id: "workspace-b".into(),
            owner_tenant_id: "tenant-b".into(),
            organization_id: "tenant-a".into(),
        }
    );
}

/// A reference that names no control-plane row is reported, not refused: the
/// same key can be declared in `ferrogate.toml`, where no storage lookup
/// happens at all, and an id that resolves to nothing cannot form a
/// cross-tenant combination. The handler turns `unresolved` into an audit
/// event plus an operator warning.
#[test]
fn dangling_references_are_reported_rather_than_rejected() {
    let key = api_key(
        Some("tenant-ghost"),
        Some("project-ghost"),
        Some("ws-ghost"),
    );

    let outcome = check_api_key_tenancy(ApiKeyTenancyRefs::from_key(&key), None, None, None, false)
        .expect("dangling references must not be refused");

    // #515: the declared tenant is still the identity the key will carry, so
    // it is reported as the owner the handler authorizes against even when the
    // row is missing -- "unresolved" must not silently become "unscoped".
    assert_eq!(outcome.owner_tenant_id.as_deref(), Some("tenant-ghost"));
    assert_eq!(
        outcome.unresolved,
        vec![
            "tenant tenant-ghost".to_string(),
            "project project-ghost".to_string(),
            "workspace ws-ghost".to_string()
        ]
    );
}

/// #515: the same dangling `organization_id`, once the deployment has declared
/// that its tenants are all registered, is a refusal rather than a warning --
/// this is the half of the issue that makes `organization_id` a checked
/// foreign key instead of an unvalidated caller-authored string.
#[test]
fn unknown_tenant_is_rejected_when_registration_is_required() {
    let key = api_key(Some("tenant-ghost"), None, None);

    let error = check_api_key_tenancy(ApiKeyTenancyRefs::from_key(&key), None, None, None, true)
        .expect_err("an organization_id that names no tenant must be refused");

    assert_eq!(
        error,
        ApiKeyTenancyRejection::UnknownTenant {
            organization_id: "tenant-ghost".into(),
        }
    );
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    assert_eq!(error.code(), "invalid_api_key");
    assert!(error.message().contains("tenant-ghost"));
}

/// #515: root is the absence of a tenant boundary, so a payload that claims
/// both is a contradiction -- refused here exactly as `Config::validate`
/// refuses it on the static-config path, so the admin API cannot persist a key
/// shape the config loader would reject on the next restart.
#[test]
fn platform_operator_combined_with_a_tenant_is_rejected() {
    let key = api_key_with_operator(Some("tenant-a"), None, None, Some(true));

    let error = check_api_key_tenancy(
        ApiKeyTenancyRefs::from_key(&key),
        Some(&tenant("tenant-a")),
        None,
        None,
        false,
    )
    .expect_err("platform_operator = true must not be combined with a tenant");

    assert_eq!(
        error,
        ApiKeyTenancyRejection::PlatformOperatorWithTenant {
            organization_id: "tenant-a".into(),
        }
    );
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
}

/// A key that declares platform-root and nothing else is legal: that is the
/// whole point of the opt-in.
#[test]
fn platform_operator_without_a_tenant_is_accepted() {
    let key = api_key_with_operator(None, None, None, Some(true));
    let refs = ApiKeyTenancyRefs::from_key(&key);

    assert!(!refs.needs_lookup());
    assert_eq!(
        check_api_key_tenancy(refs, None, None, None, true),
        Ok(ApiKeyTenancyOutcome::default())
    );
}

/// A resolved reference alongside an unresolved one still enforces the tenant
/// rule on the half that exists, and reports only the missing half.
#[test]
fn partially_resolved_references_still_enforce_and_report() {
    let key = api_key(Some("tenant-a"), Some("project-a"), Some("ws-ghost"));

    let outcome = check_api_key_tenancy(
        ApiKeyTenancyRefs::from_key(&key),
        Some(&tenant("tenant-a")),
        Some(&project("project-a", "tenant-a")),
        None,
        true,
    )
    .expect("a resolved, consistent project must be accepted");

    assert_eq!(outcome.owner_tenant_id.as_deref(), Some("tenant-a"));
    assert_eq!(outcome.unresolved, vec!["workspace ws-ghost".to_string()]);
}

/// A workspace-only key still resolves a tenant, so the handler can run the
/// same `authorize_tenant_scope` check the workspaces/virtual-keys upserts run.
#[test]
fn workspace_only_key_resolves_its_workspaces_tenant() {
    let key = api_key(None, None, Some("workspace-a"));

    let resolved = check_api_key_tenancy(
        ApiKeyTenancyRefs::from_key(&key),
        None,
        None,
        Some(&workspace("workspace-a", "project-a", "tenant-a")),
        true,
    );

    assert_eq!(
        resolved,
        Ok(ApiKeyTenancyOutcome {
            owner_tenant_id: Some("tenant-a".into()),
            unresolved: Vec::new(),
        })
    );
}
