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
    assert!(!refs.needs_lookup());
}

#[test]
fn key_without_hierarchy_references_needs_no_lookup_and_resolves_no_tenant() {
    let key = api_key(Some("tenant-a"), None, None);
    let refs = ApiKeyTenancyRefs::from_key(&key);

    assert!(!refs.needs_lookup());
    assert_eq!(
        check_api_key_tenancy(refs, None, None),
        Ok(ApiKeyTenancyOutcome::default())
    );
}

#[test]
fn matching_project_and_workspace_are_accepted_and_resolve_the_tenant() {
    let key = api_key(Some("tenant-a"), Some("project-a"), Some("workspace-a"));
    let refs = ApiKeyTenancyRefs::from_key(&key);
    assert!(refs.needs_lookup());

    let resolved = check_api_key_tenancy(
        refs,
        Some(&project("project-a", "tenant-a")),
        Some(&workspace("workspace-a", "project-a", "tenant-a")),
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
        Some(&project("project-a", "tenant-a")),
        Some(&workspace("workspace-b", "project-b", "tenant-b")),
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
        Some(&project("project-b", "tenant-b")),
        None,
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
        None,
        Some(&workspace("workspace-b", "project-b", "tenant-b")),
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
    let key = api_key(Some("tenant-a"), Some("project-ghost"), Some("ws-ghost"));

    let outcome = check_api_key_tenancy(ApiKeyTenancyRefs::from_key(&key), None, None)
        .expect("dangling references must not be refused");

    assert_eq!(outcome.owner_tenant_id, None);
    assert_eq!(
        outcome.unresolved,
        vec![
            "project project-ghost".to_string(),
            "workspace ws-ghost".to_string()
        ]
    );
}

/// A resolved reference alongside an unresolved one still enforces the tenant
/// rule on the half that exists, and reports only the missing half.
#[test]
fn partially_resolved_references_still_enforce_and_report() {
    let key = api_key(Some("tenant-a"), Some("project-a"), Some("ws-ghost"));

    let outcome = check_api_key_tenancy(
        ApiKeyTenancyRefs::from_key(&key),
        Some(&project("project-a", "tenant-a")),
        None,
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
        Some(&workspace("workspace-a", "project-a", "tenant-a")),
    );

    assert_eq!(
        resolved,
        Ok(ApiKeyTenancyOutcome {
            owner_tenant_id: Some("tenant-a".into()),
            unresolved: Vec::new(),
        })
    );
}
