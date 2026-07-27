// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Coverage for RBAC authorization decisions and the storage-backed API key
//! authenticator (moved verbatim from lib.rs's inline tests module, #433).

use super::*;
use ferrogate_core::WorkspaceScope;
use ferrogate_storage::{RuntimeControlPlaneState, RuntimeStorageBackend, StorageProviderKind};

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
            tenant_id: None,
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

#[test]
fn workspace_scoped_binding_does_not_match_a_request_from_another_workspace() {
    // A binding scoped to the staging workspace must not authorize a request
    // from prod (same org/project, different environment). Before the fix
    // tenant_matches ignored workspace_id, silently leaking the grant.
    let mut staging_scope = tenant();
    staging_scope.workspace_id = Some("staging".into());
    let service = RbacAuthService::new(AuthServiceData {
        roles: vec![Role {
            id: "role_chat".into(),
            name: "Chat caller".into(),
            tenant_id: None,
            permissions: vec![Permission {
                action: "chat.completions".into(),
                resource: "model:fast-chat".into(),
            }],
        }],
        bindings: vec![PolicyBinding {
            id: "binding_chat".into(),
            role_id: "role_chat".into(),
            tenant: staging_scope,
            subject: PolicySubject::ApiKey {
                api_key_id: "key".into(),
            },
        }],
        ..AuthServiceData::default()
    });

    // Request from prod: denied.
    let mut prod_request = authorize_request();
    prod_request.tenant.workspace_id = Some("prod".into());
    assert!(!service.authorize(&prod_request).allowed);

    // Request from the bound workspace (staging): allowed.
    let mut staging_request = authorize_request();
    staging_request.tenant.workspace_id = Some("staging".into());
    assert!(service.authorize(&staging_request).allowed);
}

#[test]
fn storage_authenticator_resolves_active_hashed_api_key() {
    let secret = "fg_live_1234567890abcdef";
    let repositories = storage_with_api_key(stored_api_key("key-live", secret, |key| {
        key.scopes = vec!["chat.completions".into()];
    }));
    let authenticator =
        StorageApiKeyAuthenticator::with_clock(repositories, Arc::new(|| 1_700_000_000));

    let decision = authenticator.authenticate(secret).unwrap();

    assert_eq!(decision.scopes, ["chat.completions"]);
    assert_eq!(
        decision.subject,
        PolicySubject::ApiKey {
            api_key_id: "key-live".into()
        }
    );
    assert_eq!(decision.tenant.organization_id.as_deref(), Some("tenant-1"));
    assert_eq!(decision.tenant.project_id.as_deref(), Some("project-1"));
    assert_eq!(decision.tenant.workspace_id.as_deref(), Some("workspace-1"));
    assert_eq!(decision.tenant.api_key_id.as_deref(), Some("key-live"));
}

#[test]
fn storage_authenticator_rejects_wrong_disabled_revoked_and_expired_keys() {
    let secret = "fg_live_1234567890abcdef";
    let authenticator = StorageApiKeyAuthenticator::with_clock(
        storage_with_api_key(stored_api_key("key-disabled", secret, |key| {
            key.enabled = false;
        })),
        Arc::new(|| 1_700_000_000),
    );
    assert!(authenticator.authenticate(secret).is_none());

    let authenticator = StorageApiKeyAuthenticator::with_clock(
        storage_with_api_key(stored_api_key("key-revoked", secret, |key| {
            key.revoked_at_unix = Some(1_699_999_999);
        })),
        Arc::new(|| 1_700_000_000),
    );
    assert!(authenticator.authenticate(secret).is_none());

    let authenticator = StorageApiKeyAuthenticator::with_clock(
        storage_with_api_key(stored_api_key("key-expired", secret, |key| {
            key.expires_at_unix = Some(1_700_000_000);
        })),
        Arc::new(|| 1_700_000_000),
    );
    assert!(authenticator.authenticate(secret).is_none());

    let authenticator = StorageApiKeyAuthenticator::with_clock(
        storage_with_api_key(stored_api_key("key-live", secret, |_| {})),
        Arc::new(|| 1_700_000_000),
    );
    assert!(authenticator
        .authenticate("fg_live_wrong00000000")
        .is_none());
}

#[test]
fn storage_authenticator_supports_existing_blake2b_hashes() {
    let secret = "fg_live_1234567890abcdef";
    let repositories = storage_with_api_key(stored_api_key("key-live", secret, |key| {
        let digest = Blake2b512::digest(secret.as_bytes());
        key.key_hash = format!("blake2b:{}", encode_hex(&digest));
    }));
    let authenticator =
        StorageApiKeyAuthenticator::with_clock(repositories, Arc::new(|| 1_700_000_000));

    assert!(authenticator.authenticate(secret).is_some());
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

fn storage_with_api_key(api_key: StoredApiKey) -> Arc<RuntimeStorageRepositories> {
    let mut control_plane = RuntimeControlPlaneState::new();
    control_plane.upsert_tenant_account(ferrogate_storage::StoredTenantAccount {
        id: "tenant-1".into(),
        name: "Tenant 1".into(),
        slug: "tenant-1".into(),
        status: "active".into(),
        plan_id: "free".into(),
        created_at_unix: 1,
        updated_at_unix: 1,
    });
    control_plane.upsert_project(ferrogate_storage::StoredProject {
        id: "project-1".into(),
        tenant_id: "tenant-1".into(),
        name: "Project 1".into(),
        slug: "project-1".into(),
        status: "active".into(),
        created_at_unix: 1,
        updated_at_unix: 1,
    });
    control_plane.upsert_workspace(ferrogate_storage::StoredWorkspace {
        id: "workspace-1".into(),
        tenant_id: "tenant-1".into(),
        project_id: "project-1".into(),
        name: "Workspace 1".into(),
        slug: "workspace-1".into(),
        environment: "prod".into(),
        status: "active".into(),
        created_at_unix: 1,
        updated_at_unix: 1,
    });
    control_plane.upsert_api_key_record(api_key);
    Arc::new(RuntimeStorageRepositories::new(
        RuntimeStorageBackend::in_memory(vec![StorageProviderKind::Memory]),
        control_plane,
        0,
        0,
    ))
}

fn stored_api_key(id: &str, secret: &str, mutate: impl FnOnce(&mut StoredApiKey)) -> StoredApiKey {
    let material = virtual_api_key_material(secret).unwrap();
    let scope = WorkspaceScope::new("tenant-1", "project-1", "workspace-1");
    let mut tenant = TenantContext::default();
    scope.apply_to(&mut tenant);
    tenant.api_key_id = Some(id.into());
    let mut key = StoredApiKey {
        id: id.into(),
        workspace_id: scope.workspace_id,
        tenant_id: scope.tenant_id,
        project_id: scope.project_id,
        name: "Live key".into(),
        key_prefix: material.key_prefix,
        key_hash: material.key_hash,
        last4: material.last4,
        enabled: true,
        scopes: Vec::new(),
        allowed_models: Vec::new(),
        allowed_providers: Vec::new(),
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
    key
}
