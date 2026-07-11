// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for MCP identity storage, kept outside business logic.

use std::sync::{Arc, Barrier};

use super::*;
use crate::StorageProviderKind;

fn credential() -> StoredMcpOauthCredential {
    StoredMcpOauthCredential {
        id: "credential".into(),
        tenant_id: "tenant".into(),
        workspace_id: "workspace".into(),
        user_id: "user".into(),
        server_name: "server".into(),
        issuer: "https://issuer.invalid".into(),
        subject: "user".into(),
        token_type: "Bearer".into(),
        scopes: vec!["openid".into()],
        access_token_nonce: vec![1],
        access_token_ciphertext: vec![2],
        refresh_token_nonce: Some(vec![3]),
        refresh_token_ciphertext: Some(vec![4]),
        expires_at_unix: 1,
        key_version: 1,
        version: 1,
        authorization_generation: 1,
        refresh_lease_id: None,
        refresh_lease_expires_at_unix: None,
        created_at_unix: 1,
        updated_at_unix: 1,
        revoked_at_unix: None,
        last_refresh_outcome: None,
        last_revocation_outcome: None,
    }
}

fn repositories_with_credential() -> RuntimeStorageRepositories {
    let repositories =
        RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16);
    let RuntimeControlPlaneBackend::Memory(store) = &repositories.control_plane else {
        panic!("expected memory control plane");
    };
    store
        .lock()
        .expect("memory control plane lock")
        .mcp_oauth_credentials
        .insert("credential", credential());
    repositories
}

#[test]
fn refresh_lease_has_exactly_one_concurrent_winner() {
    let repositories = Arc::new(repositories_with_credential());
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for lease_id in ["lease-a", "lease-b"] {
        let repositories = Arc::clone(&repositories);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            repositories
                .claim_mcp_oauth_refresh(&McpRefreshClaimRequest {
                    tenant_id: "tenant".into(),
                    credential_id: "credential".into(),
                    expected_version: 1,
                    authorization_generation: 1,
                    lease_id: lease_id.into(),
                    now_unix: 10,
                    lease_expires_at_unix: 20,
                })
                .expect("refresh claim")
        }));
    }
    let outcomes = handles
        .into_iter()
        .map(|handle| handle.join().expect("claim thread"))
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, McpRefreshClaimOutcome::Acquired(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, McpRefreshClaimOutcome::Busy { .. }))
            .count(),
        1
    );
}

#[test]
fn revoke_supersedes_refresh_lease_and_pending_flow() {
    let repositories = repositories_with_credential();
    let request = McpIdentityAccessRequest {
        tenant_id: "tenant".into(),
        workspace_id: "workspace".into(),
        user_id: "user".into(),
        server_name: "server".into(),
        permission_key: "mcp.identity.revoke".into(),
    };
    let RuntimeControlPlaneBackend::Memory(store) = &repositories.control_plane else {
        panic!("expected memory control plane");
    };
    {
        let mut store = store.lock().expect("memory control plane lock");
        store
            .mcp_oauth_authorization_generations
            .insert(authorization_generation_key(&request), 1);
        store.mcp_oauth_flows.insert(
            "flow",
            StoredMcpOauthFlow {
                id: "flow".into(),
                tenant_id: "tenant".into(),
                workspace_id: "workspace".into(),
                user_id: "user".into(),
                server_name: "server".into(),
                pkce_nonce: vec![1],
                pkce_ciphertext: vec![2],
                oidc_nonce: "nonce".into(),
                authorization_generation: 1,
                created_at_unix: 1,
                expires_at_unix: 100,
                consumed_at_unix: None,
            },
        );
    }
    let claim = repositories
        .claim_mcp_oauth_refresh(&McpRefreshClaimRequest {
            tenant_id: "tenant".into(),
            credential_id: "credential".into(),
            expected_version: 1,
            authorization_generation: 1,
            lease_id: "lease".into(),
            now_unix: 10,
            lease_expires_at_unix: 20,
        })
        .expect("refresh claim");
    assert!(matches!(claim, McpRefreshClaimOutcome::Acquired(_)));
    repositories
        .revoke_mcp_oauth_identity(&request, 11, "local_revoked")
        .expect("revoke")
        .expect("active credential");
    let flow = {
        let store = store.lock().expect("memory control plane lock");
        store.mcp_oauth_flows.get("flow").expect("flow")
    };
    assert_eq!(flow.consumed_at_unix, Some(11));
    let mut stale = credential();
    stale.last_refresh_outcome = Some("refreshed".into());
    assert!(!repositories
        .complete_mcp_oauth_refresh(stale, "lease")
        .expect("late refresh completion"));
}
