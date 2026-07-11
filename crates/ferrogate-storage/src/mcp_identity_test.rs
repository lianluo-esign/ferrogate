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

fn claim(
    repositories: &RuntimeStorageRepositories,
    lease_id: &str,
    now_unix: i64,
    lease_ttl_secs: i64,
) -> McpRefreshClaimOutcome {
    repositories
        .claim_mcp_oauth_refresh(&McpRefreshClaimRequest {
            tenant_id: "tenant".into(),
            credential_id: "credential".into(),
            expected_version: 1,
            authorization_generation: 1,
            lease_id: lease_id.into(),
            now_unix,
            lease_ttl_secs,
        })
        .expect("refresh claim")
}

fn renew(
    repositories: &RuntimeStorageRepositories,
    lease_id: &str,
    now_unix: i64,
    lease_ttl_secs: i64,
) -> McpRefreshRenewOutcome {
    repositories
        .renew_mcp_oauth_refresh(&McpRefreshRenewRequest {
            tenant_id: "tenant".into(),
            credential_id: "credential".into(),
            expected_version: 1,
            authorization_generation: 1,
            lease_id: lease_id.into(),
            now_unix,
            lease_ttl_secs,
        })
        .expect("refresh renewal")
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
                    lease_ttl_secs: 10,
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
fn nonpositive_refresh_claim_ttl_does_not_mutate_the_credential() {
    let repositories = repositories_with_credential();
    for lease_ttl_secs in [0, -1] {
        let error = repositories
            .claim_mcp_oauth_refresh(&McpRefreshClaimRequest {
                tenant_id: "tenant".into(),
                credential_id: "credential".into(),
                expected_version: 1,
                authorization_generation: 1,
                lease_id: "owner".into(),
                now_unix: 10,
                lease_ttl_secs,
            })
            .expect_err("nonpositive claim TTL must fail");
        assert!(error
            .to_string()
            .contains("refresh lease TTL must be greater than zero"));
    }
    let RuntimeControlPlaneBackend::Memory(store) = &repositories.control_plane else {
        panic!("expected memory control plane");
    };
    let persisted = store
        .lock()
        .expect("memory control plane lock")
        .mcp_oauth_credentials
        .get("credential")
        .expect("credential");
    assert_eq!(persisted.refresh_lease_id, None);
    assert_eq!(persisted.refresh_lease_expires_at_unix, None);
}

#[test]
fn refresh_claim_uses_database_operation_time_for_takeover_and_full_ttl() {
    let mut expired_at_database = credential();
    expired_at_database.refresh_lease_id = Some("stale-owner".into());
    expired_at_database.refresh_lease_expires_at_unix = Some(95);
    let delayed_request = McpRefreshClaimRequest {
        tenant_id: "tenant".into(),
        credential_id: "credential".into(),
        expected_version: 1,
        authorization_generation: 1,
        lease_id: "new-owner".into(),
        now_unix: 10,
        lease_ttl_secs: 10,
    };
    let database_now = 100;

    assert!(matches!(
        classify_mcp_refresh_claim(Some(expired_at_database), &delayed_request, database_now),
        McpRefreshClaimClassification::Acquirable(_)
    ));
    assert_eq!(
        require_refresh_lease_expiry(database_now, delayed_request.lease_ttl_secs).unwrap(),
        110
    );

    let mut active_at_database = credential();
    active_at_database.refresh_lease_id = Some("active-owner".into());
    active_at_database.refresh_lease_expires_at_unix = Some(105);
    let skewed_request = McpRefreshClaimRequest {
        now_unix: 1_000,
        ..delayed_request
    };
    assert!(matches!(
        classify_mcp_refresh_claim(Some(active_at_database), &skewed_request, database_now),
        McpRefreshClaimClassification::Outcome(McpRefreshClaimOutcome::Busy {
            lease_expires_at_unix: 105
        })
    ));
}

#[test]
fn refresh_lease_renewal_extends_exclusivity_until_safe_takeover() {
    let repositories = repositories_with_credential();
    assert!(matches!(
        claim(&repositories, "owner", 10, 10),
        McpRefreshClaimOutcome::Acquired(_)
    ));
    assert_eq!(
        renew(&repositories, "owner", 15, 15),
        McpRefreshRenewOutcome::Renewed {
            lease_expires_at_unix: 30
        }
    );
    assert_eq!(
        claim(&repositories, "contender", 21, 10),
        McpRefreshClaimOutcome::Busy {
            lease_expires_at_unix: 30
        }
    );
    assert!(matches!(
        claim(&repositories, "contender", 30, 10),
        McpRefreshClaimOutcome::Acquired(_)
    ));
    assert_eq!(
        renew(&repositories, "owner", 30, 11),
        McpRefreshRenewOutcome::OwnershipChanged
    );
    let mut stale = credential();
    stale.last_refresh_outcome = Some("refreshed".into());
    assert!(!repositories
        .complete_mcp_oauth_refresh(stale, "owner")
        .expect("stale refresh completion"));
}

#[test]
fn same_tick_renewal_is_monotonic_and_expired_owner_cannot_renew() {
    let repositories = repositories_with_credential();
    assert!(matches!(
        claim(&repositories, "owner", 10, 10),
        McpRefreshClaimOutcome::Acquired(_)
    ));
    assert_eq!(
        renew(&repositories, "owner", 15, 5),
        McpRefreshRenewOutcome::Renewed {
            lease_expires_at_unix: 21
        }
    );
    assert_eq!(
        renew(&repositories, "owner", 21, 10),
        McpRefreshRenewOutcome::Expired {
            lease_expires_at_unix: Some(21)
        }
    );
    assert!(matches!(
        claim(&repositories, "contender", 21, 10),
        McpRefreshClaimOutcome::Acquired(_)
    ));
}

#[test]
fn same_second_renewal_extends_claimed_lease_by_one_second() {
    let repositories = repositories_with_credential();
    let claimed = claim(&repositories, "owner", 10, 18);
    let McpRefreshClaimOutcome::Acquired(claimed) = claimed else {
        panic!("expected refresh claim");
    };
    assert_eq!(claimed.refresh_lease_expires_at_unix, Some(28));
    assert_eq!(
        renew(&repositories, "owner", 10, 18),
        McpRefreshRenewOutcome::Renewed {
            lease_expires_at_unix: 29
        }
    );
}

#[test]
fn nonpositive_refresh_lease_ttl_does_not_mutate_the_active_lease() {
    let repositories = repositories_with_credential();
    assert!(matches!(
        claim(&repositories, "owner", 10, 10),
        McpRefreshClaimOutcome::Acquired(_)
    ));
    assert_eq!(
        renew(&repositories, "owner", 15, 0),
        McpRefreshRenewOutcome::NotExtended {
            lease_expires_at_unix: 20
        }
    );
    assert_eq!(
        renew(&repositories, "owner", 15, -1),
        McpRefreshRenewOutcome::NotExtended {
            lease_expires_at_unix: 20
        }
    );
    let RuntimeControlPlaneBackend::Memory(store) = &repositories.control_plane else {
        panic!("expected memory control plane");
    };
    let persisted = store
        .lock()
        .expect("memory control plane lock")
        .mcp_oauth_credentials
        .get("credential")
        .expect("credential");
    assert_eq!(persisted.refresh_lease_expires_at_unix, Some(20));
}

#[test]
fn refresh_lease_expiry_is_derived_from_operation_time_after_queue_delay() {
    let request = McpRefreshRenewRequest {
        tenant_id: "tenant".into(),
        credential_id: "credential".into(),
        expected_version: 1,
        authorization_generation: 1,
        lease_id: "owner".into(),
        now_unix: 10,
        lease_ttl_secs: 10,
    };
    let state = McpRefreshLeaseState {
        tenant_matches: true,
        version: 1,
        authorization_generation: 1,
        refresh_lease_id: Some("owner".into()),
        refresh_lease_expires_at_unix: Some(105),
        revoked: false,
    };
    let database_now = 100;
    let database_expiry = derive_refresh_lease_renewal_expiry(
        database_now,
        request.lease_ttl_secs,
        state.refresh_lease_expires_at_unix,
    );

    assert_eq!(derive_refresh_lease_expiry(request.now_unix, 10), Some(20));
    assert_eq!(database_expiry, Some(110));
    assert_eq!(
        mcp_refresh_renewal_rejection(Some(&state), &request, database_now, database_expiry),
        None
    );
}

#[test]
fn refresh_renewal_fails_closed_when_credential_version_changes() {
    let repositories = repositories_with_credential();
    assert!(matches!(
        claim(&repositories, "owner", 10, 10),
        McpRefreshClaimOutcome::Acquired(_)
    ));
    let RuntimeControlPlaneBackend::Memory(store) = &repositories.control_plane else {
        panic!("expected memory control plane");
    };
    let mut current = store
        .lock()
        .expect("memory control plane lock")
        .mcp_oauth_credentials
        .get("credential")
        .expect("credential");
    current.version = 2;
    store
        .lock()
        .expect("memory control plane lock")
        .mcp_oauth_credentials
        .insert("credential", current);
    assert_eq!(
        renew(&repositories, "owner", 15, 15),
        McpRefreshRenewOutcome::CredentialChanged
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
            lease_ttl_secs: 10,
        })
        .expect("refresh claim");
    assert!(matches!(claim, McpRefreshClaimOutcome::Acquired(_)));
    assert_eq!(
        renew(&repositories, "lease", 11, 19),
        McpRefreshRenewOutcome::Renewed {
            lease_expires_at_unix: 30
        }
    );
    repositories
        .revoke_mcp_oauth_identity(&request, 11, "local_revoked")
        .expect("revoke")
        .expect("active credential");
    assert_eq!(
        renew(&repositories, "lease", 12, 28),
        McpRefreshRenewOutcome::Revoked
    );
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
