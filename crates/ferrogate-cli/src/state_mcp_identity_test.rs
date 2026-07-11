// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for MCP identity state, kept outside business logic.

use super::*;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

static IDENTITY_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn ciphertext_is_bound_to_subject_aad_and_debug_never_contains_plaintext() {
    let _guard = IDENTITY_ENV_LOCK.lock().unwrap();
    std::env::set_var(MCP_IDENTITY_KEY_ENV, "11".repeat(32));
    let cipher = IdentityCipher::from_env().unwrap();
    let (nonce, ciphertext) = cipher
        .encrypt(b"secret-access-token", b"tenant-a/user-a")
        .unwrap();
    assert!(!ciphertext
        .windows(19)
        .any(|window| window == b"secret-access-token"));
    assert_eq!(
        cipher
            .decrypt(&nonce, &ciphertext, b"tenant-a/user-a")
            .unwrap(),
        b"secret-access-token"
    );
    assert!(cipher
        .decrypt(&nonce, &ciphertext, b"tenant-a/user-b")
        .is_err());
    std::env::remove_var(MCP_IDENTITY_KEY_ENV);
}

#[test]
fn encryption_key_requires_exact_hex_material() {
    let _guard = IDENTITY_ENV_LOCK.lock().unwrap();
    std::env::set_var(MCP_IDENTITY_KEY_ENV, "short");
    let error = match IdentityCipher::from_env() {
        Ok(_) => panic!("short encryption key unexpectedly passed validation"),
        Err(error) => error,
    };
    assert_eq!(error.code, "mcp_identity_key_invalid");
    std::env::remove_var(MCP_IDENTITY_KEY_ENV);
}

#[test]
fn refresh_heartbeat_renews_until_slow_work_completes() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let renewals = Arc::new(AtomicU64::new(0));
        let observed = Arc::clone(&renewals);
        let result = run_with_refresh_heartbeat(
            async {
                tokio::time::sleep(Duration::from_millis(85)).await;
                Ok::<_, McpIdentityError>("refreshed")
            },
            Duration::from_millis(20),
            Duration::from_millis(20),
            Duration::from_millis(250),
            move || {
                let observed = Arc::clone(&observed);
                async move {
                    observed.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(result, "refreshed");
        assert!(renewals.load(Ordering::SeqCst) >= 3);
    });
}

#[test]
fn refresh_heartbeat_failure_cancels_inflight_work() {
    struct CancellationProbe(Arc<AtomicBool>);

    impl Drop for CancellationProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let cancelled = Arc::new(AtomicBool::new(false));
        let work_cancelled = Arc::clone(&cancelled);
        let renewal_attempts = Arc::new(AtomicU64::new(0));
        let observed_attempts = Arc::clone(&renewal_attempts);
        let error = run_with_refresh_heartbeat(
            async move {
                let _probe = CancellationProbe(work_cancelled);
                std::future::pending::<Result<(), McpIdentityError>>().await
            },
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(250),
            move || {
                let observed_attempts = Arc::clone(&observed_attempts);
                async move {
                    if observed_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        Ok(())
                    } else {
                        Err(McpIdentityError::unavailable(
                            "mcp_identity_refresh_conflict",
                            "test lease ownership changed",
                        ))
                    }
                }
            },
        )
        .await
        .unwrap_err();

        assert_eq!(error.code, "mcp_identity_refresh_conflict");
        assert!(renewal_attempts.load(Ordering::SeqCst) >= 2);
        assert!(cancelled.load(Ordering::SeqCst));
    });
}

#[test]
fn refresh_owner_timeout_cancels_work_without_releasing_ownership() {
    struct CancellationProbe(Arc<AtomicBool>);

    impl Drop for CancellationProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let cancelled = Arc::new(AtomicBool::new(false));
        let work_cancelled = Arc::clone(&cancelled);
        let renewals = Arc::new(AtomicU64::new(0));
        let observed = Arc::clone(&renewals);
        let error = run_with_refresh_heartbeat(
            async move {
                let _probe = CancellationProbe(work_cancelled);
                std::future::pending::<Result<(), McpIdentityError>>().await
            },
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(45),
            move || {
                let observed = Arc::clone(&observed);
                async move {
                    observed.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
        )
        .await
        .unwrap_err();

        assert_eq!(error.code, "mcp_identity_refresh_owner_timeout");
        assert!(renewals.load(Ordering::SeqCst) >= 3);
        assert!(cancelled.load(Ordering::SeqCst));
    });
}

#[test]
fn refresh_renewal_response_timeout_stops_waiting_for_inflight_work() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let error = run_with_refresh_heartbeat(
            std::future::pending::<Result<(), McpIdentityError>>(),
            Duration::from_millis(5),
            Duration::from_millis(10),
            Duration::from_millis(100),
            std::future::pending::<Result<(), McpIdentityError>>,
        )
        .await
        .unwrap_err();

        assert_eq!(error.code, "mcp_identity_refresh_renewal_timeout");
    });
}

#[test]
fn refresh_heartbeat_tolerates_slow_successful_renewal_responses() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let renewals = Arc::new(AtomicU64::new(0));
        let observed = Arc::clone(&renewals);
        let result = run_with_refresh_heartbeat(
            async {
                tokio::time::sleep(Duration::from_millis(90)).await;
                Ok::<_, McpIdentityError>("refreshed")
            },
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(200),
            move || {
                let observed = Arc::clone(&observed);
                async move {
                    observed.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(15)).await;
                    Ok(())
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(result, "refreshed");
        assert!(renewals.load(Ordering::SeqCst) >= 3);
    });
}

#[test]
fn refresh_wait_backoff_is_bounded_lease_aware_and_deterministic() {
    let waiter_remaining = Duration::from_secs(20);
    let delays = (0..8)
        .map(|attempt| refresh_wait_backoff(110, 100, attempt, waiter_remaining, "credential-a"))
        .collect::<Vec<_>>();

    assert!(delays.windows(2).all(|window| window[0] <= window[1]));
    assert!(delays
        .iter()
        .all(|delay| *delay <= Duration::from_millis(REFRESH_WAIT_MAX_MILLIS)));
    assert_eq!(
        delays,
        (0..8)
            .map(|attempt| {
                refresh_wait_backoff(110, 100, attempt, waiter_remaining, "credential-a")
            })
            .collect::<Vec<_>>()
    );

    let lease_capped = refresh_wait_backoff(101, 100, 7, waiter_remaining, "credential-a");
    assert!(lease_capped <= Duration::from_secs(1));
    let deadline_capped =
        refresh_wait_backoff(110, 100, 7, Duration::from_millis(25), "credential-a");
    assert_eq!(deadline_capped, Duration::from_millis(25));
    let expired = refresh_wait_backoff(100, 100, 7, waiter_remaining, "credential-a");
    assert!(expired <= Duration::from_millis(REFRESH_WAIT_MIN_MILLIS));
}

fn completion_reread_credential(
    version: u64,
    revoked_at_unix: Option<i64>,
) -> StoredMcpOauthCredential {
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
        expires_at_unix: 100,
        key_version: 1,
        version,
        authorization_generation: 1,
        refresh_lease_id: None,
        refresh_lease_expires_at_unix: None,
        created_at_unix: 1,
        updated_at_unix: 1,
        revoked_at_unix,
        last_refresh_outcome: Some("refreshed".into()),
        last_revocation_outcome: None,
    }
}

#[test]
fn refresh_completion_reread_maps_missing_and_revoked_to_not_connected() {
    let missing = resolve_mcp_refresh_completion_reread(None, 1).unwrap_err();
    assert_eq!(missing.status, StatusCode::UNAUTHORIZED);
    assert_eq!(missing.code, "mcp_identity_not_connected");

    let revoked =
        resolve_mcp_refresh_completion_reread(Some(completion_reread_credential(2, Some(100))), 1)
            .unwrap_err();
    assert_eq!(revoked.status, StatusCode::UNAUTHORIZED);
    assert_eq!(revoked.code, "mcp_identity_not_connected");
}

#[test]
fn refresh_completion_reread_accepts_winner_and_rejects_unadvanced_version() {
    let winner =
        resolve_mcp_refresh_completion_reread(Some(completion_reread_credential(2, None)), 1)
            .unwrap();
    assert_eq!(winner.version, 2);

    let conflict =
        resolve_mcp_refresh_completion_reread(Some(completion_reread_credential(1, None)), 1)
            .unwrap_err();
    assert_eq!(conflict.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(conflict.code, "mcp_identity_refresh_conflict");
}
