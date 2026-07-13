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

async fn run_with_refresh_heartbeat<T, Work, Renew, RenewFuture>(
    work: Work,
    heartbeat_interval: Duration,
    renewal_timeout: Duration,
    owner_timeout: Duration,
    renew: Renew,
) -> Result<T, McpIdentityError>
where
    Work: std::future::Future<Output = Result<T, McpIdentityError>>,
    Renew: FnMut() -> RenewFuture,
    RenewFuture: std::future::Future<Output = Result<(), McpIdentityError>>,
{
    match run_with_refresh_heartbeat_tagged(
        work,
        heartbeat_interval,
        renewal_timeout,
        owner_timeout,
        renew,
    )
    .await
    {
        RefreshHeartbeatOutcome::Work(result) => result,
        RefreshHeartbeatOutcome::HeartbeatFailed(error)
        | RefreshHeartbeatOutcome::OwnerTimedOut(error) => Err(error),
    }
}

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
fn commit_started_storage_result_reconciles_success_before_secondary_deadline() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let metrics = Arc::new(Mutex::new(GatewayMetricsAccumulator::default()));
        let operation = StorageOperation::new_reconcilable_commit(
            "test completion",
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        let blocking_operation = operation.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            blocking_operation
                .begin_commit("test commit")
                .expect("commit fence");
            started_tx.send(()).expect("commit started signal");
            std::thread::sleep(Duration::from_millis(20));
            blocking_operation.finish_commit();
            Ok::<_, StorageError>("persisted")
        });
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("commit did not start");

        let result = reconcile_mcp_refresh_storage_after_deadline(
            Arc::clone(&metrics),
            "test completion",
            operation,
            task,
            Duration::from_millis(100),
            Duration::from_millis(100),
            tracing::Span::current(),
        )
        .await
        .expect("late result must reconcile");

        assert_eq!(result, "persisted");
        let metrics = metrics.lock().unwrap();
        assert_eq!(metrics.mcp_refresh_response_deadline_total, 1);
        assert_eq!(metrics.mcp_refresh_storage_cancellation_total, 0);
        assert_eq!(metrics.mcp_refresh_late_reconciliation_total, 1);
    });
}

#[test]
fn commit_started_storage_result_returns_pending_then_records_background_outcome() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let metrics = Arc::new(Mutex::new(GatewayMetricsAccumulator::default()));
        let operation = StorageOperation::new_reconcilable_commit(
            "test pending completion",
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
        let blocking_operation = operation.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            blocking_operation
                .begin_commit("test commit")
                .expect("commit fence");
            started_tx.send(()).expect("commit started signal");
            std::thread::sleep(Duration::from_millis(80));
            blocking_operation.finish_commit();
            Ok::<_, StorageError>("persisted")
        });
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("commit did not start");

        let error = reconcile_mcp_refresh_storage_after_deadline(
            Arc::clone(&metrics),
            "test pending completion",
            operation,
            task,
            Duration::from_millis(5),
            Duration::from_millis(100),
            tracing::Span::current(),
        )
        .await
        .expect_err("slow commit must return pending evidence");
        assert_eq!(error.code, "mcp_identity_storage_reconciliation_pending");
        {
            let metrics = metrics.lock().unwrap();
            assert_eq!(metrics.mcp_refresh_response_deadline_total, 1);
            assert_eq!(metrics.mcp_refresh_storage_cancellation_total, 0);
            assert_eq!(metrics.mcp_refresh_late_reconciliation_total, 0);
        }

        tokio::time::sleep(Duration::from_millis(120)).await;
        let metrics = metrics.lock().unwrap();
        assert_eq!(metrics.mcp_refresh_late_reconciliation_total, 1);
    });
}

#[test]
fn renewal_commit_crossing_reconcile_window_reports_late_commit_deadline() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let metrics = Arc::new(Mutex::new(GatewayMetricsAccumulator::default()));
        let operation = StorageOperation::new("test renewal", Duration::from_secs(1));
        let blocking_operation = operation.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            blocking_operation
                .begin_commit("test renewal commit")
                .expect("commit fence");
            started_tx.send(()).expect("commit started signal");
            std::thread::sleep(Duration::from_millis(80));
            blocking_operation.finish_commit();
            Err::<(), _>(StorageError::OperationDeadlineExceeded {
                operation: "test renewal",
                stage: "transaction commit",
                commit_started: true,
            })
        });
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("renewal commit did not start");

        let error = reconcile_mcp_refresh_storage_after_deadline(
            Arc::clone(&metrics),
            "test renewal",
            operation,
            task,
            Duration::from_millis(5),
            Duration::from_millis(100),
            tracing::Span::current(),
        )
        .await
        .expect_err("renewal must return its authoritative commit deadline");

        assert_eq!(error.code, "mcp_identity_storage_deadline");
        {
            let metrics = metrics.lock().unwrap();
            assert_eq!(metrics.mcp_refresh_response_deadline_total, 1);
            assert_eq!(metrics.mcp_refresh_storage_cancellation_total, 1);
            assert_eq!(metrics.mcp_refresh_late_reconciliation_total, 0);
        }
    });
}

#[test]
fn cancel_policy_commit_exceeding_authoritative_grace_requires_reread_without_pending() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let metrics = Arc::new(Mutex::new(GatewayMetricsAccumulator::default()));
        let operation = StorageOperation::new("test cancel grace", Duration::from_secs(1));
        let blocking_operation = operation.clone();
        let finished = Arc::new(AtomicBool::new(false));
        let worker_finished = Arc::clone(&finished);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            blocking_operation
                .begin_commit("test cancel grace commit")
                .expect("commit fence");
            started_tx.send(()).expect("commit started signal");
            std::thread::sleep(Duration::from_millis(80));
            blocking_operation.finish_commit();
            worker_finished.store(true, Ordering::SeqCst);
            Err::<(), _>(StorageError::OperationDeadlineExceeded {
                operation: "test cancel grace",
                stage: "transaction commit",
                commit_started: true,
            })
        });
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("cancel-policy commit did not start");

        let error = reconcile_mcp_refresh_storage_after_deadline(
            Arc::clone(&metrics),
            "test cancel grace",
            operation,
            task,
            Duration::from_millis(5),
            Duration::from_millis(5),
            tracing::Span::current(),
        )
        .await
        .expect_err("cancel-policy grace exhaustion must fail closed");
        assert_eq!(error.code, "mcp_identity_storage_reconcile_required");
        assert_ne!(error.code, "mcp_identity_storage_reconciliation_pending");
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(finished.load(Ordering::SeqCst));
        let metrics = metrics.lock().unwrap();
        assert_eq!(metrics.mcp_refresh_storage_cancellation_total, 0);
        assert_eq!(metrics.mcp_refresh_storage_outcome_unknown_total, 0);
        assert_eq!(metrics.mcp_refresh_late_reconciliation_total, 0);
    });
}

#[test]
fn unresolved_renewal_commit_with_old_reread_is_outcome_unknown() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let metrics = Arc::new(Mutex::new(GatewayMetricsAccumulator::default()));
        let operation = StorageOperation::new("delayed committed renewal", Duration::from_secs(1));
        let blocking_operation = operation.clone();
        let finished = Arc::new(AtomicBool::new(false));
        let worker_finished = Arc::clone(&finished);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            blocking_operation
                .begin_commit("delayed committed renewal")
                .expect("commit fence");
            started_tx.send(()).expect("commit signal");
            release_rx.recv().expect("commit release");
            blocking_operation.finish_commit();
            worker_finished.store(true, Ordering::SeqCst);
            Ok::<_, StorageError>(())
        });
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("renewal did not commit");

        let error = reconcile_mcp_refresh_storage_after_deadline(
            Arc::clone(&metrics),
            "delayed committed renewal",
            operation,
            task,
            Duration::from_millis(5),
            Duration::from_millis(5),
            tracing::Span::current(),
        )
        .await
        .expect_err("delayed result must not be reported as cancellation");
        assert_eq!(error.code, "mcp_identity_storage_reconcile_required");
        assert!(!finished.load(Ordering::SeqCst));
        let old_state = resolve_reconciled_mcp_refresh_renewal(
            McpRefreshRenewOutcome::NotExtended {
                lease_expires_at_unix: 100,
            },
            100,
        )
        .expect_err("old state cannot prove an unresolved COMMIT was cancelled");
        assert_eq!(old_state.code, "mcp_identity_storage_outcome_unknown");
        let metrics = metrics.lock().unwrap();
        assert_eq!(metrics.mcp_refresh_storage_cancellation_total, 0);
        assert_eq!(metrics.mcp_refresh_storage_outcome_unknown_total, 0);
        drop(metrics);
        release_tx.send(()).expect("release renewal commit");
    });
}

#[test]
fn unresolved_claim_commit_with_old_reread_is_outcome_unknown() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let metrics = Arc::new(Mutex::new(GatewayMetricsAccumulator::default()));
        let operation = StorageOperation::new("delayed committed claim", Duration::from_secs(1));
        let blocking_operation = operation.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            blocking_operation
                .begin_commit("delayed committed claim")
                .expect("commit fence");
            started_tx.send(()).expect("commit signal");
            release_rx.recv().expect("commit release");
            blocking_operation.finish_commit();
            Ok::<_, StorageError>(())
        });
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("claim did not commit");

        let internal = reconcile_mcp_refresh_storage_after_deadline(
            Arc::clone(&metrics),
            "delayed committed claim",
            operation,
            task,
            Duration::from_millis(5),
            Duration::from_millis(5),
            tracing::Span::current(),
        )
        .await
        .expect_err("delayed claim ACK must request authoritative reread");
        assert_eq!(internal.code, "mcp_identity_storage_reconcile_required");

        let old_state = resolve_reconciled_mcp_refresh_claim(McpRefreshClaimOutcome::Changed(
            Some(completion_reread_credential(1, None)),
        ))
        .expect_err("old state cannot prove an unresolved claim COMMIT was cancelled");
        assert_eq!(old_state.code, "mcp_identity_storage_outcome_unknown");
        release_tx.send(()).expect("release claim commit");
    });
}

#[test]
fn authoritative_claim_reread_with_matching_lease_recovers_success() {
    let mut claimed = completion_reread_credential(1, None);
    claimed.refresh_lease_id = Some("owner".into());
    claimed.refresh_lease_expires_at_unix = Some(120);
    let resolved = resolve_reconciled_mcp_refresh_claim(McpRefreshClaimOutcome::Acquired(claimed))
        .expect("matching durable lease must recover the claim");

    assert!(matches!(resolved, McpRefreshClaimOutcome::Acquired(_)));
}

#[test]
fn authoritative_reread_caller_timeout_is_unknown_and_keeps_an_observer() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let metrics = Arc::new(Mutex::new(GatewayMetricsAccumulator::default()));
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            started_tx.send(()).expect("reread started");
            release_rx.recv().expect("reread release");
            finished_tx.send(()).expect("reread finished");
            Ok::<_, StorageError>(())
        });
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("reread did not start");

        let error = await_mcp_authoritative_reread(
            Arc::clone(&metrics),
            "test authoritative reread",
            task,
            Duration::from_millis(5),
            tracing::Span::current(),
        )
        .await
        .expect_err("reread caller deadline must be bounded");
        assert_eq!(error.code, "mcp_identity_storage_outcome_unknown");
        {
            let metrics = metrics.lock().unwrap();
            assert_eq!(metrics.mcp_refresh_storage_cancellation_total, 0);
            assert_eq!(metrics.mcp_refresh_storage_outcome_unknown_total, 1);
        }

        release_tx.send(()).expect("release reread");
        finished_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("observed reread did not finish");
        tokio::task::yield_now().await;
    });
}

#[test]
fn finished_mutation_result_is_observed_without_false_cancellation() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let metrics = Arc::new(Mutex::new(GatewayMetricsAccumulator::default()));
        let operation = StorageOperation::new("published renewal", Duration::from_secs(1));
        let blocking_operation = operation.clone();
        let (mutation_finished_tx, mutation_finished_rx) = std::sync::mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            blocking_operation
                .begin_commit("published renewal")
                .expect("commit fence");
            blocking_operation.finish_commit();
            mutation_finished_tx
                .send(())
                .expect("mutation finished signal");
            Ok::<_, StorageError>("renewed")
        });
        mutation_finished_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("mutation did not finish");

        let result = reconcile_mcp_refresh_storage_after_deadline(
            Arc::clone(&metrics),
            "published renewal",
            operation,
            task,
            Duration::from_millis(5),
            Duration::from_millis(50),
            tracing::Span::current(),
        )
        .await
        .expect("published result must not wait for cleanup");
        assert_eq!(result, "renewed");
        let metrics = metrics.lock().unwrap();
        assert_eq!(metrics.mcp_refresh_storage_cancellation_total, 0);
        assert_eq!(metrics.mcp_refresh_storage_outcome_unknown_total, 0);
    });
}

#[test]
fn reconciliation_error_evidence_redacts_connection_secrets() {
    let sanitized = sanitize_mcp_reconciliation_text(
        "postgresql://user:url-secret@db.invalid/db password=first passfile=second password=third",
    );

    assert!(!sanitized.contains("url-secret"));
    assert!(!sanitized.contains("first"));
    assert!(!sanitized.contains("second"));
    assert!(!sanitized.contains("third"));
    assert_eq!(sanitized.matches("[redacted]").count(), 4);
}

#[test]
fn storage_cancellation_stage_preserves_typed_deadline_context() {
    let deadline = StorageError::OperationDeadlineExceeded {
        operation: "claim MCP refresh lease",
        stage: "SQL execution",
        commit_started: false,
    };
    let cancelled = StorageError::OperationCancelled {
        operation: "renew MCP refresh lease",
        stage: "pool acquisition",
    };

    assert_eq!(mcp_storage_error_stage(&deadline), Some("SQL execution"));
    assert_eq!(
        mcp_storage_error_stage(&cancelled),
        Some("pool acquisition")
    );
    assert_eq!(
        mcp_storage_error_stage(&StorageError::Runtime("failure".into())),
        None
    );
}

#[test]
fn prompt_commit_error_requires_reconciliation_not_false_cancellation() {
    let error = storage_identity_error(StorageError::OperationCommitOutcomeUnknown {
        operation: "claim MCP refresh lease",
        stage: "transaction commit",
    });

    assert_eq!(error.code, "mcp_identity_storage_reconcile_required");
    assert_ne!(error.code, "mcp_identity_storage_deadline");
}

#[test]
fn bounded_error_audit_preserves_original_error_and_fences_late_side_effect() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let metrics = Arc::new(Mutex::new(GatewayMetricsAccumulator::default()));
        let side_effect = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&side_effect);
        let original = McpIdentityError::unavailable(
            "mcp_identity_storage_deadline",
            "refresh storage deadline",
        );
        let started = Instant::now();

        let returned = preserve_mcp_identity_error_after_bounded_audit(
            Arc::clone(&metrics),
            Arc::new(tokio::sync::Semaphore::new(1)),
            original,
            Duration::from_millis(30),
            move |operation| {
                while operation.remaining("test audit wait").is_ok() {
                    std::thread::sleep(Duration::from_millis(2));
                }
                operation.check_active("test audit side effect")?;
                observed.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;

        assert_eq!(returned.code, "mcp_identity_storage_deadline");
        assert_eq!(returned.message, "refresh storage deadline");
        assert!(started.elapsed() < Duration::from_millis(250));
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(!side_effect.load(Ordering::SeqCst));
        assert_eq!(
            metrics
                .lock()
                .unwrap()
                .mcp_identity_error_audit_deadline_total,
            1
        );
    });
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
fn refresh_work_completes_before_first_heartbeat_without_redundant_renewal() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let renewals = Arc::new(AtomicU64::new(0));
        let observed = Arc::clone(&renewals);
        let result = run_with_refresh_heartbeat(
            async { Ok::<_, McpIdentityError>("refreshed") },
            Duration::from_millis(50),
            Duration::from_millis(20),
            Duration::from_millis(200),
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
        assert_eq!(renewals.load(Ordering::SeqCst), 0);
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
        let work_started = Arc::new(AtomicBool::new(false));
        let observed_work_started = Arc::clone(&work_started);
        let renewal_attempts = Arc::new(AtomicU64::new(0));
        let observed_attempts = Arc::clone(&renewal_attempts);
        let error = run_with_refresh_heartbeat(
            async move {
                observed_work_started.store(true, Ordering::SeqCst);
                let _probe = CancellationProbe(work_cancelled);
                std::future::pending::<Result<(), McpIdentityError>>().await
            },
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(250),
            move || {
                let observed_attempts = Arc::clone(&observed_attempts);
                async move {
                    observed_attempts.fetch_add(1, Ordering::SeqCst);
                    Err(McpIdentityError::unavailable(
                        "mcp_identity_refresh_conflict",
                        "test lease ownership changed",
                    ))
                }
            },
        )
        .await
        .unwrap_err();

        assert_eq!(error.code, "mcp_identity_refresh_conflict");
        assert_eq!(renewal_attempts.load(Ordering::SeqCst), 1);
        assert!(work_started.load(Ordering::SeqCst));
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

#[test]
fn refresh_claim_storage_budgets_never_overshoot_waiter_deadline() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        assert!(refresh_claim_storage_budgets(
            tokio::time::Instant::now() + Duration::from_millis(25)
        )
        .is_none());

        let (operation, response) =
            refresh_claim_storage_budgets(tokio::time::Instant::now() + Duration::from_secs(20))
                .expect("long waiter budget");
        assert_eq!(
            operation,
            Duration::from_secs(REFRESH_CLAIM_OPERATION_TIMEOUT_SECS)
        );
        assert_eq!(
            response,
            Duration::from_secs(REFRESH_CLAIM_RESPONSE_TIMEOUT_SECS)
        );

        let remaining = Duration::from_secs(5);
        let started = tokio::time::Instant::now();
        let (operation, response) =
            refresh_claim_storage_budgets(started + remaining).expect("partial waiter budget");
        assert!(operation <= Duration::from_secs(REFRESH_CLAIM_OPERATION_TIMEOUT_SECS));
        assert!(response <= remaining);
        assert!(operation < response);
    });
}

#[test]
fn six_concurrent_waiters_receive_the_full_initial_claim_budget() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(REFRESH_WAIT_TIMEOUT_SECS);
        for _ in 0..6 {
            let (operation, response) =
                refresh_claim_storage_budgets(deadline).expect("initial waiter claim budget");
            assert_eq!(
                operation,
                Duration::from_secs(REFRESH_CLAIM_OPERATION_TIMEOUT_SECS)
            );
            assert_eq!(
                response,
                Duration::from_secs(REFRESH_CLAIM_RESPONSE_TIMEOUT_SECS)
            );
        }
    });
}

#[test]
fn refresh_authorization_read_budget_uses_waiter_deadline_not_claim_budget() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        assert!(refresh_authorization_read_budgets(
            tokio::time::Instant::now() + Duration::from_millis(1_500)
        )
        .is_none());

        let (operation, response) = refresh_authorization_read_budgets(
            tokio::time::Instant::now() + Duration::from_secs(20),
        )
        .expect("long waiter authorization budget");
        assert_eq!(
            operation,
            Duration::from_secs(REFRESH_AUTH_READ_OPERATION_TIMEOUT_SECS)
        );
        assert_eq!(
            response,
            Duration::from_secs(REFRESH_AUTH_READ_RESPONSE_TIMEOUT_SECS)
        );
        assert!(operation > Duration::from_secs(REFRESH_STORAGE_OPERATION_TIMEOUT_SECS));

        let remaining = Duration::from_secs(5);
        let started = tokio::time::Instant::now();
        let (operation, response) = refresh_authorization_read_budgets(started + remaining)
            .expect("partial waiter authorization budget");
        assert!(operation <= Duration::from_secs(3));
        assert!(response <= remaining);
        assert!(operation < response);
    });
}

#[test]
fn tagged_heartbeat_preserves_provider_and_renewal_failure_identity() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let provider = run_with_refresh_heartbeat_tagged(
            async {
                Err::<(), _>(McpIdentityError::unavailable(
                    "mcp_identity_provider_unavailable",
                    "provider failed",
                ))
            },
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
            || async { Ok(()) },
        )
        .await;
        assert!(matches!(
            provider,
            RefreshHeartbeatOutcome::Work(Err(McpIdentityError {
                code: "mcp_identity_provider_unavailable",
                ..
            }))
        ));

        let heartbeat = run_with_refresh_heartbeat_tagged(
            std::future::pending::<Result<(), McpIdentityError>>(),
            Duration::from_millis(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
            || async {
                Err(McpIdentityError::unavailable(
                    "mcp_identity_refresh_conflict",
                    "renewal failed",
                ))
            },
        )
        .await;
        assert!(matches!(
            heartbeat,
            RefreshHeartbeatOutcome::HeartbeatFailed(McpIdentityError {
                code: "mcp_identity_refresh_conflict",
                ..
            })
        ));
    });
}

#[test]
fn provider_phase_waits_for_inflight_renewal_before_final_mutation() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let renewal_completed = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&renewal_completed);
        let started = std::time::Instant::now();
        let outcome = run_with_refresh_heartbeat_tagged(
            async {
                tokio::time::sleep(Duration::from_millis(2)).await;
                Ok::<_, McpIdentityError>("provider-result")
            },
            Duration::from_millis(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
            move || {
                let observed = Arc::clone(&observed);
                async move {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    observed.store(true, Ordering::SeqCst);
                    Ok(())
                }
            },
        )
        .await;

        assert!(matches!(
            outcome,
            RefreshHeartbeatOutcome::Work(Ok("provider-result"))
        ));
        assert!(started.elapsed() >= Duration::from_millis(30));
        assert!(renewal_completed.load(Ordering::SeqCst));
    });
}

#[test]
fn owner_deadline_waits_for_inflight_renewal_handoff_before_return() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let renewal_completed = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&renewal_completed);
        let started = std::time::Instant::now();
        let outcome = run_with_refresh_heartbeat_tagged(
            std::future::pending::<Result<(), McpIdentityError>>(),
            Duration::from_millis(1),
            Duration::from_secs(1),
            Duration::from_millis(5),
            move || {
                let observed = Arc::clone(&observed);
                async move {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    observed.store(true, Ordering::SeqCst);
                    Ok(())
                }
            },
        )
        .await;

        assert!(matches!(outcome, RefreshHeartbeatOutcome::OwnerTimedOut(_)));
        assert!(started.elapsed() >= Duration::from_millis(30));
        assert!(renewal_completed.load(Ordering::SeqCst));
    });
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

#[test]
fn ambiguous_completion_reread_keeps_unadvanced_version_unknown() {
    let winner = resolve_ambiguous_mcp_refresh_completion_reread(
        Some(completion_reread_credential(2, None)),
        1,
    )
    .unwrap();
    assert_eq!(winner.version, 2);

    let unknown = resolve_ambiguous_mcp_refresh_completion_reread(
        Some(completion_reread_credential(1, None)),
        1,
    )
    .unwrap_err();
    assert_eq!(unknown.code, "mcp_identity_storage_outcome_unknown");
}
