// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use crate::{
    async_postgres::{acquire_before_deadline, AsyncPostgresPool},
    PostgresStorageConfig, PostgresTlsMode,
};

fn config() -> PostgresStorageConfig {
    PostgresStorageConfig {
        dsn: "host=127.0.0.1 port=1 user=postgres".into(),
        pool_size: 1,
        pool_acquire_timeout_millis: 25,
        tls_mode: PostgresTlsMode::Disable,
        tls_ca_cert_path: None,
        connect_timeout_secs: 1,
        statement_timeout_millis: 1_000,
        schema: Some("tenant schema".into()),
        search_path: vec!["public".into()],
    }
}

#[test]
fn async_pool_retains_typed_timeout_and_transaction_search_path() {
    let pool = AsyncPostgresPool::new(&config()).expect("build async PostgreSQL pool");

    assert_eq!(pool.acquire_timeout(), Duration::from_millis(25));
    assert_eq!(
        pool.transaction_search_path_sql(),
        Some("SET LOCAL search_path TO \"tenant schema\", \"public\"")
    );
    assert_eq!(pool.metrics_snapshot(), Default::default());
}

#[test]
fn acquisition_deadline_drops_pending_work_without_a_late_action() {
    struct DropSignal(Option<std::sync::mpsc::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                sender.send(()).expect("signal acquisition cancellation");
            }
        }
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("test runtime");
    runtime.block_on(async {
        let (dropped_tx, dropped_rx) = std::sync::mpsc::channel();
        let pending_acquire = async move {
            let _drop_signal = DropSignal(Some(dropped_tx));
            std::future::pending::<()>().await
        };

        acquire_before_deadline(pending_acquire, Duration::from_millis(5))
            .await
            .expect_err("pending acquisition must reach its deadline");
        dropped_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("timed-out acquisition future was not dropped");
    });
}

#[test]
fn live_local_pool_exhaustion_returns_at_deadline_without_sql_side_effect() {
    let Ok(dsn) = std::env::var("FERROGATE_TEST_POSTGRES_DSN") else {
        eprintln!(
            "skipping live_local_pool_exhaustion_returns_at_deadline_without_sql_side_effect: \
             FERROGATE_TEST_POSTGRES_DSN is not set"
        );
        return;
    };
    let mut config = config();
    config.dsn = dsn;
    config.pool_acquire_timeout_millis = 1_000;
    config.schema = None;
    config.search_path.clear();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    runtime.block_on(async {
        let pool = AsyncPostgresPool::new(&config).expect("build async PostgreSQL pool");
        let held = pool
            .acquire("hold local test connection", Duration::from_secs(1))
            .await
            .expect("acquire the only local test connection");
        held.batch_execute(
            "CREATE TEMP TABLE ferrogate_async_pool_side_effect(marker integer) ON COMMIT PRESERVE ROWS",
        )
        .await
        .expect("create local side-effect probe");

        let action_ran = AtomicBool::new(false);
        let error = match pool
            .acquire("exhausted local test pool", Duration::from_millis(25))
            .await
        {
            Ok(client) => {
                action_ran.store(true, Ordering::SeqCst);
                client
                    .execute(
                        "INSERT INTO ferrogate_async_pool_side_effect(marker) VALUES (1)",
                        &[],
                    )
                    .await
                    .expect("unexpected side-effect probe insert");
                panic!("exhausted pool unexpectedly returned a client");
            }
            Err(error) => error,
        };

        assert!(matches!(
            error,
            crate::StorageError::OperationDeadlineExceeded {
                operation: "exhausted local test pool",
                stage: "pool acquisition",
                commit_started: false,
            }
        ));
        assert!(!action_ran.load(Ordering::SeqCst));
        let row = held
            .query_one(
                "SELECT COUNT(*)::bigint FROM ferrogate_async_pool_side_effect",
                &[],
            )
            .await
            .expect("read local side-effect probe");
        assert_eq!(row.get::<_, i64>(0), 0);
        let metrics = pool.metrics_snapshot();
        assert_eq!(metrics.acquire_total, 2);
        assert_eq!(metrics.acquire_timeout_total, 1);
        assert!(metrics.acquire_wait_micros_total > 0);

        drop(held);
        let _reused = pool
            .acquire("reuse local test pool", Duration::from_secs(1))
            .await
            .expect("pool must recover after the held client is released");
    });
}
