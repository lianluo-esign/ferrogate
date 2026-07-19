// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, RecyclingMethod};

use super::{
    build_postgres_tls_connector, postgres_search_path_sql, sanitize_storage_error,
    PostgresStorageConfig, PostgresTlsMode, StorageError,
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PostgresPoolMetricsSnapshot {
    pub acquire_total: u64,
    pub acquire_timeout_total: u64,
    pub acquire_wait_micros_total: u64,
}

#[derive(Debug, Default)]
struct PostgresPoolMetrics {
    acquire_total: AtomicU64,
    acquire_timeout_total: AtomicU64,
    acquire_wait_micros_total: AtomicU64,
}

impl PostgresPoolMetrics {
    fn record_acquire(&self, waited: Duration, timed_out: bool) {
        saturating_atomic_increment(&self.acquire_total, 1);
        saturating_atomic_increment(
            &self.acquire_wait_micros_total,
            u64::try_from(waited.as_micros()).unwrap_or(u64::MAX),
        );
        if timed_out {
            saturating_atomic_increment(&self.acquire_timeout_total, 1);
        }
    }

    fn snapshot(&self) -> PostgresPoolMetricsSnapshot {
        PostgresPoolMetricsSnapshot {
            acquire_total: self.acquire_total.load(Ordering::Relaxed),
            acquire_timeout_total: self.acquire_timeout_total.load(Ordering::Relaxed),
            acquire_wait_micros_total: self.acquire_wait_micros_total.load(Ordering::Relaxed),
        }
    }
}

fn saturating_atomic_increment(counter: &AtomicU64, increment: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(increment))
    });
}

pub(crate) async fn acquire_before_deadline<F>(
    acquire: F,
    timeout: Duration,
) -> Result<F::Output, tokio::time::error::Elapsed>
where
    F: std::future::Future,
{
    tokio::time::timeout(timeout, acquire).await
}

pub(crate) struct AsyncPostgresPool {
    pool: Pool,
    acquire_timeout: Duration,
    statement_timeout: Duration,
    transaction_search_path_sql: Option<String>,
    configured_schema: Option<String>,
    metrics: PostgresPoolMetrics,
}

impl std::fmt::Debug for AsyncPostgresPool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AsyncPostgresPool")
            .field("pool", &"<redacted>")
            .field("acquire_timeout", &self.acquire_timeout)
            .field("statement_timeout", &self.statement_timeout)
            .field(
                "transaction_search_path_sql",
                &self.transaction_search_path_sql,
            )
            .finish()
    }
}

impl AsyncPostgresPool {
    pub(crate) fn new(config: &PostgresStorageConfig) -> Result<Self, StorageError> {
        let connect_timeout = Duration::from_secs(config.connect_timeout_secs);
        let mut pg_config = tokio_postgres::Config::from_str(&config.dsn)
            .map_err(|error| StorageError::Postgres(sanitize_storage_error(&error.to_string())))?;
        pg_config.connect_timeout(connect_timeout);
        pg_config.tcp_user_timeout(connect_timeout);
        pg_config.ssl_mode(match config.tls_mode {
            PostgresTlsMode::Disable => tokio_postgres::config::SslMode::Disable,
            PostgresTlsMode::Prefer => tokio_postgres::config::SslMode::Prefer,
            PostgresTlsMode::Require | PostgresTlsMode::VerifyCa | PostgresTlsMode::VerifyFull => {
                tokio_postgres::config::SslMode::Require
            }
        });
        let manager_config = ManagerConfig {
            recycling_method: RecyclingMethod::Verified,
        };
        let manager = match config.tls_mode {
            PostgresTlsMode::Disable => {
                Manager::from_config(pg_config, tokio_postgres::NoTls, manager_config)
            }
            PostgresTlsMode::Prefer
            | PostgresTlsMode::Require
            | PostgresTlsMode::VerifyCa
            | PostgresTlsMode::VerifyFull => Manager::from_config(
                pg_config,
                build_postgres_tls_connector(config)?,
                manager_config,
            ),
        };
        let pool = Pool::builder(manager)
            .max_size(config.pool_size)
            .build()
            .map_err(|error| {
                StorageError::Postgres(sanitize_storage_error(&format!(
                    "failed to build async PostgreSQL pool: {error}"
                )))
            })?;
        Ok(Self {
            pool,
            acquire_timeout: Duration::from_millis(config.pool_acquire_timeout_millis),
            statement_timeout: Duration::from_millis(config.statement_timeout_millis),
            transaction_search_path_sql: (config.schema.is_some()
                || !config.search_path.is_empty())
            .then(|| {
                format!(
                    "SET LOCAL search_path TO {}",
                    postgres_search_path_sql(config)
                )
            }),
            configured_schema: config.schema.clone(),
            metrics: PostgresPoolMetrics::default(),
        })
    }

    pub(crate) async fn acquire(
        &self,
        operation: &'static str,
        caller_timeout: Duration,
    ) -> Result<Object, StorageError> {
        let timeout = self.acquire_timeout.min(caller_timeout);
        let started = Instant::now();
        let acquired = acquire_before_deadline(self.pool.get(), timeout).await;
        let waited = started.elapsed();
        match acquired {
            Ok(Ok(client)) => {
                self.metrics.record_acquire(waited, false);
                tracing::debug!(
                    operation,
                    wait_micros = u64::try_from(waited.as_micros()).unwrap_or(u64::MAX),
                    outcome = "acquired",
                    "acquired async PostgreSQL client"
                );
                Ok(client)
            }
            Ok(Err(error)) => {
                self.metrics.record_acquire(waited, false);
                Err(StorageError::Postgres(sanitize_storage_error(&format!(
                    "async PostgreSQL pool acquisition failed: {error}"
                ))))
            }
            Err(_) => {
                self.metrics.record_acquire(waited, true);
                tracing::warn!(
                    operation,
                    wait_micros = u64::try_from(waited.as_micros()).unwrap_or(u64::MAX),
                    outcome = "deadline",
                    "async PostgreSQL pool acquisition reached its deadline"
                );
                Err(StorageError::OperationDeadlineExceeded {
                    operation,
                    stage: "pool acquisition",
                    commit_started: false,
                })
            }
        }
    }

    pub(crate) fn metrics_snapshot(&self) -> PostgresPoolMetricsSnapshot {
        self.metrics.snapshot()
    }

    pub(crate) fn transaction_search_path_sql(&self) -> Option<&str> {
        self.transaction_search_path_sql.as_deref()
    }

    /// The `postgres_schema` this pool was configured with, if any. Schema DDL
    /// (`initialize_schema`) must create + target this schema, and schema
    /// validation must resolve tables against it, mirroring how every data
    /// query pins it via [`Self::transaction_search_path_sql`] (#237-#239).
    pub(crate) fn configured_schema(&self) -> Option<&str> {
        self.configured_schema.as_deref()
    }

    pub(crate) fn statement_timeout(&self) -> Duration {
        self.statement_timeout
    }

    #[cfg(test)]
    pub(crate) fn acquire_timeout(&self) -> Duration {
        self.acquire_timeout
    }
}
