// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-18
// description: Shared test support for the DSN-gated schema-routing tests
// (`replay_floor_test`, `usage_metadata_schema_test`, `control_plane_schema_test`).
// Makes the 9 live-Supabase tests HERMETIC and reliable as a group (#241):
//   * one process-wide multi-thread runtime so pooled connections are closed
//     gracefully instead of being abandoned when a per-op ephemeral runtime is
//     dropped (abandoned connections lingered on the shared live pooler and,
//     across the group, exhausted it -> pool-acquisition timeouts / silently
//     dropped writes that surfaced as "configured-schema count 0");
//   * a global mutex that serializes the DB-touching body so the parallel run
//     never opens a connection storm against the shared pooler;
//   * globally-unique schema names (process id + monotonic nonce) so no two
//     tests -- or two runs in one process -- ever collide or CASCADE-drop each
//     other's schema;
//   * an RAII teardown guard that drops the unique schema and clears the test's
//     rows from the shared `public` shadow tables on scope exit, INCLUDING panic
//     unwinding, so a failed assertion never leaks state into a sibling test.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use tokio::runtime::Runtime;

/// One process-wide multi-thread runtime shared by every schema-routing test.
/// Reusing a single long-lived runtime (rather than building an ephemeral
/// current-thread runtime per operation) keeps every `tokio-postgres`
/// connection driver on persistent worker threads, so pooled connections are
/// closed gracefully instead of being abandoned mid-flight when an ephemeral
/// runtime is dropped.
fn shared_runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("shared schema-routing test runtime")
    })
}

/// Run a future to completion on the shared runtime.
pub(crate) fn block_on<F: std::future::Future>(future: F) -> F::Output {
    shared_runtime().block_on(future)
}

/// Acquire the process-wide lock that serializes the DB-touching section of the
/// schema-routing tests. Under default (parallel) `cargo test`, this guarantees
/// only one test opens connections against the shared live pooler at a time,
/// eliminating the parallel connection storm. Poisoning (a prior test panicked
/// while holding the lock) is intentionally ignored so one failure does not
/// cascade into spurious failures of every sibling test.
pub(crate) fn serialize_db_test() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// Globally-unique schema name: `<prefix>_<pid>_<nonce>`. The process id keeps
/// concurrent `cargo test` processes apart; the monotonic nonce keeps every test
/// (and every call) within one process apart, so no schema is ever shared or
/// CASCADE-dropped out from under a sibling test.
pub(crate) fn unique_schema(prefix: &str) -> String {
    static NONCE: AtomicU64 = AtomicU64::new(0);
    format!(
        "{prefix}_{}_{}",
        std::process::id(),
        NONCE.fetch_add(1, Ordering::Relaxed)
    )
}

/// One process-wide admin connection, reused by EVERY setup / probe / teardown
/// query across all schema-routing tests. Opening a fresh throwaway connection
/// per call (the previous design) churned ~6-8 connections per test which, over
/// the 9-test group, saturated the shared live pooler's hard connection cap and
/// caused the group-only `pool acquisition` timeouts. A single long-lived
/// connection (its driver spawned on the persistent shared runtime) keeps the
/// group's out-of-band connection footprint at exactly one; the per-test product
/// pool under test is the only other connection source, and [`serialize_db_test`]
/// guarantees just one of those is open at a time.
///
/// The connection is `Sync` and every caller holds the DB serialization lock, so
/// sharing `&Client` is safe.
fn admin_client() -> &'static tokio_postgres::Client {
    static CLIENT: OnceLock<tokio_postgres::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let dsn = std::env::var("FERROGATE_TEST_POSTGRES_DSN")
            .expect("FERROGATE_TEST_POSTGRES_DSN must be set to use the shared admin connection");
        block_on(async move {
            let (client, connection) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
                .await
                .expect("connect the shared admin connection to the test postgres");
            // Keep the connection driver alive on the persistent shared runtime
            // for the whole process (intentionally detached / leaked).
            tokio::spawn(async move {
                let _ = connection.await;
            });
            client
        })
    })
}

/// Run a batch of setup/teardown SQL against the test DSN over the shared admin
/// connection. Panics on failure -- use only for setup the test depends on.
pub(crate) fn run_sql(_dsn: &str, sql: &str) {
    // Resolve (and lazily initialize) the client OUTSIDE `block_on`; its init
    // itself calls `block_on`, which must not be nested inside another.
    let client = admin_client();
    block_on(async {
        client
            .batch_execute(sql)
            .await
            .expect("execute test setup/teardown sql");
    })
}

/// Best-effort teardown SQL: never panics, so it is safe to run while unwinding
/// from a failed assertion (used by [`SchemaGuard`]).
fn run_sql_best_effort(sql: &str) {
    let client = admin_client();
    block_on(async {
        let _ = client.batch_execute(sql).await;
    })
}

/// Count rows matching `sql` (a `SELECT COUNT(*)::BIGINT ...`) over the shared
/// admin connection. Used to prove which physical schema a row landed in.
pub(crate) fn count_rows(_dsn: &str, sql: &str) -> i64 {
    let client = admin_client();
    block_on(async {
        client
            .query_one(sql, &[])
            .await
            .expect("count the control-plane probe rows")
            .get::<_, i64>(0)
    })
}

/// Read a single `BIGINT` column over the shared admin connection, or `None`
/// when no row matches. Used to prove which physical schema a row landed in.
pub(crate) fn query_i64(_dsn: &str, sql: &str) -> Option<i64> {
    let client = admin_client();
    block_on(async {
        client
            .query_opt(sql, &[])
            .await
            .expect("query the probe row")
            .map(|row| row.get::<_, i64>(0))
    })
}

/// RAII teardown for a schema-routing test. On scope exit -- including panic
/// unwinding from a failed assertion -- it drops the test's unique schema and
/// runs any extra teardown SQL (e.g. deleting the test's rows from the shared
/// `public` shadow tables), so no test ever leaks state into the shared live
/// database and poisons a sibling.
pub(crate) struct SchemaGuard {
    cleanup_sql: String,
}

impl SchemaGuard {
    /// Create a guard that will `DROP SCHEMA IF EXISTS "<schema>" CASCADE` on
    /// drop. Construct it as soon as the schema name is known (before
    /// provisioning) so even a mid-setup panic still cleans up. `_dsn` is kept
    /// for call-site symmetry; teardown runs over the shared admin connection.
    pub(crate) fn new(_dsn: &str, schema: &str) -> Self {
        Self {
            cleanup_sql: format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE;"),
        }
    }

    /// Append extra teardown SQL, run (best-effort) after the schema drop --
    /// typically `DELETE FROM public.<table> WHERE ...` for the shared shadow
    /// tables this test wrote a probe row into.
    pub(crate) fn also(mut self, sql: impl AsRef<str>) -> Self {
        self.cleanup_sql.push(' ');
        self.cleanup_sql.push_str(sql.as_ref());
        self
    }
}

impl Drop for SchemaGuard {
    fn drop(&mut self) {
        run_sql_best_effort(&self.cleanup_sql);
    }
}
