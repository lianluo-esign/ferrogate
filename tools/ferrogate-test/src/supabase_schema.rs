// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Isolated live Supabase schema leases for the FerroGate test harness.

use crate::cli::SupabaseLiveRestartArgs;
use anyhow::{bail, Context, Result};
use native_tls::{Certificate, TlsConnector};
use postgres_native_tls::MakeTlsConnector;
use std::{
    fs, process,
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::runtime::{Builder, Runtime};
use tokio_postgres::{
    config::SslMode, types::ToSql, Client, Config as PostgresConfig, Error, Row, ToStatement,
    Transaction,
};

static NEXT_SCHEMA_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug)]
pub(crate) enum LiveSupabaseScenario {
    Smoke,
    Restart,
    Token4ai,
    Guardrail,
    McpIdentity,
    Compliance,
    TargetCapability,
    AdminConsoleRoles,
    LifecycleTenancy,
}

impl LiveSupabaseScenario {
    fn slug(self) -> &'static str {
        match self {
            Self::Smoke => "smk",
            Self::Restart => "rst",
            Self::Token4ai => "t4ai",
            Self::Guardrail => "grd",
            Self::McpIdentity => "mcp",
            Self::Compliance => "cmp",
            Self::TargetCapability => "tgt",
            Self::AdminConsoleRoles => "role",
            Self::LifecycleTenancy => "life",
        }
    }
}

trait SchemaBackend {
    fn create_schema(&mut self, schema: &str) -> Result<()>;
    fn drop_schema(&mut self, schema: &str) -> Result<()>;
    fn schema_count(&mut self, schema: &str) -> Result<i64>;
}

struct PostgresSchemaBackend {
    args: SupabaseLiveRestartArgs,
}

impl SchemaBackend for PostgresSchemaBackend {
    fn create_schema(&mut self, schema: &str) -> Result<()> {
        connect_live_supabase(&self.args)?
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .with_context(|| format!("failed to create live Supabase schema {schema}"))
    }

    fn drop_schema(&mut self, schema: &str) -> Result<()> {
        connect_live_supabase(&self.args)?
            .batch_execute(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
            .with_context(|| format!("failed to drop live Supabase schema {schema}"))
    }

    fn schema_count(&mut self, schema: &str) -> Result<i64> {
        Ok(connect_live_supabase(&self.args)?
            .query_one(
                "SELECT count(*) FROM pg_namespace WHERE nspname = $1",
                &[&schema],
            )?
            .get(0))
    }
}

struct SchemaLease<B: SchemaBackend> {
    backend: B,
    schema: String,
    keep: bool,
    finished: bool,
}

impl<B: SchemaBackend> SchemaLease<B> {
    fn create(mut backend: B, schema: String, keep: bool) -> Result<Self> {
        validate_schema_name(&schema)?;
        backend.create_schema(&schema)?;
        if keep {
            eprintln!("retaining live Supabase test schema: {schema}");
        }
        Ok(Self {
            backend,
            schema,
            keep,
            finished: false,
        })
    }

    fn finish(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        if self.keep {
            self.finished = true;
            return Ok(());
        }
        self.backend.drop_schema(&self.schema)?;
        let remaining = self.backend.schema_count(&self.schema)?;
        if remaining != 0 {
            bail!(
                "live Supabase schema cleanup left {remaining} matching schema(s): {}",
                self.schema
            );
        }
        self.finished = true;
        Ok(())
    }
}

impl<B: SchemaBackend> Drop for SchemaLease<B> {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            eprintln!(
                "failed to clean live Supabase test schema {}: {error:#}",
                self.schema
            );
        }
    }
}

pub(crate) struct LiveSupabaseSchema {
    lease: SchemaLease<PostgresSchemaBackend>,
    run_id: String,
}

impl LiveSupabaseSchema {
    pub(crate) fn create(
        args: &SupabaseLiveRestartArgs,
        scenario: LiveSupabaseScenario,
    ) -> Result<Self> {
        let (schema, run_id) = unique_schema_name(scenario)?;
        let backend = PostgresSchemaBackend { args: args.clone() };
        let lease = SchemaLease::create(backend, schema, args.keep_supabase_schema)?;
        Ok(Self { lease, run_id })
    }

    pub(crate) fn name(&self) -> &str {
        &self.lease.schema
    }

    pub(crate) fn run_id(&self) -> &str {
        &self.run_id
    }

    pub(crate) fn finish(&mut self) -> Result<()> {
        self.lease.finish()
    }
}

/// A synchronous facade over an async `tokio_postgres` connection.
///
/// The FerroGate test harness runs on a plain synchronous `main` with no
/// ambient Tokio runtime, so each live Supabase connection owns a dedicated
/// current-thread runtime that drives both the connection task and every
/// statement to completion via `block_on`. This mirrors the async-bridge
/// precedent in `compliance.rs` while keeping every existing call site (which
/// expects the synchronous `postgres` crate `Client` API surface) unchanged as
/// the workspace standardizes on the async `tokio-postgres` driver.
pub(crate) struct LiveSupabaseClient {
    client: Client,
    runtime: Runtime,
}

impl LiveSupabaseClient {
    pub(crate) fn query<T>(
        &mut self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, Error>
    where
        T: ?Sized + ToStatement,
    {
        self.runtime.block_on(self.client.query(statement, params))
    }

    pub(crate) fn query_one<T>(
        &mut self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Row, Error>
    where
        T: ?Sized + ToStatement,
    {
        self.runtime
            .block_on(self.client.query_one(statement, params))
    }

    pub(crate) fn query_opt<T>(
        &mut self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, Error>
    where
        T: ?Sized + ToStatement,
    {
        self.runtime
            .block_on(self.client.query_opt(statement, params))
    }

    pub(crate) fn execute<T>(
        &mut self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, Error>
    where
        T: ?Sized + ToStatement,
    {
        self.runtime
            .block_on(self.client.execute(statement, params))
    }

    pub(crate) fn batch_execute(&mut self, query: &str) -> Result<(), Error> {
        self.runtime.block_on(self.client.batch_execute(query))
    }

    pub(crate) fn transaction(&mut self) -> Result<LiveTransaction<'_>, Error> {
        let runtime = &self.runtime;
        let transaction = runtime.block_on(self.client.transaction())?;
        Ok(LiveTransaction {
            transaction,
            runtime,
        })
    }
}

/// A synchronous facade over an async `tokio_postgres` transaction, driven by
/// the owning [`LiveSupabaseClient`]'s runtime.
pub(crate) struct LiveTransaction<'a> {
    transaction: Transaction<'a>,
    runtime: &'a Runtime,
}

impl LiveTransaction<'_> {
    pub(crate) fn query<T>(
        &mut self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, Error>
    where
        T: ?Sized + ToStatement,
    {
        self.runtime
            .block_on(self.transaction.query(statement, params))
    }

    pub(crate) fn query_one<T>(
        &mut self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Row, Error>
    where
        T: ?Sized + ToStatement,
    {
        self.runtime
            .block_on(self.transaction.query_one(statement, params))
    }

    pub(crate) fn execute<T>(
        &mut self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, Error>
    where
        T: ?Sized + ToStatement,
    {
        self.runtime
            .block_on(self.transaction.execute(statement, params))
    }

    pub(crate) fn batch_execute(&mut self, query: &str) -> Result<(), Error> {
        self.runtime.block_on(self.transaction.batch_execute(query))
    }

    pub(crate) fn commit(self) -> Result<(), Error> {
        let runtime = self.runtime;
        runtime.block_on(self.transaction.commit())
    }

    pub(crate) fn rollback(self) -> Result<(), Error> {
        let runtime = self.runtime;
        runtime.block_on(self.transaction.rollback())
    }
}

pub(crate) fn connect_live_supabase(args: &SupabaseLiveRestartArgs) -> Result<LiveSupabaseClient> {
    let dsn = args.supabase_dsn.trim();
    if dsn.is_empty() {
        bail!("--supabase-dsn must not be empty");
    }
    let mut config = PostgresConfig::from_str(dsn).context("failed to parse Supabase DSN")?;
    config.connect_timeout(Duration::from_secs(10));
    config.ssl_mode(SslMode::Require);

    let mut tls = TlsConnector::builder();
    if let Some(path) = args.tls_ca_cert_path.as_deref() {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read Supabase CA file {}", path.display()))?;
        let certificate = Certificate::from_pem(&bytes)
            .or_else(|_| Certificate::from_der(&bytes))
            .context("failed to parse Supabase CA certificate")?;
        tls.add_root_certificate(certificate);
    }
    match args.tls_mode.trim() {
        "verify_full" | "verify-full" => {}
        "verify_ca" | "verify-ca" => {
            tls.danger_accept_invalid_hostnames(true);
        }
        "require" => {
            tls.danger_accept_invalid_certs(true);
            tls.danger_accept_invalid_hostnames(true);
        }
        other => bail!(
            "--tls-mode must be require, verify_ca, or verify_full for live Supabase, got {other}"
        ),
    }
    let connector = MakeTlsConnector::new(
        tls.build()
            .context("failed to initialize Supabase TLS connector")?,
    );
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build live Supabase async runtime")?;
    let (client, connection) = runtime
        .block_on(config.connect(connector))
        .context("failed to connect to live Supabase PostgreSQL")?;
    runtime.spawn(async move {
        let _ = connection.await;
    });
    Ok(LiveSupabaseClient { client, runtime })
}

fn unique_schema_name(scenario: LiveSupabaseScenario) -> Result<(String, String)> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?;
    let counter = NEXT_SCHEMA_ID.fetch_add(1, Ordering::Relaxed) as u32;
    let run_id = format!(
        "{:x}_{:08x}_{:x}_{:08x}",
        elapsed.as_secs(),
        elapsed.subsec_nanos(),
        process::id(),
        counter
    );
    let schema = format!("ferrogate_test_{}_{}", scenario.slug(), run_id);
    validate_schema_name(&schema)?;
    Ok((schema, run_id))
}

fn validate_schema_name(schema: &str) -> Result<()> {
    if schema.is_empty()
        || schema.len() > 63
        || !schema.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
    {
        bail!("generated live Supabase schema name is invalid: {schema}");
    }
    Ok(())
}

#[cfg(test)]
#[path = "supabase_schema_test.rs"]
mod supabase_schema_test;
