// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use crate::{
    assertions::{assert_array_contains, assert_secret_redacted, list_contains},
    cli::{LocalArgs, SupabaseLiveRestartArgs, SupabaseLiveToken4aiProviderArgs},
    constants::{ADMIN_AUTH, CLIENT_AUTH, JSON_CONTENT},
    docker::{
        docker_args, MYSQL_CONTAINER, MYSQL_IMAGE, POSTGRES_CONTAINER, POSTGRES_IMAGE,
        POSTGRES_MIGRATION_SOURCE_CONTAINER, POSTGRES_MIGRATION_TARGET_CONTAINER,
    },
    fixtures::toml_basic_string,
    http::{free_addr, free_port, http_request_addr},
    mocks::spawn_local_provider_upstream,
};
use anyhow::{bail, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair,
};
use serde_json::Value;
use std::{
    env, fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(crate) fn run_supabase_restart(args: &LocalArgs) -> Result<()> {
    let host_port = free_port()?;
    let cert_dir = tempfile::tempdir()?;
    let certs = write_postgres_tls_certs(cert_dir.path())?;
    let _cleanup = PostgresCleanup;
    stop_postgres_container();
    let cert_mount = format!("{}:/ferrogate-postgres-tls:ro", cert_dir.path().display());
    docker_args([
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        POSTGRES_CONTAINER.to_string(),
        "-e".to_string(),
        "POSTGRES_PASSWORD=postgres".to_string(),
        "-e".to_string(),
        "POSTGRES_DB=ferrogate".to_string(),
        "-p".to_string(),
        format!("127.0.0.1:{host_port}:5432"),
        "-v".to_string(),
        cert_mount,
        "--entrypoint".to_string(),
        "sh".to_string(),
        POSTGRES_IMAGE.to_string(),
        "-c".to_string(),
        r#"set -eu
mkdir -p /var/lib/postgresql/tls
cp /ferrogate-postgres-tls/server.crt /var/lib/postgresql/tls/server.crt
cp /ferrogate-postgres-tls/server.key /var/lib/postgresql/tls/server.key
chown postgres:postgres /var/lib/postgresql/tls/server.crt /var/lib/postgresql/tls/server.key
chmod 600 /var/lib/postgresql/tls/server.key
exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/var/lib/postgresql/tls/server.crt -c ssl_key_file=/var/lib/postgresql/tls/server.key"#
            .to_string(),
    ])?;
    wait_for_postgres_server()?;
    let dsn =
        format!("host=127.0.0.1 port={host_port} user=postgres password=postgres dbname=ferrogate sslmode=require");
    wait_for_postgres_query()?;
    expect_supabase_validate_only_schema_failure(
        &args.ferrogate_bin,
        &dsn,
        PostgresRestartTls {
            mode: "verify_full",
            ca_cert_path: Some(certs.ca_cert_path.as_path()),
        },
    )?;
    run_control_plane_supabase_restart(
        &args.ferrogate_bin,
        &dsn,
        PostgresRestartTls {
            mode: "verify_full",
            ca_cert_path: Some(certs.ca_cert_path.as_path()),
        },
        "ferrogate-supabase-test",
        true,
    )?;
    expect_supabase_schema_migrations("ferrogate_control")?;
    println!("supabase-restart scenario passed");
    Ok(())
}

fn expect_supabase_validate_only_schema_failure(
    ferrogate_bin: &Path,
    supabase_dsn: &str,
    tls: PostgresRestartTls<'_>,
) -> Result<()> {
    let storage = ControlPlaneRestartStorage::Supabase {
        dsn: supabase_dsn,
        tls,
    };
    let gateway_addr = free_addr()?;
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("ferrogate-validate-only.yaml");
    std::fs::write(
        &config_path,
        storage.restart_config(
            &gateway_addr,
            false,
            false,
            StorageMigrationMode::ValidateOnly,
            None,
        ),
    )?;

    let mut gateway = Command::new(ferrogate_bin);
    gateway
        .args(["run", "--config"])
        .arg(&config_path)
        .env("FERROGATE_PROVIDER_SECRET", "provider-secret")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    storage.apply_env(&mut gateway);
    let mut gateway = gateway
        .spawn()
        .with_context(|| format!("failed to start {}", ferrogate_bin.display()))?;

    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(20) {
        if let Some(status) = gateway.try_wait()? {
            if status.success() {
                bail!("validate-only Supabase startup unexpectedly succeeded without schema");
            }
            let mut stderr = String::new();
            if let Some(mut pipe) = gateway.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            assert_secret_redacted(&stderr);
            if !stderr.contains("required schema table control_plane_resources is missing") {
                bail!("validate-only Supabase startup failed with unexpected stderr: {stderr}");
            }
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }

    let _ = gateway.kill();
    bail!("validate-only Supabase startup did not fail before readiness timeout");
}

pub(crate) fn run_supabase_live_restart(args: &SupabaseLiveRestartArgs) -> Result<()> {
    let dsn = args.supabase_dsn.trim();
    if dsn.is_empty() {
        bail!("--supabase-dsn must not be empty");
    }
    run_control_plane_supabase_restart(
        &args.local.ferrogate_bin,
        dsn,
        PostgresRestartTls {
            mode: supabase_live_tls_mode(&args.tls_mode)?,
            ca_cert_path: args.tls_ca_cert_path.as_deref(),
        },
        "ferrogate-supabase-live-test",
        false,
    )?;
    println!("supabase-live-restart scenario passed");
    Ok(())
}

pub(crate) fn run_supabase_live_smoke(args: &SupabaseLiveRestartArgs) -> Result<()> {
    let dsn = args.supabase_dsn.trim();
    if dsn.is_empty() {
        bail!("--supabase-dsn must not be empty");
    }
    let tls = PostgresRestartTls {
        mode: supabase_live_tls_mode(&args.tls_mode)?,
        ca_cert_path: args.tls_ca_cert_path.as_deref(),
    };
    let resource_id = format!(
        "ferrogate-supabase-live-smoke-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before UNIX epoch")?
            .as_millis()
    );
    let api_key_body = serde_json::json!({
        "id": resource_id,
        "name": "Supabase live smoke key",
        "key": format!("{resource_id}-secret"),
        "scopes": ["models.read"],
        "allowed_models": ["fast-chat"],
        "organization_id": "org_supabase_live",
        "project_id": "project_smoke"
    })
    .to_string();
    let storage = ControlPlaneRestartStorage::Supabase { dsn, tls };

    {
        let case = TursoRestartHarness::start(&args.local.ferrogate_bin, storage, false, false)?;
        case.expect_storage_status()?;
        case.expect_json(
            "POST",
            "/admin/v1/api-keys",
            &[ADMIN_AUTH, JSON_CONTENT],
            &api_key_body,
            201,
            |body| {
                assert_eq!(body["key"]["id"], resource_id);
                assert_eq!(body["key"]["key_source"], "inline");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        case.expect_api_key_named(&resource_id, "Supabase live smoke key")?;
    }

    {
        let case = TursoRestartHarness::start_with_migration_mode(
            &args.local.ferrogate_bin,
            storage,
            false,
            false,
            StorageMigrationMode::ValidateOnly,
            None,
        )?;
        case.expect_storage_status()?;
        case.expect_api_key_named(&resource_id, "Supabase live smoke key")?;
        case.expect_json(
            "DELETE",
            &format!("/admin/v1/api-keys/{resource_id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["deleted"], true);
                Ok(())
            },
        )?;
    }

    println!("supabase-live-smoke scenario passed");
    Ok(())
}

pub(crate) fn run_supabase_live_token4ai_provider(
    args: &SupabaseLiveToken4aiProviderArgs,
) -> Result<()> {
    let dsn = args.supabase.supabase_dsn.trim();
    if dsn.is_empty() {
        bail!("--supabase-dsn must not be empty");
    }
    let provider_api_key = args.provider_api_key.trim();
    if provider_api_key.is_empty() {
        bail!("--provider-api-key must not be empty");
    }
    let provider_base_url = args.provider_base_url.trim();
    if provider_base_url.is_empty() {
        bail!("--provider-base-url must not be empty");
    }
    let provider_model = args.provider_model.trim();
    if provider_model.is_empty() {
        bail!("--provider-model must not be empty");
    }

    let tls = PostgresRestartTls {
        mode: supabase_live_tls_mode(&args.supabase.tls_mode)?,
        ca_cert_path: args.supabase.tls_ca_cert_path.as_deref(),
    };
    let resource_id = format!(
        "ferrogate-token4ai-live-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before UNIX epoch")?
            .as_millis()
    );
    let storage = ControlPlaneRestartStorage::Supabase { dsn, tls };

    {
        let case = TursoRestartHarness::start_live_token4ai_provider(
            &args.supabase.local.ferrogate_bin,
            storage,
            provider_base_url,
            provider_model,
            provider_api_key,
        )?;
        case.expect_storage_status()?;
        case.expect_live_token4ai_completion(&resource_id, provider_model)?;
        case.expect_live_token4ai_metering_usage(&resource_id, provider_model)?;
    }

    {
        let case = TursoRestartHarness::start_live_token4ai_provider_with_migration_mode(
            &args.supabase.local.ferrogate_bin,
            storage,
            provider_base_url,
            provider_model,
            provider_api_key,
            StorageMigrationMode::ValidateOnly,
        )?;
        case.expect_storage_status()?;
        case.expect_live_token4ai_metering_usage(&resource_id, provider_model)?;
    }

    println!("supabase-live-token4ai-provider scenario passed");
    Ok(())
}

pub(crate) fn run_supabase_migration(args: &LocalArgs) -> Result<()> {
    let source_port = free_port()?;
    let target_port = free_port()?;
    let source_cert_dir = tempfile::tempdir()?;
    let target_cert_dir = tempfile::tempdir()?;
    write_postgres_tls_certs(source_cert_dir.path())?;
    write_postgres_tls_certs(target_cert_dir.path())?;
    let _cleanup = PostgresMigrationCleanup;
    stop_postgres_container_named(POSTGRES_MIGRATION_SOURCE_CONTAINER);
    stop_postgres_container_named(POSTGRES_MIGRATION_TARGET_CONTAINER);
    start_postgres_tls_container(
        POSTGRES_MIGRATION_SOURCE_CONTAINER,
        source_port,
        source_cert_dir.path(),
    )?;
    start_postgres_tls_container(
        POSTGRES_MIGRATION_TARGET_CONTAINER,
        target_port,
        target_cert_dir.path(),
    )?;
    wait_for_postgres_server_named(POSTGRES_MIGRATION_SOURCE_CONTAINER)?;
    wait_for_postgres_server_named(POSTGRES_MIGRATION_TARGET_CONTAINER)?;
    wait_for_postgres_query_named(POSTGRES_MIGRATION_SOURCE_CONTAINER)?;
    wait_for_postgres_query_named(POSTGRES_MIGRATION_TARGET_CONTAINER)?;

    let source_dsn =
        format!("host=127.0.0.1 port={source_port} user=postgres password=postgres dbname=ferrogate sslmode=require");
    let target_dsn =
        format!("host=127.0.0.1 port={target_port} user=postgres password=postgres dbname=ferrogate sslmode=require");
    let resource_id = format!(
        "ferrogate-migration-test-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before UNIX epoch")?
            .as_millis()
    );
    let api_key_body = serde_json::json!({
        "id": resource_id,
        "name": "Supabase migration test key",
        "key": format!("{resource_id}-secret"),
        "scopes": ["models.read"],
        "allowed_models": ["fast-chat"],
        "organization_id": "org_migration",
        "project_id": "project_migration"
    })
    .to_string();

    {
        let source = TursoRestartHarness::start(
            &args.ferrogate_bin,
            ControlPlaneRestartStorage::Postgres {
                dsn: &source_dsn,
                tls: PostgresRestartTls {
                    mode: "require",
                    ca_cert_path: None,
                },
            },
            false,
            true,
        )?;
        source.expect_storage_status()?;
        source.expect_json(
            "POST",
            "/admin/v1/api-keys",
            &[ADMIN_AUTH, JSON_CONTENT],
            &api_key_body,
            201,
            |body| {
                assert_eq!(body["key"]["id"], resource_id);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        source.expect_api_key_named(&resource_id, "Supabase migration test key")?;
    }

    let dry_run = Command::new(&args.ferrogate_bin)
        .args([
            "storage",
            "migrate-to-supabase",
            "--source-provider",
            "postgres",
            "--source-postgres-dsn-env",
            "FERROGATE_TEST_SOURCE_DSN",
            "--target-supabase-dsn-env",
            "FERROGATE_TEST_TARGET_DSN",
            "--postgres-schema",
            "ferrogate_control",
            "--postgres-tls-mode",
            "require",
            "--dry-run",
        ])
        .env("FERROGATE_TEST_SOURCE_DSN", &source_dsn)
        .env("FERROGATE_TEST_TARGET_DSN", &target_dsn)
        .output()
        .context("run storage migration dry-run")?;
    assert!(
        dry_run.status.success(),
        "dry-run stderr: {}",
        String::from_utf8_lossy(&dry_run.stderr)
    );
    let dry_run_stdout = String::from_utf8_lossy(&dry_run.stdout);
    assert!(dry_run_stdout.contains("FerroGate storage migration dry-run"));
    assert!(dry_run_stdout.contains("target=supabase"));
    assert!(dry_run_stdout.contains("api_keys=2"));
    assert!(!dry_run_stdout.contains("password=postgres"));
    assert!(!String::from_utf8_lossy(&dry_run.stderr).contains("password=postgres"));

    let execute = Command::new(&args.ferrogate_bin)
        .args([
            "storage",
            "migrate-to-supabase",
            "--source-provider",
            "postgres",
            "--source-postgres-dsn-env",
            "FERROGATE_TEST_SOURCE_DSN",
            "--target-supabase-dsn-env",
            "FERROGATE_TEST_TARGET_DSN",
            "--postgres-schema",
            "ferrogate_control",
            "--postgres-tls-mode",
            "require",
            "--execute",
        ])
        .env("FERROGATE_TEST_SOURCE_DSN", &source_dsn)
        .env("FERROGATE_TEST_TARGET_DSN", &target_dsn)
        .output()
        .context("run storage migration execute")?;
    assert!(
        execute.status.success(),
        "execute stderr: {}",
        String::from_utf8_lossy(&execute.stderr)
    );
    let execute_stdout = String::from_utf8_lossy(&execute.stdout);
    assert!(execute_stdout.contains("FerroGate storage migration executed"));
    assert!(execute_stdout.contains("api_keys=2"));
    assert!(!execute_stdout.contains("password=postgres"));
    assert!(!String::from_utf8_lossy(&execute.stderr).contains("password=postgres"));

    {
        let target = TursoRestartHarness::start_with_migration_mode(
            &args.ferrogate_bin,
            ControlPlaneRestartStorage::Supabase {
                dsn: &target_dsn,
                tls: PostgresRestartTls {
                    mode: "require",
                    ca_cert_path: None,
                },
            },
            false,
            false,
            StorageMigrationMode::ValidateOnly,
            None,
        )?;
        target.expect_storage_status()?;
        target.expect_api_key_named(&resource_id, "Supabase migration test key")?;
    }

    println!("supabase-migration scenario passed");
    Ok(())
}

fn supabase_live_tls_mode(mode: &str) -> Result<&'static str> {
    match mode.trim() {
        "require" => Ok("require"),
        "verify_ca" | "verify-ca" => Ok("verify_ca"),
        "verify_full" | "verify-full" => Ok("verify_full"),
        other => bail!(
            "--tls-mode must be require, verify_ca, or verify_full for live Supabase, got {other}"
        ),
    }
}

pub(crate) fn run_postgres_restart(args: &LocalArgs) -> Result<()> {
    let host_port = free_port()?;
    let _cleanup = PostgresCleanup;
    stop_postgres_container();
    start_postgres_container(POSTGRES_CONTAINER, host_port)?;
    wait_for_postgres_server()?;
    let dsn =
        format!("host=127.0.0.1 port={host_port} user=postgres password=postgres dbname=ferrogate sslmode=disable");
    wait_for_postgres_query()?;
    run_control_plane_postgres_restart(
        &args.ferrogate_bin,
        &dsn,
        PostgresRestartTls {
            mode: "disable",
            ca_cert_path: None,
        },
        "ferrogate-postgres-test",
        true,
    )?;
    println!("postgres-restart scenario passed");
    Ok(())
}

fn start_postgres_container(name: &str, host_port: u16) -> Result<()> {
    docker_args([
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        name.to_string(),
        "-e".to_string(),
        "POSTGRES_PASSWORD=postgres".to_string(),
        "-e".to_string(),
        "POSTGRES_DB=ferrogate".to_string(),
        "-p".to_string(),
        format!("127.0.0.1:{host_port}:5432"),
        POSTGRES_IMAGE.to_string(),
    ])
}

fn start_postgres_tls_container(name: &str, host_port: u16, cert_dir: &Path) -> Result<()> {
    let cert_mount = format!("{}:/ferrogate-postgres-tls:ro", cert_dir.display());
    docker_args([
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        name.to_string(),
        "-e".to_string(),
        "POSTGRES_PASSWORD=postgres".to_string(),
        "-e".to_string(),
        "POSTGRES_DB=ferrogate".to_string(),
        "-p".to_string(),
        format!("127.0.0.1:{host_port}:5432"),
        "-v".to_string(),
        cert_mount,
        "--entrypoint".to_string(),
        "sh".to_string(),
        POSTGRES_IMAGE.to_string(),
        "-c".to_string(),
        r#"set -eu
mkdir -p /var/lib/postgresql/tls
cp /ferrogate-postgres-tls/server.crt /var/lib/postgresql/tls/server.crt
cp /ferrogate-postgres-tls/server.key /var/lib/postgresql/tls/server.key
chown postgres:postgres /var/lib/postgresql/tls/server.crt /var/lib/postgresql/tls/server.key
chmod 600 /var/lib/postgresql/tls/server.key
exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/var/lib/postgresql/tls/server.crt -c ssl_key_file=/var/lib/postgresql/tls/server.key"#
            .to_string(),
    ])
}

pub(crate) fn run_postgres_tls_restart(args: &LocalArgs) -> Result<()> {
    let host_port = free_port()?;
    let cert_dir = tempfile::tempdir()?;
    let certs = write_postgres_tls_certs(cert_dir.path())?;
    let _cleanup = PostgresCleanup;
    stop_postgres_container();
    let cert_mount = format!("{}:/ferrogate-postgres-tls:ro", cert_dir.path().display());
    docker_args([
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        POSTGRES_CONTAINER.to_string(),
        "-e".to_string(),
        "POSTGRES_PASSWORD=postgres".to_string(),
        "-e".to_string(),
        "POSTGRES_DB=ferrogate".to_string(),
        "-p".to_string(),
        format!("127.0.0.1:{host_port}:5432"),
        "-v".to_string(),
        cert_mount,
        "--entrypoint".to_string(),
        "sh".to_string(),
        POSTGRES_IMAGE.to_string(),
        "-c".to_string(),
        r#"set -eu
mkdir -p /var/lib/postgresql/tls
cp /ferrogate-postgres-tls/server.crt /var/lib/postgresql/tls/server.crt
cp /ferrogate-postgres-tls/server.key /var/lib/postgresql/tls/server.key
chown postgres:postgres /var/lib/postgresql/tls/server.crt /var/lib/postgresql/tls/server.key
chmod 600 /var/lib/postgresql/tls/server.key
exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/var/lib/postgresql/tls/server.crt -c ssl_key_file=/var/lib/postgresql/tls/server.key"#
            .to_string(),
    ])?;
    wait_for_postgres_server()?;
    let dsn =
        format!("host=127.0.0.1 port={host_port} user=postgres password=postgres dbname=ferrogate sslmode=require");
    wait_for_postgres_query()?;
    run_control_plane_postgres_restart(
        &args.ferrogate_bin,
        &dsn,
        PostgresRestartTls {
            mode: "verify_full",
            ca_cert_path: Some(certs.ca_cert_path.as_path()),
        },
        "ferrogate-postgres-tls-test",
        true,
    )?;
    println!("postgres-tls-restart scenario passed");
    Ok(())
}

pub(crate) fn run_mysql_restart(args: &LocalArgs) -> Result<()> {
    let host_port = free_port()?;
    let _cleanup = MySqlCleanup;
    start_mysql_container(host_port)?;
    let dsn = format!("mysql://root:mysql@127.0.0.1:{host_port}/ferrogate?prefer_socket=false");
    run_control_plane_mysql_restart(
        &args.ferrogate_bin,
        &dsn,
        MySqlRestartTls {
            mode: "disable",
            ca_cert_path: None,
        },
        "ferrogate-mysql-test",
        true,
    )?;
    println!("mysql-restart scenario passed");
    Ok(())
}

pub(crate) fn run_mysql_tls_restart(args: &LocalArgs) -> Result<()> {
    let host_port = free_port()?;
    let ca_dir = tempfile::tempdir()?;
    let ca_cert_path = ca_dir.path().join("mysql-ca.pem");
    let _cleanup = MySqlCleanup;
    start_mysql_container(host_port)?;
    docker_args([
        "cp".to_string(),
        format!("{MYSQL_CONTAINER}:/var/lib/mysql/ca.pem"),
        ca_cert_path.display().to_string(),
    ])?;
    let dsn = format!("mysql://root:mysql@127.0.0.1:{host_port}/ferrogate?prefer_socket=false");
    run_control_plane_mysql_restart(
        &args.ferrogate_bin,
        &dsn,
        MySqlRestartTls {
            mode: "verify_ca",
            ca_cert_path: Some(ca_cert_path.as_path()),
        },
        "ferrogate-mysql-tls-test",
        true,
    )?;
    println!("mysql-tls-restart scenario passed");
    Ok(())
}

fn start_mysql_container(host_port: u16) -> Result<()> {
    stop_mysql_container();
    docker_args([
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        MYSQL_CONTAINER.to_string(),
        "-e".to_string(),
        "MYSQL_ROOT_PASSWORD=mysql".to_string(),
        "-e".to_string(),
        "MYSQL_DATABASE=ferrogate".to_string(),
        "-p".to_string(),
        format!("127.0.0.1:{host_port}:3306"),
        MYSQL_IMAGE.to_string(),
    ])?;
    wait_for_mysql_server()
}

struct PostgresTlsFiles {
    ca_cert_path: PathBuf,
}

fn write_postgres_tls_certs(dir: &Path) -> Result<PostgresTlsFiles> {
    let ca_key = KeyPair::generate().context("failed to generate PostgreSQL test CA key")?;
    let mut ca_params = CertificateParams::new(vec!["ferrogate-postgres-test-ca".to_string()])
        .context("failed to build PostgreSQL test CA params")?;
    let mut ca_name = DistinguishedName::new();
    ca_name.push(DnType::CommonName, "ferrogate-postgres-test-ca");
    ca_params.distinguished_name = ca_name;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key)
        .context("failed to self-sign PostgreSQL test CA")?;

    let server_key =
        KeyPair::generate().context("failed to generate PostgreSQL test server key")?;
    let server_params = CertificateParams::new(vec!["127.0.0.1".to_string()])
        .context("failed to build PostgreSQL test server params")?;
    let mut server_params = server_params;
    let mut server_name = DistinguishedName::new();
    server_name.push(DnType::CommonName, "127.0.0.1");
    server_params.distinguished_name = server_name;
    let server_cert = server_params
        .signed_by(&server_key, &ca)
        .context("failed to sign PostgreSQL test server certificate")?;

    let ca_cert_path = dir.join("ca.crt");
    fs::write(&ca_cert_path, ca.pem()).context("failed to write PostgreSQL test CA cert")?;
    fs::write(dir.join("server.crt"), server_cert.pem())
        .context("failed to write PostgreSQL test server cert")?;
    fs::write(dir.join("server.key"), server_key.serialize_pem())
        .context("failed to write PostgreSQL test server key")?;

    Ok(PostgresTlsFiles { ca_cert_path })
}

fn run_control_plane_postgres_restart(
    ferrogate_bin: &Path,
    postgres_dsn: &str,
    tls: PostgresRestartTls<'_>,
    resource_prefix: &str,
    verify_deleted_after_restart: bool,
) -> Result<()> {
    run_control_plane_restart(
        ferrogate_bin,
        ControlPlaneRestartStorage::Postgres {
            dsn: postgres_dsn,
            tls,
        },
        resource_prefix,
        verify_deleted_after_restart,
    )
}

fn run_control_plane_supabase_restart(
    ferrogate_bin: &Path,
    supabase_dsn: &str,
    tls: PostgresRestartTls<'_>,
    resource_prefix: &str,
    verify_deleted_after_restart: bool,
) -> Result<()> {
    run_control_plane_restart(
        ferrogate_bin,
        ControlPlaneRestartStorage::Supabase {
            dsn: supabase_dsn,
            tls,
        },
        resource_prefix,
        verify_deleted_after_restart,
    )
}

fn run_control_plane_mysql_restart(
    ferrogate_bin: &Path,
    mysql_dsn: &str,
    tls: MySqlRestartTls<'_>,
    resource_prefix: &str,
    verify_deleted_after_restart: bool,
) -> Result<()> {
    run_control_plane_restart(
        ferrogate_bin,
        ControlPlaneRestartStorage::Mysql {
            dsn: mysql_dsn,
            tls,
        },
        resource_prefix,
        verify_deleted_after_restart,
    )
}

fn run_control_plane_restart(
    ferrogate_bin: &Path,
    storage: ControlPlaneRestartStorage<'_>,
    resource_prefix: &str,
    verify_deleted_after_restart: bool,
) -> Result<()> {
    let resource_id = format!(
        "{resource_prefix}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before UNIX epoch")?
            .as_millis()
    );
    let api_key_body = serde_json::json!({
        "id": resource_id,
        "name": "Durable storage restart test key",
        "key": format!("{resource_id}-secret"),
        "scopes": ["models.read", "chat.completions", "prompts.render"],
        "allowed_models": ["fast-chat"],
        "organization_id": "org_storage_e2e",
        "project_id": "project_restart"
    })
    .to_string();
    let gateway_config_id = format!("{resource_id}-profile");
    let gateway_config_body = serde_json::json!({
        "id": gateway_config_id,
        "name": "Durable storage restart profile",
        "revision": 7,
        "api_key_ids": [resource_id],
        "cache_enabled": false
    })
    .to_string();
    let policy_name = format!("{resource_id}-policy");
    let policy_body = |enabled: bool| {
        serde_json::json!({
            "name": policy_name,
            "effect": "deny",
            "api_key_ids": [resource_id],
            "models": ["fast-chat"],
            "providers": ["openai"],
            "code": "blocked_by_storage_restart_test",
            "message": "blocked by durable storage restart test",
            "enabled": enabled
        })
        .to_string()
    };
    let disabled_policy_body = policy_body(false);
    let enabled_policy_body = policy_body(true);
    let prompt_template_id = format!("{resource_id}-prompt");
    let prompt_template_body = serde_json::json!({
        "id": prompt_template_id,
        "name": "Durable storage restart prompt",
        "model": "fast-chat",
        "variables": [{"name": "topic", "required": true}],
        "version": {
            "messages": [{"role": "user", "content": "Summarize {{topic}}"}],
            "temperature": 0.1
        }
    })
    .to_string();
    let agent_upstream_id = format!("{resource_id}-agent-upstream");
    let agent_upstream_body = serde_json::json!({
        "id": agent_upstream_id,
        "name": "Durable storage restart agent upstream",
        "description": "Durable upstream",
        "enabled": true,
        "protocol": "a2a",
        "endpoint": "https://agent.example.com/a2a",
        "tenant_ids": [resource_id],
        "capabilities": ["invoke", "read", "stream", "discover"]
    })
    .to_string();

    let approval_id;
    let mcp_server_name = format!(
        "dbhttp{}",
        resource_id
            .chars()
            .filter(char::is_ascii_digit)
            .collect::<String>()
    );
    {
        let case = TursoRestartHarness::start(ferrogate_bin, storage, false, true)?;
        case.expect_storage_status()?;
        case.register_echo_plugin()?;
        case.expect_plugin("tool.echo")?;
        approval_id = case.create_expired_echo_approval()?;
        case.register_echo_plugin()?;
        case.expect_echo_tool()?;
        case.register_mcp_server(&mcp_server_name)?;
        case.expect_mcp_server(&mcp_server_name)?;
        case.expect_json(
            "POST",
            "/admin/v1/api-keys",
            &[ADMIN_AUTH, JSON_CONTENT],
            &api_key_body,
            201,
            |body| {
                assert_eq!(body["key"]["id"], resource_id);
                assert_eq!(body["key"]["key_source"], "inline");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        case.expect_api_key(&resource_id)?;
        case.expect_json(
            "POST",
            "/admin/v1/gateway-configs",
            &[ADMIN_AUTH, JSON_CONTENT],
            &gateway_config_body,
            201,
            |body| {
                assert_eq!(body["gateway_config"]["id"], gateway_config_id);
                assert_eq!(body["gateway_config"]["revision"], 7);
                assert_eq!(body["gateway_config"]["cache_enabled"], false);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        case.expect_gateway_config(&gateway_config_id)?;
        case.expect_json(
            "POST",
            "/admin/v1/policies",
            &[ADMIN_AUTH, JSON_CONTENT],
            &disabled_policy_body,
            201,
            |body| {
                assert_eq!(body["policy"]["name"], policy_name);
                assert_eq!(body["policy"]["enabled"], false);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        case.expect_policy(&policy_name)?;
        case.expect_json(
            "POST",
            "/admin/v1/prompt-templates",
            &[ADMIN_AUTH, JSON_CONTENT],
            &prompt_template_body,
            201,
            |body| {
                assert_eq!(body["prompt_template"]["id"], prompt_template_id);
                assert_eq!(body["prompt_template"]["active_revision"], 1);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        case.expect_prompt_template(&prompt_template_id, "active")?;
        case.expect_json(
            "POST",
            "/admin/v1/agent-upstreams",
            &[ADMIN_AUTH, JSON_CONTENT],
            &agent_upstream_body,
            201,
            |body| {
                assert_eq!(body["agent_upstream"]["id"], agent_upstream_id);
                assert_eq!(body["agent_upstream"]["protocol"], "a2a");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        case.expect_agent_upstream(&agent_upstream_id, true)?;
    }

    {
        let provider_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (provider_addr, provider) =
            spawn_local_provider_upstream(1, provider_stop).context("start durable metering provider")?;
        let provider_base_url = format!("http://{provider_addr}/v1");
        let case = TursoRestartHarness::start_with_migration_mode(
            ferrogate_bin,
            storage,
            false,
            false,
            StorageMigrationMode::ValidateOnly,
            Some(&provider_base_url),
        )?;
        case.expect_storage_status()?;
        case.expect_plugin("tool.echo")?;
        case.expect_mcp_server(&mcp_server_name)?;
        case.expect_echo_tool()?;
        case.expect_tool_approval(&approval_id, "expired")?;
        case.expect_api_key(&resource_id)?;
        case.expect_gateway_config(&gateway_config_id)?;
        case.expect_policy(&policy_name)?;
        case.expect_prompt_template(&prompt_template_id, "active")?;
        case.expect_agent_upstream(&agent_upstream_id, true)?;
        case.expect_restored_prompt_template_render(&resource_id, &prompt_template_id)?;
        case.expect_restored_api_key_models_access(&resource_id)?;
        case.expect_metered_chat_completion(&resource_id, &gateway_config_id)?;
        let provider_requests = provider.join().unwrap_or_default();
        if !provider_requests
            .iter()
            .any(|request| request.contains("POST /v1/chat/completions "))
        {
            bail!("durable metering provider did not receive chat completion request");
        }
        if storage.supports_durable_metering() {
            case.expect_durable_metering_usage(&resource_id, 2)?;
            case.expect_durable_request_and_audit_evidence(&resource_id)?;
        }
        case.expect_json(
            "PATCH",
            &format!("/admin/v1/policies/{policy_name}"),
            &[ADMIN_AUTH, JSON_CONTENT],
            &enabled_policy_body,
            200,
            |body| {
                assert_eq!(body["policy"]["name"], policy_name);
                assert_eq!(body["policy"]["enabled"], true);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        case.expect_restored_policy_denies_chat(&resource_id)?;
        case.delete_mcp_server(&mcp_server_name)?;
        case.expect_json(
            "DELETE",
            &format!("/admin/v1/gateway-configs/{gateway_config_id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["deleted"], true);
                Ok(())
            },
        )?;
        case.expect_json(
            "DELETE",
            &format!("/admin/v1/policies/{policy_name}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["deleted"], true);
                Ok(())
            },
        )?;
        case.expect_json(
            "DELETE",
            &format!("/admin/v1/api-keys/{resource_id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["deleted"], true);
                Ok(())
            },
        )?;
        case.expect_json(
            "DELETE",
            &format!("/admin/v1/prompt-templates/{prompt_template_id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["deleted"], false);
                Ok(())
            },
        )?;
        case.expect_json(
            "DELETE",
            &format!("/admin/v1/agent-upstreams/{agent_upstream_id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["deleted"], true);
                Ok(())
            },
        )?;
    }

    {
        let case = TursoRestartHarness::start_with_migration_mode(
            ferrogate_bin,
            storage,
            false,
            false,
            StorageMigrationMode::ValidateOnly,
            None,
        )?;
        case.expect_storage_status()?;
        case.expect_plugin("tool.echo")?;
        case.expect_missing_mcp_server(&mcp_server_name)?;
        case.expect_tool_approval(&approval_id, "expired")?;
        if verify_deleted_after_restart {
            case.expect_missing_api_key(&resource_id)?;
            case.expect_missing_gateway_config(&gateway_config_id)?;
            case.expect_missing_policy(&policy_name)?;
        }
        if storage.supports_durable_metering() {
            case.expect_durable_metering_usage(&resource_id, 2)?;
            case.expect_durable_request_and_audit_evidence(&resource_id)?;
        }
        case.expect_prompt_template(&prompt_template_id, "archived")?;
        case.expect_missing_agent_upstream(&agent_upstream_id)?;
    }

    Ok(())
}

fn wait_for_postgres_server() -> Result<()> {
    wait_for_postgres_server_named(POSTGRES_CONTAINER)
}

fn wait_for_postgres_server_named(container_name: &str) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(30) {
        if Command::new("docker")
            .args([
                "exec",
                container_name,
                "pg_isready",
                "-U",
                "postgres",
                "-d",
                "ferrogate",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(500));
    }
    let logs = Command::new("docker")
        .args(["logs", container_name, "--tail", "120"])
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stderr).to_string())
        .unwrap_or_default();
    bail!("timed out waiting for local PostgreSQL server; logs: {logs}");
}

fn wait_for_postgres_query() -> Result<()> {
    wait_for_postgres_query_named(POSTGRES_CONTAINER)
}

fn wait_for_postgres_query_named(container_name: &str) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(30) {
        if Command::new("docker")
            .args([
                "exec",
                "-e",
                "PGPASSWORD=postgres",
                container_name,
                "psql",
                "-U",
                "postgres",
                "-d",
                "ferrogate",
                "-c",
                "select 1",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(500));
    }
    let logs = Command::new("docker")
        .args(["logs", container_name, "--tail", "120"])
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stderr).to_string())
        .unwrap_or_default();
    bail!("timed out waiting for local PostgreSQL query readiness; logs: {logs}");
}

fn expect_supabase_schema_migrations(schema: &str) -> Result<()> {
    let expected_tables = [
        "control_plane_resources",
        "agent_runs",
        "agent_run_events",
        "managed_worker_templates",
        "agent_worker_instances",
        "managed_worker_sessions",
        "managed_worker_lifecycle_events",
        "managed_worker_isolation_selections",
        "managed_worker_isolation_policies",
        "managed_worker_isolation_evidence",
        "self_hosted_worker_registrations",
        "self_hosted_worker_heartbeats",
        "self_hosted_worker_telemetry_events",
        "self_hosted_worker_artifacts",
        "self_hosted_worker_checkpoints",
        "self_hosted_run_dispatches",
        "self_hosted_run_dispatch_capabilities",
        "request_logs",
        "audit_events",
        "billing_metering_events",
        "usage_aggregates",
        "tenant_contexts",
        "metering_events",
        "metering_event_routes",
        "metering_event_usage",
        "usage_aggregate_rollups",
        "billing_ledger",
        "billing_report_outbox",
        "storage_schema_migrations",
    ];
    for table in expected_tables {
        let count = postgres_scalar(&format!(
            "SELECT count(*) FROM information_schema.tables \
             WHERE table_schema = '{}' AND table_name = '{}'",
            sql_literal(schema),
            sql_literal(table)
        ))?;
        if count.trim() != "1" {
            bail!("expected Supabase schema table {schema}.{table}, got count {count}");
        }
    }

    let jsonb_columns = [
        ("control_plane_resources", "document_json"),
        ("agent_runs", "run_json"),
        ("agent_run_events", "event_json"),
        ("agent_worker_instances", "process_json"),
        ("managed_worker_sessions", "capability_envelope_json"),
        ("managed_worker_sessions", "resource_limits_json"),
        ("managed_worker_lifecycle_events", "evidence_json"),
        ("managed_worker_isolation_evidence", "evidence_json"),
        (
            "self_hosted_worker_registrations",
            "capability_envelope_json",
        ),
        ("self_hosted_worker_heartbeats", "heartbeat_json"),
        ("self_hosted_worker_telemetry_events", "event_json"),
        ("self_hosted_worker_artifacts", "artifact_json"),
        ("self_hosted_worker_checkpoints", "checkpoint_json"),
        ("request_logs", "request_json"),
        ("audit_events", "audit_json"),
    ];
    for (table, column) in jsonb_columns {
        let data_type = postgres_scalar(&format!(
            "SELECT data_type FROM information_schema.columns \
             WHERE table_schema = '{}' AND table_name = '{}' AND column_name = '{}'",
            sql_literal(schema),
            sql_literal(table),
            sql_literal(column)
        ))?;
        if data_type.trim() != "jsonb" {
            bail!("expected {schema}.{table}.{column} to be jsonb, got {data_type}");
        }
    }

    let bigint_columns = [(
        "self_hosted_worker_registrations",
        "identity_expires_at_unix",
    )];
    for (table, column) in bigint_columns {
        let data_type = postgres_scalar(&format!(
            "SELECT data_type FROM information_schema.columns \
             WHERE table_schema = '{}' AND table_name = '{}' AND column_name = '{}'",
            sql_literal(schema),
            sql_literal(table),
            sql_literal(column)
        ))?;
        if data_type.trim() != "bigint" {
            bail!("expected {schema}.{table}.{column} to be bigint, got {data_type}");
        }
    }

    let expected_indexes = [
        "idx_control_plane_resources_document_gin",
        "idx_agent_runs_tenant_started",
        "idx_agent_run_events_run_time",
        "idx_managed_worker_templates_enabled_adapter",
        "idx_agent_worker_instances_status_seen",
        "idx_managed_worker_sessions_tenant_status",
        "idx_managed_worker_lifecycle_session_time",
        "idx_managed_worker_isolation_selection_backend",
        "idx_managed_worker_isolation_policy_egress",
        "idx_managed_worker_isolation_evidence_session_time",
        "idx_self_hosted_worker_registrations_tenant_status",
        "idx_self_hosted_worker_registrations_identity_expiry",
        "idx_self_hosted_worker_heartbeats_worker_time",
        "idx_self_hosted_worker_telemetry_worker_time",
        "idx_self_hosted_worker_artifacts_run",
        "idx_self_hosted_worker_checkpoints_run",
        "idx_self_hosted_run_dispatches_tenant_queue",
        "idx_self_hosted_run_dispatches_worker_lease",
        "idx_self_hosted_run_dispatch_capabilities_capability",
        "idx_request_logs_model_provider_started",
        "idx_audit_events_actor_time",
        "idx_billing_metering_model_provider_time",
        "idx_usage_aggregates_tenant_model_provider",
        "idx_tenant_contexts_api_key",
        "idx_metering_events_tenant_time",
        "idx_metering_event_routes_model_provider",
        "idx_usage_rollups_tenant_model_provider",
    ];
    for index in expected_indexes {
        let count = postgres_scalar(&format!(
            "SELECT count(*) FROM pg_indexes \
             WHERE schemaname = '{}' AND indexname = '{}'",
            sql_literal(schema),
            sql_literal(index)
        ))?;
        if count.trim() != "1" {
            bail!("expected Supabase schema index {schema}.{index}, got count {count}");
        }
    }

    let migration_versions = postgres_scalar(&format!(
        "SELECT string_agg(version::text || ':' || name, ',' ORDER BY version) \
         FROM {}.storage_schema_migrations \
         WHERE version IN (1, 2, 3, 4, 5, 6, 7, 8)",
        quote_ident(schema)
    ))?;
    if migration_versions.trim()
        != "1:001_init_postgres,2:002_supabase_control_plane_billing_evidence,3:003_supabase_structured_metering_usage,4:004_supabase_managed_worker_lifecycle,5:005_supabase_self_hosted_worker_lifecycle,6:006_self_hosted_worker_identity_expiry,7:007_self_hosted_run_dispatch_state,8:008_managed_worker_isolation_evidence"
    {
        bail!("unexpected Supabase migration versions: {migration_versions}");
    }

    Ok(())
}

fn postgres_scalar(query: &str) -> Result<String> {
    let output = Command::new("docker")
        .args([
            "exec",
            "-e",
            "PGPASSWORD=postgres",
            POSTGRES_CONTAINER,
            "psql",
            "-U",
            "postgres",
            "-d",
            "ferrogate",
            "-At",
            "-c",
            query,
        ])
        .stdin(Stdio::null())
        .output()
        .context("failed to query local PostgreSQL container")?;
    if !output.status.success() {
        bail!(
            "PostgreSQL query failed with {}; stdout: {}; stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn sql_literal(value: &str) -> String {
    value.replace('\'', "''")
}

fn quote_ident(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn wait_for_mysql_server() -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(60) {
        if Command::new("docker")
            .args([
                "exec",
                MYSQL_CONTAINER,
                "mysqladmin",
                "ping",
                "--protocol=tcp",
                "-h127.0.0.1",
                "-P3306",
                "-uroot",
                "-pmysql",
                "--silent",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(500));
    }
    let logs = Command::new("docker")
        .args(["logs", MYSQL_CONTAINER, "--tail", "160"])
        .output()
        .ok()
        .map(|output| {
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })
        .unwrap_or_default();
    bail!("timed out waiting for local MySQL server; logs: {logs}");
}

fn stop_postgres_container() {
    stop_postgres_container_named(POSTGRES_CONTAINER);
}

fn stop_postgres_container_named(container_name: &str) {
    let _ = Command::new("docker")
        .args(["rm", "-f", container_name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn stop_mysql_container() {
    let _ = Command::new("docker")
        .args(["rm", "-f", MYSQL_CONTAINER])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

struct PostgresCleanup;

impl Drop for PostgresCleanup {
    fn drop(&mut self) {
        if env::var("FERROGATE_TEST_KEEP_CONTAINERS").is_ok_and(|value| value == "1") {
            return;
        }
        stop_postgres_container();
    }
}

struct PostgresMigrationCleanup;

impl Drop for PostgresMigrationCleanup {
    fn drop(&mut self) {
        if env::var("FERROGATE_TEST_KEEP_CONTAINERS").is_ok_and(|value| value == "1") {
            return;
        }
        stop_postgres_container_named(POSTGRES_MIGRATION_SOURCE_CONTAINER);
        stop_postgres_container_named(POSTGRES_MIGRATION_TARGET_CONTAINER);
    }
}

struct MySqlCleanup;

impl Drop for MySqlCleanup {
    fn drop(&mut self) {
        if env::var("FERROGATE_TEST_KEEP_CONTAINERS").is_ok_and(|value| value == "1") {
            return;
        }
        stop_mysql_container();
    }
}

#[derive(Clone, Copy)]
pub(crate) struct MySqlRestartTls<'a> {
    pub(crate) mode: &'a str,
    pub(crate) ca_cert_path: Option<&'a Path>,
}

#[derive(Clone, Copy)]
pub(crate) struct PostgresRestartTls<'a> {
    pub(crate) mode: &'a str,
    pub(crate) ca_cert_path: Option<&'a Path>,
}

#[derive(Clone, Copy)]
pub(crate) enum ControlPlaneRestartStorage<'a> {
    Postgres {
        dsn: &'a str,
        tls: PostgresRestartTls<'a>,
    },
    Supabase {
        dsn: &'a str,
        tls: PostgresRestartTls<'a>,
    },
    Mysql {
        dsn: &'a str,
        tls: MySqlRestartTls<'a>,
    },
}

impl ControlPlaneRestartStorage<'_> {
    pub(crate) fn supports_durable_metering(self) -> bool {
        matches!(
            self,
            ControlPlaneRestartStorage::Postgres { .. }
                | ControlPlaneRestartStorage::Supabase { .. }
        )
    }

    pub(crate) fn provider_name(self) -> &'static str {
        match self {
            ControlPlaneRestartStorage::Supabase { .. } => "supabase",
            ControlPlaneRestartStorage::Postgres { .. } => "postgres",
            ControlPlaneRestartStorage::Mysql { .. } => "mysql",
        }
    }

    pub(crate) fn apply_env(self, command: &mut Command) {
        match self {
            ControlPlaneRestartStorage::Postgres { dsn, .. } => {
                command.env("FERROGATE_POSTGRES_DSN", dsn);
            }
            ControlPlaneRestartStorage::Supabase { dsn, .. } => {
                command.env("FERROGATE_SUPABASE_DSN", dsn);
            }
            ControlPlaneRestartStorage::Mysql { dsn, .. } => {
                command.env("FERROGATE_MYSQL_DSN", dsn);
            }
        }
    }

    fn storage_block_with_migration_mode(self, migration_mode: StorageMigrationMode) -> String {
        match self {
            ControlPlaneRestartStorage::Postgres { tls, .. } => {
                let ca_cert_path = tls
                    .ca_cert_path
                    .map(|path| {
                        format!(
                            "\n  postgres_tls_ca_cert_path: {}",
                            toml_basic_string(&path.to_string_lossy())
                        )
                    })
                    .unwrap_or_default();
                format!(
                    r#"storage:
  provider: postgres
  required: true
  provider_order:
    - supabase
    - postgres
    - mysql
  postgres_dsn_env: FERROGATE_POSTGRES_DSN
  postgres_pool_size: 2
  postgres_tls_mode: {tls_mode}{ca_cert_path}
  postgres_connect_timeout_secs: 5
  postgres_statement_timeout_millis: 30000
  postgres_schema: ferrogate_control
  postgres_search_path:
    - public
  migration_mode: {migration_mode}"#,
                    tls_mode = tls.mode,
                    ca_cert_path = ca_cert_path,
                    migration_mode = migration_mode.as_str()
                )
            }
            ControlPlaneRestartStorage::Supabase { tls, .. } => {
                let ca_cert_path = tls
                    .ca_cert_path
                    .map(|path| {
                        format!(
                            "\n  postgres_tls_ca_cert_path: {}",
                            toml_basic_string(&path.to_string_lossy())
                        )
                    })
                    .unwrap_or_default();
                format!(
                    r#"storage:
  provider: supabase
  required: true
  provider_order:
    - supabase
    - postgres
    - mysql
  supabase_dsn_env: FERROGATE_SUPABASE_DSN
  postgres_pool_size: 2
  postgres_tls_mode: {tls_mode}{ca_cert_path}
  postgres_connect_timeout_secs: 5
  postgres_statement_timeout_millis: 30000
  postgres_schema: ferrogate_control
  postgres_search_path:
    - public
  migration_mode: {migration_mode}"#,
                    tls_mode = tls.mode,
                    ca_cert_path = ca_cert_path,
                    migration_mode = migration_mode.as_str()
                )
            }
            ControlPlaneRestartStorage::Mysql { tls, .. } => {
                let ca_cert_path = tls
                    .ca_cert_path
                    .map(|path| {
                        format!(
                            "\n  mysql_tls_ca_cert_path: {}",
                            toml_basic_string(&path.to_string_lossy())
                        )
                    })
                    .unwrap_or_default();
                format!(
                    r#"storage:
  provider: mysql
  required: true
  provider_order:
    - supabase
    - postgres
    - mysql
  mysql_dsn_env: FERROGATE_MYSQL_DSN
  mysql_pool_size: 2
  mysql_tls_mode: {tls_mode}{ca_cert_path}
  mysql_connect_timeout_secs: 5
  migration_mode: {migration_mode}"#,
                    tls_mode = tls.mode,
                    ca_cert_path = ca_cert_path,
                    migration_mode = migration_mode.as_str()
                )
            }
        }
    }

    pub(crate) fn restart_config(
        self,
        gateway_addr: &str,
        include_plugins: bool,
        include_mcp_server: bool,
        migration_mode: StorageMigrationMode,
        provider_base_url: Option<&str>,
    ) -> String {
        let plugins = if include_plugins {
            r#"
plugins:
  - id: tool.echo
    kind: tool_provider
    source: builtin
    enabled: true
    order: 10
    approval_policy: never
    permissions:
      tools:
        - tool.echo
"#
        } else {
            ""
        };
        let mcp_server = if include_mcp_server {
            r#"
mcp_servers:
  - name: dbhttp
    transport: streamable_http
    url: "http://127.0.0.1:1/mcp"
    tools_to_execute:
      - search
    tools_to_auto_execute:
      - search
    tool_include:
      - search
    approval_policy: never
    timeout_ms: 100
"#
        } else {
            ""
        };
        let provider_base_url = provider_base_url.unwrap_or("http://127.0.0.1:1/v1");
        format!(
            r#"
listen: "{gateway_addr}"

{storage}

reliability:
  tool_approval_timeout_secs: 1

providers:
  - name: openai
    kind: openai
    base_url: "{provider_base_url}"
    api_key_env: FERROGATE_PROVIDER_SECRET

models:
  - name: fast-chat
    provider: openai
    provider_model: gpt-4o-mini
    capabilities:
      - chat

api_keys:
  - id: admin
    name: Admin
    key: admin-secret
    scopes:
      - admin.read
      - admin.write
      - tools.read
      - tools.execute
{plugins}
{mcp_server}
"#,
            storage = self.storage_block_with_migration_mode(migration_mode),
            provider_base_url = provider_base_url
        )
    }

    pub(crate) fn live_token4ai_provider_config(
        self,
        gateway_addr: &str,
        provider_base_url: &str,
        provider_model: &str,
        migration_mode: StorageMigrationMode,
    ) -> String {
        format!(
            r#"
listen: "{gateway_addr}"

{storage}

providers:
  - name: token4ai
    kind: openai
    base_url: "{provider_base_url}"
    api_key_env: FERROGATE_PROVIDER_SECRET

models:
  - name: live-chat
    provider: token4ai
    provider_model: "{provider_model}"
    capabilities:
      - chat

api_keys:
  - id: client
    name: Live Token4AI client
    key: client-secret
    scopes:
      - models.read
      - chat.completions
    allowed_models:
      - live-chat
    organization_id: org_token4ai_live
    project_id: project_gateway
  - id: admin
    name: Admin
    key: admin-secret
    scopes:
      - admin.read
      - admin.write
"#,
            storage = self.storage_block_with_migration_mode(migration_mode),
            provider_base_url = provider_base_url,
            provider_model = provider_model,
        )
    }
}

#[derive(Clone, Copy)]
pub(crate) enum StorageMigrationMode {
    Auto,
    ValidateOnly,
}

impl StorageMigrationMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            StorageMigrationMode::Auto => "auto",
            StorageMigrationMode::ValidateOnly => "validate_only",
        }
    }
}

pub(crate) struct TursoRestartHarness {
    _dir: tempfile::TempDir,
    gateway_addr: String,
    gateway: Child,
    stderr: Option<std::process::ChildStderr>,
    expected_storage_provider: &'static str,
    expected_migration_mode: StorageMigrationMode,
}

impl TursoRestartHarness {
    pub(crate) fn start(
        ferrogate_bin: &Path,
        storage: ControlPlaneRestartStorage<'_>,
        include_plugins: bool,
        include_mcp_server: bool,
    ) -> Result<Self> {
        Self::start_with_migration_mode(
            ferrogate_bin,
            storage,
            include_plugins,
            include_mcp_server,
            StorageMigrationMode::Auto,
            None,
        )
    }

    pub(crate) fn start_with_migration_mode(
        ferrogate_bin: &Path,
        storage: ControlPlaneRestartStorage<'_>,
        include_plugins: bool,
        include_mcp_server: bool,
        migration_mode: StorageMigrationMode,
        provider_base_url: Option<&str>,
    ) -> Result<Self> {
        if !ferrogate_bin.exists() {
            bail!(
                "ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli` first or pass --ferrogate-bin",
                ferrogate_bin.display()
            );
        }

        let gateway_addr = free_addr()?;
        let dir = tempfile::tempdir()?;
        let config_path = dir.path().join("ferrogate.yaml");
        std::fs::write(
            &config_path,
            storage.restart_config(
                &gateway_addr,
                include_plugins,
                include_mcp_server,
                migration_mode,
                provider_base_url,
            ),
        )?;

        let mut command = Command::new(ferrogate_bin);
        command
            .args(["run", "--config"])
            .arg(&config_path)
            .env("FERROGATE_PROVIDER_SECRET", "provider-secret")
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        if env::var("FERROGATE_TEST_DEBUG_STDERR").is_ok_and(|value| value == "1") {
            command.stderr(Stdio::inherit());
        } else {
            command.stderr(Stdio::piped());
        }
        storage.apply_env(&mut command);
        let gateway = command
            .spawn()
            .with_context(|| format!("failed to start {}", ferrogate_bin.display()))?;

        let mut harness = Self {
            _dir: dir,
            gateway_addr,
            gateway,
            stderr: None,
            expected_storage_provider: storage.provider_name(),
            expected_migration_mode: migration_mode,
        };
        harness.stderr = harness.gateway.stderr.take();
        harness.wait_for_gateway()?;
        Ok(harness)
    }

    pub(crate) fn start_live_token4ai_provider(
        ferrogate_bin: &Path,
        storage: ControlPlaneRestartStorage<'_>,
        provider_base_url: &str,
        provider_model: &str,
        provider_api_key: &str,
    ) -> Result<Self> {
        Self::start_live_token4ai_provider_with_migration_mode(
            ferrogate_bin,
            storage,
            provider_base_url,
            provider_model,
            provider_api_key,
            StorageMigrationMode::Auto,
        )
    }

    pub(crate) fn start_live_token4ai_provider_with_migration_mode(
        ferrogate_bin: &Path,
        storage: ControlPlaneRestartStorage<'_>,
        provider_base_url: &str,
        provider_model: &str,
        provider_api_key: &str,
        migration_mode: StorageMigrationMode,
    ) -> Result<Self> {
        if !ferrogate_bin.exists() {
            bail!(
                "ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli` first or pass --ferrogate-bin",
                ferrogate_bin.display()
            );
        }

        let gateway_addr = free_addr()?;
        let dir = tempfile::tempdir()?;
        let config_path = dir.path().join("ferrogate-token4ai-live.yaml");
        std::fs::write(
            &config_path,
            storage.live_token4ai_provider_config(
                &gateway_addr,
                provider_base_url,
                provider_model,
                migration_mode,
            ),
        )?;

        let mut command = Command::new(ferrogate_bin);
        command
            .args(["run", "--config"])
            .arg(&config_path)
            .env("FERROGATE_PROVIDER_SECRET", provider_api_key)
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        if env::var("FERROGATE_TEST_DEBUG_STDERR").is_ok_and(|value| value == "1") {
            command.stderr(Stdio::inherit());
        } else {
            command.stderr(Stdio::piped());
        }
        storage.apply_env(&mut command);
        let gateway = command
            .spawn()
            .with_context(|| format!("failed to start {}", ferrogate_bin.display()))?;

        let mut harness = Self {
            _dir: dir,
            gateway_addr,
            gateway,
            stderr: None,
            expected_storage_provider: storage.provider_name(),
            expected_migration_mode: migration_mode,
        };
        harness.stderr = harness.gateway.stderr.take();
        harness.wait_for_gateway()?;
        Ok(harness)
    }

    fn wait_for_gateway(&mut self) -> Result<()> {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < Duration::from_secs(60) {
            if let Some(status) = self.gateway.try_wait()? {
                let stderr = self.read_stderr();
                assert_secret_redacted(&stderr);
                bail!(
                    "ferrogate process exited before readiness check: {status}; stderr: {stderr}"
                );
            }
            match http_request_addr(&self.gateway_addr, "GET", "/healthz", &[], "") {
                Ok(response) if response.status == 200 => return Ok(()),
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(250));
        }
        bail!(
            "timed out waiting for durable-storage FerroGate on {}; last response: {last}",
            self.gateway_addr
        );
    }

    fn read_stderr(&mut self) -> String {
        let Some(mut stderr) = self.stderr.take() else {
            return String::new();
        };
        let mut output = String::new();
        let _ = stderr.read_to_string(&mut output);
        output
    }

    pub(crate) fn expect_json<F>(
        &self,
        method: &str,
        path: &str,
        headers: &[&str],
        body: &str,
        expected_status: u16,
        check: F,
    ) -> Result<()>
    where
        F: FnOnce(Value) -> Result<()>,
    {
        let response = http_request_addr(&self.gateway_addr, method, path, headers, body)
            .with_context(|| format!("failed HTTP request {method} {path}"))?;
        if response.status != expected_status {
            bail!(
                "{method} {path} expected status {expected_status}, got {}; raw: {}",
                response.status,
                response.raw
            );
        }
        let body: Value = serde_json::from_str(&response.body).with_context(|| {
            format!(
                "failed to parse JSON body for {method} {path}: {}",
                response.body
            )
        })?;
        check(body)
    }

    pub(crate) fn expect_storage_status(&self) -> Result<()> {
        self.expect_json("GET", "/admin/v1/status", &[ADMIN_AUTH], "", 200, |body| {
            assert_eq!(body["storage"]["provider"], self.expected_storage_provider);
            assert_eq!(body["storage"]["durable"], true);
            assert_eq!(body["storage"]["implemented"], true);
            assert_eq!(body["storage"]["required"], true);
            assert_eq!(
                body["storage"]["migration_mode"],
                self.expected_migration_mode.as_str()
            );
            assert_eq!(body["storage"]["health"], "ok");
            assert_eq!(body["storage"]["provider_order"][0], "supabase");
            assert_eq!(body["storage"]["provider_order"][1], "postgres");
            assert_eq!(body["storage"]["provider_order"][2], "mysql");
            if matches!(self.expected_storage_provider, "supabase" | "postgres") {
                assert_eq!(body["storage"]["schema"]["engine"], "postgres");
                assert_eq!(body["storage"]["schema"]["version"], 8);
                assert_eq!(
                    body["storage"]["schema"]["name"],
                    "008_managed_worker_isolation_evidence"
                );
                assert_eq!(body["storage"]["schema"]["validated"], true);
                assert!(body["storage"]["schema"]["checksum"]
                    .as_str()
                    .is_some_and(|checksum| checksum.len() == 16));
            } else {
                assert!(body["storage"]["schema"].is_null());
            }
            assert_secret_redacted(&body.to_string());
            Ok(())
        })
    }

    pub(crate) fn expect_api_key(&self, id: &str) -> Result<()> {
        self.expect_api_key_named(id, "Durable storage restart test key")
    }

    pub(crate) fn expect_api_key_named(&self, id: &str, name: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/api-keys/{id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["key"]["id"], id);
                assert_eq!(body["key"]["name"], name);
                assert_eq!(body["key"]["key_source"], "inline");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_restored_api_key_models_access(&self, id: &str) -> Result<()> {
        let auth = format!("Authorization: Bearer {id}-secret");
        self.expect_json("GET", "/v1/models", &[auth.as_str()], "", 200, |body| {
            assert!(list_contains(&body, "id", "fast-chat"));
            assert_secret_redacted(&body.to_string());
            Ok(())
        })
    }

    pub(crate) fn expect_gateway_config(&self, id: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/gateway-configs/{id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["gateway_config"]["id"], id);
                assert_eq!(
                    body["gateway_config"]["name"],
                    "Durable storage restart profile"
                );
                assert_eq!(body["gateway_config"]["revision"], 7);
                assert_eq!(body["gateway_config"]["cache_enabled"], false);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_metered_chat_completion(
        &self,
        api_key_id: &str,
        profile_id: &str,
    ) -> Result<()> {
        let auth = format!("Authorization: Bearer {api_key_id}-secret");
        let profile = format!("x-ferrogate-config: {profile_id}");
        self.expect_json(
            "POST",
            "/v1/chat/completions",
            &[auth.as_str(), JSON_CONTENT, profile.as_str()],
            r#"{"model":"fast-chat","messages":[{"role":"user","content":"durable metering check"}]}"#,
            200,
            |body| {
                assert_eq!(body["object"], "chat.completion");
                assert_eq!(body["usage"]["total_tokens"], 2);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_durable_metering_usage(
        &self,
        api_key_id: &str,
        expected_total: u64,
    ) -> Result<()> {
        self.expect_json(
            "GET",
            "/admin/v1/metering-events?limit=100",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let events = body["data"]
                    .as_array()
                    .context("metering events response data must be an array")?;
                let event = events
                    .iter()
                    .find(|event| {
                        event["tenant"]["api_key_id"] == api_key_id
                            && event["logical_model"] == "fast-chat"
                            && event["provider"] == "openai"
                    })
                    .with_context(|| {
                        format!("durable metering event for API key {api_key_id} was not found")
                    })?;
                assert_eq!(event["usage_source"], "provider_usage");
                assert_eq!(event["usage"]["total_tokens"], expected_total);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;

        self.expect_json(
            "GET",
            "/admin/v1/usage-aggregates",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let aggregates = body["data"]
                    .as_array()
                    .context("usage aggregates response data must be an array")?;
                let aggregate = aggregates
                    .iter()
                    .find(|aggregate| {
                        aggregate["api_key_id"] == api_key_id
                            && aggregate["logical_model"] == "fast-chat"
                            && aggregate["provider"] == "openai"
                    })
                    .with_context(|| {
                        format!(
                            "durable usage aggregate for API key {api_key_id} was not found in {body}"
                        )
                    })?;
                assert_eq!(aggregate["usage"]["total_tokens"], expected_total);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_durable_request_and_audit_evidence(&self, api_key_id: &str) -> Result<()> {
        self.expect_json(
            "GET",
            "/admin/v1/request-logs?limit=100",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let logs = body["data"]
                    .as_array()
                    .context("request logs response data must be an array")?;
                let log = logs
                    .iter()
                    .find(|log| {
                        log["tenant"]["api_key_id"] == api_key_id
                            && log["logical_model"] == "fast-chat"
                            && log["provider"] == "openai"
                            && log["status_code"] == 200
                    })
                    .with_context(|| {
                        format!(
                            "durable request log for API key {api_key_id} was not found in {body}"
                        )
                    })?;
                assert_eq!(log["prompt_recorded"], false);
                assert_eq!(log["response_recorded"], false);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;

        self.expect_json(
            "GET",
            "/admin/v1/audit-events?limit=200",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let events = body["data"]
                    .as_array()
                    .context("audit events response data must be an array")?;
                let event = events
                    .iter()
                    .find(|event| {
                        event["actor_api_key_id"] == "admin"
                            && event["target"].as_str().is_some_and(|target| {
                                target == api_key_id || target.contains(api_key_id)
                            })
                            && event["outcome"] == "committed"
                    })
                    .with_context(|| {
                        format!(
                            "durable audit event for API key {api_key_id} was not found in {body}"
                        )
                    })?;
                assert!(event["action"].as_str().is_some_and(|action| {
                    action == "api_key.upsert" || action == "api_key.delete"
                }));
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_live_token4ai_completion(
        &self,
        request_marker: &str,
        provider_model: &str,
    ) -> Result<()> {
        let body = serde_json::json!({
            "model": "live-chat",
            "messages": [
                {
                    "role": "user",
                    "content": format!("Reply with exactly: ok. Marker: {request_marker}")
                }
            ],
            "max_tokens": 64
        })
        .to_string();
        self.expect_json(
            "POST",
            "/v1/chat/completions",
            &[CLIENT_AUTH, JSON_CONTENT],
            &body,
            200,
            |body| {
                assert_eq!(body["object"], "chat.completion");
                assert!(
                    body["usage"]["total_tokens"].as_u64().unwrap_or_default() > 0,
                    "provider usage total_tokens must be positive: {body}"
                );
                assert_secret_redacted(&body.to_string());
                if let Some(model) = body["model"].as_str() {
                    assert!(
                        !model.trim().is_empty(),
                        "provider response model must not be empty"
                    );
                } else {
                    assert!(
                        !provider_model.trim().is_empty(),
                        "configured provider model must not be empty"
                    );
                }
                Ok(())
            },
        )
    }

    pub(crate) fn expect_live_token4ai_metering_usage(
        &self,
        request_marker: &str,
        provider_model: &str,
    ) -> Result<()> {
        let event_total = self.live_token4ai_metering_total(request_marker, provider_model)?;
        if event_total == 0 {
            bail!("live Token4AI metering total_tokens must be positive");
        }

        self.expect_json(
            "GET",
            "/admin/v1/usage-aggregates",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let aggregates = body["data"]
                    .as_array()
                    .context("usage aggregates response data must be an array")?;
                let aggregate = aggregates
                    .iter()
                    .find(|aggregate| {
                        aggregate["api_key_id"] == "client"
                            && aggregate["logical_model"] == "live-chat"
                            && aggregate["provider"] == "token4ai"
                    })
                    .with_context(|| {
                        format!(
                            "live Token4AI usage aggregate for marker {request_marker} was not found in {body}"
                        )
                    })?;
                assert_eq!(aggregate["usage"]["total_tokens"], event_total);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn live_token4ai_metering_total(
        &self,
        request_marker: &str,
        provider_model: &str,
    ) -> Result<u64> {
        let mut total = 0;
        self.expect_json(
            "GET",
            "/admin/v1/metering-events?limit=100",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let events = body["data"]
                    .as_array()
                    .context("metering events response data must be an array")?;
                let event = events
                    .iter()
                    .rev()
                    .find(|event| {
                        event["tenant"]["api_key_id"] == "client"
                            && event["logical_model"] == "live-chat"
                            && event["provider"] == "token4ai"
                    })
                    .with_context(|| {
                        format!(
                            "live Token4AI metering event for marker {request_marker} was not found in {body}"
                        )
                    })?;
                assert_eq!(event["provider_model"], provider_model);
                assert_eq!(event["usage_source"], "provider_usage");
                total = event["usage"]["total_tokens"]
                    .as_u64()
                    .context("metering event usage.total_tokens must be an integer")?;
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        Ok(total)
    }

    pub(crate) fn expect_policy(&self, name: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/policies/{name}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["policy"]["name"], name);
                assert_eq!(body["policy"]["enabled"], false);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_missing_api_key(&self, id: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/api-keys/{id}"),
            &[ADMIN_AUTH],
            "",
            404,
            |body| {
                assert_eq!(body["error"]["code"], "api_key_not_found");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_missing_gateway_config(&self, id: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/gateway-configs/{id}"),
            &[ADMIN_AUTH],
            "",
            404,
            |body| {
                assert_eq!(body["error"]["code"], "gateway_config_not_found");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_missing_policy(&self, name: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/policies/{name}"),
            &[ADMIN_AUTH],
            "",
            404,
            |body| {
                assert_eq!(body["error"]["code"], "policy_not_found");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_restored_policy_denies_chat(&self, id: &str) -> Result<()> {
        let auth = format!("Authorization: Bearer {id}-secret");
        self.expect_json(
            "POST",
            "/v1/chat/completions",
            &[auth.as_str(), JSON_CONTENT],
            r#"{"model":"fast-chat","messages":[{"role":"user","content":"durable policy check"}]}"#,
            403,
            |body| {
                assert_eq!(body["error"]["code"], "blocked_by_storage_restart_test");
                assert_eq!(
                    body["error"]["message"],
                    "blocked by durable storage restart test"
                );
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_prompt_template(&self, id: &str, status: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/prompt-templates/{id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["prompt_template"]["id"], id);
                assert_eq!(
                    body["prompt_template"]["name"],
                    "Durable storage restart prompt"
                );
                assert_eq!(body["prompt_template"]["status"], status);
                assert_eq!(body["prompt_template"]["active_revision"], 1);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_agent_upstream(&self, id: &str, enabled: bool) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/agent-upstreams/{id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["agent_upstream"]["id"], id);
                assert_eq!(body["agent_upstream"]["enabled"], enabled);
                assert_eq!(body["agent_upstream"]["protocol"], "a2a");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_missing_agent_upstream(&self, id: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/agent-upstreams/{id}"),
            &[ADMIN_AUTH],
            "",
            404,
            |body| {
                assert_eq!(body["error"]["code"], "agent_upstream_not_found");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_restored_prompt_template_render(
        &self,
        api_key_id: &str,
        template_id: &str,
    ) -> Result<()> {
        let auth = format!("Authorization: Bearer {api_key_id}-secret");
        self.expect_json(
            "POST",
            &format!("/v1/prompts/{template_id}/render"),
            &[auth.as_str(), JSON_CONTENT],
            r#"{"variables":{"topic":"durable storage"}}"#,
            200,
            |body| {
                assert_eq!(body["model"], "fast-chat");
                assert_eq!(body["temperature"], 0.1);
                assert_eq!(body["messages"][0]["role"], "user");
                assert_eq!(body["messages"][0]["content"], "Summarize durable storage");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_mcp_server(&self, name: &str) -> Result<()> {
        self.expect_json(
            "GET",
            "/admin/v1/mcp-servers",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let servers = body["data"]
                    .as_array()
                    .context("mcp servers response data must be an array")?;
                let server = servers
                    .iter()
                    .find(|server| server["name"] == name)
                    .with_context(|| format!("MCP server {name} was not restored from storage"))?;
                assert_eq!(server["transport"], "streamable_http");
                assert_eq!(server["health"], "degraded");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_missing_mcp_server(&self, name: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/mcp-servers/{name}"),
            &[ADMIN_AUTH],
            "",
            404,
            |body| {
                assert_eq!(body["error"]["code"], "mcp_server_not_found");
                Ok(())
            },
        )
    }

    pub(crate) fn register_echo_plugin(&self) -> Result<()> {
        self.register_echo_plugin_with_policy("never")
    }

    fn register_echo_plugin_with_policy(&self, approval_policy: &str) -> Result<()> {
        let body = serde_json::json!({
            "id": "tool.echo",
            "kind": "tool_provider",
            "source": "builtin",
            "enabled": true,
            "order": 10,
            "approval_policy": approval_policy,
            "permissions": {
                "tools": ["tool.echo"],
                "network": [],
                "filesystem": false,
                "shell": false
            },
            "config": {
                "registered_by": "ferrogate-test"
            }
        })
        .to_string();
        self.expect_json(
            "POST",
            "/admin/v1/plugins",
            &[ADMIN_AUTH, JSON_CONTENT],
            &body,
            201,
            |body| {
                assert_eq!(body["object"], "plugin");
                assert_eq!(body["plugin"]["id"], "tool.echo");
                assert_eq!(body["plugin"]["kind"], "tool_provider");
                assert_eq!(body["plugin"]["source"], "builtin");
                assert_eq!(body["plugin"]["enabled"], true);
                assert_eq!(body["plugin"]["active"], true);
                assert_eq!(body["plugin"]["health"], "ok");
                assert_eq!(body["plugin"]["approval_policy"], approval_policy);
                assert_array_contains(&body["plugin"]["capabilities"], "tool_provider")
                    .context("registered plugin must advertise tool_provider capability")?;
                assert_array_contains(&body["plugin"]["tools"], "tool.echo")
                    .context("registered plugin must expose tool.echo")?;
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn register_mcp_server(&self, name: &str) -> Result<()> {
        let body = serde_json::json!({
            "name": name,
            "transport": "streamable_http",
            "url": "http://127.0.0.1:1/mcp",
            "auth_type": "none",
            "tools_to_execute": ["search"],
            "tools_to_auto_execute": ["search"],
            "approval_policy": "never",
            "tool_include": ["search"],
            "tool_regex": [],
            "headers": [],
            "tls": {},
            "timeout_ms": 100,
            "health_ping_interval_secs": 30,
            "max_reconnect_attempts": 3,
            "min_reconnect_backoff_secs": 1,
            "max_reconnect_backoff_secs": 5
        })
        .to_string();
        self.expect_json(
            "POST",
            "/admin/v1/mcp-servers",
            &[ADMIN_AUTH, JSON_CONTENT],
            &body,
            201,
            |body| {
                assert_eq!(body["object"], "mcp_server");
                assert_eq!(body["server"]["name"], name);
                assert_eq!(body["server"]["transport"], "streamable_http");
                assert_eq!(body["server"]["health"], "degraded");
                assert_eq!(body["server"]["connected"], false);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn delete_mcp_server(&self, name: &str) -> Result<()> {
        self.expect_json(
            "DELETE",
            &format!("/admin/v1/mcp-servers/{name}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["object"], "mcp_server");
                assert_eq!(body["id"], name);
                assert_eq!(body["deleted"], true);
                Ok(())
            },
        )
    }

    pub(crate) fn create_expired_echo_approval(&self) -> Result<String> {
        self.register_echo_plugin_with_policy("always")?;
        let mut request_id = String::new();
        self.expect_json(
            "POST",
            "/v1/tools/execute",
            &[ADMIN_AUTH, JSON_CONTENT],
            r#"{"name":"tool.echo","arguments":{"message":"approval durability"}}"#,
            403,
            |body| {
                assert_eq!(body["error"]["code"], "tool_denied");
                request_id = body["error"]["request_id"]
                    .as_str()
                    .context("tool approval error response must include request_id")?
                    .to_string();
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        let mut approval_id = String::new();
        self.expect_json(
            "GET",
            "/admin/v1/tool-approvals",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let approvals = body["data"]
                    .as_array()
                    .context("tool approvals response data must be an array")?;
                let approval = approvals
                    .iter()
                    .find(|approval| approval["request_id"] == request_id)
                    .with_context(|| {
                        format!("tool approval for request {request_id} was not persisted")
                    })?;
                assert_eq!(approval["tool_name"], "tool.echo");
                assert_eq!(approval["status"], "expired");
                assert_eq!(approval["approval_policy"], "always");
                assert_secret_redacted(&body.to_string());
                approval_id = approval["id"]
                    .as_str()
                    .context("tool approval id missing")?
                    .to_string();
                Ok(())
            },
        )?;
        Ok(approval_id)
    }

    pub(crate) fn expect_tool_approval(&self, id: &str, status: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/tool-approvals/{id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["id"], id);
                assert_eq!(body["tool_name"], "tool.echo");
                assert_eq!(body["status"], status);
                assert_eq!(body["approval_policy"], "always");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_plugin(&self, id: &str) -> Result<()> {
        self.expect_json("GET", "/admin/v1/plugins", &[ADMIN_AUTH], "", 200, |body| {
            let plugins = body["data"]
                .as_array()
                .context("plugins response data must be an array")?;
            let plugin = plugins
                .iter()
                .find(|plugin| plugin["id"] == id)
                .with_context(|| format!("plugin {id} was not restored from storage"))?;
            assert_eq!(plugin["source"], "builtin");
            assert_eq!(plugin["enabled"], true);
            assert_eq!(plugin["active"], true);
            assert_eq!(plugin["health"], "ok");
            assert_array_contains(&plugin["capabilities"], "tool_provider")
                .context("plugin must advertise the tool_provider capability")?;
            assert_array_contains(&plugin["tools"], "tool.echo")
                .context("plugin must advertise its registered tool")?;
            assert_secret_redacted(&body.to_string());
            Ok(())
        })?;
        self.expect_json(
            "GET",
            &format!("/admin/v1/plugins/{id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["id"], id);
                assert_eq!(body["source"], "builtin");
                assert_eq!(body["enabled"], true);
                assert_eq!(body["active"], true);
                assert_eq!(body["health"], "ok");
                assert_array_contains(&body["capabilities"], "tool_provider")
                    .context("plugin detail must advertise the tool_provider capability")?;
                assert_array_contains(&body["tools"], "tool.echo")
                    .context("plugin detail must advertise its registered tool")?;
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        self.expect_json(
            "GET",
            &format!("/admin/v1/plugins/{id}/tools"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let tools = body["data"]
                    .as_array()
                    .context("plugin tools response data must be an array")?;
                let tool = tools
                    .iter()
                    .find(|tool| tool["name"] == "tool.echo")
                    .context("plugin tool.echo was not listed")?;
                assert_eq!(tool["extension_id"], id);
                assert_eq!(tool["approval_policy"], "never");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    pub(crate) fn expect_echo_tool(&self) -> Result<()> {
        self.expect_json(
            "POST",
            "/v1/tools/execute",
            &[ADMIN_AUTH, JSON_CONTENT],
            r#"{"name":"tool.echo","arguments":{"message":"plugin durable restore"}}"#,
            200,
            |body| {
                assert_eq!(body["object"], "tool_execution");
                assert_eq!(body["name"], "tool.echo");
                assert_eq!(body["content"]["echo"]["message"], "plugin durable restore");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }
}

impl Drop for TursoRestartHarness {
    fn drop(&mut self) {
        let _ = self.gateway.kill();
        let _ = self.gateway.wait();
    }
}
