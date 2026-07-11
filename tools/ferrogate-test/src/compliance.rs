// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Reusable cross-component runtime compliance contracts for issue #210.

use crate::{
    cli::{LocalArgs, SupabaseLiveRestartArgs},
    constants::{ADMIN_AUTH, JSON_CONTENT},
    http::http_request_addr,
    local::LocalHarness,
};
use anyhow::{bail, Context, Result};
use native_tls::{Certificate, TlsConnector};
use postgres::{config::SslMode, Client, Config as PostgresConfig};
use postgres_native_tls::MakeTlsConnector;
use serde_json::{json, Value};
use std::{
    env,
    fmt::Debug,
    fs,
    path::Path,
    process::{Child, Command, Stdio},
    str::FromStr,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(crate) trait ComponentContract {
    type Case: Debug;
    type Written: Debug + PartialEq;
    type Runtime: Debug;

    fn name(&self) -> &'static str;
    fn cases(&self) -> Vec<Self::Case>;
    fn write(&self, gateway_addr: &str, case: &Self::Case) -> Result<Self::Written>;
    fn read(&self, gateway_addr: &str, case: &Self::Case) -> Result<Self::Written>;
    fn exercise(&self, gateway_addr: &str, case: &Self::Case) -> Result<Self::Runtime>;
    fn verify(
        &self,
        case: &Self::Case,
        written: &Self::Written,
        runtime: &Self::Runtime,
    ) -> Result<()>;
    fn cleanup(&self, gateway_addr: &str, case: &Self::Case) -> Result<()>;
}

pub(crate) fn run_component_compliance(args: &LocalArgs) -> Result<()> {
    let harness = LocalHarness::start(&args.ferrogate_bin, 0)?;
    run_component_compliance_at(&harness.gateway_addr)?;
    println!("component-compliance scenario passed");
    Ok(())
}

pub(crate) fn run_component_compliance_supabase(args: &SupabaseLiveRestartArgs) -> Result<()> {
    if args.supabase_dsn.trim().is_empty() {
        bail!("--supabase-dsn must not be empty");
    }
    if !args.local.ferrogate_bin.exists() {
        bail!(
            "ferrogate binary does not exist at {}; run cargo build -p ferrogate-cli first",
            args.local.ferrogate_bin.display()
        );
    }
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?
        .as_millis();
    let schema = format!("ferrogate_component_compliance_e2e_{suffix}");
    let mut evidence = SupabaseSchema::create(args, schema.clone())?;
    let gateway_addr = crate::http::free_addr()?;
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("component-compliance-supabase.yaml");
    fs::write(
        &config_path,
        compliance_supabase_config(&gateway_addr, &schema, args)?,
    )?;
    let _gateway = GatewayGuard::start(
        &args.local.ferrogate_bin,
        &config_path,
        &gateway_addr,
        args.supabase_dsn.trim(),
    )?;
    run_component_compliance_at(&gateway_addr)?;
    evidence.verify_contract_cleanup()?;
    println!("component-compliance-supabase scenario passed");
    Ok(())
}

pub(crate) fn run_component_compliance_at(gateway_addr: &str) -> Result<()> {
    let fixture = bootstrap_quota_fixture(gateway_addr)?;
    assert_component_contract(gateway_addr, &QuotaScopeContract::new(&fixture))?;
    assert_component_contract(gateway_addr, &TenantAssetQuotaContract::new(&fixture))?;
    assert_narrow_asset_quota_scopes_are_rejected(gateway_addr, &fixture)?;
    Ok(())
}

pub(crate) fn assert_component_contract<C: ComponentContract>(
    gateway_addr: &str,
    contract: &C,
) -> Result<()> {
    for case in contract.cases() {
        let result = (|| {
            let written = contract.write(gateway_addr, &case)?;
            let read = contract.read(gateway_addr, &case)?;
            if written != read {
                bail!(
                    "write/read mismatch for {} case {case:?}: wrote {written:?}, read {read:?}",
                    contract.name()
                );
            }
            let runtime = contract.exercise(gateway_addr, &case)?;
            contract.verify(&case, &written, &runtime)
        })()
        .with_context(|| {
            format!(
                "{} component contract case {case:?} failed",
                contract.name()
            )
        });

        let cleanup = contract
            .cleanup(gateway_addr, &case)
            .with_context(|| format!("{} cleanup for case {case:?} failed", contract.name()));
        match (result, cleanup) {
            (Err(error), _) => return Err(error),
            (Ok(()), Err(error)) => return Err(error),
            (Ok(()), Ok(())) => {}
        }
    }
    Ok(())
}

#[derive(Debug)]
struct QuotaFixture {
    key_id: String,
    key_secret: String,
}

#[derive(Clone, Copy, Debug)]
struct ScopeCase<'a> {
    scope_type: &'static str,
    scope_id: &'a str,
}

#[derive(Debug, PartialEq)]
struct QuotaPolicyProjection {
    scope_type: String,
    scope_id: String,
    enabled: bool,
}

#[derive(Debug)]
struct RuntimeDecision {
    status: u16,
    code: Option<String>,
}

struct QuotaScopeContract<'a> {
    fixture: &'a QuotaFixture,
}

impl<'a> QuotaScopeContract<'a> {
    fn new(fixture: &'a QuotaFixture) -> Self {
        Self { fixture }
    }
}

impl<'a> ComponentContract for QuotaScopeContract<'a> {
    type Case = ScopeCase<'a>;
    type Written = QuotaPolicyProjection;
    type Runtime = RuntimeDecision;

    fn name(&self) -> &'static str {
        "quota-scope-runtime"
    }

    fn cases(&self) -> Vec<Self::Case> {
        vec![
            ScopeCase {
                scope_type: "tenant",
                scope_id: "compliance-tenant",
            },
            ScopeCase {
                scope_type: "project",
                scope_id: "compliance-project",
            },
            ScopeCase {
                scope_type: "workspace",
                scope_id: "compliance-workspace",
            },
            ScopeCase {
                scope_type: "key",
                scope_id: &self.fixture.key_id,
            },
        ]
    }

    fn write(&self, gateway_addr: &str, case: &Self::Case) -> Result<Self::Written> {
        quota_policy_request(gateway_addr, "PUT", case, r#"{"enabled":false}"#, 200)
    }

    fn read(&self, gateway_addr: &str, case: &Self::Case) -> Result<Self::Written> {
        quota_policy_request(gateway_addr, "GET", case, "", 200)
    }

    fn exercise(&self, gateway_addr: &str, _case: &Self::Case) -> Result<Self::Runtime> {
        let auth = format!("Authorization: Bearer {}", self.fixture.key_secret);
        runtime_decision(
            gateway_addr,
            "POST",
            "/v1/chat/completions",
            &[&auth, JSON_CONTENT],
            r#"{"model":"fast-chat","messages":[]}"#,
        )
    }

    fn verify(
        &self,
        _case: &Self::Case,
        written: &Self::Written,
        runtime: &Self::Runtime,
    ) -> Result<()> {
        if written.enabled {
            bail!("quota contract fixture must write enabled=false");
        }
        if runtime.status != 403 || runtime.code.as_deref() != Some("quota_scope_disabled") {
            bail!("runtime ignored disabled quota scope: {runtime:?}");
        }
        Ok(())
    }

    fn cleanup(&self, gateway_addr: &str, case: &Self::Case) -> Result<()> {
        let path = quota_policy_path(case);
        expect_status(gateway_addr, "DELETE", &path, &[ADMIN_AUTH], "", 200)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct TenantAssetCase;

#[derive(Debug, PartialEq)]
struct AssetQuotaProjection {
    bytes: u64,
}

struct TenantAssetQuotaContract<'a> {
    fixture: &'a QuotaFixture,
}

impl<'a> TenantAssetQuotaContract<'a> {
    fn new(fixture: &'a QuotaFixture) -> Self {
        Self { fixture }
    }
}

impl ComponentContract for TenantAssetQuotaContract<'_> {
    type Case = TenantAssetCase;
    type Written = AssetQuotaProjection;
    type Runtime = RuntimeDecision;

    fn name(&self) -> &'static str {
        "tenant-asset-quota-runtime"
    }

    fn cases(&self) -> Vec<Self::Case> {
        vec![TenantAssetCase]
    }

    fn write(&self, gateway_addr: &str, _case: &Self::Case) -> Result<Self::Written> {
        asset_quota_projection(
            gateway_addr,
            "PUT",
            r#"{"asset_storage_quota_bytes":50}"#,
            200,
        )
    }

    fn read(&self, gateway_addr: &str, _case: &Self::Case) -> Result<Self::Written> {
        asset_quota_projection(gateway_addr, "GET", "", 200)
    }

    fn exercise(&self, gateway_addr: &str, _case: &Self::Case) -> Result<Self::Runtime> {
        let auth = format!("Authorization: Bearer {}", self.fixture.key_secret);
        expect_status(
            gateway_addr,
            "PUT",
            "/v1/assets/config_file/compliance-first/1.0.0",
            &[&auth, "Content-Type: text/plain"],
            &"a".repeat(30),
            200,
        )?;
        runtime_decision(
            gateway_addr,
            "PUT",
            "/v1/assets/config_file/compliance-second/1.0.0",
            &[&auth, "Content-Type: text/plain"],
            &"b".repeat(30),
        )
    }

    fn verify(
        &self,
        _case: &Self::Case,
        written: &Self::Written,
        runtime: &Self::Runtime,
    ) -> Result<()> {
        if written.bytes != 50 {
            bail!("tenant asset quota fixture must write 50 bytes");
        }
        if runtime.status != 403 || runtime.code.as_deref() != Some("asset_storage_quota_exceeded")
        {
            bail!("runtime ignored tenant asset quota: {runtime:?}");
        }
        Ok(())
    }

    fn cleanup(&self, gateway_addr: &str, _case: &Self::Case) -> Result<()> {
        let auth = format!("Authorization: Bearer {}", self.fixture.key_secret);
        expect_status(
            gateway_addr,
            "DELETE",
            "/v1/assets/config_file/compliance-first/1.0.0",
            &[&auth],
            "",
            200,
        )?;
        expect_status(
            gateway_addr,
            "DELETE",
            "/admin/v1/quota-policies/tenant/compliance-tenant",
            &[ADMIN_AUTH],
            "",
            200,
        )?;
        Ok(())
    }
}

fn bootstrap_quota_fixture(gateway_addr: &str) -> Result<QuotaFixture> {
    expect_json(
        gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &[ADMIN_AUTH, JSON_CONTENT],
        &json!({
            "id": "compliance-tenant",
            "name": "Component compliance tenant",
            "slug": "component-compliance-tenant"
        })
        .to_string(),
        201,
    )?;
    expect_json(
        gateway_addr,
        "POST",
        "/admin/v1/plans",
        &[ADMIN_AUTH, JSON_CONTENT],
        &json!({
            "id": "compliance-plan",
            "name": "Component compliance plan",
            "slug": "component-compliance-plan",
            "asset_hosting_enabled": true,
            "default_asset_storage_quota_bytes": 1_000
        })
        .to_string(),
        201,
    )?;
    expect_json(
        gateway_addr,
        "PATCH",
        "/admin/v1/tenant-accounts/compliance-tenant",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"plan_id":"compliance-plan"}"#,
        200,
    )?;
    expect_json(
        gateway_addr,
        "POST",
        "/admin/v1/projects",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"compliance-project","tenant_id":"compliance-tenant","name":"Component compliance project","slug":"component-compliance-project"}"#,
        201,
    )?;
    expect_json(
        gateway_addr,
        "POST",
        "/admin/v1/workspaces",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"compliance-workspace","project_id":"compliance-project","name":"Component compliance workspace","slug":"component-compliance-workspace"}"#,
        201,
    )?;
    let key = expect_json(
        gateway_addr,
        "POST",
        "/admin/v1/virtual-keys",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"name":"Component compliance key","workspace_id":"compliance-workspace","scopes":["assets.read","assets.write","chat.completions"],"allowed_models":["fast-chat"]}"#,
        201,
    )?;
    Ok(QuotaFixture {
        key_id: required_string(&key["key"]["id"], "virtual-key response key.id")?,
        key_secret: required_string(&key["secret"], "virtual-key response secret")?,
    })
}

fn assert_narrow_asset_quota_scopes_are_rejected(
    gateway_addr: &str,
    fixture: &QuotaFixture,
) -> Result<()> {
    for case in [
        ScopeCase {
            scope_type: "project",
            scope_id: "compliance-project",
        },
        ScopeCase {
            scope_type: "workspace",
            scope_id: "compliance-workspace",
        },
        ScopeCase {
            scope_type: "key",
            scope_id: &fixture.key_id,
        },
    ] {
        let path = quota_policy_path(&case);
        let rejected = expect_json(
            gateway_addr,
            "PUT",
            &path,
            &[ADMIN_AUTH, JSON_CONTENT],
            r#"{"asset_storage_quota_bytes":50}"#,
            400,
        )?;
        if rejected["error"]["code"] != "invalid_quota_policy" {
            bail!("narrow asset quota returned the wrong error: {rejected}");
        }
        expect_status(gateway_addr, "GET", &path, &[ADMIN_AUTH], "", 404)?;
    }
    Ok(())
}

fn quota_policy_request(
    gateway_addr: &str,
    method: &str,
    case: &ScopeCase<'_>,
    body: &str,
    expected_status: u16,
) -> Result<QuotaPolicyProjection> {
    let path = quota_policy_path(case);
    let response = expect_json(
        gateway_addr,
        method,
        &path,
        if body.is_empty() {
            &[ADMIN_AUTH]
        } else {
            &[ADMIN_AUTH, JSON_CONTENT]
        },
        body,
        expected_status,
    )?;
    Ok(QuotaPolicyProjection {
        scope_type: required_string(&response["policy"]["scope_type"], "policy.scope_type")?,
        scope_id: required_string(&response["policy"]["scope_id"], "policy.scope_id")?,
        enabled: response["policy"]["enabled"]
            .as_bool()
            .context("policy.enabled must be a boolean")?,
    })
}

fn asset_quota_projection(
    gateway_addr: &str,
    method: &str,
    body: &str,
    expected_status: u16,
) -> Result<AssetQuotaProjection> {
    let response = expect_json(
        gateway_addr,
        method,
        "/admin/v1/quota-policies/tenant/compliance-tenant",
        if body.is_empty() {
            &[ADMIN_AUTH]
        } else {
            &[ADMIN_AUTH, JSON_CONTENT]
        },
        body,
        expected_status,
    )?;
    Ok(AssetQuotaProjection {
        bytes: response["policy"]["asset_storage_quota_bytes"]
            .as_u64()
            .context("policy.asset_storage_quota_bytes must be an unsigned integer")?,
    })
}

fn runtime_decision(
    gateway_addr: &str,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &str,
) -> Result<RuntimeDecision> {
    let response = http_request_addr(gateway_addr, method, path, headers, body)?;
    let parsed = serde_json::from_str::<Value>(&response.body).ok();
    Ok(RuntimeDecision {
        status: response.status,
        code: parsed
            .as_ref()
            .and_then(|body| body["error"]["code"].as_str())
            .map(str::to_string),
    })
}

fn quota_policy_path(case: &ScopeCase<'_>) -> String {
    format!(
        "/admin/v1/quota-policies/{}/{}",
        case.scope_type, case.scope_id
    )
}

fn expect_json(
    gateway_addr: &str,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &str,
    expected_status: u16,
) -> Result<Value> {
    let response = http_request_addr(gateway_addr, method, path, headers, body)?;
    if response.status != expected_status {
        bail!(
            "{method} {path} expected status {expected_status}, got {}; raw: {}",
            response.status,
            response.raw
        );
    }
    serde_json::from_str(&response.body)
        .with_context(|| format!("{method} {path} returned invalid JSON: {}", response.body))
}

fn expect_status(
    gateway_addr: &str,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &str,
    expected_status: u16,
) -> Result<String> {
    let response = http_request_addr(gateway_addr, method, path, headers, body)?;
    if response.status != expected_status {
        bail!(
            "{method} {path} expected status {expected_status}, got {}; raw: {}",
            response.status,
            response.raw
        );
    }
    Ok(response.body)
}

fn required_string(value: &Value, field: &str) -> Result<String> {
    value
        .as_str()
        .map(str::to_string)
        .with_context(|| format!("{field} must be a string, got {value}"))
}

fn compliance_supabase_config(
    gateway_addr: &str,
    schema: &str,
    args: &SupabaseLiveRestartArgs,
) -> Result<String> {
    let tls_mode = match args.tls_mode.trim() {
        "disable" | "prefer" | "require" | "verify_ca" | "verify_full" => args.tls_mode.trim(),
        other => bail!("unsupported Supabase TLS mode {other}"),
    };
    let ca = args
        .tls_ca_cert_path
        .as_ref()
        .map(|path| {
            format!(
                "  postgres_tls_ca_cert_path: {:?}\n",
                path.to_string_lossy()
            )
        })
        .unwrap_or_default();
    Ok(format!(
        r#"listen: "{gateway_addr}"
storage:
  provider: "supabase"
  required: true
  provider_order: ["supabase", "postgres"]
  supabase_dsn_env: "FERROGATE_SUPABASE_DSN"
  postgres_pool_size: 2
  postgres_tls_mode: "{tls_mode}"
{ca}  postgres_connect_timeout_secs: 10
  postgres_statement_timeout_millis: 30000
  postgres_schema: "{schema}"
  postgres_search_path: ["public"]
  migration_mode: "auto"
providers:
  - name: "openai"
    kind: "openai"
    base_url: "http://127.0.0.1:1/v1"
models:
  - name: "fast-chat"
    provider: "openai"
    provider_model: "gpt-4o-mini"
api_keys:
  - id: "admin"
    name: "Component compliance admin"
    key: "admin-secret"
    scopes: ["admin.read", "admin.write"]
"#
    ))
}

struct GatewayGuard {
    child: Child,
}

impl GatewayGuard {
    fn start(binary: &Path, config: &Path, gateway_addr: &str, dsn: &str) -> Result<Self> {
        let child = Command::new(binary)
            .args(["run", "--config"])
            .arg(config)
            .env("FERROGATE_SUPABASE_DSN", dsn)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(
                if env::var("FERROGATE_TEST_DEBUG_STDERR").is_ok_and(|value| value == "1") {
                    Stdio::inherit()
                } else {
                    Stdio::null()
                },
            )
            .spawn()
            .with_context(|| format!("failed to start {}", binary.display()))?;
        let mut guard = Self { child };
        guard.wait_for_readiness(gateway_addr)?;
        Ok(guard)
    }

    fn wait_for_readiness(&mut self, gateway_addr: &str) -> Result<()> {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < Duration::from_secs(180) {
            if let Some(status) = self.child.try_wait()? {
                bail!("FerroGate exited before compliance readiness: {status}");
            }
            match http_request_addr(gateway_addr, "GET", "/healthz", &[], "") {
                Ok(response) if response.status == 200 => return Ok(()),
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("timed out waiting for compliance gateway: {last}")
    }
}

impl Drop for GatewayGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct SupabaseSchema {
    client: Client,
    schema: String,
}

impl SupabaseSchema {
    fn create(args: &SupabaseLiveRestartArgs, schema: String) -> Result<Self> {
        let mut client = connect_supabase(args)?;
        client.batch_execute(&format!("CREATE SCHEMA \"{schema}\""))?;
        Ok(Self { client, schema })
    }

    fn verify_contract_cleanup(&mut self) -> Result<()> {
        let migration = self.client.query_one(
            &format!(
                "SELECT name FROM \"{}\".storage_schema_migrations WHERE version = 29",
                self.schema
            ),
            &[],
        )?;
        let migration_name: String = migration.get(0);
        if migration_name != "029_tenant_only_asset_storage_quota" {
            bail!("unexpected Supabase migration 29 name: {migration_name}");
        }
        let invalid_insert = self.client.execute(
            &format!(
                "INSERT INTO \"{}\".quota_policies \
                 (id, scope_type, scope_id, asset_storage_quota_bytes) \
                 VALUES ('invalid-project-asset-quota', 'project', 'compliance-project', 50)",
                self.schema
            ),
            &[],
        );
        if invalid_insert.is_ok() {
            bail!("Supabase accepted a non-tenant asset storage quota directly");
        }
        for table in ["quota_policies", "stored_assets"] {
            let count: i64 = self
                .client
                .query_one(
                    &format!("SELECT COUNT(*) FROM \"{}\".{table}", self.schema),
                    &[],
                )?
                .get(0);
            if count != 0 {
                bail!("compliance cleanup left {count} rows in {table}");
            }
        }
        let tenant_count: i64 = self
            .client
            .query_one(
                &format!(
                    "SELECT COUNT(*) FROM \"{}\".tenants WHERE id = 'compliance-tenant'",
                    self.schema
                ),
                &[],
            )?
            .get(0);
        if tenant_count != 1 {
            bail!("compliance API writes did not reach the Supabase tenant table");
        }
        Ok(())
    }
}

impl Drop for SupabaseSchema {
    fn drop(&mut self) {
        let _ = self.client.batch_execute(&format!(
            "DROP SCHEMA IF EXISTS \"{}\" CASCADE",
            self.schema
        ));
    }
}

fn connect_supabase(args: &SupabaseLiveRestartArgs) -> Result<Client> {
    let mut config = PostgresConfig::from_str(args.supabase_dsn.trim())?;
    config.connect_timeout(Duration::from_secs(10));
    if args.tls_mode == "disable" {
        config.ssl_mode(SslMode::Disable);
        return config.connect(postgres::NoTls).map_err(Into::into);
    }
    config.ssl_mode(SslMode::Require);
    let mut builder = TlsConnector::builder();
    if let Some(path) = args.tls_ca_cert_path.as_deref() {
        let bytes = fs::read(path)?;
        let certificate =
            Certificate::from_pem(&bytes).or_else(|_| Certificate::from_der(&bytes))?;
        builder.add_root_certificate(certificate);
    }
    match args.tls_mode.as_str() {
        "require" => {
            builder.danger_accept_invalid_certs(true);
            builder.danger_accept_invalid_hostnames(true);
        }
        "verify_ca" => {
            builder.danger_accept_invalid_hostnames(true);
        }
        "prefer" | "verify_full" => {}
        other => bail!("unsupported Supabase TLS mode {other}"),
    }
    let connector = MakeTlsConnector::new(builder.build()?);
    config.connect(connector).map_err(Into::into)
}

#[cfg(test)]
#[path = "compliance_test.rs"]
mod compliance_test;
