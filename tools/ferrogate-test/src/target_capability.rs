// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-13
// description: Live Supabase RBAC-to-runtime contract for target capabilities (#204).

use crate::{
    cli::SupabaseLiveRestartArgs,
    constants::{ADMIN_AUTH, JSON_CONTENT},
    http::{free_addr, http_request_addr},
    supabase_schema::{
        connect_live_supabase, LiveSupabaseClient, LiveSupabaseScenario, LiveSupabaseSchema,
    },
};
use anyhow::{bail, Context, Result};
use ferrogate_runtime::{
    ExternalActionAuthorizationRequest, ExternalActionFramework, ExternalActionMode,
    ExternalActionSession, ExternalActionSpec, GatewayExternalActionTransportRequest,
    GatewayExternalActionTransportResponse,
};
use serde_json::json;
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const TARGET_TENANT_ID: &str = "target-capability-tenant";
const TARGET_PERMISSION_ID: &str = "permission-target-capability-204";
const TARGET_PERMISSION_KEY: &str = "managed_actions.mcp.customer_lookup";
const TARGET_ROLE_ID: &str = "customer-defined-role-204";

pub(crate) fn run_target_capability_supabase(args: &SupabaseLiveRestartArgs) -> Result<()> {
    if args.supabase_dsn.trim().is_empty() {
        bail!("--supabase-dsn must not be empty");
    }
    if !args.local.ferrogate_bin.exists() {
        bail!(
            "ferrogate binary does not exist at {}; run cargo build -p ferrogate-cli first",
            args.local.ferrogate_bin.display()
        );
    }

    let mut schema = LiveSupabaseSchema::create(args, LiveSupabaseScenario::TargetCapability)?;
    let schema_name = schema.name().to_string();
    let mut evidence = SupabaseRbacEvidence::connect(args, schema_name.clone())?;
    let gateway_addr = free_addr()?;
    let dir = tempfile::tempdir()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
    let authorizer_socket = dir.path().join("target-capability.sock");
    let config_path = dir.path().join("target-capability-supabase.toml");
    fs::write(
        &config_path,
        target_capability_supabase_config(
            &gateway_addr,
            &schema_name,
            &authorizer_socket,
            args.tls_mode.trim(),
            args.tls_ca_cert_path.as_deref(),
        )?,
    )?;
    let gateway = GatewayGuard::start(
        &args.local.ferrogate_bin,
        &config_path,
        &gateway_addr,
        &authorizer_socket,
        args.supabase_dsn.trim(),
    )?;

    create_target_tenant(&gateway_addr)?;
    assert_target_decision(&authorizer_socket, false, "unbound tenant")?;
    create_target_rbac_graph(&gateway_addr)?;
    evidence.verify_graph(true)?;
    assert_target_decision(&authorizer_socket, true, "bound arbitrary role")?;
    delete_target_rbac_graph(&gateway_addr)?;
    evidence.verify_graph(false)?;
    assert_target_decision(&authorizer_socket, false, "revoked arbitrary role")?;

    drop(gateway);
    drop(evidence);
    schema.finish()?;
    println!("target-capability-supabase scenario passed");
    Ok(())
}

fn create_target_tenant(gateway_addr: &str) -> Result<()> {
    expect_status(
        gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &json!({
            "id": TARGET_TENANT_ID,
            "name": "Target capability live contract",
            "slug": "target-capability-live-contract"
        })
        .to_string(),
        &[200, 201],
    )
}

fn create_target_rbac_graph(gateway_addr: &str) -> Result<()> {
    expect_status(
        gateway_addr,
        "POST",
        "/admin/v1/permissions",
        &json!({
            "id": TARGET_PERMISSION_ID,
            "key": TARGET_PERMISSION_KEY,
            "name": "Customer lookup managed action"
        })
        .to_string(),
        &[200],
    )?;
    expect_status(
        gateway_addr,
        "POST",
        "/admin/v1/roles",
        &json!({
            "id": TARGET_ROLE_ID,
            "name": "Customer supplied role name",
            "slug": "operator-invented-role-204",
            "permission_keys": [TARGET_PERMISSION_KEY]
        })
        .to_string(),
        &[200],
    )?;
    expect_status(
        gateway_addr,
        "POST",
        &format!("/admin/v1/tenant-roles/{TARGET_TENANT_ID}"),
        &json!({"role_id": TARGET_ROLE_ID}).to_string(),
        &[200],
    )
}

fn delete_target_rbac_graph(gateway_addr: &str) -> Result<()> {
    expect_status(
        gateway_addr,
        "DELETE",
        &format!("/admin/v1/tenant-roles/{TARGET_TENANT_ID}/{TARGET_ROLE_ID}"),
        "",
        &[200],
    )?;
    expect_status(
        gateway_addr,
        "DELETE",
        &format!("/admin/v1/roles/{TARGET_ROLE_ID}"),
        "",
        &[200],
    )?;
    expect_status(
        gateway_addr,
        "DELETE",
        &format!("/admin/v1/permissions/{TARGET_PERMISSION_ID}"),
        "",
        &[200],
    )
}

fn assert_target_decision(socket_path: &Path, expected_allowed: bool, stage: &str) -> Result<()> {
    let request = target_authorization_request();
    let mut stream = UnixStream::connect(socket_path).with_context(|| {
        format!(
            "failed to connect target authorizer {} at {stage}",
            socket_path.display()
        )
    })?;
    stream.write_all(serde_json::to_string(&request)?.as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let response: GatewayExternalActionTransportResponse = serde_json::from_str(&response)?;
    if response.response.accepted != expected_allowed {
        bail!("target capability {stage} expected allowed={expected_allowed}, got {response:?}");
    }
    if expected_allowed {
        let event = response
            .response
            .event
            .context("allowed target decision omitted normalized evidence")?;
        if event["metadata"]["selector"] != "customer-lookup"
            || event["metadata"]["policy_revision"] != "target-supabase-1"
            || event["metadata"]["subject"]
                != format!("tenant:{TARGET_TENANT_ID}/workspace:workspace-204/worker:worker-204")
        {
            bail!("allowed target decision returned incomplete evidence: {event}");
        }
    }
    Ok(())
}

fn target_authorization_request() -> GatewayExternalActionTransportRequest {
    let authorization = ExternalActionAuthorizationRequest {
        session: ExternalActionSession {
            session_id: "session-204".into(),
            run_id: "run-204".into(),
            tenant_id: TARGET_TENANT_ID.into(),
            workspace_id: "workspace-204".into(),
            worker_id: "worker-204".into(),
            isolation_backend: "firecracker".into(),
            adapter_name: "native-harness".into(),
            adapter_version: "test".into(),
            framework: ExternalActionFramework::NativeHarness,
            mode: ExternalActionMode::Managed,
        },
        action: ExternalActionSpec::McpTool {
            server_name: "customer-crm".into(),
            tool_name: "lookup".into(),
            arguments_policy: "exact_arguments".into(),
            arguments: json!({"customer_id": "customer-204"}),
        },
        high_risk: false,
    };
    GatewayExternalActionTransportRequest {
        request_id: authorization.stable_request_id(),
        authorization,
    }
}

fn expect_status(
    gateway_addr: &str,
    method: &str,
    path: &str,
    body: &str,
    expected: &[u16],
) -> Result<()> {
    let headers = if body.is_empty() {
        &[ADMIN_AUTH][..]
    } else {
        &[ADMIN_AUTH, JSON_CONTENT][..]
    };
    let response = http_request_addr(gateway_addr, method, path, headers, body)?;
    if !expected.contains(&response.status) {
        bail!(
            "{method} {path} expected status {expected:?}, got {}; raw: {}",
            response.status,
            response.raw
        );
    }
    Ok(())
}

fn target_capability_supabase_config(
    gateway_addr: &str,
    schema: &str,
    authorizer_socket: &Path,
    tls_mode: &str,
    ca_path: Option<&Path>,
) -> Result<String> {
    if !matches!(
        tls_mode,
        "disable" | "prefer" | "require" | "verify_ca" | "verify_full"
    ) {
        bail!("unsupported Supabase TLS mode {tls_mode}");
    }
    let ca = ca_path
        .map(|path| format!("postgres_tls_ca_cert_path = {:?}\n", path.to_string_lossy()))
        .unwrap_or_default();
    Ok(format!(
        r#"listen = "{gateway_addr}"

[storage]
provider = "supabase"
required = true
provider_order = ["supabase", "postgres"]
supabase_dsn_env = "FERROGATE_SUPABASE_DSN"
postgres_pool_size = 2
postgres_pool_acquire_timeout_millis = 30000
postgres_tls_mode = "{tls_mode}"
{ca}postgres_connect_timeout_secs = 10
postgres_statement_timeout_millis = 30000
postgres_schema = "{schema}"
postgres_search_path = ["public"]
migration_mode = "auto"

[[api_keys]]
id = "admin"
name = "Target capability live admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
platform_operator = true

[agent_runtime]
enabled = true
provider = "managed_worker"

[agent_runtime.managed_worker]
external_action_authorizer_socket = {:?}
external_action_authorizer_max_requests = 3
policy_revision = "target-supabase-1"
class_only_policy_mode = "deny"

[[agent_runtime.managed_worker.target_grants]]
selector_id = "customer-lookup"
permission_key = "{TARGET_PERMISSION_KEY}"
action = "mcp_tool"
[agent_runtime.managed_worker.target_grants.selector]
kind = "mcp"
server = "customer-crm"
tool = "lookup"
risk = "read"
allow_extra_arguments = false
[agent_runtime.managed_worker.target_grants.selector.argument_schema]
kind = "object"
[agent_runtime.managed_worker.target_grants.selector.argument_schema.fields.customer_id]
kind = "string"
"#,
        authorizer_socket.to_string_lossy()
    ))
}

struct GatewayGuard {
    child: Child,
}

impl GatewayGuard {
    fn start(
        binary: &Path,
        config: &Path,
        gateway_addr: &str,
        authorizer_socket: &Path,
        dsn: &str,
    ) -> Result<Self> {
        let child = Command::new(binary)
            .args(["run", "--config"])
            .arg(config)
            .env("FERROGATE_SUPABASE_DSN", dsn)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("failed to start {}", binary.display()))?;
        let mut guard = Self { child };
        guard.wait_for_readiness(gateway_addr, authorizer_socket)?;
        Ok(guard)
    }

    fn wait_for_readiness(&mut self, gateway_addr: &str, socket: &Path) -> Result<()> {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < Duration::from_secs(180) {
            if let Some(status) = self.child.try_wait()? {
                bail!("FerroGate exited before target capability readiness: {status}");
            }
            match http_request_addr(gateway_addr, "GET", "/healthz", &[], "") {
                Ok(response) if response.status == 200 && socket.exists() => return Ok(()),
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("timed out waiting for target capability gateway: {last}")
    }
}

impl Drop for GatewayGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct SupabaseRbacEvidence {
    client: LiveSupabaseClient,
    schema: String,
}

impl SupabaseRbacEvidence {
    fn connect(args: &SupabaseLiveRestartArgs, schema: String) -> Result<Self> {
        Ok(Self {
            client: connect_live_supabase(args)?,
            schema,
        })
    }

    fn verify_graph(&mut self, expected_present: bool) -> Result<()> {
        let row = self.client.query_opt(
            &format!(
                "SELECT p.key, r.slug, r.permission_keys_json::text, b.tenant_id \
                 FROM \"{}\".permissions p \
                 JOIN \"{}\".roles r ON r.id = $2 \
                 JOIN \"{}\".tenant_role_bindings b ON b.role_id = r.id \
                 WHERE p.id = $1 AND b.tenant_id = $3",
                self.schema, self.schema, self.schema
            ),
            &[&TARGET_PERMISSION_ID, &TARGET_ROLE_ID, &TARGET_TENANT_ID],
        )?;
        if expected_present {
            let row = row.context("Supabase RBAC graph was not durably written")?;
            let key: String = row.get(0);
            let slug: String = row.get(1);
            let permissions: String = row.get(2);
            let tenant_id: String = row.get(3);
            if key != TARGET_PERMISSION_KEY
                || slug != "operator-invented-role-204"
                || tenant_id != TARGET_TENANT_ID
                || !permissions.contains(TARGET_PERMISSION_KEY)
            {
                bail!(
                    "Supabase RBAC graph did not preserve arbitrary role data: key={key} slug={slug} tenant={tenant_id} permissions={permissions}"
                );
            }
        } else if row.is_some() {
            bail!("Supabase RBAC graph remained after explicit cleanup");
        }
        if !expected_present {
            for (table, column, value) in [
                ("permissions", "id", TARGET_PERMISSION_ID),
                ("roles", "id", TARGET_ROLE_ID),
                ("tenant_role_bindings", "tenant_id", TARGET_TENANT_ID),
            ] {
                let count: i64 = self
                    .client
                    .query_one(
                        &format!(
                            "SELECT COUNT(*) FROM \"{}\".{table} WHERE {column} = $1",
                            self.schema
                        ),
                        &[&value],
                    )?
                    .get(0);
                if count != 0 {
                    bail!("Supabase RBAC cleanup left {count} matching row(s) in {table}");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "target_capability_test.rs"]
mod target_capability_test;
