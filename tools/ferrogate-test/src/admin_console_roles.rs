// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-28
// description: Admin-console membership-role and gateway-key E2E coverage.

use crate::{
    cli::SupabaseLiveRestartArgs,
    http::{free_addr, http_request_addr},
    readiness::{require_service_ready, AUTH},
    supabase_schema::{connect_live_supabase, LiveSupabaseScenario, LiveSupabaseSchema},
};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

const JSON_CONTENT: &str = "Content-Type: application/json";
/// Readiness ceiling for this scenario's `ferrogate-auth` child, preserved from
/// the status-only loop this replaced: live Supabase startup opens a remote
/// TLS/SCRAM pool and initializes the isolated schema before the listener binds,
/// which can exceed the 30-second per-acquire ceiling once migrations are
/// included.
const AUTH_READINESS_TIMEOUT: Duration = Duration::from_secs(90);
const ADMIN_JWT_SECRET_ENV: &str = "FERROGATE_TEST_ADMIN_CONSOLE_JWT_SECRET";

pub(crate) fn run_admin_console_roles_supabase(args: &SupabaseLiveRestartArgs) -> Result<()> {
    ensure!(
        !args.supabase_dsn.trim().is_empty(),
        "--supabase-dsn must not be empty"
    );

    let mut schema = LiveSupabaseSchema::create(args, LiveSupabaseScenario::AdminConsoleRoles)?;
    {
        let mut service = AdminConsoleHarness::start(args, schema.name())?;
        prove_membership_role_gateway_keys(&service.addr, args, &schema)?;
        service.stop()?;
    }
    schema.finish()?;
    println!("admin-console-roles-supabase scenario passed");
    Ok(())
}

fn prove_membership_role_gateway_keys(
    addr: &str,
    args: &SupabaseLiveRestartArgs,
    schema: &LiveSupabaseSchema,
) -> Result<()> {
    let owner_email = format!("owner.{}@ferrogate.test", schema.run_id());
    let teammate_email = format!("teammate.{}@ferrogate.test", schema.run_id());
    let password = "ferrogate-role-e2e-password";

    let owner = register(addr, "Role E2E Owner", &owner_email, password)?;
    let owner_token = required_string(&owner, "/access_token")?;
    let owner_key = required_string(&owner, "/gateway_api_key")?;
    let owner_tenant_id = required_string(&owner, "/tenant/id")?;
    expect_key_scopes(
        addr,
        &owner_key,
        &["admin.read", "admin.write", "assets.read", "assets.write"],
    )?;

    let teammate = register(addr, "Role E2E Teammate", &teammate_email, password)?;
    let teammate_user_id = required_string(&teammate, "/user/id")?;
    let teammate_tenant_id = required_string(&teammate, "/tenant/id")?;

    let invite = request_json(
        addr,
        "POST",
        "/v1/admin/team/invite",
        &[JSON_CONTENT, &bearer_header(&owner_token)],
        &json!({"email": teammate_email, "role": "viewer"}).to_string(),
        201,
    )?;
    ensure!(
        invite["role"] == "viewer",
        "viewer invite stored the wrong role"
    );

    // Registration necessarily creates a separate tenant for an account. Remove
    // only that test-only membership so the public login flow has one unambiguous
    // target tenant and exercises the invited viewer membership end-to-end.
    let mut database = connect_live_supabase(args)?;
    let deleted = database.execute(
        &format!(
            "DELETE FROM \"{}\".admin_user_tenant_memberships \
             WHERE user_id = $1 AND tenant_id = $2",
            schema.name()
        ),
        &[&teammate_user_id, &teammate_tenant_id],
    )?;
    ensure!(
        deleted == 1,
        "expected to remove one test-only owner membership"
    );

    let invalid_path = format!("/v1/admin/team/members/{teammate_user_id}");
    let invalid = request_json(
        addr,
        "POST",
        &invalid_path,
        &[JSON_CONTENT, &bearer_header(&owner_token)],
        r#"{"role":"superuser"}"#,
        422,
    )?;
    ensure!(
        invalid["error"]["message"].as_str().is_some_and(|message| {
            message.contains("must be one of owner, admin, member, viewer")
        }),
        "invalid role did not return the typed role-domain diagnostic"
    );

    let viewer = login(addr, &teammate_email, password)?;
    expect_session_tenant_role(&viewer, &owner_tenant_id, "viewer")?;
    let viewer_key = required_string(&viewer, "/gateway_api_key")?;
    expect_key_scopes(addr, &viewer_key, &["admin.read", "assets.read"])?;

    change_role(addr, &owner_token, &teammate_user_id, "member")?;
    expect_key_revoked(addr, &viewer_key)?;
    let member = login(addr, &teammate_email, password)?;
    expect_session_tenant_role(&member, &owner_tenant_id, "member")?;
    let member_key = required_string(&member, "/gateway_api_key")?;
    expect_key_scopes(
        addr,
        &member_key,
        &["admin.read", "assets.read", "assets.write"],
    )?;

    change_role(addr, &owner_token, &teammate_user_id, "admin")?;
    expect_key_revoked(addr, &member_key)?;
    let admin = login(addr, &teammate_email, password)?;
    expect_session_tenant_role(&admin, &owner_tenant_id, "admin")?;
    let admin_key = required_string(&admin, "/gateway_api_key")?;
    expect_key_scopes(
        addr,
        &admin_key,
        &["admin.read", "admin.write", "assets.read", "assets.write"],
    )?;

    change_role(addr, &owner_token, &teammate_user_id, "viewer")?;
    expect_key_revoked(addr, &admin_key)?;
    let demoted = login(addr, &teammate_email, password)?;
    expect_session_tenant_role(&demoted, &owner_tenant_id, "viewer")?;
    let demoted_key = required_string(&demoted, "/gateway_api_key")?;
    expect_key_scopes(addr, &demoted_key, &["admin.read", "assets.read"])
}

fn register(addr: &str, organization: &str, email: &str, password: &str) -> Result<Value> {
    request_json(
        addr,
        "POST",
        "/v1/admin/register",
        &[JSON_CONTENT],
        &json!({
            "organization_name": organization,
            "email": email,
            "password": password,
            "display_name": organization,
        })
        .to_string(),
        201,
    )
}

fn login(addr: &str, email: &str, password: &str) -> Result<Value> {
    request_json(
        addr,
        "POST",
        "/v1/admin/login",
        &[JSON_CONTENT],
        &json!({"email": email, "password": password}).to_string(),
        200,
    )
}

fn change_role(addr: &str, owner_token: &str, user_id: &str, role: &str) -> Result<()> {
    let path = format!("/v1/admin/team/members/{user_id}");
    let response = request_json(
        addr,
        "POST",
        &path,
        &[JSON_CONTENT, &bearer_header(owner_token)],
        &json!({"role": role}).to_string(),
        200,
    )?;
    ensure!(
        response["role"] == role,
        "role change returned the wrong tier"
    );
    Ok(())
}

fn expect_session_tenant_role(session: &Value, tenant_id: &str, role: &str) -> Result<()> {
    ensure!(
        session["tenant"]["id"] == tenant_id,
        "login selected the wrong tenant"
    );
    ensure!(
        session["tenant"]["role"] == role,
        "login reported the wrong membership tier"
    );
    Ok(())
}

fn expect_key_scopes(addr: &str, key: &str, expected: &[&str]) -> Result<()> {
    let body = request_json(
        addr,
        "POST",
        "/v1/auth/resolve-api-key",
        &[JSON_CONTENT],
        &json!({"presented_key": key}).to_string(),
        200,
    )?;
    let scopes = body["scopes"]
        .as_array()
        .context("resolved gateway key response omitted scopes")?
        .iter()
        .map(|scope| scope.as_str().context("gateway key scope was not a string"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        scopes == expected,
        "resolved gateway key scopes were {scopes:?}, expected {expected:?}"
    );
    Ok(())
}

fn expect_key_revoked(addr: &str, key: &str) -> Result<()> {
    let body = request_json(
        addr,
        "POST",
        "/v1/auth/resolve-api-key",
        &[JSON_CONTENT],
        &json!({"presented_key": key}).to_string(),
        401,
    )?;
    ensure!(
        body["error"]["code"] == "invalid_api_key",
        "revoked session key did not fail closed"
    );
    Ok(())
}

fn request_json(
    addr: &str,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &str,
    expected_status: u16,
) -> Result<Value> {
    let response = http_request_addr(addr, method, path, headers, body)?;
    ensure!(
        response.status == expected_status,
        "{method} {path} returned status {}, expected {expected_status}; body: {}",
        response.status,
        response.body
    );
    serde_json::from_str(&response.body)
        .with_context(|| format!("{method} {path} returned non-JSON response"))
}

fn required_string(value: &Value, pointer: &str) -> Result<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .with_context(|| format!("response omitted required field {pointer}"))
}

fn bearer_header(token: &str) -> String {
    format!("Authorization: Bearer {token}")
}

struct AdminConsoleHarness {
    addr: String,
    child: Option<Child>,
}

impl AdminConsoleHarness {
    fn start(args: &SupabaseLiveRestartArgs, schema: &str) -> Result<Self> {
        let binary = &args.local.ferrogate_bin;
        ensure_binary(binary)?;
        let addr = free_addr()?;
        let mut command = Command::new(binary);
        command
            .args(["auth", "serve", "--listen", &addr])
            .env("FERROGATE_AUTH_SUPABASE_DSN", args.supabase_dsn.trim())
            .env("FERROGATE_AUTH_SUPABASE_TLS_MODE", args.tls_mode.trim())
            .env("FERROGATE_AUTH_SUPABASE_SCHEMA", schema)
            .env("FERROGATE_AUTH_SUPABASE_INIT_SCHEMA", "true")
            .env("FERROGATE_AUTH_ADMIN_JWT_SECRET_ENV", ADMIN_JWT_SECRET_ENV)
            .env(
                ADMIN_JWT_SECRET_ENV,
                "ferrogate-test-admin-console-role-signing-secret",
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(ca_path) = args.tls_ca_cert_path.as_deref() {
            command.env("FERROGATE_AUTH_SUPABASE_TLS_CA_CERT_PATH", ca_path);
        }
        let child = command
            .spawn()
            .with_context(|| format!("failed to start {} auth serve", binary.display()))?;
        let mut harness = Self {
            addr,
            child: Some(child),
        };
        harness.wait_until_ready()?;
        Ok(harness)
    }

    /// Readiness is the shared identity-checked decision (#444): `addr` comes from
    /// `free_addr()`, so a mock in a parallel harness can win it inside the
    /// release->rebind window and answer 200 to anything -- which previously
    /// started this scenario against the squatter instead of `ferrogate-auth`.
    /// The service proves itself with `service: ferrogate-auth` on `/healthz`.
    fn wait_until_ready(&mut self) -> Result<()> {
        let addr = self.addr.clone();
        require_service_ready(
            AUTH,
            self.child
                .as_mut()
                .context("auth service process is missing")?,
            &addr,
            "admin-console auth service",
            AUTH_READINESS_TIMEOUT,
        )
    }

    fn stop(&mut self) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            if child.try_wait()?.is_none() {
                child.kill()?;
            }
            let _ = child.wait();
        }
        Ok(())
    }
}

impl Drop for AdminConsoleHarness {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn ensure_binary(binary: &Path) -> Result<()> {
    ensure!(
        binary.exists(),
        "ferrogate binary does not exist at {}; build ferrogate-cli first or pass --ferrogate-bin",
        binary.display()
    );
    Ok(())
}
