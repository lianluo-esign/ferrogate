// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Live Supabase end-to-end coverage for the Guardrail detector runtime.

use crate::{
    cli::SupabaseLiveRestartArgs,
    http::{free_addr, http_request_addr, HttpResponse},
    mocks::read_http_request,
};
use anyhow::{bail, Context, Result};
use native_tls::{Certificate, TlsConnector};
use postgres::{config::SslMode, Client, Config as PostgresConfig};
use postgres_native_tls::MakeTlsConnector;
use serde_json::Value;
use std::{
    env, fs,
    io::Write,
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const CLIENT_AUTH: &str = "Authorization: Bearer guardrail-client-secret";
const DYNAMIC_CLIENT_AUTH: &str = "Authorization: Bearer guardrail-dynamic-client-secret";
const ADMIN_AUTH: &str = "Authorization: Bearer guardrail-admin-secret";
const JSON_CONTENT: &str = "Content-Type: application/json";
const DETECTOR_SECRET: &str = "guardrail-detector-e2e-secret";
const DYNAMIC_TENANT_ID: &str = "org_dynamic_guardrail_e2e";
const GUARDRAIL_MANAGER_ROLE_ID: &str = "role-guardrail-manager-e2e";
const GUARDRAIL_ACTIONS: [(&str, &str); 6] = [
    ("guardrails.policy.read", "Read Guardrail policies"),
    (
        "guardrails.policy.create_revision",
        "Create Guardrail policy revisions",
    ),
    (
        "guardrails.policy.activate",
        "Activate Guardrail policy revisions",
    ),
    (
        "guardrails.policy.rollback",
        "Roll back Guardrail policy revisions",
    ),
    (
        "guardrails.policy.archive",
        "Archive Guardrail policy revisions",
    ),
    ("guardrails.policy.dry_run", "Dry-run Guardrail policies"),
];

pub(crate) fn run_guardrail_supabase(args: &SupabaseLiveRestartArgs) -> Result<()> {
    if args.supabase_dsn.trim().is_empty() {
        bail!("--supabase-dsn must not be empty");
    }
    if !args.local.ferrogate_bin.exists() {
        bail!(
            "ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli` first or pass --ferrogate-bin",
            args.local.ferrogate_bin.display()
        );
    }

    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?
        .as_millis();
    let schema = format!("ferrogate_guardrail_e2e_{suffix}");
    let mut evidence = SupabaseEvidence::connect(args, schema.clone())?;

    let gateway_addr = free_addr()?;
    let provider_stop = Arc::new(AtomicBool::new(false));
    let (provider_addr, provider_handle) = spawn_guardrail_provider(Arc::clone(&provider_stop))
        .context("start local model provider")?;
    let mut provider = ProviderGuard::new(provider_stop, provider_handle);
    let mut detector = MockDetector::start(2)?;
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("guardrail-supabase.yaml");
    fs::write(
        &config_path,
        guardrail_supabase_config(&gateway_addr, &provider_addr, &detector.addr, &schema, args)?,
    )?;

    let gateway = GatewayGuard::start(
        &args.local.ferrogate_bin,
        &config_path,
        &gateway_addr,
        args.supabase_dsn.trim(),
    )?;

    let detected = send_chat(&gateway_addr, "my email is pii@example.com")?;
    assert_json_error(&detected, 403, "guardrail_pii_detected")?;

    let allowed = send_chat(&gateway_addr, "ordinary safe request")?;
    if allowed.status != 200 {
        bail!(
            "safe Guardrail request expected 200, got {}; raw: {}",
            allowed.status,
            allowed.raw
        );
    }
    let allowed_body: Value = serde_json::from_str(&allowed.body)
        .with_context(|| format!("safe provider response was not JSON: {}", allowed.body))?;
    if allowed_body["choices"][0]["message"]["content"] != "ok" {
        bail!("safe request did not reach the local model provider");
    }

    let detector_requests = detector.join()?;
    if detector_requests.len() != 2 {
        bail!(
            "Guardrail detector expected 2 requests, got {}",
            detector_requests.len()
        );
    }
    for request in &detector_requests {
        let lowercase = request.to_ascii_lowercase();
        if !lowercase.contains(&format!(
            "authorization: bearer {}",
            DETECTOR_SECRET.to_ascii_lowercase()
        )) {
            bail!("Guardrail detector request did not contain the resolved bearer credential");
        }
        if !request.contains("\"contract_version\":1")
            || !request.contains("\"organization_id\":\"org_guardrail_e2e\"")
            || !request.contains("\"model\":\"fast-chat\"")
            || !request.contains("\"provider\":\"openai\"")
        {
            bail!("Guardrail detector request omitted required execution context");
        }
    }

    // The detector listener is now closed. A new request must fail closed and
    // generate both runtime metrics and durable Supabase evidence.
    let unavailable = send_chat(&gateway_addr, "detector must now fail closed")?;
    assert_json_error(&unavailable, 403, "guardrail_provider_unavailable")?;
    let request_id = response_header(&unavailable, "x-request-id")
        .context("Guardrail failure response omitted x-request-id")?;

    let metrics = http_request_addr(&gateway_addr, "GET", "/metrics", &[ADMIN_AUTH], "")?;
    if metrics.status != 200
        || !metrics
            .body
            .lines()
            .any(|line| line == "ferrogate_guardrail_detector_errors_total 1")
    {
        bail!(
            "Guardrail detector failure metric missing or incorrect: {}",
            metrics.body
        );
    }

    evidence.wait_for_detector_error(&request_id)?;

    let tenant_create = http_request_addr(
        &gateway_addr,
        "POST",
        "/admin/v1/guardrail-policies",
        &[DYNAMIC_CLIENT_AUTH, JSON_CONTENT],
        &dynamic_policy_body(
            Some("tenant-must-not-create"),
            "forbidden",
            "tenant_guardrail",
        ),
    )?;
    assert_json_error(&tenant_create, 403, "guardrail_rbac_denied")?;

    configure_guardrail_manager_role(&gateway_addr)?;
    evidence.verify_guardrail_rbac_binding(true)?;

    let cross_tenant_create = dynamic_json_request(
        &gateway_addr,
        "POST",
        "/admin/v1/guardrail-policies",
        &dynamic_policy_body_for_tenant(
            Some("cross-tenant-policy"),
            "other_org",
            "forbidden",
            "cross_tenant_guardrail",
        ),
    )?;
    assert_json_error(&cross_tenant_create, 403, "guardrail_policy_scope_denied")?;

    let create_v1 = dynamic_json_request(
        &gateway_addr,
        "POST",
        "/admin/v1/guardrail-policies",
        &dynamic_policy_body(
            Some("dynamic-supabase-policy"),
            "dynamic-secret-v1",
            "dynamic_guardrail_v1",
        ),
    )?;
    assert_policy_revision_response(&create_v1, 201, 1, "draft")?;

    let tenant_list =
        dynamic_json_request(&gateway_addr, "GET", "/admin/v1/guardrail-policies", "")?;
    if tenant_list.status != 200 {
        bail!(
            "Guardrail manager could not list policies: {}",
            tenant_list.raw
        );
    }
    let tenant_list_body: Value = serde_json::from_str(&tenant_list.body)?;
    let visible = tenant_list_body["data"]
        .as_array()
        .context("Guardrail policy list omitted data")?;
    if visible.len() != 1 || visible[0]["policy_id"] != "dynamic-supabase-policy" {
        bail!("tenant Guardrail list leaked another tenant's policies: {tenant_list_body}");
    }

    let archive_draft = dynamic_json_request(
        &gateway_addr,
        "POST",
        "/admin/v1/guardrail-policies",
        &dynamic_policy_body_for_tenant(
            Some("dynamic-archive-policy"),
            DYNAMIC_TENANT_ID,
            "archive-only",
            "archive_only_guardrail",
        ),
    )?;
    if archive_draft.status != 201 {
        bail!(
            "failed to create Guardrail archive fixture: {}",
            archive_draft.raw
        );
    }
    let archived = dynamic_json_request(
        &gateway_addr,
        "DELETE",
        "/admin/v1/guardrail-policies/dynamic-archive-policy/revisions/1",
        "",
    )?;
    if archived.status != 200 {
        bail!(
            "Guardrail manager could not archive a draft: {}",
            archived.raw
        );
    }

    let dry_run = dynamic_json_request(
        &gateway_addr,
        "POST",
        "/admin/v1/guardrail-policies/dynamic-supabase-policy/dry-run",
        &serde_json::json!({
            "revision": 1,
            "stage": "request",
            "organization_id": "org_dynamic_guardrail_e2e",
            "model": "fast-chat",
            "provider": "openai",
            "text": "contains dynamic-secret-v1"
        })
        .to_string(),
    )?;
    assert_dry_run(&dry_run)?;

    let activate_v1 = dynamic_json_request(
        &gateway_addr,
        "POST",
        "/admin/v1/guardrail-policies/dynamic-supabase-policy/activate",
        r#"{"revision":1}"#,
    )?;
    assert_binding_response(&activate_v1, 1, false)?;
    let blocked_v1 = send_dynamic_chat(&gateway_addr, "contains dynamic-secret-v1")?;
    assert_json_error(&blocked_v1, 403, "dynamic_guardrail_v1")?;

    drop(gateway);
    let gateway = GatewayGuard::start(
        &args.local.ferrogate_bin,
        &config_path,
        &gateway_addr,
        args.supabase_dsn.trim(),
    )?;
    let blocked_v1_after_restart =
        send_dynamic_chat(&gateway_addr, "contains dynamic-secret-v1 after restart")?;
    assert_json_error(&blocked_v1_after_restart, 403, "dynamic_guardrail_v1")?;

    let create_v2 = dynamic_json_request(
        &gateway_addr,
        "POST",
        "/admin/v1/guardrail-policies/dynamic-supabase-policy/revisions",
        &dynamic_policy_body(None, "dynamic-secret-v2", "dynamic_guardrail_v2"),
    )?;
    assert_policy_revision_response(&create_v2, 201, 2, "draft")?;
    let activate_v2 = dynamic_json_request(
        &gateway_addr,
        "POST",
        "/admin/v1/guardrail-policies/dynamic-supabase-policy/activate",
        r#"{"revision":2}"#,
    )?;
    assert_binding_response(&activate_v2, 2, false)?;

    drop(gateway);
    let gateway = GatewayGuard::start(
        &args.local.ferrogate_bin,
        &config_path,
        &gateway_addr,
        args.supabase_dsn.trim(),
    )?;
    let blocked_v2 = send_dynamic_chat(&gateway_addr, "contains dynamic-secret-v2")?;
    assert_json_error(&blocked_v2, 403, "dynamic_guardrail_v2")?;
    let v1_allowed = send_dynamic_chat(&gateway_addr, "contains dynamic-secret-v1")?;
    assert_provider_success(&v1_allowed, "revision 1 should be inactive")?;

    let rollback_v1 = dynamic_json_request(
        &gateway_addr,
        "POST",
        "/admin/v1/guardrail-policies/dynamic-supabase-policy/rollback",
        r#"{"revision":1}"#,
    )?;
    assert_binding_response(&rollback_v1, 1, true)?;

    drop(gateway);
    let gateway = GatewayGuard::start(
        &args.local.ferrogate_bin,
        &config_path,
        &gateway_addr,
        args.supabase_dsn.trim(),
    )?;
    let restart_probe = http_request_addr(&gateway_addr, "GET", "/metrics", &[ADMIN_AUTH], "")?;
    if restart_probe.status != 200 {
        bail!("post-rollback restart probe failed: {}", restart_probe.raw);
    }
    let rollback_block = send_dynamic_chat(&gateway_addr, "contains dynamic-secret-v1")?;
    assert_json_error(&rollback_block, 403, "dynamic_guardrail_v1")?;
    let v2_allowed = send_dynamic_chat(&gateway_addr, "contains dynamic-secret-v2")?;
    assert_provider_success(&v2_allowed, "revision 2 should be inactive after rollback")?;

    evidence.wait_for_policy_lifecycle()?;
    let unbind = admin_json_request(
        &gateway_addr,
        "DELETE",
        &format!("/admin/v1/tenant-roles/{DYNAMIC_TENANT_ID}/{GUARDRAIL_MANAGER_ROLE_ID}"),
        "",
    )?;
    if unbind.status != 200 {
        bail!("failed to revoke Guardrail manager role: {}", unbind.raw);
    }
    evidence.verify_guardrail_rbac_binding(false)?;
    let denied_after_unbind = dynamic_json_request(
        &gateway_addr,
        "POST",
        "/admin/v1/guardrail-policies/dynamic-supabase-policy/revisions",
        &dynamic_policy_body(None, "dynamic-secret-v3", "dynamic_guardrail_v3"),
    )?;
    assert_json_error(&denied_after_unbind, 403, "guardrail_rbac_denied")?;
    let provider_requests = provider.join()?;
    let chat_requests = provider_requests
        .iter()
        .filter(|request| request.contains("POST /v1/chat/completions "))
        .collect::<Vec<_>>();
    if chat_requests.len() != 3
        || !chat_requests[0].contains("ordinary safe request")
        || !chat_requests[1].contains("dynamic-secret-v1")
        || !chat_requests[2].contains("dynamic-secret-v2")
    {
        bail!(
            "provider dispatch count/content proved neither dry-run isolation nor revision switching: {provider_requests:?}"
        );
    }

    drop(gateway);
    evidence.cleanup()?;
    println!("guardrail-supabase scenario passed");
    Ok(())
}

fn send_chat(addr: &str, content: &str) -> Result<HttpResponse> {
    send_chat_with_auth(addr, content, CLIENT_AUTH)
}

fn send_dynamic_chat(addr: &str, content: &str) -> Result<HttpResponse> {
    send_chat_with_auth(addr, content, DYNAMIC_CLIENT_AUTH)
}

fn send_chat_with_auth(addr: &str, content: &str, auth: &str) -> Result<HttpResponse> {
    let body = serde_json::json!({
        "model": "fast-chat",
        "messages": [{"role": "user", "content": content}],
        "stream": false
    })
    .to_string();
    http_request_addr(
        addr,
        "POST",
        "/v1/chat/completions",
        &[auth, JSON_CONTENT],
        &body,
    )
}

fn admin_json_request(addr: &str, method: &str, path: &str, body: &str) -> Result<HttpResponse> {
    http_request_addr(addr, method, path, &[ADMIN_AUTH, JSON_CONTENT], body)
}

fn dynamic_json_request(addr: &str, method: &str, path: &str, body: &str) -> Result<HttpResponse> {
    http_request_addr(
        addr,
        method,
        path,
        &[DYNAMIC_CLIENT_AUTH, JSON_CONTENT],
        body,
    )
}

fn configure_guardrail_manager_role(addr: &str) -> Result<()> {
    let tenant = admin_json_request(
        addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &serde_json::json!({
            "id": DYNAMIC_TENANT_ID,
            "name": "Dynamic Guardrail E2E",
            "slug": "dynamic-guardrail-e2e",
            "plan_id": "free"
        })
        .to_string(),
    )?;
    if tenant.status != 200 && tenant.status != 201 {
        bail!("failed to create Guardrail RBAC tenant: {}", tenant.raw);
    }

    for (index, (key, name)) in GUARDRAIL_ACTIONS.iter().enumerate() {
        let permission = admin_json_request(
            addr,
            "POST",
            "/admin/v1/permissions",
            &serde_json::json!({
                "id": format!("permission-guardrail-e2e-{index}"),
                "key": key,
                "name": name
            })
            .to_string(),
        )?;
        if permission.status != 200 {
            bail!(
                "failed to create Guardrail permission {key}: {}",
                permission.raw
            );
        }
    }

    let role = admin_json_request(
        addr,
        "POST",
        "/admin/v1/roles",
        &serde_json::json!({
            "id": GUARDRAIL_MANAGER_ROLE_ID,
            "name": "Guardrail Manager",
            "slug": "guardrail_manager",
            "permission_keys": GUARDRAIL_ACTIONS
                .iter()
                .map(|(key, _)| *key)
                .collect::<Vec<_>>()
        })
        .to_string(),
    )?;
    if role.status != 200 {
        bail!("failed to create Guardrail manager role: {}", role.raw);
    }

    let binding = admin_json_request(
        addr,
        "POST",
        &format!("/admin/v1/tenant-roles/{DYNAMIC_TENANT_ID}"),
        &serde_json::json!({"role_id": GUARDRAIL_MANAGER_ROLE_ID}).to_string(),
    )?;
    if binding.status != 200 {
        bail!("failed to bind Guardrail manager role: {}", binding.raw);
    }
    Ok(())
}

fn dynamic_policy_body(policy_id: Option<&str>, keyword: &str, code: &str) -> String {
    dynamic_policy_body_for_tenant(policy_id, DYNAMIC_TENANT_ID, keyword, code)
}

fn dynamic_policy_body_for_tenant(
    policy_id: Option<&str>,
    tenant_id: &str,
    keyword: &str,
    code: &str,
) -> String {
    let mut policy = serde_json::json!({
        "name": "Dynamic Supabase Guardrail",
        "description": "ferrogate-test durable revision lifecycle",
        "enforced": true,
        "scope": {
            "organization_ids": [tenant_id],
            "models": ["fast-chat"],
            "providers": ["openai"]
        },
        "checks": [{
            "id": "keyword",
            "enabled": true,
            "stage": "request",
            "detector": {"kind": "local", "keywords": [keyword]}
        }],
        "aggregation": {"type": "all"},
        "execution": "parallel",
        "mode": "enforce",
        "streaming": "buffer_and_enforce",
        "on_pass": [{"kind": "allow"}],
        "on_fail": [{
            "kind": "block",
            "code": code,
            "message": "blocked by dynamic Supabase Guardrail"
        }],
        "on_error": [{
            "kind": "block",
            "code": "dynamic_guardrail_unavailable",
            "message": "dynamic Supabase Guardrail unavailable"
        }],
        "deadline_ms": 1000
    });
    if let Some(policy_id) = policy_id {
        policy["policy_id"] = Value::String(policy_id.to_string());
    }
    policy.to_string()
}

fn assert_policy_revision_response(
    response: &HttpResponse,
    status: u16,
    revision: u64,
    expected_state: &str,
) -> Result<()> {
    if response.status != status {
        bail!(
            "Guardrail revision expected status {status}, got {}; raw: {}",
            response.status,
            response.raw
        );
    }
    let body: Value = serde_json::from_str(&response.body)?;
    if body["object"] != "guardrail_policy_revision"
        || body["policy"]["policy_id"] != "dynamic-supabase-policy"
        || body["policy"]["revision"] != revision
        || body["policy"]["status"] != expected_state
    {
        bail!("Guardrail revision response was incomplete: {body}");
    }
    Ok(())
}

fn assert_dry_run(response: &HttpResponse) -> Result<()> {
    if response.status != 200 {
        bail!("Guardrail dry-run failed: {}", response.raw);
    }
    let body: Value = serde_json::from_str(&response.body)?;
    if body["policy_revision"] != "dynamic-supabase-policy@1"
        || body["selected"] != true
        || body["result"] != "planned"
        || body["checks"][0]["result"] != "fail"
        || body["provider_dispatched"] != false
        || body["external_action_dispatched"] != false
    {
        bail!("Guardrail dry-run did not prove side-effect isolation: {body}");
    }
    Ok(())
}

fn assert_binding_response(response: &HttpResponse, revision: u64, rollback: bool) -> Result<()> {
    if response.status != 200 {
        bail!("Guardrail binding mutation failed: {}", response.raw);
    }
    let body: Value = serde_json::from_str(&response.body)?;
    if body["policy_id"] != "dynamic-supabase-policy"
        || body["active_revision"] != revision
        || body["rollback"] != rollback
        || body["reload"]["committed"] != true
    {
        bail!("Guardrail binding response was incomplete: {body}");
    }
    Ok(())
}

fn assert_provider_success(response: &HttpResponse, context: &str) -> Result<()> {
    if response.status != 200 {
        bail!("{context}: expected provider success, got {}", response.raw);
    }
    let body: Value = serde_json::from_str(&response.body)?;
    if body["choices"][0]["message"]["content"] != "ok" {
        bail!("{context}: provider response was incomplete");
    }
    Ok(())
}

fn assert_json_error(response: &HttpResponse, status: u16, code: &str) -> Result<()> {
    if response.status != status {
        bail!(
            "Guardrail error expected status {status}, got {}; raw: {}",
            response.status,
            response.raw
        );
    }
    let body: Value = serde_json::from_str(&response.body)
        .with_context(|| format!("Guardrail error body was not JSON: {}", response.body))?;
    if body["error"]["code"] != code {
        bail!(
            "Guardrail error expected code {code}, got {}",
            body["error"]["code"]
        );
    }
    Ok(())
}

fn response_header(response: &HttpResponse, expected_name: &str) -> Option<String> {
    response.raw.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case(expected_name)
            .then(|| value.trim().to_string())
    })
}

fn guardrail_supabase_config(
    gateway_addr: &str,
    provider_addr: &str,
    detector_addr: &str,
    schema: &str,
    args: &SupabaseLiveRestartArgs,
) -> Result<String> {
    let tls_mode = match args.tls_mode.as_str() {
        "require" | "verify_ca" | "verify_full" => args.tls_mode.as_str(),
        other => bail!(
            "--tls-mode must be require, verify_ca, or verify_full for live Supabase, got {other}"
        ),
    };
    let ca_path = args
        .tls_ca_cert_path
        .as_ref()
        .map(|path| {
            format!(
                "  postgres_tls_ca_cert_path: {}\n",
                yaml_string(&path.to_string_lossy())
            )
        })
        .unwrap_or_default();
    Ok(format!(
        r#"listen: {gateway_addr:?}
cluster:
  enabled: true
  cluster_id: "guardrail-supabase-e2e"
  node_id: "guardrail-supabase-node"
  node_region: "local"
  node_zone: "local-a"
  state_backend: "local"
  counter_backend: "local"
storage:
  provider: "supabase"
  required: true
  provider_order:
    - "supabase"
    - "postgres"
  supabase_dsn_env: "FERROGATE_SUPABASE_DSN"
  postgres_pool_size: 2
  postgres_tls_mode: "{tls_mode}"
{ca_path}  postgres_connect_timeout_secs: 10
  postgres_statement_timeout_millis: 30000
  postgres_schema: "{schema}"
  postgres_search_path:
    - "public"
  migration_mode: "auto"
providers:
  - name: "openai"
    kind: "openai"
    base_url: "http://{provider_addr}/v1"
    api_key_env: "FERROGATE_PROVIDER_SECRET"
models:
  - name: "fast-chat"
    provider: "openai"
    provider_model: "gpt-4o-mini"
    capabilities: ["chat"]
api_keys:
  - id: "guardrail-e2e-client"
    name: "Guardrail E2E client"
    key: "guardrail-client-secret"
    scopes: ["models.read", "chat.completions", "admin.read", "admin.write"]
    allowed_models: ["fast-chat"]
    organization_id: "org_guardrail_e2e"
    project_id: "project_guardrail_e2e"
  - id: "guardrail-dynamic-client"
    name: "Guardrail dynamic policy E2E client"
    key: "guardrail-dynamic-client-secret"
    scopes: ["models.read", "chat.completions", "admin.read", "admin.write"]
    allowed_models: ["fast-chat"]
    organization_id: "org_dynamic_guardrail_e2e"
    project_id: "project_dynamic_guardrail_e2e"
  - id: "guardrail-e2e-admin"
    name: "Guardrail E2E admin"
    key: "guardrail-admin-secret"
    scopes: ["admin.read", "admin.write"]
guardrails:
  - id: "e2e-pii-detector"
    name: "E2E PII detector"
    enabled: true
    stage: "request"
    organization_ids: ["org_guardrail_e2e"]
    models: ["fast-chat"]
    providers: ["openai"]
    provider: "custom_http"
    provider_endpoint: "http://{detector_addr}/check"
    provider_timeout_ms: 250
    provider_on_error: "block"
    provider_max_concurrency: 2
    provider_circuit_failure_threshold: 2
    provider_circuit_cooldown_ms: 1000
    provider_max_retries: 0
    provider_max_payload_bytes: 65536
    provider_max_response_bytes: 16384
    provider_allow_private_network: true
    provider_secret_ref: "env://FERROGATE_TEST_GUARDRAIL_SECRET"
    effect: "deny"
    code: "guardrail_pii_detected"
    message: "request blocked by E2E detector"
"#
    ))
}

fn yaml_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

struct GatewayGuard {
    child: Child,
}

impl GatewayGuard {
    fn start(
        binary: &Path,
        config_path: &Path,
        gateway_addr: &str,
        supabase_dsn: &str,
    ) -> Result<Self> {
        let child = Command::new(binary)
            .args(["run", "--config"])
            .arg(config_path)
            .env("FERROGATE_SUPABASE_DSN", supabase_dsn)
            .env("FERROGATE_PROVIDER_SECRET", "provider-secret")
            .env("FERROGATE_TEST_GUARDRAIL_SECRET", DETECTOR_SECRET)
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
        while started.elapsed() < Duration::from_secs(60) {
            if let Some(status) = self.child.try_wait()? {
                bail!("FerroGate exited before Guardrail E2E readiness: {status}");
            }
            match http_request_addr(gateway_addr, "GET", "/healthz", &[], "") {
                Ok(response) if response.status == 200 => return Ok(()),
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("timed out waiting for Guardrail E2E gateway: {last}")
    }
}

impl Drop for GatewayGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct ProviderGuard {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Vec<String>>>,
}

fn spawn_guardrail_provider(stop: Arc<AtomicBool>) -> Result<(String, JoinHandle<Vec<String>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?.to_string();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let Ok(request) = read_http_request(&mut stream) else {
                        continue;
                    };
                    let body = r#"{"id":"chatcmpl_guardrail_e2e","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    requests.push(request);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        requests
    });
    Ok((addr, handle))
}

impl ProviderGuard {
    fn new(stop: Arc<AtomicBool>, handle: JoinHandle<Vec<String>>) -> Self {
        Self {
            stop,
            handle: Some(handle),
        }
    }

    fn join(&mut self) -> Result<Vec<String>> {
        self.stop.store(true, Ordering::Relaxed);
        self.handle
            .take()
            .context("provider mock join handle missing")?
            .join()
            .map_err(|_| anyhow::anyhow!("provider mock thread panicked"))
    }
}

impl Drop for ProviderGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct MockDetector {
    addr: String,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Vec<String>>>,
}

impl MockDetector {
    fn start(expected_requests: usize) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?.to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            let started = Instant::now();
            while requests.len() < expected_requests
                && started.elapsed() < Duration::from_secs(60)
                && !server_stop.load(Ordering::Relaxed)
            {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let Ok(request) = read_http_request(&mut stream) else {
                            continue;
                        };
                        let body = if request.contains("pii@example.com") {
                            r#"{"verdict":"fail","findings":[{"category":"pii","severity":"high","matched_text":"pii@example.com"}],"patches":[],"detector_version":"e2e-1"}"#
                        } else {
                            r#"{"verdict":"pass","findings":[],"patches":[],"detector_version":"e2e-1"}"#
                        };
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        requests.push(request);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
            requests
        });
        Ok(Self {
            addr,
            stop,
            handle: Some(handle),
        })
    }

    fn join(&mut self) -> Result<Vec<String>> {
        self.handle
            .take()
            .context("Guardrail detector mock join handle missing")?
            .join()
            .map_err(|_| anyhow::anyhow!("Guardrail detector mock thread panicked"))
    }
}

impl Drop for MockDetector {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct SupabaseEvidence {
    client: Client,
    schema: String,
    cleaned: bool,
}

impl SupabaseEvidence {
    fn connect(args: &SupabaseLiveRestartArgs, schema: String) -> Result<Self> {
        if !schema
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            bail!("generated Supabase schema contains invalid characters");
        }
        let mut config = PostgresConfig::from_str(args.supabase_dsn.trim())
            .context("failed to parse Supabase PostgreSQL DSN")?;
        config.connect_timeout(Duration::from_secs(10));
        config.ssl_mode(SslMode::Require);
        let mut tls = TlsConnector::builder();
        if let Some(path) = args.tls_ca_cert_path.as_ref() {
            let bytes = fs::read(path)
                .with_context(|| format!("failed to read Supabase CA file {}", path.display()))?;
            let certificate = Certificate::from_pem(&bytes)
                .or_else(|_| Certificate::from_der(&bytes))
                .context("failed to parse Supabase CA certificate")?;
            tls.add_root_certificate(certificate);
        }
        match args.tls_mode.as_str() {
            "verify_full" => {}
            "verify_ca" => {
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
        let client = config
            .connect(connector)
            .context("failed to connect to live Supabase PostgreSQL")?;
        Ok(Self {
            client,
            schema,
            cleaned: false,
        })
    }

    fn wait_for_detector_error(&mut self, request_id: &str) -> Result<()> {
        let audit_query = format!(
            "SELECT action, target, outcome, tenant, audit_json::text FROM \"{}\".audit_events WHERE request_id = $1 AND action = 'guardrail.detector_error'",
            self.schema
        );
        let request_query = format!(
            "SELECT status_code, error_code, request_json::text FROM \"{}\".request_logs WHERE request_id = $1",
            self.schema
        );
        let started = Instant::now();
        let mut last = "Supabase evidence row not visible yet".to_string();
        while started.elapsed() < Duration::from_secs(15) {
            match self.client.query_opt(&audit_query, &[&request_id]) {
                Ok(Some(audit_row)) => {
                    let action: String = audit_row.get(0);
                    let target: Option<String> = audit_row.get(1);
                    let outcome: String = audit_row.get(2);
                    let tenant: Option<String> = audit_row.get(3);
                    let audit_json: String = audit_row.get(4);
                    let audit: Value = serde_json::from_str(&audit_json)
                        .context("Supabase Guardrail audit_json was invalid")?;
                    if action != "guardrail.detector_error"
                        || target.as_deref() != Some("e2e-pii-detector@1/static-check")
                        || outcome != "blocked"
                        || tenant.as_deref()
                            != Some(
                                "org:org_guardrail_e2e|team:|project:project_guardrail_e2e|workspace:|user:|api_key:guardrail-e2e-client",
                            )
                        || audit["request_id"] != request_id
                        || audit["tenant"]["organization_id"] != "org_guardrail_e2e"
                    {
                        bail!("Supabase Guardrail detector audit evidence was incomplete");
                    }

                    let request_row = self
                        .client
                        .query_opt(&request_query, &[&request_id])
                        .context("failed to read Guardrail request evidence from Supabase")?
                        .context("Supabase omitted the Guardrail failure request log")?;
                    let status_code: Option<i32> = request_row.get(0);
                    let error_code: Option<String> = request_row.get(1);
                    let request_json: String = request_row.get(2);
                    let request: Value = serde_json::from_str(&request_json)
                        .context("Supabase Guardrail request_json was invalid")?;
                    if status_code != Some(403)
                        || error_code.as_deref() != Some("guardrail_provider_unavailable")
                        || request["tenant"]["organization_id"] != "org_guardrail_e2e"
                    {
                        bail!("Supabase Guardrail request evidence was incomplete");
                    }
                    return Ok(());
                }
                Ok(None) => {}
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(150));
        }
        bail!("timed out reading Guardrail evidence directly from Supabase: {last}")
    }

    fn verify_guardrail_rbac_binding(&mut self, expected_bound: bool) -> Result<()> {
        let permission_count: i64 = self
            .client
            .query_one(
                &format!(
                    "SELECT count(*) FROM \"{}\".permissions WHERE key LIKE 'guardrails.policy.%'",
                    self.schema
                ),
                &[],
            )?
            .get(0);
        if permission_count != GUARDRAIL_ACTIONS.len() as i64 {
            bail!(
                "Supabase permission catalog expected {} Guardrail actions, got {permission_count}",
                GUARDRAIL_ACTIONS.len()
            );
        }

        let role_row = self
            .client
            .query_opt(
                &format!(
                    "SELECT slug, permission_keys_json::text FROM \"{}\".roles WHERE id = $1",
                    self.schema
                ),
                &[&GUARDRAIL_MANAGER_ROLE_ID],
            )?
            .context("Supabase omitted the Guardrail manager role")?;
        let slug: String = role_row.get(0);
        let permission_keys_json: String = role_row.get(1);
        let permission_keys: Vec<String> = serde_json::from_str(&permission_keys_json)?;
        if slug != "guardrail_manager"
            || !GUARDRAIL_ACTIONS
                .iter()
                .all(|(key, _)| permission_keys.iter().any(|actual| actual == key))
        {
            bail!("Supabase Guardrail role did not contain the expected action bundle");
        }

        let binding_count: i64 = self
            .client
            .query_one(
                &format!(
                    "SELECT count(*) FROM \"{}\".tenant_role_bindings WHERE tenant_id = $1 AND role_id = $2",
                    self.schema
                ),
                &[&DYNAMIC_TENANT_ID, &GUARDRAIL_MANAGER_ROLE_ID],
            )?
            .get(0);
        if (binding_count == 1) != expected_bound {
            bail!(
                "Supabase Guardrail role binding state was wrong: expected_bound={expected_bound}, count={binding_count}"
            );
        }
        Ok(())
    }

    fn wait_for_policy_lifecycle(&mut self) -> Result<()> {
        let started = Instant::now();
        let mut last = "Supabase Guardrail lifecycle rows not visible yet".to_string();
        while started.elapsed() < Duration::from_secs(15) {
            match self.verify_policy_lifecycle_once() {
                Ok(()) => return Ok(()),
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(150));
        }
        bail!("timed out verifying Guardrail policy lifecycle in Supabase: {last}")
    }

    fn verify_policy_lifecycle_once(&mut self) -> Result<()> {
        let revisions = self.client.query(
            &format!(
                "SELECT immutable_id, revision, policy_json::text FROM \"{}\".guardrail_policy_revisions WHERE policy_id = 'dynamic-supabase-policy' ORDER BY revision",
                self.schema
            ),
            &[],
        )?;
        if revisions.len() != 2 {
            bail!(
                "expected two immutable Guardrail revisions, got {}",
                revisions.len()
            );
        }
        for (index, row) in revisions.iter().enumerate() {
            let expected_revision = (index + 1) as i64;
            let immutable_id: String = row.get(0);
            let revision: i64 = row.get(1);
            let policy_json: String = row.get(2);
            let policy: Value = serde_json::from_str(&policy_json)?;
            if immutable_id != format!("dynamic-supabase-policy@{expected_revision}")
                || revision != expected_revision
                || policy["revision"] != expected_revision
                || policy["policy_id"] != "dynamic-supabase-policy"
            {
                bail!("immutable Guardrail revision metadata diverged from policy_json");
            }
        }

        let binding = self
            .client
            .query_opt(
                &format!(
                    "SELECT active_revision, archived_revisions_json::text FROM \"{}\".guardrail_policy_bindings WHERE policy_id = 'dynamic-supabase-policy'",
                    self.schema
                ),
                &[],
            )?
            .context("Guardrail policy binding was not persisted")?;
        let active_revision: Option<i64> = binding.get(0);
        let archived_json: String = binding.get(1);
        let archived: Vec<u32> = serde_json::from_str(&archived_json)?;
        if active_revision != Some(1) || archived != vec![2] {
            bail!(
                "Guardrail rollback binding was incorrect: active={active_revision:?}, archived={archived:?}"
            );
        }

        let audit_rows = self.client.query(
            &format!(
                "SELECT action, target, outcome, audit_json::text FROM \"{}\".audit_events WHERE target LIKE 'dynamic-supabase-policy@%'",
                self.schema
            ),
            &[],
        )?;
        let mut created = [false; 2];
        let mut activated = [false; 2];
        let mut rollback = false;
        let mut evaluated = [false; 2];
        let mut dry_run = false;
        for row in audit_rows {
            let action: String = row.get(0);
            let target: Option<String> = row.get(1);
            let outcome: String = row.get(2);
            let audit_json: String = row.get(3);
            if action == "guardrail.policy_dry_run" && audit_json.contains("dynamic-secret-v1") {
                bail!("Guardrail dry-run audit leaked input text");
            }
            match (action.as_str(), target.as_deref(), outcome.as_str()) {
                (
                    "guardrail.policy_revision_create",
                    Some("dynamic-supabase-policy@1"),
                    "committed",
                ) => {
                    created[0] = true;
                }
                (
                    "guardrail.policy_revision_create",
                    Some("dynamic-supabase-policy@2"),
                    "committed",
                ) => {
                    created[1] = true;
                }
                ("guardrail.policy_activate", Some("dynamic-supabase-policy@1"), "committed") => {
                    activated[0] = true;
                }
                ("guardrail.policy_activate", Some("dynamic-supabase-policy@2"), "committed") => {
                    activated[1] = true;
                }
                ("guardrail.policy_rollback", Some("dynamic-supabase-policy@1"), "committed") => {
                    rollback = true;
                }
                ("guardrail.policy_evaluate", Some("dynamic-supabase-policy@1"), "fail") => {
                    evaluated[0] = true;
                }
                ("guardrail.policy_evaluate", Some("dynamic-supabase-policy@2"), "fail") => {
                    evaluated[1] = true;
                }
                ("guardrail.policy_dry_run", Some("dynamic-supabase-policy@1"), "planned") => {
                    dry_run = true;
                }
                _ => {}
            }
        }
        if !created.into_iter().all(|seen| seen)
            || !activated.into_iter().all(|seen| seen)
            || !evaluated.into_iter().all(|seen| seen)
            || !rollback
            || !dry_run
        {
            bail!(
                "Supabase Guardrail lifecycle audit was incomplete: created={created:?}, activated={activated:?}, evaluated={evaluated:?}, rollback={rollback}, dry_run={dry_run}"
            );
        }

        let request_rows = self.client.query(
            &format!(
                "SELECT error_code FROM \"{}\".request_logs WHERE error_code IN ('dynamic_guardrail_v1', 'dynamic_guardrail_v2')",
                self.schema
            ),
            &[],
        )?;
        let mut v1 = false;
        let mut v2 = false;
        for row in request_rows {
            match row.get::<_, Option<String>>(0).as_deref() {
                Some("dynamic_guardrail_v1") => v1 = true,
                Some("dynamic_guardrail_v2") => v2 = true,
                _ => {}
            }
        }
        if !v1 || !v2 {
            bail!("Supabase request_logs omitted an enforced Guardrail revision");
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<()> {
        if self.cleaned {
            return Ok(());
        }
        self.client
            .batch_execute(&format!(
                "DROP SCHEMA IF EXISTS \"{}\" CASCADE",
                self.schema
            ))
            .context("failed to remove Guardrail E2E Supabase schema")?;
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for SupabaseEvidence {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}
