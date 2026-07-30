// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Docker-free E2E coverage for config-selected Workers AI Llama Guard detection (#430).

//! End-to-end proof that the `workers_ai_llama_guard` detector is
//! operator-selectable (#430): a durable guardrail policy naming the detector is
//! created and activated through the real Admin API, the gateway builds it from
//! the `[cloudflare]` block, and live gateway traffic is allowed/blocked by the
//! verdict of a REAL HTTP round-trip to a local mock of the Workers AI
//! `/ai/run/{model}` endpoint. No Docker and no live Cloudflare account are
//! required: `cloudflare.api_base_url` points at the mock, which speaks the
//! documented Cloudflare envelope.
//!
//! Covered end-to-end:
//! - config -> Admin API create/activate -> detector construction -> engine.
//! - Bearer-token resolution and the `accounts/{account}/ai/run/{model}` wire
//!   contract (default model slug), asserted on the mock's captured requests.
//! - Composition with a native deterministic rule inside one policy
//!   (aggregation `all`): the native keyword blocks even when Llama Guard says
//!   `safe`, and both checks execute.
//! - The MLCommons category allow-list: `unsafe\nS9` passes a policy scoped to
//!   `categories: ["S2"]`, while `unsafe\nS2` is blocked by it.
//! - The #430 RBAC boundary: a tenant-scoped author cannot register the
//!   detector (mandatory host `fingerprint_secret_ref`).

use crate::{
    cli::LocalArgs,
    constants::JSON_CONTENT,
    http::{free_addr, http_request_addr, HttpResponse},
    mocks::read_http_request,
    readiness::{require_gateway_ready, GATEWAY_READINESS_TIMEOUT},
};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{
    env, fs,
    io::Write,
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const HOST_ADMIN_AUTH: &str = "Authorization: Bearer wa-llama-host-admin-secret";
const CLIENT_A_AUTH: &str = "Authorization: Bearer wa-llama-client-secret";
const CLIENT_B_AUTH: &str = "Authorization: Bearer wa-llama-categories-client-secret";
const CF_ACCOUNT_ID: &str = "wa-llama-e2e-account";
const CF_API_TOKEN: &str = "wa-llama-e2e-cf-token";
const DEFAULT_MODEL_SLUG: &str = "@cf/meta/llama-guard-3-8b";
const FINGERPRINT_SECRET: &str = "wa-llama-guard-fingerprint-secret";
const MOCK_LIFETIME: Duration = Duration::from_secs(90);

pub(crate) fn run_workers_ai_llama_guard(args: &LocalArgs) -> Result<()> {
    if !args.ferrogate_bin.exists() {
        bail!(
            "ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli` first or pass --ferrogate-bin",
            args.ferrogate_bin.display()
        );
    }

    let gateway_addr = free_addr()?;
    let mut workers_ai = MockWorkersAi::start(5)?;
    let mut provider = MockChatProvider::start(2)?;

    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("workers-ai-llama-guard.yaml");
    fs::write(
        &config_path,
        scenario_config(&gateway_addr, &provider.addr, &workers_ai.addr),
    )?;
    let _gateway = GatewayGuard::start(&args.ferrogate_bin, &config_path, &gateway_addr)?;

    // Grant client A's tenant the guardrail policy RBAC actions so the
    // host-secret authorization (not the generic action check) decides the
    // negative case below.
    grant_tenant_guardrail_role(&gateway_addr)?;

    // The #430 RBAC boundary, end-to-end: a tenant-scoped author (client A has
    // admin scopes, an organization_id, and the guardrail RBAC role) may still
    // NOT register the detector, because its mandatory fingerprint_secret_ref
    // is a host secret.
    let tenant_create = http_request_addr(
        &gateway_addr,
        "POST",
        "/admin/v1/guardrail-policies",
        &[CLIENT_A_AUTH, JSON_CONTENT],
        &llama_guard_policy_body(
            "wa-llama-tenant-forbidden",
            "org_wa_llama_e2e",
            None,
            "wa_llama_tenant_forbidden",
        ),
    )?;
    assert_json_error(
        &tenant_create,
        403,
        "guardrail_secret_ref_forbidden",
        "tenant-scoped author registered a host-secret detector",
    )?;

    // Host-operator create + activate of both durable policies through the
    // real Admin API: the plain detector policy composed with a native rule,
    // and the category-allow-list policy.
    create_and_activate(
        &gateway_addr,
        "wa-llama-guard-policy",
        &llama_guard_policy_body(
            "wa-llama-guard-policy",
            "org_wa_llama_e2e",
            None,
            "wa_llama_guard_blocked",
        ),
    )?;
    create_and_activate(
        &gateway_addr,
        "wa-llama-categories-policy",
        &llama_guard_policy_body(
            "wa-llama-categories-policy",
            "org_wa_llama_categories_e2e",
            Some(&["S2"]),
            "wa_llama_s2_blocked",
        ),
    )?;

    // Case 1 (policy A): Llama Guard says safe, native rule passes -> the
    // request reaches the model provider.
    let allowed = send_chat(&gateway_addr, CLIENT_A_AUTH, "an ordinary safe request")?;
    if allowed.status != 200 {
        bail!(
            "safe request through workers_ai_llama_guard expected 200, got {}; raw: {}",
            allowed.status,
            allowed.raw
        );
    }
    let allowed_body: Value = serde_json::from_str(&allowed.body)
        .with_context(|| format!("safe response was not JSON: {}", allowed.body))?;
    if allowed_body["choices"][0]["message"]["content"] != "ok" {
        bail!("safe request did not reach the local model provider: {allowed_body}");
    }

    // Case 2 (policy A): Llama Guard answers `unsafe\nS2` -> blocked with the
    // policy's on_fail code before the provider is reached.
    let blocked = send_chat(
        &gateway_addr,
        CLIENT_A_AUTH,
        "please wa-trigger-unsafe-s2 now",
    )?;
    assert_json_error(
        &blocked,
        403,
        "wa_llama_guard_blocked",
        "unsafe S2 verdict did not block",
    )?;
    if response_header(&blocked, "x-request-id").is_none() {
        bail!("Workers AI Llama Guard block response omitted x-request-id");
    }

    // Case 3 (policy A): composition with the native deterministic rule. Llama
    // Guard says safe (the mock still receives and answers this request), but
    // the native keyword check fails, and aggregation `all` blocks.
    let native_blocked = send_chat(
        &gateway_addr,
        CLIENT_A_AUTH,
        "wa-native-forbidden-keyword but harmless for llama guard",
    )?;
    assert_json_error(
        &native_blocked,
        403,
        "wa_llama_guard_blocked",
        "native rule composed via aggregation `all` did not block",
    )?;

    // Case 4 (policy B): `unsafe\nS9` with a `categories: ["S2"]` allow-list
    // passes -- the operator opted out of every category except S2.
    let category_pass = send_chat(
        &gateway_addr,
        CLIENT_B_AUTH,
        "please wa-trigger-unsafe-s9 now",
    )?;
    if category_pass.status != 200 {
        bail!(
            "unsafe S9 verdict must pass a categories=[S2] policy, got {}; raw: {}",
            category_pass.status,
            category_pass.raw
        );
    }

    // Case 5 (policy B): `unsafe\nS2` is inside the allow-list -> blocked.
    let category_blocked = send_chat(
        &gateway_addr,
        CLIENT_B_AUTH,
        "please wa-trigger-unsafe-s2 now",
    )?;
    assert_json_error(
        &category_blocked,
        403,
        "wa_llama_s2_blocked",
        "unsafe S2 verdict did not block the categories policy",
    )?;

    // The Workers AI wire contract, asserted on every captured mock request.
    let requests = workers_ai.join()?;
    if requests.len() != 5 {
        bail!(
            "Workers AI mock expected 5 detector calls, got {}",
            requests.len()
        );
    }
    for request in &requests {
        let lowercase = request.to_ascii_lowercase();
        if !lowercase.contains(&format!(
            "authorization: bearer {}",
            CF_API_TOKEN.to_ascii_lowercase()
        )) {
            bail!("Workers AI request did not carry the resolved [cloudflare] bearer token");
        }
        if !request.contains(&format!(
            "/client/v4/accounts/{CF_ACCOUNT_ID}/ai/run/{DEFAULT_MODEL_SLUG}"
        )) {
            bail!("Workers AI request did not use the accounts/{{account}}/ai/run/{{model}} path with the default model slug");
        }
        if !request.contains("\"messages\"") {
            bail!("Workers AI request omitted the chat-style messages array");
        }
        if request.contains("wa-llama-client-secret")
            || request.contains("wa-llama-host-admin-secret")
        {
            bail!("Workers AI request leaked a gateway credential");
        }
    }
    if !requests
        .iter()
        .any(|request| request.contains("wa-native-forbidden-keyword"))
    {
        bail!("the composed native-rule request never reached the Workers AI detector");
    }

    let provider_requests = provider.join()?;
    if provider_requests.len() != 2 {
        bail!(
            "model provider expected exactly the 2 allowed requests, got {}",
            provider_requests.len()
        );
    }

    println!("guardrail-workers-ai-llama-guard scenario passed");
    Ok(())
}

fn send_chat(addr: &str, auth: &str, content: &str) -> Result<HttpResponse> {
    let body = serde_json::json!({
        "model": "fast-chat",
        "messages": [{"role": "user", "content": content}]
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

const GUARDRAIL_ACTIONS: [(&str, &str); 3] = [
    ("guardrails.policy.read", "Read Guardrail policies"),
    (
        "guardrails.policy.create_revision",
        "Create Guardrail policy revisions",
    ),
    (
        "guardrails.policy.activate",
        "Activate Guardrail policy revisions",
    ),
];

/// Create client A's tenant account, the guardrail policy permissions, a role
/// carrying them, and bind it to the tenant — all through the host Admin API.
fn grant_tenant_guardrail_role(addr: &str) -> Result<()> {
    let admin = |method: &str, path: &str, body: String| -> Result<HttpResponse> {
        http_request_addr(addr, method, path, &[HOST_ADMIN_AUTH, JSON_CONTENT], &body)
    };
    let tenant = admin(
        "POST",
        "/admin/v1/tenant-accounts",
        serde_json::json!({
            "id": "org_wa_llama_e2e",
            "name": "Workers AI Llama Guard E2E",
            "slug": "wa-llama-guard-e2e",
            "plan_id": "free"
        })
        .to_string(),
    )?;
    if tenant.status != 200 && tenant.status != 201 {
        bail!("failed to create Workers AI E2E tenant: {}", tenant.raw);
    }
    for (index, (key, name)) in GUARDRAIL_ACTIONS.iter().enumerate() {
        let permission = admin(
            "POST",
            "/admin/v1/permissions",
            serde_json::json!({
                "id": format!("permission-wa-llama-e2e-{index}"),
                "key": key,
                "name": name
            })
            .to_string(),
        )?;
        if permission.status != 200 {
            bail!("failed to create permission {key}: {}", permission.raw);
        }
    }
    let role = admin(
        "POST",
        "/admin/v1/roles",
        serde_json::json!({
            "id": "role-wa-llama-e2e",
            "name": "Workers AI Llama Guard E2E policy role",
            "slug": "wa-llama-e2e-policy-role",
            "permission_keys": GUARDRAIL_ACTIONS
                .iter()
                .map(|(key, _)| *key)
                .collect::<Vec<_>>()
        })
        .to_string(),
    )?;
    if role.status != 200 {
        bail!("failed to create guardrail policy role: {}", role.raw);
    }
    let binding = admin(
        "POST",
        "/admin/v1/tenant-roles/org_wa_llama_e2e",
        serde_json::json!({"role_id": "role-wa-llama-e2e"}).to_string(),
    )?;
    if binding.status != 200 {
        bail!("failed to bind guardrail policy role: {}", binding.raw);
    }
    Ok(())
}

fn create_and_activate(addr: &str, policy_id: &str, body: &str) -> Result<()> {
    let created = http_request_addr(
        addr,
        "POST",
        "/admin/v1/guardrail-policies",
        &[HOST_ADMIN_AUTH, JSON_CONTENT],
        body,
    )?;
    if created.status != 201 {
        bail!(
            "host operator could not create {policy_id}: {}",
            created.raw
        );
    }
    let activated = http_request_addr(
        addr,
        "POST",
        &format!("/admin/v1/guardrail-policies/{policy_id}/activate"),
        &[HOST_ADMIN_AUTH, JSON_CONTENT],
        r#"{"revision":1}"#,
    )?;
    if activated.status != 200 {
        bail!(
            "host operator could not activate {policy_id}: {}",
            activated.raw
        );
    }
    Ok(())
}

/// A durable policy revision selecting the `workers_ai_llama_guard` detector
/// (model omitted -> crate default slug) composed with a native keyword rule.
fn llama_guard_policy_body(
    policy_id: &str,
    organization_id: &str,
    categories: Option<&[&str]>,
    block_code: &str,
) -> String {
    let mut detector = serde_json::json!({
        "kind": "workers_ai_llama_guard",
        "fingerprint_secret_ref": "env://FERROGATE_TEST_GUARDRAIL_SECRET"
    });
    if let Some(categories) = categories {
        detector["categories"] = serde_json::json!(categories);
    }
    serde_json::json!({
        "policy_id": policy_id,
        "name": "Workers AI Llama Guard E2E",
        "description": "#430: config-selected Workers AI Llama Guard, real Admin API + real HTTP detector round-trip",
        "enforced": true,
        "scope": {
            "organization_ids": [organization_id],
            "models": ["fast-chat"],
            "providers": ["openai"]
        },
        "checks": [
            {
                "id": "llama-guard",
                "enabled": true,
                "stage": "request",
                "sources": ["user"],
                "detector": detector
            },
            {
                "id": "native-keyword",
                "enabled": true,
                "stage": "request",
                "sources": ["user"],
                "detector": {"kind": "local", "keywords": ["wa-native-forbidden-keyword"]}
            }
        ],
        "aggregation": {"type": "all"},
        "execution": "parallel",
        "mode": "enforce",
        "streaming": "buffer_and_enforce",
        "on_pass": [{"kind": "allow"}],
        "on_fail": [{
            "kind": "block",
            "code": block_code,
            "message": "blocked by Workers AI Llama Guard E2E policy"
        }],
        "on_error": [{
            "kind": "block",
            "code": "wa_llama_guard_unavailable",
            "message": "Workers AI Llama Guard E2E detector unavailable"
        }],
        "deadline_ms": 2000
    })
    .to_string()
}

fn scenario_config(gateway_addr: &str, provider_addr: &str, workers_ai_addr: &str) -> String {
    format!(
        r#"listen: {gateway_addr:?}
cluster:
  enabled: true
  cluster_id: "wa-llama-guard-e2e"
  node_id: "wa-llama-guard-node"
  node_region: "local"
  node_zone: "local-a"
  state_backend: "local"
  counter_backend: "local"
cloudflare:
  account_id: "{CF_ACCOUNT_ID}"
  api_token: "{CF_API_TOKEN}"
  api_base_url: "http://{workers_ai_addr}/client/v4"
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
  - id: "wa-llama-host-admin"
    name: "Workers AI Llama Guard host operator"
    key: "wa-llama-host-admin-secret"
    scopes: ["admin.read", "admin.write"]
    # #540: platform root is stated, never inherited from an omitted field.
    platform_operator: true
  - id: "wa-llama-client"
    name: "Workers AI Llama Guard traffic client"
    key: "wa-llama-client-secret"
    scopes: ["models.read", "chat.completions", "admin.read", "admin.write"]
    allowed_models: ["fast-chat"]
    organization_id: "org_wa_llama_e2e"
    project_id: "project_wa_llama_e2e"
  - id: "wa-llama-categories-client"
    name: "Workers AI Llama Guard categories client"
    key: "wa-llama-categories-client-secret"
    scopes: ["models.read", "chat.completions"]
    allowed_models: ["fast-chat"]
    organization_id: "org_wa_llama_categories_e2e"
    project_id: "project_wa_llama_categories_e2e"
"#
    )
}

/// Local mock of the Workers AI `/ai/run/{model}` endpoint speaking the
/// documented Cloudflare envelope. The Llama Guard verdict is keyed on the
/// projected request content.
struct MockWorkersAi {
    addr: String,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Vec<String>>>,
}

impl MockWorkersAi {
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
                && started.elapsed() < MOCK_LIFETIME
                && !server_stop.load(Ordering::Relaxed)
            {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let Ok(request) = read_http_request(&mut stream) else {
                            continue;
                        };
                        if request.trim().is_empty() {
                            continue;
                        }
                        let verdict = if request.contains("wa-trigger-unsafe-s2") {
                            "unsafe\\nS2"
                        } else if request.contains("wa-trigger-unsafe-s9") {
                            "unsafe\\nS9"
                        } else {
                            "safe"
                        };
                        let body = format!(
                            r#"{{"success":true,"errors":[],"messages":[],"result":{{"response":"{verdict}"}}}}"#
                        );
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
            .context("Workers AI mock join handle missing")?
            .join()
            .map_err(|_| anyhow::anyhow!("Workers AI mock thread panicked"))
    }
}

impl Drop for MockWorkersAi {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Minimal OpenAI-compatible chat provider: every completion answers "ok".
struct MockChatProvider {
    addr: String,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Vec<String>>>,
}

impl MockChatProvider {
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
                && started.elapsed() < MOCK_LIFETIME
                && !server_stop.load(Ordering::Relaxed)
            {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let Ok(request) = read_http_request(&mut stream) else {
                            continue;
                        };
                        if request.trim().is_empty() {
                            continue;
                        }
                        let body = serde_json::json!({
                            "id": "chatcmpl_wa_llama_e2e",
                            "object": "chat.completion",
                            "model": "gpt-4o-mini",
                            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
                        })
                        .to_string();
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
            .context("model provider mock join handle missing")?
            .join()
            .map_err(|_| anyhow::anyhow!("model provider mock thread panicked"))
    }
}

impl Drop for MockChatProvider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct GatewayGuard {
    child: Child,
}

impl GatewayGuard {
    fn start(binary: &Path, config_path: &Path, gateway_addr: &str) -> Result<Self> {
        let child = Command::new(binary)
            .args(["run", "--config"])
            .arg(config_path)
            .env("FERROGATE_PROVIDER_SECRET", "provider-secret")
            .env("FERROGATE_TEST_GUARDRAIL_SECRET", FINGERPRINT_SECRET)
            .env(
                "FERROGATE_GUARDRAIL_EVIDENCE_HMAC_KEY",
                "ferrogate-e2e-guardrail-evidence-hmac-key-v1",
            )
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
        require_gateway_ready(
            &mut self.child,
            gateway_addr,
            "Workers AI Llama Guard E2E gateway",
            GATEWAY_READINESS_TIMEOUT,
        )
    }
}

impl Drop for GatewayGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn assert_json_error(response: &HttpResponse, status: u16, code: &str, what: &str) -> Result<()> {
    if response.status != status {
        bail!(
            "{what}: expected {status}, got {}; raw: {}",
            response.status,
            response.raw
        );
    }
    let body: Value = serde_json::from_str(&response.body)
        .with_context(|| format!("{what}: error body was not JSON: {}", response.body))?;
    if body["error"]["code"] != code {
        bail!("{what}: expected error code {code}, got: {body}");
    }
    Ok(())
}

fn response_header(response: &HttpResponse, expected_name: &str) -> Option<String> {
    let headers = response.raw.split_once("\r\n\r\n")?.0;
    for line in headers.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case(expected_name) {
            return Some(value.trim().to_string());
        }
    }
    None
}
