// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Live Supabase end-to-end coverage for the Guardrail detector runtime.

use crate::{
    cli::SupabaseLiveRestartArgs,
    compliance::{assert_component_contract, ComponentContract},
    http::{free_addr, http_request_addr, HttpResponse},
    mocks::read_http_request,
    readiness::{require_gateway_ready, GATEWAY_READINESS_TIMEOUT},
    supabase_schema::{
        connect_live_supabase, LiveSupabaseClient, LiveSupabaseScenario, LiveSupabaseSchema,
    },
};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{
    cell::RefCell,
    collections::HashMap,
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const CLIENT_AUTH: &str = "Authorization: Bearer guardrail-client-secret";
const DYNAMIC_CLIENT_AUTH: &str = "Authorization: Bearer guardrail-dynamic-client-secret";
const STRUCTURED_CLIENT_AUTH: &str = "Authorization: Bearer guardrail-structured-client-secret";
const REDACT_CLIENT_AUTH: &str = "Authorization: Bearer guardrail-redact-client-secret";
const PATCH_CLIENT_AUTH: &str = "Authorization: Bearer guardrail-patch-client-secret";
const BUFFER_CLIENT_AUTH: &str = "Authorization: Bearer guardrail-buffer-client-secret";
const SHADOW_CLIENT_AUTH: &str = "Authorization: Bearer guardrail-shadow-client-secret";
const REJECT_CLIENT_AUTH: &str = "Authorization: Bearer guardrail-reject-client-secret";
const UNGUARDED_CLIENT_AUTH: &str = "Authorization: Bearer guardrail-unguarded-client-secret";
const ADMIN_AUTH: &str = "Authorization: Bearer guardrail-admin-secret";
const JSON_CONTENT: &str = "Content-Type: application/json";
const DETECTOR_SECRET: &str = "guardrail-detector-e2e-secret";
const DYNAMIC_TENANT_ID: &str = "org_dynamic_guardrail_e2e";
const COMPLIANCE_ALLOW_CONTENT: &str = "guardrail compliance benign input";
const COMPLIANCE_BLOCK_CONTENT: &str = "contains dynamic-secret-v1";
const GUARDRAIL_ACTIONS: [(&str, &str); 7] = [
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
    (
        "guardrails.evidence.read",
        "Read sanitized Guardrail evaluation evidence",
    ),
];

#[derive(Clone, Copy, Debug)]
struct GuardrailEvidenceCase;

#[derive(Debug, PartialEq)]
struct GuardrailPolicyProjection {
    policy_id: String,
    revision: u64,
    scope: Value,
    checks: Value,
    on_pass: Value,
    on_fail: Value,
}

#[derive(Clone, Debug)]
struct GuardrailEvidenceRuntime {
    allowed_status: u16,
    allowed_body: Value,
    allowed_request_id: String,
    allowed_evaluation: Value,
    blocked_status: u16,
    blocked_code: Option<String>,
    blocked_request_id: String,
    blocked_evaluation: Value,
}

#[derive(Default)]
struct GuardrailEvidenceContract {
    runtime: RefCell<Option<GuardrailEvidenceRuntime>>,
}

impl GuardrailEvidenceContract {
    fn runtime(&self) -> Option<GuardrailEvidenceRuntime> {
        self.runtime.borrow().clone()
    }
}

impl ComponentContract for GuardrailEvidenceContract {
    type Case = GuardrailEvidenceCase;
    type Written = GuardrailPolicyProjection;
    type Runtime = GuardrailEvidenceRuntime;

    fn name(&self) -> &'static str {
        "guardrail-allow-block-evidence"
    }

    fn cases(&self) -> Vec<Self::Case> {
        vec![GuardrailEvidenceCase]
    }

    fn write(&self, gateway_addr: &str, _case: &Self::Case) -> Result<Self::Written> {
        let created = dynamic_json_request(
            gateway_addr,
            "POST",
            "/admin/v1/guardrail-policies",
            &dynamic_policy_body(
                Some("dynamic-supabase-policy"),
                "dynamic-secret-v1",
                "dynamic_guardrail_v1",
            ),
        )?;
        assert_policy_revision_response(&created, 201, 1, "draft")?;
        let projection = guardrail_policy_projection(&created)?;

        let activated = dynamic_json_request(
            gateway_addr,
            "POST",
            "/admin/v1/guardrail-policies/dynamic-supabase-policy/activate",
            r#"{"revision":1}"#,
        )?;
        assert_binding_response(&activated, 1, false)?;
        Ok(projection)
    }

    fn read(&self, gateway_addr: &str, _case: &Self::Case) -> Result<Self::Written> {
        let response = dynamic_json_request(
            gateway_addr,
            "GET",
            "/admin/v1/guardrail-policies/dynamic-supabase-policy/revisions/1",
            "",
        )?;
        if response.status != 200 {
            bail!("Guardrail compliance policy read failed: {}", response.raw);
        }
        guardrail_policy_projection(&response)
    }

    fn exercise(&self, gateway_addr: &str, _case: &Self::Case) -> Result<Self::Runtime> {
        let allowed = send_dynamic_chat(gateway_addr, COMPLIANCE_ALLOW_CONTENT)?;
        let allowed_request_id = response_header(&allowed, "x-request-id")
            .context("Guardrail compliance allow response omitted x-request-id")?;
        let allowed_body = serde_json::from_str::<Value>(&allowed.body).with_context(|| {
            format!(
                "Guardrail compliance allow response was not JSON: {}",
                allowed.body
            )
        })?;

        let blocked = send_dynamic_chat(gateway_addr, COMPLIANCE_BLOCK_CONTENT)?;
        let blocked_request_id = response_header(&blocked, "x-request-id")
            .context("Guardrail compliance block response omitted x-request-id")?;
        let blocked_code = serde_json::from_str::<Value>(&blocked.body)
            .ok()
            .and_then(|body| body["error"]["code"].as_str().map(str::to_string));
        let allowed_evaluation =
            wait_for_guardrail_evidence_api(gateway_addr, &allowed_request_id)?;
        let blocked_evaluation =
            wait_for_guardrail_evidence_api(gateway_addr, &blocked_request_id)?;
        let runtime = GuardrailEvidenceRuntime {
            allowed_status: allowed.status,
            allowed_body,
            allowed_request_id,
            allowed_evaluation,
            blocked_status: blocked.status,
            blocked_code,
            blocked_request_id,
            blocked_evaluation,
        };
        self.runtime.replace(Some(runtime.clone()));
        Ok(runtime)
    }

    fn verify(
        &self,
        _case: &Self::Case,
        written: &Self::Written,
        runtime: &Self::Runtime,
    ) -> Result<()> {
        if written.policy_id != "dynamic-supabase-policy"
            || written.revision != 1
            || written.scope["organization_ids"][0] != DYNAMIC_TENANT_ID
            || written.scope["models"][0] != "fast-chat"
            || written.scope["providers"][0] != "openai"
            || written.checks[0]["id"] != "keyword"
            || written.checks[0]["detector"]["keywords"][0] != "dynamic-secret-v1"
            || written.on_pass[0]["kind"] != "allow"
            || written.on_fail[0]["kind"] != "block"
            || written.on_fail[0]["code"] != "dynamic_guardrail_v1"
        {
            bail!("Guardrail compliance wrote the wrong policy: {written:?}");
        }
        if runtime.allowed_status != 200
            || runtime.allowed_body["choices"][0]["message"]["content"] != "ok"
        {
            bail!("Guardrail compliance allow path did not reach the provider: {runtime:?}");
        }
        assert_contract_evaluation(
            &runtime.allowed_evaluation,
            &runtime.allowed_request_id,
            "pass",
            "allow",
            "pass",
            0,
        )?;
        if runtime.blocked_status != 403
            || runtime.blocked_code.as_deref() != Some("dynamic_guardrail_v1")
        {
            bail!("Guardrail compliance block path was not enforced: {runtime:?}");
        }
        assert_contract_evaluation(
            &runtime.blocked_evaluation,
            &runtime.blocked_request_id,
            "fail",
            "block",
            "fail",
            1,
        )
    }

    fn cleanup(&self, _gateway_addr: &str, _case: &Self::Case) -> Result<()> {
        // The active revision is intentionally reused by the restart/rollback
        // checks below. The unique Supabase schema and gateway process own the
        // fixture lifetime and are removed at the end of this scenario.
        Ok(())
    }
}

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

    let mut schema = LiveSupabaseSchema::create(args, LiveSupabaseScenario::Guardrail)?;
    let schema_name = schema.name().to_string();
    let fixture_suffix = schema.run_id().replace('_', "-");
    let policy_role_id = format!("role-e2e-{fixture_suffix}");
    let policy_role_slug = format!("e2e-runtime-role-{fixture_suffix}");
    let mut evidence = SupabaseEvidence::connect(args, schema_name.clone())?;

    let gateway_addr = free_addr()?;
    let provider_stop = Arc::new(AtomicBool::new(false));
    let (provider_addr, provider_handle, provider_signals) =
        spawn_guardrail_provider(Arc::clone(&provider_stop))
            .context("start local model provider")?;
    let mut provider = ProviderGuard::new(provider_stop, provider_handle);
    let mut detector = MockDetector::start(2)?;
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("guardrail-supabase.yaml");
    fs::write(
        &config_path,
        guardrail_supabase_config(
            &gateway_addr,
            &provider_addr,
            &detector.addr,
            &schema_name,
            args,
        )?,
    )?;

    let gateway = GatewayGuard::start(
        &args.local.ferrogate_bin,
        &config_path,
        &gateway_addr,
        args.supabase_dsn.trim(),
    )?;

    let detected = send_chat_with_system(
        &gateway_addr,
        "system-private-content",
        "my email is pii@example.com",
    )?;
    assert_json_error(&detected, 403, "guardrail_pii_detected")?;
    let detected_request_id = response_header(&detected, "x-request-id")
        .context("Guardrail block response omitted x-request-id")?;

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
            || !request.contains("\"segments\":[")
            || !request.contains("\"segment_id\":")
            || !request.contains("\"source\":\"user\"")
            || !request.contains("\"fingerprint\":")
        {
            bail!("Guardrail detector request omitted execution context or content segments");
        }
        if request.contains("system-private-content")
            || request.contains("guardrail-client-secret")
            || request.contains("\"source\":\"system\"")
        {
            bail!("Guardrail detector request exceeded its declared content projection");
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
    let evidence_before_grant =
        dynamic_json_request(&gateway_addr, "GET", "/admin/v1/guardrail-evaluations", "")?;
    if evidence_before_grant.status != 403 {
        bail!(
            "Guardrail evidence read succeeded without a DB role grant: {}",
            evidence_before_grant.raw
        );
    }

    configure_guardrail_policy_role(&gateway_addr, &policy_role_id, &policy_role_slug)?;
    evidence.verify_guardrail_rbac_binding(&policy_role_id, true)?;

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

    install_streaming_policies(&gateway_addr)?;
    verify_normalized_and_streaming_paths(&gateway_addr, &provider_signals)?;
    evidence.wait_for_streaming_semantics()?;

    let guardrail_contract = GuardrailEvidenceContract::default();
    assert_component_contract(&gateway_addr, &guardrail_contract)?;
    let guardrail_runtime = guardrail_contract
        .runtime()
        .context("Guardrail component contract omitted runtime evidence")?;
    let allowed_v1_request_id = guardrail_runtime.allowed_request_id;
    let blocked_v1_request_id = guardrail_runtime.blocked_request_id;

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
    if !visible
        .iter()
        .any(|policy| policy["policy_id"] == "dynamic-supabase-policy")
        || visible.iter().any(|policy| {
            policy["scope"]["organization_ids"]
                .as_array()
                .is_none_or(|organizations| {
                    !organizations
                        .iter()
                        .any(|organization| organization == DYNAMIC_TENANT_ID)
                })
        })
    {
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

    let redacted = send_chat_with_auth(&gateway_addr, "redaction-probe", REDACT_CLIENT_AUTH)?;
    assert_redacted_provider_success(&redacted)?;
    let redacted_request_id = response_header(&redacted, "x-request-id")
        .context("Guardrail redaction response omitted x-request-id")?;
    evidence.wait_for_guardrail_evaluations(
        &allowed_v1_request_id,
        &blocked_v1_request_id,
        &redacted_request_id,
    )?;
    verify_guardrail_evidence_api(
        &gateway_addr,
        &allowed_v1_request_id,
        &blocked_v1_request_id,
        &redacted_request_id,
        &detected_request_id,
    )?;

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
    verify_guardrail_evidence_api(
        &gateway_addr,
        &allowed_v1_request_id,
        &blocked_v1_request_id,
        &redacted_request_id,
        &detected_request_id,
    )?;

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
    let mut patch_detector = ProtectedPatchDetector::start()?;
    verify_deterministic_checks_and_patches(&gateway_addr, &patch_detector.addr, &mut evidence)?;
    let patch_requests = patch_detector.join()?;
    if patch_requests.len() != 1 || patch_requests[0].contains("guardrail-patch-client-secret") {
        bail!("protected patch detector request count or projection was invalid");
    }
    let unbind = admin_json_request(
        &gateway_addr,
        "DELETE",
        &format!("/admin/v1/tenant-roles/{DYNAMIC_TENANT_ID}/{policy_role_id}"),
        "",
    )?;
    if unbind.status != 200 {
        bail!(
            "failed to revoke generated Guardrail policy role: {}",
            unbind.raw
        );
    }
    evidence.verify_guardrail_rbac_binding(&policy_role_id, false)?;
    let denied_after_unbind = dynamic_json_request(
        &gateway_addr,
        "POST",
        "/admin/v1/guardrail-policies/dynamic-supabase-policy/revisions",
        &dynamic_policy_body(None, "dynamic-secret-v3", "dynamic_guardrail_v3"),
    )?;
    assert_json_error(&denied_after_unbind, 403, "guardrail_rbac_denied")?;
    let provider_requests = provider.join()?;
    let request_count = |needle: &str| {
        provider_requests
            .iter()
            .filter(|request| request.contains(needle))
            .count()
    };
    if request_count("ordinary safe request") != 1
        || request_count(COMPLIANCE_ALLOW_CONTENT) != 1
        || request_count("redaction-probe") != 1
        || request_count("dynamic-secret-v1") != 1
        || request_count("dynamic-secret-v2") != 1
        || request_count("normalized-input-secret") != 0
        || request_count("stream-reject-chat") != 0
        || request_count("stream-buffer-chat") != 1
        || request_count("stream-buffer-responses") != 1
        || request_count("stream-buffer-overflow") != 1
        || request_count("stream-shadow-chat") != 1
        || request_count("stream-shadow-responses") != 1
        || request_count("stream-unguarded-chat") != 1
        || request_count("stream-unguarded-responses") != 1
        || request_count("structured-input-block") != 0
        || request_count("trigger-output-redact") != 1
        || request_count("protected-patch-attempt") != 0
    {
        bail!(
            "provider dispatch evidence did not prove Guardrail normalization/streaming isolation: {provider_requests:?}"
        );
    }

    drop(gateway);
    drop(evidence);
    schema.finish()?;
    println!("guardrail-supabase scenario passed");
    Ok(())
}

fn send_chat(addr: &str, content: &str) -> Result<HttpResponse> {
    send_chat_with_auth(addr, content, CLIENT_AUTH)
}

fn send_dynamic_chat(addr: &str, content: &str) -> Result<HttpResponse> {
    send_chat_with_auth(addr, content, DYNAMIC_CLIENT_AUTH)
}

fn send_chat_with_system(addr: &str, system: &str, user: &str) -> Result<HttpResponse> {
    let body = serde_json::json!({
        "model": "fast-chat",
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user}
        ],
        "stream": false
    })
    .to_string();
    http_request_addr(
        addr,
        "POST",
        "/v1/chat/completions",
        &[CLIENT_AUTH, JSON_CONTENT],
        &body,
    )
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

fn send_chat_with_metadata(
    addr: &str,
    content: &str,
    auth: &str,
    metadata: Value,
) -> Result<HttpResponse> {
    let body = serde_json::json!({
        "model": "fast-chat",
        "messages": [{"role": "user", "content": content}],
        "metadata": metadata,
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

fn configure_guardrail_policy_role(addr: &str, role_id: &str, role_slug: &str) -> Result<()> {
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
            "id": role_id,
            "name": format!("Generated E2E role {role_slug}"),
            "slug": role_slug,
            "permission_keys": GUARDRAIL_ACTIONS
                .iter()
                .map(|(key, _)| *key)
                .collect::<Vec<_>>()
        })
        .to_string(),
    )?;
    if role.status != 200 {
        bail!(
            "failed to create generated Guardrail policy role: {}",
            role.raw
        );
    }

    let binding = admin_json_request(
        addr,
        "POST",
        &format!("/admin/v1/tenant-roles/{DYNAMIC_TENANT_ID}"),
        &serde_json::json!({"role_id": role_id}).to_string(),
    )?;
    if binding.status != 200 {
        bail!(
            "failed to bind generated Guardrail policy role: {}",
            binding.raw
        );
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
            "sources": ["user"],
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

fn verify_deterministic_checks_and_patches(
    addr: &str,
    patch_detector_addr: &str,
    evidence: &mut SupabaseEvidence,
) -> Result<()> {
    create_and_activate_dynamic_policy(
        addr,
        "structured-input-policy",
        serde_json::json!({
            "policy_id": "structured-input-policy",
            "name": "Structured input policy",
            "enforced": true,
            "scope": {
                "organization_ids": [DYNAMIC_TENANT_ID],
                "api_key_ids": ["guardrail-structured-client"],
                "models": ["fast-chat"],
                "providers": ["openai"]
            },
            "checks": [{
                "id": "metadata-structure",
                "stage": "request",
                "sources": ["metadata"],
                "detector": {
                    "kind": "local",
                    "json": {
                        "schema": {"type": "object"},
                        "forbidden_keys": ["/credential"]
                    }
                }
            }],
            "aggregation": {"type": "all"},
            "execution": "sequential",
            "mode": "enforce",
            "streaming": "buffer_and_enforce",
            "on_pass": [{"kind": "allow"}],
            "on_fail": [{
                "kind": "block",
                "code": "deterministic_input_block",
                "message": "structured input rejected"
            }],
            "on_error": [{
                "kind": "block",
                "code": "deterministic_input_error",
                "message": "structured input could not be evaluated"
            }],
            "deadline_ms": 1000
        }),
    )?;
    let blocked = send_chat_with_metadata(
        addr,
        "structured-input-block",
        STRUCTURED_CLIENT_AUTH,
        serde_json::json!({"credential": "must-not-reach-provider"}),
    )?;
    assert_json_error(&blocked, 403, "deterministic_input_block")?;

    create_and_activate_dynamic_policy(
        addr,
        "typed-output-redact-policy",
        serde_json::json!({
            "policy_id": "typed-output-redact-policy",
            "name": "Typed output redaction",
            "enforced": true,
            "scope": {
                "organization_ids": [DYNAMIC_TENANT_ID],
                "api_key_ids": ["guardrail-redact-client"],
                "models": ["fast-chat"],
                "providers": ["openai"]
            },
            "checks": [{
                "id": "assistant-secret",
                "stage": "response",
                "sources": ["assistant"],
                "detector": {"kind": "local", "keywords": ["output-secret"]}
            }],
            "aggregation": {"type": "all"},
            "execution": "sequential",
            "mode": "enforce",
            "streaming": "buffer_and_enforce",
            "on_pass": [{"kind": "allow"}],
            "on_fail": [{
                "kind": "redact",
                "code": "typed_output_redacted",
                "message": "assistant content redacted"
            }],
            "on_error": [{
                "kind": "block",
                "code": "typed_output_error",
                "message": "assistant content could not be transformed"
            }],
            "deadline_ms": 1000
        }),
    )?;
    let redacted = send_chat_with_auth(addr, "trigger-output-redact", REDACT_CLIENT_AUTH)?;
    if redacted.status != 200 {
        bail!("typed output redaction failed: {}", redacted.raw);
    }
    let redacted_body: Value = serde_json::from_str(&redacted.body)?;
    if redacted_body["choices"][0]["message"]["content"] != "[REDACTED]"
        || redacted_body["model"] != "provider-model-must-remain"
        || redacted_body["usage"]["total_tokens"] != 2
        || redacted_body["id"] != "chatcmpl_guardrail_e2e"
    {
        bail!("typed output patch modified a protected response field: {redacted_body}");
    }

    create_and_activate_dynamic_policy(
        addr,
        "protected-patch-policy",
        serde_json::json!({
            "policy_id": "protected-patch-policy",
            "name": "Protected patch rejection",
            "enforced": true,
            "scope": {
                "organization_ids": [DYNAMIC_TENANT_ID],
                "api_key_ids": ["guardrail-patch-client"],
                "models": ["fast-chat"],
                "providers": ["openai"]
            },
            "checks": [{
                "id": "metadata-patch",
                "stage": "request",
                "sources": ["metadata"],
                "detector": {
                    "kind": "custom_http",
                    "endpoint": format!("http://{patch_detector_addr}/check"),
                    "allow_private_network": true,
                    "timeout_ms": 1000,
                    "max_concurrency": 1,
                    "max_retries": 0
                }
            }],
            "aggregation": {"type": "all"},
            "execution": "sequential",
            "mode": "enforce",
            "streaming": "buffer_and_enforce",
            "on_pass": [{"kind": "allow"}],
            "on_fail": [{
                "kind": "redact",
                "code": "protected_patch_must_not_apply",
                "message": "protected patch must not apply"
            }],
            "on_error": [{
                "kind": "block",
                "code": "protected_patch_rejected",
                "message": "detector patch targeted protected content"
            }],
            "deadline_ms": 1000
        }),
    )?;
    let rejected = send_chat_with_metadata(
        addr,
        "protected-patch-attempt",
        PATCH_CLIENT_AUTH,
        serde_json::json!({"credential": "protected-value"}),
    )?;
    assert_json_error(&rejected, 403, "protected_patch_rejected")?;
    let request_id = response_header(&rejected, "x-request-id")
        .context("protected patch rejection omitted x-request-id")?;
    evidence.wait_for_protected_patch_rejection(&request_id)?;
    Ok(())
}

fn create_and_activate_dynamic_policy(addr: &str, policy_id: &str, policy: Value) -> Result<()> {
    let created = dynamic_json_request(
        addr,
        "POST",
        "/admin/v1/guardrail-policies",
        &policy.to_string(),
    )?;
    if created.status != 201 {
        bail!(
            "generated RBAC role could not create {policy_id}: {}",
            created.raw
        );
    }
    let activated = dynamic_json_request(
        addr,
        "POST",
        &format!("/admin/v1/guardrail-policies/{policy_id}/activate"),
        r#"{"revision":1}"#,
    )?;
    if activated.status != 200 {
        bail!(
            "generated RBAC role could not activate {policy_id}: {}",
            activated.raw
        );
    }
    Ok(())
}

fn install_streaming_policies(addr: &str) -> Result<()> {
    create_and_activate_policy(
        addr,
        "stream-buffer-policy",
        serde_json::json!({
            "policy_id": "stream-buffer-policy",
            "name": "Buffered streaming and normalized input",
            "enforced": true,
            "scope": {
                "organization_ids": ["org_guardrail_buffer_e2e"],
                "models": ["fast-chat"],
                "providers": ["openai"]
            },
            "checks": [
                {
                    "id": "normalized-input",
                    "stage": "request",
                    "sources": ["system", "developer", "user", "tool_schema", "tool_arguments", "tool_result", "metadata", "text_attachment"],
                    "detector": {"kind": "local", "keywords": ["normalized-input-secret"]}
                },
                {
                    "id": "split-stream-output",
                    "stage": "response",
                    "sources": ["assistant", "tool_arguments", "tool_result"],
                    "detector": {"kind": "local", "keywords": ["split-secret"]}
                }
            ],
            "aggregation": {"type": "any"},
            "execution": "parallel",
            "mode": "enforce",
            "streaming": "buffer_and_enforce",
            "on_pass": [{"kind": "allow"}],
            "on_fail": [{
                "kind": "block",
                "code": "guardrail_stream_buffered",
                "message": "blocked by buffered Guardrail"
            }],
            "on_error": [{
                "kind": "block",
                "code": "guardrail_stream_buffer_unavailable",
                "message": "buffered Guardrail unavailable"
            }],
            "deadline_ms": 1000
        }),
    )?;
    create_and_activate_policy(
        addr,
        "stream-shadow-policy",
        streaming_response_policy(
            "stream-shadow-policy",
            "org_guardrail_shadow_e2e",
            "shadow_after_complete",
        ),
    )?;
    create_and_activate_policy(
        addr,
        "stream-reject-policy",
        streaming_response_policy(
            "stream-reject-policy",
            "org_guardrail_reject_e2e",
            "reject_streaming",
        ),
    )?;
    Ok(())
}

fn streaming_response_policy(policy_id: &str, tenant_id: &str, streaming: &str) -> Value {
    serde_json::json!({
        "policy_id": policy_id,
        "name": policy_id,
        "enforced": true,
        "scope": {
            "organization_ids": [tenant_id],
            "models": ["fast-chat"],
            "providers": ["openai"]
        },
        "checks": [{
            "id": "split-stream-output",
            "stage": "response",
            "sources": ["assistant", "tool_arguments", "tool_result"],
            "detector": {"kind": "local", "keywords": ["split-secret"]}
        }],
        "aggregation": {"type": "all"},
        "execution": "parallel",
        "mode": "enforce",
        "streaming": streaming,
        "on_pass": [{"kind": "allow"}],
        "on_fail": [{
            "kind": "block",
            "code": "guardrail_shadow_must_not_escape",
            "message": "shadow result must not become an enforced block"
        }],
        "on_error": [{"kind": "record"}],
        "deadline_ms": 1000
    })
}

fn create_and_activate_policy(addr: &str, policy_id: &str, policy: Value) -> Result<()> {
    let created = admin_json_request(
        addr,
        "POST",
        "/admin/v1/guardrail-policies",
        &policy.to_string(),
    )?;
    if created.status != 201 {
        bail!("failed to create {policy_id}: {}", created.raw);
    }
    let activated = admin_json_request(
        addr,
        "POST",
        &format!("/admin/v1/guardrail-policies/{policy_id}/activate"),
        r#"{"revision":1}"#,
    )?;
    if activated.status != 200 {
        bail!("failed to activate {policy_id}: {}", activated.raw);
    }
    Ok(())
}

fn verify_normalized_and_streaming_paths(
    addr: &str,
    provider_signals: &ProviderSignals,
) -> Result<()> {
    let chat_input = http_request_addr(
        addr,
        "POST",
        "/v1/chat/completions",
        &[BUFFER_CLIENT_AUTH, JSON_CONTENT],
        &serde_json::json!({
            "model": "fast-chat",
            "messages": [
                {"role": "system", "content": "normalized-input-secret"},
                {"role": "user", "content": "safe user content"}
            ]
        })
        .to_string(),
    )?;
    assert_json_error(&chat_input, 403, "guardrail_stream_buffered")?;

    let responses_input = http_request_addr(
        addr,
        "POST",
        "/v1/responses",
        &[BUFFER_CLIENT_AUTH, JSON_CONTENT],
        &serde_json::json!({
            "model": "fast-chat",
            "instructions": "normalized-input-secret",
            "input": "safe user content"
        })
        .to_string(),
    )?;
    assert_json_error(&responses_input, 403, "guardrail_stream_buffered")?;

    let responses_output = http_request_addr(
        addr,
        "POST",
        "/v1/responses",
        &[BUFFER_CLIENT_AUTH, JSON_CONTENT],
        &serde_json::json!({
            "model": "fast-chat",
            "input": "nonstream-response-secret",
            "stream": false
        })
        .to_string(),
    )?;
    assert_json_error(&responses_output, 403, "guardrail_stream_buffered")?;

    for (path, marker) in [
        ("/v1/chat/completions", "stream-buffer-chat"),
        ("/v1/responses", "stream-buffer-responses"),
    ] {
        let probe = probe_streaming_request(
            addr,
            path,
            BUFFER_CLIENT_AUTH,
            marker,
            false,
            provider_signals,
        )?;
        if probe.status != 403
            || probe.raw.contains("split-sec")
            || !probe.raw.contains("guardrail_stream_buffered")
        {
            bail!(
                "buffered stream leaked content or returned wrong status: {}",
                probe.raw
            );
        }
    }

    let overflow = http_request_addr(
        addr,
        "POST",
        "/v1/chat/completions",
        &[BUFFER_CLIENT_AUTH, JSON_CONTENT],
        &streaming_request_body("/v1/chat/completions", "stream-buffer-overflow"),
    )?;
    assert_json_error(&overflow, 403, "guardrail_stream_buffer_unavailable")?;
    if overflow.raw.contains("overflow-sensitive") {
        bail!("buffer overflow response leaked provider content");
    }

    for (path, marker) in [
        ("/v1/chat/completions", "stream-shadow-chat"),
        ("/v1/responses", "stream-shadow-responses"),
    ] {
        let probe = probe_streaming_request(
            addr,
            path,
            SHADOW_CLIENT_AUTH,
            marker,
            true,
            provider_signals,
        )?;
        if probe.status != 200
            || !probe.first_body.contains("split-sec")
            || probe.first_body_elapsed >= Duration::from_millis(2500)
        {
            bail!("shadow stream was not a measured pass-through: {probe:?}");
        }
    }

    let rejected = http_request_addr(
        addr,
        "POST",
        "/v1/chat/completions",
        &[REJECT_CLIENT_AUTH, JSON_CONTENT],
        &streaming_request_body("/v1/chat/completions", "stream-reject-chat"),
    )?;
    assert_json_error(&rejected, 403, "guardrail_streaming_unsupported")?;

    for (path, marker) in [
        ("/v1/chat/completions", "stream-unguarded-chat"),
        ("/v1/responses", "stream-unguarded-responses"),
    ] {
        let probe = probe_streaming_request(
            addr,
            path,
            UNGUARDED_CLIENT_AUTH,
            marker,
            true,
            provider_signals,
        )?;
        if probe.status != 200 || probe.first_body_elapsed >= Duration::from_millis(2500) {
            bail!("unguarded stream regressed from pass-through: {probe:?}");
        }
    }
    Ok(())
}

#[derive(Debug)]
struct StreamingProbe {
    status: u16,
    first_body_elapsed: Duration,
    first_body: String,
    raw: String,
}

fn probe_streaming_request(
    addr: &str,
    path: &str,
    auth: &str,
    marker: &str,
    expect_early_body: bool,
    provider_signals: &ProviderSignals,
) -> Result<StreamingProbe> {
    let body = streaming_request_body(path, marker);
    let mut stream = TcpStream::connect(addr)?;
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\n{auth}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()?;

    let provider_first_chunk = provider_signals.wait(marker, Duration::from_secs(60))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut raw = Vec::new();
    let mut buffer = [0_u8; 8192];
    if expect_early_body {
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    raw.extend_from_slice(&buffer[..read]);
                    if response_body(&raw).is_some_and(|body| !body.is_empty()) {
                        break;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    bail!(
                        "stream {marker} did not produce an early body chunk for {path}: {error}"
                    );
                }
                Err(error) => return Err(error.into()),
            }
        }
    } else {
        match stream.read(&mut buffer) {
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Ok(read) => {
                raw.extend_from_slice(&buffer[..read]);
                bail!("buffered Guardrail emitted {read} bytes before evaluation completed");
            }
            Err(error) => return Err(error.into()),
        }
    }
    let first_body_elapsed = provider_first_chunk.elapsed();
    let first_body = response_body(&raw).unwrap_or_default().to_string();

    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => raw.extend_from_slice(&buffer[..read]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break
            }
            Err(error) => return Err(error.into()),
        }
    }
    let raw = String::from_utf8(raw)?;
    let status = raw
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .with_context(|| {
            format!(
                "stream {marker} on {path} omitted HTTP status after receiving {} bytes",
                raw.len()
            )
        })?;
    Ok(StreamingProbe {
        status,
        first_body_elapsed,
        first_body,
        raw,
    })
}

fn streaming_request_body(path: &str, marker: &str) -> String {
    if path == "/v1/responses" {
        serde_json::json!({"model": "fast-chat", "input": marker, "stream": true}).to_string()
    } else {
        serde_json::json!({
            "model": "fast-chat",
            "messages": [{"role": "user", "content": marker}],
            "stream": true
        })
        .to_string()
    }
}

fn response_body(raw: &[u8]) -> Option<&str> {
    let header_end = raw.windows(4).position(|window| window == b"\r\n\r\n")?;
    std::str::from_utf8(&raw[header_end + 4..]).ok()
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

fn assert_redacted_provider_success(response: &HttpResponse) -> Result<()> {
    if response.status != 200 {
        bail!(
            "Guardrail redaction expected provider success, got {}",
            response.raw
        );
    }
    let body: Value = serde_json::from_str(&response.body)?;
    let content = body["choices"][0]["message"]["content"]
        .as_str()
        .context("redacted provider response omitted assistant content")?;
    if content != "prefix [REDACTED] suffix" || content.contains("provider-redact-secret") {
        bail!("Guardrail response redaction was not applied safely: {body}");
    }
    Ok(())
}

fn guardrail_policy_projection(response: &HttpResponse) -> Result<GuardrailPolicyProjection> {
    let body: Value = serde_json::from_str(&response.body)
        .with_context(|| format!("Guardrail policy response was not JSON: {}", response.body))?;
    let policy = &body["policy"];
    Ok(GuardrailPolicyProjection {
        policy_id: policy["policy_id"]
            .as_str()
            .context("Guardrail policy response omitted policy_id")?
            .to_string(),
        revision: policy["revision"]
            .as_u64()
            .context("Guardrail policy response omitted revision")?,
        scope: policy["scope"].clone(),
        checks: policy["checks"].clone(),
        on_pass: policy["on_pass"].clone(),
        on_fail: policy["on_fail"].clone(),
    })
}

fn wait_for_guardrail_evidence_api(addr: &str, request_id: &str) -> Result<Value> {
    let started = Instant::now();
    let mut last = "Guardrail evaluation was not visible through the Admin API".to_string();
    while started.elapsed() < Duration::from_secs(15) {
        match dynamic_json_request(
            addr,
            "GET",
            &format!("/admin/v1/guardrail-evaluations?request_id={request_id}"),
            "",
        ) {
            Ok(response) if response.status == 200 => {
                match serde_json::from_str::<Value>(&response.body) {
                    Ok(body) => {
                        if let Some(evaluation) = body["data"].as_array().and_then(|rows| {
                            rows.iter().find(|row| {
                                row["policy_id"] == "dynamic-supabase-policy"
                                    && row["policy_revision"] == 1
                                    && row["stage"] == "request"
                            })
                        }) {
                            return Ok(evaluation.clone());
                        }
                        last = format!("unexpected evidence body: {body}");
                    }
                    Err(error) => last = error.to_string(),
                }
            }
            Ok(response) => last = response.raw,
            Err(error) => last = error.to_string(),
        }
        thread::sleep(Duration::from_millis(150));
    }
    bail!("timed out reading Guardrail evaluation {request_id} through the Admin API: {last}")
}

fn assert_contract_evaluation(
    evaluation: &Value,
    request_id: &str,
    verdict: &str,
    action: &str,
    check_verdict: &str,
    finding_count: u64,
) -> Result<()> {
    if evaluation["request_id"] != request_id
        || evaluation["policy_id"] != "dynamic-supabase-policy"
        || evaluation["policy_revision"] != 1
        || evaluation["tenant"]["organization_id"] != DYNAMIC_TENANT_ID
        || evaluation["target"] != "model=fast-chat;provider=openai"
        || evaluation["stage"] != "request"
        || evaluation["verdict"] != verdict
        || evaluation["action"] != action
        || evaluation["enforcement_status"] != "enforced"
        || evaluation["finding_count"] != finding_count
        || evaluation["checks"][0]["check_id"] != "keyword"
        || evaluation["checks"][0]["verdict"] != check_verdict
        || evaluation["checks"][0]["action"] != action
        || evaluation["checks"][0]["finding_count"] != finding_count
        || !evaluation["input_fingerprint"]
            .as_str()
            .is_some_and(|value| value.starts_with("hmac-sha256:"))
    {
        bail!("Guardrail {action} evidence was incomplete: {evaluation}");
    }
    Ok(())
}

fn verify_guardrail_evidence_api(
    addr: &str,
    allowed_request_id: &str,
    blocked_request_id: &str,
    redacted_request_id: &str,
    cross_tenant_request_id: &str,
) -> Result<()> {
    let allowed = wait_for_guardrail_evidence_api(addr, allowed_request_id)?;
    assert_contract_evaluation(&allowed, allowed_request_id, "pass", "allow", "pass", 0)?;
    let blocked = dynamic_json_request(
        addr,
        "GET",
        &format!("/admin/v1/guardrail-evaluations?request_id={blocked_request_id}"),
        "",
    )?;
    if blocked.status != 200 {
        bail!("Guardrail evaluation query failed: {}", blocked.raw);
    }
    let blocked_body: Value = serde_json::from_str(&blocked.body)?;
    let blocked_rows = blocked_body["data"]
        .as_array()
        .context("Guardrail evaluation response omitted data")?;
    if blocked_rows.len() != 1
        || blocked_rows[0]["policy_id"] != "dynamic-supabase-policy"
        || blocked_rows[0]["verdict"] != "fail"
        || blocked_rows[0]["action"] != "block"
        || blocked_rows[0]["enforcement_status"] != "enforced"
        || blocked_rows[0]["checks"][0]["verdict"] != "fail"
        || blocked_rows[0]["checks"][0]["finding_category_counts"]["contains"] != 1
        || !blocked_rows[0]["input_fingerprint"]
            .as_str()
            .is_some_and(|value| value.starts_with("hmac-sha256:"))
    {
        bail!("blocked Guardrail evidence was incomplete: {blocked_body}");
    }
    let trace_id = blocked_rows[0]["trace_id"]
        .as_str()
        .context("blocked Guardrail evidence omitted trace_id")?;
    let agent_run_id = blocked_rows[0]["agent_run_id"]
        .as_str()
        .context("blocked Guardrail evidence omitted agent_run_id")?;
    for (selector, value) in [("trace_id", trace_id), ("agent_run_id", agent_run_id)] {
        let timeline = dynamic_json_request(
            addr,
            "GET",
            &format!("/admin/v1/investigations?{selector}={value}"),
            "",
        )?;
        let timeline_body: Value = serde_json::from_str(&timeline.body)?;
        if timeline.status != 200
            || timeline_body["guardrail_evaluations"]
                .as_array()
                .is_none_or(|rows| {
                    !rows
                        .iter()
                        .any(|row| row["request_id"] == blocked_request_id)
                })
            || !timeline_body["agent_runs"].is_array()
            || !timeline_body["agent_events"].is_array()
        {
            bail!("Guardrail investigation failed for {selector}: {timeline_body}");
        }
    }

    let category = dynamic_json_request(
        addr,
        "GET",
        "/admin/v1/guardrail-evaluations?category=contains&verdict=fail&action=block",
        "",
    )?;
    if category.status != 200
        || !serde_json::from_str::<Value>(&category.body)?["data"]
            .as_array()
            .is_some_and(|rows| {
                rows.iter()
                    .any(|row| row["request_id"] == blocked_request_id)
            })
    {
        bail!("Guardrail evidence category filters did not find the blocked request");
    }

    let cross_tenant = dynamic_json_request(
        addr,
        "GET",
        &format!("/admin/v1/guardrail-evaluations?request_id={cross_tenant_request_id}"),
        "",
    )?;
    if cross_tenant.status != 200
        || serde_json::from_str::<Value>(&cross_tenant.body)?["total"] != 0
    {
        bail!(
            "tenant Guardrail evidence isolation failed (status={}): {}",
            cross_tenant.status,
            cross_tenant.body
        );
    }

    let blocked_timeline = dynamic_json_request(
        addr,
        "GET",
        &format!("/admin/v1/investigations?request_id={blocked_request_id}"),
        "",
    )?;
    if blocked_timeline.status != 200 {
        bail!(
            "blocked Guardrail investigation failed: {}",
            blocked_timeline.raw
        );
    }
    let blocked_timeline_body: Value = serde_json::from_str(&blocked_timeline.body)?;
    if blocked_timeline_body["final_outcome"] != "blocked"
        || blocked_timeline_body["identity"]["organization_id"] != DYNAMIC_TENANT_ID
        || blocked_timeline_body["guardrail_evaluations"]
            .as_array()
            .is_none_or(Vec::is_empty)
        || blocked_timeline_body["audit_events"]
            .as_array()
            .is_none_or(Vec::is_empty)
    {
        bail!("blocked Guardrail investigation was incomplete: {blocked_timeline_body}");
    }

    let redacted_timeline = dynamic_json_request(
        addr,
        "GET",
        &format!("/admin/v1/investigations?request_id={redacted_request_id}"),
        "",
    )?;
    if redacted_timeline.status != 200 {
        bail!(
            "redacted Guardrail investigation failed: {}",
            redacted_timeline.raw
        );
    }
    let redacted_timeline_body: Value = serde_json::from_str(&redacted_timeline.body)?;
    let redacted_evaluations = redacted_timeline_body["guardrail_evaluations"]
        .as_array()
        .context("redacted investigation omitted Guardrail evaluations")?;
    if redacted_timeline_body["final_outcome"] != "succeeded"
        || !redacted_evaluations.iter().any(|evaluation| {
            evaluation["action"] == "redact"
                && evaluation["verdict"] == "fail"
                && evaluation["transformed"] == true
        })
        || redacted_timeline_body["billing_events"]
            .as_array()
            .is_none_or(Vec::is_empty)
    {
        bail!("redacted Guardrail investigation was incomplete: {redacted_timeline_body}");
    }

    let combined = format!(
        "{}{}{}{}{}",
        allowed, blocked.body, category.body, blocked_timeline.body, redacted_timeline.body
    );
    for forbidden in [
        "dynamic-secret-v1",
        "provider-redact-secret",
        "guardrail-dynamic-client-secret",
        "guardrail-redact-client-secret",
        DETECTOR_SECRET,
        "authorization",
        "matched_text",
    ] {
        if combined
            .to_ascii_lowercase()
            .contains(&forbidden.to_ascii_lowercase())
        {
            bail!("Guardrail evidence API leaked forbidden content: {forbidden}");
        }
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
reliability:
  provider_response_body_max_bytes: 2048
storage:
  provider: "supabase"
  required: true
  provider_order:
    - "supabase"
    - "postgres"
  supabase_dsn_env: "FERROGATE_SUPABASE_DSN"
  postgres_pool_size: 2
  postgres_pool_acquire_timeout_millis: 30000
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
    # #540: platform root is stated, never inherited from an omitted field.
    platform_operator: true
  - id: "guardrail-structured-client"
    name: "Structured Guardrail E2E client"
    key: "guardrail-structured-client-secret"
    scopes: ["models.read", "chat.completions"]
    allowed_models: ["fast-chat"]
    organization_id: "org_dynamic_guardrail_e2e"
  - id: "guardrail-redact-client"
    name: "Typed redaction Guardrail E2E client"
    key: "guardrail-redact-client-secret"
    scopes: ["models.read", "chat.completions"]
    allowed_models: ["fast-chat"]
    organization_id: "org_dynamic_guardrail_e2e"
    project_id: "project_dynamic_guardrail_e2e"
  - id: "guardrail-patch-client"
    name: "Protected patch Guardrail E2E client"
    key: "guardrail-patch-client-secret"
    scopes: ["models.read", "chat.completions"]
    allowed_models: ["fast-chat"]
    organization_id: "org_dynamic_guardrail_e2e"
  - id: "guardrail-buffer-client"
    name: "Guardrail buffered streaming client"
    key: "guardrail-buffer-client-secret"
    scopes: ["models.read", "chat.completions", "responses.create"]
    allowed_models: ["fast-chat"]
    organization_id: "org_guardrail_buffer_e2e"
  - id: "guardrail-shadow-client"
    name: "Guardrail shadow streaming client"
    key: "guardrail-shadow-client-secret"
    scopes: ["models.read", "chat.completions", "responses.create"]
    allowed_models: ["fast-chat"]
    organization_id: "org_guardrail_shadow_e2e"
  - id: "guardrail-reject-client"
    name: "Guardrail reject streaming client"
    key: "guardrail-reject-client-secret"
    scopes: ["models.read", "chat.completions", "responses.create"]
    allowed_models: ["fast-chat"]
    organization_id: "org_guardrail_reject_e2e"
  - id: "guardrail-unguarded-client"
    name: "Guardrail unguarded streaming client"
    key: "guardrail-unguarded-client-secret"
    scopes: ["models.read", "chat.completions", "responses.create"]
    allowed_models: ["fast-chat"]
    organization_id: "org_guardrail_unguarded_e2e"
guardrails:
  - id: "e2e-pii-detector"
    name: "E2E PII detector"
    enabled: true
    stage: "request"
    sources: ["user"]
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
  - id: "e2e-response-redaction"
    name: "E2E response redaction"
    enabled: true
    stage: "response"
    sources: ["assistant"]
    organization_ids: ["org_dynamic_guardrail_e2e"]
    models: ["fast-chat"]
    providers: ["openai"]
    keywords: ["provider-redact-secret"]
    provider: "none"
    effect: "redact"
    code: "guardrail_response_redacted"
    message: "response redacted by E2E Guardrail"
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
            "Guardrail E2E gateway",
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

struct ProviderGuard {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Vec<String>>>,
}

#[derive(Clone, Default)]
struct ProviderSignals {
    emitted: Arc<(Mutex<HashMap<String, Instant>>, Condvar)>,
}

impl ProviderSignals {
    fn mark(&self, marker: String) {
        let (emitted, changed) = &*self.emitted;
        emitted.lock().unwrap().insert(marker, Instant::now());
        changed.notify_all();
    }

    fn wait(&self, marker: &str, timeout: Duration) -> Result<Instant> {
        let (emitted, changed) = &*self.emitted;
        let started = Instant::now();
        let mut state = emitted.lock().unwrap();
        loop {
            if let Some(emitted_at) = state.remove(marker) {
                return Ok(emitted_at);
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                bail!("provider did not emit the first stream chunk for marker {marker}");
            }
            let (next, result) = changed.wait_timeout(state, remaining).unwrap();
            state = next;
            if result.timed_out() && !state.contains_key(marker) {
                bail!("provider did not emit the first stream chunk for marker {marker}");
            }
        }
    }
}

fn spawn_guardrail_provider(
    stop: Arc<AtomicBool>,
) -> Result<(String, JoinHandle<Vec<String>>, ProviderSignals)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?.to_string();
    let signals = ProviderSignals::default();
    let server_signals = signals.clone();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let Ok(request) = read_http_request(&mut stream) else {
                        continue;
                    };
                    let _ =
                        write_guardrail_provider_response(&mut stream, &request, &server_signals);
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
    Ok((addr, handle, signals))
}

fn write_guardrail_provider_response(
    stream: &mut TcpStream,
    request: &str,
    signals: &ProviderSignals,
) -> Result<()> {
    let is_responses = request.contains("POST /v1/responses ");
    let is_streaming = request.contains(r#""stream":true"#);
    if is_streaming {
        let overflow = request.contains("stream-buffer-overflow");
        let first = if overflow {
            format!(
                "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{}\"}}}}]}}\n\n",
                "overflow-sensitive".repeat(256)
            )
        } else {
            "data: {\"choices\":[{\"delta\":{\"content\":\"split-sec\"}}]}\n\n".to_string()
        };
        let second = "data: {\"choices\":[{\"delta\":{\"content\":\"ret\"}}]}\n\ndata: [DONE]\n\n";
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n{first}"
        )?;
        stream.flush()?;
        if let Some(marker) = streaming_marker(request) {
            signals.mark(marker);
        }
        if overflow {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(3));
        stream.write_all(second.as_bytes())?;
        stream.flush()?;
        return Ok(());
    }

    let body = if is_responses {
        let content = if request.contains("nonstream-response-secret") {
            "split-secret"
        } else {
            "ok"
        };
        serde_json::json!({
            "id": "resp_guardrail_e2e",
            "object": "response",
            "output": [{
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": content}]
            }],
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}
        })
        .to_string()
    } else {
        let content = if request.contains("redaction-probe") {
            "prefix provider-redact-secret suffix"
        } else if request.contains("trigger-output-redact") {
            "output-secret"
        } else {
            "ok"
        };
        serde_json::json!({
            "id": "chatcmpl_guardrail_e2e",
            "object": "chat.completion",
            "model": "provider-model-must-remain",
            "choices": [{"message": {"role": "assistant", "content": content}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        })
        .to_string()
    };
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )?;
    Ok(())
}

fn streaming_marker(request: &str) -> Option<String> {
    let body = request.split_once("\r\n\r\n")?.1;
    let body: Value = serde_json::from_str(body).ok()?;
    body.get("input")
        .and_then(Value::as_str)
        .or_else(|| {
            body.get("messages")
                .and_then(Value::as_array)
                .and_then(|messages| messages.first())
                .and_then(|message| message.get("content"))
                .and_then(Value::as_str)
        })
        .filter(|marker| marker.starts_with("stream-"))
        .map(str::to_string)
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
            while requests.len() < expected_requests && !server_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let Ok(request) = read_http_request(&mut stream) else {
                            continue;
                        };
                        let body = if request.contains("pii@example.com") {
                            r#"{"verdict":"fail","findings":[{"category":"pii","severity":"high","segment_id":"chat:1","byte_start":12,"byte_end":27,"matched_text":"pii@example.com"}],"patches":[],"detector_version":"e2e-1"}"#
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

struct ProtectedPatchDetector {
    addr: String,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Vec<String>>>,
}

impl ProtectedPatchDetector {
    fn start() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?.to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            while requests.is_empty() && !server_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let Ok(request) = read_http_request(&mut stream) else {
                            continue;
                        };
                        let response = request
                            .split_once("\r\n\r\n")
                            .and_then(|(_, body)| serde_json::from_str::<Value>(body).ok())
                            .and_then(|body| body["segments"].as_array().cloned())
                            .and_then(|segments| segments.into_iter().next())
                            .map(|segment| {
                                let text = segment["text"].as_str().unwrap_or_default();
                                serde_json::json!({
                                    "verdict": "fail",
                                    "findings": [{
                                        "category": "adversarial.protected_patch",
                                        "severity": "critical",
                                        "confidence": 1.0,
                                        "segment_id": segment["segment_id"],
                                        "byte_start": 0,
                                        "byte_end": text.len()
                                    }],
                                    "patches": [{
                                        "segment_id": segment["segment_id"],
                                        "expected_fingerprint": segment["fingerprint"],
                                        "protocol_location": segment["protocol_location"],
                                        "byte_start": 0,
                                        "byte_end": text.len(),
                                        "replacement": "{}"
                                    }],
                                    "detector_version": "protected-patch-e2e/1"
                                })
                                .to_string()
                            })
                            .unwrap_or_else(|| {
                                r#"{"verdict":"pass","findings":[],"patches":[],"detector_version":"protected-patch-e2e/1"}"#.to_string()
                            });
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            response.len(),
                            response
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
            .context("protected patch detector join handle missing")?
            .join()
            .map_err(|_| anyhow::anyhow!("protected patch detector thread panicked"))
    }
}

impl Drop for ProtectedPatchDetector {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct SupabaseEvidence {
    client: LiveSupabaseClient,
    schema: String,
}

impl SupabaseEvidence {
    fn connect(args: &SupabaseLiveRestartArgs, schema: String) -> Result<Self> {
        Ok(Self {
            client: connect_live_supabase(args)?,
            schema,
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

    fn wait_for_guardrail_evaluations(
        &mut self,
        allowed_request_id: &str,
        blocked_request_id: &str,
        redacted_request_id: &str,
    ) -> Result<()> {
        let started = Instant::now();
        let mut last = "Guardrail evaluation rows are not visible".to_string();
        while started.elapsed() < Duration::from_secs(15) {
            match self.verify_guardrail_evaluations_once(
                allowed_request_id,
                blocked_request_id,
                redacted_request_id,
            ) {
                Ok(()) => return Ok(()),
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(150));
        }
        bail!("timed out verifying Guardrail evaluation rows in Supabase: {last}")
    }

    fn verify_guardrail_evaluations_once(
        &mut self,
        allowed_request_id: &str,
        blocked_request_id: &str,
        redacted_request_id: &str,
    ) -> Result<()> {
        let policy_count: i64 = self
            .client
            .query_one(
                "SELECT count(*) FROM pg_policies WHERE schemaname = $1 AND \
                 ((tablename = 'guardrail_evaluations' AND policyname = 'guardrail_evaluations_tenant_scope') OR \
                  (tablename = 'guardrail_check_evaluations' AND policyname = 'guardrail_checks_tenant_scope')) \
                 AND qual IS NOT NULL AND with_check IS NOT NULL",
                &[&self.schema],
            )?
            .get(0);
        if policy_count != 2 {
            bail!("Supabase Guardrail evidence tenant RLS policies were incomplete");
        }
        let rows = self.client.query(
            &format!(
                "SELECT id, request_id, evaluation_json::text FROM \"{}\".guardrail_evaluations WHERE request_id IN ($1, $2, $3) ORDER BY request_id, id",
                self.schema
            ),
            &[&allowed_request_id, &blocked_request_id, &redacted_request_id],
        )?;
        if rows.len() < 4 {
            bail!(
                "expected allow, block, and request/response redaction evaluations, got {}",
                rows.len()
            );
        }
        let mut allowed = false;
        let mut blocked = false;
        let mut redacted = false;
        let mut evaluation_ids = Vec::new();
        let mut evaluation_requests = HashMap::new();
        let mut contract_evaluation_ids = Vec::new();
        for row in rows {
            let id: String = row.get(0);
            let request_id: String = row.get(1);
            let document: String = row.get(2);
            let value: Value = serde_json::from_str(&document)?;
            if value["tenant"]["organization_id"] != DYNAMIC_TENANT_ID
                || !value["input_fingerprint"]
                    .as_str()
                    .is_some_and(|fingerprint| fingerprint.starts_with("hmac-sha256:"))
            {
                bail!("Supabase Guardrail evaluation metadata was incomplete");
            }
            if request_id == blocked_request_id
                && value["policy_id"] == "dynamic-supabase-policy"
                && value["stage"] == "request"
                && value["verdict"] == "fail"
                && value["action"] == "block"
                && value["enforcement_status"] == "enforced"
            {
                blocked = true;
            }
            if request_id == allowed_request_id
                && value["policy_id"] == "dynamic-supabase-policy"
                && value["stage"] == "request"
                && value["verdict"] == "pass"
                && value["action"] == "allow"
                && value["enforcement_status"] == "enforced"
            {
                allowed = true;
            }
            if value["policy_id"] == "dynamic-supabase-policy" && value["stage"] == "request" {
                contract_evaluation_ids.push(id.clone());
            }
            if request_id == redacted_request_id
                && value["verdict"] == "fail"
                && value["action"] == "redact"
                && value["transformed"] == true
            {
                redacted = true;
            }
            for forbidden in [
                "dynamic-secret-v1",
                "provider-redact-secret",
                "guardrail-dynamic-client-secret",
                "guardrail-redact-client-secret",
                DETECTOR_SECRET,
                "matched_text",
            ] {
                if document.contains(forbidden) {
                    bail!("Supabase Guardrail evaluation leaked forbidden content");
                }
            }
            evaluation_requests.insert(id.clone(), request_id);
            evaluation_ids.push(id);
        }
        if !allowed || !blocked || !redacted {
            bail!("Supabase Guardrail evidence omitted allow, block, or redaction decision");
        }
        let checks = self.client.query(
            &format!(
                "SELECT evaluation_id, check_json::text FROM \"{}\".guardrail_check_evaluations WHERE evaluation_id = ANY($1)",
                self.schema
            ),
            &[&evaluation_ids],
        )?;
        if checks.len() < 4 {
            bail!("Supabase Guardrail evidence omitted per-check rows");
        }
        let mut allowed_check = false;
        let mut blocked_check = false;
        for row in checks {
            let evaluation_id: String = row.get(0);
            let document: String = row.get(1);
            let value: Value = serde_json::from_str(&document)?;
            if !evaluation_ids.contains(&evaluation_id)
                || document.contains("dynamic-secret-v1")
                || document.contains("provider-redact-secret")
                || document.contains("matched_text")
            {
                bail!("Supabase Guardrail per-check evidence was unsafe or orphaned");
            }
            match evaluation_requests.get(&evaluation_id).map(String::as_str) {
                Some(request_id)
                    if request_id == allowed_request_id
                        && contract_evaluation_ids.contains(&evaluation_id) =>
                {
                    allowed_check = value["verdict"] == "pass"
                        && value["action"] == "allow"
                        && value["enforcement_status"] == "enforced"
                        && value["finding_count"] == 0;
                }
                Some(request_id)
                    if request_id == blocked_request_id
                        && contract_evaluation_ids.contains(&evaluation_id) =>
                {
                    blocked_check = value["verdict"] == "fail"
                        && value["action"] == "block"
                        && value["enforcement_status"] == "enforced"
                        && value["finding_count"] == 1;
                }
                _ => {}
            }
        }
        if !allowed_check || !blocked_check {
            bail!("Supabase Guardrail per-check evidence omitted allow or block semantics");
        }

        let audit_rows = self.client.query(
            &format!(
                "SELECT request_id, action, target, outcome FROM \"{}\".audit_events WHERE request_id IN ($1, $2)",
                self.schema
            ),
            &[&allowed_request_id, &blocked_request_id],
        )?;
        let mut allowed_audit = false;
        let mut blocked_policy_audit = false;
        let mut blocked_deny_audit = false;
        for row in audit_rows {
            let request_id: String = row.get(0);
            let action: String = row.get(1);
            let target: Option<String> = row.get(2);
            let outcome: String = row.get(3);
            match (
                request_id.as_str(),
                action.as_str(),
                target.as_deref(),
                outcome.as_str(),
            ) {
                (
                    request_id,
                    "guardrail.policy_evaluate",
                    Some("dynamic-supabase-policy@1"),
                    "pass",
                ) if request_id == allowed_request_id => {
                    allowed_audit = true;
                }
                (
                    request_id,
                    "guardrail.policy_evaluate",
                    Some("dynamic-supabase-policy@1"),
                    "fail",
                ) if request_id == blocked_request_id => {
                    blocked_policy_audit = true;
                }
                (request_id, "guardrail.deny", _, "blocked")
                    if request_id == blocked_request_id =>
                {
                    blocked_deny_audit = true;
                }
                _ => {}
            }
        }
        if !allowed_audit || !blocked_policy_audit || !blocked_deny_audit {
            bail!("Supabase Guardrail audit evidence omitted allow or block outcomes");
        }

        let request_rows = self.client.query(
            &format!(
                "SELECT request_id, status_code, error_code FROM \"{}\".request_logs WHERE request_id IN ($1, $2)",
                self.schema
            ),
            &[&allowed_request_id, &blocked_request_id],
        )?;
        let mut allowed_request = false;
        let mut blocked_request = false;
        for row in request_rows {
            let request_id: String = row.get(0);
            let status_code: Option<i32> = row.get(1);
            let error_code: Option<String> = row.get(2);
            if request_id == allowed_request_id && status_code == Some(200) && error_code.is_none()
            {
                allowed_request = true;
            }
            if request_id == blocked_request_id
                && status_code == Some(403)
                && error_code.as_deref() == Some("dynamic_guardrail_v1")
            {
                blocked_request = true;
            }
        }
        if !allowed_request || !blocked_request {
            bail!("Supabase request logs omitted Guardrail allow or block outcome");
        }
        Ok(())
    }

    fn wait_for_protected_patch_rejection(&mut self, request_id: &str) -> Result<()> {
        let audit_query = format!(
            "SELECT target, outcome, audit_json::text FROM \"{}\".audit_events WHERE request_id = $1 AND action = 'guardrail.detector_error'",
            self.schema
        );
        let request_query = format!(
            "SELECT status_code, error_code FROM \"{}\".request_logs WHERE request_id = $1",
            self.schema
        );
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(15) {
            if let Some(audit_row) = self.client.query_opt(&audit_query, &[&request_id])? {
                let target: Option<String> = audit_row.get(0);
                let outcome: String = audit_row.get(1);
                let audit_json: String = audit_row.get(2);
                let request_row = self.client.query_opt(&request_query, &[&request_id])?;
                if target.as_deref() == Some("protected-patch-policy@1/metadata-patch")
                    && outcome == "blocked"
                    && audit_json.contains("protected_path")
                    && request_row.as_ref().is_some_and(|row| {
                        row.get::<_, Option<i32>>(0) == Some(403)
                            && row.get::<_, Option<String>>(1).as_deref()
                                == Some("protected_patch_rejected")
                    })
                {
                    return Ok(());
                }
            }
            thread::sleep(Duration::from_millis(150));
        }
        bail!("timed out reading protected patch rejection evidence from Supabase")
    }

    fn verify_guardrail_rbac_binding(&mut self, role_id: &str, expected_bound: bool) -> Result<()> {
        let permission_count: i64 = self
            .client
            .query_one(
                &format!(
                    "SELECT count(*) FROM \"{}\".permissions WHERE key LIKE 'guardrails.policy.%' OR key = 'guardrails.evidence.read'",
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
                    "SELECT permission_keys_json::text FROM \"{}\".roles WHERE id = $1",
                    self.schema
                ),
                &[&role_id],
            )?
            .context("Supabase omitted the generated Guardrail policy role")?;
        let permission_keys_json: String = role_row.get(0);
        let permission_keys: Vec<String> = serde_json::from_str(&permission_keys_json)?;
        if !GUARDRAIL_ACTIONS
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
                &[&DYNAMIC_TENANT_ID, &role_id],
            )?
            .get(0);
        if (binding_count == 1) != expected_bound {
            bail!(
                "Supabase Guardrail role binding state was wrong: expected_bound={expected_bound}, count={binding_count}"
            );
        }
        Ok(())
    }

    fn wait_for_streaming_semantics(&mut self) -> Result<()> {
        let started = Instant::now();
        let mut last = "Supabase streaming Guardrail evidence not visible yet".to_string();
        while started.elapsed() < Duration::from_secs(15) {
            match self.verify_streaming_semantics_once() {
                Ok(()) => return Ok(()),
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(150));
        }
        bail!("timed out verifying streaming Guardrail evidence in Supabase: {last}")
    }

    fn verify_streaming_semantics_once(&mut self) -> Result<()> {
        let rows = self.client.query(
            &format!(
                "SELECT action, target, outcome, audit_json::text FROM \"{}\".audit_events WHERE target LIKE 'stream-%'",
                self.schema
            ),
            &[],
        )?;
        let mut buffered_fail = false;
        let mut buffered_error = false;
        let mut shadow_not_enforced = false;
        let mut rejected = false;
        let mut normalized_location = false;
        for row in rows {
            let action: String = row.get(0);
            let target: Option<String> = row.get(1);
            let outcome: String = row.get(2);
            let audit_json: String = row.get(3);
            if audit_json.contains("split-secret")
                || audit_json.contains("normalized-input-secret")
                || audit_json.contains("overflow-sensitive")
            {
                bail!("streaming Guardrail audit leaked inspected content");
            }
            match (action.as_str(), target.as_deref(), outcome.as_str()) {
                ("guardrail.policy_evaluate", Some("stream-buffer-policy@1"), "fail") => {
                    buffered_fail = true;
                }
                ("guardrail.policy_evaluate", Some("stream-buffer-policy@1"), "error") => {
                    buffered_error = true;
                    let audit: Value = serde_json::from_str(&audit_json)?;
                    if !audit["message"].as_str().is_some_and(|message| {
                        message.contains("guardrail_stream_buffer_limit_exceeded")
                            && !message.contains("overflow-sensitive")
                    }) {
                        bail!("buffer overflow audit evidence was not sanitized");
                    }
                }
                ("guardrail.policy_evaluate", Some("stream-shadow-policy@1"), "not_enforced") => {
                    shadow_not_enforced = true
                }
                ("guardrail.policy_evaluate", Some("stream-reject-policy@1"), "fail") => {
                    rejected = true;
                }
                ("guardrail.deny", Some(target), "blocked")
                    if target.starts_with("stream-shadow-policy@1") =>
                {
                    bail!("shadow streaming policy emitted a blocked audit outcome");
                }
                ("guardrail.deny", Some(target), "blocked")
                    if target.starts_with("stream-buffer-policy@1") =>
                {
                    let audit: Value = serde_json::from_str(&audit_json)?;
                    normalized_location |= audit["message"].as_str().is_some_and(|message| {
                        message.contains("segment ") && message.contains(" bytes ")
                    });
                }
                _ => {}
            }
        }
        if !buffered_fail
            || !buffered_error
            || !shadow_not_enforced
            || !rejected
            || !normalized_location
        {
            bail!(
                "streaming Guardrail evidence incomplete: buffered={buffered_fail}, buffer_error={buffered_error}, shadow={shadow_not_enforced}, rejected={rejected}, location={normalized_location}"
            );
        }

        let request_codes = self.client.query(
            &format!(
                "SELECT error_code FROM \"{}\".request_logs WHERE error_code IN ('guardrail_stream_buffered', 'guardrail_stream_buffer_unavailable', 'guardrail_streaming_unsupported')",
                self.schema
            ),
            &[],
        )?;
        let mut buffered_code = false;
        let mut buffered_error_code = false;
        let mut rejected_code = false;
        for row in request_codes {
            match row.get::<_, Option<String>>(0).as_deref() {
                Some("guardrail_stream_buffered") => buffered_code = true,
                Some("guardrail_stream_buffer_unavailable") => buffered_error_code = true,
                Some("guardrail_streaming_unsupported") => rejected_code = true,
                _ => {}
            }
        }
        if !buffered_code || !buffered_error_code || !rejected_code {
            bail!("request logs omitted stable streaming Guardrail error codes");
        }

        let evaluations = self.client.query(
            &format!(
                "SELECT evaluation.policy_id, evaluation.enforcement_status, check_row.verdict, check_row.error_kind \
                 FROM \"{}\".guardrail_evaluations AS evaluation \
                 JOIN \"{}\".guardrail_check_evaluations AS check_row ON check_row.evaluation_id = evaluation.id \
                 WHERE evaluation.policy_id IN ('stream-buffer-policy', 'stream-shadow-policy', 'stream-reject-policy')",
                self.schema, self.schema
            ),
            &[],
        )?;
        let mut buffered_check_error = false;
        let mut shadow_check_not_enforced = false;
        let mut rejected_check_skipped = false;
        for row in evaluations {
            let policy_id: String = row.get(0);
            let enforcement_status: String = row.get(1);
            let verdict: String = row.get(2);
            let error_kind: Option<String> = row.get(3);
            match policy_id.as_str() {
                "stream-buffer-policy"
                    if verdict == "error"
                        && error_kind.as_deref()
                            == Some("guardrail_stream_buffer_limit_exceeded") =>
                {
                    buffered_check_error = true;
                }
                "stream-shadow-policy" if enforcement_status == "not_enforced" => {
                    shadow_check_not_enforced = true;
                }
                "stream-reject-policy"
                    if verdict == "skipped"
                        && error_kind.as_deref() == Some("streaming_unsupported") =>
                {
                    rejected_check_skipped = true;
                }
                _ => {}
            }
        }
        if !buffered_check_error || !shadow_check_not_enforced || !rejected_check_skipped {
            bail!(
                "streaming per-check evidence incomplete: buffer_error={buffered_check_error}, shadow={shadow_check_not_enforced}, rejected={rejected_check_skipped}"
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
                || policy["checks"][0]["sources"] != serde_json::json!(["user"])
            {
                bail!("immutable Guardrail revision metadata diverged from policy_json");
            }
        }

        let binding = self
            .client
            .query_opt(
                &format!(
                    "SELECT active_revision, archived_revisions_json::text, generation FROM \"{}\".guardrail_policy_bindings WHERE policy_id = 'dynamic-supabase-policy'",
                    self.schema
                ),
                &[],
            )?
            .context("Guardrail policy binding was not persisted")?;
        let active_revision: Option<i64> = binding.get(0);
        let archived_json: String = binding.get(1);
        let generation: i64 = binding.get(2);
        let archived: Vec<u32> = serde_json::from_str(&archived_json)?;
        if active_revision != Some(1) || archived != vec![2] || generation <= 0 {
            bail!(
                "Guardrail rollback binding was incorrect: active={active_revision:?}, archived={archived:?}, generation={generation}"
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
}
