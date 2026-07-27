// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Live regression for issue #514 -- "suspension enforces nothing".
// This is the test-gate audit's own probe, turned into a test. Before the fix,
// against a real gateway process, after suspending the tenant (200 OK):
//   * a pre-existing virtual key still returned 200 from GET /v1/models;
//   * the same key still PASSED auth on POST /v1/chat/completions;
//   * a brand-new virtual key could still be minted under the suspended chain
//     (201 + live secret);
//   * POST /admin/v1/projects under the suspended tenant returned 201.
// Every one of those is asserted here, in both directions (before suspension it
// works, after suspension it is refused, after un-suspension it works again) so
// the assertions cannot pass vacuously against a gateway that refuses
// everything.

mod support;

use support::{free_addr, http_request, spawn_provider_upstream, start_gateway, wait_for_gateway};

const ADMIN: [&str; 2] = [
    "Authorization: Bearer admin-secret",
    "Content-Type: application/json",
];

fn write_config(path: &std::path::Path, gateway_addr: &str, provider_addr: &str) {
    std::fs::write(
        path,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"

[[api_keys]]
id = "admin"
name = "Platform operator"
key = "admin-secret"
"#
        ),
    )
    .unwrap();
}

fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or_default()
}

fn body_json(response: &str) -> serde_json::Value {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(response);
    serde_json::from_str(body).unwrap_or_else(|error| panic!("invalid JSON: {error}; {response}"))
}

fn admin(gateway_addr: &str, method: &str, path: &str, body: &str) -> String {
    http_request(gateway_addr, method, path, &ADMIN, body)
}

fn as_key(gateway_addr: &str, secret: &str, method: &str, path: &str, body: &str) -> String {
    http_request(
        gateway_addr,
        method,
        path,
        &[
            &format!("Authorization: Bearer {secret}"),
            "Content-Type: application/json",
        ],
        body,
    )
}

fn set_tenant_status(gateway_addr: &str, status: &str) {
    let response = admin(
        gateway_addr,
        "PUT",
        "/admin/v1/tenant-accounts/tenant-susp",
        &format!(r#"{{"name":"Suspendable","slug":"tenant-susp","status":"{status}"}}"#),
    );
    assert!(
        status_line(&response).contains("200"),
        "setting tenant status to {status} failed: {response}"
    );
}

/// The error body a refused request must carry: a typed 403 with a
/// distinguishable code -- never a panic, never a generic 500, never a silent
/// 200.
fn assert_suspended_rejection(response: &str, expected_code: &str) {
    assert!(
        status_line(response).contains("403"),
        "expected a 403-shaped rejection, got: {response}"
    );
    let body = body_json(response);
    let code = body["error"]["code"]
        .as_str()
        .or_else(|| body["code"].as_str())
        .unwrap_or_else(|| panic!("rejection body carries no error code: {body}"));
    assert_eq!(code, expected_code, "unexpected rejection code in {body}");
}

#[test]
fn suspending_a_tenant_stops_its_keys_and_blocks_new_credentials() {
    let gateway_addr = free_addr();
    // Two upstream responses: one for the pre-suspension baseline, one for the
    // post-reactivation control. If suspension leaked a single request through,
    // the upstream would be over-consumed and the control call would fail --
    // the counter is part of the proof.
    let (provider_addr, _provider) = spawn_provider_upstream(
        2,
        r#"{"id":"chatcmpl_susp","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, &provider_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    // --- Bootstrap tenant -> project -> workspace -> virtual key ------------
    let tenant = admin(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        r#"{"id":"tenant-susp","name":"Suspendable","slug":"tenant-susp"}"#,
    );
    assert!(
        status_line(&tenant).contains("200") || status_line(&tenant).contains("201"),
        "tenant setup: {tenant}"
    );
    let project = admin(
        &gateway_addr,
        "POST",
        "/admin/v1/projects",
        r#"{"id":"proj-susp","tenant_id":"tenant-susp","name":"Proj","slug":"proj-susp"}"#,
    );
    assert!(
        status_line(&project).contains("200") || status_line(&project).contains("201"),
        "project setup: {project}"
    );
    let workspace = admin(
        &gateway_addr,
        "POST",
        "/admin/v1/workspaces",
        r#"{"id":"ws-susp","project_id":"proj-susp","name":"Ws","slug":"ws-susp"}"#,
    );
    assert!(
        status_line(&workspace).contains("200") || status_line(&workspace).contains("201"),
        "workspace setup: {workspace}"
    );
    let created = body_json(&admin(
        &gateway_addr,
        "POST",
        "/admin/v1/virtual-keys",
        r#"{"name":"Pre-existing key","workspace_id":"ws-susp","scopes":["chat.completions","models.read"]}"#,
    ));
    let secret = created["secret"]
        .as_str()
        .expect("create must return the plaintext secret")
        .to_string();

    // --- Baseline: everything works while the tenant is active -------------
    let models = as_key(&gateway_addr, &secret, "GET", "/v1/models", "");
    assert!(
        status_line(&models).contains("200"),
        "baseline GET /v1/models must succeed while active: {models}"
    );
    let chat = as_key(
        &gateway_addr,
        &secret,
        "POST",
        "/v1/chat/completions",
        r#"{"model":"fast-chat","messages":[]}"#,
    );
    assert!(
        status_line(&chat).contains("200"),
        "baseline chat completion must succeed while active: {chat}"
    );

    // --- Suspend the tenant ------------------------------------------------
    set_tenant_status(&gateway_addr, "suspended");

    // 1. Request-time seam: the PRE-EXISTING key stops working. This is the
    //    one that matters for billing -- before #514 this returned 200.
    let models = as_key(&gateway_addr, &secret, "GET", "/v1/models", "");
    assert_suspended_rejection(&models, "tenancy_suspended");

    // 2. Same key, the spend-generating route. Before #514 this reached model
    //    resolution (400 model_not_found), i.e. it had PASSED authentication.
    let chat = as_key(
        &gateway_addr,
        &secret,
        "POST",
        "/v1/chat/completions",
        r#"{"model":"fast-chat","messages":[]}"#,
    );
    assert_suspended_rejection(&chat, "tenancy_suspended");

    // 3. Attach-time seam: no fresh virtual key under the suspended chain.
    //    Before #514 this returned 201 with a live secret.
    let minted = admin(
        &gateway_addr,
        "POST",
        "/admin/v1/virtual-keys",
        r#"{"name":"Minted while suspended","workspace_id":"ws-susp","scopes":["chat.completions"]}"#,
    );
    assert_suspended_rejection(&minted, "inactive_tenancy_reference");
    assert!(
        !body_json(&minted).to_string().contains("fg_"),
        "a refused mint must not leak a secret: {minted}"
    );

    // 4. Attach-time seam: no new project under the suspended tenant.
    let new_project = admin(
        &gateway_addr,
        "POST",
        "/admin/v1/projects",
        r#"{"id":"proj-susp-2","tenant_id":"tenant-susp","name":"Proj2","slug":"proj-susp-2"}"#,
    );
    assert_suspended_rejection(&new_project, "inactive_tenancy_reference");

    // 5. Attach-time seam: no new workspace under the suspended tenant's
    //    (still nominally active) project -- the chain is checked whole.
    let new_workspace = admin(
        &gateway_addr,
        "POST",
        "/admin/v1/workspaces",
        r#"{"id":"ws-susp-2","project_id":"proj-susp","name":"Ws2","slug":"ws-susp-2"}"#,
    );
    assert_suspended_rejection(&new_workspace, "inactive_tenancy_reference");

    // 6. Attach-time seam: no native api-key scoped to the suspended chain.
    let new_api_key = admin(
        &gateway_addr,
        "POST",
        "/admin/v1/api-keys",
        r#"{"id":"ak-susp","name":"AK","key":"ak-secret-value","project_id":"proj-susp"}"#,
    );
    assert_suspended_rejection(&new_api_key, "inactive_tenancy_reference");

    // --- Reactivate: suspension is reversible, and un-suspending is itself
    // --- never blocked (the operator key carries no organization_id).
    set_tenant_status(&gateway_addr, "active");
    let models = as_key(&gateway_addr, &secret, "GET", "/v1/models", "");
    assert!(
        status_line(&models).contains("200"),
        "the same key must work again once the tenant is reactivated: {models}"
    );
    let chat = as_key(
        &gateway_addr,
        &secret,
        "POST",
        "/v1/chat/completions",
        r#"{"model":"fast-chat","messages":[]}"#,
    );
    assert!(
        status_line(&chat).contains("200"),
        "spend must resume after reactivation: {chat}"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
}

/// Suspension at the project level alone must hold too: an operator who
/// suspends one business line must not be silently ignored because the tenant
/// above it is healthy. Also pins the dangerous default -- a SIBLING project
/// created before any status was ever written keeps serving.
#[test]
fn suspending_one_project_stops_only_that_projects_keys() {
    let gateway_addr = free_addr();
    let (provider_addr, _provider) = spawn_provider_upstream(
        1,
        r#"{"id":"chatcmpl_leaf","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, &provider_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    admin(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        r#"{"id":"tenant-leaf","name":"Leaf","slug":"tenant-leaf"}"#,
    );
    for (project, workspace) in [("proj-a", "ws-a"), ("proj-b", "ws-b")] {
        admin(
            &gateway_addr,
            "POST",
            "/admin/v1/projects",
            &format!(
                r#"{{"id":"{project}","tenant_id":"tenant-leaf","name":"{project}","slug":"{project}"}}"#
            ),
        );
        admin(
            &gateway_addr,
            "POST",
            "/admin/v1/workspaces",
            &format!(
                r#"{{"id":"{workspace}","project_id":"{project}","name":"{workspace}","slug":"{workspace}"}}"#
            ),
        );
    }
    let mut secrets = Vec::new();
    for workspace in ["ws-a", "ws-b"] {
        let created = body_json(&admin(
            &gateway_addr,
            "POST",
            "/admin/v1/virtual-keys",
            &format!(
                r#"{{"name":"{workspace} key","workspace_id":"{workspace}","scopes":["chat.completions","models.read"]}}"#
            ),
        ));
        secrets.push(
            created["secret"]
                .as_str()
                .expect("create must return the plaintext secret")
                .to_string(),
        );
    }

    let suspend = admin(
        &gateway_addr,
        "PUT",
        "/admin/v1/projects/proj-a",
        r#"{"tenant_id":"tenant-leaf","name":"proj-a","slug":"proj-a","status":"suspended"}"#,
    );
    assert!(
        status_line(&suspend).contains("200"),
        "suspending proj-a failed: {suspend}"
    );

    let blocked = as_key(&gateway_addr, &secrets[0], "GET", "/v1/models", "");
    assert_suspended_rejection(&blocked, "tenancy_suspended");

    // The sibling project was never touched: it must be completely unaffected.
    // This is the guard against an over-broad fix that denies everything.
    let unaffected = as_key(&gateway_addr, &secrets[1], "GET", "/v1/models", "");
    assert!(
        status_line(&unaffected).contains("200"),
        "an untouched sibling project's key must keep working: {unaffected}"
    );
    let unaffected_chat = as_key(
        &gateway_addr,
        &secrets[1],
        "POST",
        "/v1/chat/completions",
        r#"{"model":"fast-chat","messages":[]}"#,
    );
    assert!(
        status_line(&unaffected_chat).contains("200"),
        "an untouched sibling project's key must keep spending: {unaffected_chat}"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
}
