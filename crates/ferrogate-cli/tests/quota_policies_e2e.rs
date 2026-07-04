// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-04
// description: End-to-end proof of the P1-3 multi-level quota/rate-limit
// admin surface against a real running gateway: bootstrap a tenant ->
// project -> workspace -> virtual key over HTTP, attach a quota policy over
// HTTP, then drive a real chat completion request through the durable-key
// hot path to prove enforcement (not just that the code compiles).

mod support;

use support::{free_addr, http_request, spawn_provider_upstream, start_gateway, wait_for_gateway};

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
name = "Admin bootstrap key"
key = "admin-secret"
"#
        ),
    )
    .unwrap();
}

fn admin_headers() -> Vec<&'static str> {
    vec![
        "Authorization: Bearer admin-secret",
        "Content-Type: application/json",
    ]
}

fn response_json(response: String) -> serde_json::Value {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(&response);
    serde_json::from_str(body).unwrap_or_else(|error| panic!("invalid JSON: {error}; {response}"))
}

fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or_default()
}

#[test]
fn quota_policy_admin_surface_bootstraps_hierarchy_and_enforces_tpm_and_model_allowlist() {
    let gateway_addr = free_addr();
    let (provider_addr, _provider_handle) = spawn_provider_upstream(
        1,
        r#"{"id":"chatcmpl_quota","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr, &provider_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    // 1. Bootstrap tenant -> project -> workspace over the real admin HTTP
    // surface (not by touching storage in-process).
    let tenant = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &admin_headers(),
        r#"{"id":"tenant-e2e","name":"Tenant E2E","slug":"tenant-e2e"}"#,
    ));
    assert_eq!(tenant["tenant"]["id"], "tenant-e2e");

    let project = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/projects",
        &admin_headers(),
        r#"{"id":"project-e2e","tenant_id":"tenant-e2e","name":"Project E2E","slug":"project-e2e"}"#,
    ));
    assert_eq!(project["project"]["tenant_id"], "tenant-e2e");

    let workspace = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/workspaces",
        &admin_headers(),
        r#"{"id":"workspace-e2e","project_id":"project-e2e","name":"Workspace E2E","slug":"workspace-e2e"}"#,
    ));
    assert_eq!(workspace["workspace"]["project_id"], "project-e2e");

    // 2. Create a durable virtual key bound to the workspace; the plaintext
    // secret is only ever returned here.
    let created_key = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/virtual-keys",
        &admin_headers(),
        r#"{"name":"E2E key","workspace_id":"workspace-e2e","scopes":["chat.completions"],"allowed_models":["fast-chat"]}"#,
    ));
    let secret = created_key["secret"]
        .as_str()
        .expect("create response must include the plaintext secret")
        .to_string();
    assert!(secret.starts_with("fg_"));
    let key_id = created_key["key"]["id"]
        .as_str()
        .expect("create response must include the key id")
        .to_string();
    assert_eq!(created_key["key"]["workspace_id"], "workspace-e2e");
    assert_eq!(created_key["key"]["tenant_id"], "tenant-e2e");

    // A list call must never leak the hash or the secret.
    let listed = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/virtual-keys",
        &admin_headers(),
        "",
    );
    assert!(!listed.contains(&secret));
    assert!(!listed.contains("key_hash"));

    // 3. The freshly created key authenticates and can call chat.completions
    // before any quota policy narrows it.
    let baseline = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            &format!("Authorization: Bearer {secret}"),
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[]}"#,
    );
    assert!(
        status_line(&baseline).contains("200 OK"),
        "baseline request should succeed before any quota policy applies: {baseline}"
    );

    // 4. Attach a project-scoped quota policy that narrows the model
    // allowlist to a model this key was never granted -- the effective
    // allowlist becomes the (empty) intersection, so every model is denied.
    let quota_models = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/quota-policies",
        &admin_headers(),
        r#"{"scope_type":"project","scope_id":"project-e2e","model_allowlist":["other-model"]}"#,
    ));
    assert_eq!(quota_models["policy"]["scope_type"], "project");

    let denied_by_allowlist = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            &format!("Authorization: Bearer {secret}"),
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[]}"#,
    );
    assert!(
        status_line(&denied_by_allowlist).contains("403"),
        "project quota policy must narrow the allowlist: {denied_by_allowlist}"
    );
    assert!(denied_by_allowlist.contains("model_not_allowed"));

    // 5. Replace the project policy with one that permits fast-chat again,
    // and add a tenant-scoped TPM cap tight enough that this single
    // request's estimated usage (~8 tokens) exceeds it.
    let replace_models = response_json(http_request(
        &gateway_addr,
        "PUT",
        "/admin/v1/quota-policies/project/project-e2e",
        &admin_headers(),
        r#"{"model_allowlist":["fast-chat"]}"#,
    ));
    assert_eq!(
        replace_models["policy"]["model_allowlist"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // The request below asks for max_tokens=4 (and near-zero prompt tokens
    // from an empty message list), so its estimated usage is ~4 tokens; a
    // tpm_limit of 2 is comfortably below that regardless of exact rounding
    // in the prompt-token estimator.
    let quota_tpm = response_json(http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/quota-policies",
        &admin_headers(),
        r#"{"scope_type":"tenant","scope_id":"tenant-e2e","tpm_limit":2}"#,
    ));
    assert_eq!(quota_tpm["policy"]["tpm_limit"], 2);

    let denied_by_tpm = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            &format!("Authorization: Bearer {secret}"),
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[],"max_tokens":4}"#,
    );
    assert!(
        status_line(&denied_by_tpm).contains("429"),
        "tenant TPM policy tighter than the estimated usage must reject: {denied_by_tpm}"
    );
    assert!(denied_by_tpm.contains("tpm_limit_exceeded"));

    // 6. PATCH-disabling the tenant-level quota policy is a hard deny
    // regardless of RPM/TPM/model-allowlist specifics -- and, since PATCH
    // merges rather than replaces, the tpm_limit set in step 5 must survive
    // this call untouched (proving PATCH doesn't silently wipe it the way a
    // naive full-replace would).
    let disable = response_json(http_request(
        &gateway_addr,
        "PATCH",
        "/admin/v1/quota-policies/tenant/tenant-e2e",
        &admin_headers(),
        r#"{"enabled":false}"#,
    ));
    assert_eq!(disable["policy"]["enabled"], false);
    assert_eq!(
        disable["policy"]["tpm_limit"], 2,
        "PATCH must merge, not replace: tpm_limit from step 5 must survive"
    );

    let denied_by_disabled_scope = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            &format!("Authorization: Bearer {secret}"),
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[]}"#,
    );
    assert!(
        status_line(&denied_by_disabled_scope).contains("403"),
        "disabling the tenant scope must hard-deny: {denied_by_disabled_scope}"
    );
    assert!(denied_by_disabled_scope.contains("quota_scope_disabled"));

    // 7. Clean up the tenant-level policy and confirm the key id survives a
    // GET, then delete the project-level policy and confirm 404 afterward.
    let get_key = response_json(http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/virtual-keys/{key_id}"),
        &admin_headers(),
        "",
    ));
    assert_eq!(get_key["key"]["id"], key_id);
    assert!(get_key.get("secret").is_none() || get_key["secret"].is_null());

    let delete_response = http_request(
        &gateway_addr,
        "DELETE",
        "/admin/v1/quota-policies/project/project-e2e",
        &admin_headers(),
        "",
    );
    assert!(status_line(&delete_response).contains("200 OK"));

    let get_after_delete = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/quota-policies/project/project-e2e",
        &admin_headers(),
        "",
    );
    assert!(status_line(&get_after_delete).contains("404"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
