// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: HTTP-level end-to-end proof for issue #357 (observed
//   "Unknown" agent activity). A tenant-scoped virtual API key that drives
//   data-plane traffic WITHOUT any verified managed-worker / self-hosted /
//   agent-run identity surfaces on `GET /admin/v1/observed-agent-activity`
//   as exactly ONE coalesced Unknown/unattributed/running row per (tenant,
//   key) -- re-derived from the request logs the gateway already records on
//   the hot path. Proven end-to-end (real gateway process, real chat proxy,
//   real admin read), not by unit-testing the derivation in isolation:
//     1. unattributed requests on one key coalesce into ONE running row
//        carrying the exact contract strings (source/identity_status/
//        display_name/status/status_basis) and an operator-visible TTL,
//     2. spoof resistance: a request that carries a CLIENT-SUPPLIED
//        agent-run id (an `X-FerroGate-Agent-Run-Id` header, which the chat
//        path stamps on the request log but which creates NO verified
//        agent-run record) is NOT reclassified as attributed -- it still
//        folds into the Unknown row, so a caller cannot launder itself out
//        of the Unknown surface by inventing a run id,
//     3. a second tenant's key produces its own separate Unknown row,
//     4. tenant-scoped operators see ONLY their own tenant's row
//        (cross-tenant denial), while the platform operator sees both.
//   (The inverse -- a VERIFIED managed/self-hosted/agent-run identity is
//   never surfaced as Unknown -- is exhaustively unit-tested at the
//   derivation layer in `observed_agent_activity_test.rs`; reaching it here
//   would require standing up the full agent runtime, out of this slice's
//   read-only scope.)

mod support;

use serde_json::Value;
use support::{free_addr, http_request, spawn_provider_upstream, start_gateway, wait_for_gateway};

/// Issue #357 acceptance, end-to-end over a live gateway: operator input
/// (virtual keys owned by tenants) -> runtime touch (chat proxy traffic) ->
/// durable projection (request logs) -> tenant-scoped API output (the observed
/// activity list) -> UI-facing contract strings -> spoof resistance ->
/// cross-tenant denial.
#[test]
fn unattributed_virtual_key_activity_surfaces_as_tenant_scoped_unknown_running() {
    let gateway_addr = free_addr();
    // Four data-plane chat exchanges reach the stub upstream: two unattributed
    // (tenant A), one attributed-by-verified-run (tenant A), one unattributed
    // (tenant B). Each carries a usage block so the token evidence can fold.
    let (provider_addr, provider) = spawn_provider_upstream(
        4,
        r#"{"id":"chatcmpl_357","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
    );
    // Three tenant-A exchanges (two bare + one spoofed-run header) plus one
    // tenant-B exchange reach the stub upstream.

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        observed_activity_config(&gateway_addr, &provider_addr),
    )
    .unwrap();
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    // --- Runtime touch: tenant-A virtual key drives two unattributed chat
    //     requests (no agent-run header => request logs carry no run id). ---
    for _ in 0..2 {
        let chat = chat_completion(&gateway_addr, "vkey-a-secret", None);
        assert!(chat.contains("200 OK"), "{chat}");
    }

    // --- Spoof resistance: a THIRD tenant-A request that declares a
    //     client-supplied agent-run id. The chat path stamps this onto the
    //     request log but creates NO verified agent-run record, so it must
    //     STILL fold into the Unknown row (a caller cannot launder itself out
    //     of the Unknown surface by inventing a run id). ---
    let spoofed = chat_completion(&gateway_addr, "vkey-a-secret", Some("spoofed-run-357"));
    assert!(spoofed.contains("200 OK"), "{spoofed}");

    // --- A second tenant's virtual key: its own separate Unknown row. ---
    let tenant_b = chat_completion(&gateway_addr, "vkey-b-secret", None);
    assert!(tenant_b.contains("200 OK"), "{tenant_b}");

    // ================= Platform operator: cross-tenant view. =================
    let all = observed_activity(&gateway_addr, "admin-secret");
    let rows = all["data"].as_array().expect("data is a list");
    assert_eq!(
        rows.len(),
        2,
        "exactly one Unknown row per (tenant, key); the spoofed-run request must not spawn a third: {all}"
    );

    // Most-recently-observed-first sort; find each tenant's row explicitly.
    let row_a = find_row(rows, "org_a", "vkey-a");
    let row_b = find_row(rows, "org_b", "vkey-b");

    // --- The exact UI-facing contract strings (do not soften). ---
    assert_eq!(row_a["id"], "observed:org_a:vkey-a", "{row_a}");
    assert_eq!(row_a["source"], "virtual_api_key", "{row_a}");
    assert_eq!(row_a["identity_status"], "unattributed", "{row_a}");
    assert_eq!(row_a["display_name"], "Unknown", "{row_a}");
    assert_eq!(row_a["status"], "running", "{row_a}");
    assert_eq!(row_a["status_basis"], "recent_api_key_activity", "{row_a}");
    assert_eq!(row_a["tenant_id"], "org_a", "{row_a}");
    assert_eq!(row_a["api_key_id"], "vkey-a", "{row_a}");
    assert_eq!(row_a["project_id"], "project_a", "{row_a}");
    // The running-window TTL is surfaced on every row so the window is
    // operator-visible (default 60s).
    assert_eq!(row_a["running_ttl_seconds"], 60, "{row_a}");

    // --- Coalescing + spoof resistance: all THREE tenant-A requests fold
    //     into one row, including the spoofed-run-header request (which is
    //     not attributed to any verified run). ---
    let evidence = &row_a["evidence"];
    assert_eq!(evidence["evidence_source"], "request_logs", "{row_a}");
    assert_eq!(
        evidence["request_count"], 3,
        "all three tenant-A requests coalesce into one row; the spoofed run id does not attribute the traffic away from Unknown: {row_a}"
    );
    assert_eq!(evidence["within_running_window"], true, "{row_a}");
    // #494: on a healthy read the feed is explicitly `available` and the list
    // says so too, so the operator never has to infer whether the answer was
    // decidable.
    assert_eq!(evidence["presence_feed_status"], "available", "{row_a}");
    assert!(
        evidence["presence_unavailable_reason"].is_null(),
        "a healthy read names no condition: {row_a}"
    );
    assert_eq!(all["presence_feed"]["status"], "available", "{all}");
    assert_eq!(
        all["presence_feed"]["rows_may_be_incomplete"], false,
        "a healthy read is complete: {all}"
    );

    // --- Usage evidence folds when settled billing/metering is available;
    //     when present it must be real (never invented). Metering settlement is
    //     asynchronous, so treat availability as best-effort but assert the
    //     invariant: available => positive folded tokens; absent => omitted. ---
    if evidence["usage_evidence_available"] == Value::Bool(true) {
        assert!(
            evidence["total_tokens"].as_u64().unwrap_or(0) > 0,
            "folded usage must be real when reported available: {row_a}"
        );
    } else {
        assert!(
            evidence["total_tokens"].is_null(),
            "absent usage stays omitted, never zeroed: {row_a}"
        );
    }

    // The second tenant is present in the operator view.
    assert_eq!(row_b["display_name"], "Unknown", "{row_b}");
    assert_eq!(row_b["tenant_id"], "org_b", "{row_b}");

    // ================= Tenant isolation / cross-tenant denial. ===============
    let a_scoped = observed_activity(&gateway_addr, "admin-a-secret");
    let a_rows = a_scoped["data"].as_array().unwrap();
    assert_eq!(
        a_rows.len(),
        1,
        "tenant-A operator sees only its own row: {a_scoped}"
    );
    assert_eq!(a_rows[0]["tenant_id"], "org_a", "{a_scoped}");
    assert!(
        !a_scoped.to_string().contains("org_b"),
        "tenant-A operator must never see tenant B's observed activity: {a_scoped}"
    );

    let b_scoped = observed_activity(&gateway_addr, "admin-b-secret");
    let b_rows = b_scoped["data"].as_array().unwrap();
    assert_eq!(
        b_rows.len(),
        1,
        "tenant-B operator sees only its own row: {b_scoped}"
    );
    assert_eq!(b_rows[0]["tenant_id"], "org_b", "{b_scoped}");
    assert!(
        !b_scoped.to_string().contains("org_a"),
        "tenant-B operator must never see tenant A's observed activity: {b_scoped}"
    );

    let forwarded = provider.join().unwrap();
    assert_eq!(
        forwarded.len(),
        4,
        "all four chat exchanges reached upstream"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Drive one chat/completions request through the given virtual key, optionally
/// declaring an agent-run identity (which the gateway records as a verified
/// agent run, attributing the traffic).
fn chat_completion(gateway_addr: &str, key: &str, agent_run_id: Option<&str>) -> String {
    let auth = format!("Authorization: Bearer {key}");
    let mut headers: Vec<String> = vec![auth, "Content-Type: application/json".to_string()];
    if let Some(run_id) = agent_run_id {
        headers.push(format!("X-FerroGate-Agent-Run-Id: {run_id}"));
    }
    let header_refs: Vec<&str> = headers.iter().map(String::as_str).collect();
    http_request(
        gateway_addr,
        "POST",
        "/v1/chat/completions",
        &header_refs,
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}"#,
    )
}

fn observed_activity(gateway_addr: &str, admin_key: &str) -> Value {
    response_json(http_request(
        gateway_addr,
        "GET",
        "/admin/v1/observed-agent-activity",
        &[&format!("Authorization: Bearer {admin_key}")],
        "",
    ))
}

fn find_row<'a>(rows: &'a [Value], tenant_id: &str, api_key_id: &str) -> &'a Value {
    rows.iter()
        .find(|row| row["tenant_id"] == tenant_id && row["api_key_id"] == api_key_id)
        .unwrap_or_else(|| panic!("no observed row for {tenant_id}/{api_key_id} in {rows:?}"))
}

fn response_json(response: String) -> Value {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(&response);
    serde_json::from_str(body).unwrap_or_else(|error| panic!("invalid JSON: {error}; {response}"))
}

/// A gateway with a chat provider (stub upstream), two tenant-owned virtual
/// keys (org_a / org_b), a platform-operator admin key (no tenant => cross-
/// tenant view), and two tenant-scoped admin keys (org_a / org_b => scoped).
fn observed_activity_config(gateway_addr: &str, provider_addr: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]
input_price_per_1m = 1.0
output_price_per_1m = 2.0

[[api_keys]]
id = "vkey-a"
name = "Virtual key A"
key = "vkey-a-secret"
scopes = ["chat.completions", "models.read"]
allowed_models = ["fast-chat"]
organization_id = "org_a"
project_id = "project_a"

[[api_keys]]
id = "vkey-b"
name = "Virtual key B"
key = "vkey-b-secret"
scopes = ["chat.completions", "models.read"]
allowed_models = ["fast-chat"]
organization_id = "org_b"
project_id = "project_b"

[[api_keys]]
id = "admin"
name = "Platform operator"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[[api_keys]]
id = "admin-a"
name = "Tenant A operator"
key = "admin-a-secret"
scopes = ["admin.read"]
organization_id = "org_a"

[[api_keys]]
id = "admin-b"
name = "Tenant B operator"
key = "admin-b-secret"
scopes = ["admin.read"]
organization_id = "org_b"
"#
    )
}
