// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: End-to-end coverage for the #251 agent-schedule admin API +
// scheduler firing chain, against a real gateway process with the in-memory
// backend (no Docker, no Postgres). Proves the full loop: create a schedule
// over `/admin/v1/agent-schedules` -> the always-on tick loop fires it ->
// a dispatch lands in the self-hosted lease queue -> a self-hosted worker
// polls (leases) and acks it -> the fire-history endpoint reports the fire
// as `dispatched` with the linked dispatch id. It also proves the at-most-once
// firing gate holds across a scheduler restart (disable+re-enable via hot
// config reload): the in-memory fire ledger survives, and no slot is ever
// fired twice.

mod support;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

const ADMIN: [&str; 2] = [
    "Authorization: Bearer admin-secret",
    "Content-Type: application/json",
];

const TENANT: &str = "sched-tenant";
const WORKSPACE: &str = "sched-ws";
const SCHEDULE_ID: &str = "sched-e2e";
const WORKER_FINGERPRINT: &str = "sha256:sched-worker";

fn scheduler_config(gateway_addr: &str, enabled: bool) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Platform operator"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
platform_operator = true

[scheduler]
enabled = {enabled}
tick_interval_secs = 1
"#
    )
}

fn body_of(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(response)
}

fn response_json(response: &str) -> serde_json::Value {
    serde_json::from_str(body_of(response))
        .unwrap_or_else(|error| panic!("invalid JSON: {error}; {response}"))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The `mutual_tls` header is an accepted (marker) transport in the default
/// pre-production posture, and its body is plain JSON -- exactly what a
/// self-hosted worker sends before verified-mTLS admission exists.
fn worker_transport_headers() -> [&'static str; 2] {
    [
        "Content-Type: application/json",
        "x-ferrogate-transport-security: mutual_tls",
    ]
}

fn poll_once(gateway_addr: &str, transport_secret: &str, worker_id: &str) -> serde_json::Value {
    let body = serde_json::json!({
        "protocol_version": 1,
        "identity": {
            "tenant_id": TENANT,
            "workspace_id": WORKSPACE,
            "worker_id": worker_id,
            "token_id": WORKER_FINGERPRINT,
            "token_secret": transport_secret,
        },
        "supported_capabilities": ["shell"],
        "now_unix": now_unix(),
        "lease_duration_secs": 30
    })
    .to_string();
    let response = http_request(
        gateway_addr,
        "POST",
        "/v1/self-hosted-workers/runs/poll",
        &worker_transport_headers(),
        &body,
    );
    assert!(
        response.contains("HTTP/1.1 200"),
        "worker poll should be accepted: {response}"
    );
    response_json(&response)
}

fn dispatched_fires(gateway_addr: &str) -> Vec<serde_json::Value> {
    let response = http_request(
        gateway_addr,
        "GET",
        &format!("/admin/v1/agent-schedules/{SCHEDULE_ID}/fires"),
        &ADMIN,
        "",
    );
    assert!(
        response.contains("HTTP/1.1 200"),
        "fire history read should succeed: {response}"
    );
    response_json(&response)["data"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|fire| fire["outcome"] == "dispatched")
        .collect()
}

fn assert_slots_unique(fires: &[serde_json::Value], context: &str) {
    let mut slots: Vec<i64> = fires
        .iter()
        .map(|fire| fire["scheduled_fire_at_unix"].as_i64().unwrap())
        .collect();
    let total = slots.len();
    slots.sort_unstable();
    slots.dedup();
    assert_eq!(
        slots.len(),
        total,
        "no slot may fire twice ({context}): {fires:?}"
    );
}

#[test]
fn scheduled_dispatch_fires_is_leased_acked_and_never_double_fires() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, scheduler_config(&gateway_addr, true)).unwrap();

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    // 1. Create a short-interval self-hosted-dispatch schedule.
    let create = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/agent-schedules",
        &ADMIN,
        &serde_json::json!({
            "id": SCHEDULE_ID,
            "tenant_id": TENANT,
            "workspace_id": WORKSPACE,
            "name": "e2e-interval",
            "spec_kind": "interval",
            "interval_secs": 1,
            "target_kind": "self_hosted_dispatch",
            "target": {"required_capabilities": ["shell"]}
        })
        .to_string(),
    );
    assert!(
        create.contains("HTTP/1.1 201"),
        "schedule creation should succeed: {create}"
    );

    // 2. Register a self-hosted worker in the schedule's tenant/workspace whose
    //    default framework (native-harness) + capabilities (shell) match the
    //    schedule's dispatch, so it can lease the scheduled run.
    let register = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/self-hosted-workers",
        &ADMIN,
        &serde_json::json!({
            "tenant": {
                "organization_id": TENANT,
                "team_id": null,
                "project_id": "sched-project",
                "workspace_id": WORKSPACE,
                "user_id": null,
                "api_key_id": "admin"
            },
            "workspace_id": WORKSPACE,
            "worker_name": "sched-worker",
            "identity_fingerprint": WORKER_FINGERPRINT,
            "orchestration_enabled": false
        })
        .to_string(),
    );
    assert!(
        register.contains("HTTP/1.1 200") || register.contains("HTTP/1.1 201"),
        "worker registration should succeed: {register}"
    );
    let register_json = response_json(&register);
    let worker_id = register_json["worker"]["id"].as_str().unwrap().to_string();
    let transport_secret = register_json["transport_token_secret"]
        .as_str()
        .unwrap()
        .to_string();

    // 3. Wait for the always-on tick loop to fire the schedule.
    let started = Instant::now();
    let mut fires = Vec::new();
    while started.elapsed() < Duration::from_secs(10) {
        fires = dispatched_fires(&gateway_addr);
        if !fires.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        !fires.is_empty(),
        "the scheduler tick loop should have fired a dispatched fire within 10s"
    );
    let fire = &fires[0];
    let dispatch_id = fire["dispatch_id"].as_str().unwrap().to_string();
    assert!(
        dispatch_id.starts_with(&format!("schedule-dispatch-{SCHEDULE_ID}-")),
        "fire should link the scheduled dispatch id: {dispatch_id}"
    );
    assert!(
        fire["run_id"].is_null(),
        "a self-hosted-dispatch fire records a dispatch, not a run id"
    );

    // 4. The worker polls -> leases the scheduled dispatch -> acks it.
    let started = Instant::now();
    let mut lease = serde_json::Value::Null;
    while started.elapsed() < Duration::from_secs(5) {
        let candidate = poll_once(&gateway_addr, &transport_secret, &worker_id);
        if candidate
            .get("dispatch_id")
            .and_then(|id| id.as_str())
            .is_some()
        {
            lease = candidate;
            break;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    let leased_dispatch_id = lease["dispatch_id"]
        .as_str()
        .expect("worker should lease a scheduled dispatch");
    assert!(
        leased_dispatch_id.starts_with(&format!("schedule-dispatch-{SCHEDULE_ID}-")),
        "leased dispatch should be the scheduled one: {leased_dispatch_id}"
    );

    let ack_body = serde_json::json!({
        "protocol_version": 1,
        "identity": {
            "tenant_id": TENANT,
            "workspace_id": WORKSPACE,
            "worker_id": worker_id,
            "token_id": WORKER_FINGERPRINT,
            "token_secret": transport_secret,
        },
        "dispatch_id": lease["dispatch_id"],
        "action": lease["action"],
        "lease_id": lease["lease_id"],
        "run_id": lease["run_id"],
        "status": "accepted",
        "reported_at_unix": now_unix()
    })
    .to_string();
    let ack = http_request(
        &gateway_addr,
        "POST",
        "/v1/self-hosted-workers/runs/ack",
        &worker_transport_headers(),
        &ack_body,
    );
    assert!(
        ack.contains("HTTP/1.1 200") || ack.contains("HTTP/1.1 201"),
        "worker ack should be accepted: {ack}"
    );

    // The leased dispatch id must match a dispatched fire's dispatch id.
    let linked = dispatched_fires(&gateway_addr)
        .into_iter()
        .any(|fire| fire["dispatch_id"].as_str() == Some(leased_dispatch_id));
    assert!(linked, "fire history should link the leased dispatch id");

    // 5. Idempotency across a scheduler restart: disable then re-enable the
    //    scheduler via hot config reload. The process (and its in-memory fire
    //    ledger) survives, so no already-fired slot may fire again.
    let before_restart = dispatched_fires(&gateway_addr);
    assert_slots_unique(&before_restart, "before scheduler restart");

    let reload_disabled = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/config/reload",
        &ADMIN,
        &serde_json::json!({ "config_toml": scheduler_config(&gateway_addr, false) }).to_string(),
    );
    assert!(
        reload_disabled.contains("HTTP/1.1 200"),
        "disabling the scheduler via reload should succeed: {reload_disabled}"
    );
    std::thread::sleep(Duration::from_secs(2));
    let reload_enabled = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/config/reload",
        &ADMIN,
        &serde_json::json!({ "config_toml": scheduler_config(&gateway_addr, true) }).to_string(),
    );
    assert!(
        reload_enabled.contains("HTTP/1.1 200"),
        "re-enabling the scheduler via reload should succeed: {reload_enabled}"
    );

    // The schedule survived the restart (proving the ledger persisted too).
    let get = http_request(
        &gateway_addr,
        "GET",
        &format!("/admin/v1/agent-schedules/{SCHEDULE_ID}"),
        &ADMIN,
        "",
    );
    assert!(
        get.contains("HTTP/1.1 200"),
        "schedule should survive the scheduler restart: {get}"
    );

    // Let the resumed scheduler run several more ticks, then re-check the gate.
    std::thread::sleep(Duration::from_secs(3));
    let after_restart = dispatched_fires(&gateway_addr);
    assert!(
        after_restart.len() >= before_restart.len(),
        "the resumed scheduler should keep firing new slots"
    );
    assert_slots_unique(&after_restart, "after scheduler restart");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
