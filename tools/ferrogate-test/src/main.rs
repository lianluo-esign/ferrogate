// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use serde_json::Value;
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

mod assertions;
mod cli;
mod fixtures;
mod http;
mod local;
mod mocks;
mod scenarios;
mod storage;

use assertions::*;
use cli::{DockerScenario, IMAGE_TAG};
use fixtures::{
    analytics_direct_clickhouse_gateway_config, analytics_gateway_config, gateway_config,
    guardrail_complete_gateway_config, guardrail_gateway_config, guardrail_response_gateway_config,
    redis_counter_gateway_config, vector_clickhouse_config,
};
use http::http_request;
use scenarios::{
    run_admin_api, run_auth_api, run_gateway_api, run_gateway_external_auth_api,
    run_gateway_third_party_auth_api,
};
use storage::{
    run_mysql_restart, run_mysql_tls_restart, run_postgres_restart, run_postgres_tls_restart,
    run_supabase_live_restart, run_supabase_live_smoke, run_supabase_live_token4ai_provider,
    run_supabase_migration, run_supabase_restart,
};
const NETWORK_NAME: &str = "ferrogate-e2e-net";
const PROVIDER_CONTAINER: &str = "ferrogate-e2e-provider";
const REDIS_CONTAINER: &str = "ferrogate-e2e-redis";
const CLICKHOUSE_CONTAINER: &str = "ferrogate-e2e-clickhouse";
const VECTOR_CONTAINER: &str = "ferrogate-e2e-vector";
const POSTGRES_CONTAINER: &str = "ferrogate-e2e-postgres";
const POSTGRES_MIGRATION_SOURCE_CONTAINER: &str = "ferrogate-e2e-postgres-migration-source";
const POSTGRES_MIGRATION_TARGET_CONTAINER: &str = "ferrogate-e2e-postgres-migration-target";
const POSTGRES_IMAGE: &str = "postgres:16-alpine";
const MYSQL_CONTAINER: &str = "ferrogate-e2e-mysql";
const MYSQL_IMAGE: &str = "mysql:8.4";
const GATEWAY_A_CONTAINER: &str = "ferrogate-e2e-gateway-a";
const GATEWAY_B_CONTAINER: &str = "ferrogate-e2e-gateway-b";
const GATEWAY_A_PORT: u16 = 18080;
const GATEWAY_B_PORT: u16 = 18081;

fn main() -> Result<()> {
    cli::run(cli::Dispatch {
        admin: run_admin_api,
        auth: run_auth_api,
        gateway: run_gateway_api,
        supabase_restart: run_supabase_restart,
        supabase_live_smoke: run_supabase_live_smoke,
        supabase_live_restart: run_supabase_live_restart,
        supabase_live_token4ai_provider: run_supabase_live_token4ai_provider,
        supabase_migration: run_supabase_migration,
        postgres_restart: run_postgres_restart,
        postgres_tls_restart: run_postgres_tls_restart,
        mysql_restart: run_mysql_restart,
        mysql_tls_restart: run_mysql_tls_restart,
        docker: run_docker_scenario,
        run_all_admin_auth_gateway: |local, auth, include_docker, image| {
            run_admin_api(local)?;
            run_auth_api(auth)?;
            run_gateway_external_auth_api(local, auth)?;
            run_gateway_third_party_auth_api(local)?;
            run_gateway_api(local)?;
            if include_docker {
                run_all_docker_scenarios(image)?;
            }
            Ok(())
        },
        ci: |local, auth| {
            run_admin_api(local)?;
            run_auth_api(auth)?;
            run_gateway_external_auth_api(local, auth)?;
            run_gateway_third_party_auth_api(local)?;
            run_gateway_api(local)?;
            run_supabase_migration(local)?;
            run_supabase_restart(local)?;
            run_postgres_restart(local)?;
            run_postgres_tls_restart(local)?;
            run_mysql_restart(local)?;
            run_mysql_tls_restart(local)
        },
    })
}

fn run_docker_scenario(scenario: DockerScenario, image: &str) -> Result<()> {
    match scenario {
        DockerScenario::AnalyticsDirectClickhouse => run_analytics_direct_clickhouse(image),
        DockerScenario::AnalyticsVectorClickhouse => run_analytics_vector_clickhouse(image),
        DockerScenario::ClusterDrain => run_cluster_drain(image),
        DockerScenario::GuardrailComplete => run_guardrail_complete(image),
        DockerScenario::GuardrailRequestDeny => run_guardrail_request_deny(image),
        DockerScenario::GuardrailResponseRedact => run_guardrail_response_redact(image),
        DockerScenario::SharedApiKey => run_shared_api_key(image),
        DockerScenario::SharedStateStale => run_shared_state_stale(image),
        DockerScenario::SharedStateStartupUnavailable => {
            run_shared_state_startup_unavailable(image)
        }
        DockerScenario::RedisCounters => run_redis_counters(image),
    }
}

fn run_all_docker_scenarios(image: &str) -> Result<()> {
    for scenario in DockerScenario::value_variants() {
        run_docker_scenario(*scenario, image)?;
    }
    Ok(())
}

const ADMIN_AUTH: &str = "Authorization: Bearer admin-secret";
const CLIENT_AUTH: &str = "Authorization: Bearer client-secret";
const OBSERVER_AUTH: &str = "Authorization: Bearer observer-secret";
const AUTH_TEST_CLIENT_2: &str = "Authorization: Bearer test-secret-2";
const JSON_CONTENT: &str = "Content-Type: application/json";
const SUPPORT_SKILL_HEADER: &str = "x-ferrogate-skill-package: support-skill";

fn run_analytics_direct_clickhouse(image: &str) -> Result<()> {
    let _cleanup = setup_environment(image)?;
    start_provider()?;
    start_clickhouse()?;
    wait_for_provider()?;
    wait_for_clickhouse()?;
    initialize_clickhouse_schema()?;

    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, analytics_direct_clickhouse_gateway_config())?;
    start_gateway(
        image,
        GATEWAY_A_CONTAINER,
        GATEWAY_A_PORT,
        &config_path,
        None,
    )?;
    wait_for_http(GATEWAY_A_PORT, "/readyz", 200)?;

    expect_json(
        GATEWAY_A_PORT,
        "GET",
        "/admin/v1/status",
        &["Authorization: Bearer admin-secret"],
        "",
        200,
        |body| {
            assert_eq!(body["analytics"]["provider"], "clickhouse");
            assert_eq!(body["analytics"]["mode"], "direct_warehouse");
            assert_eq!(body["analytics"]["active"], true);
            assert!(
                body["analytics"]["health"] == "configured" || body["analytics"]["health"] == "ok"
            );
            Ok(())
        },
    )?;
    expect_json(
        GATEWAY_A_PORT,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"direct clickhouse analytics"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            Ok(())
        },
    )?;
    emit_analytics_audit_event(GATEWAY_A_PORT)?;

    expect_clickhouse_analytics_rows()?;
    expect_json(
        GATEWAY_A_PORT,
        "GET",
        "/admin/v1/status",
        &["Authorization: Bearer admin-secret"],
        "",
        200,
        |body| {
            assert_eq!(body["analytics"]["health"], "ok");
            assert!(body["analytics"]["last_success_at_unix"].is_number());
            assert!(body["analytics"]["last_export_error"].is_null());
            Ok(())
        },
    )?;

    println!("analytics-direct-clickhouse scenario passed");
    Ok(())
}

fn run_analytics_vector_clickhouse(image: &str) -> Result<()> {
    let _cleanup = setup_environment(image)?;
    start_provider()?;
    start_clickhouse()?;
    wait_for_provider()?;
    wait_for_clickhouse()?;
    initialize_clickhouse_schema()?;

    let dir = tempfile::tempdir()?;
    let vector_config_path = dir.path().join("vector.toml");
    std::fs::write(&vector_config_path, vector_clickhouse_config())?;
    validate_vector_config(&vector_config_path)?;
    start_vector(&vector_config_path)?;
    wait_for_container(VECTOR_CONTAINER, "Vector")?;

    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, analytics_gateway_config())?;
    start_gateway(
        image,
        GATEWAY_A_CONTAINER,
        GATEWAY_A_PORT,
        &config_path,
        None,
    )?;
    wait_for_http(GATEWAY_A_PORT, "/readyz", 200)?;

    expect_json(
        GATEWAY_A_PORT,
        "GET",
        "/admin/v1/status",
        &["Authorization: Bearer admin-secret"],
        "",
        200,
        |body| {
            assert_eq!(body["analytics"]["provider"], "vector");
            assert_eq!(body["analytics"]["mode"], "pipeline");
            assert_eq!(body["analytics"]["active"], true);
            assert!(
                body["analytics"]["health"] == "configured" || body["analytics"]["health"] == "ok"
            );
            Ok(())
        },
    )?;
    expect_json(
        GATEWAY_A_PORT,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"analytics pipeline"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            Ok(())
        },
    )?;
    emit_analytics_audit_event(GATEWAY_A_PORT)?;

    expect_clickhouse_analytics_rows()?;

    expect_json(
        GATEWAY_A_PORT,
        "GET",
        "/admin/v1/status",
        &["Authorization: Bearer admin-secret"],
        "",
        200,
        |body| {
            assert_eq!(body["analytics"]["health"], "ok");
            assert!(body["analytics"]["last_success_at_unix"].is_number());
            assert!(body["analytics"]["last_export_error"].is_null());
            Ok(())
        },
    )?;

    println!("analytics-vector-clickhouse scenario passed");
    Ok(())
}

fn run_cluster_drain(image: &str) -> Result<()> {
    let _cleanup = setup_environment(image)?;
    start_provider()?;
    wait_for_provider()?;

    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, gateway_config("e2e-node-a", "local", None))?;
    start_gateway(
        image,
        GATEWAY_A_CONTAINER,
        GATEWAY_A_PORT,
        &config_path,
        None,
    )?;

    wait_for_http(GATEWAY_A_PORT, "/healthz", 200)?;
    expect_json(GATEWAY_A_PORT, "GET", "/readyz", &[], "", 200, |body| {
        assert_eq!(body["status"], "ready");
        assert_eq!(body["cluster"]["cluster_id"], "e2e-cluster");
        assert_eq!(body["cluster"]["node_id"], "e2e-node-a");
        assert_eq!(body["cluster"]["draining"], false);
        Ok(())
    })?;
    expect_json(
        GATEWAY_A_PORT,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            Ok(())
        },
    )?;
    expect_json(
        GATEWAY_A_PORT,
        "POST",
        "/admin/v1/drain",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"drain":true}"#,
        200,
        |body| {
            assert_eq!(body["draining"], true);
            assert_eq!(body["accepting_new_requests"], false);
            Ok(())
        },
    )?;
    expect_json(GATEWAY_A_PORT, "GET", "/readyz", &[], "", 503, |body| {
        assert_eq!(body["status"], "not_ready");
        assert_eq!(body["cluster"]["readiness_reason"], "operator_drain");
        assert_eq!(body["cluster"]["draining"], true);
        Ok(())
    })?;
    expect_json(
        GATEWAY_A_PORT,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}"#,
        503,
        |body| {
            assert_eq!(body["error"]["code"], "node_draining");
            Ok(())
        },
    )?;
    expect_json(
        GATEWAY_A_PORT,
        "POST",
        "/admin/v1/drain",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"drain":false}"#,
        200,
        |body| {
            assert_eq!(body["draining"], false);
            assert_eq!(body["accepting_new_requests"], true);
            Ok(())
        },
    )?;
    expect_json(GATEWAY_A_PORT, "GET", "/readyz", &[], "", 200, |body| {
        assert_eq!(body["status"], "ready");
        assert_eq!(body["cluster"]["draining"], false);
        Ok(())
    })?;
    expect_json(
        GATEWAY_A_PORT,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            Ok(())
        },
    )?;

    println!("cluster-drain scenario passed");
    Ok(())
}

fn run_guardrail_request_deny(image: &str) -> Result<()> {
    let _cleanup = setup_environment(image)?;
    start_provider()?;
    wait_for_provider()?;

    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("guardrail.toml");
    std::fs::write(&config_path, guardrail_gateway_config())?;
    start_gateway(
        image,
        GATEWAY_A_CONTAINER,
        GATEWAY_A_PORT,
        &config_path,
        None,
    )?;

    wait_for_http(GATEWAY_A_PORT, "/readyz", 200)?;
    expect_json(
        GATEWAY_A_PORT,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"this contains secret"}]}"#,
        403,
        |body| {
            assert_eq!(body["error"]["code"], "guardrail_blocked");
            assert_eq!(body["error"]["message"], "blocked by guardrail");
            Ok(())
        },
    )?;

    let provider_log = Command::new("docker")
        .args(["logs", PROVIDER_CONTAINER])
        .output()
        .context("failed to inspect provider logs")?;
    let provider_log = String::from_utf8_lossy(&provider_log.stdout);
    assert!(
        !provider_log.contains("POST /v1/chat/completions"),
        "provider should not receive a POST dispatch when guardrail denies the request"
    );

    println!("guardrail-request-deny scenario passed");
    Ok(())
}

fn run_guardrail_response_redact(image: &str) -> Result<()> {
    let _cleanup = setup_environment(image)?;
    start_provider_with_content("contains secret from provider")?;
    wait_for_provider()?;

    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("guardrail-response.toml");
    std::fs::write(&config_path, guardrail_response_gateway_config())?;
    start_gateway(
        image,
        GATEWAY_A_CONTAINER,
        GATEWAY_A_PORT,
        &config_path,
        None,
    )?;

    wait_for_http(GATEWAY_A_PORT, "/readyz", 200)?;
    expect_json(
        GATEWAY_A_PORT,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}"#,
        200,
        |body| {
            assert_eq!(
                body["choices"][0]["message"]["content"],
                "contains [REDACTED] from provider"
            );
            assert!(!body.to_string().contains("contains secret from provider"));
            Ok(())
        },
    )?;

    let provider_log = Command::new("docker")
        .args(["logs", PROVIDER_CONTAINER])
        .output()
        .context("failed to inspect provider logs")?;
    let provider_log = String::from_utf8_lossy(&provider_log.stdout);
    assert!(
        provider_log.contains("POST /v1/chat/completions"),
        "provider should receive dispatch before response guardrail redacts output"
    );

    expect_json(
        GATEWAY_A_PORT,
        "GET",
        "/admin/v1/audit-events",
        &["Authorization: Bearer admin-secret"],
        "",
        200,
        |body| {
            assert!(list_contains(&body, "action", "guardrail.redact"));
            assert!(!body.to_string().contains("contains secret from provider"));
            Ok(())
        },
    )?;
    expect_json(
        GATEWAY_A_PORT,
        "GET",
        "/admin/v1/request-logs",
        &["Authorization: Bearer admin-secret"],
        "",
        200,
        |body| {
            let raw = body.to_string();
            assert!(raw.contains("[REDACTED]"));
            assert!(!raw.contains("contains secret from provider"));
            Ok(())
        },
    )?;
    expect_text(
        GATEWAY_A_PORT,
        "GET",
        "/metrics",
        &["Authorization: Bearer admin-secret"],
        "",
        200,
        |body| {
            assert!(body.contains("ferrogate_guardrail_matches_total 1"));
            assert!(body.contains("ferrogate_guardrail_redactions_total 1"));
            Ok(())
        },
    )?;

    println!("guardrail-response-redact scenario passed");
    Ok(())
}

fn run_guardrail_complete(image: &str) -> Result<()> {
    let _cleanup = setup_environment(image)?;
    start_guardrail_complete_provider()?;
    wait_for_provider()?;

    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("guardrail-complete.toml");
    std::fs::write(&config_path, guardrail_complete_gateway_config())?;
    start_gateway(
        image,
        GATEWAY_A_CONTAINER,
        GATEWAY_A_PORT,
        &config_path,
        None,
    )?;

    wait_for_http(GATEWAY_A_PORT, "/readyz", 200)?;
    expect_json(
        GATEWAY_A_PORT,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"ticket ABC-123"}]}"#,
        403,
        |body| {
            assert_eq!(body["error"]["code"], "guardrail_regex_blocked");
            Ok(())
        },
    )
    .context("request regex deny guardrail")?;
    expect_json(
        GATEWAY_A_PORT,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"this input is deliberately long enough to trip the max input bytes guardrail"}]}"#,
        403,
        |body| {
            assert_eq!(body["error"]["code"], "guardrail_input_too_large");
            Ok(())
        },
    )
    .context("request max input bytes guardrail")?;
    expect_json(
        GATEWAY_A_PORT,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"deny"}]}"#,
        403,
        |body| {
            assert_eq!(body["error"]["code"], "guardrail_response_blocked");
            assert!(!body.to_string().contains("deny-output"));
            Ok(())
        },
    )
    .context("response deny guardrail")?;
    expect_text(
        GATEWAY_A_PORT,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","stream":true,"messages":[{"role":"user","content":"stream"}]}"#,
        200,
        |body| {
            assert!(body.contains("[REDACTED]"));
            assert!(!body.contains("stream-secret"));
            Ok(())
        },
    )
    .context("streaming response redact guardrail")?;

    let provider_log = Command::new("docker")
        .args(["logs", PROVIDER_CONTAINER])
        .output()
        .context("failed to inspect provider logs")?;
    let provider_log = String::from_utf8_lossy(&provider_log.stdout);
    assert_eq!(
        provider_log.matches("POST /v1/chat/completions").count(),
        2,
        "request regex and length guardrails should block before provider dispatch"
    );

    expect_json(
        GATEWAY_A_PORT,
        "GET",
        "/admin/v1/audit-events",
        &["Authorization: Bearer admin-secret"],
        "",
        200,
        |body| {
            assert!(list_contains(&body, "action", "guardrail.deny"));
            assert!(list_contains(&body, "action", "guardrail.redact"));
            assert!(!body.to_string().contains("deny-output"));
            assert!(!body.to_string().contains("stream-secret"));
            Ok(())
        },
    )
    .context("guardrail audit event evidence")?;
    expect_json(
        GATEWAY_A_PORT,
        "GET",
        "/admin/v1/request-logs",
        &["Authorization: Bearer admin-secret"],
        "",
        200,
        |body| {
            let raw = body.to_string();
            assert!(raw.contains("[REDACTED]"));
            assert!(!raw.contains("deny-output"));
            assert!(!raw.contains("stream-secret"));
            Ok(())
        },
    )
    .context("guardrail request log evidence")?;
    expect_text(
        GATEWAY_A_PORT,
        "GET",
        "/metrics",
        &["Authorization: Bearer admin-secret"],
        "",
        200,
        |body| {
            assert!(body.contains("ferrogate_guardrail_matches_total 4"));
            assert!(body.contains("ferrogate_guardrail_denials_total 3"));
            assert!(body.contains("ferrogate_guardrail_redactions_total 1"));
            Ok(())
        },
    )
    .context("guardrail metrics evidence")?;

    println!("guardrail-complete scenario passed");
    Ok(())
}

fn run_shared_api_key(image: &str) -> Result<()> {
    let _cleanup = setup_environment(image)?;
    start_provider()?;
    wait_for_provider()?;

    let shared = start_shared_file_gateways(image)?;
    publish_shared_client_and_policy()?;

    expect_json(
        GATEWAY_B_PORT,
        "GET",
        "/admin/v1/api-keys/shared-client",
        &["Authorization: Bearer admin-secret"],
        "",
        200,
        |body| {
            assert_eq!(body["key"]["id"], "shared-client");
            Ok(())
        },
    )?;
    expect_json(
        GATEWAY_B_PORT,
        "GET",
        "/admin/v1/policies/shared-policy",
        &["Authorization: Bearer admin-secret"],
        "",
        200,
        |body| {
            assert_eq!(body["policy"]["name"], "shared-policy");
            assert_eq!(body["policy"]["code"], "blocked_by_shared_policy");
            Ok(())
        },
    )?;
    expect_json(
        GATEWAY_B_PORT,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer shared-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            Ok(())
        },
    )?;

    let raw_state = std::fs::read_to_string(&shared.state_path)?;
    let shared_state: Value = serde_json::from_str(&raw_state)?;
    assert_eq!(shared_state["version"], 1);
    assert!(shared_state["api_keys"]
        .as_array()
        .is_some_and(|keys| keys.iter().any(|key| key["id"] == "shared-client")));

    println!("shared-api-key scenario passed");
    Ok(())
}

fn run_shared_state_stale(image: &str) -> Result<()> {
    let _cleanup = setup_environment(image)?;
    start_provider()?;
    wait_for_provider()?;

    let _shared = start_shared_file_gateways(image)?;
    publish_shared_client_and_policy()?;

    expect_json(
        GATEWAY_B_PORT,
        "GET",
        "/admin/v1/api-keys/shared-client",
        &["Authorization: Bearer admin-secret"],
        "",
        200,
        |body| {
            assert_eq!(body["key"]["id"], "shared-client");
            Ok(())
        },
    )?;
    corrupt_shared_state_file()?;
    expect_json(GATEWAY_B_PORT, "GET", "/readyz", &[], "", 200, |body| {
        assert_eq!(body["status"], "ready");
        assert_eq!(body["cluster"]["stale"], true);
        assert_eq!(body["cluster"]["readiness_reason"], "stale_state");
        assert!(body["cluster"]["last_sync_error"]
            .as_str()
            .is_some_and(|error| error.contains("invalid file cluster state JSON")));
        Ok(())
    })?;
    expect_json(
        GATEWAY_B_PORT,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer shared-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            Ok(())
        },
    )?;

    println!("shared-state-stale scenario passed");
    Ok(())
}

fn run_shared_state_startup_unavailable(image: &str) -> Result<()> {
    let _cleanup = setup_environment(image)?;
    start_provider()?;
    wait_for_provider()?;

    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("gateway-a.toml");
    std::fs::write(
        &config_path,
        gateway_config(
            "e2e-node-a",
            "file",
            Some("/proc/ferrogate/cluster-state.json"),
        ),
    )?;
    start_gateway(
        image,
        GATEWAY_A_CONTAINER,
        GATEWAY_A_PORT,
        &config_path,
        None,
    )?;
    wait_for_http(GATEWAY_A_PORT, "/healthz", 200)?;
    expect_json(GATEWAY_A_PORT, "GET", "/readyz", &[], "", 503, |body| {
        assert_eq!(body["status"], "not_ready");
        assert_eq!(body["cluster"]["node_id"], "e2e-node-a");
        assert_eq!(body["cluster"]["state_backend"], "file");
        assert_eq!(body["cluster"]["active_revision"], "");
        assert_eq!(body["cluster"]["stale"], false);
        assert_eq!(body["cluster"]["readiness_reason"], "sync_error");
        assert!(body["cluster"]["last_sync_error"]
            .as_str()
            .is_some_and(|error| error.contains("failed to publish file cluster state")));
        Ok(())
    })?;

    println!("shared-state-startup-unavailable scenario passed");
    Ok(())
}

fn run_redis_counters(image: &str) -> Result<()> {
    let _cleanup = setup_environment(image)?;
    start_provider()?;
    start_redis()?;
    wait_for_provider()?;
    wait_for_redis()?;

    let dir = tempfile::tempdir()?;
    let config_a = dir.path().join("gateway-a.toml");
    let config_b = dir.path().join("gateway-b.toml");
    std::fs::write(&config_a, redis_counter_gateway_config("e2e-node-a"))?;
    std::fs::write(&config_b, redis_counter_gateway_config("e2e-node-b"))?;

    start_gateway(image, GATEWAY_A_CONTAINER, GATEWAY_A_PORT, &config_a, None)?;
    start_gateway(image, GATEWAY_B_CONTAINER, GATEWAY_B_PORT, &config_b, None)?;
    wait_for_http(GATEWAY_A_PORT, "/readyz", 200)?;
    wait_for_http(GATEWAY_B_PORT, "/readyz", 200)?;

    expect_json(
        GATEWAY_A_PORT,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer redis-rate-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            Ok(())
        },
    )?;
    expect_json(
        GATEWAY_B_PORT,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer redis-rate-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}"#,
        429,
        |body| {
            assert_eq!(body["error"]["code"], "rate_limit_exceeded");
            Ok(())
        },
    )?;

    expect_json(
        GATEWAY_A_PORT,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer redis-budget-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[],"max_tokens":8}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            Ok(())
        },
    )?;
    expect_json(
        GATEWAY_B_PORT,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer redis-budget-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[],"max_tokens":8}"#,
        429,
        |body| {
            assert_eq!(body["error"]["code"], "token_budget_exceeded");
            Ok(())
        },
    )?;

    println!("redis-counters scenario passed");
    Ok(())
}

struct SharedFileGateways {
    _dir: tempfile::TempDir,
    state_path: std::path::PathBuf,
}

fn start_shared_file_gateways(image: &str) -> Result<SharedFileGateways> {
    let dir = tempfile::tempdir()?;
    let state_dir = dir.path().join("state");
    let state_path = state_dir.join("cluster-state.json");
    std::fs::create_dir_all(&state_dir)?;

    let config_a = dir.path().join("gateway-a.toml");
    let config_b = dir.path().join("gateway-b.toml");
    std::fs::write(
        &config_a,
        gateway_config(
            "e2e-node-a",
            "file",
            Some("/var/lib/ferrogate/cluster-state.json"),
        ),
    )?;
    std::fs::write(
        &config_b,
        gateway_config(
            "e2e-node-b",
            "file",
            Some("/var/lib/ferrogate/cluster-state.json"),
        ),
    )?;

    start_gateway(
        image,
        GATEWAY_A_CONTAINER,
        GATEWAY_A_PORT,
        &config_a,
        Some(&state_dir),
    )?;
    start_gateway(
        image,
        GATEWAY_B_CONTAINER,
        GATEWAY_B_PORT,
        &config_b,
        Some(&state_dir),
    )?;

    wait_for_http(GATEWAY_A_PORT, "/healthz", 200)?;
    wait_for_http(GATEWAY_B_PORT, "/healthz", 200)?;
    expect_json(GATEWAY_A_PORT, "GET", "/readyz", &[], "", 200, |body| {
        assert_eq!(body["cluster"]["node_id"], "e2e-node-a");
        assert_eq!(body["cluster"]["state_backend"], "file");
        Ok(())
    })?;
    expect_json(GATEWAY_B_PORT, "GET", "/readyz", &[], "", 200, |body| {
        assert_eq!(body["cluster"]["node_id"], "e2e-node-b");
        assert_eq!(body["cluster"]["state_backend"], "file");
        Ok(())
    })?;

    Ok(SharedFileGateways {
        _dir: dir,
        state_path,
    })
}

fn publish_shared_client_and_policy() -> Result<()> {
    expect_json(
        GATEWAY_A_PORT,
        "POST",
        "/admin/v1/api-keys",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"id":"shared-client","name":"Shared client","key":"shared-secret","scopes":["chat.completions"],"allowed_models":["fast-chat"]}"#,
        201,
        |body| {
            assert_eq!(body["key"]["id"], "shared-client");
            assert_eq!(body["key"]["key_source"], "inline");
            Ok(())
        },
    )?;
    expect_json(
        GATEWAY_A_PORT,
        "POST",
        "/admin/v1/policies",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"name":"shared-policy","effect":"deny","api_key_ids":["key_dev"],"models":["fast-chat"],"code":"blocked_by_shared_policy","message":"blocked by shared policy","enabled":true}"#,
        201,
        |body| {
            assert_eq!(body["policy"]["name"], "shared-policy");
            Ok(())
        },
    )
}

fn corrupt_shared_state_file() -> Result<()> {
    docker([
        "exec",
        GATEWAY_A_CONTAINER,
        "sh",
        "-c",
        "printf '{not valid json' > /var/lib/ferrogate/cluster-state.json",
    ])
}

fn setup_environment(image: &str) -> Result<Cleanup> {
    let cleanup = Cleanup;
    cleanup_containers();
    docker(["network", "create", NETWORK_NAME])?;
    if image == IMAGE_TAG {
        build_local_ferrogate_image()?;
    } else {
        docker(["pull", image])?;
    }
    Ok(cleanup)
}

fn build_local_ferrogate_image() -> Result<()> {
    match env::var("FERROGATE_TEST_IMAGE_MODE")
        .unwrap_or_else(|_| "host-binary".into())
        .as_str()
    {
        "docker-build" => docker(["build", "-t", IMAGE_TAG, "."]),
        "host-binary" => build_local_image_from_host_binary(),
        other => {
            bail!("FERROGATE_TEST_IMAGE_MODE must be host-binary or docker-build, got {other}")
        }
    }
}

fn build_local_image_from_host_binary() -> Result<()> {
    let binary = env::var("FERROGATE_TEST_HOST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("target/debug/ferrogate"));
    if !binary.exists() {
        bail!(
            "host ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli --locked` or set FERROGATE_TEST_IMAGE_MODE=docker-build",
            binary.display()
        );
    }
    let dir = tempfile::tempdir()?;
    let binary_name = binary
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("ferrogate");
    let base_image =
        env::var("FERROGATE_TEST_HOST_IMAGE_BASE").unwrap_or_else(|_| "rust:1.94-slim".into());
    fs::copy(&binary, dir.path().join("ferrogate"))
        .with_context(|| format!("failed to copy {}", binary.display()))?;
    fs::create_dir_all(dir.path().join("Ferrogate"))?;
    fs::copy(
        "Ferrogate/Caddyfile",
        dir.path().join("Ferrogate/Caddyfile"),
    )
    .context("failed to copy default Caddyfile")?;
    fs::write(
        dir.path().join("Dockerfile"),
        format!(
            r#"FROM {base_image}
LABEL org.opencontainers.image.vendor="Token4AI Cloud" \
      org.opencontainers.image.authors="jamesduan <https://x.com/JamesDuanL>"
COPY ferrogate /usr/local/bin/ferrogate
COPY Ferrogate/Caddyfile /etc/ferrogate/Caddyfile
EXPOSE 8080
ENV FERROGATE_CONFIG=/etc/ferrogate/Caddyfile
CMD ["ferrogate", "run"]
"#
        ),
    )?;
    println!(
        "building {IMAGE_TAG} from host binary {} ({binary_name})",
        binary.display()
    );
    docker_args([
        "build".to_string(),
        "-t".to_string(),
        IMAGE_TAG.to_string(),
        dir.path().display().to_string(),
    ])
}

fn start_provider() -> Result<()> {
    start_provider_with_content("ok")
}

fn start_provider_with_content(content: &str) -> Result<()> {
    let provider_image =
        env::var("FERROGATE_E2E_PROVIDER_IMAGE").unwrap_or_else(|_| "python:3.11-slim".into());
    let command = r#"
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os

CONTENT = os.environ.get("FERROGATE_E2E_PROVIDER_CONTENT", "ok")
BODY = json.dumps({
    "id": "chatcmpl_e2e",
    "object": "chat.completion",
    "choices": [{"message": {"role": "assistant", "content": CONTENT}}],
    "usage": {"total_tokens": 1},
}).encode()

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        print(self.requestline, flush=True)
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, format, *args):
        return

ThreadingHTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
"#;
    docker([
        "run",
        "-d",
        "--name",
        PROVIDER_CONTAINER,
        "--network",
        NETWORK_NAME,
        "-e",
        &format!("FERROGATE_E2E_PROVIDER_CONTENT={content}"),
        &provider_image,
        "python",
        "-u",
        "-c",
        command,
    ])
}

fn start_guardrail_complete_provider() -> Result<()> {
    let provider_image =
        env::var("FERROGATE_E2E_PROVIDER_IMAGE").unwrap_or_else(|_| "python:3.11-slim".into());
    let command = r#"
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json

def json_body(content):
    return json.dumps({
        "id": "chatcmpl_e2e",
        "object": "chat.completion",
        "choices": [{"message": {"role": "assistant", "content": content}}],
        "usage": {"total_tokens": 1},
    }).encode()

STREAM_BODY = b'data: {"choices":[{"delta":{"content":"stream-secret"}}]}\n\ndata: [DONE]\n\n'

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        print(self.requestline, flush=True)
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode() if length else ""
        if '"stream":true' in raw or '"stream": true' in raw:
            body = STREAM_BODY
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        content = "deny-output" if "deny" in raw else "ok"
        body = json_body(content)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return

ThreadingHTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
"#;
    docker([
        "run",
        "-d",
        "--name",
        PROVIDER_CONTAINER,
        "--network",
        NETWORK_NAME,
        &provider_image,
        "python",
        "-u",
        "-c",
        command,
    ])
}

fn start_redis() -> Result<()> {
    let redis_image =
        env::var("FERROGATE_E2E_REDIS_IMAGE").unwrap_or_else(|_| "redis:7-alpine".into());
    docker([
        "run",
        "-d",
        "--name",
        REDIS_CONTAINER,
        "--network",
        NETWORK_NAME,
        &redis_image,
        "redis-server",
        "--save",
        "",
        "--appendonly",
        "no",
    ])
}

fn start_clickhouse() -> Result<()> {
    let clickhouse_image = env::var("FERROGATE_E2E_CLICKHOUSE_IMAGE")
        .unwrap_or_else(|_| "clickhouse/clickhouse-server:24.8".into());
    docker([
        "run",
        "-d",
        "--name",
        CLICKHOUSE_CONTAINER,
        "--network",
        NETWORK_NAME,
        "-e",
        "CLICKHOUSE_DB=ferrogate",
        "-e",
        "CLICKHOUSE_SKIP_USER_SETUP=1",
        &clickhouse_image,
    ])
}

fn wait_for_clickhouse() -> Result<()> {
    let started = Instant::now();
    let mut last = String::new();
    while started.elapsed() < Duration::from_secs(45) {
        match clickhouse_query("SELECT 1") {
            Ok(output) if output.trim() == "1" => return Ok(()),
            Ok(output) => last = output,
            Err(error) => last = error.to_string(),
        }
        thread::sleep(Duration::from_millis(500));
    }
    bail!("ClickHouse did not become ready; last output: {last}")
}

fn initialize_clickhouse_schema() -> Result<()> {
    let schema = std::fs::read_to_string("sql/clickhouse/001_init_analytics.sql")
        .context("failed to read ClickHouse analytics schema")?;
    let mut child = Command::new("docker")
        .args([
            "exec",
            "-i",
            CLICKHOUSE_CONTAINER,
            "clickhouse-client",
            "--multiquery",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to run clickhouse-client")?;
    child
        .stdin
        .as_mut()
        .context("clickhouse-client stdin unavailable")?
        .write_all(schema.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "failed to initialize ClickHouse schema: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn validate_vector_config(config_path: &Path) -> Result<()> {
    let vector_image = env::var("FERROGATE_E2E_VECTOR_IMAGE")
        .unwrap_or_else(|_| "timberio/vector:0.56.0-debian".into());
    let mount = format!("{}:/etc/vector/vector.toml:ro", config_path.display());
    docker([
        "run",
        "--rm",
        "-v",
        &mount,
        &vector_image,
        "validate",
        "--skip-healthchecks",
        "/etc/vector/vector.toml",
    ])
}

fn start_vector(config_path: &Path) -> Result<()> {
    let vector_image = env::var("FERROGATE_E2E_VECTOR_IMAGE")
        .unwrap_or_else(|_| "timberio/vector:0.56.0-debian".into());
    let mount = format!("{}:/etc/vector/vector.toml:ro", config_path.display());
    docker([
        "run",
        "-d",
        "--name",
        VECTOR_CONTAINER,
        "--network",
        NETWORK_NAME,
        "-v",
        &mount,
        &vector_image,
        "--config",
        "/etc/vector/vector.toml",
    ])
}

fn wait_for_container(container: &str, label: &str) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(20) {
        let status = Command::new("docker")
            .args(["inspect", "-f", "{{.State.Running}}", container])
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("failed to inspect {label} container"))?;
        if status.status.success() && String::from_utf8_lossy(&status.stdout).trim() == "true" {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    bail!("{label} container did not stay running")
}

fn clickhouse_query(query: &str) -> Result<String> {
    let output = Command::new("docker")
        .args([
            "exec",
            CLICKHOUSE_CONTAINER,
            "clickhouse-client",
            "--query",
            query,
        ])
        .stdin(Stdio::null())
        .output()
        .context("failed to run ClickHouse query")?;
    if !output.status.success() {
        bail!(
            "ClickHouse query failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn wait_for_clickhouse_count(label: &str, query: &str) -> Result<()> {
    let started = Instant::now();
    let mut last = String::new();
    while started.elapsed() < Duration::from_secs(45) {
        match clickhouse_query(query) {
            Ok(output) => {
                last = output.trim().to_string();
                if last.parse::<u64>().unwrap_or_default() > 0 {
                    return Ok(());
                }
            }
            Err(error) => last = error.to_string(),
        }
        thread::sleep(Duration::from_millis(500));
    }
    bail!("timed out waiting for {label} rows in ClickHouse; last count/output: {last}")
}

fn expect_clickhouse_analytics_rows() -> Result<()> {
    wait_for_clickhouse_count(
        "request log",
        "SELECT count() FROM ferrogate.ferrogate_request_logs WHERE logical_model = 'fast-chat'",
    )?;
    wait_for_clickhouse_count(
        "trace span",
        "SELECT count() FROM ferrogate.ferrogate_trace_spans WHERE span_name = 'ferrogate.gateway.request'",
    )?;
    wait_for_clickhouse_count(
        "billing/metering event",
        "SELECT count() FROM ferrogate.ferrogate_billing_metering_events WHERE logical_model = 'fast-chat'",
    )?;
    wait_for_clickhouse_count(
        "usage metric",
        "SELECT count() FROM ferrogate.ferrogate_usage_metrics WHERE logical_model = 'fast-chat'",
    )?;
    wait_for_clickhouse_count(
        "audit timeline event",
        "SELECT count() FROM ferrogate.ferrogate_audit_timeline WHERE action = 'config.validate'",
    )
}

fn emit_analytics_audit_event(port: u16) -> Result<()> {
    let config_candidate = serde_json::json!({
        "config_toml": "listen = \"0.0.0.0:8080\"\n"
    })
    .to_string();
    expect_json(
        port,
        "POST",
        "/admin/v1/config/validate",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &config_candidate,
        200,
        |body| {
            assert_eq!(body["valid"], true);
            Ok(())
        },
    )
}

fn start_gateway(
    image: &str,
    name: &str,
    host_port: u16,
    config_path: &std::path::Path,
    state_dir: Option<&std::path::Path>,
) -> Result<()> {
    let config_mount = format!("{}:/etc/ferrogate/ferrogate.toml:ro", config_path.display());
    let port = format!("127.0.0.1:{host_port}:8080");
    let mut args = vec![
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        name.to_string(),
        "--network".to_string(),
        NETWORK_NAME.to_string(),
        "-p".to_string(),
        port,
        "-v".to_string(),
        config_mount,
    ];
    if let Some(state_dir) = state_dir {
        args.push("-v".to_string());
        args.push(format!("{}:/var/lib/ferrogate", state_dir.display()));
    }
    args.extend([
        "-e".to_string(),
        "FERROGATE_CONFIG=/etc/ferrogate/ferrogate.toml".to_string(),
        "-e".to_string(),
        "FERROGATE_PROVIDER_SECRET=provider-secret".to_string(),
        image.to_string(),
    ]);
    docker_args(args)
}

fn wait_for_provider() -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(15) {
        if Command::new("docker")
            .args([
                "exec",
                PROVIDER_CONTAINER,
                "python",
                "-c",
                "import socket; socket.create_connection(('127.0.0.1', 8081), 1).close()",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    bail!("provider mock did not start listening on 8081")
}

fn wait_for_redis() -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(15) {
        if Command::new("docker")
            .args(["exec", REDIS_CONTAINER, "redis-cli", "PING"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    bail!("redis did not start responding to PING")
}

fn wait_for_http(host_port: u16, path: &str, expected_status: u16) -> Result<()> {
    let started = Instant::now();
    let mut last = String::new();
    while started.elapsed() < Duration::from_secs(30) {
        match http_request(host_port, "GET", path, &[], "") {
            Ok(response) if response.status == expected_status => return Ok(()),
            Ok(response) => last = response.raw,
            Err(error) => last = error.to_string(),
        }
        thread::sleep(Duration::from_millis(500));
    }
    bail!("timed out waiting for {path}; last response: {last}");
}

fn expect_json<F>(
    host_port: u16,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &str,
    expected_status: u16,
    check: F,
) -> Result<()>
where
    F: FnOnce(Value) -> Result<()>,
{
    let response = http_request(host_port, method, path, headers, body)?;
    if response.status != expected_status {
        bail!(
            "{method} {path} expected status {expected_status}, got {}; raw: {}",
            response.status,
            response.raw
        );
    }
    let body: Value = serde_json::from_str(&response.body).with_context(|| {
        format!(
            "failed to parse JSON body for {method} {path}: {}",
            response.body
        )
    })?;
    check(body)
}

fn expect_text<F>(
    host_port: u16,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &str,
    expected_status: u16,
    check: F,
) -> Result<()>
where
    F: FnOnce(&str) -> Result<()>,
{
    let response = http_request(host_port, method, path, headers, body)?;
    if response.status != expected_status {
        bail!(
            "{method} {path} expected status {expected_status}, got {}; raw: {}",
            response.status,
            response.raw
        );
    }
    check(&response.body)
}

fn docker<const N: usize>(args: [&str; N]) -> Result<()> {
    docker_args(args.map(str::to_string))
}

fn docker_args<I, S>(args: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let status = Command::new("docker")
        .args(args)
        .stdin(Stdio::null())
        .status()
        .context("failed to run docker")?;
    if !status.success() {
        bail!("docker command failed with {status}");
    }
    Ok(())
}

fn cleanup_containers() {
    let _ = Command::new("docker")
        .args([
            "rm",
            "-f",
            GATEWAY_A_CONTAINER,
            GATEWAY_B_CONTAINER,
            PROVIDER_CONTAINER,
            REDIS_CONTAINER,
            CLICKHOUSE_CONTAINER,
            VECTOR_CONTAINER,
            POSTGRES_CONTAINER,
            POSTGRES_MIGRATION_SOURCE_CONTAINER,
            POSTGRES_MIGRATION_TARGET_CONTAINER,
            MYSQL_CONTAINER,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = Command::new("docker")
        .args(["network", "rm", NETWORK_NAME])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        if env::var("FERROGATE_TEST_KEEP_CONTAINERS").is_ok_and(|value| value == "1") {
            return;
        }
        cleanup_containers();
    }
}
