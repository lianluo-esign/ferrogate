// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use anyhow::{anyhow, bail, Context, Result};
use clap::ValueEnum;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair,
};
use serde_json::Value;
use std::{
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

mod assertions;
mod cli;
mod http;

use assertions::*;
use cli::{
    AuthArgs, DockerScenario, LocalArgs, SupabaseLiveRestartArgs, SupabaseLiveToken4aiProviderArgs,
    IMAGE_TAG,
};
use http::{free_addr, free_port, http_request, http_request_addr};
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

fn run_admin_api(args: &LocalArgs) -> Result<()> {
    let case = LocalHarness::start(&args.ferrogate_bin, 4)?;

    case.expect_json("GET", "/healthz", &[], "", 200, |body| {
        assert_eq!(body["status"], "ok");
        Ok(())
    })?;
    case.expect_json("GET", "/readyz", &[], "", 200, |body| {
        assert_eq!(body["status"], "ready");
        assert_eq!(body["cluster"]["node_id"], "ferrogate-test-node");
        Ok(())
    })?;
    case.expect_json("GET", "/admin/v1/status", &[ADMIN_AUTH], "", 200, |body| {
        assert_eq!(body["service"], "ferrogate");
        assert_eq!(body["auth_required"], true);
        assert_eq!(body["cluster"]["ready"], true);
        assert_eq!(body["cluster"]["draining"], false);
        assert_eq!(body["storage"]["provider"], "memory");
        assert_eq!(body["storage"]["durable"], false);
        assert_eq!(body["storage"]["implemented"], true);
        assert_eq!(body["storage"]["required"], false);
        assert_eq!(body["storage"]["migration_mode"], "disabled");
        assert_eq!(body["storage"]["health"], "ok");
        assert_eq!(body["storage"]["contract_version"], 1);
        assert_eq!(body["storage"]["provider_order"][0], "supabase");
        assert_eq!(body["storage"]["provider_order"][1], "postgres");
        assert_eq!(body["storage"]["provider_order"][2], "mysql");
        assert_eq!(body["analytics"]["provider"], "vector");
        assert_eq!(body["analytics"]["enabled"], false);
        assert_eq!(body["analytics"]["active"], false);
        assert_eq!(body["analytics"]["mode"], "pipeline");
        assert_eq!(body["analytics"]["health"], "disabled");
        assert!(body["analytics"]["last_success_at_unix"].is_null());
        assert!(body["analytics"]["last_export_error"].is_null());
        assert_eq!(body["analytics"]["contract_version"], 1);
        assert_eq!(body["observability"][0]["provider"], "vector");
        assert_eq!(body["observability"][0]["endpoint_source"], "observability");
        Ok(())
    })?;
    case.expect_json("GET", "/admin/status", &[ADMIN_AUTH], "", 200, |body| {
        assert_eq!(body["service"], "ferrogate");
        Ok(())
    })?;
    case.expect_json(
        "GET",
        "/admin/v1/providers",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(list_contains(&body, "name", "openai"));
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/provider-health",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(body["data"].is_array());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/provider-models?provider=openai",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["data"][0]["provider"], "openai");
            assert_eq!(body["data"][0]["status"], "ok");
            assert!(array_contains(
                &body["data"][0],
                "models",
                "id",
                "provider-chat"
            ));
            let raw = body.to_string();
            assert_secret_redacted(&raw);
            assert!(!raw.contains("FERROGATE_PROVIDER_SECRET"));
            assert!(!raw.contains("provider-secret"));
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/observability",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["data"][0]["provider"], "vector");
            assert_eq!(body["data"][0]["enabled"], true);
            assert_eq!(body["data"][0]["protocol"], "otlp_http_json");
            assert_eq!(body["data"][0]["prometheus_metrics_path"], "/metrics");
            assert!(body["data"][0]["endpoint"]
                .as_str()
                .is_some_and(|endpoint| endpoint.starts_with("http://127.0.0.1:")));
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/extensions",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(body["data"].is_array());
            Ok(())
        },
    )?;
    case.expect_json("GET", "/admin/v1/tools", &[ADMIN_AUTH], "", 200, |body| {
        assert!(body["data"].is_array());
        Ok(())
    })?;
    case.expect_json(
        "GET",
        "/admin/v1/tool-approvals",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "list");
            assert_eq!(body["total"], 0);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/tool-approvals/approval-missing/approve",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"fingerprint":"missing"}"#,
        404,
        |body| {
            assert_eq!(body["error"]["code"], "tool_approval_not_found");
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/mcp-servers",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(body["data"].is_array());
            Ok(())
        },
    )?;

    let plugin = r#"{"id":"hook.noop.harness","kind":"request_hook","source":"builtin","enabled":true,"order":90,"permissions":{"tools":[],"network":[],"filesystem":false,"shell":false},"config":{"mode":"harness"}}"#;
    case.expect_json(
        "POST",
        "/admin/v1/plugins",
        &[ADMIN_AUTH, JSON_CONTENT],
        plugin,
        201,
        |body| {
            assert_eq!(body["plugin"]["id"], "hook.noop.harness");
            assert_eq!(body["plugin"]["kind"], "request_hook");
            assert_eq!(body["plugin"]["active"], true);
            assert_eq!(body["plugin"]["health"], "ok");
            assert_array_contains(&body["plugin"]["capabilities"], "request_hook")?;
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/plugins/hook.noop.harness",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["id"], "hook.noop.harness");
            assert_eq!(body["active"], true);
            assert_array_contains(&body["capabilities"], "request_hook")?;
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    let updated_plugin = r#"{"id":"hook.noop.harness","kind":"request_hook","source":"builtin","enabled":false,"order":90,"permissions":{"tools":[],"network":[],"filesystem":false,"shell":false},"config":{"mode":"harness-disabled"}}"#;
    case.expect_json(
        "PATCH",
        "/admin/v1/plugins/hook.noop.harness",
        &[ADMIN_AUTH, JSON_CONTENT],
        updated_plugin,
        200,
        |body| {
            assert_eq!(body["plugin"]["id"], "hook.noop.harness");
            assert_eq!(body["plugin"]["enabled"], false);
            assert_eq!(body["plugin"]["active"], false);
            assert_eq!(body["plugin"]["health"], "disabled");
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/tool-sessions/ferrogate-test-session",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["total"], 0);
            Ok(())
        },
    )?;
    case.expect_json("GET", "/admin/v1/models", &[ADMIN_AUTH], "", 200, |body| {
        assert!(list_contains(&body, "name", "fast-chat"));
        Ok(())
    })?;
    case.expect_json("GET", "/admin/v1/tenants", &[ADMIN_AUTH], "", 200, |body| {
        assert!(body["data"].is_array());
        Ok(())
    })?;

    let api_key = r#"{"id":"test-client","name":"Test client","key":"test-secret","scopes":["models.read","chat.completions","responses.create"],"allowed_models":["fast-chat"],"organization_id":"org_test","project_id":"project_harness"}"#;
    case.expect_json(
        "POST",
        "/admin/v1/api-keys",
        &[ADMIN_AUTH, JSON_CONTENT],
        api_key,
        201,
        |body| {
            assert_eq!(body["key"]["id"], "test-client");
            assert_eq!(body["key"]["key_source"], "inline");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/api-keys/test-client",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["key"]["id"], "test-client");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    let updated_api_key = r#"{"id":"test-client","name":"Updated test client","key":"test-secret-2","scopes":["models.read","chat.completions","responses.create"],"allowed_models":["fast-chat"],"enabled":true}"#;
    case.expect_json(
        "PATCH",
        "/admin/v1/api-keys/test-client",
        &[ADMIN_AUTH, JSON_CONTENT],
        updated_api_key,
        200,
        |body| {
            assert_eq!(body["key"]["name"], "Updated test client");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;

    let policy = r#"{"name":"block-test-client","effect":"deny","api_key_ids":["test-client"],"models":["fast-chat"],"providers":["openai"],"code":"blocked_by_ferrogate_test","message":"blocked by ferrogate-test","enabled":true}"#;
    case.expect_json(
        "POST",
        "/admin/v1/policies",
        &[ADMIN_AUTH, JSON_CONTENT],
        policy,
        201,
        |body| {
            assert_eq!(body["policy"]["name"], "block-test-client");
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/policies/block-test-client",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["policy"]["enabled"], true);
            Ok(())
        },
    )?;
    let disabled_policy = r#"{"name":"block-test-client","effect":"deny","api_key_ids":["test-client"],"models":["fast-chat"],"providers":["openai"],"code":"blocked_by_ferrogate_test","message":"blocked by ferrogate-test","enabled":false}"#;
    case.expect_json(
        "PATCH",
        "/admin/v1/policies/block-test-client",
        &[ADMIN_AUTH, JSON_CONTENT],
        disabled_policy,
        200,
        |body| {
            assert_eq!(body["policy"]["enabled"], false);
            Ok(())
        },
    )?;

    let gateway_config = r#"{"id":"harness-profile","name":"Harness profile","revision":2,"api_key_ids":["test-client"],"cache_enabled":false}"#;
    case.expect_json(
        "POST",
        "/admin/v1/gateway-configs",
        &[ADMIN_AUTH, JSON_CONTENT],
        gateway_config,
        201,
        |body| {
            assert_eq!(body["gateway_config"]["id"], "harness-profile");
            assert_eq!(body["gateway_config"]["cache_enabled"], false);
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/gateway-configs/harness-profile",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["gateway_config"]["revision"], 2);
            Ok(())
        },
    )?;

    let config_candidate = serde_json::json!({
        "config_toml": format!("listen = \"{}\"\n", case.gateway_addr)
    })
    .to_string();
    case.expect_json(
        "POST",
        "/admin/v1/config/validate",
        &[ADMIN_AUTH, JSON_CONTENT],
        &config_candidate,
        200,
        |body| {
            assert_eq!(body["valid"], true);
            assert_eq!(body["listener_reload_required"], false);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/config/reload",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"config_toml":"listen = \"not-an-address\"\n"}"#,
        200,
        |body| {
            assert_eq!(body["valid"], false);
            assert_eq!(body["committed"], false);
            Ok(())
        },
    )?;
    case.expect_json("GET", "/admin/v1/drain", &[ADMIN_AUTH], "", 200, |body| {
        assert_eq!(body["draining"], false);
        Ok(())
    })?;
    case.expect_json(
        "POST",
        "/admin/v1/drain",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"drain":true}"#,
        200,
        |body| {
            assert_eq!(body["draining"], true);
            assert_eq!(body["accepting_new_requests"], false);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/drain",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"drain":false}"#,
        200,
        |body| {
            assert_eq!(body["draining"], false);
            Ok(())
        },
    )?;

    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[AUTH_TEST_CLIENT_2, JSON_CONTENT],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"admin coverage"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/request-logs",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(list_contains(&body, "logical_model", "fast-chat"));
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/metering-events",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(list_contains(&body, "logical_model", "fast-chat"));
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/billing-events",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(list_contains(&body, "logical_model", "fast-chat"));
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/usage-aggregates",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(body["data"].is_array());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/audit-events",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(list_contains(&body, "action", "api_key.upsert"));
            assert!(list_contains(&body, "action", "policy.upsert"));
            assert!(list_contains(&body, "action", "gateway_config.upsert"));
            assert!(list_contains(&body, "action", "plugin.upsert"));
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_text("GET", "/metrics", &[ADMIN_AUTH], "", 200, |body| {
        assert!(body.contains("ferrogate_request_logs_total"));
        Ok(())
    })?;
    thread::sleep(Duration::from_secs(6));
    case.expect_vector_otlp_export()?;

    case.expect_json(
        "DELETE",
        "/admin/v1/gateway-configs/harness-profile",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["deleted"], true);
            Ok(())
        },
    )?;
    case.expect_json(
        "DELETE",
        "/admin/v1/policies/block-test-client",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["deleted"], true);
            Ok(())
        },
    )?;
    case.expect_json(
        "DELETE",
        "/admin/v1/plugins/hook.noop.harness",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["deleted"], true);
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/audit-events",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(list_contains(&body, "action", "plugin.delete"));
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "DELETE",
        "/admin/v1/api-keys/test-client",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["deleted"], true);
            Ok(())
        },
    )?;

    println!("admin-api scenario passed");
    Ok(())
}

fn run_auth_api(args: &AuthArgs) -> Result<()> {
    let case = AuthHarness::start(&args.ferrogate_auth_bin)?;

    case.expect_json("GET", "/healthz", &[], "", 200, |body| {
        assert_eq!(body["service"], "ferrogate-auth");
        assert_eq!(body["status"], "ok");
        Ok(())
    })?;
    case.expect_json("GET", "/v1/healthz", &[], "", 200, |body| {
        assert_eq!(body["service"], "ferrogate-auth");
        Ok(())
    })?;
    case.expect_json("GET", "/v1/tenants", &[], "", 200, |body| {
        assert!(array_contains(&body, "tenants", "id", "tenant-example"));
        Ok(())
    })?;
    case.expect_json(
        "POST",
        "/v1/auth/resolve-api-key",
        &[JSON_CONTENT],
        r#"{"presented_key":"dev-secret"}"#,
        200,
        |body| {
            assert_eq!(body["tenant"]["organization_id"], "org-example");
            assert_eq!(body["subject"]["type"], "api_key");
            assert_eq!(body["scopes"][0], "models.read");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/auth/authorize",
        &[JSON_CONTENT],
        r#"{"tenant":{"organization_id":"org-example","team_id":"team-example","project_id":"project-example","user_id":null,"api_key_id":"key-example"},"subject":{"type":"api_key","api_key_id":"key-example"},"action":"chat.completions","resource":"model:fast-chat"}"#,
        200,
        |body| {
            assert_eq!(body["allowed"], true);
            assert_eq!(body["reason"], "matched_rbac_binding");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/auth/authorize",
        &[JSON_CONTENT],
        r#"{"tenant":{"organization_id":"org-example","team_id":"team-example","project_id":"project-example","user_id":null,"api_key_id":"key-example"},"subject":{"type":"api_key","api_key_id":"key-example"},"action":"responses.create","resource":"model:fast-chat"}"#,
        200,
        |body| {
            assert_eq!(body["allowed"], false);
            assert_eq!(body["reason"], "no_matching_rbac_binding");
            Ok(())
        },
    )?;

    println!("auth-api scenario passed");
    Ok(())
}

fn run_gateway_api(args: &LocalArgs) -> Result<()> {
    let case = LocalHarness::start_with_billing_and_agent(&args.ferrogate_bin, 7)?;

    case.expect_json("GET", "/v1/models", &[CLIENT_AUTH], "", 200, |body| {
        assert!(list_contains(&body, "id", "fast-chat"));
        Ok(())
    })?;
    case.expect_json(
        "GET",
        "/.well-known/agent.json",
        &[CLIENT_AUTH],
        "",
        200,
        |body| {
            assert!(body["data"].is_array());
            assert!(list_contains(&body, "id", "agent.echo"));
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/agents/agent.echo/message:send",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":"msg-1","method":"message:send","params":{"message":{"role":"user","parts":[{"type":"text","text":"hello"}]}}}"#,
        200,
        |body| {
            assert_eq!(body["result"]["content"][0]["text"], "agent-result");
            assert_eq!(body["result"]["isError"], false);
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/.well-known/agent.json",
        &[OBSERVER_AUTH],
        "",
        403,
        |body| {
            assert_eq!(body["error"]["code"], "scope_denied");
            Ok(())
        },
    )?;
    let agent_upstream_endpoint = case.agent_endpoint()?;
    let agent_upstream = format!(
        r#"{{"id":"pi-agent-us","name":"Pi Agent US","description":"Community agent upstream","enabled":true,"protocol":"a2a","endpoint":"http://{agent_upstream_endpoint}/a2a","tenant_ids":["client"],"capabilities":["invoke","read","stream","discover"]}}"#
    );
    case.expect_json(
        "POST",
        "/admin/v1/agent-upstreams",
        &[ADMIN_AUTH, JSON_CONTENT],
        &agent_upstream,
        201,
        |body| {
            assert_eq!(body["object"], "agent_upstream");
            assert_eq!(body["agent_upstream"]["id"], "pi-agent-us");
            assert_eq!(body["agent_upstream"]["protocol"], "a2a");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/agent-upstreams/pi-agent-us",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "agent_upstream");
            assert_eq!(body["agent_upstream"]["id"], "pi-agent-us");
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/.well-known/agent.json",
        &[CLIENT_AUTH],
        "",
        200,
        |body| {
            assert!(body["data"].is_array());
            assert!(list_contains(&body, "id", "pi-agent-us"));
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/agents/pi-agent-us/message:stream",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":"msg-2","method":"message:stream","params":{"message":{"role":"user","parts":[{"type":"text","text":"hello"}]}}}"#,
        200,
        |body| {
            assert_eq!(body["result"]["content"][0]["text"], "agent-stream");
            Ok(())
        },
    )?;
    case.expect_json(
        "PUT",
        "/admin/v1/agent-upstreams/pi-agent-us",
        &[ADMIN_AUTH, JSON_CONTENT],
        &format!(
            r#"{{"id":"pi-agent-us","name":"Pi Agent US","enabled":false,"protocol":"a2a","endpoint":"http://{agent_upstream_endpoint}/a2a","tenant_ids":["client"],"capabilities":["invoke","read"]}}"#
        ),
        200,
        |body| {
            assert_eq!(body["agent_upstream"]["enabled"], false);
            assert_eq!(body["agent_upstream"]["capabilities"][1], "read");
            Ok(())
        },
    )?;
    case.expect_json(
        "DELETE",
        "/admin/v1/agent-upstreams/pi-agent-us",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["deleted"], true);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-upstreams",
        &[OBSERVER_AUTH, JSON_CONTENT],
        &agent_upstream,
        403,
        |body| {
            assert_eq!(body["error"]["code"], "scope_denied");
            Ok(())
        },
    )?;
    case.expect_json("GET", "/v1/models", &[], "", 401, |body| {
        assert_eq!(body["error"]["code"], "missing_api_key");
        Ok(())
    })?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-workflows",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"support-flow","name":"Support flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"draft","kind":"model","model":"fast-chat","providers":["openai"],"token_budget":600}],"edges":[],"max_model_calls":1,"max_iterations":2,"token_budget":600}"#,
        201,
        |body| {
            assert_eq!(body["object"], "agent_workflow");
            assert_eq!(body["agent_workflow"]["workflow"]["id"], "support-flow");
            assert_eq!(body["agent_workflow"]["workflow"]["version"], 1);
            assert_eq!(
                body["agent_workflow"]["workflow"]["nodes"][0]["providers"][0],
                "openai"
            );
            assert_eq!(body["agent_workflow"]["counters"]["request_count"], 0);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-workflows",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"budget-flow","name":"Budget flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"draft","kind":"model","model":"fast-chat","token_budget":600}],"edges":[],"max_model_calls":10,"max_iterations":2,"token_budget":600}"#,
        201,
        |body| {
            assert_eq!(body["object"], "agent_workflow");
            assert_eq!(body["agent_workflow"]["workflow"]["id"], "budget-flow");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-workflows",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"bad-tool-flow","name":"Bad tool flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"missing","kind":"tool","tool":"tool.missing"}],"edges":[],"max_tool_calls":1}"#,
        400,
        |body| {
            assert_eq!(body["error"]["code"], "invalid_agent_workflow");
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("references unknown tool tool.missing")));
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-workflows",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"bad-provider-flow","name":"Bad provider flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"draft","kind":"model","model":"fast-chat","providers":["missing-provider"]}],"edges":[],"max_model_calls":1}"#,
        400,
        |body| {
            assert_eq!(body["error"]["code"], "invalid_agent_workflow");
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("references unknown provider missing-provider")));
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-workflows",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"provider-flow","name":"Provider flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"draft","kind":"model","model":"fast-chat","providers":["anthropic"]}],"edges":[],"max_model_calls":10,"max_iterations":2}"#,
        201,
        |body| {
            assert_eq!(body["object"], "agent_workflow");
            assert_eq!(body["agent_workflow"]["workflow"]["id"], "provider-flow");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-workflows",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"timeout-flow","name":"Timeout flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"draft","kind":"model","model":"fast-chat"}],"edges":[],"max_model_calls":10,"max_iterations":2,"timeout_millis":1}"#,
        201,
        |body| {
            assert_eq!(body["object"], "agent_workflow");
            assert_eq!(body["agent_workflow"]["workflow"]["id"], "timeout-flow");
            assert_eq!(body["agent_workflow"]["workflow"]["timeout_millis"], 1);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-workflows",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"tool-flow","name":"Tool flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"echo","kind":"tool","tool":"tool.echo","max_iterations":2}],"edges":[],"max_tool_calls":1,"max_iterations":2}"#,
        201,
        |body| {
            assert_eq!(body["object"], "agent_workflow");
            assert_eq!(body["agent_workflow"]["workflow"]["id"], "tool-flow");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-workflows",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"parallel-flow","name":"Parallel flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"echo","kind":"tool","tool":"tool.echo","max_iterations":3}],"edges":[],"max_tool_calls":2,"max_parallelism":1,"max_iterations":3}"#,
        201,
        |body| {
            assert_eq!(body["object"], "agent_workflow");
            assert_eq!(body["agent_workflow"]["workflow"]["id"], "parallel-flow");
            assert_eq!(body["agent_workflow"]["workflow"]["max_parallelism"], 1);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/agent-workflows",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"graph-flow","name":"Graph flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"start","kind":"model","model":"fast-chat"},{"id":"review","kind":"model","model":"fast-chat"}],"edges":[{"from":"start","to":"review"}],"max_model_calls":10,"max_iterations":3}"#,
        201,
        |body| {
            assert_eq!(body["object"], "agent_workflow");
            assert_eq!(body["agent_workflow"]["workflow"]["id"], "graph-flow");
            assert_eq!(
                body["agent_workflow"]["workflow"]["edges"][0]["from"],
                "start"
            );
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    let support_skill = r#"{"id":"support-skill","name":"Support skill","version":"1.0.0","description":"Pi-compatible support skill package","enabled":true,"api_key_ids":["client"],"compatibility":{"agent_runtimes":["pi-agent","codex","claude-code"]},"permissions":{"tools":["tool.echo"],"network":[],"filesystem":false,"shell":false,"tenant_scope":true,"secrets":false,"admin_mutation":false},"capabilities":[{"kind":"plugin","id":"tool.echo","description":"governed builtin echo plugin"},{"kind":"tool","id":"tool.echo","description":"echo tool through FerroGate tool governance"},{"kind":"mcp_server","id":"http","description":"HTTP MCP server binding"},{"kind":"mcp_tool","id":"http-search","description":"MCP search tool through FerroGate MCP governance"},{"kind":"agent_workflow","id":"support-flow","description":"bounded support workflow"}],"metadata":{"display":"Support","token":"client-secret"}}"#;
    case.expect_json(
        "POST",
        "/admin/v1/skill-packages",
        &[ADMIN_AUTH, JSON_CONTENT],
        support_skill,
        201,
        |body| {
            assert_eq!(body["object"], "skill_package");
            assert_eq!(body["skill_package"]["id"], "support-skill");
            assert_eq!(body["skill_package"]["version"], "1.0.0");
            assert_eq!(body["skill_package"]["capabilities"][1]["kind"], "tool");
            assert_eq!(body["skill_package"]["metadata"]["token"], "[redacted]");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/skill-packages/support-skill",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "skill_package");
            assert_eq!(body["skill_package"]["id"], "support-skill");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json("GET", "/v1/skills", &[CLIENT_AUTH], "", 200, |body| {
        let skill = admin_list_item(&body, "id", "support-skill")
            .context("support skill was not visible to owning client")?;
        assert_eq!(skill["name"], "Support skill");
        assert_eq!(skill["compatibility"]["agent_runtimes"][0], "pi-agent");
        assert!(skill.get("metadata").is_none());
        assert_secret_redacted(&body.to_string());
        Ok(())
    })?;
    case.expect_json("GET", "/v1/skills", &[OBSERVER_AUTH], "", 200, |body| {
        assert!(!list_contains(&body, "id", "support-skill"));
        assert_secret_redacted(&body.to_string());
        Ok(())
    })?;
    case.expect_json(
        "POST",
        "/v1/tools/execute",
        &[CLIENT_AUTH, JSON_CONTENT, SUPPORT_SKILL_HEADER],
        r#"{"name":"tool.echo","arguments":{"message":"skill-governed-tool"},"session_id":"skill-tool-session"}"#,
        200,
        |body| {
            assert_eq!(body["name"], "tool.echo");
            assert_eq!(body["is_error"], false);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/mcp/tool/execute",
        &[CLIENT_AUTH, JSON_CONTENT, SUPPORT_SKILL_HEADER],
        r#"{"name":"http-search","arguments":{"query":"skill-mcp"},"session_id":"skill-mcp-session"}"#,
        200,
        |body| {
            assert_eq!(body["name"], "http-search");
            assert_eq!(body["is_error"], false);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_mcp_json(
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT, SUPPORT_SKILL_HEADER],
        r#"{"jsonrpc":"2.0","id":73,"method":"tools/call","params":{"name":"http-search","arguments":{"query":"skill-native-mcp"}}}"#,
        200,
        |body| {
            assert_eq!(body["result"]["content"][0]["text"], "ferrogate-result");
            assert_eq!(body["result"]["isError"], false);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/tools/execute",
        &[OBSERVER_AUTH, JSON_CONTENT, SUPPORT_SKILL_HEADER],
        r#"{"name":"tool.echo","arguments":{"message":"blocked"}}"#,
        403,
        |body| {
            assert_eq!(body["error"]["code"], "skill_package_not_allowed");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    let embedded_skill = r#"{"id":"embedded-skill","name":"Embedded skill","version":"1.0.0","description":"Skill package with owned resources","enabled":true,"api_key_ids":["client"],"compatibility":{"agent_runtimes":["pi-agent","codex","claude-code"]},"permissions":{"tools":["tool.health_check"],"network":[],"filesystem":false,"shell":false,"tenant_scope":true,"secrets":false,"admin_mutation":false},"capabilities":[{"kind":"plugin","id":"tool.health_check","description":"owned health-check tool provider"},{"kind":"tool","id":"tool.health_check","description":"owned health-check tool"},{"kind":"mcp_server","id":"skillhttp","description":"owned MCP server binding"},{"kind":"mcp_tool","id":"skillhttp-search","description":"owned MCP search tool"},{"kind":"prompt_template","id":"embedded-prompt","description":"owned prompt template"},{"kind":"agent_workflow","id":"embedded-flow","description":"owned workflow"}],"resources":{"plugins":[{"id":"tool.health_check","kind":"tool_provider","version":"1.0.0","manifest":{"name":"Health check","capabilities":["tool_provider"],"required_permissions":{"tools":["tool.health_check"],"network":[],"filesystem":false,"shell":false,"tenant_scope":false,"secrets":false,"admin_mutation":false},"hooks":[]},"enabled":true,"source":"builtin","order":11,"approval_policy":"never","permissions":{"tools":["tool.health_check"],"network":[],"filesystem":false,"shell":false,"tenant_scope":false,"secrets":false,"admin_mutation":false},"config":{"registered_by":"embedded-skill"}}],"mcp_servers":[{"name":"skillhttp","transport":"streamable_http","url":"http://127.0.0.1:1/mcp","auth_type":"none","headers":[],"tools_to_execute":["search"],"tools_to_auto_execute":["search"],"approval_policy":"never","tool_include":["search"],"tool_regex":[],"tls":{},"timeout_ms":100,"health_ping_interval_secs":10,"max_reconnect_attempts":1,"min_reconnect_backoff_secs":1,"max_reconnect_backoff_secs":1}],"prompt_templates":[{"id":"embedded-prompt","name":"Embedded prompt","status":"active","target":"chat_completions","model":"fast-chat","variables":[],"versions":[{"revision":1,"status":"active","messages":[{"role":"system","content":"Use gateway policy."}]}]}],"agent_workflows":[{"id":"embedded-flow","name":"Embedded flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"health","kind":"tool","tool":"tool.health_check","max_iterations":1}],"edges":[],"max_tool_calls":1,"max_iterations":1}]},"metadata":{"display":"Embedded","token":"client-secret"}}"#;
    case.expect_json(
        "POST",
        "/admin/v1/skill-packages",
        &[ADMIN_AUTH, JSON_CONTENT],
        embedded_skill,
        201,
        |body| {
            assert_eq!(body["object"], "skill_package");
            assert_eq!(body["skill_package"]["id"], "embedded-skill");
            assert_eq!(
                body["skill_package"]["resources"]["plugins"][0]["config"]["registered_by"],
                "embedded-skill"
            );
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/plugins/tool.health_check",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["id"], "tool.health_check");
            assert_eq!(body["enabled"], true);
            assert_array_contains(&body["tools"], "tool.health_check")
                .context("skill-owned plugin must expose tool.health_check")?;
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json("GET", "/admin/v1/tools", &[ADMIN_AUTH], "", 200, |body| {
        let tool = admin_list_item(&body, "name", "tool.health_check")
            .context("skill-owned tool was not materialized")?;
        assert_eq!(tool["extension_id"], "tool.health_check");
        assert_secret_redacted(&body.to_string());
        Ok(())
    })?;
    case.expect_json(
        "GET",
        "/admin/v1/mcp-servers/skillhttp",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["name"], "skillhttp");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/tools/execute",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-skill-package: embedded-skill",
        ],
        r#"{"name":"tool.health_check","arguments":{},"session_id":"embedded-skill-tool-session"}"#,
        200,
        |body| {
            assert_eq!(body["name"], "tool.health_check");
            assert_eq!(body["content"]["status"], "ok");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    let disabled_embedded_skill = r#"{"id":"embedded-skill","name":"Embedded skill","version":"1.0.0","description":"Skill package with owned resources","enabled":false,"api_key_ids":["client"],"compatibility":{"agent_runtimes":["pi-agent","codex","claude-code"]},"permissions":{"tools":["tool.health_check"],"network":[],"filesystem":false,"shell":false,"tenant_scope":true,"secrets":false,"admin_mutation":false},"capabilities":[{"kind":"plugin","id":"tool.health_check"},{"kind":"tool","id":"tool.health_check"},{"kind":"mcp_server","id":"skillhttp"},{"kind":"mcp_tool","id":"skillhttp-search"},{"kind":"prompt_template","id":"embedded-prompt"},{"kind":"agent_workflow","id":"embedded-flow"}],"resources":{"plugins":[{"id":"tool.health_check","kind":"tool_provider","version":"1.0.0","manifest":{"name":"Health check","capabilities":["tool_provider"],"required_permissions":{"tools":["tool.health_check"],"network":[],"filesystem":false,"shell":false,"tenant_scope":false,"secrets":false,"admin_mutation":false},"hooks":[]},"enabled":true,"source":"builtin","order":11,"approval_policy":"never","permissions":{"tools":["tool.health_check"],"network":[],"filesystem":false,"shell":false,"tenant_scope":false,"secrets":false,"admin_mutation":false},"config":{"registered_by":"embedded-skill"}}],"mcp_servers":[{"name":"skillhttp","transport":"streamable_http","url":"http://127.0.0.1:1/mcp","auth_type":"none","headers":[],"tools_to_execute":["search"],"tools_to_auto_execute":["search"],"approval_policy":"never","tool_include":["search"],"tool_regex":[],"tls":{},"timeout_ms":100,"health_ping_interval_secs":10,"max_reconnect_attempts":1,"min_reconnect_backoff_secs":1,"max_reconnect_backoff_secs":1}],"prompt_templates":[{"id":"embedded-prompt","name":"Embedded prompt","status":"active","target":"chat_completions","model":"fast-chat","variables":[],"versions":[{"revision":1,"status":"active","messages":[{"role":"system","content":"Use gateway policy."}]}]}],"agent_workflows":[{"id":"embedded-flow","name":"Embedded flow","version":1,"enabled":true,"api_key_ids":["client"],"nodes":[{"id":"health","kind":"tool","tool":"tool.health_check","max_iterations":1}],"edges":[],"max_tool_calls":1,"max_iterations":1}]},"metadata":{"display":"Embedded","token":"client-secret"}}"#;
    case.expect_json(
        "PUT",
        "/admin/v1/skill-packages/embedded-skill",
        &[ADMIN_AUTH, JSON_CONTENT],
        disabled_embedded_skill,
        200,
        |body| {
            assert_eq!(body["object"], "skill_package");
            assert_eq!(body["skill_package"]["enabled"], false);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/plugins/tool.health_check",
        &[ADMIN_AUTH],
        "",
        404,
        |body| {
            assert_eq!(body["error"]["code"], "plugin_not_found");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json("GET", "/admin/v1/tools", &[ADMIN_AUTH], "", 200, |body| {
        assert!(!list_contains(&body, "name", "tool.health_check"));
        assert_secret_redacted(&body.to_string());
        Ok(())
    })?;
    case.expect_json(
        "GET",
        "/admin/v1/mcp-servers/skillhttp",
        &[ADMIN_AUTH],
        "",
        404,
        |body| {
            assert_eq!(body["error"]["code"], "mcp_server_not_found");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/audit-events",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            let raw = body.to_string();
            assert!(raw.contains("skill_package:support-skill@1.0.0/tool_session:skill-tool-session"));
            assert!(raw.contains("skill_package:support-skill@1.0.0/tool_session:skill-mcp-session/mcp:http/tool:search"));
            assert!(raw.contains("skill_package:support-skill@1.0.0/mcp:http/tool:search"));
            assert!(raw.contains("skill_package=support-skill@1.0.0"));
            assert_secret_redacted(&raw);
            Ok(())
        },
    )?;
    case.expect_json(
        "PUT",
        "/admin/v1/skill-packages/support-skill",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"support-skill","name":"Support skill","version":"1.0.0","description":"Pi-compatible support skill package","enabled":false,"api_key_ids":["client"],"compatibility":{"agent_runtimes":["pi-agent","codex","claude-code"]},"permissions":{"tools":["tool.echo"],"network":[],"filesystem":false,"shell":false,"tenant_scope":true,"secrets":false,"admin_mutation":false},"capabilities":[{"kind":"plugin","id":"tool.echo"},{"kind":"tool","id":"tool.echo"},{"kind":"mcp_server","id":"http"},{"kind":"mcp_tool","id":"http-search"},{"kind":"agent_workflow","id":"support-flow"}],"metadata":{"display":"Support","token":"client-secret"}}"#,
        200,
        |body| {
            assert_eq!(body["object"], "skill_package");
            assert_eq!(body["skill_package"]["enabled"], false);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/v1/skills/support-skill",
        &[CLIENT_AUTH],
        "",
        404,
        |body| {
            assert_eq!(body["error"]["code"], "skill_package_not_found");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"gateway coverage client-secret"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-agent-run-id: workflow-run-e2e",
            "x-ferrogate-workflow-id: support-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: draft",
            "x-ferrogate-workflow-iteration: 1",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"workflow coverage"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-agent-run-id: workflow-graph-e2e",
            "x-ferrogate-workflow-id: graph-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: review",
            "x-ferrogate-workflow-iteration: 1",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"workflow graph rejected"}]}"#,
        403,
        |body| {
            assert_eq!(body["error"]["code"], "workflow_edge_not_allowed");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-agent-run-id: workflow-graph-e2e",
            "x-ferrogate-workflow-id: graph-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: start",
            "x-ferrogate-workflow-iteration: 1",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"workflow graph start"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-agent-run-id: workflow-graph-e2e",
            "x-ferrogate-workflow-id: graph-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: review",
            "x-ferrogate-workflow-iteration: 2",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"workflow graph review"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-agent-run-id: workflow-timeout-e2e",
            "x-ferrogate-workflow-id: timeout-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: draft",
            "x-ferrogate-workflow-iteration: 1",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"workflow timeout seed"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    thread::sleep(Duration::from_millis(1_100));
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-agent-run-id: workflow-timeout-e2e",
            "x-ferrogate-workflow-id: timeout-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: draft",
            "x-ferrogate-workflow-iteration: 2",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"workflow timeout rejected"}]}"#,
        429,
        |body| {
            assert_eq!(body["error"]["code"], "workflow_timeout_exceeded");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-workflow-id: budget-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: draft",
            "x-ferrogate-workflow-iteration: 1",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"workflow denied"}],"max_tokens":1000}"#,
        429,
        |body| {
            assert_eq!(body["error"]["code"], "workflow_token_budget_exceeded");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-workflow-id: provider-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: draft",
            "x-ferrogate-workflow-iteration: 1",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"workflow provider denied"}]}"#,
        403,
        |body| {
            assert_eq!(body["error"]["code"], "workflow_provider_not_allowed");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-workflow-id: support-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: draft",
            "x-ferrogate-workflow-iteration: 1",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"workflow model call limit"}]}"#,
        429,
        |body| {
            assert_eq!(body["error"]["code"], "workflow_model_call_limit_exceeded");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/responses",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"model":"fast-chat","input":"gateway responses coverage"}"#,
        200,
        |body| {
            assert_eq!(body["object"], "response");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-config: static-profile",
            "x-ferrogate-agent-run-id: agent-run-e2e",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"profile coverage"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-config: missing-profile",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"bad profile"}]}"#,
        400,
        |body| {
            assert_eq!(body["error"]["code"], "gateway_config_not_found");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"model":"missing-chat","messages":[{"role":"user","content":"bad model"}]}"#,
        403,
        |body| {
            assert_eq!(body["error"]["code"], "model_not_allowed");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/drain",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"drain":true}"#,
        200,
        |body| {
            assert_eq!(body["draining"], true);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"drained"}]}"#,
        503,
        |body| {
            assert_eq!(body["error"]["code"], "node_draining");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/admin/v1/drain",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"drain":false}"#,
        200,
        |_| Ok(()),
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/request-logs",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            let raw = body.to_string();
            assert!(raw.contains("openai.chat.completions"));
            assert!(raw.contains("openai.responses"));
            assert!(raw.contains("agent-run-e2e"));
            assert!(raw.contains("workflow-run-e2e"));
            assert!(raw.contains("\"workflow_id\":\"support-flow\""));
            assert!(raw.contains("\"workflow_version\":1"));
            assert!(raw.contains("\"workflow_node_id\":\"draft\""));
            assert!(raw.contains("workflow_token_budget_exceeded"));
            assert!(raw.contains("workflow_timeout_exceeded"));
            assert_secret_redacted(&raw);
            Ok(())
        },
    )?;
    case.expect_text(
        "GET",
        "/admin/v1/request-log-exports?organization_id=org_demo&project_id=project_gateway&model=fast-chat&provider=openai&status=200&limit=10",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            let records = parse_jsonl(body)?;
            assert!(!records.is_empty());
            let chat = records
                .iter()
                .find(|record| {
                    record["route"] == "openai.chat.completions"
                        && record["agent_run_id"] == "agent-run-e2e"
                })
                .context("missing chat completion export record with agent run evidence")?;
            assert_eq!(chat["object"], "request_log_export");
            assert_eq!(chat["tenant"]["organization_id"], "org_demo");
            assert_eq!(chat["tenant"]["project_id"], "project_gateway");
            assert_eq!(chat["logical_model"], "fast-chat");
            assert_eq!(chat["provider"], "openai");
            assert_eq!(chat["provider_model"], "gpt-4o-mini");
            assert_eq!(chat["status_code"], 200);
            assert_eq!(chat["agent_run_id"], "agent-run-e2e");
            assert_eq!(chat["usage"]["total_tokens"], 2);
            assert_eq!(chat["prompt_recorded"], true);
            assert_eq!(chat["response_recorded"], true);
            assert!(chat["prompt_body"]
                .as_str()
                .is_some_and(|prompt| prompt.contains("profile coverage")));
            assert!(records
                .iter()
                .any(|record| record["route"] == "openai.responses"));
            let workflow_chat = records
                .iter()
                .find(|record| record["agent_run_id"] == "workflow-run-e2e")
                .context("missing workflow export record")?;
            assert_eq!(workflow_chat["workflow_id"], "support-flow");
            assert_eq!(workflow_chat["workflow_version"], 1);
            assert_eq!(workflow_chat["workflow_node_id"], "draft");
            assert_secret_redacted(body);
            assert!(!body.contains("provider-secret"));
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/agent-workflows/support-flow",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "agent_workflow");
            assert_eq!(body["agent_workflow"]["workflow"]["id"], "support-flow");
            assert_eq!(body["agent_workflow"]["counters"]["request_count"], 2);
            assert_eq!(body["agent_workflow"]["counters"]["error_count"], 1);
            assert_eq!(body["agent_workflow"]["counters"]["billing_event_count"], 1);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/agent-workflows",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            let workflow = body["data"]
                .as_array()
                .and_then(|items| {
                    items
                        .iter()
                        .find(|item| item["workflow"]["id"] == "support-flow")
                })
                .context("agent workflow summary was not listed")?;
            assert_eq!(workflow["workflow"]["version"], 1);
            assert_eq!(workflow["counters"]["request_count"], 2);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/billing-events",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            let raw = body.to_string();
            assert!(raw.contains("\"workflow_id\":\"support-flow\""));
            assert!(raw.contains("\"workflow_version\":1"));
            assert!(raw.contains("\"workflow_node_id\":\"draft\""));
            assert_secret_redacted(&raw);
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/agent-runs",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            let run = admin_list_item(&body, "id", "agent-run-e2e")
                .context("agent run summary was not listed")?;
            assert_eq!(run["object"], "agent_run");
            assert_eq!(run["status"], "completed");
            assert_eq!(run["request_count"], 1);
            assert_eq!(run["billing_event_count"], 1);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/agent-runs/agent-run-e2e",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "agent_run_timeline");
            assert_eq!(body["id"], "agent-run-e2e");
            assert_eq!(body["summary"]["id"], "agent-run-e2e");
            assert_eq!(body["requests"][0]["agent_run_id"], "agent-run-e2e");
            assert_eq!(body["billing_events"][0]["agent_run_id"], "agent-run-e2e");
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/agent-runs",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-workflow-id: parallel-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: echo",
        ],
        r#"{"input":"run the parallel denied harness","max_turns":3,"timeout_millis":1000,"tool_calls":[{"name":"tool.echo","arguments":{"message":"first"}},{"name":"tool.echo","arguments":{"message":"second"}}]}"#,
        429,
        |body| {
            assert_eq!(
                body["error"]["code"],
                "workflow_parallelism_limit_exceeded"
            );
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/agent-runs",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-workflow-id: tool-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: echo",
        ],
        r#"{"input":"run the denied harness","max_turns":3,"timeout_millis":1000,"tool_calls":[{"name":"tool.echo","arguments":{"message":"first"}},{"name":"tool.echo","arguments":{"message":"second"}}]}"#,
        429,
        |body| {
            assert_eq!(body["error"]["code"], "workflow_tool_call_limit_exceeded");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/agent-runs",
        &[
            CLIENT_AUTH,
            JSON_CONTENT,
            "x-ferrogate-agent-run-id: agent-run-harness",
            "x-ferrogate-workflow-id: tool-flow",
            "x-ferrogate-workflow-version: 1",
            "x-ferrogate-workflow-node-id: echo",
        ],
        r#"{"input":"run the bounded harness","max_turns":3,"timeout_millis":1000,"tool_calls":[{"name":"tool.echo","arguments":{"message":"from ferrogate-test"},"session_id":"agent-harness-tool-session"}]}"#,
        201,
        |body| {
            assert_eq!(body["object"], "agent_run");
            assert_eq!(body["id"], "agent-run-harness");
            assert_eq!(body["status"], "completed");
            assert_eq!(body["turns_executed"], 2);
            assert_eq!(body["output"], "run the bounded harness");
            assert_eq!(body["tool_results"].as_array().unwrap().len(), 1);
            assert_eq!(
                body["tool_results"][0]["content"]["echo"]["message"],
                "from ferrogate-test"
            );
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/agent-runs/agent-run-harness",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "agent_run_timeline");
            assert_eq!(body["id"], "agent-run-harness");
            assert_eq!(body["summary"]["request_count"], 0);
            assert_eq!(body["summary"]["audit_event_count"], 7);
            assert_eq!(body["summary"]["agent_event_count"], 6);
            assert_eq!(body["run"]["id"], "agent-run-harness");
            assert_eq!(body["run"]["status"], "completed");
            assert_eq!(body["run"]["provider"], "ferrogate.default");
            assert_eq!(body["agent_events"].as_array().unwrap().len(), 6);
            assert!(body["agent_events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| {
                    event["kind"] == "tool_call_completed"
                        && event["run_id"] == "agent-run-harness"
                        && event["outcome"] == "success"
                }));
            assert!(body["audit_events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| {
                    event["action"] == "tool.execute"
                        && event["target"] == "tool_session:agent-harness-tool-session"
                        && event["outcome"] == "success"
                        && event["agent_run_id"] == "agent-run-harness"
                        && event["workflow_id"] == "tool-flow"
                        && event["workflow_version"] == 1
                        && event["workflow_node_id"] == "echo"
                }));
            assert!(body["audit_events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| {
                    event["action"] == "agent.run_completed"
                        && event["agent_run_id"] == "agent-run-harness"
                        && event["workflow_id"] == "tool-flow"
                        && event["workflow_node_id"] == "echo"
                }));
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/agent-workflows/tool-flow",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "agent_workflow");
            assert_eq!(body["agent_workflow"]["workflow"]["id"], "tool-flow");
            assert_eq!(body["agent_workflow"]["counters"]["request_count"], 0);
            assert_eq!(body["agent_workflow"]["counters"]["billing_event_count"], 0);
            assert_eq!(body["agent_workflow"]["counters"]["audit_event_count"], 7);
            assert_secret_redacted(&body.to_string());
            Ok(())
        },
    )?;
    case.expect_text("GET", "/metrics", &[ADMIN_AUTH], "", 200, |body| {
        assert!(body.contains("ferrogate_request_logs_total"));
        Ok(())
    })?;
    case.expect_mcp_json(
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"ferrogate-test","version":"1.0.0"}}}"#,
        200,
        |body| {
            assert_eq!(body["jsonrpc"], "2.0");
            assert_eq!(body["id"], 1);
            assert_eq!(body["result"]["protocolVersion"], "2025-06-18");
            assert_eq!(body["result"]["serverInfo"]["name"], "ferrogate");
            assert!(body["result"]["instructions"]
                .as_str()
                .is_some_and(|instructions| instructions.contains("governed MCP gateway")));
            Ok(())
        },
    )?;
    case.expect_text(
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
        202,
        |body| {
            assert!(body.is_empty());
            Ok(())
        },
    )?;
    case.expect_mcp_json(
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        200,
        |body| {
            assert_mcp_tool_present(&body, "http-search", "Search the harness MCP upstream")?;
            assert_mcp_tool_present(&body, "stdio-search", "Blocking stdio search")?;
            Ok(())
        },
    )?;
    case.expect_mcp_json(
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"http-search","arguments":{"query":"ferrogate"}}}"#,
        200,
        |body| {
            let content = body["result"]["content"]
                .as_array()
                .with_context(|| format!("MCP tools/call response missing content array: {body}"))?;
            assert_eq!(content[0]["type"], "text");
            assert_eq!(content[0]["text"], "ferrogate-result");
            assert_eq!(body["result"]["isError"], false);
            Ok(())
        },
    )?;
    case.expect_mcp_json(
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"http-write","arguments":{"value":"denied"}}}"#,
        200,
        |body| {
            assert_eq!(body["error"]["code"], -32001);
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("not allowlisted")));
            Ok(())
        },
    )?;
    case.expect_mcp_json(
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"stdio-search","arguments":{"query":"blocked"}}}"#,
        200,
        |body| {
            assert_eq!(body["jsonrpc"], "2.0");
            assert_eq!(body["id"], 5);
            assert_eq!(body["error"]["code"], -32000);
            assert!(body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("timed out after 1 seconds")));
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/mcp-servers",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            let stdio = admin_list_item(&body, "name", "stdio")
                .context("stdio MCP server status missing")?;
            assert_eq!(stdio["transport"], "stdio");
            assert_eq!(stdio["health"], "ok");
            assert_eq!(stdio["connected"], true);
            assert!(stdio["tools"].as_u64().is_some_and(|tools| tools >= 1));
            assert!(stdio["reconnect_attempts"]
                .as_u64()
                .is_some_and(|attempts| attempts >= 1));
            assert!(stdio["last_connected_at_unix"].as_u64().is_some());
            Ok(())
        },
    )?;
    case.expect_mcp_json(
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/list","params":{}}"#,
        200,
        |body| {
            assert_mcp_tool_present(&body, "http-search", "Search the harness MCP upstream")?;
            assert_mcp_tool_present(&body, "stdio-search", "Blocking stdio search")?;
            Ok(())
        },
    )?;
    case.expect_mcp_json(
        "POST",
        "/v1/mcp",
        &[JSON_CONTENT],
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}"#,
        401,
        |body| {
            assert_eq!(body["error"]["code"], "missing_api_key");
            Ok(())
        },
    )?;
    case.expect_openmeter_export()?;
    case.wait_for_metering_export_status()?;
    case.expect_agent_run_otlp_trace_export("agent-run-e2e")?;

    println!("gateway-api scenario passed");
    Ok(())
}

fn run_gateway_external_auth_api(local: &LocalArgs, auth_args: &AuthArgs) -> Result<()> {
    let auth = AuthHarness::start(&auth_args.ferrogate_auth_bin)?;
    let case = LocalHarness::start_with_external_auth(&local.ferrogate_bin, 1, &auth.auth_addr)?;

    case.expect_json("GET", "/v1/models", &[CLIENT_AUTH], "", 200, |body| {
        assert!(list_contains(&body, "id", "fast-chat"));
        Ok(())
    })?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"external auth allow"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            assert_eq!(body["usage"]["total_tokens"], 2);
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"model":"blocked-chat","messages":[{"role":"user","content":"external auth deny"}]}"#,
        403,
        |body| {
            assert_eq!(body["error"]["code"], "rbac_denied");
            Ok(())
        },
    )?;

    println!("gateway-external-auth-api scenario passed");
    Ok(())
}

fn run_gateway_third_party_auth_api(local: &LocalArgs) -> Result<()> {
    let auth = spawn_mock_third_party_auth_server(5)?;
    let case = LocalHarness::start_with_external_auth(&local.ferrogate_bin, 1, &auth.addr)?;

    case.expect_json("GET", "/v1/models", &[CLIENT_AUTH], "", 200, |body| {
        assert!(list_contains(&body, "id", "fast-chat"));
        Ok(())
    })?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"third party allow"}]}"#,
        200,
        |body| {
            assert_eq!(body["object"], "chat.completion");
            Ok(())
        },
    )?;
    case.expect_json(
        "POST",
        "/v1/chat/completions",
        &[CLIENT_AUTH, JSON_CONTENT],
        r#"{"model":"blocked-chat","messages":[{"role":"user","content":"third party deny"}]}"#,
        403,
        |body| {
            assert_eq!(body["error"]["code"], "rbac_denied");
            Ok(())
        },
    )?;

    let requests = auth.join()?;
    assert!(
        requests
            .iter()
            .any(|request| request.contains("POST /v1/auth/resolve-api-key ")),
        "third-party auth mock did not receive resolve-api-key request"
    );
    assert!(
        requests
            .iter()
            .any(|request| request.contains("POST /v1/auth/authorize ")),
        "third-party auth mock did not receive authorize request"
    );

    println!("gateway-third-party-auth-api scenario passed");
    Ok(())
}

fn run_supabase_restart(args: &LocalArgs) -> Result<()> {
    let host_port = free_port()?;
    let cert_dir = tempfile::tempdir()?;
    let certs = write_postgres_tls_certs(cert_dir.path())?;
    let _cleanup = PostgresCleanup;
    stop_postgres_container();
    let cert_mount = format!("{}:/ferrogate-postgres-tls:ro", cert_dir.path().display());
    docker_args([
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        POSTGRES_CONTAINER.to_string(),
        "-e".to_string(),
        "POSTGRES_PASSWORD=postgres".to_string(),
        "-e".to_string(),
        "POSTGRES_DB=ferrogate".to_string(),
        "-p".to_string(),
        format!("127.0.0.1:{host_port}:5432"),
        "-v".to_string(),
        cert_mount,
        "--entrypoint".to_string(),
        "sh".to_string(),
        POSTGRES_IMAGE.to_string(),
        "-c".to_string(),
        r#"set -eu
mkdir -p /var/lib/postgresql/tls
cp /ferrogate-postgres-tls/server.crt /var/lib/postgresql/tls/server.crt
cp /ferrogate-postgres-tls/server.key /var/lib/postgresql/tls/server.key
chown postgres:postgres /var/lib/postgresql/tls/server.crt /var/lib/postgresql/tls/server.key
chmod 600 /var/lib/postgresql/tls/server.key
exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/var/lib/postgresql/tls/server.crt -c ssl_key_file=/var/lib/postgresql/tls/server.key"#
            .to_string(),
    ])?;
    wait_for_postgres_server()?;
    let dsn =
        format!("host=127.0.0.1 port={host_port} user=postgres password=postgres dbname=ferrogate sslmode=require");
    wait_for_postgres_query()?;
    expect_supabase_validate_only_schema_failure(
        &args.ferrogate_bin,
        &dsn,
        PostgresRestartTls {
            mode: "verify_full",
            ca_cert_path: Some(certs.ca_cert_path.as_path()),
        },
    )?;
    run_control_plane_supabase_restart(
        &args.ferrogate_bin,
        &dsn,
        PostgresRestartTls {
            mode: "verify_full",
            ca_cert_path: Some(certs.ca_cert_path.as_path()),
        },
        "ferrogate-supabase-test",
        true,
    )?;
    expect_supabase_schema_migrations("ferrogate_control")?;
    println!("supabase-restart scenario passed");
    Ok(())
}

fn expect_supabase_validate_only_schema_failure(
    ferrogate_bin: &Path,
    supabase_dsn: &str,
    tls: PostgresRestartTls<'_>,
) -> Result<()> {
    let storage = ControlPlaneRestartStorage::Supabase {
        dsn: supabase_dsn,
        tls,
    };
    let gateway_addr = free_addr()?;
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("ferrogate-validate-only.yaml");
    std::fs::write(
        &config_path,
        storage.restart_config(
            &gateway_addr,
            false,
            false,
            StorageMigrationMode::ValidateOnly,
            None,
        ),
    )?;

    let mut gateway = Command::new(ferrogate_bin);
    gateway
        .args(["run", "--config"])
        .arg(&config_path)
        .env("FERROGATE_PROVIDER_SECRET", "provider-secret")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    storage.apply_env(&mut gateway);
    let mut gateway = gateway
        .spawn()
        .with_context(|| format!("failed to start {}", ferrogate_bin.display()))?;

    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(20) {
        if let Some(status) = gateway.try_wait()? {
            if status.success() {
                bail!("validate-only Supabase startup unexpectedly succeeded without schema");
            }
            let mut stderr = String::new();
            if let Some(mut pipe) = gateway.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            assert_secret_redacted(&stderr);
            if !stderr.contains("required schema table control_plane_resources is missing") {
                bail!("validate-only Supabase startup failed with unexpected stderr: {stderr}");
            }
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }

    let _ = gateway.kill();
    bail!("validate-only Supabase startup did not fail before readiness timeout");
}

fn run_supabase_live_restart(args: &SupabaseLiveRestartArgs) -> Result<()> {
    let dsn = args.supabase_dsn.trim();
    if dsn.is_empty() {
        bail!("--supabase-dsn must not be empty");
    }
    run_control_plane_supabase_restart(
        &args.local.ferrogate_bin,
        dsn,
        PostgresRestartTls {
            mode: supabase_live_tls_mode(&args.tls_mode)?,
            ca_cert_path: args.tls_ca_cert_path.as_deref(),
        },
        "ferrogate-supabase-live-test",
        false,
    )?;
    println!("supabase-live-restart scenario passed");
    Ok(())
}

fn run_supabase_live_smoke(args: &SupabaseLiveRestartArgs) -> Result<()> {
    let dsn = args.supabase_dsn.trim();
    if dsn.is_empty() {
        bail!("--supabase-dsn must not be empty");
    }
    let tls = PostgresRestartTls {
        mode: supabase_live_tls_mode(&args.tls_mode)?,
        ca_cert_path: args.tls_ca_cert_path.as_deref(),
    };
    let resource_id = format!(
        "ferrogate-supabase-live-smoke-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before UNIX epoch")?
            .as_millis()
    );
    let api_key_body = serde_json::json!({
        "id": resource_id,
        "name": "Supabase live smoke key",
        "key": format!("{resource_id}-secret"),
        "scopes": ["models.read"],
        "allowed_models": ["fast-chat"],
        "organization_id": "org_supabase_live",
        "project_id": "project_smoke"
    })
    .to_string();
    let storage = ControlPlaneRestartStorage::Supabase { dsn, tls };

    {
        let case = TursoRestartHarness::start(&args.local.ferrogate_bin, storage, false, false)?;
        case.expect_storage_status()?;
        case.expect_json(
            "POST",
            "/admin/v1/api-keys",
            &[ADMIN_AUTH, JSON_CONTENT],
            &api_key_body,
            201,
            |body| {
                assert_eq!(body["key"]["id"], resource_id);
                assert_eq!(body["key"]["key_source"], "inline");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        case.expect_api_key_named(&resource_id, "Supabase live smoke key")?;
    }

    {
        let case = TursoRestartHarness::start_with_migration_mode(
            &args.local.ferrogate_bin,
            storage,
            false,
            false,
            StorageMigrationMode::ValidateOnly,
            None,
        )?;
        case.expect_storage_status()?;
        case.expect_api_key_named(&resource_id, "Supabase live smoke key")?;
        case.expect_json(
            "DELETE",
            &format!("/admin/v1/api-keys/{resource_id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["deleted"], true);
                Ok(())
            },
        )?;
    }

    println!("supabase-live-smoke scenario passed");
    Ok(())
}

fn run_supabase_live_token4ai_provider(args: &SupabaseLiveToken4aiProviderArgs) -> Result<()> {
    let dsn = args.supabase.supabase_dsn.trim();
    if dsn.is_empty() {
        bail!("--supabase-dsn must not be empty");
    }
    let provider_api_key = args.provider_api_key.trim();
    if provider_api_key.is_empty() {
        bail!("--provider-api-key must not be empty");
    }
    let provider_base_url = args.provider_base_url.trim();
    if provider_base_url.is_empty() {
        bail!("--provider-base-url must not be empty");
    }
    let provider_model = args.provider_model.trim();
    if provider_model.is_empty() {
        bail!("--provider-model must not be empty");
    }

    let tls = PostgresRestartTls {
        mode: supabase_live_tls_mode(&args.supabase.tls_mode)?,
        ca_cert_path: args.supabase.tls_ca_cert_path.as_deref(),
    };
    let resource_id = format!(
        "ferrogate-token4ai-live-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before UNIX epoch")?
            .as_millis()
    );
    let storage = ControlPlaneRestartStorage::Supabase { dsn, tls };

    {
        let case = TursoRestartHarness::start_live_token4ai_provider(
            &args.supabase.local.ferrogate_bin,
            storage,
            provider_base_url,
            provider_model,
            provider_api_key,
        )?;
        case.expect_storage_status()?;
        case.expect_live_token4ai_completion(&resource_id, provider_model)?;
        case.expect_live_token4ai_metering_usage(&resource_id, provider_model)?;
    }

    {
        let case = TursoRestartHarness::start_live_token4ai_provider_with_migration_mode(
            &args.supabase.local.ferrogate_bin,
            storage,
            provider_base_url,
            provider_model,
            provider_api_key,
            StorageMigrationMode::ValidateOnly,
        )?;
        case.expect_storage_status()?;
        case.expect_live_token4ai_metering_usage(&resource_id, provider_model)?;
    }

    println!("supabase-live-token4ai-provider scenario passed");
    Ok(())
}

fn run_supabase_migration(args: &LocalArgs) -> Result<()> {
    let source_port = free_port()?;
    let target_port = free_port()?;
    let source_cert_dir = tempfile::tempdir()?;
    let target_cert_dir = tempfile::tempdir()?;
    write_postgres_tls_certs(source_cert_dir.path())?;
    write_postgres_tls_certs(target_cert_dir.path())?;
    let _cleanup = PostgresMigrationCleanup;
    stop_postgres_container_named(POSTGRES_MIGRATION_SOURCE_CONTAINER);
    stop_postgres_container_named(POSTGRES_MIGRATION_TARGET_CONTAINER);
    start_postgres_tls_container(
        POSTGRES_MIGRATION_SOURCE_CONTAINER,
        source_port,
        source_cert_dir.path(),
    )?;
    start_postgres_tls_container(
        POSTGRES_MIGRATION_TARGET_CONTAINER,
        target_port,
        target_cert_dir.path(),
    )?;
    wait_for_postgres_server_named(POSTGRES_MIGRATION_SOURCE_CONTAINER)?;
    wait_for_postgres_server_named(POSTGRES_MIGRATION_TARGET_CONTAINER)?;
    wait_for_postgres_query_named(POSTGRES_MIGRATION_SOURCE_CONTAINER)?;
    wait_for_postgres_query_named(POSTGRES_MIGRATION_TARGET_CONTAINER)?;

    let source_dsn =
        format!("host=127.0.0.1 port={source_port} user=postgres password=postgres dbname=ferrogate sslmode=require");
    let target_dsn =
        format!("host=127.0.0.1 port={target_port} user=postgres password=postgres dbname=ferrogate sslmode=require");
    let resource_id = format!(
        "ferrogate-migration-test-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before UNIX epoch")?
            .as_millis()
    );
    let api_key_body = serde_json::json!({
        "id": resource_id,
        "name": "Supabase migration test key",
        "key": format!("{resource_id}-secret"),
        "scopes": ["models.read"],
        "allowed_models": ["fast-chat"],
        "organization_id": "org_migration",
        "project_id": "project_migration"
    })
    .to_string();

    {
        let source = TursoRestartHarness::start(
            &args.ferrogate_bin,
            ControlPlaneRestartStorage::Postgres {
                dsn: &source_dsn,
                tls: PostgresRestartTls {
                    mode: "require",
                    ca_cert_path: None,
                },
            },
            false,
            true,
        )?;
        source.expect_storage_status()?;
        source.expect_json(
            "POST",
            "/admin/v1/api-keys",
            &[ADMIN_AUTH, JSON_CONTENT],
            &api_key_body,
            201,
            |body| {
                assert_eq!(body["key"]["id"], resource_id);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        source.expect_api_key_named(&resource_id, "Supabase migration test key")?;
    }

    let dry_run = Command::new(&args.ferrogate_bin)
        .args([
            "storage",
            "migrate-to-supabase",
            "--source-provider",
            "postgres",
            "--source-postgres-dsn-env",
            "FERROGATE_TEST_SOURCE_DSN",
            "--target-supabase-dsn-env",
            "FERROGATE_TEST_TARGET_DSN",
            "--postgres-schema",
            "ferrogate_control",
            "--postgres-tls-mode",
            "require",
            "--dry-run",
        ])
        .env("FERROGATE_TEST_SOURCE_DSN", &source_dsn)
        .env("FERROGATE_TEST_TARGET_DSN", &target_dsn)
        .output()
        .context("run storage migration dry-run")?;
    assert!(
        dry_run.status.success(),
        "dry-run stderr: {}",
        String::from_utf8_lossy(&dry_run.stderr)
    );
    let dry_run_stdout = String::from_utf8_lossy(&dry_run.stdout);
    assert!(dry_run_stdout.contains("FerroGate storage migration dry-run"));
    assert!(dry_run_stdout.contains("target=supabase"));
    assert!(dry_run_stdout.contains("api_keys=2"));
    assert!(!dry_run_stdout.contains("password=postgres"));
    assert!(!String::from_utf8_lossy(&dry_run.stderr).contains("password=postgres"));

    let execute = Command::new(&args.ferrogate_bin)
        .args([
            "storage",
            "migrate-to-supabase",
            "--source-provider",
            "postgres",
            "--source-postgres-dsn-env",
            "FERROGATE_TEST_SOURCE_DSN",
            "--target-supabase-dsn-env",
            "FERROGATE_TEST_TARGET_DSN",
            "--postgres-schema",
            "ferrogate_control",
            "--postgres-tls-mode",
            "require",
            "--execute",
        ])
        .env("FERROGATE_TEST_SOURCE_DSN", &source_dsn)
        .env("FERROGATE_TEST_TARGET_DSN", &target_dsn)
        .output()
        .context("run storage migration execute")?;
    assert!(
        execute.status.success(),
        "execute stderr: {}",
        String::from_utf8_lossy(&execute.stderr)
    );
    let execute_stdout = String::from_utf8_lossy(&execute.stdout);
    assert!(execute_stdout.contains("FerroGate storage migration executed"));
    assert!(execute_stdout.contains("api_keys=2"));
    assert!(!execute_stdout.contains("password=postgres"));
    assert!(!String::from_utf8_lossy(&execute.stderr).contains("password=postgres"));

    {
        let target = TursoRestartHarness::start_with_migration_mode(
            &args.ferrogate_bin,
            ControlPlaneRestartStorage::Supabase {
                dsn: &target_dsn,
                tls: PostgresRestartTls {
                    mode: "require",
                    ca_cert_path: None,
                },
            },
            false,
            false,
            StorageMigrationMode::ValidateOnly,
            None,
        )?;
        target.expect_storage_status()?;
        target.expect_api_key_named(&resource_id, "Supabase migration test key")?;
    }

    println!("supabase-migration scenario passed");
    Ok(())
}

fn supabase_live_tls_mode(mode: &str) -> Result<&'static str> {
    match mode.trim() {
        "require" => Ok("require"),
        "verify_ca" | "verify-ca" => Ok("verify_ca"),
        "verify_full" | "verify-full" => Ok("verify_full"),
        other => bail!(
            "--tls-mode must be require, verify_ca, or verify_full for live Supabase, got {other}"
        ),
    }
}

fn run_postgres_restart(args: &LocalArgs) -> Result<()> {
    let host_port = free_port()?;
    let _cleanup = PostgresCleanup;
    stop_postgres_container();
    start_postgres_container(POSTGRES_CONTAINER, host_port)?;
    wait_for_postgres_server()?;
    let dsn =
        format!("host=127.0.0.1 port={host_port} user=postgres password=postgres dbname=ferrogate sslmode=disable");
    wait_for_postgres_query()?;
    run_control_plane_postgres_restart(
        &args.ferrogate_bin,
        &dsn,
        PostgresRestartTls {
            mode: "disable",
            ca_cert_path: None,
        },
        "ferrogate-postgres-test",
        true,
    )?;
    println!("postgres-restart scenario passed");
    Ok(())
}

fn start_postgres_container(name: &str, host_port: u16) -> Result<()> {
    docker_args([
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        name.to_string(),
        "-e".to_string(),
        "POSTGRES_PASSWORD=postgres".to_string(),
        "-e".to_string(),
        "POSTGRES_DB=ferrogate".to_string(),
        "-p".to_string(),
        format!("127.0.0.1:{host_port}:5432"),
        POSTGRES_IMAGE.to_string(),
    ])
}

fn start_postgres_tls_container(name: &str, host_port: u16, cert_dir: &Path) -> Result<()> {
    let cert_mount = format!("{}:/ferrogate-postgres-tls:ro", cert_dir.display());
    docker_args([
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        name.to_string(),
        "-e".to_string(),
        "POSTGRES_PASSWORD=postgres".to_string(),
        "-e".to_string(),
        "POSTGRES_DB=ferrogate".to_string(),
        "-p".to_string(),
        format!("127.0.0.1:{host_port}:5432"),
        "-v".to_string(),
        cert_mount,
        "--entrypoint".to_string(),
        "sh".to_string(),
        POSTGRES_IMAGE.to_string(),
        "-c".to_string(),
        r#"set -eu
mkdir -p /var/lib/postgresql/tls
cp /ferrogate-postgres-tls/server.crt /var/lib/postgresql/tls/server.crt
cp /ferrogate-postgres-tls/server.key /var/lib/postgresql/tls/server.key
chown postgres:postgres /var/lib/postgresql/tls/server.crt /var/lib/postgresql/tls/server.key
chmod 600 /var/lib/postgresql/tls/server.key
exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/var/lib/postgresql/tls/server.crt -c ssl_key_file=/var/lib/postgresql/tls/server.key"#
            .to_string(),
    ])
}

fn run_postgres_tls_restart(args: &LocalArgs) -> Result<()> {
    let host_port = free_port()?;
    let cert_dir = tempfile::tempdir()?;
    let certs = write_postgres_tls_certs(cert_dir.path())?;
    let _cleanup = PostgresCleanup;
    stop_postgres_container();
    let cert_mount = format!("{}:/ferrogate-postgres-tls:ro", cert_dir.path().display());
    docker_args([
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        POSTGRES_CONTAINER.to_string(),
        "-e".to_string(),
        "POSTGRES_PASSWORD=postgres".to_string(),
        "-e".to_string(),
        "POSTGRES_DB=ferrogate".to_string(),
        "-p".to_string(),
        format!("127.0.0.1:{host_port}:5432"),
        "-v".to_string(),
        cert_mount,
        "--entrypoint".to_string(),
        "sh".to_string(),
        POSTGRES_IMAGE.to_string(),
        "-c".to_string(),
        r#"set -eu
mkdir -p /var/lib/postgresql/tls
cp /ferrogate-postgres-tls/server.crt /var/lib/postgresql/tls/server.crt
cp /ferrogate-postgres-tls/server.key /var/lib/postgresql/tls/server.key
chown postgres:postgres /var/lib/postgresql/tls/server.crt /var/lib/postgresql/tls/server.key
chmod 600 /var/lib/postgresql/tls/server.key
exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/var/lib/postgresql/tls/server.crt -c ssl_key_file=/var/lib/postgresql/tls/server.key"#
            .to_string(),
    ])?;
    wait_for_postgres_server()?;
    let dsn =
        format!("host=127.0.0.1 port={host_port} user=postgres password=postgres dbname=ferrogate sslmode=require");
    wait_for_postgres_query()?;
    run_control_plane_postgres_restart(
        &args.ferrogate_bin,
        &dsn,
        PostgresRestartTls {
            mode: "verify_full",
            ca_cert_path: Some(certs.ca_cert_path.as_path()),
        },
        "ferrogate-postgres-tls-test",
        true,
    )?;
    println!("postgres-tls-restart scenario passed");
    Ok(())
}

fn run_mysql_restart(args: &LocalArgs) -> Result<()> {
    let host_port = free_port()?;
    let _cleanup = MySqlCleanup;
    start_mysql_container(host_port)?;
    let dsn = format!("mysql://root:mysql@127.0.0.1:{host_port}/ferrogate?prefer_socket=false");
    run_control_plane_mysql_restart(
        &args.ferrogate_bin,
        &dsn,
        MySqlRestartTls {
            mode: "disable",
            ca_cert_path: None,
        },
        "ferrogate-mysql-test",
        true,
    )?;
    println!("mysql-restart scenario passed");
    Ok(())
}

fn run_mysql_tls_restart(args: &LocalArgs) -> Result<()> {
    let host_port = free_port()?;
    let ca_dir = tempfile::tempdir()?;
    let ca_cert_path = ca_dir.path().join("mysql-ca.pem");
    let _cleanup = MySqlCleanup;
    start_mysql_container(host_port)?;
    docker_args([
        "cp".to_string(),
        format!("{MYSQL_CONTAINER}:/var/lib/mysql/ca.pem"),
        ca_cert_path.display().to_string(),
    ])?;
    let dsn = format!("mysql://root:mysql@127.0.0.1:{host_port}/ferrogate?prefer_socket=false");
    run_control_plane_mysql_restart(
        &args.ferrogate_bin,
        &dsn,
        MySqlRestartTls {
            mode: "verify_ca",
            ca_cert_path: Some(ca_cert_path.as_path()),
        },
        "ferrogate-mysql-tls-test",
        true,
    )?;
    println!("mysql-tls-restart scenario passed");
    Ok(())
}

fn start_mysql_container(host_port: u16) -> Result<()> {
    stop_mysql_container();
    docker_args([
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        MYSQL_CONTAINER.to_string(),
        "-e".to_string(),
        "MYSQL_ROOT_PASSWORD=mysql".to_string(),
        "-e".to_string(),
        "MYSQL_DATABASE=ferrogate".to_string(),
        "-p".to_string(),
        format!("127.0.0.1:{host_port}:3306"),
        MYSQL_IMAGE.to_string(),
    ])?;
    wait_for_mysql_server()
}

struct PostgresTlsFiles {
    ca_cert_path: PathBuf,
}

fn write_postgres_tls_certs(dir: &Path) -> Result<PostgresTlsFiles> {
    let ca_key = KeyPair::generate().context("failed to generate PostgreSQL test CA key")?;
    let mut ca_params = CertificateParams::new(vec!["ferrogate-postgres-test-ca".to_string()])
        .context("failed to build PostgreSQL test CA params")?;
    let mut ca_name = DistinguishedName::new();
    ca_name.push(DnType::CommonName, "ferrogate-postgres-test-ca");
    ca_params.distinguished_name = ca_name;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key)
        .context("failed to self-sign PostgreSQL test CA")?;

    let server_key =
        KeyPair::generate().context("failed to generate PostgreSQL test server key")?;
    let server_params = CertificateParams::new(vec!["127.0.0.1".to_string()])
        .context("failed to build PostgreSQL test server params")?;
    let mut server_params = server_params;
    let mut server_name = DistinguishedName::new();
    server_name.push(DnType::CommonName, "127.0.0.1");
    server_params.distinguished_name = server_name;
    let server_cert = server_params
        .signed_by(&server_key, &ca)
        .context("failed to sign PostgreSQL test server certificate")?;

    let ca_cert_path = dir.join("ca.crt");
    fs::write(&ca_cert_path, ca.pem()).context("failed to write PostgreSQL test CA cert")?;
    fs::write(dir.join("server.crt"), server_cert.pem())
        .context("failed to write PostgreSQL test server cert")?;
    fs::write(dir.join("server.key"), server_key.serialize_pem())
        .context("failed to write PostgreSQL test server key")?;

    Ok(PostgresTlsFiles { ca_cert_path })
}

fn run_control_plane_postgres_restart(
    ferrogate_bin: &Path,
    postgres_dsn: &str,
    tls: PostgresRestartTls<'_>,
    resource_prefix: &str,
    verify_deleted_after_restart: bool,
) -> Result<()> {
    run_control_plane_restart(
        ferrogate_bin,
        ControlPlaneRestartStorage::Postgres {
            dsn: postgres_dsn,
            tls,
        },
        resource_prefix,
        verify_deleted_after_restart,
    )
}

fn run_control_plane_supabase_restart(
    ferrogate_bin: &Path,
    supabase_dsn: &str,
    tls: PostgresRestartTls<'_>,
    resource_prefix: &str,
    verify_deleted_after_restart: bool,
) -> Result<()> {
    run_control_plane_restart(
        ferrogate_bin,
        ControlPlaneRestartStorage::Supabase {
            dsn: supabase_dsn,
            tls,
        },
        resource_prefix,
        verify_deleted_after_restart,
    )
}

fn run_control_plane_mysql_restart(
    ferrogate_bin: &Path,
    mysql_dsn: &str,
    tls: MySqlRestartTls<'_>,
    resource_prefix: &str,
    verify_deleted_after_restart: bool,
) -> Result<()> {
    run_control_plane_restart(
        ferrogate_bin,
        ControlPlaneRestartStorage::Mysql {
            dsn: mysql_dsn,
            tls,
        },
        resource_prefix,
        verify_deleted_after_restart,
    )
}

#[derive(Clone, Copy)]
struct MySqlRestartTls<'a> {
    mode: &'a str,
    ca_cert_path: Option<&'a Path>,
}

#[derive(Clone, Copy)]
struct PostgresRestartTls<'a> {
    mode: &'a str,
    ca_cert_path: Option<&'a Path>,
}

#[derive(Clone, Copy)]
enum ControlPlaneRestartStorage<'a> {
    Postgres {
        dsn: &'a str,
        tls: PostgresRestartTls<'a>,
    },
    Supabase {
        dsn: &'a str,
        tls: PostgresRestartTls<'a>,
    },
    Mysql {
        dsn: &'a str,
        tls: MySqlRestartTls<'a>,
    },
}

impl ControlPlaneRestartStorage<'_> {
    fn supports_durable_metering(self) -> bool {
        matches!(
            self,
            ControlPlaneRestartStorage::Postgres { .. }
                | ControlPlaneRestartStorage::Supabase { .. }
        )
    }
}

fn run_control_plane_restart(
    ferrogate_bin: &Path,
    storage: ControlPlaneRestartStorage<'_>,
    resource_prefix: &str,
    verify_deleted_after_restart: bool,
) -> Result<()> {
    let resource_id = format!(
        "{resource_prefix}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before UNIX epoch")?
            .as_millis()
    );
    let api_key_body = serde_json::json!({
        "id": resource_id,
        "name": "Durable storage restart test key",
        "key": format!("{resource_id}-secret"),
        "scopes": ["models.read", "chat.completions", "prompts.render"],
        "allowed_models": ["fast-chat"],
        "organization_id": "org_storage_e2e",
        "project_id": "project_restart"
    })
    .to_string();
    let gateway_config_id = format!("{resource_id}-profile");
    let gateway_config_body = serde_json::json!({
        "id": gateway_config_id,
        "name": "Durable storage restart profile",
        "revision": 7,
        "api_key_ids": [resource_id],
        "cache_enabled": false
    })
    .to_string();
    let policy_name = format!("{resource_id}-policy");
    let policy_body = |enabled: bool| {
        serde_json::json!({
            "name": policy_name,
            "effect": "deny",
            "api_key_ids": [resource_id],
            "models": ["fast-chat"],
            "providers": ["openai"],
            "code": "blocked_by_storage_restart_test",
            "message": "blocked by durable storage restart test",
            "enabled": enabled
        })
        .to_string()
    };
    let disabled_policy_body = policy_body(false);
    let enabled_policy_body = policy_body(true);
    let prompt_template_id = format!("{resource_id}-prompt");
    let prompt_template_body = serde_json::json!({
        "id": prompt_template_id,
        "name": "Durable storage restart prompt",
        "model": "fast-chat",
        "variables": [{"name": "topic", "required": true}],
        "version": {
            "messages": [{"role": "user", "content": "Summarize {{topic}}"}],
            "temperature": 0.1
        }
    })
    .to_string();
    let agent_upstream_id = format!("{resource_id}-agent-upstream");
    let agent_upstream_body = serde_json::json!({
        "id": agent_upstream_id,
        "name": "Durable storage restart agent upstream",
        "description": "Durable upstream",
        "enabled": true,
        "protocol": "a2a",
        "endpoint": "https://agent.example.com/a2a",
        "tenant_ids": [resource_id],
        "capabilities": ["invoke", "read", "stream", "discover"]
    })
    .to_string();

    let approval_id;
    let mcp_server_name = format!(
        "dbhttp{}",
        resource_id
            .chars()
            .filter(char::is_ascii_digit)
            .collect::<String>()
    );
    {
        let case = TursoRestartHarness::start(ferrogate_bin, storage, false, true)?;
        case.expect_storage_status()?;
        case.register_echo_plugin()?;
        case.expect_plugin("tool.echo")?;
        approval_id = case.create_expired_echo_approval()?;
        case.register_echo_plugin()?;
        case.expect_echo_tool()?;
        case.register_mcp_server(&mcp_server_name)?;
        case.expect_mcp_server(&mcp_server_name)?;
        case.expect_json(
            "POST",
            "/admin/v1/api-keys",
            &[ADMIN_AUTH, JSON_CONTENT],
            &api_key_body,
            201,
            |body| {
                assert_eq!(body["key"]["id"], resource_id);
                assert_eq!(body["key"]["key_source"], "inline");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        case.expect_api_key(&resource_id)?;
        case.expect_json(
            "POST",
            "/admin/v1/gateway-configs",
            &[ADMIN_AUTH, JSON_CONTENT],
            &gateway_config_body,
            201,
            |body| {
                assert_eq!(body["gateway_config"]["id"], gateway_config_id);
                assert_eq!(body["gateway_config"]["revision"], 7);
                assert_eq!(body["gateway_config"]["cache_enabled"], false);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        case.expect_gateway_config(&gateway_config_id)?;
        case.expect_json(
            "POST",
            "/admin/v1/policies",
            &[ADMIN_AUTH, JSON_CONTENT],
            &disabled_policy_body,
            201,
            |body| {
                assert_eq!(body["policy"]["name"], policy_name);
                assert_eq!(body["policy"]["enabled"], false);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        case.expect_policy(&policy_name)?;
        case.expect_json(
            "POST",
            "/admin/v1/prompt-templates",
            &[ADMIN_AUTH, JSON_CONTENT],
            &prompt_template_body,
            201,
            |body| {
                assert_eq!(body["prompt_template"]["id"], prompt_template_id);
                assert_eq!(body["prompt_template"]["active_revision"], 1);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        case.expect_prompt_template(&prompt_template_id, "active")?;
        case.expect_json(
            "POST",
            "/admin/v1/agent-upstreams",
            &[ADMIN_AUTH, JSON_CONTENT],
            &agent_upstream_body,
            201,
            |body| {
                assert_eq!(body["agent_upstream"]["id"], agent_upstream_id);
                assert_eq!(body["agent_upstream"]["protocol"], "a2a");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        case.expect_agent_upstream(&agent_upstream_id, true)?;
    }

    {
        let (provider_addr, provider) =
            spawn_local_provider_upstream(1).context("start durable metering provider")?;
        let provider_base_url = format!("http://{provider_addr}/v1");
        let case = TursoRestartHarness::start_with_migration_mode(
            ferrogate_bin,
            storage,
            false,
            false,
            StorageMigrationMode::ValidateOnly,
            Some(&provider_base_url),
        )?;
        case.expect_storage_status()?;
        case.expect_plugin("tool.echo")?;
        case.expect_mcp_server(&mcp_server_name)?;
        case.expect_echo_tool()?;
        case.expect_tool_approval(&approval_id, "expired")?;
        case.expect_api_key(&resource_id)?;
        case.expect_gateway_config(&gateway_config_id)?;
        case.expect_policy(&policy_name)?;
        case.expect_prompt_template(&prompt_template_id, "active")?;
        case.expect_agent_upstream(&agent_upstream_id, true)?;
        case.expect_restored_prompt_template_render(&resource_id, &prompt_template_id)?;
        case.expect_restored_api_key_models_access(&resource_id)?;
        case.expect_metered_chat_completion(&resource_id, &gateway_config_id)?;
        let provider_requests = provider.join().unwrap_or_default();
        if !provider_requests
            .iter()
            .any(|request| request.contains("POST /v1/chat/completions "))
        {
            bail!("durable metering provider did not receive chat completion request");
        }
        if storage.supports_durable_metering() {
            case.expect_durable_metering_usage(&resource_id, 2)?;
            case.expect_durable_request_and_audit_evidence(&resource_id)?;
        }
        case.expect_json(
            "PATCH",
            &format!("/admin/v1/policies/{policy_name}"),
            &[ADMIN_AUTH, JSON_CONTENT],
            &enabled_policy_body,
            200,
            |body| {
                assert_eq!(body["policy"]["name"], policy_name);
                assert_eq!(body["policy"]["enabled"], true);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        case.expect_restored_policy_denies_chat(&resource_id)?;
        case.delete_mcp_server(&mcp_server_name)?;
        case.expect_json(
            "DELETE",
            &format!("/admin/v1/gateway-configs/{gateway_config_id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["deleted"], true);
                Ok(())
            },
        )?;
        case.expect_json(
            "DELETE",
            &format!("/admin/v1/policies/{policy_name}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["deleted"], true);
                Ok(())
            },
        )?;
        case.expect_json(
            "DELETE",
            &format!("/admin/v1/api-keys/{resource_id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["deleted"], true);
                Ok(())
            },
        )?;
        case.expect_json(
            "DELETE",
            &format!("/admin/v1/prompt-templates/{prompt_template_id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["deleted"], false);
                Ok(())
            },
        )?;
        case.expect_json(
            "DELETE",
            &format!("/admin/v1/agent-upstreams/{agent_upstream_id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["deleted"], true);
                Ok(())
            },
        )?;
    }

    {
        let case = TursoRestartHarness::start_with_migration_mode(
            ferrogate_bin,
            storage,
            false,
            false,
            StorageMigrationMode::ValidateOnly,
            None,
        )?;
        case.expect_storage_status()?;
        case.expect_plugin("tool.echo")?;
        case.expect_missing_mcp_server(&mcp_server_name)?;
        case.expect_tool_approval(&approval_id, "expired")?;
        if verify_deleted_after_restart {
            case.expect_missing_api_key(&resource_id)?;
            case.expect_missing_gateway_config(&gateway_config_id)?;
            case.expect_missing_policy(&policy_name)?;
        }
        if storage.supports_durable_metering() {
            case.expect_durable_metering_usage(&resource_id, 2)?;
            case.expect_durable_request_and_audit_evidence(&resource_id)?;
        }
        case.expect_prompt_template(&prompt_template_id, "archived")?;
        case.expect_missing_agent_upstream(&agent_upstream_id)?;
    }

    Ok(())
}

const ADMIN_AUTH: &str = "Authorization: Bearer admin-secret";
const CLIENT_AUTH: &str = "Authorization: Bearer client-secret";
const OBSERVER_AUTH: &str = "Authorization: Bearer observer-secret";
const AUTH_TEST_CLIENT_2: &str = "Authorization: Bearer test-secret-2";
const JSON_CONTENT: &str = "Content-Type: application/json";
const SUPPORT_SKILL_HEADER: &str = "x-ferrogate-skill-package: support-skill";

struct LocalHarness {
    _dir: tempfile::TempDir,
    gateway_addr: String,
    gateway: Child,
    provider: Option<JoinHandle<Vec<String>>>,
    mcp_server: Option<JoinHandle<Vec<String>>>,
    agent_server: Option<JoinHandle<Vec<String>>>,
    agent_addr: Option<String>,
    billing: Option<MockBillingServer>,
    observability: Option<MockOtlpServer>,
}

struct MockBillingServer {
    addr: String,
    received: mpsc::Receiver<String>,
    handle: Option<JoinHandle<()>>,
}

struct MockOtlpServer {
    addr: String,
    received: mpsc::Receiver<String>,
    handle: Option<JoinHandle<()>>,
}

struct MockThirdPartyAuthServer {
    addr: String,
    handle: Option<JoinHandle<Vec<String>>>,
}

struct AuthHarness {
    _dir: tempfile::TempDir,
    auth_addr: String,
    auth: Child,
}

struct TursoRestartHarness {
    _dir: tempfile::TempDir,
    gateway_addr: String,
    gateway: Child,
    stderr: Option<std::process::ChildStderr>,
    expected_storage_provider: &'static str,
    expected_migration_mode: StorageMigrationMode,
}

#[derive(Clone, Copy)]
enum StorageMigrationMode {
    Auto,
    ValidateOnly,
}

impl StorageMigrationMode {
    fn as_str(self) -> &'static str {
        match self {
            StorageMigrationMode::Auto => "auto",
            StorageMigrationMode::ValidateOnly => "validate_only",
        }
    }
}

impl AuthHarness {
    fn start(ferrogate_auth_bin: &Path) -> Result<Self> {
        if !ferrogate_auth_bin.exists() {
            bail!(
                "ferrogate-auth binary does not exist at {}; run `cargo build -p ferrogate-auth` first or pass --ferrogate-auth-bin",
                ferrogate_auth_bin.display()
            );
        }

        let auth_addr = free_addr()?;
        let dir = tempfile::tempdir()?;
        let config_path = dir.path().join("auth-service.yaml");
        std::fs::write(&config_path, auth_service_config())?;

        let auth = Command::new(ferrogate_auth_bin)
            .args(["serve", "--listen"])
            .arg(&auth_addr)
            .args(["--data"])
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("failed to start {}", ferrogate_auth_bin.display()))?;

        let mut harness = Self {
            _dir: dir,
            auth_addr,
            auth,
        };
        harness.wait_for_auth()?;
        Ok(harness)
    }

    fn wait_for_auth(&mut self) -> Result<()> {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < Duration::from_secs(20) {
            if let Some(status) = self.auth.try_wait()? {
                bail!("ferrogate-auth process exited before readiness check: {status}");
            }
            match http_request_addr(&self.auth_addr, "GET", "/healthz", &[], "") {
                Ok(response) if response.status == 200 => return Ok(()),
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!(
            "timed out waiting for ferrogate-auth on {}; last response: {last}",
            self.auth_addr
        );
    }

    fn expect_json<F>(
        &self,
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
        let response = http_request_addr(&self.auth_addr, method, path, headers, body)?;
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
}

impl Drop for AuthHarness {
    fn drop(&mut self) {
        let _ = self.auth.kill();
        let _ = self.auth.wait();
    }
}

impl TursoRestartHarness {
    fn start(
        ferrogate_bin: &Path,
        storage: ControlPlaneRestartStorage<'_>,
        include_plugins: bool,
        include_mcp_server: bool,
    ) -> Result<Self> {
        Self::start_with_migration_mode(
            ferrogate_bin,
            storage,
            include_plugins,
            include_mcp_server,
            StorageMigrationMode::Auto,
            None,
        )
    }

    fn start_with_migration_mode(
        ferrogate_bin: &Path,
        storage: ControlPlaneRestartStorage<'_>,
        include_plugins: bool,
        include_mcp_server: bool,
        migration_mode: StorageMigrationMode,
        provider_base_url: Option<&str>,
    ) -> Result<Self> {
        if !ferrogate_bin.exists() {
            bail!(
                "ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli` first or pass --ferrogate-bin",
                ferrogate_bin.display()
            );
        }

        let gateway_addr = free_addr()?;
        let dir = tempfile::tempdir()?;
        let config_path = dir.path().join("ferrogate.yaml");
        std::fs::write(
            &config_path,
            storage.restart_config(
                &gateway_addr,
                include_plugins,
                include_mcp_server,
                migration_mode,
                provider_base_url,
            ),
        )?;

        let mut command = Command::new(ferrogate_bin);
        command
            .args(["run", "--config"])
            .arg(&config_path)
            .env("FERROGATE_PROVIDER_SECRET", "provider-secret")
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        if env::var("FERROGATE_TEST_DEBUG_STDERR").is_ok_and(|value| value == "1") {
            command.stderr(Stdio::inherit());
        } else {
            command.stderr(Stdio::piped());
        }
        storage.apply_env(&mut command);
        let gateway = command
            .spawn()
            .with_context(|| format!("failed to start {}", ferrogate_bin.display()))?;

        let mut harness = Self {
            _dir: dir,
            gateway_addr,
            gateway,
            stderr: None,
            expected_storage_provider: storage.provider_name(),
            expected_migration_mode: migration_mode,
        };
        harness.stderr = harness.gateway.stderr.take();
        harness.wait_for_gateway()?;
        Ok(harness)
    }

    fn start_live_token4ai_provider(
        ferrogate_bin: &Path,
        storage: ControlPlaneRestartStorage<'_>,
        provider_base_url: &str,
        provider_model: &str,
        provider_api_key: &str,
    ) -> Result<Self> {
        Self::start_live_token4ai_provider_with_migration_mode(
            ferrogate_bin,
            storage,
            provider_base_url,
            provider_model,
            provider_api_key,
            StorageMigrationMode::Auto,
        )
    }

    fn start_live_token4ai_provider_with_migration_mode(
        ferrogate_bin: &Path,
        storage: ControlPlaneRestartStorage<'_>,
        provider_base_url: &str,
        provider_model: &str,
        provider_api_key: &str,
        migration_mode: StorageMigrationMode,
    ) -> Result<Self> {
        if !ferrogate_bin.exists() {
            bail!(
                "ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli` first or pass --ferrogate-bin",
                ferrogate_bin.display()
            );
        }

        let gateway_addr = free_addr()?;
        let dir = tempfile::tempdir()?;
        let config_path = dir.path().join("ferrogate-token4ai-live.yaml");
        std::fs::write(
            &config_path,
            storage.live_token4ai_provider_config(
                &gateway_addr,
                provider_base_url,
                provider_model,
                migration_mode,
            ),
        )?;

        let mut command = Command::new(ferrogate_bin);
        command
            .args(["run", "--config"])
            .arg(&config_path)
            .env("FERROGATE_PROVIDER_SECRET", provider_api_key)
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        if env::var("FERROGATE_TEST_DEBUG_STDERR").is_ok_and(|value| value == "1") {
            command.stderr(Stdio::inherit());
        } else {
            command.stderr(Stdio::piped());
        }
        storage.apply_env(&mut command);
        let gateway = command
            .spawn()
            .with_context(|| format!("failed to start {}", ferrogate_bin.display()))?;

        let mut harness = Self {
            _dir: dir,
            gateway_addr,
            gateway,
            stderr: None,
            expected_storage_provider: storage.provider_name(),
            expected_migration_mode: migration_mode,
        };
        harness.stderr = harness.gateway.stderr.take();
        harness.wait_for_gateway()?;
        Ok(harness)
    }

    fn wait_for_gateway(&mut self) -> Result<()> {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < Duration::from_secs(60) {
            if let Some(status) = self.gateway.try_wait()? {
                let stderr = self.read_stderr();
                assert_secret_redacted(&stderr);
                bail!(
                    "ferrogate process exited before readiness check: {status}; stderr: {stderr}"
                );
            }
            match http_request_addr(&self.gateway_addr, "GET", "/healthz", &[], "") {
                Ok(response) if response.status == 200 => return Ok(()),
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(250));
        }
        bail!(
            "timed out waiting for durable-storage FerroGate on {}; last response: {last}",
            self.gateway_addr
        );
    }

    fn read_stderr(&mut self) -> String {
        let Some(mut stderr) = self.stderr.take() else {
            return String::new();
        };
        let mut output = String::new();
        let _ = stderr.read_to_string(&mut output);
        output
    }

    fn expect_json<F>(
        &self,
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
        let response = http_request_addr(&self.gateway_addr, method, path, headers, body)
            .with_context(|| format!("failed HTTP request {method} {path}"))?;
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

    fn expect_storage_status(&self) -> Result<()> {
        self.expect_json("GET", "/admin/v1/status", &[ADMIN_AUTH], "", 200, |body| {
            assert_eq!(body["storage"]["provider"], self.expected_storage_provider);
            assert_eq!(body["storage"]["durable"], true);
            assert_eq!(body["storage"]["implemented"], true);
            assert_eq!(body["storage"]["required"], true);
            assert_eq!(
                body["storage"]["migration_mode"],
                self.expected_migration_mode.as_str()
            );
            assert_eq!(body["storage"]["health"], "ok");
            assert_eq!(body["storage"]["provider_order"][0], "supabase");
            assert_eq!(body["storage"]["provider_order"][1], "postgres");
            assert_eq!(body["storage"]["provider_order"][2], "mysql");
            if matches!(self.expected_storage_provider, "supabase" | "postgres") {
                assert_eq!(body["storage"]["schema"]["engine"], "postgres");
                assert_eq!(body["storage"]["schema"]["version"], 3);
                assert_eq!(
                    body["storage"]["schema"]["name"],
                    "003_supabase_structured_metering_usage"
                );
                assert_eq!(body["storage"]["schema"]["validated"], true);
                assert!(body["storage"]["schema"]["checksum"]
                    .as_str()
                    .is_some_and(|checksum| checksum.len() == 16));
            } else {
                assert!(body["storage"]["schema"].is_null());
            }
            assert_secret_redacted(&body.to_string());
            Ok(())
        })
    }

    fn expect_api_key(&self, id: &str) -> Result<()> {
        self.expect_api_key_named(id, "Durable storage restart test key")
    }

    fn expect_api_key_named(&self, id: &str, name: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/api-keys/{id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["key"]["id"], id);
                assert_eq!(body["key"]["name"], name);
                assert_eq!(body["key"]["key_source"], "inline");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn expect_restored_api_key_models_access(&self, id: &str) -> Result<()> {
        let auth = format!("Authorization: Bearer {id}-secret");
        self.expect_json("GET", "/v1/models", &[auth.as_str()], "", 200, |body| {
            assert!(list_contains(&body, "id", "fast-chat"));
            assert_secret_redacted(&body.to_string());
            Ok(())
        })
    }

    fn expect_gateway_config(&self, id: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/gateway-configs/{id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["gateway_config"]["id"], id);
                assert_eq!(
                    body["gateway_config"]["name"],
                    "Durable storage restart profile"
                );
                assert_eq!(body["gateway_config"]["revision"], 7);
                assert_eq!(body["gateway_config"]["cache_enabled"], false);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn expect_metered_chat_completion(&self, api_key_id: &str, profile_id: &str) -> Result<()> {
        let auth = format!("Authorization: Bearer {api_key_id}-secret");
        let profile = format!("x-ferrogate-config: {profile_id}");
        self.expect_json(
            "POST",
            "/v1/chat/completions",
            &[auth.as_str(), JSON_CONTENT, profile.as_str()],
            r#"{"model":"fast-chat","messages":[{"role":"user","content":"durable metering check"}]}"#,
            200,
            |body| {
                assert_eq!(body["object"], "chat.completion");
                assert_eq!(body["usage"]["total_tokens"], 2);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn expect_durable_metering_usage(&self, api_key_id: &str, expected_total: u64) -> Result<()> {
        self.expect_json(
            "GET",
            "/admin/v1/metering-events?limit=100",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let events = body["data"]
                    .as_array()
                    .context("metering events response data must be an array")?;
                let event = events
                    .iter()
                    .find(|event| {
                        event["tenant"]["api_key_id"] == api_key_id
                            && event["logical_model"] == "fast-chat"
                            && event["provider"] == "openai"
                    })
                    .with_context(|| {
                        format!("durable metering event for API key {api_key_id} was not found")
                    })?;
                assert_eq!(event["usage_source"], "provider_usage");
                assert_eq!(event["usage"]["total_tokens"], expected_total);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;

        self.expect_json(
            "GET",
            "/admin/v1/usage-aggregates",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let aggregates = body["data"]
                    .as_array()
                    .context("usage aggregates response data must be an array")?;
                let aggregate = aggregates
                    .iter()
                    .find(|aggregate| {
                        aggregate["api_key_id"] == api_key_id
                            && aggregate["logical_model"] == "fast-chat"
                            && aggregate["provider"] == "openai"
                    })
                    .with_context(|| {
                        format!(
                            "durable usage aggregate for API key {api_key_id} was not found in {body}"
                        )
                    })?;
                assert_eq!(aggregate["usage"]["total_tokens"], expected_total);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn expect_durable_request_and_audit_evidence(&self, api_key_id: &str) -> Result<()> {
        self.expect_json(
            "GET",
            "/admin/v1/request-logs?limit=100",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let logs = body["data"]
                    .as_array()
                    .context("request logs response data must be an array")?;
                let log = logs
                    .iter()
                    .find(|log| {
                        log["tenant"]["api_key_id"] == api_key_id
                            && log["logical_model"] == "fast-chat"
                            && log["provider"] == "openai"
                            && log["status_code"] == 200
                    })
                    .with_context(|| {
                        format!(
                            "durable request log for API key {api_key_id} was not found in {body}"
                        )
                    })?;
                assert_eq!(log["prompt_recorded"], false);
                assert_eq!(log["response_recorded"], false);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;

        self.expect_json(
            "GET",
            "/admin/v1/audit-events?limit=200",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let events = body["data"]
                    .as_array()
                    .context("audit events response data must be an array")?;
                let event = events
                    .iter()
                    .find(|event| {
                        event["actor_api_key_id"] == "admin"
                            && event["target"].as_str().is_some_and(|target| {
                                target == api_key_id || target.contains(api_key_id)
                            })
                            && event["outcome"] == "committed"
                    })
                    .with_context(|| {
                        format!(
                            "durable audit event for API key {api_key_id} was not found in {body}"
                        )
                    })?;
                assert!(event["action"].as_str().is_some_and(|action| {
                    action == "api_key.upsert" || action == "api_key.delete"
                }));
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn expect_live_token4ai_completion(
        &self,
        request_marker: &str,
        provider_model: &str,
    ) -> Result<()> {
        let body = serde_json::json!({
            "model": "live-chat",
            "messages": [
                {
                    "role": "user",
                    "content": format!("Reply with exactly: ok. Marker: {request_marker}")
                }
            ],
            "max_tokens": 64
        })
        .to_string();
        self.expect_json(
            "POST",
            "/v1/chat/completions",
            &[CLIENT_AUTH, JSON_CONTENT],
            &body,
            200,
            |body| {
                assert_eq!(body["object"], "chat.completion");
                assert!(
                    body["usage"]["total_tokens"].as_u64().unwrap_or_default() > 0,
                    "provider usage total_tokens must be positive: {body}"
                );
                assert_secret_redacted(&body.to_string());
                if let Some(model) = body["model"].as_str() {
                    assert!(
                        !model.trim().is_empty(),
                        "provider response model must not be empty"
                    );
                } else {
                    assert!(
                        !provider_model.trim().is_empty(),
                        "configured provider model must not be empty"
                    );
                }
                Ok(())
            },
        )
    }

    fn expect_live_token4ai_metering_usage(
        &self,
        request_marker: &str,
        provider_model: &str,
    ) -> Result<()> {
        let event_total = self.live_token4ai_metering_total(request_marker, provider_model)?;
        if event_total == 0 {
            bail!("live Token4AI metering total_tokens must be positive");
        }

        self.expect_json(
            "GET",
            "/admin/v1/usage-aggregates",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let aggregates = body["data"]
                    .as_array()
                    .context("usage aggregates response data must be an array")?;
                let aggregate = aggregates
                    .iter()
                    .find(|aggregate| {
                        aggregate["api_key_id"] == "client"
                            && aggregate["logical_model"] == "live-chat"
                            && aggregate["provider"] == "token4ai"
                    })
                    .with_context(|| {
                        format!(
                            "live Token4AI usage aggregate for marker {request_marker} was not found in {body}"
                        )
                    })?;
                assert_eq!(aggregate["usage"]["total_tokens"], event_total);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn live_token4ai_metering_total(
        &self,
        request_marker: &str,
        provider_model: &str,
    ) -> Result<u64> {
        let mut total = 0;
        self.expect_json(
            "GET",
            "/admin/v1/metering-events?limit=100",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let events = body["data"]
                    .as_array()
                    .context("metering events response data must be an array")?;
                let event = events
                    .iter()
                    .rev()
                    .find(|event| {
                        event["tenant"]["api_key_id"] == "client"
                            && event["logical_model"] == "live-chat"
                            && event["provider"] == "token4ai"
                    })
                    .with_context(|| {
                        format!(
                            "live Token4AI metering event for marker {request_marker} was not found in {body}"
                        )
                    })?;
                assert_eq!(event["provider_model"], provider_model);
                assert_eq!(event["usage_source"], "provider_usage");
                total = event["usage"]["total_tokens"]
                    .as_u64()
                    .context("metering event usage.total_tokens must be an integer")?;
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        Ok(total)
    }

    fn expect_policy(&self, name: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/policies/{name}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["policy"]["name"], name);
                assert_eq!(body["policy"]["enabled"], false);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn expect_missing_api_key(&self, id: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/api-keys/{id}"),
            &[ADMIN_AUTH],
            "",
            404,
            |body| {
                assert_eq!(body["error"]["code"], "api_key_not_found");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn expect_missing_gateway_config(&self, id: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/gateway-configs/{id}"),
            &[ADMIN_AUTH],
            "",
            404,
            |body| {
                assert_eq!(body["error"]["code"], "gateway_config_not_found");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn expect_missing_policy(&self, name: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/policies/{name}"),
            &[ADMIN_AUTH],
            "",
            404,
            |body| {
                assert_eq!(body["error"]["code"], "policy_not_found");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn expect_restored_policy_denies_chat(&self, id: &str) -> Result<()> {
        let auth = format!("Authorization: Bearer {id}-secret");
        self.expect_json(
            "POST",
            "/v1/chat/completions",
            &[auth.as_str(), JSON_CONTENT],
            r#"{"model":"fast-chat","messages":[{"role":"user","content":"durable policy check"}]}"#,
            403,
            |body| {
                assert_eq!(body["error"]["code"], "blocked_by_storage_restart_test");
                assert_eq!(
                    body["error"]["message"],
                    "blocked by durable storage restart test"
                );
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn expect_prompt_template(&self, id: &str, status: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/prompt-templates/{id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["prompt_template"]["id"], id);
                assert_eq!(
                    body["prompt_template"]["name"],
                    "Durable storage restart prompt"
                );
                assert_eq!(body["prompt_template"]["status"], status);
                assert_eq!(body["prompt_template"]["active_revision"], 1);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn expect_agent_upstream(&self, id: &str, enabled: bool) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/agent-upstreams/{id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["agent_upstream"]["id"], id);
                assert_eq!(body["agent_upstream"]["enabled"], enabled);
                assert_eq!(body["agent_upstream"]["protocol"], "a2a");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn expect_missing_agent_upstream(&self, id: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/agent-upstreams/{id}"),
            &[ADMIN_AUTH],
            "",
            404,
            |body| {
                assert_eq!(body["error"]["code"], "agent_upstream_not_found");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn expect_restored_prompt_template_render(
        &self,
        api_key_id: &str,
        template_id: &str,
    ) -> Result<()> {
        let auth = format!("Authorization: Bearer {api_key_id}-secret");
        self.expect_json(
            "POST",
            &format!("/v1/prompts/{template_id}/render"),
            &[auth.as_str(), JSON_CONTENT],
            r#"{"variables":{"topic":"durable storage"}}"#,
            200,
            |body| {
                assert_eq!(body["model"], "fast-chat");
                assert_eq!(body["temperature"], 0.1);
                assert_eq!(body["messages"][0]["role"], "user");
                assert_eq!(body["messages"][0]["content"], "Summarize durable storage");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn expect_mcp_server(&self, name: &str) -> Result<()> {
        self.expect_json(
            "GET",
            "/admin/v1/mcp-servers",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let servers = body["data"]
                    .as_array()
                    .context("mcp servers response data must be an array")?;
                let server = servers
                    .iter()
                    .find(|server| server["name"] == name)
                    .with_context(|| format!("MCP server {name} was not restored from storage"))?;
                assert_eq!(server["transport"], "streamable_http");
                assert_eq!(server["health"], "degraded");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn expect_missing_mcp_server(&self, name: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/mcp-servers/{name}"),
            &[ADMIN_AUTH],
            "",
            404,
            |body| {
                assert_eq!(body["error"]["code"], "mcp_server_not_found");
                Ok(())
            },
        )
    }

    fn register_echo_plugin(&self) -> Result<()> {
        self.register_echo_plugin_with_policy("never")
    }

    fn register_echo_plugin_with_policy(&self, approval_policy: &str) -> Result<()> {
        let body = serde_json::json!({
            "id": "tool.echo",
            "kind": "tool_provider",
            "source": "builtin",
            "enabled": true,
            "order": 10,
            "approval_policy": approval_policy,
            "permissions": {
                "tools": ["tool.echo"],
                "network": [],
                "filesystem": false,
                "shell": false
            },
            "config": {
                "registered_by": "ferrogate-test"
            }
        })
        .to_string();
        self.expect_json(
            "POST",
            "/admin/v1/plugins",
            &[ADMIN_AUTH, JSON_CONTENT],
            &body,
            201,
            |body| {
                assert_eq!(body["object"], "plugin");
                assert_eq!(body["plugin"]["id"], "tool.echo");
                assert_eq!(body["plugin"]["kind"], "tool_provider");
                assert_eq!(body["plugin"]["source"], "builtin");
                assert_eq!(body["plugin"]["enabled"], true);
                assert_eq!(body["plugin"]["active"], true);
                assert_eq!(body["plugin"]["health"], "ok");
                assert_eq!(body["plugin"]["approval_policy"], approval_policy);
                assert_array_contains(&body["plugin"]["capabilities"], "tool_provider")
                    .context("registered plugin must advertise tool_provider capability")?;
                assert_array_contains(&body["plugin"]["tools"], "tool.echo")
                    .context("registered plugin must expose tool.echo")?;
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn register_mcp_server(&self, name: &str) -> Result<()> {
        let body = serde_json::json!({
            "name": name,
            "transport": "streamable_http",
            "url": "http://127.0.0.1:1/mcp",
            "auth_type": "none",
            "tools_to_execute": ["search"],
            "tools_to_auto_execute": ["search"],
            "approval_policy": "never",
            "tool_include": ["search"],
            "tool_regex": [],
            "headers": [],
            "tls": {},
            "timeout_ms": 100,
            "health_ping_interval_secs": 30,
            "max_reconnect_attempts": 3,
            "min_reconnect_backoff_secs": 1,
            "max_reconnect_backoff_secs": 5
        })
        .to_string();
        self.expect_json(
            "POST",
            "/admin/v1/mcp-servers",
            &[ADMIN_AUTH, JSON_CONTENT],
            &body,
            201,
            |body| {
                assert_eq!(body["object"], "mcp_server");
                assert_eq!(body["server"]["name"], name);
                assert_eq!(body["server"]["transport"], "streamable_http");
                assert_eq!(body["server"]["health"], "degraded");
                assert_eq!(body["server"]["connected"], false);
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn delete_mcp_server(&self, name: &str) -> Result<()> {
        self.expect_json(
            "DELETE",
            &format!("/admin/v1/mcp-servers/{name}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["object"], "mcp_server");
                assert_eq!(body["id"], name);
                assert_eq!(body["deleted"], true);
                Ok(())
            },
        )
    }

    fn create_expired_echo_approval(&self) -> Result<String> {
        self.register_echo_plugin_with_policy("always")?;
        let mut request_id = String::new();
        self.expect_json(
            "POST",
            "/v1/tools/execute",
            &[ADMIN_AUTH, JSON_CONTENT],
            r#"{"name":"tool.echo","arguments":{"message":"approval durability"}}"#,
            403,
            |body| {
                assert_eq!(body["error"]["code"], "tool_denied");
                request_id = body["error"]["request_id"]
                    .as_str()
                    .context("tool approval error response must include request_id")?
                    .to_string();
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        let mut approval_id = String::new();
        self.expect_json(
            "GET",
            "/admin/v1/tool-approvals",
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let approvals = body["data"]
                    .as_array()
                    .context("tool approvals response data must be an array")?;
                let approval = approvals
                    .iter()
                    .find(|approval| approval["request_id"] == request_id)
                    .with_context(|| {
                        format!("tool approval for request {request_id} was not persisted")
                    })?;
                assert_eq!(approval["tool_name"], "tool.echo");
                assert_eq!(approval["status"], "expired");
                assert_eq!(approval["approval_policy"], "always");
                assert_secret_redacted(&body.to_string());
                approval_id = approval["id"]
                    .as_str()
                    .context("tool approval id missing")?
                    .to_string();
                Ok(())
            },
        )?;
        Ok(approval_id)
    }

    fn expect_tool_approval(&self, id: &str, status: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/tool-approvals/{id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["id"], id);
                assert_eq!(body["tool_name"], "tool.echo");
                assert_eq!(body["status"], status);
                assert_eq!(body["approval_policy"], "always");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn expect_plugin(&self, id: &str) -> Result<()> {
        self.expect_json("GET", "/admin/v1/plugins", &[ADMIN_AUTH], "", 200, |body| {
            let plugins = body["data"]
                .as_array()
                .context("plugins response data must be an array")?;
            let plugin = plugins
                .iter()
                .find(|plugin| plugin["id"] == id)
                .with_context(|| format!("plugin {id} was not restored from storage"))?;
            assert_eq!(plugin["source"], "builtin");
            assert_eq!(plugin["enabled"], true);
            assert_eq!(plugin["active"], true);
            assert_eq!(plugin["health"], "ok");
            assert_array_contains(&plugin["capabilities"], "tool_provider")
                .context("plugin must advertise the tool_provider capability")?;
            assert_array_contains(&plugin["tools"], "tool.echo")
                .context("plugin must advertise its registered tool")?;
            assert_secret_redacted(&body.to_string());
            Ok(())
        })?;
        self.expect_json(
            "GET",
            &format!("/admin/v1/plugins/{id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["id"], id);
                assert_eq!(body["source"], "builtin");
                assert_eq!(body["enabled"], true);
                assert_eq!(body["active"], true);
                assert_eq!(body["health"], "ok");
                assert_array_contains(&body["capabilities"], "tool_provider")
                    .context("plugin detail must advertise the tool_provider capability")?;
                assert_array_contains(&body["tools"], "tool.echo")
                    .context("plugin detail must advertise its registered tool")?;
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        self.expect_json(
            "GET",
            &format!("/admin/v1/plugins/{id}/tools"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                let tools = body["data"]
                    .as_array()
                    .context("plugin tools response data must be an array")?;
                let tool = tools
                    .iter()
                    .find(|tool| tool["name"] == "tool.echo")
                    .context("plugin tool.echo was not listed")?;
                assert_eq!(tool["extension_id"], id);
                assert_eq!(tool["approval_policy"], "never");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }

    fn expect_echo_tool(&self) -> Result<()> {
        self.expect_json(
            "POST",
            "/v1/tools/execute",
            &[ADMIN_AUTH, JSON_CONTENT],
            r#"{"name":"tool.echo","arguments":{"message":"plugin durable restore"}}"#,
            200,
            |body| {
                assert_eq!(body["object"], "tool_execution");
                assert_eq!(body["name"], "tool.echo");
                assert_eq!(body["content"]["echo"]["message"], "plugin durable restore");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )
    }
}

impl Drop for TursoRestartHarness {
    fn drop(&mut self) {
        let _ = self.gateway.kill();
        let _ = self.gateway.wait();
    }
}

impl LocalHarness {
    fn start(ferrogate_bin: &Path, expected_provider_requests: usize) -> Result<Self> {
        Self::start_inner(ferrogate_bin, expected_provider_requests, None, None, false)
    }

    fn start_with_billing_and_agent(
        ferrogate_bin: &Path,
        expected_provider_requests: usize,
    ) -> Result<Self> {
        let billing = spawn_mock_billing_server(expected_provider_requests)
            .context("start billing provider")?;
        Self::start_inner(
            ferrogate_bin,
            expected_provider_requests,
            Some(billing),
            None,
            true,
        )
    }

    fn start_with_external_auth(
        ferrogate_bin: &Path,
        expected_provider_requests: usize,
        auth_addr: &str,
    ) -> Result<Self> {
        Self::start_inner(
            ferrogate_bin,
            expected_provider_requests,
            None,
            Some(auth_addr),
            false,
        )
    }

    fn start_inner(
        ferrogate_bin: &Path,
        expected_provider_requests: usize,
        billing: Option<MockBillingServer>,
        auth_addr: Option<&str>,
        include_agent: bool,
    ) -> Result<Self> {
        if !ferrogate_bin.exists() {
            bail!(
                "ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli` first or pass --ferrogate-bin",
                ferrogate_bin.display()
            );
        }

        let gateway_addr = free_addr()?;
        let (provider_addr, provider) =
            spawn_local_provider_upstream(expected_provider_requests).context("start provider")?;
        let (mcp_addr, mcp_server) = spawn_mock_mcp_server().context("start mcp provider")?;
        let (agent_addr, agent_server) = if include_agent {
            let (addr, server) = spawn_mock_agent_server().context("start agent provider")?;
            (Some(addr), Some(server))
        } else {
            (None, None)
        };
        let dir = tempfile::tempdir()?;
        let stdio_mcp_path = dir.path().join("blocking-stdio-mcp.py");
        std::fs::write(&stdio_mcp_path, blocking_stdio_mcp_script())?;
        let observability =
            spawn_mock_otlp_server().context("start observability provider mock")?;
        let config_path = dir.path().join("ferrogate.toml");
        std::fs::write(
            &config_path,
            local_gateway_config(LocalGatewayConfig {
                gateway_addr: &gateway_addr,
                provider_addr: &provider_addr,
                mcp_addr: &mcp_addr,
                agent_addr: agent_addr.as_deref().unwrap_or("http://127.0.0.1:1/a2a"),
                stdio_mcp_path: &stdio_mcp_path,
                billing: billing.as_ref(),
                observability: Some(&observability),
                auth_addr,
            }),
        )?;

        let gateway = Command::new(ferrogate_bin)
            .args(["run", "--config"])
            .arg(&config_path)
            .env("FERROGATE_PROVIDER_SECRET", "provider-secret")
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
            .with_context(|| format!("failed to start {}", ferrogate_bin.display()))?;

        let mut harness = Self {
            _dir: dir,
            gateway_addr,
            gateway,
            provider: Some(provider),
            mcp_server: Some(mcp_server),
            agent_server,
            agent_addr,
            billing,
            observability: Some(observability),
        };
        harness.wait_for_gateway()?;
        Ok(harness)
    }

    fn wait_for_gateway(&mut self) -> Result<()> {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < Duration::from_secs(20) {
            if let Some(status) = self.gateway.try_wait()? {
                bail!("ferrogate process exited before readiness check: {status}");
            }
            match http_request_addr(&self.gateway_addr, "GET", "/healthz", &[], "") {
                Ok(response) if response.status == 200 => return Ok(()),
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!(
            "timed out waiting for ferrogate on {}; last response: {last}",
            self.gateway_addr
        );
    }

    fn expect_json<F>(
        &self,
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
        let response = http_request_addr(&self.gateway_addr, method, path, headers, body)?;
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
        &self,
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
        let response = http_request_addr(&self.gateway_addr, method, path, headers, body)?;
        if response.status != expected_status {
            bail!(
                "{method} {path} expected status {expected_status}, got {}; raw: {}",
                response.status,
                response.raw
            );
        }
        check(&response.body)
    }

    fn expect_mcp_json<F>(
        &self,
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
        self.expect_json(method, path, headers, body, expected_status, check)
    }

    fn agent_endpoint(&self) -> Result<&str> {
        self.agent_addr
            .as_deref()
            .context("agent harness is not configured")
    }

    fn expect_openmeter_export(&self) -> Result<()> {
        let Some(billing) = &self.billing else {
            bail!("billing provider mock is not configured");
        };
        let mut last = None;
        let body = loop {
            let request = billing
                .received
                .recv_timeout(Duration::from_secs(5))
                .context("timed out waiting for OpenMeter export")?;
            assert!(request.starts_with("POST /api/v1/events "));
            assert!(request.contains("Authorization: Bearer test-metering-token"));
            let payload = http_request_body(&request)?;
            let body: Value = serde_json::from_str(payload)
                .with_context(|| format!("failed to parse billing export payload: {payload}"))?;
            let is_chat_usage = body["data"]["prompt_tokens"] == 1
                && body["data"]["completion_tokens"] == 1
                && body["data"]["total_tokens"] == 2;
            if is_chat_usage {
                break body;
            }
            last = Some(body);
        };
        assert_eq!(body["specversion"], "1.0");
        assert_eq!(body["type"], "ai.tokens");
        assert_eq!(body["source"], "ferrogate-test");
        assert_eq!(body["subject"], "client");
        assert!(body["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("ferrogate:")));
        assert_eq!(body["data"]["logical_model"], "fast-chat");
        assert_eq!(body["data"]["provider"], "openai");
        assert_eq!(body["data"]["provider_model"], "gpt-4o-mini");
        assert_eq!(body["data"]["prompt_tokens"], 1);
        assert_eq!(body["data"]["completion_tokens"], 1);
        assert_eq!(body["data"]["total_tokens"], 2);
        assert_eq!(body["data"]["tenant"]["organization_id"], "org_demo");
        assert_eq!(body["data"]["tenant"]["project_id"], "project_gateway");
        drop(last);
        Ok(())
    }

    fn wait_for_metering_export_status(&self) -> Result<()> {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < Duration::from_secs(5) {
            let response = http_request_addr(
                &self.gateway_addr,
                "GET",
                "/admin/v1/metering-export-status",
                &[ADMIN_AUTH],
                "",
            )?;
            if response.status == 200
                && response.body.contains("openmeter")
                && response.body.contains("exported")
            {
                return Ok(());
            }
            last = response.raw;
            thread::sleep(Duration::from_millis(100));
        }
        bail!("timed out waiting for metering export status; last response: {last}")
    }

    fn expect_vector_otlp_export(&self) -> Result<()> {
        let Some(observability) = &self.observability else {
            bail!("observability provider mock is not configured");
        };
        let mut requests = Vec::new();
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(12) {
            let request = observability
                .received
                .recv_timeout(Duration::from_millis(500))
                .context("timed out waiting for Vector-compatible OTLP export")?;
            requests.push(request);
            if requests
                .iter()
                .any(|request| request.starts_with("POST /v1/metrics "))
                && requests
                    .iter()
                    .any(|request| request.starts_with("POST /v1/logs "))
                && requests
                    .iter()
                    .any(|request| request.starts_with("POST /v1/traces "))
            {
                break;
            }
        }
        let raw = requests.join("\n---otlp-request---\n");
        assert!(raw.contains("Content-Type: application/json"));
        assert!(
            raw.contains("POST /v1/metrics "),
            "missing OTLP metrics request: {raw}"
        );
        assert!(
            raw.contains("POST /v1/logs "),
            "missing OTLP logs request: {raw}"
        );
        assert!(
            raw.contains("POST /v1/traces "),
            "missing OTLP traces request: {raw}"
        );
        assert!(raw.contains("\"service.name\""));
        assert!(raw.contains("ferrogate-test"));
        assert!(raw.contains("ferrogate.request_logs"));
        assert!(raw.contains("ferrogate.billing_events"));
        assert!(raw.contains("ferrogate.gateway.request"));
        assert!(raw.contains("\"event_family\""));
        assert!(raw.contains("\"request\""));
        assert!(raw.contains("\"audit\""));
        assert!(raw.contains("\"billing_event_observed\""));
        assert!(raw.contains("\"audit_action\""));
        assert!(raw.contains("api_key.upsert"));
        assert!(raw.contains("logical_model"));
        assert!(raw.contains("fast-chat"));
        assert!(raw.contains("provider"));
        assert!(raw.contains("openai"));
        assert!(raw.contains("api_key_id"));
        assert!(raw.contains("test-client"));
        assert_secret_redacted(&raw);
        assert!(!raw.contains("provider-secret"));
        assert!(!raw.contains("test-secret"));
        Ok(())
    }

    fn expect_agent_run_otlp_trace_export(&self, agent_run_id: &str) -> Result<()> {
        let Some(observability) = &self.observability else {
            bail!("observability provider mock is not configured");
        };
        let mut trace_payloads = Vec::new();
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(12) {
            match observability
                .received
                .recv_timeout(Duration::from_millis(500))
            {
                Ok(request) => {
                    if !request.starts_with("POST /v1/traces ") {
                        continue;
                    }
                    let payload = http_request_body(&request)?.to_string();
                    trace_payloads.push(payload.clone());
                    let body = serde_json::from_str::<Value>(&payload).with_context(|| {
                        format!("failed to parse OTLP trace payload: {payload}")
                    })?;
                    if agent_run_otlp_trace_is_reconstructable(&body, agent_run_id)? {
                        assert_secret_redacted(&payload);
                        assert!(!payload.contains("provider-secret"));
                        assert!(!payload.contains("test-secret"));
                        return Ok(());
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        bail!(
            "timed out waiting for reconstructable OTLP trace for agent run {agent_run_id}; trace payloads: {}",
            trace_payloads.join("\n---otlp-trace-payload---\n")
        )
    }
}

impl Drop for LocalHarness {
    fn drop(&mut self) {
        let _ = self.gateway.kill();
        let _ = self.gateway.wait();
        if let Some(provider) = self.provider.take() {
            let _ = provider.join();
        }
        if let Some(mcp_server) = self.mcp_server.take() {
            let _ = mcp_server.join();
        }
        if let Some(agent_server) = self.agent_server.take() {
            let _ = agent_server.join();
        }
        if let Some(billing) = self.billing.as_mut() {
            let _ = billing.handle.take().map(|handle| handle.join());
        }
        if let Some(observability) = self.observability.as_mut() {
            let _ = observability.handle.take().map(|handle| handle.join());
        }
    }
}

impl MockThirdPartyAuthServer {
    fn join(mut self) -> Result<Vec<String>> {
        let handle = self
            .handle
            .take()
            .context("third-party auth mock join handle missing")?;
        handle
            .join()
            .map_err(|_| anyhow!("third-party auth mock thread panicked"))
    }
}

impl Drop for MockThirdPartyAuthServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct LocalGatewayConfig<'a> {
    gateway_addr: &'a str,
    provider_addr: &'a str,
    mcp_addr: &'a str,
    agent_addr: &'a str,
    stdio_mcp_path: &'a Path,
    billing: Option<&'a MockBillingServer>,
    observability: Option<&'a MockOtlpServer>,
    auth_addr: Option<&'a str>,
}

fn local_gateway_config(config: LocalGatewayConfig<'_>) -> String {
    let metering = config
        .billing
        .map(|billing| {
            format!(
                r#"
[metering]
export_enabled = true
export_provider = "openmeter"
export_endpoint = "http://{}/api/v1/events"
export_token = "test-metering-token"
export_timeout_secs = 3
export_event_type = "ai.tokens"
export_source = "ferrogate-test"
export_subject = "api_key_id"
"#,
                billing.addr
            )
        })
        .unwrap_or_default();
    let observability = config
        .observability
        .map(|observability| {
            format!(
                r#"
[observability]
enabled = true
provider = "vector"
otlp_endpoint = "http://{}"
prometheus_metrics_path = "/metrics"
export_timeout_secs = 3
"#,
                observability.addr
            )
        })
        .unwrap_or_default();
    let auth_service = config
        .auth_addr
        .map(|auth_addr| {
            format!(
                r#"
[auth_service]
enabled = true
endpoint = "http://{auth_addr}"
timeout_millis = 1000
"#
            )
        })
        .unwrap_or_default();
    let gateway_addr = config.gateway_addr;
    let provider_addr = config.provider_addr;
    let mcp_addr = config.mcp_addr;
    let agent_addr = config.agent_addr;
    format!(
        r#"
listen = "{gateway_addr}"

[cluster]
enabled = true
cluster_id = "ferrogate-test-cluster"
node_id = "ferrogate-test-node"
node_region = "local"
node_zone = "local-a"
state_backend = "local"
counter_backend = "local"
{metering}
{observability}
{auth_service}

[telemetry]
service_name = "ferrogate-test"
log_bodies = true

[reliability]
mcp_dispatch_timeout_secs = 1
mcp_dispatch_max_concurrency = 4

[agent_runtime]
enabled = true
max_turns = 3
timeout_millis = 5000

[[extensions]]
id = "tool.echo"
kind = "tool_provider"
source = "builtin"
enabled = true
order = 10

[extensions.permissions]
tools = ["tool.echo"]
network = []
filesystem = false
shell = false
tenant_scope = true

[extensions.config]
tenant_allowlist = ["org_demo"]

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[providers]]
name = "anthropic"
kind = "anthropic"
base_url = "http://{provider_addr}/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[mcp_servers]]
name = "http"
transport = "streamable_http"
url = "http://{mcp_addr}/mcp"
tools_to_execute = ["search"]
tools_to_auto_execute = ["search"]
approval_policy = "never"
timeout_ms = 3000

[[mcp_servers]]
name = "stdio"
transport = "stdio"
command = "python3"
args = [{stdio_mcp_path}]
tools_to_execute = ["search"]
tools_to_auto_execute = ["search"]
approval_policy = "never"
timeout_ms = 3000

[[agent_upstreams]]
id = "agent.echo"
name = "Agent Echo"
description = "Harness agent upstream"
enabled = true
protocol = "a2a"
endpoint = "http://{agent_addr}/a2a"
tenant_ids = ["client"]
capabilities = ["invoke", "read", "stream", "discover"]

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat", "streaming"]
input_price_per_1m = 1.0
output_price_per_1m = 2.0

[[models]]
name = "blocked-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]
input_price_per_1m = 1.0
output_price_per_1m = 2.0

[[api_keys]]
id = "client"
name = "Client"
key = "client-secret"
scopes = ["models.read", "chat.completions", "responses.create", "agent.runs.create", "admin.read", "agents.read", "agents.invoke", "tools.read", "tools.execute"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
project_id = "project_gateway"
log_bodies = true

[[api_keys]]
id = "observer"
name = "Observer"
key = "observer-secret"
scopes = ["tools.read", "tools.execute"]
organization_id = "org_observer"
project_id = "project_observer"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[[gateway_configs]]
id = "static-profile"
name = "Static profile"
revision = 1
enabled = true
api_key_ids = ["client"]
cache_enabled = false
"#,
        stdio_mcp_path = toml_basic_string(&config.stdio_mcp_path.to_string_lossy())
    )
}

impl ControlPlaneRestartStorage<'_> {
    fn provider_name(self) -> &'static str {
        match self {
            ControlPlaneRestartStorage::Supabase { .. } => "supabase",
            ControlPlaneRestartStorage::Postgres { .. } => "postgres",
            ControlPlaneRestartStorage::Mysql { .. } => "mysql",
        }
    }

    fn apply_env(self, command: &mut Command) {
        match self {
            ControlPlaneRestartStorage::Postgres { dsn, .. } => {
                command.env("FERROGATE_POSTGRES_DSN", dsn);
            }
            ControlPlaneRestartStorage::Supabase { dsn, .. } => {
                command.env("FERROGATE_SUPABASE_DSN", dsn);
            }
            ControlPlaneRestartStorage::Mysql { dsn, .. } => {
                command.env("FERROGATE_MYSQL_DSN", dsn);
            }
        }
    }

    fn storage_block_with_migration_mode(self, migration_mode: StorageMigrationMode) -> String {
        match self {
            ControlPlaneRestartStorage::Postgres { tls, .. } => {
                let ca_cert_path = tls
                    .ca_cert_path
                    .map(|path| {
                        format!(
                            "\n  postgres_tls_ca_cert_path: {}",
                            toml_basic_string(&path.to_string_lossy())
                        )
                    })
                    .unwrap_or_default();
                format!(
                    r#"storage:
  provider: postgres
  required: true
  provider_order:
    - supabase
    - postgres
    - mysql
  postgres_dsn_env: FERROGATE_POSTGRES_DSN
  postgres_pool_size: 2
  postgres_tls_mode: {tls_mode}{ca_cert_path}
  postgres_connect_timeout_secs: 5
  postgres_statement_timeout_millis: 30000
  postgres_schema: ferrogate_control
  postgres_search_path:
    - public
  migration_mode: {migration_mode}"#,
                    tls_mode = tls.mode,
                    ca_cert_path = ca_cert_path,
                    migration_mode = migration_mode.as_str()
                )
            }
            ControlPlaneRestartStorage::Supabase { tls, .. } => {
                let ca_cert_path = tls
                    .ca_cert_path
                    .map(|path| {
                        format!(
                            "\n  postgres_tls_ca_cert_path: {}",
                            toml_basic_string(&path.to_string_lossy())
                        )
                    })
                    .unwrap_or_default();
                format!(
                    r#"storage:
  provider: supabase
  required: true
  provider_order:
    - supabase
    - postgres
    - mysql
  supabase_dsn_env: FERROGATE_SUPABASE_DSN
  postgres_pool_size: 2
  postgres_tls_mode: {tls_mode}{ca_cert_path}
  postgres_connect_timeout_secs: 5
  postgres_statement_timeout_millis: 30000
  postgres_schema: ferrogate_control
  postgres_search_path:
    - public
  migration_mode: {migration_mode}"#,
                    tls_mode = tls.mode,
                    ca_cert_path = ca_cert_path,
                    migration_mode = migration_mode.as_str()
                )
            }
            ControlPlaneRestartStorage::Mysql { tls, .. } => {
                let ca_cert_path = tls
                    .ca_cert_path
                    .map(|path| {
                        format!(
                            "\n  mysql_tls_ca_cert_path: {}",
                            toml_basic_string(&path.to_string_lossy())
                        )
                    })
                    .unwrap_or_default();
                format!(
                    r#"storage:
  provider: mysql
  required: true
  provider_order:
    - supabase
    - postgres
    - mysql
  mysql_dsn_env: FERROGATE_MYSQL_DSN
  mysql_pool_size: 2
  mysql_tls_mode: {tls_mode}{ca_cert_path}
  mysql_connect_timeout_secs: 5
  migration_mode: {migration_mode}"#,
                    tls_mode = tls.mode,
                    ca_cert_path = ca_cert_path,
                    migration_mode = migration_mode.as_str()
                )
            }
        }
    }

    fn restart_config(
        self,
        gateway_addr: &str,
        include_plugins: bool,
        include_mcp_server: bool,
        migration_mode: StorageMigrationMode,
        provider_base_url: Option<&str>,
    ) -> String {
        let plugins = if include_plugins {
            r#"
plugins:
  - id: tool.echo
    kind: tool_provider
    source: builtin
    enabled: true
    order: 10
    approval_policy: never
    permissions:
      tools:
        - tool.echo
"#
        } else {
            ""
        };
        let mcp_server = if include_mcp_server {
            r#"
mcp_servers:
  - name: dbhttp
    transport: streamable_http
    url: "http://127.0.0.1:1/mcp"
    tools_to_execute:
      - search
    tools_to_auto_execute:
      - search
    tool_include:
      - search
    approval_policy: never
    timeout_ms: 100
"#
        } else {
            ""
        };
        let provider_base_url = provider_base_url.unwrap_or("http://127.0.0.1:1/v1");
        format!(
            r#"
listen: "{gateway_addr}"

{storage}

reliability:
  tool_approval_timeout_secs: 1

providers:
  - name: openai
    kind: openai
    base_url: "{provider_base_url}"
    api_key_env: FERROGATE_PROVIDER_SECRET

models:
  - name: fast-chat
    provider: openai
    provider_model: gpt-4o-mini
    capabilities:
      - chat

api_keys:
  - id: admin
    name: Admin
    key: admin-secret
    scopes:
      - admin.read
      - admin.write
      - tools.read
      - tools.execute
{plugins}
{mcp_server}
"#,
            storage = self.storage_block_with_migration_mode(migration_mode),
            provider_base_url = provider_base_url
        )
    }

    fn live_token4ai_provider_config(
        self,
        gateway_addr: &str,
        provider_base_url: &str,
        provider_model: &str,
        migration_mode: StorageMigrationMode,
    ) -> String {
        format!(
            r#"
listen: "{gateway_addr}"

{storage}

providers:
  - name: token4ai
    kind: openai
    base_url: "{provider_base_url}"
    api_key_env: FERROGATE_PROVIDER_SECRET

models:
  - name: live-chat
    provider: token4ai
    provider_model: "{provider_model}"
    capabilities:
      - chat

api_keys:
  - id: client
    name: Live Token4AI client
    key: client-secret
    scopes:
      - models.read
      - chat.completions
    allowed_models:
      - live-chat
    organization_id: org_token4ai_live
    project_id: project_gateway
  - id: admin
    name: Admin
    key: admin-secret
    scopes:
      - admin.read
      - admin.write
"#,
            storage = self.storage_block_with_migration_mode(migration_mode),
            provider_base_url = provider_base_url,
            provider_model = provider_model,
        )
    }
}

fn toml_basic_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn blocking_stdio_mcp_script() -> &'static str {
    r#"import json
import sys
import time

for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    response = {"jsonrpc": "2.0", "id": request.get("id")}
    if method == "initialize":
        response["result"] = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "blocking-stdio", "version": "1.0.0"},
        }
    elif method == "tools/list":
        response["result"] = {
            "tools": [
                {
                    "name": "search",
                    "description": "Blocking stdio search",
                    "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
                }
            ]
        }
    elif method == "tools/call":
        time.sleep(60)
        continue
    elif method == "ping":
        response["result"] = {}
    else:
        response["error"] = {"code": -32601, "message": "unsupported method"}
    print(json.dumps(response), flush=True)
"#
}

fn auth_service_config() -> String {
    r#"
tenants:
  - id: tenant-example
    name: Example tenant
    enabled: true
    context:
      organization_id: org-example
      team_id: team-example
      project_id: project-example
      user_id: null
      api_key_id: null
api_keys:
  - id: key-example
    name: Example gateway key
    secret: dev-secret
    enabled: true
    tenant:
      organization_id: org-example
      team_id: team-example
      project_id: project-example
      user_id: null
      api_key_id: key-example
    scopes:
      - models.read
      - chat.completions
  - id: client
    name: Gateway client key
    secret: client-secret
    enabled: true
    tenant:
      organization_id: org_demo
      team_id: null
      project_id: project_gateway
      user_id: null
      api_key_id: client
    scopes:
      - models.read
      - chat.completions
      - responses.create
roles:
  - id: role-chat-caller
    name: Chat caller
    permissions:
      - action: chat.completions
        resource: model:fast-chat
      - action: models.read
        resource: "*"
bindings:
  - id: binding-key-example-chat
    role_id: role-chat-caller
    tenant:
      organization_id: org-example
      team_id: team-example
      project_id: project-example
      user_id: null
      api_key_id: key-example
    subject:
      type: api_key
      api_key_id: key-example
  - id: binding-client-chat
    role_id: role-chat-caller
    tenant:
      organization_id: org_demo
      team_id: null
      project_id: project_gateway
      user_id: null
      api_key_id: client
    subject:
      type: api_key
      api_key_id: client
"#
    .to_string()
}

fn spawn_local_provider_upstream(
    expected_requests: usize,
) -> Result<(String, JoinHandle<Vec<String>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?.to_string();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        let started = Instant::now();
        while requests.len() < expected_requests && started.elapsed() < Duration::from_secs(3) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = match read_http_request(&mut stream) {
                        Ok(request) => request,
                        Err(_) => continue,
                    };
                    let body = if request.contains("GET /v1/models ") {
                        r#"{"object":"list","data":[{"id":"provider-chat","owned_by":"ferrogate-test","created":1781417600,"context_window":8192,"capabilities":["chat","tools"]}]}"#
                    } else if request.contains("POST /v1/responses ") {
                        r#"{"id":"resp_ferrogate_test","object":"response","output_text":"ok","usage":{"input_tokens":3,"output_tokens":5,"total_tokens":8}}"#
                    } else {
                        r#"{"id":"chatcmpl_ferrogate_test","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#
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
    Ok((addr, handle))
}

fn spawn_mock_mcp_server() -> Result<(String, JoinHandle<Vec<String>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?.to_string();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(5) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = match read_http_request(&mut stream) {
                        Ok(request) => request,
                        Err(_) => continue,
                    };
                    let body = if request.contains(r#""method":"initialize""#) {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": extract_jsonrpc_id(&request),
                            "result": {
                                "protocolVersion": "2025-06-18",
                                "capabilities": {
                                    "tools": {
                                        "listChanged": false
                                    }
                                },
                                "serverInfo": {
                                    "name": "mcp-harness",
                                    "version": "1.0.0"
                                },
                                "instructions": "Use the harness MCP server for compatibility checks."
                            }
                        })
                        .to_string()
                    } else if request.contains(r#""method":"tools/list""#) {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": extract_jsonrpc_id(&request),
                            "result": {
                                "tools": [
                                    {
                                        "name": "search",
                                        "description": "Search the harness MCP upstream",
                                        "inputSchema": {
                                            "type": "object",
                                            "properties": {
                                                "query": {
                                                    "type": "string"
                                                }
                                            },
                                            "required": ["query"]
                                        }
                                    }
                                ]
                            }
                        })
                        .to_string()
                    } else if request.contains(r#""method":"tools/call""#) {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": extract_jsonrpc_id(&request),
                            "result": {
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "ferrogate-result"
                                    }
                                ],
                                "isError": false
                            }
                        })
                        .to_string()
                    } else if request.contains(r#""method":"ping""#) {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": extract_jsonrpc_id(&request),
                            "result": {}
                        })
                        .to_string()
                    } else {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": extract_jsonrpc_id(&request),
                            "error": {
                                "code": -32601,
                                "message": "unsupported method"
                            }
                        })
                        .to_string()
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
    Ok((addr, handle))
}

fn spawn_mock_agent_server() -> Result<(String, JoinHandle<Vec<String>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?.to_string();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(30) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = match read_http_request(&mut stream) {
                        Ok(request) => request,
                        Err(_) => continue,
                    };
                    let body = if request.contains(r#""method":"initialize""#) {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": extract_jsonrpc_id(&request),
                            "result": {
                                "protocolVersion": "2025-06-18",
                                "capabilities": {"tools": {"listChanged": false}},
                                "serverInfo": {"name": "agent-harness", "version": "1.0.0"}
                            }
                        })
                        .to_string()
                    } else if request.contains(r#""method":"message:send""#) {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": extract_jsonrpc_id(&request),
                            "result": {
                                "content": [
                                    {"type": "text", "text": "agent-result"}
                                ],
                                "isError": false
                            }
                        })
                        .to_string()
                    } else if request.contains(r#""method":"message:stream""#) {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": extract_jsonrpc_id(&request),
                            "result": {
                                "content": [
                                    {"type": "text", "text": "agent-stream"}
                                ],
                                "isError": false
                            }
                        })
                        .to_string()
                    } else {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": extract_jsonrpc_id(&request),
                            "error": {"code": -32601, "message": "unsupported method"}
                        })
                        .to_string()
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
    Ok((addr, handle))
}

fn spawn_mock_billing_server(expected_requests: usize) -> Result<MockBillingServer> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?.to_string();
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut received = 0;
        let started = Instant::now();
        while received < expected_requests && started.elapsed() < Duration::from_secs(10) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = match read_http_request(&mut stream) {
                        Ok(request) => request,
                        Err(_) => continue,
                    };
                    let body = r#"{"ok":true}"#;
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = tx.send(request);
                    received += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        }
    });
    Ok(MockBillingServer {
        addr,
        received: rx,
        handle: Some(handle),
    })
}

fn spawn_mock_otlp_server() -> Result<MockOtlpServer> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?.to_string();
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(15) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = match read_http_request(&mut stream) {
                        Ok(request) => request,
                        Err(_) => continue,
                    };
                    let body = r#"{"ok":true}"#;
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = tx.send(request);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        }
    });
    Ok(MockOtlpServer {
        addr,
        received: rx,
        handle: Some(handle),
    })
}

fn spawn_mock_third_party_auth_server(
    expected_requests: usize,
) -> Result<MockThirdPartyAuthServer> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?.to_string();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        let started = Instant::now();
        while requests.len() < expected_requests && started.elapsed() < Duration::from_secs(5) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = match read_http_request(&mut stream) {
                        Ok(request) => request,
                        Err(_) => continue,
                    };
                    let body = third_party_auth_response_body(&request);
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
    Ok(MockThirdPartyAuthServer {
        addr,
        handle: Some(handle),
    })
}

fn third_party_auth_response_body(request: &str) -> String {
    if request.contains("POST /v1/auth/resolve-api-key ") {
        return r#"{"tenant":{"organization_id":"org_demo","team_id":null,"project_id":"project_gateway","user_id":null,"api_key_id":"client"},"subject":{"type":"api_key","api_key_id":"client"},"scopes":["models.read","chat.completions","responses.create"]}"#.to_string();
    }
    if request.contains("POST /v1/auth/authorize ") {
        let allowed = http_request_body(request)
            .ok()
            .and_then(|body| serde_json::from_str::<Value>(body).ok())
            .and_then(|body| {
                body.get("resource")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .is_some_and(|resource| resource == "model:fast-chat");
        let reason = if allowed {
            "third_party_policy_allow"
        } else {
            "third_party_policy_deny"
        };
        return format!(
            r#"{{"allowed":{allowed},"tenant":{{"organization_id":"org_demo","team_id":null,"project_id":"project_gateway","user_id":null,"api_key_id":"client"}},"reason":"{reason}"}}"#
        );
    }
    r#"{"error":{"code":"not_found","message":"third-party auth mock endpoint not found"}}"#
        .to_string()
}

fn read_http_request(stream: &mut TcpStream) -> Result<String> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            let text = String::from_utf8_lossy(&request).to_string();
            let content_length = text
                .lines()
                .find_map(|line| {
                    line.strip_prefix("Content-Length:")
                        .or_else(|| line.strip_prefix("content-length:"))
                })
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let header_len = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|position| position + 4)
                .unwrap_or(request.len());
            while request.len().saturating_sub(header_len) < content_length {
                let read = stream.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            break;
        }
    }
    Ok(String::from_utf8_lossy(&request).to_string())
}

fn extract_jsonrpc_id(request: &str) -> serde_json::Value {
    http_request_body(request)
        .ok()
        .and_then(|body| serde_json::from_str::<serde_json::Value>(body).ok())
        .and_then(|body| body.get("id").cloned())
        .unwrap_or(serde_json::Value::Null)
}

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

fn gateway_config(node_id: &str, state_backend: &str, file_state_path: Option<&str>) -> String {
    let file_state_path = file_state_path
        .map(|path| format!("file_state_path = \"{path}\"\n"))
        .unwrap_or_default();
    format!(
        r#"
listen = "0.0.0.0:8080"

[cluster]
enabled = true
cluster_id = "e2e-cluster"
node_id = "{node_id}"
node_region = "local"
node_zone = "local-a"
state_backend = "{state_backend}"
{file_state_path}counter_backend = "local"
heartbeat_interval_secs = 10
config_poll_interval_secs = 5

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://ferrogate-e2e-provider:8081/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["models.read", "chat.completions"]
allowed_models = ["fast-chat"]

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
"#
    )
}

fn guardrail_gateway_config() -> String {
    r#"
listen = "0.0.0.0:8080"

[cluster]
enabled = true
cluster_id = "e2e-cluster"
node_id = "e2e-node-a"
node_region = "local"
node_zone = "local-a"
state_backend = "local"
counter_backend = "local"

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://ferrogate-e2e-provider:8081/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]

[[api_keys]]
id = "client"
name = "Client"
key = "client-secret"
scopes = ["models.read", "chat.completions"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
project_id = "project_gateway"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[[guardrails]]
id = "block-secret"
name = "Block secret"
stage = "request"
organization_ids = ["org_demo"]
project_ids = ["project_gateway"]
api_key_ids = ["client"]
models = ["fast-chat"]
providers = ["openai"]
keywords = ["secret"]
effect = "deny"
code = "guardrail_blocked"
message = "blocked by guardrail"
enabled = true
"#
    .to_string()
}

fn guardrail_response_gateway_config() -> String {
    r#"
listen = "0.0.0.0:8080"

[cluster]
enabled = true
cluster_id = "e2e-cluster"
node_id = "e2e-node-a"
node_region = "local"
node_zone = "local-a"
state_backend = "local"
counter_backend = "local"

[telemetry]
log_bodies = true

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://ferrogate-e2e-provider:8081/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]

[[api_keys]]
id = "client"
name = "Client"
key = "client-secret"
scopes = ["models.read", "chat.completions"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
project_id = "project_gateway"
log_bodies = true

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[[guardrails]]
id = "redact-provider-output"
name = "Redact provider output"
stage = "response"
organization_ids = ["org_demo"]
project_ids = ["project_gateway"]
api_key_ids = ["client"]
models = ["fast-chat"]
providers = ["openai"]
keywords = ["secret"]
effect = "redact"
code = "guardrail_redacted"
message = "response redacted by guardrail"
enabled = true
"#
    .to_string()
}

fn guardrail_complete_gateway_config() -> String {
    r#"
listen = "0.0.0.0:8080"

[cluster]
enabled = true
cluster_id = "e2e-cluster"
node_id = "e2e-node-a"
node_region = "local"
node_zone = "local-a"
state_backend = "local"
counter_backend = "local"

[telemetry]
log_bodies = true

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://ferrogate-e2e-provider:8081/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat", "streaming"]

[[api_keys]]
id = "client"
name = "Client"
key = "client-secret"
scopes = ["models.read", "chat.completions"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
project_id = "project_gateway"
log_bodies = true

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[[guardrails]]
id = "block-ticket-regex"
name = "Block ticket regex"
stage = "request"
organization_ids = ["org_demo"]
project_ids = ["project_gateway"]
api_key_ids = ["client"]
models = ["fast-chat"]
providers = ["openai"]
regex = ["ABC-[0-9]+"]
effect = "deny"
code = "guardrail_regex_blocked"
message = "blocked by regex guardrail"
enabled = true

[[guardrails]]
id = "limit-request-size"
name = "Limit request size"
stage = "request"
organization_ids = ["org_demo"]
project_ids = ["project_gateway"]
api_key_ids = ["client"]
models = ["fast-chat"]
providers = ["openai"]
max_input_bytes = 120
effect = "deny"
code = "guardrail_input_too_large"
message = "input is too large"
enabled = true

[[guardrails]]
id = "block-provider-output"
name = "Block provider output"
stage = "response"
organization_ids = ["org_demo"]
project_ids = ["project_gateway"]
api_key_ids = ["client"]
models = ["fast-chat"]
providers = ["openai"]
keywords = ["deny-output"]
effect = "deny"
code = "guardrail_response_blocked"
message = "response blocked by guardrail"
enabled = true

[[guardrails]]
id = "redact-stream-output"
name = "Redact stream output"
stage = "response"
organization_ids = ["org_demo"]
project_ids = ["project_gateway"]
api_key_ids = ["client"]
models = ["fast-chat"]
providers = ["openai"]
regex = ["stream-secret"]
effect = "redact"
code = "guardrail_stream_redacted"
message = "stream redacted by guardrail"
enabled = true
"#
    .to_string()
}

fn redis_counter_gateway_config(node_id: &str) -> String {
    format!(
        r#"
listen = "0.0.0.0:8080"

[cluster]
enabled = true
cluster_id = "e2e-cluster"
node_id = "{node_id}"
node_region = "local"
node_zone = "local-a"
state_backend = "local"
counter_backend = "redis"
redis_url = "redis://ferrogate-e2e-redis:6379/0"
counter_timeout_millis = 500
heartbeat_interval_secs = 10
config_poll_interval_secs = 5

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://ferrogate-e2e-provider:8081/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]

[[api_keys]]
id = "redis_rate"
name = "Redis rate limit"
key = "redis-rate-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
request_limit_per_minute = 1

[[api_keys]]
id = "redis_budget"
name = "Redis budget"
key = "redis-budget-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
monthly_token_budget = 8

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
"#
    )
}

fn analytics_gateway_config() -> String {
    r#"
listen = "0.0.0.0:8080"

[cluster]
enabled = true
cluster_id = "e2e-cluster"
node_id = "e2e-node-a"
node_region = "local"
node_zone = "local-a"
state_backend = "local"
counter_backend = "local"

[analytics]
enabled = true
provider = "vector"
required = true
vector_endpoint = "http://ferrogate-e2e-vector:4319"
export_timeout_secs = 3
batch_max_events = 256
flush_interval_millis = 500
queue_capacity = 1024

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://ferrogate-e2e-provider:8081/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]
input_price_per_1m = 1.0
output_price_per_1m = 2.0

[[api_keys]]
id = "client"
name = "Client"
key = "client-secret"
scopes = ["models.read", "chat.completions"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
project_id = "project_gateway"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
"#
    .to_string()
}

fn analytics_direct_clickhouse_gateway_config() -> String {
    r#"
listen = "0.0.0.0:8080"

[cluster]
enabled = true
cluster_id = "e2e-cluster"
node_id = "e2e-node-a"
node_region = "local"
node_zone = "local-a"
state_backend = "local"
counter_backend = "local"

[analytics]
enabled = true
provider = "clickhouse"
required = true
clickhouse_url = "http://ferrogate-e2e-clickhouse:8123"
export_timeout_secs = 3
batch_max_events = 256
flush_interval_millis = 500
queue_capacity = 1024

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://ferrogate-e2e-provider:8081/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]
input_price_per_1m = 1.0
output_price_per_1m = 2.0

[[api_keys]]
id = "client"
name = "Client"
key = "client-secret"
scopes = ["models.read", "chat.completions"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
project_id = "project_gateway"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
"#
    .to_string()
}

fn vector_clickhouse_config() -> String {
    r#"
[sources.ferrogate_analytics]
type = "http_server"
address = "0.0.0.0:4319"
framing.method = "newline_delimited"
decoding.codec = "json"

[transforms.request_logs_filter]
type = "filter"
inputs = ["ferrogate_analytics"]
condition = '.event_kind == "request_log"'

[transforms.trace_spans_filter]
type = "filter"
inputs = ["ferrogate_analytics"]
condition = '.event_kind == "trace_span"'

[transforms.usage_metrics_filter]
type = "filter"
inputs = ["ferrogate_analytics"]
condition = '.event_kind == "usage_metric"'

[transforms.billing_metering_events_filter]
type = "filter"
inputs = ["ferrogate_analytics"]
condition = '.event_kind == "billing_metering_event"'

[transforms.audit_timeline_filter]
type = "filter"
inputs = ["ferrogate_analytics"]
condition = '.event_kind == "audit_event"'

[sinks.request_logs]
type = "clickhouse"
inputs = ["request_logs_filter"]
endpoint = "http://ferrogate-e2e-clickhouse:8123"
database = "ferrogate"
table = "ferrogate_request_logs"
format = "json_each_row"
skip_unknown_fields = true

[sinks.trace_spans]
type = "clickhouse"
inputs = ["trace_spans_filter"]
endpoint = "http://ferrogate-e2e-clickhouse:8123"
database = "ferrogate"
table = "ferrogate_trace_spans"
format = "json_each_row"
skip_unknown_fields = true

[sinks.usage_metrics]
type = "clickhouse"
inputs = ["usage_metrics_filter"]
endpoint = "http://ferrogate-e2e-clickhouse:8123"
database = "ferrogate"
table = "ferrogate_usage_metrics"
format = "json_each_row"
skip_unknown_fields = true

[sinks.billing_metering_events]
type = "clickhouse"
inputs = ["billing_metering_events_filter"]
endpoint = "http://ferrogate-e2e-clickhouse:8123"
database = "ferrogate"
table = "ferrogate_billing_metering_events"
format = "json_each_row"
skip_unknown_fields = true

[sinks.audit_timeline]
type = "clickhouse"
inputs = ["audit_timeline_filter"]
endpoint = "http://ferrogate-e2e-clickhouse:8123"
database = "ferrogate"
table = "ferrogate_audit_timeline"
format = "json_each_row"
skip_unknown_fields = true
"#
    .to_string()
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

fn wait_for_postgres_server() -> Result<()> {
    wait_for_postgres_server_named(POSTGRES_CONTAINER)
}

fn wait_for_postgres_server_named(container_name: &str) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(30) {
        if Command::new("docker")
            .args([
                "exec",
                container_name,
                "pg_isready",
                "-U",
                "postgres",
                "-d",
                "ferrogate",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(500));
    }
    let logs = Command::new("docker")
        .args(["logs", container_name, "--tail", "120"])
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stderr).to_string())
        .unwrap_or_default();
    bail!("timed out waiting for local PostgreSQL server; logs: {logs}");
}

fn wait_for_postgres_query() -> Result<()> {
    wait_for_postgres_query_named(POSTGRES_CONTAINER)
}

fn wait_for_postgres_query_named(container_name: &str) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(30) {
        if Command::new("docker")
            .args([
                "exec",
                "-e",
                "PGPASSWORD=postgres",
                container_name,
                "psql",
                "-U",
                "postgres",
                "-d",
                "ferrogate",
                "-c",
                "select 1",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(500));
    }
    let logs = Command::new("docker")
        .args(["logs", container_name, "--tail", "120"])
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stderr).to_string())
        .unwrap_or_default();
    bail!("timed out waiting for local PostgreSQL query readiness; logs: {logs}");
}

fn expect_supabase_schema_migrations(schema: &str) -> Result<()> {
    let expected_tables = [
        "control_plane_resources",
        "agent_runs",
        "agent_run_events",
        "request_logs",
        "audit_events",
        "billing_metering_events",
        "usage_aggregates",
        "tenant_contexts",
        "metering_events",
        "metering_event_routes",
        "metering_event_usage",
        "usage_aggregate_rollups",
        "storage_schema_migrations",
    ];
    for table in expected_tables {
        let count = postgres_scalar(&format!(
            "SELECT count(*) FROM information_schema.tables \
             WHERE table_schema = '{}' AND table_name = '{}'",
            sql_literal(schema),
            sql_literal(table)
        ))?;
        if count.trim() != "1" {
            bail!("expected Supabase schema table {schema}.{table}, got count {count}");
        }
    }

    let jsonb_columns = [
        ("control_plane_resources", "document_json"),
        ("agent_runs", "run_json"),
        ("agent_run_events", "event_json"),
        ("request_logs", "request_json"),
        ("audit_events", "audit_json"),
    ];
    for (table, column) in jsonb_columns {
        let data_type = postgres_scalar(&format!(
            "SELECT data_type FROM information_schema.columns \
             WHERE table_schema = '{}' AND table_name = '{}' AND column_name = '{}'",
            sql_literal(schema),
            sql_literal(table),
            sql_literal(column)
        ))?;
        if data_type.trim() != "jsonb" {
            bail!("expected {schema}.{table}.{column} to be jsonb, got {data_type}");
        }
    }

    let expected_indexes = [
        "idx_control_plane_resources_document_gin",
        "idx_agent_runs_tenant_started",
        "idx_agent_run_events_run_time",
        "idx_request_logs_model_provider_started",
        "idx_audit_events_actor_time",
        "idx_billing_metering_model_provider_time",
        "idx_usage_aggregates_tenant_model_provider",
        "idx_tenant_contexts_api_key",
        "idx_metering_events_tenant_time",
        "idx_metering_event_routes_model_provider",
        "idx_usage_rollups_tenant_model_provider",
    ];
    for index in expected_indexes {
        let count = postgres_scalar(&format!(
            "SELECT count(*) FROM pg_indexes \
             WHERE schemaname = '{}' AND indexname = '{}'",
            sql_literal(schema),
            sql_literal(index)
        ))?;
        if count.trim() != "1" {
            bail!("expected Supabase schema index {schema}.{index}, got count {count}");
        }
    }

    let migration_versions = postgres_scalar(&format!(
        "SELECT string_agg(version::text || ':' || name, ',' ORDER BY version) \
         FROM {}.storage_schema_migrations \
         WHERE version IN (1, 2, 3)",
        quote_ident(schema)
    ))?;
    if migration_versions.trim()
        != "1:001_init_postgres,2:002_supabase_control_plane_billing_evidence,3:003_supabase_structured_metering_usage"
    {
        bail!("unexpected Supabase migration versions: {migration_versions}");
    }

    Ok(())
}

fn postgres_scalar(query: &str) -> Result<String> {
    let output = Command::new("docker")
        .args([
            "exec",
            "-e",
            "PGPASSWORD=postgres",
            POSTGRES_CONTAINER,
            "psql",
            "-U",
            "postgres",
            "-d",
            "ferrogate",
            "-At",
            "-c",
            query,
        ])
        .stdin(Stdio::null())
        .output()
        .context("failed to query local PostgreSQL container")?;
    if !output.status.success() {
        bail!(
            "PostgreSQL query failed with {}; stdout: {}; stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn sql_literal(value: &str) -> String {
    value.replace('\'', "''")
}

fn quote_ident(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn wait_for_mysql_server() -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(60) {
        if Command::new("docker")
            .args([
                "exec",
                MYSQL_CONTAINER,
                "mysqladmin",
                "ping",
                "--protocol=tcp",
                "-h127.0.0.1",
                "-P3306",
                "-uroot",
                "-pmysql",
                "--silent",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(500));
    }
    let logs = Command::new("docker")
        .args(["logs", MYSQL_CONTAINER, "--tail", "160"])
        .output()
        .ok()
        .map(|output| {
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })
        .unwrap_or_default();
    bail!("timed out waiting for local MySQL server; logs: {logs}");
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

fn stop_postgres_container() {
    stop_postgres_container_named(POSTGRES_CONTAINER);
}

fn stop_postgres_container_named(container_name: &str) {
    let _ = Command::new("docker")
        .args(["rm", "-f", container_name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn stop_mysql_container() {
    let _ = Command::new("docker")
        .args(["rm", "-f", MYSQL_CONTAINER])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
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

struct PostgresCleanup;

impl Drop for PostgresCleanup {
    fn drop(&mut self) {
        if env::var("FERROGATE_TEST_KEEP_CONTAINERS").is_ok_and(|value| value == "1") {
            return;
        }
        stop_postgres_container();
    }
}

struct PostgresMigrationCleanup;

impl Drop for PostgresMigrationCleanup {
    fn drop(&mut self) {
        if env::var("FERROGATE_TEST_KEEP_CONTAINERS").is_ok_and(|value| value == "1") {
            return;
        }
        stop_postgres_container_named(POSTGRES_MIGRATION_SOURCE_CONTAINER);
        stop_postgres_container_named(POSTGRES_MIGRATION_TARGET_CONTAINER);
    }
}

struct MySqlCleanup;

impl Drop for MySqlCleanup {
    fn drop(&mut self) {
        if env::var("FERROGATE_TEST_KEEP_CONTAINERS").is_ok_and(|value| value == "1") {
            return;
        }
        stop_mysql_container();
    }
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
