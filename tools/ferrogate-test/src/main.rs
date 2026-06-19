// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::Value;
use std::{
    env,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const IMAGE_TAG: &str = "ferrogate:e2e-local";
const NETWORK_NAME: &str = "ferrogate-e2e-net";
const PROVIDER_CONTAINER: &str = "ferrogate-e2e-provider";
const REDIS_CONTAINER: &str = "ferrogate-e2e-redis";
const CLICKHOUSE_CONTAINER: &str = "ferrogate-e2e-clickhouse";
const VECTOR_CONTAINER: &str = "ferrogate-e2e-vector";
const GATEWAY_A_CONTAINER: &str = "ferrogate-e2e-gateway-a";
const GATEWAY_B_CONTAINER: &str = "ferrogate-e2e-gateway-b";
const GATEWAY_A_PORT: u16 = 18080;
const GATEWAY_B_PORT: u16 = 18081;

fn main() -> Result<()> {
    print_attribution_banner();
    let cli = Cli::parse();
    match cli.command {
        Commands::List => {
            println!("local: admin-api, auth-api, gateway-api, ci, turso-libsql-restart (opt-in)");
            println!("docker: {}", DockerScenario::names().join(", "));
            Ok(())
        }
        Commands::Run(args) => run_docker_scenario(args.scenario, &args.image),
        Commands::RunAll(args) => {
            run_admin_api(&args.local)?;
            run_auth_api(&args.auth)?;
            run_gateway_api(&args.local)?;
            if args.include_docker {
                run_all_docker_scenarios(&args.image)?;
            }
            Ok(())
        }
        Commands::AdminApi(args) => run_admin_api(&args),
        Commands::AuthApi(args) => run_auth_api(&args),
        Commands::GatewayApi(args) => run_gateway_api(&args),
        Commands::TursoLibsqlRestart(args) => run_turso_libsql_restart(&args),
        Commands::Ci(args) => {
            run_admin_api(&args.local)?;
            run_auth_api(&args.auth)?;
            run_gateway_api(&args.local)
        }
    }
}

fn print_attribution_banner() {
    println!("Token4AI Cloud Attribution");
    println!(
        "Developed by the commercial cloud service company represented by https://token4ai.cloud."
    );
    println!("Author: jamesduan (X: https://x.com/JamesDuanL)");
    println!("Created: 2026-06-11");
    println!(
        "description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure."
    );
    println!();
}

#[derive(Debug, Parser)]
#[command(name = "ferrogate-test")]
#[command(author = "jamesduan <https://x.com/JamesDuanL>")]
#[command(version)]
#[command(about = "FerroGate end-to-end test harness for admin, auth, and gateway APIs")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// List available local and Docker-backed scenarios.
    List,
    /// Run one Docker-backed cluster/container scenario.
    Run(DockerRunArgs),
    /// Run the full local API harness and optionally the Docker scenario set.
    RunAll(RunAllArgs),
    /// Run Admin API coverage against a real local FerroGate process.
    AdminApi(LocalArgs),
    /// Run auth service coverage against a real local ferrogate-auth process.
    AuthApi(AuthArgs),
    /// Run gateway API coverage against a real local FerroGate process.
    GatewayApi(LocalArgs),
    /// Opt-in live Turso/libSQL restart durability scenario.
    TursoLibsqlRestart(TursoLibsqlRestartArgs),
    /// CI entrypoint: run deterministic local Admin API, auth API, and gateway API E2E coverage.
    Ci(CiArgs),
}

#[derive(Debug, Args)]
struct DockerRunArgs {
    #[arg(value_enum)]
    scenario: DockerScenario,
    /// Docker image to verify. Defaults to a local build tag, but may point at a GHCR image.
    #[arg(long, env = "FERROGATE_TEST_IMAGE", default_value = IMAGE_TAG)]
    image: String,
}

#[derive(Debug, Args)]
struct RunAllArgs {
    #[command(flatten)]
    local: LocalArgs,
    #[command(flatten)]
    auth: AuthArgs,
    /// Also run Docker-backed cluster, shared-state, and Redis scenarios.
    #[arg(long)]
    include_docker: bool,
    /// Docker image to verify. Defaults to a local build tag, but may point at a GHCR image.
    #[arg(long, env = "FERROGATE_TEST_IMAGE", default_value = IMAGE_TAG)]
    image: String,
}

#[derive(Debug, Args)]
struct LocalArgs {
    /// Path to a built ferrogate binary. Defaults to target/debug/ferrogate.
    #[arg(
        long,
        env = "FERROGATE_TEST_FERROGATE_BIN",
        default_value = "target/debug/ferrogate"
    )]
    ferrogate_bin: PathBuf,
}

#[derive(Debug, Args)]
struct AuthArgs {
    /// Path to a built ferrogate-auth binary. Defaults to target/debug/ferrogate-auth.
    #[arg(
        long,
        env = "FERROGATE_TEST_FERROGATE_AUTH_BIN",
        default_value = "target/debug/ferrogate-auth"
    )]
    ferrogate_auth_bin: PathBuf,
}

#[derive(Debug, Args)]
struct CiArgs {
    #[command(flatten)]
    local: LocalArgs,
    #[command(flatten)]
    auth: AuthArgs,
}

#[derive(Debug, Args)]
struct TursoLibsqlRestartArgs {
    #[command(flatten)]
    local: LocalArgs,
    /// Turso/libSQL remote database URL, for example libsql://database.turso.io.
    #[arg(long, env = "FERROGATE_LIBSQL_URL")]
    libsql_url: String,
    /// Turso/libSQL auth token. Prefer FERROGATE_LIBSQL_AUTH_TOKEN in shell/CI.
    #[arg(long, env = "FERROGATE_LIBSQL_AUTH_TOKEN")]
    libsql_auth_token: String,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum DockerScenario {
    AnalyticsVectorClickhouse,
    ClusterDrain,
    GuardrailComplete,
    GuardrailRequestDeny,
    GuardrailResponseRedact,
    SharedApiKey,
    SharedStateStale,
    SharedStateStartupUnavailable,
    RedisCounters,
}

impl DockerScenario {
    fn names() -> &'static [&'static str] {
        &[
            "analytics-vector-clickhouse",
            "cluster-drain",
            "guardrail-complete",
            "guardrail-request-deny",
            "guardrail-response-redact",
            "shared-api-key",
            "shared-state-stale",
            "shared-state-startup-unavailable",
            "redis-counters",
        ]
    }
}

fn run_docker_scenario(scenario: DockerScenario, image: &str) -> Result<()> {
    match scenario {
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
        assert_eq!(body["storage"]["contract_version"], 1);
        assert_eq!(body["storage"]["provider_order"][0], "turso_libsql");
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
    let case = LocalHarness::start_with_billing(&args.ferrogate_bin, 3)?;

    case.expect_json("GET", "/v1/models", &[CLIENT_AUTH], "", 200, |body| {
        assert!(list_contains(&body, "id", "fast-chat"));
        Ok(())
    })?;
    case.expect_json("GET", "/v1/models", &[], "", 401, |body| {
        assert_eq!(body["error"]["code"], "missing_api_key");
        Ok(())
    })?;
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
                .find(|record| record["route"] == "openai.chat.completions")
                .context("missing chat completion export record")?;
            assert_eq!(chat["object"], "request_log_export");
            assert_eq!(chat["tenant"]["organization_id"], "org_demo");
            assert_eq!(chat["tenant"]["project_id"], "project_gateway");
            assert_eq!(chat["logical_model"], "fast-chat");
            assert_eq!(chat["provider"], "openai");
            assert_eq!(chat["provider_model"], "gpt-4o-mini");
            assert_eq!(chat["status_code"], 200);
            assert_eq!(chat["usage"]["total_tokens"], 2);
            assert_eq!(chat["prompt_recorded"], true);
            assert_eq!(chat["response_recorded"], true);
            assert!(chat["prompt_body"]
                .as_str()
                .is_some_and(|prompt| prompt.contains("[REDACTED]")));
            assert!(records
                .iter()
                .any(|record| record["route"] == "openai.responses"));
            assert_secret_redacted(body);
            assert!(!body.contains("provider-secret"));
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
            assert_eq!(body["result"]["content"][0]["type"], "text");
            assert_eq!(body["result"]["content"][0]["text"], "ferrogate-result");
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

    println!("gateway-api scenario passed");
    Ok(())
}

fn run_turso_libsql_restart(args: &TursoLibsqlRestartArgs) -> Result<()> {
    if !args.libsql_url.starts_with("libsql://") {
        bail!("--libsql-url must use the libsql:// protocol");
    }
    if args.libsql_auth_token.trim().is_empty() {
        bail!("--libsql-auth-token must not be empty");
    }

    let resource_id = format!(
        "ferrogate-test-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before UNIX epoch")?
            .as_millis()
    );
    let request_body = serde_json::json!({
        "id": resource_id,
        "name": "Turso restart test key",
        "key": format!("{resource_id}-secret"),
        "scopes": ["models.read", "chat.completions"],
        "allowed_models": ["fast-chat"],
        "organization_id": "org_turso_e2e",
        "project_id": "project_restart"
    })
    .to_string();

    {
        let case = TursoRestartHarness::start(args)?;
        case.expect_storage_status()?;
        case.expect_json(
            "POST",
            "/admin/v1/api-keys",
            &[ADMIN_AUTH, JSON_CONTENT],
            &request_body,
            201,
            |body| {
                assert_eq!(body["key"]["id"], resource_id);
                assert_eq!(body["key"]["key_source"], "inline");
                assert_secret_redacted(&body.to_string());
                Ok(())
            },
        )?;
        case.expect_api_key(&resource_id)?;
    }

    {
        let case = TursoRestartHarness::start(args)?;
        case.expect_storage_status()?;
        case.expect_api_key(&resource_id)?;
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

    println!("turso-libsql-restart scenario passed");
    Ok(())
}

const ADMIN_AUTH: &str = "Authorization: Bearer admin-secret";
const CLIENT_AUTH: &str = "Authorization: Bearer client-secret";
const AUTH_TEST_CLIENT_2: &str = "Authorization: Bearer test-secret-2";
const JSON_CONTENT: &str = "Content-Type: application/json";

struct LocalHarness {
    _dir: tempfile::TempDir,
    gateway_addr: String,
    gateway: Child,
    provider: Option<JoinHandle<Vec<String>>>,
    mcp_server: Option<JoinHandle<Vec<String>>>,
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

struct AuthHarness {
    _dir: tempfile::TempDir,
    auth_addr: String,
    auth: Child,
}

struct TursoRestartHarness {
    _dir: tempfile::TempDir,
    gateway_addr: String,
    gateway: Child,
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
    fn start(args: &TursoLibsqlRestartArgs) -> Result<Self> {
        let ferrogate_bin = &args.local.ferrogate_bin;
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
            turso_libsql_restart_config(&gateway_addr, &args.libsql_url),
        )?;

        let gateway = Command::new(ferrogate_bin)
            .args(["run", "--config"])
            .arg(&config_path)
            .env("FERROGATE_LIBSQL_AUTH_TOKEN", &args.libsql_auth_token)
            .env("FERROGATE_PROVIDER_SECRET", "provider-secret")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("failed to start {}", ferrogate_bin.display()))?;

        let mut harness = Self {
            _dir: dir,
            gateway_addr,
            gateway,
        };
        harness.wait_for_gateway()?;
        Ok(harness)
    }

    fn wait_for_gateway(&mut self) -> Result<()> {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < Duration::from_secs(60) {
            if let Some(status) = self.gateway.try_wait()? {
                bail!("ferrogate process exited before readiness check: {status}");
            }
            match http_request_addr(&self.gateway_addr, "GET", "/healthz", &[], "") {
                Ok(response) if response.status == 200 => return Ok(()),
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(250));
        }
        bail!(
            "timed out waiting for Turso/libSQL FerroGate on {}; last response: {last}",
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

    fn expect_storage_status(&self) -> Result<()> {
        self.expect_json("GET", "/admin/v1/status", &[ADMIN_AUTH], "", 200, |body| {
            assert_eq!(body["storage"]["provider"], "turso_libsql");
            assert_eq!(body["storage"]["durable"], true);
            assert_eq!(body["storage"]["implemented"], true);
            assert_eq!(body["storage"]["required"], true);
            assert_eq!(body["storage"]["provider_order"][0], "turso_libsql");
            assert_eq!(body["storage"]["provider_order"][1], "postgres");
            assert_eq!(body["storage"]["provider_order"][2], "mysql");
            assert_secret_redacted(&body.to_string());
            Ok(())
        })
    }

    fn expect_api_key(&self, id: &str) -> Result<()> {
        self.expect_json(
            "GET",
            &format!("/admin/v1/api-keys/{id}"),
            &[ADMIN_AUTH],
            "",
            200,
            |body| {
                assert_eq!(body["key"]["id"], id);
                assert_eq!(body["key"]["name"], "Turso restart test key");
                assert_eq!(body["key"]["key_source"], "inline");
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
        Self::start_inner(ferrogate_bin, expected_provider_requests, None)
    }

    fn start_with_billing(ferrogate_bin: &Path, expected_provider_requests: usize) -> Result<Self> {
        let billing = spawn_mock_billing_server(expected_provider_requests)
            .context("start billing provider")?;
        Self::start_inner(ferrogate_bin, expected_provider_requests, Some(billing))
    }

    fn start_inner(
        ferrogate_bin: &Path,
        expected_provider_requests: usize,
        billing: Option<MockBillingServer>,
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
        let dir = tempfile::tempdir()?;
        let stdio_mcp_path = dir.path().join("blocking-stdio-mcp.py");
        std::fs::write(&stdio_mcp_path, blocking_stdio_mcp_script())?;
        let observability =
            spawn_mock_otlp_server().context("start observability provider mock")?;
        let config_path = dir.path().join("ferrogate.toml");
        std::fs::write(
            &config_path,
            local_gateway_config(
                &gateway_addr,
                &provider_addr,
                &mcp_addr,
                &stdio_mcp_path,
                billing.as_ref(),
                Some(&observability),
            ),
        )?;

        let gateway = Command::new(ferrogate_bin)
            .args(["run", "--config"])
            .arg(&config_path)
            .env("FERROGATE_PROVIDER_SECRET", "provider-secret")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("failed to start {}", ferrogate_bin.display()))?;

        let mut harness = Self {
            _dir: dir,
            gateway_addr,
            gateway,
            provider: Some(provider),
            mcp_server: Some(mcp_server),
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
        if let Some(billing) = self.billing.as_mut() {
            let _ = billing.handle.take().map(|handle| handle.join());
        }
        if let Some(observability) = self.observability.as_mut() {
            let _ = observability.handle.take().map(|handle| handle.join());
        }
    }
}

fn local_gateway_config(
    gateway_addr: &str,
    provider_addr: &str,
    mcp_addr: &str,
    stdio_mcp_path: &Path,
    billing: Option<&MockBillingServer>,
    observability: Option<&MockOtlpServer>,
) -> String {
    let metering = billing
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
    let observability = observability
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

[telemetry]
service_name = "ferrogate-test"
log_bodies = true

[reliability]
mcp_dispatch_timeout_secs = 1
mcp_dispatch_max_concurrency = 4

[[providers]]
name = "openai"
kind = "openai"
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

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat", "streaming"]
input_price_per_1m = 1.0
output_price_per_1m = 2.0

[[api_keys]]
id = "client"
name = "Client"
key = "client-secret"
scopes = ["models.read", "chat.completions", "responses.create", "admin.read", "tools.read", "tools.execute"]
allowed_models = ["fast-chat"]
organization_id = "org_demo"
project_id = "project_gateway"
log_bodies = true

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
        stdio_mcp_path = toml_basic_string(&stdio_mcp_path.to_string_lossy())
    )
}

fn turso_libsql_restart_config(gateway_addr: &str, libsql_url: &str) -> String {
    format!(
        r#"
listen: "{gateway_addr}"

storage:
  provider: turso_libsql
  required: true
  provider_order:
    - turso_libsql
    - postgres
    - mysql
  libsql_url: "{libsql_url}"
  libsql_auth_token_env: FERROGATE_LIBSQL_AUTH_TOKEN
  migration_mode: auto

providers:
  - name: openai
    kind: openai
    base_url: "http://127.0.0.1:1/v1"
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
"#
    )
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
roles:
  - id: role-chat-caller
    name: Chat caller
    permissions:
      - action: chat.completions
        resource: model:fast-chat
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
"#
    .to_string()
}

fn free_addr() -> Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.to_string())
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

fn http_request_body(request: &str) -> Result<&str> {
    request
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .ok_or_else(|| anyhow!("HTTP request body separator not found"))
}

fn parse_jsonl(body: &str) -> Result<Vec<Value>> {
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .with_context(|| format!("failed to parse JSONL line: {line}"))
        })
        .collect()
}

fn list_contains(body: &Value, field: &str, expected: &str) -> bool {
    body.get("data")
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().any(|item| item[field] == expected))
}

fn admin_list_item<'a>(body: &'a Value, field: &str, expected: &str) -> Option<&'a Value> {
    body.get("data")
        .and_then(Value::as_array)
        .and_then(|items| items.iter().find(|item| item[field] == expected))
}

fn assert_mcp_tool_present(body: &Value, name: &str, description: &str) -> Result<()> {
    let tools = body["result"]["tools"]
        .as_array()
        .context("MCP tools/list result must contain a tools array")?;
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == name)
        .with_context(|| format!("MCP tool {name} missing from tools/list response: {body}"))?;
    assert_eq!(tool["description"], description);
    assert_eq!(tool["inputSchema"]["type"], "object");
    Ok(())
}

fn array_contains(body: &Value, array_field: &str, item_field: &str, expected: &str) -> bool {
    body.get(array_field)
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().any(|item| item[item_field] == expected))
}

fn assert_secret_redacted(raw: &str) {
    for secret in [
        "admin-secret",
        "client-secret",
        "test-secret",
        "test-secret-2",
        "provider-secret",
        "Bearer",
    ] {
        assert!(!raw.contains(secret), "secret leaked in response: {secret}");
    }
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
        docker(["build", "-t", IMAGE_TAG, "."])?;
    } else {
        docker(["pull", image])?;
    }
    Ok(cleanup)
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

fn vector_clickhouse_config() -> String {
    r#"
[sources.ferrogate_analytics]
type = "http_server"
address = "0.0.0.0:4319"
framing.method = "newline_delimited"
decoding.codec = "json"

[transforms.request_logs]
type = "filter"
inputs = ["ferrogate_analytics"]
condition = '.event_kind == "request_log"'

[transforms.trace_spans]
type = "filter"
inputs = ["ferrogate_analytics"]
condition = '.event_kind == "trace_span"'

[transforms.usage_metrics]
type = "filter"
inputs = ["ferrogate_analytics"]
condition = '.event_kind == "usage_metric"'

[transforms.billing_metering_events]
type = "filter"
inputs = ["ferrogate_analytics"]
condition = '.event_kind == "billing_metering_event"'

[transforms.audit_timeline]
type = "filter"
inputs = ["ferrogate_analytics"]
condition = '.event_kind == "audit_event"'

[sinks.request_logs]
type = "clickhouse"
inputs = ["request_logs"]
endpoint = "http://ferrogate-e2e-clickhouse:8123"
database = "ferrogate"
table = "ferrogate_request_logs"
format = "json_each_row"
skip_unknown_fields = true

[sinks.trace_spans]
type = "clickhouse"
inputs = ["trace_spans"]
endpoint = "http://ferrogate-e2e-clickhouse:8123"
database = "ferrogate"
table = "ferrogate_trace_spans"
format = "json_each_row"
skip_unknown_fields = true

[sinks.usage_metrics]
type = "clickhouse"
inputs = ["usage_metrics"]
endpoint = "http://ferrogate-e2e-clickhouse:8123"
database = "ferrogate"
table = "ferrogate_usage_metrics"
format = "json_each_row"
skip_unknown_fields = true

[sinks.billing_metering_events]
type = "clickhouse"
inputs = ["billing_metering_events"]
endpoint = "http://ferrogate-e2e-clickhouse:8123"
database = "ferrogate"
table = "ferrogate_billing_metering_events"
format = "json_each_row"
skip_unknown_fields = true

[sinks.audit_timeline]
type = "clickhouse"
inputs = ["audit_timeline"]
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
        "CLICKHOUSE_USER=default",
        "-e",
        "CLICKHOUSE_PASSWORD=",
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

struct HttpResponse {
    status: u16,
    body: String,
    raw: String,
}

fn http_request(
    host_port: u16,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &str,
) -> Result<HttpResponse> {
    http_request_addr(
        &format!("127.0.0.1:{host_port}"),
        method,
        path,
        headers,
        body,
    )
}

fn http_request_addr(
    addr: &str,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &str,
) -> Result<HttpResponse> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    )?;
    for header in headers {
        write!(stream, "{header}\r\n")?;
    }
    write!(stream, "\r\n{body}")?;

    let mut raw = String::new();
    stream.read_to_string(&mut raw)?;
    let status = raw
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("HTTP response missing status: {raw}"))?;
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    Ok(HttpResponse { status, body, raw })
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
        cleanup_containers();
    }
}
