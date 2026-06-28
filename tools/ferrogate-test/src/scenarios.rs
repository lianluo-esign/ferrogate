// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use crate::{
    assertions::*,
    cli::{AuthArgs, LocalArgs},
    constants::{
        ADMIN_AUTH, AUTH_TEST_CLIENT_2, CLIENT_AUTH, JSON_CONTENT, OBSERVER_AUTH,
        SUPPORT_SKILL_HEADER,
    },
    local::{AuthHarness, LocalHarness},
    mocks::spawn_mock_third_party_auth_server,
};
use anyhow::{Context, Result};
use std::{thread, time::Duration};

pub(crate) fn run_admin_api(args: &LocalArgs) -> Result<()> {
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
        "/admin/v1/managed-workers",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["data"][0]["process_name"], "agent-worker");
            assert_eq!(body["data"][0]["process_boundary"], "external_process");
            assert_eq!(
                body["data"][0]["agent_worker_role"],
                "microvm_lifecycle_controller"
            );
            assert_eq!(body["data"][0]["capability_boundary"], "gateway_mediated");
            assert_eq!(
                body["data"][0]["isolation_backends"][0]["kind"],
                "firecracker_microvm"
            );
            assert_eq!(
                body["data"][0]["isolation_backends"][0]["host_lifecycle_owner"],
                "agent-worker"
            );
            assert_eq!(body["data"][0]["persistence"]["provider"], "memory");
            assert_eq!(body["data"][0]["persistence"]["implemented"], false);
            assert_eq!(
                body["data"][0]["persistence"]["timeline_evidence_implemented"],
                true
            );
            assert_eq!(
                body["data"][0]["persistence"]["session_lifecycle_schema_ready"],
                false
            );
            assert_eq!(
                body["data"][0]["persistence"]["session_lifecycle_implemented"],
                false
            );
            assert_eq!(
                body["data"][0]["persistence"]["agent_worker_transport_implemented"],
                false
            );
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/managed-worker-sessions",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["object"], "list");
            assert_eq!(body["data"].as_array().map(Vec::len), Some(0));
            assert_eq!(body["total"], 0);
            assert_eq!(body["offset"], 0);
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/framework-adapters",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert!(list_contains(&body, "id", "claude-code"));
            assert!(list_contains(&body, "id", "codex"));
            assert!(list_contains(&body, "id", "hermes"));
            assert!(list_contains(&body, "id", "native-harness"));
            let native = admin_list_item(&body, "id", "native-harness")
                .context("native harness adapter should be listed")?;
            assert_eq!(native["integration_status"], "contract_ready");
            assert_eq!(native["enabled"], true);
            assert_eq!(native["managed_capability_boundary"], "gateway_mediated");
            assert_eq!(
                native["self_hosted_trust_level"],
                "reported_by_self_hosted_worker"
            );
            assert_eq!(native["public_api_exposes_framework_details"], false);
            let codex =
                admin_list_item(&body, "id", "codex").context("codex adapter should be listed")?;
            assert_eq!(codex["integration_status"], "process_shim_contract_ready");
            assert_eq!(codex["enabled"], false);
            Ok(())
        },
    )?;
    case.expect_json(
        "GET",
        "/admin/v1/self-hosted-workers",
        &[ADMIN_AUTH],
        "",
        200,
        |body| {
            assert_eq!(body["data"][0]["execution_owner"], "customer");
            assert_eq!(
                body["data"][0]["enforcement_boundary"],
                "customer_owned_host"
            );
            assert_eq!(
                body["data"][0]["trust_level"],
                "reported_by_self_hosted_worker"
            );
            assert_eq!(body["data"][0]["transport_actions"][0], "register_worker");
            assert_eq!(body["data"][0]["registration_api"]["implemented"], false);
            assert_eq!(body["data"][0]["persistence"]["implemented"], false);
            assert_eq!(body["data"][0]["persistence"]["provider"], "memory");
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

pub(crate) fn run_auth_api(args: &AuthArgs) -> Result<()> {
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

pub(crate) fn run_gateway_api(args: &LocalArgs) -> Result<()> {
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

pub(crate) fn run_gateway_external_auth_api(local: &LocalArgs, auth_args: &AuthArgs) -> Result<()> {
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

pub(crate) fn run_gateway_third_party_auth_api(local: &LocalArgs) -> Result<()> {
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
