// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: D1 presence-read failure E2E for truthful observed-agent activity (#494).

use crate::{cli::LocalArgs, local::LocalHarness, mocks::spawn_mock_d1_rest_server};
use anyhow::{ensure, Context, Result};
use ferrogate_core::TenantContext;
use ferrogate_storage::StoredRequestLog;
use std::time::{SystemTime, UNIX_EPOCH};

const CONTROL_DATABASE_ID: &str = "control-private-uuid";
const TENANT_DATABASE_ID: &str = "tenant-private-uuid";

/// Start the real gateway on a D1-backed control plane whose REST reads work
/// but whose proxy-Worker transport is unavailable. The admin response must
/// preserve a durable request-log row while refusing to call it inactive.
pub(crate) fn run_observed_activity_d1_failure(args: &LocalArgs) -> Result<()> {
    let seen_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs()
        .saturating_sub(3_600);
    let request_log = StoredRequestLog {
        request_id: "req-d1-presence-failure".into(),
        trace_id: None,
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: TenantContext {
            organization_id: Some("org_demo".into()),
            team_id: None,
            project_id: Some("project_gateway".into()),
            workspace_id: Some("workspace_gateway".into()),
            user_id: None,
            api_key_id: Some("client".into()),
        },
        route: Some("chat.completions".into()),
        provider: Some("openai".into()),
        logical_model: Some("fast-chat".into()),
        provider_model: Some("gpt-4o-mini".into()),
        gateway_config_id: None,
        gateway_config_revision: None,
        status_code: 200,
        error_code: None,
        prompt_recorded: false,
        response_recorded: false,
        prompt_body: None,
        response_body: None,
        cache_status: None,
        started_at_unix: Some(seen_at_unix),
        completed_at_unix: Some(seen_at_unix),
        parent_action_fingerprint: None,
    };
    let d1 = spawn_mock_d1_rest_server(serde_json::to_string(&request_log)?)?;
    let config_template = format!(
        r#"
listen = "__FERROGATE_TEST_LISTEN__"

[storage]
provider = "cloudflare_d1"
required = false
migration_mode = "disabled"
d1_control_database_id = "{CONTROL_DATABASE_ID}"
d1_tenant_databases = {{ org_demo = "{TENANT_DATABASE_ID}" }}

[auth]
disabled = true

[cloudflare]
account_id = "account-private"
api_token = "plaintext-test-token"
api_base_url = "http://{}"
ai_gateway_base_url = "http://127.0.0.1:1"
"#,
        d1.addr
    );
    let case = LocalHarness::start_with_config_template(&args.ferrogate_bin, 0, &config_template)?;

    case.expect_json(
        "GET",
        "/admin/v1/observed-agent-activity",
        &[],
        "",
        200,
        |body| {
            ensure!(body["presence_feed"]["status"] == "unavailable", "{body}");
            ensure!(
                body["presence_feed"]["rows_may_be_incomplete"] == true,
                "{body}"
            );
            ensure!(
                body["presence_feed"]["unavailable_reason"] == "presence_read_failed",
                "{body}"
            );
            ensure!(body["data"].as_array().map(Vec::len) == Some(1), "{body}");
            let row = &body["data"][0];
            ensure!(row["id"] == "observed:org_demo:client", "{row}");
            ensure!(row["status"] == "unknown", "{row}");
            ensure!(row["status_basis"] == "presence_feed_unavailable", "{row}");
            ensure!(
                row["evidence"]["presence_feed_status"] == "unavailable",
                "{row}"
            );
            ensure!(
                row["evidence"]["presence_unavailable_reason"] == "presence_read_failed",
                "{row}"
            );

            let tenant_visible = body.to_string();
            ensure!(
                !tenant_visible.contains("cloudflare_d1"),
                "{tenant_visible}"
            );
            ensure!(
                !tenant_visible.contains(CONTROL_DATABASE_ID),
                "{tenant_visible}"
            );
            ensure!(
                !tenant_visible.contains(TENANT_DATABASE_ID),
                "{tenant_visible}"
            );
            ensure!(!tenant_visible.contains(&d1.addr), "{tenant_visible}");
            Ok(())
        },
    )?;
    ensure!(
        d1.request_log_reads() >= 1,
        "gateway never read the durable D1 request-log row"
    );
    Ok(())
}
