// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: `ferrogate plans create/list/assign` (issue #168) -- the CLI
// entry point for the /admin/v1/plans HTTP surface (gateway/plans.rs) and
// tenant plan assignment via PATCH /admin/v1/tenant-accounts/{id}. Reuses
// assets_cli's raw-TCP HTTP client rather than duplicating it.

use anyhow::Result as AnyResult;

use crate::assets_cli::{print_json_or_raise, send_request, GatewayEndpoint};
use crate::cli::{PlansAssignArgs, PlansCommands, PlansConnectionArgs, PlansCreateArgs};

pub(crate) fn execute_plans_command(command: PlansCommands) -> AnyResult<()> {
    match command {
        PlansCommands::Create(args) => execute_create(args),
        PlansCommands::List(connection) => execute_list(connection),
        PlansCommands::Assign(args) => execute_assign(args),
    }
}

fn execute_create(args: PlansCreateArgs) -> AnyResult<()> {
    let endpoint = GatewayEndpoint::parse(&args.connection.gateway_url)?;
    let mut payload = serde_json::json!({
        "name": args.name,
        "slug": args.slug,
        "mcp_enabled": args.mcp_enabled,
        "self_hosted_workers_enabled": args.self_hosted_workers_enabled,
        "asset_hosting_enabled": args.asset_hosting_enabled,
        "extension_tools_enabled": args.extension_tools_enabled,
        "default_rpm_limit": args.default_rpm_limit,
        "default_tpm_limit": args.default_tpm_limit,
        "default_monthly_budget_usd": args.default_monthly_budget_usd,
    });
    if let Some(id) = args.id {
        payload["id"] = serde_json::Value::String(id);
    }
    let body = serde_json::to_vec(&payload)?;
    let response = send_request(
        &endpoint,
        "POST",
        "/admin/v1/plans",
        &args.connection.api_key,
        Some("application/json"),
        &body,
    )?;
    print_json_or_raise(&response, "create plan")
}

fn execute_list(connection: PlansConnectionArgs) -> AnyResult<()> {
    let endpoint = GatewayEndpoint::parse(&connection.gateway_url)?;
    let response = send_request(
        &endpoint,
        "GET",
        "/admin/v1/plans",
        &connection.api_key,
        None,
        &[],
    )?;
    print_json_or_raise(&response, "list plans")
}

fn execute_assign(args: PlansAssignArgs) -> AnyResult<()> {
    let endpoint = GatewayEndpoint::parse(&args.connection.gateway_url)?;
    let body = serde_json::to_vec(&serde_json::json!({ "plan_id": args.plan_id }))?;
    let response = send_request(
        &endpoint,
        "PATCH",
        &format!("/admin/v1/tenant-accounts/{}", args.tenant_id),
        &args.connection.api_key,
        Some("application/json"),
        &body,
    )?;
    print_json_or_raise(&response, "assign plan")
}
