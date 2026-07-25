// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Generic resource dispatch: the one seam a *composing binary* drives to turn
//! a resolved `<group> <verb>` invocation into a [`RequestSpec`] (issues
//! #361–#365 wired into the `ferrogate` binary via #360's transport).
//!
//! Why this lives here and not in the binary: the epic's extensibility contract
//! is "adding a resource family must not require editing the binary". The binary
//! already builds its command tree generically from the
//! [`Registry`](crate::command::Registry) metadata ([`GroupDescriptor`] /
//! [`VerbDescriptor`](crate::command::VerbDescriptor)); the only remaining
//! family-specific knowledge is *which* `build_*` function maps a verb to a
//! request. Centralising that group-name → builder routing here — next to the
//! family modules that own the builders — keeps the binary a pure, generic
//! consumer: it calls [`build_request`] and [`redact_response`] by group name
//! and never names a resource. A new family is registered in
//! [`crate::register_resource_families`] and routed in [`resource_builder`];
//! the binary is untouched.
//!
//! [`GroupDescriptor`]: crate::command::GroupDescriptor
//!
//! The [`resource_builder`] table is kept honest by a test
//! (`dispatch_test.rs`): it builds the full registry and asserts every
//! registered group resolves to a builder, so a family added to
//! [`crate::register_resource_families`] without a routing entry fails the suite
//! rather than surfacing as an "unknown resource group" only at runtime.

use http::Method;
use serde_json::Value;

use crate::error::{CliError, CliResult};
use crate::registry_helpers::ResourceInput;
use crate::resource::redact_secret_fields;
use crate::transport::RequestSpec;
use crate::{
    agent, asset, billing, catalog, evidence, guardrail, iam, mcp, ops, organization,
    tool_approval, worker,
};

/// The uniform request-builder signature every resource family exposes: a
/// resolved verb name plus the typed [`ResourceInput`] a command line supplied
/// (id segments, optional JSON body, list pagination/filters) mapped onto a
/// [`RequestSpec`]. Every family `build_*` free function has exactly this shape,
/// so they compose into one dispatch table as plain function pointers.
pub type VerbBuilder = fn(&str, &ResourceInput) -> CliResult<RequestSpec>;

/// Resolve a registered resource group name to its request-builder, or `None`
/// when the name is not a resource family group (e.g. the local `context`
/// verbs, which the binary handles itself and which carry no API operation).
///
/// The arms mirror [`crate::register_resource_families`] one-for-one; the
/// dispatch parity test asserts the two never drift.
pub fn resource_builder(group: &str) -> Option<VerbBuilder> {
    let builder: VerbBuilder = match group {
        // Organization / tenancy (#361).
        "tenant-accounts" => organization::build_tenant_accounts,
        "tenants" => organization::build_tenants,
        "projects" => organization::build_projects,
        "workspaces" => organization::build_workspaces,
        "plans" => organization::build_plans,
        "quota-policies" => organization::build_quota_policies,
        // IAM (#361).
        "virtual-keys" => iam::build_virtual_keys,
        "api-keys" => iam::build_api_keys,
        "roles" => iam::build_roles,
        "permissions" => iam::build_permissions,
        "access-policies" => iam::build_access_policies,
        "tenant-roles" => iam::build_tenant_roles,
        // Agent lifecycle (#362).
        "agent-workflows" => agent::build_agent_workflows,
        "agent-schedules" => agent::build_agent_schedules,
        "agent-upstreams" => agent::build_agent_upstreams,
        "agent-runs" => agent::build_agent_runs,
        // Async long-running agent jobs (#474).
        "agent-jobs" => agent::build_agent_jobs,
        // Worker lifecycle (#362).
        "self-hosted-workers" => worker::build_self_hosted_workers,
        "managed-workers" => worker::build_managed_workers,
        "managed-worker-sessions" => worker::build_managed_worker_sessions,
        "self-hosted-worker-records" => worker::build_self_hosted_worker_records,
        "self-hosted-runs" => worker::build_self_hosted_runs,
        // MCP / tool governance (#362).
        "mcp-servers" => mcp::build_mcp_servers,
        "mcp-identity" => mcp::build_mcp_identity,
        "tool-sessions" => mcp::build_tool_sessions,
        "tools" => mcp::build_tools,
        // Tool approvals (#362).
        "tool-approvals" => tool_approval::build_tool_approvals,
        // Guardrails (#362).
        "guardrail-policies" => guardrail::build_guardrail_policies,
        "guardrail-evaluations" => guardrail::build_guardrail_evaluations,
        "investigations" => guardrail::build_investigations,
        // Assets / transfer / channels / static sites (#363).
        "assets" => asset::build_assets,
        "asset-transfer" => asset::build_asset_transfer,
        "asset-channels" => asset::build_asset_channels,
        "site-domains" => asset::build_site_domains,
        // Catalog + prompt/skill/plugin registries + dashboard (#363).
        "prompt-templates" => catalog::build_prompt_templates,
        "skill-packages" => catalog::build_skill_packages,
        "plugins" => catalog::build_plugins,
        "catalog" => catalog::build_catalog,
        "dashboard" => catalog::build_dashboard,
        // Billing / usage (#364).
        "wallets" => billing::build_wallets,
        "payment-methods" => billing::build_payment_methods,
        "billing-events" => billing::build_billing_events,
        "usage" => billing::build_usage,
        // Evidence (#364).
        "request-logs" => evidence::build_request_logs,
        "audit-events" => evidence::build_audit_events,
        "observed-agent-activity" => evidence::build_observed_agent_activity,
        // Operator actions / gateway config (#364).
        "system" => ops::build_system,
        "provider-health" => ops::build_provider_health,
        "config" => ops::build_config,
        "drain" => ops::build_drain,
        "gateway-configs" => ops::build_gateway_configs,
        _ => return None,
    };
    Some(builder)
}

/// Build the request for a resolved `<group> <verb>` invocation against the
/// typed [`ResourceInput`]. Returns a usage error when the group is not a known
/// resource family — a defensive arm the binary should never trigger, because
/// it only offers group names it read from the same [`resource_builder`] table
/// via the registry, but which keeps a misconfiguration a stable usage exit
/// rather than a panic.
pub fn build_request(group: &str, verb: &str, input: &ResourceInput) -> CliResult<RequestSpec> {
    let builder = resource_builder(group).ok_or_else(|| {
        CliError::usage(format!(
            "unknown resource group '{group}'; run `--help` for the command list"
        ))
    })?;
    builder(verb, input)
}

/// The one-time secret fields a group's create/rotate response may carry, which
/// must never survive into a later read. Groups with no secret material return
/// an empty slice.
pub fn secret_fields_for(group: &str) -> &'static [&'static str] {
    match group {
        // A virtual key's key/secret are shown once at create/rotate.
        "virtual-keys" => iam::VIRTUAL_KEY_SECRET_FIELDS,
        // An admin API key's secret is shown once at create.
        "api-keys" => iam::API_KEY_SECRET_FIELDS,
        // Asset transfer presign URLs are one-time capability grants.
        "asset-transfer" => asset::ASSET_TRANSFER_SECRET_FIELDS,
        _ => &[],
    }
}

/// Redact a group's one-time secret fields from a response body, but only for a
/// read (`GET`) request. A mutation (create/rotate/transfer) legitimately
/// returns a one-time secret, so its response is left intact for the single
/// moment of that call — the binary routes it to the operator once and it is
/// never persisted. A `GET` (`list`/`get`) must never surface key material, so
/// any secret field the server echoes back is blanked defensively.
pub fn redact_response(group: &str, spec: &RequestSpec, body: &mut Value) {
    if spec.method == Method::GET {
        let fields = secret_fields_for(group);
        if !fields.is_empty() {
            redact_secret_fields(body, fields);
        }
    }
}

#[cfg(test)]
#[path = "dispatch_test.rs"]
mod dispatch_test;
