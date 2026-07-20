// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for gateway route groups, kept outside business logic.

use super::*;

/// Forces the lazily-built router to initialize, surfacing any
/// conflicting/invalid route pattern immediately instead of only on a
/// real request.
#[test]
fn route_group_router_builds_without_conflicts() {
    assert!(match_route_group("/v1/assets").is_some());
}

#[test]
fn every_previously_flat_route_still_resolves_to_a_group() {
    let paths = [
        "/admin",
        "/admin/",
        "/admin/dashboard",
        "/v1/models",
        "/v1/tools",
        "/v1/tools/execute",
        "/v1/mcp/tool/execute",
        "/v1/functions/execute",
        "/v1/mcp",
        "/v1/agent-runs",
        "/.well-known/agent.json",
        "/v1/self-hosted-workers/heartbeat",
        "/v1/self-hosted-workers/events",
        "/v1/self-hosted-workers/artifacts",
        "/v1/self-hosted-workers/checkpoints",
        "/v1/self-hosted-workers/runs/poll",
        "/v1/self-hosted-workers/runs/ack",
        "/v1/agents/foo",
        "/v1/skills",
        "/v1/skills/foo",
        "/v1/prompts/foo/render",
        "/v1/chat/completions",
        "/v1/responses",
        "/admin/status",
        "/admin/v1/status",
        "/admin/v1/request-logs",
        "/admin/v1/agent-runs",
        "/admin/v1/agent-runs/run-1",
        "/admin/v1/self-hosted-runs/run-1",
        "/admin/v1/request-log-exports",
        "/admin/v1/audit-events",
        "/admin/v1/config/validate",
        "/admin/v1/config/reload",
        "/admin/v1/drain",
        "/admin/v1/providers",
        "/admin/v1/provider-health",
        "/admin/v1/provider-models",
        "/admin/v1/managed-workers",
        "/admin/v1/managed-worker-sessions",
        "/admin/v1/framework-adapters",
        "/admin/v1/self-hosted-workers",
        "/admin/v1/self-hosted-workers/worker-1",
        "/admin/v1/self-hosted-worker-records",
        "/admin/v1/agent-upstreams",
        "/admin/v1/agent-upstreams/up-1",
        "/admin/v1/observability",
        "/admin/v1/extensions",
        "/admin/v1/plugins",
        "/admin/v1/plugins/plugin-1",
        "/admin/v1/tools",
        "/admin/v1/tool-approvals",
        "/admin/v1/tool-approvals/approval-1",
        "/admin/v1/mcp-servers",
        "/admin/v1/mcp-servers/server-1",
        "/admin/v1/tool-sessions/session-1",
        "/admin/v1/models",
        "/admin/v1/gateway-configs",
        "/admin/v1/gateway-configs/config-1",
        "/admin/v1/agent-workflows",
        "/admin/v1/agent-workflows/workflow-1",
        "/admin/v1/agent-schedules",
        "/admin/v1/agent-schedules/schedule-1",
        "/admin/v1/agent-schedules/schedule-1/run-now",
        "/admin/v1/agent-schedules/schedule-1/fires",
        "/admin/v1/skill-packages",
        "/admin/v1/skill-packages/package-1",
        "/admin/v1/prompt-templates",
        "/admin/v1/prompt-templates/template-1",
        "/admin/v1/api-keys",
        "/admin/v1/api-keys/key-1",
        "/admin/v1/policies",
        "/admin/v1/policies/policy-1",
        "/admin/v1/guardrail-policies",
        "/admin/v1/guardrail-policies/policy-1/revisions",
        "/admin/v1/guardrail-policies/policy-1/activate",
        "/admin/v1/guardrail-policies/policy-1/dry-run",
        "/admin/v1/tenant-accounts",
        "/admin/v1/projects",
        "/admin/v1/workspaces",
        "/admin/v1/virtual-keys",
        "/admin/v1/virtual-keys/key-1",
        "/admin/v1/quota-policies",
        "/admin/v1/quota-policies/tenant/t1",
        "/v1/assets",
        "/v1/assets/cli_tool/name/1.0.0",
        "/sites/org_demo/marketing/",
        "/sites/org_demo/marketing/style.css",
        "/sites/org_demo/marketing/docs/readme.md",
        "/admin/v1/site-domains",
        "/admin/v1/site-domains/mysite.example.com",
        "/admin/v1/tenants",
        "/admin/v1/metering-events",
        "/admin/v1/billing-events",
        "/admin/v1/metering-export-status",
        "/admin/v1/usage-aggregates",
        "/admin/v1/usage-reports",
        "/admin/v1/billing-outbox-dead-letters",
        "/metrics",
    ];
    for path in paths {
        assert!(
            match_route_group(path).is_some(),
            "path {path} no longer resolves to any route group"
        );
    }
}

#[test]
fn dynamic_and_unknown_paths_fall_through() {
    assert_eq!(match_route_group("/healthz"), Some(RouteGroup::Health));
    assert_eq!(match_route_group("/readyz"), Some(RouteGroup::Readiness));
    assert!(match_route_group("/some/customer/upstream/path").is_none());
}

#[test]
fn site_domain_admin_paths_resolve_to_the_site_domain_group() {
    assert_eq!(
        match_route_group("/admin/v1/site-domains"),
        Some(RouteGroup::SiteDomain)
    );
    assert_eq!(
        match_route_group("/admin/v1/site-domains/mysite.example.com"),
        Some(RouteGroup::SiteDomain)
    );
}

#[test]
fn site_serve_paths_resolve_to_the_site_group() {
    assert_eq!(
        match_route_group("/sites/org_demo/marketing/"),
        Some(RouteGroup::Site)
    );
    assert_eq!(
        match_route_group("/sites/org_demo/marketing/docs/readme.md"),
        Some(RouteGroup::Site)
    );
}
