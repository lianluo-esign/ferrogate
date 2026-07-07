// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: Route-group dispatch: fixed (non-dynamic-route) API surface
// grouped by business entity and matched through a `matchit` radix-tree
// router (https://github.com/ibraheemdev/matchit) instead of a flat
// sequential if-chain in handlers.rs::handle_request_filter. Each
// `RouteGroup` owns the full set of paths for one entity; its
// `try_*_routes` handler returns `Ok(true)` once it has written a
// response, or `Ok(false)` if the matched group decided not to handle this
// specific path/method after all (e.g. a `/v1/prompts/{name}` path that
// isn't a `/render` call), in which case the caller falls through to the
// dynamic host/path route table exactly as before this refactor. Pure
// dispatch refactor -- every handler call below is identical to the
// pre-refactor flat chain; no behavior change.

use std::sync::LazyLock;

use matchit::Router;
use pingora::{proxy::Session, Result as PingoraResult};

use super::{FerroGateway, ProxyContext};

/// Parsed request-line data threaded through every route group so each one
/// takes a single parameter instead of separately re-deriving
/// headers/method/query/path at its own call site.
pub(super) struct RequestParts {
    pub(super) headers: http::HeaderMap,
    pub(super) method: http::Method,
    pub(super) path: String,
    pub(super) query: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RouteGroup {
    AdminOverview,
    Inference,
    Tool,
    AgentRun,
    SelfHostedWorker,
    Skill,
    Prompt,
    AdminRequestLog,
    AdminConfigOps,
    AdminProvider,
    AdminManagedWorker,
    AdminAgentUpstream,
    AdminPlugin,
    AdminTool,
    AdminMcpServer,
    AdminModel,
    AdminGatewayConfig,
    AdminAgentWorkflow,
    AdminApiKey,
    AdminPolicy,
    TenantHierarchy,
    AdminVirtualKey,
    QuotaPolicy,
    Asset,
    Billing,
    Rbac,
}

/// Built once (first access) and reused for the process lifetime: the
/// fixed route set never changes at runtime, unlike the dynamic host/path
/// route table (`state.match_runtime_route`), which is rebuilt on config
/// reload and stays a separate, later fallback.
static ROUTE_GROUP_ROUTER: LazyLock<Router<RouteGroup>> = LazyLock::new(build_route_group_router);

pub(super) fn match_route_group(path: &str) -> Option<RouteGroup> {
    ROUTE_GROUP_ROUTER
        .at(path)
        .ok()
        .map(|matched| *matched.value)
}

fn build_route_group_router() -> Router<RouteGroup> {
    let mut router = Router::new();
    let mut insert = |pattern: &'static str, group: RouteGroup| {
        router.insert(pattern, group).unwrap_or_else(|error| {
            panic!("invalid or conflicting route pattern {pattern}: {error}")
        });
    };

    insert("/admin", RouteGroup::AdminOverview);
    insert("/admin/", RouteGroup::AdminOverview);
    insert("/admin/dashboard", RouteGroup::AdminOverview);
    insert("/admin/status", RouteGroup::AdminOverview);
    insert("/admin/v1/status", RouteGroup::AdminOverview);
    insert("/admin/v1/observability", RouteGroup::AdminOverview);
    insert("/metrics", RouteGroup::AdminOverview);

    insert("/v1/models", RouteGroup::Inference);
    insert("/v1/chat/completions", RouteGroup::Inference);
    insert("/v1/responses", RouteGroup::Inference);

    insert("/v1/tools", RouteGroup::Tool);
    insert("/v1/tools/execute", RouteGroup::Tool);
    insert("/v1/mcp/tool/execute", RouteGroup::Tool);
    insert("/v1/functions/execute", RouteGroup::Tool);
    insert("/v1/mcp", RouteGroup::Tool);

    insert("/v1/agent-runs", RouteGroup::AgentRun);
    insert("/.well-known/agent.json", RouteGroup::AgentRun);
    insert("/v1/agents/{*rest}", RouteGroup::AgentRun);
    insert("/admin/v1/agent-runs", RouteGroup::AgentRun);
    insert("/admin/v1/agent-runs/{*rest}", RouteGroup::AgentRun);
    insert("/admin/v1/self-hosted-runs/{*rest}", RouteGroup::AgentRun);

    insert(
        "/v1/self-hosted-workers/heartbeat",
        RouteGroup::SelfHostedWorker,
    );
    insert(
        "/v1/self-hosted-workers/events",
        RouteGroup::SelfHostedWorker,
    );
    insert(
        "/v1/self-hosted-workers/artifacts",
        RouteGroup::SelfHostedWorker,
    );
    insert(
        "/v1/self-hosted-workers/checkpoints",
        RouteGroup::SelfHostedWorker,
    );
    insert(
        "/v1/self-hosted-workers/runs/poll",
        RouteGroup::SelfHostedWorker,
    );
    insert(
        "/v1/self-hosted-workers/runs/ack",
        RouteGroup::SelfHostedWorker,
    );
    insert(
        "/admin/v1/self-hosted-workers",
        RouteGroup::SelfHostedWorker,
    );
    insert(
        "/admin/v1/self-hosted-workers/{*rest}",
        RouteGroup::SelfHostedWorker,
    );
    insert(
        "/admin/v1/self-hosted-worker-records",
        RouteGroup::SelfHostedWorker,
    );

    insert("/v1/skills", RouteGroup::Skill);
    insert("/v1/skills/{*rest}", RouteGroup::Skill);
    insert("/admin/v1/skill-packages", RouteGroup::Skill);
    insert("/admin/v1/skill-packages/{*rest}", RouteGroup::Skill);

    insert("/v1/prompts/{*rest}", RouteGroup::Prompt);
    insert("/admin/v1/prompt-templates", RouteGroup::Prompt);
    insert("/admin/v1/prompt-templates/{*rest}", RouteGroup::Prompt);

    insert("/admin/v1/request-logs", RouteGroup::AdminRequestLog);
    insert("/admin/v1/request-log-exports", RouteGroup::AdminRequestLog);
    insert("/admin/v1/audit-events", RouteGroup::AdminRequestLog);

    insert("/admin/v1/config/validate", RouteGroup::AdminConfigOps);
    insert("/admin/v1/config/reload", RouteGroup::AdminConfigOps);
    insert("/admin/v1/drain", RouteGroup::AdminConfigOps);

    insert("/admin/v1/providers", RouteGroup::AdminProvider);
    insert("/admin/v1/provider-health", RouteGroup::AdminProvider);
    insert("/admin/v1/provider-models", RouteGroup::AdminProvider);

    insert("/admin/v1/managed-workers", RouteGroup::AdminManagedWorker);
    insert(
        "/admin/v1/managed-worker-sessions",
        RouteGroup::AdminManagedWorker,
    );
    insert(
        "/admin/v1/framework-adapters",
        RouteGroup::AdminManagedWorker,
    );

    insert("/admin/v1/agent-upstreams", RouteGroup::AdminAgentUpstream);
    insert(
        "/admin/v1/agent-upstreams/{*rest}",
        RouteGroup::AdminAgentUpstream,
    );

    insert("/admin/v1/extensions", RouteGroup::AdminPlugin);
    insert("/admin/v1/plugins", RouteGroup::AdminPlugin);
    insert("/admin/v1/plugins/{*rest}", RouteGroup::AdminPlugin);

    insert("/admin/v1/tools", RouteGroup::AdminTool);
    insert("/admin/v1/tool-approvals", RouteGroup::AdminTool);
    insert("/admin/v1/tool-approvals/{*rest}", RouteGroup::AdminTool);
    insert("/admin/v1/tool-sessions/{*rest}", RouteGroup::AdminTool);

    insert("/admin/v1/mcp-servers", RouteGroup::AdminMcpServer);
    insert("/admin/v1/mcp-servers/{*rest}", RouteGroup::AdminMcpServer);

    insert("/admin/v1/models", RouteGroup::AdminModel);

    insert("/admin/v1/gateway-configs", RouteGroup::AdminGatewayConfig);
    insert(
        "/admin/v1/gateway-configs/{*rest}",
        RouteGroup::AdminGatewayConfig,
    );

    insert("/admin/v1/agent-workflows", RouteGroup::AdminAgentWorkflow);
    insert(
        "/admin/v1/agent-workflows/{*rest}",
        RouteGroup::AdminAgentWorkflow,
    );

    insert("/admin/v1/api-keys", RouteGroup::AdminApiKey);
    insert("/admin/v1/api-keys/{*rest}", RouteGroup::AdminApiKey);

    insert("/admin/v1/policies", RouteGroup::AdminPolicy);
    insert("/admin/v1/policies/{*rest}", RouteGroup::AdminPolicy);

    insert("/admin/v1/tenant-accounts", RouteGroup::TenantHierarchy);
    insert("/admin/v1/projects", RouteGroup::TenantHierarchy);
    insert("/admin/v1/workspaces", RouteGroup::TenantHierarchy);
    insert("/admin/v1/tenants", RouteGroup::TenantHierarchy);

    insert("/admin/v1/virtual-keys", RouteGroup::AdminVirtualKey);
    insert(
        "/admin/v1/virtual-keys/{*rest}",
        RouteGroup::AdminVirtualKey,
    );

    insert("/admin/v1/quota-policies", RouteGroup::QuotaPolicy);
    insert("/admin/v1/quota-policies/{*rest}", RouteGroup::QuotaPolicy);

    insert("/v1/assets", RouteGroup::Asset);
    insert("/v1/assets/{*rest}", RouteGroup::Asset);

    insert("/admin/v1/permissions", RouteGroup::Rbac);
    insert("/admin/v1/permissions/{*rest}", RouteGroup::Rbac);
    insert("/admin/v1/roles", RouteGroup::Rbac);
    insert("/admin/v1/roles/{*rest}", RouteGroup::Rbac);
    insert("/admin/v1/tenant-roles/{*rest}", RouteGroup::Rbac);

    insert("/admin/v1/metering-events", RouteGroup::Billing);
    insert("/admin/v1/billing-events", RouteGroup::Billing);
    insert("/admin/v1/metering-export-status", RouteGroup::Billing);
    insert("/admin/v1/usage-aggregates", RouteGroup::Billing);
    insert("/admin/v1/usage-reports", RouteGroup::Billing);
    insert("/admin/v1/billing-outbox-dead-letters", RouteGroup::Billing);

    router
}

impl FerroGateway {
    /// Dispatches to the single route group `matchit` resolved for this
    /// path. Returns `Ok(true)` once a response has been written; `Ok(false)`
    /// means the resolved group looked at the request and declined to
    /// handle it (see the module doc comment), so the caller should fall
    /// through to dynamic route matching exactly as it did pre-refactor.
    pub(super) async fn try_route_groups(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        let Some(group) = match_route_group(&req.path) else {
            return Ok(false);
        };
        match group {
            RouteGroup::AdminOverview => self.try_admin_overview_routes(session, ctx, req).await,
            RouteGroup::Inference => self.try_inference_routes(session, ctx, req).await,
            RouteGroup::Tool => self.try_tool_routes(session, ctx, req).await,
            RouteGroup::AgentRun => self.try_agent_run_routes(session, ctx, req).await,
            RouteGroup::SelfHostedWorker => {
                self.try_self_hosted_worker_routes(session, ctx, req).await
            }
            RouteGroup::Skill => self.try_skill_routes(session, ctx, req).await,
            RouteGroup::Prompt => self.try_prompt_routes(session, ctx, req).await,
            RouteGroup::AdminRequestLog => {
                self.try_admin_request_log_routes(session, ctx, req).await
            }
            RouteGroup::AdminConfigOps => self.try_admin_config_ops_routes(session, ctx, req).await,
            RouteGroup::AdminProvider => self.try_admin_provider_routes(session, ctx, req).await,
            RouteGroup::AdminManagedWorker => {
                self.try_admin_managed_worker_routes(session, ctx, req)
                    .await
            }
            RouteGroup::AdminAgentUpstream => {
                self.try_admin_agent_upstream_routes(session, ctx, req)
                    .await
            }
            RouteGroup::AdminPlugin => self.try_admin_plugin_routes(session, ctx, req).await,
            RouteGroup::AdminTool => self.try_admin_tool_routes(session, ctx, req).await,
            RouteGroup::AdminMcpServer => self.try_admin_mcp_server_routes(session, ctx, req).await,
            RouteGroup::AdminModel => self.try_admin_model_routes(session, ctx, req).await,
            RouteGroup::AdminGatewayConfig => {
                self.try_admin_gateway_config_routes(session, ctx, req)
                    .await
            }
            RouteGroup::AdminAgentWorkflow => {
                self.try_admin_agent_workflow_routes(session, ctx, req)
                    .await
            }
            RouteGroup::AdminApiKey => self.try_admin_api_key_routes(session, ctx, req).await,
            RouteGroup::AdminPolicy => self.try_admin_policy_routes(session, ctx, req).await,
            RouteGroup::TenantHierarchy => {
                self.try_tenant_hierarchy_routes(session, ctx, req).await
            }
            RouteGroup::AdminVirtualKey => {
                self.try_admin_virtual_key_routes(session, ctx, req).await
            }
            RouteGroup::QuotaPolicy => self.try_quota_policy_routes(session, ctx, req).await,
            RouteGroup::Asset => self.try_asset_routes(session, ctx, req).await,
            RouteGroup::Billing => self.try_billing_routes(session, ctx, req).await,
            RouteGroup::Rbac => self.try_rbac_routes(session, ctx, req).await,
        }
    }

    async fn try_inference_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/v1/models" {
            self.handle_models(session, ctx, &req.headers).await?;
            return Ok(true);
        }
        if req.path == "/v1/chat/completions" {
            self.handle_chat_completions(session, ctx, req.headers.clone())
                .await?;
            return Ok(true);
        }
        if req.path == "/v1/responses" {
            self.handle_responses(session, ctx, req.headers.clone())
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_tool_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/v1/tools" {
            self.handle_tools(session, ctx, &req.headers, req.query.as_deref())
                .await?;
            return Ok(true);
        }
        if req.path == "/v1/tools/execute" {
            self.handle_tool_execute(session, ctx, req.headers.clone(), &req.method)
                .await?;
            return Ok(true);
        }
        if req.path == "/v1/mcp/tool/execute" {
            self.handle_mcp_tool_execute(session, ctx, req.headers.clone(), &req.method)
                .await?;
            return Ok(true);
        }
        if req.path == "/v1/functions/execute" {
            self.handle_function_execute(session, ctx, req.headers.clone(), &req.method)
                .await?;
            return Ok(true);
        }
        if req.path == "/v1/mcp" {
            self.handle_mcp_rpc(session, ctx, req.headers.clone(), &req.method)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_agent_run_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/v1/agent-runs" {
            self.handle_agent_run_create(session, ctx, req.headers.clone(), &req.method)
                .await?;
            return Ok(true);
        }
        if req.path == "/.well-known/agent.json" {
            self.handle_agent_discovery(session, ctx, &req.headers)
                .await?;
            return Ok(true);
        }
        if req.path.starts_with("/v1/agents/") {
            self.handle_agent_ingress(session, ctx, req.headers.clone(), &req.method, &req.path)
                .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/agent-runs" || req.path.starts_with("/admin/v1/agent-runs/") {
            self.handle_admin_agent_runs(
                session,
                ctx,
                &req.headers,
                &req.path,
                req.query.as_deref(),
            )
            .await?;
            return Ok(true);
        }
        if req.path.starts_with("/admin/v1/self-hosted-runs/") {
            self.handle_admin_self_hosted_runs(session, ctx, &req.headers, &req.path)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_self_hosted_worker_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/v1/self-hosted-workers/heartbeat"
            || req.path == "/v1/self-hosted-workers/events"
            || req.path == "/v1/self-hosted-workers/artifacts"
            || req.path == "/v1/self-hosted-workers/checkpoints"
            || req.path == "/v1/self-hosted-workers/runs/poll"
            || req.path == "/v1/self-hosted-workers/runs/ack"
        {
            self.handle_self_hosted_worker_transport(
                session,
                ctx,
                &req.headers,
                &req.method,
                &req.path,
            )
            .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/self-hosted-workers"
            || req.path.starts_with("/admin/v1/self-hosted-workers/")
        {
            self.handle_admin_self_hosted_workers(
                session,
                ctx,
                &req.headers,
                &req.method,
                &req.path,
                req.query.as_deref(),
            )
            .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/self-hosted-worker-records" {
            self.handle_admin_self_hosted_worker_records(
                session,
                ctx,
                &req.headers,
                &req.method,
                req.query.as_deref(),
            )
            .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_skill_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/v1/skills" || req.path.starts_with("/v1/skills/") {
            self.handle_agent_skills(session, ctx, req.headers.clone(), &req.method, &req.path)
                .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/skill-packages"
            || req.path.starts_with("/admin/v1/skill-packages/")
        {
            self.handle_admin_skill_packages(session, ctx, &req.headers, &req.method, &req.path)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_prompt_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path.starts_with("/v1/prompts/") && req.path.ends_with("/render") {
            self.handle_prompt_template_render(
                session,
                ctx,
                req.headers.clone(),
                &req.method,
                &req.path,
            )
            .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/prompt-templates"
            || req.path.starts_with("/admin/v1/prompt-templates/")
        {
            self.handle_admin_prompt_templates(session, ctx, &req.headers, &req.method, &req.path)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_admin_overview_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin" || req.path == "/admin/" || req.path == "/admin/dashboard" {
            self.handle_admin_dashboard(session, ctx).await?;
            return Ok(true);
        }
        if req.path == "/admin/status" || req.path == "/admin/v1/status" {
            self.handle_admin_status(session, ctx, &req.headers).await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/observability" {
            self.handle_admin_observability(session, ctx, &req.headers)
                .await?;
            return Ok(true);
        }
        if req.path == "/metrics" {
            self.handle_metrics(session, ctx, &req.headers).await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_admin_request_log_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/request-logs" {
            self.handle_admin_request_logs(session, ctx, &req.headers, req.query.as_deref())
                .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/request-log-exports" {
            self.handle_admin_request_log_export(session, ctx, &req.headers, req.query.as_deref())
                .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/audit-events" {
            self.handle_admin_audit_events(session, ctx, &req.headers, req.query.as_deref())
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_admin_config_ops_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/config/validate" {
            self.handle_admin_config_validate(session, ctx, &req.headers, &req.method)
                .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/config/reload" {
            self.handle_admin_config_reload(session, ctx, &req.headers, &req.method)
                .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/drain" {
            self.handle_admin_drain(session, ctx, &req.headers, &req.method)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_admin_provider_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/providers" {
            self.handle_admin_providers(session, ctx, &req.headers)
                .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/provider-health" {
            self.handle_admin_provider_health(session, ctx, &req.headers)
                .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/provider-models" {
            self.handle_admin_provider_models(session, ctx, &req.headers, req.query.as_deref())
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_admin_managed_worker_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/managed-workers" {
            self.handle_admin_managed_workers(session, ctx, &req.headers)
                .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/managed-worker-sessions" {
            self.handle_admin_managed_worker_sessions(
                session,
                ctx,
                &req.headers,
                &req.method,
                req.query.as_deref(),
            )
            .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/framework-adapters" {
            self.handle_admin_framework_adapters(session, ctx, &req.headers)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_admin_agent_upstream_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/agent-upstreams"
            || req.path.starts_with("/admin/v1/agent-upstreams/")
        {
            self.handle_admin_agent_upstreams(session, ctx, &req.headers, &req.method, &req.path)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_admin_plugin_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/extensions"
            || req.path == "/admin/v1/plugins"
            || req.path.starts_with("/admin/v1/plugins/")
        {
            self.handle_admin_plugins(session, ctx, &req.headers, &req.method, &req.path)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_admin_tool_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/tools" {
            self.handle_admin_tools(session, ctx, &req.headers).await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/tool-approvals"
            || req.path.starts_with("/admin/v1/tool-approvals/")
        {
            self.handle_admin_tool_approvals(session, ctx, &req.headers, &req.method, &req.path)
                .await?;
            return Ok(true);
        }
        if req.path.starts_with("/admin/v1/tool-sessions/") {
            self.handle_admin_tool_session(session, ctx, &req.headers, &req.path)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_admin_mcp_server_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/mcp-servers" || req.path.starts_with("/admin/v1/mcp-servers/") {
            self.handle_admin_mcp_servers(session, ctx, &req.headers, &req.method, &req.path)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_admin_model_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/models" {
            self.handle_admin_models(session, ctx, &req.headers).await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_admin_gateway_config_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/gateway-configs"
            || req.path.starts_with("/admin/v1/gateway-configs/")
        {
            self.handle_admin_gateway_configs(session, ctx, &req.headers, &req.method, &req.path)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_admin_agent_workflow_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/agent-workflows"
            || req.path.starts_with("/admin/v1/agent-workflows/")
        {
            self.handle_admin_agent_workflows(session, ctx, &req.headers, &req.method, &req.path)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_admin_api_key_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/api-keys" || req.path.starts_with("/admin/v1/api-keys/") {
            self.handle_admin_api_keys(session, ctx, &req.headers, &req.method, &req.path)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_admin_policy_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/policies" || req.path.starts_with("/admin/v1/policies/") {
            self.handle_admin_policies(session, ctx, &req.headers, &req.method, &req.path)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_tenant_hierarchy_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/tenant-accounts" {
            self.handle_admin_tenant_accounts(session, ctx, &req.headers, &req.method)
                .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/projects" {
            self.handle_admin_projects(session, ctx, &req.headers, &req.method)
                .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/workspaces" {
            self.handle_admin_workspaces(session, ctx, &req.headers, &req.method)
                .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/tenants" {
            self.handle_admin_tenants(session, ctx, &req.headers)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_admin_virtual_key_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/virtual-keys" || req.path.starts_with("/admin/v1/virtual-keys/") {
            self.handle_admin_virtual_keys(session, ctx, &req.headers, &req.method, &req.path)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_quota_policy_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/quota-policies"
            || req.path.starts_with("/admin/v1/quota-policies/")
        {
            self.handle_admin_quota_policies(session, ctx, &req.headers, &req.method, &req.path)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_asset_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/v1/assets" || req.path.starts_with("/v1/assets/") {
            self.handle_assets(session, ctx, &req.headers, &req.method, &req.path)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_rbac_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/permissions" || req.path.starts_with("/admin/v1/permissions/") {
            self.handle_admin_permissions(session, ctx, &req.headers, &req.method, &req.path)
                .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/roles" || req.path.starts_with("/admin/v1/roles/") {
            self.handle_admin_roles(session, ctx, &req.headers, &req.method, &req.path)
                .await?;
            return Ok(true);
        }
        if req.path.starts_with("/admin/v1/tenant-roles/") {
            self.handle_admin_tenant_roles(session, ctx, &req.headers, &req.method, &req.path)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_billing_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/metering-events" {
            self.handle_admin_metering_events(session, ctx, &req.headers, req.query.as_deref())
                .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/billing-events" {
            self.handle_admin_billing_events(session, ctx, &req.headers, req.query.as_deref())
                .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/metering-export-status" {
            self.handle_admin_metering_export_status(session, ctx, &req.headers)
                .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/usage-aggregates" {
            self.handle_admin_usage_aggregates(session, ctx, &req.headers)
                .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/usage-reports" {
            self.handle_admin_usage_reports(session, ctx, &req.headers, req.query.as_deref())
                .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/billing-outbox-dead-letters" {
            self.handle_admin_billing_outbox_dead_letters(session, ctx, &req.headers)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
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
            "/admin/v1/skill-packages",
            "/admin/v1/skill-packages/package-1",
            "/admin/v1/prompt-templates",
            "/admin/v1/prompt-templates/template-1",
            "/admin/v1/api-keys",
            "/admin/v1/api-keys/key-1",
            "/admin/v1/policies",
            "/admin/v1/policies/policy-1",
            "/admin/v1/tenant-accounts",
            "/admin/v1/projects",
            "/admin/v1/workspaces",
            "/admin/v1/virtual-keys",
            "/admin/v1/virtual-keys/key-1",
            "/admin/v1/quota-policies",
            "/admin/v1/quota-policies/tenant/t1",
            "/v1/assets",
            "/v1/assets/cli_tool/name/1.0.0",
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
        assert!(match_route_group("/healthz").is_none());
        assert!(match_route_group("/readyz").is_none());
        assert!(match_route_group("/some/customer/upstream/path").is_none());
    }
}
