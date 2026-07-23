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

use pingora::{proxy::Session, Result as PingoraResult};

use super::{FerroGateway, ProxyContext};
use crate::responses::write_json_error;

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
    Health,
    Readiness,
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
    AdminAgentSchedule,
    AdminApiKey,
    AdminPolicy,
    GuardrailPolicy,
    TenantHierarchy,
    AdminVirtualKey,
    QuotaPolicy,
    Asset,
    Site,
    SiteDomain,
    Billing,
    Rbac,
    Plans,
    Wallets,
}

impl RouteGroup {
    pub(super) fn from_contract_name(name: &str) -> Option<Self> {
        Some(match name {
            "health" => Self::Health,
            "readiness" => Self::Readiness,
            "admin_overview" => Self::AdminOverview,
            "inference" => Self::Inference,
            "tool" => Self::Tool,
            "agent_run" => Self::AgentRun,
            "self_hosted_worker" => Self::SelfHostedWorker,
            "skill" => Self::Skill,
            "prompt" => Self::Prompt,
            "admin_request_log" => Self::AdminRequestLog,
            "admin_config_ops" => Self::AdminConfigOps,
            "admin_provider" => Self::AdminProvider,
            "admin_managed_worker" => Self::AdminManagedWorker,
            "admin_agent_upstream" => Self::AdminAgentUpstream,
            "admin_plugin" => Self::AdminPlugin,
            "admin_tool" => Self::AdminTool,
            "admin_mcp_server" => Self::AdminMcpServer,
            "admin_model" => Self::AdminModel,
            "admin_gateway_config" => Self::AdminGatewayConfig,
            "admin_agent_workflow" => Self::AdminAgentWorkflow,
            "admin_agent_schedule" => Self::AdminAgentSchedule,
            "admin_api_key" => Self::AdminApiKey,
            "admin_policy" => Self::AdminPolicy,
            "guardrail_policy" => Self::GuardrailPolicy,
            "tenant_hierarchy" => Self::TenantHierarchy,
            "admin_virtual_key" => Self::AdminVirtualKey,
            "quota_policy" => Self::QuotaPolicy,
            "asset" => Self::Asset,
            "site" => Self::Site,
            "site_domain" => Self::SiteDomain,
            "billing" => Self::Billing,
            "rbac" => Self::Rbac,
            "plans" => Self::Plans,
            "wallets" => Self::Wallets,
            _ => return None,
        })
    }
}

pub(super) use super::api_contract::match_route_group;

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
            RouteGroup::Health | RouteGroup::Readiness => Ok(false),
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
            RouteGroup::AdminAgentSchedule => {
                self.try_admin_agent_schedule_routes(session, ctx, req)
                    .await
            }
            RouteGroup::AdminApiKey => self.try_admin_api_key_routes(session, ctx, req).await,
            RouteGroup::AdminPolicy => self.try_admin_policy_routes(session, ctx, req).await,
            RouteGroup::GuardrailPolicy => {
                self.handle_guardrail_policies(session, ctx, &req.headers, &req.method, &req.path)
                    .await?;
                Ok(true)
            }
            RouteGroup::TenantHierarchy => {
                self.try_tenant_hierarchy_routes(session, ctx, req).await
            }
            RouteGroup::AdminVirtualKey => {
                self.try_admin_virtual_key_routes(session, ctx, req).await
            }
            RouteGroup::QuotaPolicy => self.try_quota_policy_routes(session, ctx, req).await,
            RouteGroup::Asset => self.try_asset_routes(session, ctx, req).await,
            RouteGroup::Site => self.try_site_routes(session, ctx, req).await,
            RouteGroup::SiteDomain => self.try_site_domain_routes(session, ctx, req).await,
            RouteGroup::Billing => self.try_billing_routes(session, ctx, req).await,
            RouteGroup::Rbac => self.try_rbac_routes(session, ctx, req).await,
            RouteGroup::Plans => self.try_plans_routes(session, ctx, req).await,
            RouteGroup::Wallets => self.try_wallets_routes(session, ctx, req).await,
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
        if req.path == "/v1/messages" {
            self.handle_messages(session, ctx, req.headers.clone())
                .await?;
            return Ok(true);
        }
        if req.path == "/v1/embeddings" {
            self.handle_embeddings(session, ctx, req.headers.clone())
                .await?;
            return Ok(true);
        }
        if req.path == "/v1/images/generations" {
            self.handle_images(session, ctx, req.headers.clone())
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
        if req.path == "/v1/mcp/identity/callback" || req.path.starts_with("/v1/mcp/identity/") {
            self.handle_mcp_identity(
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
        if req.path == "/admin/v1/guardrail-evaluations" {
            self.handle_admin_guardrail_evaluations(
                session,
                ctx,
                &req.headers,
                req.query.as_deref(),
            )
            .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/investigations" {
            self.handle_admin_guardrail_investigation(
                session,
                ctx,
                &req.headers,
                req.query.as_deref(),
            )
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
            self.handle_admin_providers(session, ctx, &req.headers, req.query.as_deref())
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
        if req.path == "/admin/v1/observed-agent-activity" {
            self.handle_admin_observed_agent_activity(
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
            self.handle_admin_models(session, ctx, &req.headers, req.query.as_deref())
                .await?;
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

    async fn try_admin_agent_schedule_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/agent-schedules"
            || req.path.starts_with("/admin/v1/agent-schedules/")
        {
            self.handle_admin_agent_schedules(
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
        if req.path == "/admin/v1/tenant-accounts"
            || req.path.starts_with("/admin/v1/tenant-accounts/")
        {
            self.handle_admin_tenant_accounts(
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
        if req.path == "/admin/v1/projects" || req.path.starts_with("/admin/v1/projects/") {
            self.handle_admin_projects(
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
        if req.path == "/admin/v1/workspaces" || req.path.starts_with("/admin/v1/workspaces/") {
            self.handle_admin_workspaces(
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

    async fn try_plans_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/plans" || req.path.starts_with("/admin/v1/plans/") {
            self.handle_admin_plans(session, ctx, &req.headers, &req.method, &req.path)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_wallets_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/wallets" || req.path.starts_with("/admin/v1/wallets/") {
            self.handle_admin_wallets(session, ctx, &req.headers, &req.method, &req.path)
                .await?;
            return Ok(true);
        }
        if req.path == "/admin/v1/payment-methods"
            || req.path.starts_with("/admin/v1/payment-methods/")
        {
            self.handle_admin_payment_methods(
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
        Ok(false)
    }

    async fn try_asset_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        // Large-file presigned path (issue #259): matched first so its
        // `/v1/assets/presign/...` sub-paths reach asset_presign.rs rather
        // than the inline 3-segment handler. Falls through when the path is
        // not a presign route.
        if self.try_asset_presign_routes(session, ctx, req).await? {
            return Ok(true);
        }
        if req.path == "/v1/assets" || req.path.starts_with("/v1/assets/") {
            self.handle_assets(
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
        Ok(false)
    }

    async fn try_site_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path.starts_with("/sites/") {
            self.handle_site_serve(session, ctx, &req.headers, &req.method, &req.path)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn try_site_domain_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/site-domains" || req.path.starts_with("/admin/v1/site-domains/") {
            self.handle_admin_site_domains(
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
        Ok(false)
    }

    async fn try_rbac_routes(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
    ) -> PingoraResult<bool> {
        if req.path == "/admin/v1/permissions" || req.path.starts_with("/admin/v1/permissions/") {
            self.handle_admin_permissions(
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
        if let Some(report_id) = req
            .path
            .strip_prefix("/admin/v1/billing-outbox-dead-letters/")
            .and_then(|rest| rest.strip_suffix("/replay"))
            .filter(|report_id| !report_id.is_empty())
        {
            if req.method != http::Method::POST {
                write_json_error(
                    session,
                    http::StatusCode::METHOD_NOT_ALLOWED,
                    "method_not_allowed",
                    "dead-letter replay only supports POST",
                    &ctx.request_id,
                )
                .await?;
                return Ok(true);
            }
            self.handle_admin_billing_outbox_dead_letter_replay(
                session,
                ctx,
                &req.headers,
                report_id,
            )
            .await?;
            return Ok(true);
        }
        Ok(false)
    }
}

#[cfg(test)]
#[path = "route_groups_test.rs"]
mod route_groups_test;
