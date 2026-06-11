use http::{header, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};

use crate::{
    responses::write_json_error,
    routing::{build_target_uri, normalize_host},
};

use super::{FerroGateway, ProxyContext};

impl FerroGateway {
    pub(super) async fn handle_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> PingoraResult<bool> {
        ctx.request_id = self.state.next_request_id();
        ctx.trace_id = Some(ctx.request_id.clone());
        let state = self.state.current();
        let req = session.req_header();
        let path = req.uri.path().to_string();

        if let Err(error) = state.run_pre_request_hooks(&ctx.request_id, &path) {
            write_json_error(
                session,
                error.status(),
                error.code(),
                error.message(),
                &ctx.request_id,
            )
            .await?;
            return Ok(true);
        }

        if path == "/healthz" {
            self.handle_healthz(session, ctx).await?;
            return Ok(true);
        }

        if let Err(error) = self.state.sync_shared_control_plane() {
            tracing::warn!("failed to sync shared control plane: {error}");
        }

        if path == "/readyz" {
            self.handle_readyz(session, ctx).await?;
            return Ok(true);
        }

        if path == "/admin" || path == "/admin/" || path == "/admin/dashboard" {
            self.handle_admin_dashboard(session, ctx).await?;
            return Ok(true);
        }

        if path == "/v1/models" {
            let headers = req.headers.clone();
            self.handle_models(session, ctx, &headers).await?;
            return Ok(true);
        }

        if path == "/v1/tools" {
            let headers = req.headers.clone();
            let query = req.uri.query().map(str::to_string);
            self.handle_tools(session, ctx, &headers, query.as_deref())
                .await?;
            return Ok(true);
        }

        if path == "/v1/tools/execute" {
            let headers = req.headers.clone();
            let method = req.method.clone();
            self.handle_tool_execute(session, ctx, headers, &method)
                .await?;
            return Ok(true);
        }

        if path == "/v1/mcp/tool/execute" {
            let headers = req.headers.clone();
            let method = req.method.clone();
            self.handle_mcp_tool_execute(session, ctx, headers, &method)
                .await?;
            return Ok(true);
        }

        if path == "/v1/chat/completions" {
            self.handle_chat_completions(session, ctx, req.headers.clone())
                .await?;
            return Ok(true);
        }

        if path == "/v1/responses" {
            self.handle_responses(session, ctx, req.headers.clone())
                .await?;
            return Ok(true);
        }

        if path == "/admin/status" || path == "/admin/v1/status" {
            let headers = req.headers.clone();
            self.handle_admin_status(session, ctx, &headers).await?;
            return Ok(true);
        }

        if path == "/admin/v1/request-logs" {
            let headers = req.headers.clone();
            let query = req.uri.query().map(str::to_string);
            self.handle_admin_request_logs(session, ctx, &headers, query.as_deref())
                .await?;
            return Ok(true);
        }

        if path == "/admin/v1/audit-events" {
            let headers = req.headers.clone();
            let query = req.uri.query().map(str::to_string);
            self.handle_admin_audit_events(session, ctx, &headers, query.as_deref())
                .await?;
            return Ok(true);
        }

        if path == "/admin/v1/config/validate" {
            let headers = req.headers.clone();
            let method = req.method.clone();
            self.handle_admin_config_validate(session, ctx, &headers, &method)
                .await?;
            return Ok(true);
        }

        if path == "/admin/v1/config/reload" {
            let headers = req.headers.clone();
            let method = req.method.clone();
            self.handle_admin_config_reload(session, ctx, &headers, &method)
                .await?;
            return Ok(true);
        }

        if path == "/admin/v1/drain" {
            let headers = req.headers.clone();
            let method = req.method.clone();
            self.handle_admin_drain(session, ctx, &headers, &method)
                .await?;
            return Ok(true);
        }

        if path == "/admin/v1/providers" {
            let headers = req.headers.clone();
            self.handle_admin_providers(session, ctx, &headers).await?;
            return Ok(true);
        }

        if path == "/admin/v1/provider-health" {
            let headers = req.headers.clone();
            self.handle_admin_provider_health(session, ctx, &headers)
                .await?;
            return Ok(true);
        }

        if path == "/admin/v1/extensions" {
            let headers = req.headers.clone();
            self.handle_admin_extensions(session, ctx, &headers).await?;
            return Ok(true);
        }

        if path == "/admin/v1/tools" {
            let headers = req.headers.clone();
            self.handle_admin_tools(session, ctx, &headers).await?;
            return Ok(true);
        }

        if path == "/admin/v1/mcp-servers" {
            let headers = req.headers.clone();
            self.handle_admin_mcp_servers(session, ctx, &headers)
                .await?;
            return Ok(true);
        }

        if path.starts_with("/admin/v1/tool-sessions/") {
            let headers = req.headers.clone();
            self.handle_admin_tool_session(session, ctx, &headers, &path)
                .await?;
            return Ok(true);
        }

        if path == "/admin/v1/models" {
            let headers = req.headers.clone();
            self.handle_admin_models(session, ctx, &headers).await?;
            return Ok(true);
        }

        if path == "/admin/v1/gateway-configs" || path.starts_with("/admin/v1/gateway-configs/") {
            let headers = req.headers.clone();
            let method = req.method.clone();
            self.handle_admin_gateway_configs(session, ctx, &headers, &method, &path)
                .await?;
            return Ok(true);
        }

        if path == "/admin/v1/api-keys" || path.starts_with("/admin/v1/api-keys/") {
            let headers = req.headers.clone();
            let method = req.method.clone();
            self.handle_admin_api_keys(session, ctx, &headers, &method, &path)
                .await?;
            return Ok(true);
        }

        if path == "/admin/v1/policies" || path.starts_with("/admin/v1/policies/") {
            let headers = req.headers.clone();
            let method = req.method.clone();
            self.handle_admin_policies(session, ctx, &headers, &method, &path)
                .await?;
            return Ok(true);
        }

        if path == "/admin/v1/tenants" {
            let headers = req.headers.clone();
            self.handle_admin_tenants(session, ctx, &headers).await?;
            return Ok(true);
        }

        if path == "/admin/v1/metering-events" {
            let headers = req.headers.clone();
            let query = req.uri.query().map(str::to_string);
            self.handle_admin_metering_events(session, ctx, &headers, query.as_deref())
                .await?;
            return Ok(true);
        }

        if path == "/admin/v1/billing-events" {
            let headers = req.headers.clone();
            let query = req.uri.query().map(str::to_string);
            self.handle_admin_billing_events(session, ctx, &headers, query.as_deref())
                .await?;
            return Ok(true);
        }

        if path == "/admin/v1/usage-aggregates" {
            let headers = req.headers.clone();
            self.handle_admin_usage_aggregates(session, ctx, &headers)
                .await?;
            return Ok(true);
        }

        if path == "/metrics" {
            let headers = req.headers.clone();
            self.handle_metrics(session, ctx, &headers).await?;
            return Ok(true);
        }

        let host = req
            .headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let normalized_host = host
            .as_deref()
            .map(normalize_host)
            .filter(|value| !value.is_empty());

        let Some(route) =
            state.match_runtime_route(normalized_host.as_deref(), &path, &req.headers)
        else {
            write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "route_not_found",
                format!("no route matched {} {}", req.method, path),
                &ctx.request_id,
            )
            .await?;
            return Ok(true);
        };

        let Some(upstream) = state.upstreams.get(&route.config.upstream).cloned() else {
            write_json_error(
                session,
                StatusCode::BAD_GATEWAY,
                "upstream_not_found",
                format!(
                    "route {} references missing upstream {}",
                    route.config.name, route.config.upstream
                ),
                &ctx.request_id,
            )
            .await?;
            return Ok(true);
        };

        if !upstream.enabled {
            write_json_error(
                session,
                StatusCode::BAD_GATEWAY,
                "upstream_disabled",
                format!("upstream {} is disabled", upstream.name),
                &ctx.request_id,
            )
            .await?;
            return Ok(true);
        }

        let Some(upstream_endpoint) = state.select_runtime_upstream_endpoint(&upstream.name) else {
            write_json_error(
                session,
                StatusCode::BAD_GATEWAY,
                "upstream_empty",
                format!("upstream {} has no enabled endpoints", upstream.name),
                &ctx.request_id,
            )
            .await?;
            return Ok(true);
        };

        ctx.tenant_id = None;

        let rewritten_path = route.rewrite_path(&path);
        match build_target_uri(
            &upstream_endpoint.endpoint,
            &rewritten_path,
            req.uri.query(),
        ) {
            Ok(target_uri) => {
                ctx.original_host = host;
                ctx.target_uri = Some(target_uri);
                ctx.route = Some(route);
                ctx.upstream = Some(upstream);
                ctx.upstream_endpoint = Some(upstream_endpoint.endpoint);
                Ok(false)
            }
            Err(error) => {
                write_json_error(
                    session,
                    StatusCode::BAD_GATEWAY,
                    "target_url_error",
                    error.to_string(),
                    &ctx.request_id,
                )
                .await?;
                Ok(true)
            }
        }
    }
}
