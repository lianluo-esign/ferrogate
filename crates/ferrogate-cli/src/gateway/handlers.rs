// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use http::{header, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};

use crate::{
    responses::{cors_allowed_origin, write_cors_preflight_response, write_json_error},
    routing::{build_target_uri, normalize_host},
    state::NetworkAccessDecision,
};

use super::route_groups::{RequestParts, RouteGroup};
use super::{FerroGateway, ProxyContext};

impl FerroGateway {
    pub(super) async fn handle_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> PingoraResult<bool> {
        ctx.request_id = self.state.next_request_id();
        let state = self.state.current();
        let req = session.req_header();
        let trace = super::ingress_trace_context(&req.headers, &ctx.request_id);
        ctx.trace_id = Some(trace.trace_id);
        ctx.traceparent = trace.traceparent;
        ctx.tracestate = trace.tracestate;
        let path = req.uri.path().to_string();
        let request_headers = req.headers.clone();
        let peer_ip = session
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .map(|inet| inet.ip());

        match state.check_network_access(&request_headers, peer_ip) {
            NetworkAccessDecision::Allowed => {}
            NetworkAccessDecision::IpDenied => {
                write_json_error(
                    session,
                    StatusCode::FORBIDDEN,
                    "ip_denied",
                    "source IP is not permitted",
                    &ctx.request_id,
                )
                .await?;
                return Ok(true);
            }
            NetworkAccessDecision::RateLimited => {
                write_json_error(
                    session,
                    StatusCode::TOO_MANY_REQUESTS,
                    "unauthenticated_rate_limited",
                    "too many requests from this source; try again later",
                    &ctx.request_id,
                )
                .await?;
                return Ok(true);
            }
        }

        if req.method == http::Method::OPTIONS
            && path.starts_with("/admin/")
            && cors_allowed_origin().is_some()
        {
            write_cors_preflight_response(session).await?;
            return Ok(true);
        }

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

        let fixed_group = super::api_contract::match_route_group(&path);
        let fixed_operation = super::api_contract::operation(&req.method, &path);
        if fixed_operation.is_none() && super::api_contract::path_is_documented(&path) {
            write_json_error(
                session,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                format!("{} is not documented for {path}", req.method),
                &ctx.request_id,
            )
            .await?;
            return Ok(true);
        }
        if let Some(operation) = fixed_operation {
            tracing::trace!(
                operation_id = %operation.operation_id,
                visibility = %operation.visibility,
                auth_kind = %operation.auth.kind,
                auth_scope = operation.auth.scope.as_deref().unwrap_or("none"),
                rbac_action = operation.rbac_action.as_deref().unwrap_or("none"),
                "matched fixed API operation contract"
            );
        }

        if fixed_group == Some(RouteGroup::Health) {
            self.handle_healthz(session, ctx).await?;
            return Ok(true);
        }

        if let Err(error) = self.state.sync_shared_control_plane() {
            tracing::warn!("failed to sync shared control plane: {error}");
        }

        if fixed_group == Some(RouteGroup::Readiness) {
            self.handle_readyz(session, ctx).await?;
            return Ok(true);
        }

        let parts = RequestParts {
            headers: req.headers.clone(),
            method: req.method.clone(),
            path: path.clone(),
            query: req.uri.query().map(str::to_string),
        };
        if self.try_route_groups(session, ctx, &parts).await? {
            return Ok(true);
        }

        let host = parts
            .headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let normalized_host = host
            .as_deref()
            .map(normalize_host)
            .filter(|value| !value.is_empty());

        let Some(route) =
            state.match_runtime_route(normalized_host.as_deref(), &path, &parts.headers)
        else {
            write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "route_not_found",
                format!("no route matched {} {}", parts.method, path),
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
            parts.query.as_deref(),
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
