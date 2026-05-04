use http::{header, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};

use crate::{
    responses::write_json_error,
    routing::{build_target_path_query, normalize_host},
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
        let req = session.req_header();
        let path = req.uri.path().to_string();

        if path == "/healthz" {
            self.handle_healthz(session, ctx).await?;
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

        if path == "/v1/chat/completions" {
            self.handle_chat_completions(session, ctx, req.headers.clone())
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
            self.handle_admin_request_logs(session, ctx, &headers)
                .await?;
            return Ok(true);
        }

        if path == "/admin/v1/audit-events" {
            let headers = req.headers.clone();
            self.handle_admin_audit_events(session, ctx, &headers)
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

        if path == "/admin/v1/providers" {
            let headers = req.headers.clone();
            self.handle_admin_providers(session, ctx, &headers).await?;
            return Ok(true);
        }

        if path == "/admin/v1/models" {
            let headers = req.headers.clone();
            self.handle_admin_models(session, ctx, &headers).await?;
            return Ok(true);
        }

        if path == "/admin/v1/api-keys" {
            let headers = req.headers.clone();
            self.handle_admin_api_keys(session, ctx, &headers).await?;
            return Ok(true);
        }

        if path == "/admin/v1/policies" {
            let headers = req.headers.clone();
            self.handle_admin_policies(session, ctx, &headers).await?;
            return Ok(true);
        }

        if path == "/admin/v1/tenants" {
            let headers = req.headers.clone();
            self.handle_admin_tenants(session, ctx, &headers).await?;
            return Ok(true);
        }

        if path == "/admin/v1/billing-events" {
            let headers = req.headers.clone();
            self.handle_admin_billing_events(session, ctx, &headers)
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

        let Some(route) = self
            .state
            .config
            .routes
            .iter()
            .filter(|route| route.enabled)
            .find(|route| route.matches_request(normalized_host.as_deref(), &path, &req.headers))
            .cloned()
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

        let Some(upstream) = self.state.upstreams.get(&route.upstream).cloned() else {
            write_json_error(
                session,
                StatusCode::BAD_GATEWAY,
                "upstream_not_found",
                format!(
                    "route {} references missing upstream {}",
                    route.name, route.upstream
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

        let Some(upstream_url) = self.state.select_upstream_url(&upstream) else {
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

        match build_target_path_query(&upstream_url, &route, &path, req.uri.query()) {
            Ok(path_query) => {
                ctx.original_host = host;
                ctx.target_path_query = Some(path_query);
                ctx.route = Some(route);
                ctx.upstream = Some(upstream);
                ctx.upstream_url = Some(upstream_url);
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
