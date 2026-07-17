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

        // CSRF / confused-deputy defense for admin mutations. In zero-config
        // mode auth is disabled, so `authenticate()` admits any request; without
        // this a malicious web page could drive a cross-site state-changing POST
        // to an /admin route (e.g. config/reload) as a CORS "simple request"
        // (text/plain, no preflight), using the victim's browser as a confused
        // deputy to take over the gateway config. Reject browser cross-site
        // mutations regardless of auth mode. Non-browser clients (curl, SDKs, the
        // CLI, tests) send neither Sec-Fetch-Site nor Origin and are unaffected;
        // the same-origin admin console sends `Sec-Fetch-Site: same-origin`.
        if path.starts_with("/admin/") && admin_method_is_state_changing(&req.method) {
            if let Some(reason) = admin_cross_site_rejection(&request_headers) {
                write_json_error(
                    session,
                    StatusCode::FORBIDDEN,
                    "cross_site_admin_denied",
                    reason,
                    &ctx.request_id,
                )
                .await?;
                return Ok(true);
            }
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

/// State-changing HTTP methods (the CSRF-relevant ones for admin routes). Safe
/// methods (GET/HEAD) and OPTIONS are excluded.
fn admin_method_is_state_changing(method: &http::Method) -> bool {
    matches!(
        *method,
        http::Method::POST | http::Method::PUT | http::Method::PATCH | http::Method::DELETE
    )
}

/// Returns a rejection reason if an admin mutation looks like a cross-site
/// browser request, else `None`.
///
/// `Sec-Fetch-Site` (sent by every modern browser and NOT settable by page
/// JavaScript -- it is a forbidden header) is authoritative when present:
/// `cross-site`/`same-site` are rejected, `same-origin`/`none` allowed. When it
/// is absent the caller is either a non-browser client (no `Origin` -> allowed)
/// or an older browser, in which case a present `Origin` must match the
/// configured admin-console origin.
fn admin_cross_site_rejection(headers: &http::HeaderMap) -> Option<&'static str> {
    if let Some(site) = headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
    {
        if site.eq_ignore_ascii_case("cross-site") || site.eq_ignore_ascii_case("same-site") {
            return Some("cross-site admin mutations are not permitted");
        }
        // same-origin / none: an actual same-origin request or a direct
        // navigation / non-website initiator -- safe.
        return None;
    }
    if let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        match cors_allowed_origin() {
            Some(allowed) if origin == allowed => {}
            _ => return Some("cross-origin admin mutations are not permitted"),
        }
    }
    None
}

#[cfg(test)]
mod handlers_test {
    use super::{admin_cross_site_rejection, admin_method_is_state_changing};
    use http::{HeaderMap, HeaderValue, Method};

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn only_mutating_methods_are_guarded() {
        assert!(admin_method_is_state_changing(&Method::POST));
        assert!(admin_method_is_state_changing(&Method::DELETE));
        assert!(!admin_method_is_state_changing(&Method::GET));
        assert!(!admin_method_is_state_changing(&Method::OPTIONS));
    }

    #[test]
    fn cross_site_browser_mutation_is_rejected() {
        assert!(
            admin_cross_site_rejection(&headers(&[("sec-fetch-site", "cross-site")])).is_some()
        );
        assert!(admin_cross_site_rejection(&headers(&[("sec-fetch-site", "same-site")])).is_some());
    }

    #[test]
    fn same_origin_and_non_browser_are_allowed() {
        // Modern same-origin admin console.
        assert!(
            admin_cross_site_rejection(&headers(&[("sec-fetch-site", "same-origin")])).is_none()
        );
        // Direct navigation / non-website initiator.
        assert!(admin_cross_site_rejection(&headers(&[("sec-fetch-site", "none")])).is_none());
        // Non-browser client (curl / SDK / CLI / test): no Sec-Fetch-Site, no Origin.
        assert!(admin_cross_site_rejection(&HeaderMap::new()).is_none());
    }

    #[test]
    fn old_browser_cross_origin_by_origin_header_is_rejected() {
        // No Sec-Fetch-Site, but a cross-origin Origin with no console configured.
        assert!(
            admin_cross_site_rejection(&headers(&[("origin", "https://evil.example")])).is_some()
        );
    }
}
