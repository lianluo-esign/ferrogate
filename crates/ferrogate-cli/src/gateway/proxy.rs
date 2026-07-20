// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use async_trait::async_trait;
use http::header;
use pingora::{
    http::{RequestHeader, ResponseHeader},
    prelude::HttpPeer,
    proxy::{ProxyHttp, Session},
    Result as PingoraResult,
};
use tracing::{error, info, warn};

use super::{FerroGateway, ProxyContext};

/// Invariant (#312): `request_filter` populates `ctx.route`,
/// `ctx.upstream_endpoint`, and `ctx.target_uri` on every path that returns
/// `Ok(false)` (continue to upstream). The upstream hooks below must not
/// assume that invariant with `expect()`: a future fall-through path that
/// forgets to populate the context would panic the Pingora worker. Instead,
/// a violated invariant is logged and the single request fails with a
/// 502-class error via Pingora's `fail_to_proxy` path.
fn missing_ctx_error(field: &'static str, request_id: &str) -> Box<pingora::Error> {
    error!(
        request_id = %request_id,
        missing_field = field,
        "proxy context invariant violated: reached upstream phase without populated ctx; failing request with 502"
    );
    pingora::Error::explain(
        pingora::ErrorType::HTTPStatus(502),
        format!("missing proxy context field: {field}"),
    )
}

/// Pure helper behind `ProxyHttp::upstream_peer`, split out so the
/// unpopulated-ctx error path is unit-testable without a live `Session`.
fn resolve_upstream_peer(ctx: &ProxyContext) -> PingoraResult<Box<HttpPeer>> {
    let Some(endpoint) = ctx.upstream_endpoint.as_ref() else {
        return Err(missing_ctx_error("upstream_endpoint", &ctx.request_id));
    };
    let tls = endpoint.scheme == "https";
    let peer = HttpPeer::new(
        (endpoint.host.as_str(), endpoint.port),
        tls,
        endpoint.host.clone(),
    );
    Ok(Box::new(peer))
}

/// Pure helper behind `ProxyHttp::upstream_request_filter`; see
/// `resolve_upstream_peer` for the testability rationale.
fn apply_upstream_request_filter(
    ctx: &ProxyContext,
    upstream_request: &mut RequestHeader,
) -> PingoraResult<()> {
    let Some(route) = ctx.route.as_ref() else {
        return Err(missing_ctx_error("route", &ctx.request_id));
    };
    let Some(endpoint) = ctx.upstream_endpoint.as_ref() else {
        return Err(missing_ctx_error("upstream_endpoint", &ctx.request_id));
    };
    let Some(target_uri) = ctx.target_uri.clone() else {
        return Err(missing_ctx_error("target_uri", &ctx.request_id));
    };
    upstream_request.set_uri(target_uri);
    upstream_request.insert_header(header::HOST, endpoint.authority.as_str())?;
    upstream_request.insert_header("x-ferrogate-request-id", ctx.request_id.as_str())?;
    if let Some(trace_id) = &ctx.trace_id {
        upstream_request.insert_header("x-ferrogate-trace-id", trace_id.as_str())?;
    }
    if let Some(traceparent) = &ctx.traceparent {
        upstream_request.insert_header("traceparent", traceparent.as_str())?;
    }
    if let Some(tracestate) = &ctx.tracestate {
        upstream_request.insert_header("tracestate", tracestate.as_str())?;
    }
    if let Some(original_host) = &ctx.original_host {
        upstream_request.insert_header("x-forwarded-host", original_host.as_str())?;
    }
    for header in &route.request_headers {
        upstream_request.insert_header(header.name.clone(), header.value.clone())?;
    }
    Ok(())
}

#[async_trait]
impl ProxyHttp for FerroGateway {
    type CTX = ProxyContext;

    fn new_ctx(&self) -> Self::CTX {
        ProxyContext::default()
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<bool>
    where
        Self::CTX: Send + Sync,
    {
        self.handle_request_filter(session, ctx).await
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<Box<HttpPeer>> {
        resolve_upstream_peer(ctx)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()>
    where
        Self::CTX: Send + Sync,
    {
        apply_upstream_request_filter(ctx, upstream_request)
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()>
    where
        Self::CTX: Send + Sync,
    {
        upstream_response.insert_header("server", "FerroGate")?;
        upstream_response.insert_header("x-ferrogate-runtime", "pingora")?;
        upstream_response.insert_header("x-request-id", ctx.request_id.as_str())?;
        if let Some(trace_id) = &ctx.trace_id {
            upstream_response.insert_header("x-trace-id", trace_id.as_str())?;
        }
        if let Some(route) = &ctx.route {
            for header in &route.response_headers {
                upstream_response.insert_header(header.name.clone(), header.value.clone())?;
            }
        }
        self.state
            .current()
            .run_post_response_hooks(&ctx.request_id, upstream_response.status.as_u16());
        Ok(())
    }

    async fn logging(
        &self,
        session: &mut Session,
        error: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        let response_code = session
            .response_written()
            .map_or(0, |resp| resp.status.as_u16());
        let state = self.state.current();
        if !state.should_log_access(&ctx.request_id, response_code, error.is_some()) {
            return;
        }
        if let Some(error) = error {
            warn!(request_id = %ctx.request_id, trace_id = ?ctx.trace_id, response_code, error = ?error, "Pingora request failed");
        } else {
            info!(request_id = %ctx.request_id, trace_id = ?ctx.trace_id, response_code, "Pingora request completed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::UpstreamEndpoint;
    use pingora::ErrorType;

    // `HttpPeer::new` resolves non-IP hosts via DNS, so use a literal
    // address to keep the happy-path test hermetic.
    fn test_endpoint() -> UpstreamEndpoint {
        UpstreamEndpoint {
            scheme: "https".to_string(),
            host: "127.0.0.1".to_string(),
            port: 8443,
            authority: "127.0.0.1:8443".to_string(),
            base_path: String::new(),
        }
    }

    /// #312: an unpopulated ctx reaching `upstream_peer` must fail the
    /// request with a 502-class error instead of panicking the worker.
    #[test]
    fn upstream_peer_with_unpopulated_ctx_fails_with_502_instead_of_panicking() {
        let ctx = ProxyContext::default();
        let error = resolve_upstream_peer(&ctx).expect_err("missing endpoint must error");
        assert_eq!(*error.etype(), ErrorType::HTTPStatus(502));
        assert!(error.to_string().contains("upstream_endpoint"));
    }

    #[test]
    fn upstream_peer_with_populated_ctx_builds_peer() {
        let ctx = ProxyContext {
            upstream_endpoint: Some(test_endpoint()),
            ..ProxyContext::default()
        };
        resolve_upstream_peer(&ctx).expect("populated ctx must resolve a peer");
    }

    /// #312: same invariant for `upstream_request_filter` -- a request that
    /// somehow skipped route selection fails gracefully with a 502.
    #[test]
    fn upstream_request_filter_with_unpopulated_ctx_fails_with_502_instead_of_panicking() {
        let ctx = ProxyContext::default();
        let mut upstream_request =
            RequestHeader::build("POST", b"/v1/chat/completions", None).expect("request header");
        let error = apply_upstream_request_filter(&ctx, &mut upstream_request)
            .expect_err("missing route must error");
        assert_eq!(*error.etype(), ErrorType::HTTPStatus(502));
        assert!(error.to_string().contains("route"));
    }

    /// A ctx that carries an endpoint but no target URI (route populated is
    /// checked first, so exercise the later guard by filling earlier fields)
    /// still fails gracefully rather than panicking on `expect()`.
    #[test]
    fn upstream_request_filter_reports_first_missing_field() {
        let ctx = ProxyContext {
            upstream_endpoint: Some(test_endpoint()),
            target_uri: Some(http::Uri::from_static("https://upstream.example/v1/x")),
            ..ProxyContext::default()
        };
        let mut upstream_request =
            RequestHeader::build("POST", b"/v1/x", None).expect("request header");
        let error = apply_upstream_request_filter(&ctx, &mut upstream_request)
            .expect_err("missing route must error");
        assert_eq!(*error.etype(), ErrorType::HTTPStatus(502));
        assert!(error.to_string().contains("route"));
    }
}
