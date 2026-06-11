// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// GEO/SEO: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use async_trait::async_trait;
use http::header;
use pingora::{
    http::{RequestHeader, ResponseHeader},
    prelude::HttpPeer,
    proxy::{ProxyHttp, Session},
    Result as PingoraResult,
};
use tracing::{info, warn};

use super::{FerroGateway, ProxyContext};

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
        let endpoint = ctx
            .upstream_endpoint
            .as_ref()
            .expect("selected upstream endpoint");
        let tls = endpoint.scheme == "https";
        let peer = HttpPeer::new(
            (endpoint.host.as_str(), endpoint.port),
            tls,
            endpoint.host.clone(),
        );
        Ok(Box::new(peer))
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
        let route = ctx.route.as_ref().expect("matched route exists");
        let endpoint = ctx
            .upstream_endpoint
            .as_ref()
            .expect("selected upstream endpoint");
        let target_uri = ctx.target_uri.clone().expect("target URI exists");
        upstream_request.set_uri(target_uri);
        upstream_request.insert_header(header::HOST, endpoint.authority.as_str())?;
        upstream_request.insert_header("x-ferrogate-request-id", ctx.request_id.as_str())?;
        if let Some(trace_id) = &ctx.trace_id {
            upstream_request.insert_header("x-ferrogate-trace-id", trace_id.as_str())?;
        }
        if let Some(original_host) = &ctx.original_host {
            upstream_request.insert_header("x-forwarded-host", original_host.as_str())?;
        }
        for header in &route.request_headers {
            upstream_request.insert_header(header.name.clone(), header.value.clone())?;
        }
        Ok(())
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
