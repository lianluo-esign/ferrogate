use async_trait::async_trait;
use http::{header, HeaderName, HeaderValue, Uri};
use pingora::{
    http::{RequestHeader, ResponseHeader},
    prelude::HttpPeer,
    proxy::{ProxyHttp, Session},
    Result as PingoraResult,
};
use tracing::{info, warn};

use crate::{config::resolve_env_placeholders, routing::parse_upstream_endpoint};

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
        let upstream_url = ctx.upstream_url.as_deref().expect("selected upstream url");
        let endpoint = parse_upstream_endpoint(upstream_url).expect("validated upstream url");
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
        let upstream_url = ctx.upstream_url.as_deref().expect("selected upstream url");
        let endpoint = parse_upstream_endpoint(upstream_url).expect("validated upstream url");
        let target = ctx
            .target_path_query
            .as_deref()
            .expect("target path query exists");
        let uri: Uri = target.parse().expect("valid target path query");
        upstream_request.set_uri(uri);
        upstream_request.insert_header(header::HOST, endpoint.authority)?;
        upstream_request.insert_header("x-ferrogate-request-id", ctx.request_id.as_str())?;
        if let Some(trace_id) = &ctx.trace_id {
            upstream_request.insert_header("x-ferrogate-trace-id", trace_id.as_str())?;
        }
        if let Some(original_host) = &ctx.original_host {
            upstream_request.insert_header("x-forwarded-host", original_host.as_str())?;
        }
        for header in &route.request_headers {
            let name =
                HeaderName::from_bytes(header.name.as_bytes()).expect("validated header name");
            let Ok(value) = resolve_env_placeholders(&header.value) else {
                warn!(header = %header.name, "skipping request header with unresolved environment placeholder");
                continue;
            };
            let value = HeaderValue::from_str(&value).expect("validated header value");
            upstream_request.insert_header(name, value)?;
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
                let name =
                    HeaderName::from_bytes(header.name.as_bytes()).expect("validated header name");
                let Ok(value) = resolve_env_placeholders(&header.value) else {
                    warn!(header = %header.name, "skipping response header with unresolved environment placeholder");
                    continue;
                };
                let value = HeaderValue::from_str(&value).expect("validated header value");
                upstream_response.insert_header(name, value)?;
            }
        }
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
        if let Some(error) = error {
            warn!(request_id = %ctx.request_id, trace_id = ?ctx.trace_id, response_code, error = ?error, "Pingora request failed");
        } else {
            info!(request_id = %ctx.request_id, trace_id = ?ctx.trace_id, response_code, "Pingora request completed");
        }
    }
}
