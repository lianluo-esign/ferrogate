// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use bytes::Bytes;
use pingora::{proxy::Session, Result as PingoraResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RequestBodyTooLarge {
    pub max_bytes: usize,
}

pub(crate) async fn read_request_body(
    session: &mut Session,
    max_bytes: usize,
) -> PingoraResult<Result<Bytes, RequestBodyTooLarge>> {
    let mut body = Vec::new();
    while let Some(chunk) = session.as_downstream_mut().read_request_body().await? {
        if body.len() + chunk.len() > max_bytes {
            return Ok(Err(RequestBodyTooLarge { max_bytes }));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Ok(Bytes::from(body)))
}
