use bytes::Bytes;
use http::{header, StatusCode};
use pingora::{http::ResponseHeader, proxy::Session, ErrorType, OrErr, Result as PingoraResult};
use serde::Serialize;
use std::io::Read;

#[derive(Debug, Serialize)]
pub(crate) struct HealthResponse<'a> {
    pub(crate) status: &'a str,
    pub(crate) service: &'a str,
    pub(crate) version: &'a str,
    pub(crate) runtime: &'a str,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminStatus<'a> {
    pub(crate) service: &'a str,
    pub(crate) version: &'a str,
    pub(crate) runtime: &'a str,
    pub(crate) snapshot: String,
    pub(crate) providers: usize,
    pub(crate) enabled_providers: usize,
    pub(crate) models: usize,
    pub(crate) enabled_models: usize,
    pub(crate) api_keys: usize,
    pub(crate) upstreams: usize,
    pub(crate) enabled_upstreams: usize,
    pub(crate) routes: usize,
    pub(crate) enabled_routes: usize,
    pub(crate) auth_required: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct OpenAiModelList {
    pub(crate) object: &'static str,
    pub(crate) data: Vec<OpenAiModel>,
}

#[derive(Debug, Serialize)]
pub(crate) struct OpenAiModel {
    pub(crate) id: String,
    pub(crate) object: &'static str,
    pub(crate) created: u64,
    pub(crate) owned_by: String,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: ErrorObject,
}

#[derive(Debug, Serialize)]
struct ErrorObject {
    message: String,
    #[serde(rename = "type")]
    kind: &'static str,
    code: &'static str,
    request_id: Option<String>,
}

pub(crate) async fn write_json_response<T: Serialize>(
    session: &mut Session,
    status: StatusCode,
    value: &T,
    request_id: &str,
) -> PingoraResult<()> {
    let body = serde_json::to_vec(value).expect("JSON serialization should not fail");
    let mut response = ResponseHeader::build(status, Some(4))?;
    response.insert_header(header::CONTENT_TYPE, "application/json")?;
    response.insert_header(header::CONTENT_LENGTH, body.len().to_string())?;
    response.insert_header("x-request-id", request_id)?;
    response.insert_header("x-ferrogate-runtime", "pingora")?;
    session
        .write_response_header(Box::new(response), false)
        .await?;
    session
        .write_response_body(Some(Bytes::from(body)), true)
        .await
}

pub(crate) async fn write_raw_response(
    session: &mut Session,
    status: StatusCode,
    content_type: &str,
    body: Bytes,
    request_id: &str,
) -> PingoraResult<()> {
    let mut response = ResponseHeader::build(status, Some(4))?;
    response.insert_header(header::CONTENT_TYPE, content_type)?;
    response.insert_header(header::CONTENT_LENGTH, body.len().to_string())?;
    response.insert_header("x-request-id", request_id)?;
    response.insert_header("x-ferrogate-runtime", "pingora")?;
    session
        .write_response_header(Box::new(response), false)
        .await?;
    session.write_response_body(Some(body), true).await
}

pub(crate) async fn write_streaming_response<R: Read>(
    session: &mut Session,
    status: StatusCode,
    content_type: &str,
    initial_body: Vec<u8>,
    mut reader: R,
    request_id: &str,
) -> PingoraResult<()> {
    let mut response = ResponseHeader::build(status, Some(4))?;
    response.insert_header(header::CONTENT_TYPE, content_type)?;
    response.insert_header("x-request-id", request_id)?;
    response.insert_header("x-ferrogate-runtime", "pingora")?;
    session
        .write_response_header(Box::new(response), false)
        .await?;

    if !initial_body.is_empty() {
        session
            .write_response_body(Some(Bytes::from(initial_body)), false)
            .await?;
    }

    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader
            .read(&mut buffer)
            .or_err(ErrorType::ReadError, "reading provider streaming response")?;
        if read == 0 {
            return session.write_response_body(None, true).await;
        }
        session
            .write_response_body(Some(Bytes::copy_from_slice(&buffer[..read])), false)
            .await?;
    }
}

pub(crate) async fn write_json_error(
    session: &mut Session,
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
    request_id: &str,
) -> PingoraResult<()> {
    let body = ErrorBody {
        error: ErrorObject {
            message: message.into(),
            kind: "ferrogate_error",
            code,
            request_id: Some(request_id.to_string()),
        },
    };
    write_json_response(session, status, &body, request_id).await
}
