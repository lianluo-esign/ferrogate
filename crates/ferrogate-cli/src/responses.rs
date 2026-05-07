use bytes::Bytes;
use http::{header, StatusCode};
use pingora::{http::ResponseHeader, proxy::Session, ErrorType, OrErr, Result as PingoraResult};
use serde::{Deserialize, Serialize};
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
pub(crate) struct AdminList<T> {
    pub(crate) object: &'static str,
    pub(crate) data: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) total: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) limit: Option<usize>,
}

impl<T> AdminList<T> {
    pub(crate) fn new(data: Vec<T>) -> Self {
        Self {
            object: "list",
            data,
            total: None,
            offset: None,
            limit: None,
        }
    }

    pub(crate) fn paginated(data: Vec<T>, total: usize, offset: usize, limit: usize) -> Self {
        Self {
            object: "list",
            data,
            total: Some(total),
            offset: Some(offset),
            limit: Some(limit),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminProvider {
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) base_url: String,
    pub(crate) has_api_key: bool,
    pub(crate) enabled: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminApiKey {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) enabled: bool,
    pub(crate) key_source: &'static str,
    pub(crate) scopes: Vec<String>,
    pub(crate) allowed_models: Vec<String>,
    pub(crate) denied_models: Vec<String>,
    pub(crate) allowed_providers: Vec<String>,
    pub(crate) denied_providers: Vec<String>,
    pub(crate) organization_id: Option<String>,
    pub(crate) team_id: Option<String>,
    pub(crate) project_id: Option<String>,
    pub(crate) user_id: Option<String>,
    pub(crate) monthly_token_budget: Option<u64>,
    pub(crate) request_limit_per_minute: Option<u64>,
    pub(crate) expires_at_unix: Option<u64>,
    pub(crate) log_bodies: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminApiKeyMutation {
    pub(crate) id: Option<String>,
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) key_env: Option<String>,
    #[serde(default)]
    pub(crate) key: Option<String>,
    #[serde(default)]
    pub(crate) key_hash: Option<String>,
    #[serde(default)]
    pub(crate) enabled: Option<bool>,
    #[serde(default)]
    pub(crate) scopes: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) allowed_models: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) denied_models: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) allowed_providers: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) denied_providers: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) organization_id: Option<String>,
    #[serde(default)]
    pub(crate) team_id: Option<String>,
    #[serde(default)]
    pub(crate) project_id: Option<String>,
    #[serde(default)]
    pub(crate) user_id: Option<String>,
    #[serde(default)]
    pub(crate) monthly_token_budget: Option<u64>,
    #[serde(default)]
    pub(crate) request_limit_per_minute: Option<u64>,
    #[serde(default)]
    pub(crate) expires_at_unix: Option<u64>,
    #[serde(default)]
    pub(crate) log_bodies: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminApiKeyMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) key: AdminApiKey,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminDeleteResponse {
    pub(crate) object: &'static str,
    pub(crate) id: String,
    pub(crate) deleted: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminPolicyMutation {
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) effect: Option<String>,
    #[serde(default)]
    pub(crate) organization_ids: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) project_ids: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) api_key_ids: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) models: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) providers: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) code: Option<String>,
    #[serde(default)]
    pub(crate) message: Option<String>,
    #[serde(default)]
    pub(crate) enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminPolicyMutationResponse<T> {
    pub(crate) object: &'static str,
    pub(crate) policy: T,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminTenantRef {
    pub(crate) organization_id: Option<String>,
    pub(crate) team_id: Option<String>,
    pub(crate) project_id: Option<String>,
    pub(crate) user_id: Option<String>,
    pub(crate) api_key_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminConfigValidateRequest {
    #[serde(default)]
    pub(crate) config_toml: Option<String>,
    #[serde(default)]
    pub(crate) config_caddyfile: Option<String>,
    #[serde(default)]
    pub(crate) filename: Option<String>,
    #[serde(default)]
    pub(crate) source: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminConfigValidateResponse {
    pub(crate) valid: bool,
    pub(crate) snapshot: Option<String>,
    pub(crate) reload_mode: Option<&'static str>,
    pub(crate) listener_reload_required: bool,
    pub(crate) reload_reason: Option<String>,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminConfigReloadResponse {
    pub(crate) valid: bool,
    pub(crate) committed: bool,
    pub(crate) mode: &'static str,
    pub(crate) active_snapshot: Option<String>,
    pub(crate) candidate_snapshot: Option<String>,
    pub(crate) error: Option<String>,
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
    code: String,
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
    response.insert_header("x-trace-id", request_id)?;
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
    response.insert_header("x-trace-id", request_id)?;
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
    response.insert_header("x-trace-id", request_id)?;
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
    code: impl Into<String>,
    message: impl Into<String>,
    request_id: &str,
) -> PingoraResult<()> {
    let body = ErrorBody {
        error: ErrorObject {
            message: message.into(),
            kind: "ferrogate_error",
            code: code.into(),
            request_id: Some(request_id.to_string()),
        },
    };
    write_json_response(session, status, &body, request_id).await
}

pub(crate) async fn write_json_error_and_close(
    session: &mut Session,
    status: StatusCode,
    code: impl Into<String>,
    message: impl Into<String>,
    request_id: &str,
) -> PingoraResult<()> {
    let body = ErrorBody {
        error: ErrorObject {
            message: message.into(),
            kind: "ferrogate_error",
            code: code.into(),
            request_id: Some(request_id.to_string()),
        },
    };
    let body = serde_json::to_vec(&body).expect("JSON serialization should not fail");
    let mut response = ResponseHeader::build(status, Some(4))?;
    response.insert_header(header::CONTENT_TYPE, "application/json")?;
    response.insert_header(header::CONTENT_LENGTH, body.len().to_string())?;
    response.insert_header(header::CONNECTION, "close")?;
    response.insert_header("x-request-id", request_id)?;
    response.insert_header("x-trace-id", request_id)?;
    response.insert_header("x-ferrogate-runtime", "pingora")?;
    session
        .write_response_header(Box::new(response), false)
        .await?;
    session
        .write_response_body(Some(Bytes::from(body)), true)
        .await
}
