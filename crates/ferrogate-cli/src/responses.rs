// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use bytes::Bytes;
use http::{header, StatusCode};
use pingora::{http::ResponseHeader, proxy::Session, ErrorType, OrErr, Result as PingoraResult};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Read};
use tokio::{sync::mpsc, task};

#[derive(Debug, Serialize)]
pub(crate) struct HealthResponse<'a> {
    pub(crate) status: &'a str,
    pub(crate) service: &'a str,
    pub(crate) version: &'a str,
    pub(crate) runtime: &'a str,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReadinessResponse<'a> {
    pub(crate) status: &'a str,
    pub(crate) service: &'a str,
    pub(crate) version: &'a str,
    pub(crate) runtime: &'a str,
    pub(crate) cluster: crate::state::ClusterStatus,
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
    pub(crate) prompt_templates: usize,
    pub(crate) upstreams: usize,
    pub(crate) enabled_upstreams: usize,
    pub(crate) routes: usize,
    pub(crate) enabled_routes: usize,
    pub(crate) extensions: usize,
    pub(crate) active_extensions: usize,
    pub(crate) tools: usize,
    pub(crate) auth_required: bool,
    pub(crate) cluster: crate::state::ClusterStatus,
    pub(crate) observability: Vec<crate::state::ObservabilityStatus>,
    pub(crate) acme: Option<AdminAcmeStatus>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub(crate) struct AdminAcmeStatus {
    pub(crate) enabled: bool,
    pub(crate) domains: Vec<String>,
    pub(crate) cert_path: String,
    pub(crate) key_path: String,
    pub(crate) certificate_expires_at_unix: Option<u64>,
    pub(crate) renewal_window_secs: u64,
    pub(crate) renewal_due: bool,
    pub(crate) last_renewal_status: &'static str,
    pub(crate) last_renewal_at_unix: Option<u64>,
    pub(crate) last_renewal_error: Option<String>,
    pub(crate) next_check_at_unix: Option<u64>,
    pub(crate) reload_required: bool,
    pub(crate) reload_mode: &'static str,
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
    pub(crate) compatibility: &'static str,
    pub(crate) base_url: String,
    pub(crate) has_api_key: bool,
    pub(crate) enabled: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminProviderModelCatalog {
    pub(crate) provider: String,
    pub(crate) kind: String,
    pub(crate) base_url: String,
    pub(crate) enabled: bool,
    pub(crate) status: String,
    pub(crate) models: Vec<AdminProviderModelCandidate>,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminProviderModelCandidate {
    pub(crate) id: String,
    pub(crate) owned_by: Option<String>,
    pub(crate) created: Option<u64>,
    pub(crate) context_window: Option<u64>,
    pub(crate) capabilities: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminGatewayConfigProfile {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) revision: u32,
    pub(crate) enabled: bool,
    pub(crate) api_key_ids: Vec<String>,
    pub(crate) cache_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdminGatewayConfigMutation {
    pub(crate) id: Option<String>,
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) revision: Option<u32>,
    #[serde(default)]
    pub(crate) enabled: Option<bool>,
    #[serde(default)]
    pub(crate) api_key_ids: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) cache_enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminGatewayConfigMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) gateway_config: AdminGatewayConfigProfile,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminPromptTemplate {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) status: crate::config::PromptTemplateStatus,
    pub(crate) target: crate::config::PromptTemplateTarget,
    pub(crate) model: String,
    pub(crate) variables: Vec<crate::config::PromptTemplateVariable>,
    pub(crate) active_revision: Option<u32>,
    pub(crate) versions: Vec<crate::config::PromptTemplateVersion>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdminPromptTemplateMutation {
    pub(crate) id: Option<String>,
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) status: Option<crate::config::PromptTemplateStatus>,
    #[serde(default)]
    pub(crate) target: Option<crate::config::PromptTemplateTarget>,
    #[serde(default)]
    pub(crate) model: Option<String>,
    #[serde(default)]
    pub(crate) variables: Option<Vec<crate::config::PromptTemplateVariable>>,
    #[serde(default)]
    pub(crate) version: Option<crate::config::PromptTemplateVersion>,
    #[serde(default)]
    pub(crate) versions: Option<Vec<crate::config::PromptTemplateVersion>>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminPromptTemplateMutationResponse {
    pub(crate) object: &'static str,
    pub(crate) prompt_template: AdminPromptTemplate,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PromptTemplateRenderRequest {
    #[serde(default)]
    pub(crate) variables: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub(crate) revision: Option<u32>,
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
    pub(crate) cache_enabled: Option<bool>,
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
    #[serde(default)]
    pub(crate) cache_enabled: Option<bool>,
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

#[derive(Debug, Deserialize)]
pub(crate) struct AdminDrainRequest {
    pub(crate) drain: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminDrainResponse {
    pub(crate) object: &'static str,
    pub(crate) draining: bool,
    pub(crate) accepting_new_requests: bool,
    pub(crate) drain_reason: &'static str,
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

pub(crate) async fn write_empty_response(
    session: &mut Session,
    status: StatusCode,
    request_id: &str,
) -> PingoraResult<()> {
    let mut response = ResponseHeader::build(status, Some(4))?;
    response.insert_header(header::CONTENT_LENGTH, "0")?;
    response.insert_header("x-request-id", request_id)?;
    response.insert_header("x-trace-id", request_id)?;
    response.insert_header("x-ferrogate-runtime", "pingora")?;
    session
        .write_response_header(Box::new(response), false)
        .await?;
    session.write_response_body(None, true).await
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

pub(crate) async fn write_streaming_response<R: Read + Send + 'static>(
    session: &mut Session,
    status: StatusCode,
    content_type: &str,
    initial_body: Vec<u8>,
    reader: R,
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

    let (sender, mut receiver) = mpsc::channel::<std::io::Result<Bytes>>(8);
    let read_task = task::spawn_blocking(move || {
        read_streaming_body_chunks(reader, sender);
    });

    while let Some(chunk) = receiver.recv().await {
        let chunk = chunk.or_err(ErrorType::ReadError, "reading provider streaming response")?;
        session.write_response_body(Some(chunk), false).await?;
    }

    read_task
        .await
        .or_err(ErrorType::ReadError, "joining provider streaming reader")?;
    session.write_response_body(None, true).await
}

pub(crate) async fn write_streaming_bytes_response(
    session: &mut Session,
    status: StatusCode,
    content_type: &str,
    body: Vec<u8>,
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
    if !body.is_empty() {
        session
            .write_response_body(Some(Bytes::from(body)), false)
            .await?;
    }
    session.write_response_body(None, true).await
}

fn read_streaming_body_chunks<R: Read>(
    mut reader: R,
    sender: mpsc::Sender<std::io::Result<Bytes>>,
) {
    let mut buffer = [0_u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return,
            Ok(read) => {
                if sender
                    .blocking_send(Ok(Bytes::copy_from_slice(&buffer[..read])))
                    .is_err()
                {
                    return;
                }
            }
            Err(error) => {
                let _ = sender.blocking_send(Err(error));
                return;
            }
        }
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
