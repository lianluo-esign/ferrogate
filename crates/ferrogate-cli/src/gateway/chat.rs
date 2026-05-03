use http::{HeaderMap, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use serde::Deserialize;
use tracing::info;

use crate::{
    auth::authenticate,
    responses::{write_json_error, write_json_response, write_raw_response},
};

use super::{
    body::read_request_body, dispatch::dispatch_provider_request, FerroGateway, ProxyContext,
};

#[derive(Debug, Deserialize)]
struct ChatCompletionRequest {
    model: String,
    #[serde(default)]
    stream: bool,
}

impl FerroGateway {
    pub(super) async fn handle_chat_completions(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: HeaderMap,
    ) -> PingoraResult<()> {
        let auth = match authenticate(&self.state, &headers, "chat.completions", &ctx.request_id) {
            Ok(auth) => auth,
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            }
        };

        let body = read_request_body(session, 1024 * 1024).await?;
        let body_json: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => {
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_json",
                    format!("invalid JSON body: {error}"),
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            }
        };
        let request: ChatCompletionRequest = match serde_json::from_value(body_json.clone()) {
            Ok(request) => request,
            Err(error) => {
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    format!("invalid chat completion request: {error}"),
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            }
        };

        if !auth.can_use_model(&request.model) {
            write_json_error(
                session,
                StatusCode::FORBIDDEN,
                "model_not_allowed",
                format!("API key is not allowed to use model {}", request.model),
                &ctx.request_id,
            )
            .await?;
            return Ok(());
        }

        let Some(model) = self.state.models.get(&request.model) else {
            write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "model_not_found",
                format!("unknown model {}", request.model),
                &ctx.request_id,
            )
            .await?;
            return Ok(());
        };

        let Some(provider) = self.state.providers.get(&model.provider) else {
            write_json_error(
                session,
                StatusCode::BAD_GATEWAY,
                "provider_not_found",
                format!("provider {} not found", model.provider),
                &ctx.request_id,
            )
            .await?;
            return Ok(());
        };

        let prepared = match self.state.prepare_chat_completions(
            provider,
            model,
            request.model.clone(),
            request.stream,
            body_json,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                write_json_error(
                    session,
                    StatusCode::BAD_GATEWAY,
                    "provider_adapter_error",
                    format!("provider adapter failed: {error:?}"),
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            }
        };

        match dispatch_provider_request(&prepared) {
            Ok(response) => {
                if response.status.is_client_error() || response.status.is_server_error() {
                    let normalized = match self.state.normalize_provider_error(
                        &provider.kind,
                        response.status.as_u16(),
                        &response.content_type,
                        &response.body,
                        &ctx.request_id,
                    ) {
                        Ok(normalized) => normalized,
                        Err(error) => {
                            write_json_error(
                                session,
                                StatusCode::BAD_GATEWAY,
                                "provider_adapter_error",
                                format!("provider adapter failed: {error:?}"),
                                &ctx.request_id,
                            )
                            .await?;
                            return Ok(());
                        }
                    };
                    return write_json_response(
                        session,
                        response.status,
                        &normalized.body,
                        &ctx.request_id,
                    )
                    .await;
                }

                if let Ok(Some(usage)) = self
                    .state
                    .extract_provider_usage(&provider.kind, &response.body)
                {
                    info!(
                        request_id = %ctx.request_id,
                        logical_model = %request.model,
                        provider = %provider.name,
                        provider_model = %model.provider_model,
                        prompt_tokens = ?usage.prompt_tokens,
                        completion_tokens = ?usage.completion_tokens,
                        total_tokens = ?usage.total_tokens,
                        "provider usage extracted"
                    );
                }

                write_raw_response(
                    session,
                    response.status,
                    &response.content_type,
                    response.body.into(),
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                write_json_error(
                    session,
                    StatusCode::BAD_GATEWAY,
                    "provider_dispatch_error",
                    format!("provider dispatch failed: {error}"),
                    &ctx.request_id,
                )
                .await
            }
        }
    }
}
