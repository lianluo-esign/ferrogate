use http::{HeaderMap, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use serde::Deserialize;

use ferrogate_providers::{
    ChatCompletionPlan, OpenAiCompatibleAdapter, ProviderAdapter, ProviderConfig,
};

use crate::{
    auth::authenticate,
    responses::{write_json_error, write_raw_response},
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

        let adapter = OpenAiCompatibleAdapter;
        let prepared = match adapter.prepare_chat_completions(
            ProviderConfig {
                name: provider.name.clone(),
                kind: provider.kind.clone(),
                base_url: provider.base_url.clone(),
                api_key: provider.api_key_value(),
            },
            ChatCompletionPlan {
                logical_model: request.model.clone(),
                provider_model: model.provider_model.clone(),
                stream: request.stream,
                body: body_json,
            },
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
