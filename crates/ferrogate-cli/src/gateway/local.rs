use http::StatusCode;
use pingora::{proxy::Session, Result as PingoraResult};

use crate::{
    auth::authenticate,
    config::config_snapshot_id,
    responses::{
        write_json_error, write_json_response, AdminStatus, HealthResponse, OpenAiModel,
        OpenAiModelList,
    },
};

use super::{FerroGateway, ProxyContext};

impl FerroGateway {
    pub(super) async fn handle_healthz(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
    ) -> PingoraResult<()> {
        let body = HealthResponse {
            status: "ok",
            service: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
            runtime: "pingora",
        };
        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
    }

    pub(super) async fn handle_models(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        match authenticate(&self.state, headers, "models.read", &ctx.request_id) {
            Ok(_) => {
                let data = self
                    .state
                    .config
                    .models
                    .iter()
                    .filter(|model| model.enabled)
                    .map(|model| OpenAiModel {
                        id: model.name.clone(),
                        object: "model",
                        created: 0,
                        owned_by: model.provider.clone(),
                    })
                    .collect();
                write_json_response(
                    session,
                    StatusCode::OK,
                    &OpenAiModelList {
                        object: "list",
                        data,
                    },
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_status(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        match authenticate(&self.state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let status = AdminStatus {
                    service: env!("CARGO_PKG_NAME"),
                    version: env!("CARGO_PKG_VERSION"),
                    runtime: "pingora",
                    snapshot: config_snapshot_id(&self.state.config),
                    providers: self.state.config.providers.len(),
                    enabled_providers: self
                        .state
                        .config
                        .providers
                        .iter()
                        .filter(|p| p.enabled)
                        .count(),
                    models: self.state.config.models.len(),
                    enabled_models: self
                        .state
                        .config
                        .models
                        .iter()
                        .filter(|m| m.enabled)
                        .count(),
                    api_keys: self.state.config.api_keys.len(),
                    upstreams: self.state.config.upstreams.len(),
                    enabled_upstreams: self
                        .state
                        .config
                        .upstreams
                        .iter()
                        .filter(|u| u.enabled)
                        .count(),
                    routes: self.state.config.routes.len(),
                    enabled_routes: self
                        .state
                        .config
                        .routes
                        .iter()
                        .filter(|r| r.enabled)
                        .count(),
                    auth_required: self.state.auth_required(),
                };
                write_json_response(session, StatusCode::OK, &status, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }
}
