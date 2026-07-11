// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Per-user MCP identity control-plane HTTP endpoints.

use http::{HeaderMap, Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};

use crate::{
    auth::authenticate,
    responses::{write_json_error, write_json_response},
};

use super::{local::admin_audit_event_draft_for_target, FerroGateway, ProxyContext};

const IDENTITY_PREFIX: &str = "/v1/mcp/identity/";

impl FerroGateway {
    pub(super) async fn handle_mcp_identity(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &HeaderMap,
        method: &Method,
        path: &str,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        if path == "/v1/mcp/identity/callback" {
            if *method != Method::GET {
                return write_json_error(
                    session,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method_not_allowed",
                    "MCP OAuth callback requires GET",
                    &ctx.request_id,
                )
                .await;
            }
            let (code, oauth_state) = match oauth_callback_params(query) {
                Some(params) => params,
                None => {
                    return write_json_error(
                        session,
                        StatusCode::BAD_REQUEST,
                        "mcp_oauth_callback_invalid",
                        "OAuth callback requires code and state",
                        &ctx.request_id,
                    )
                    .await;
                }
            };
            return match state
                .complete_mcp_oauth(&oauth_state, &code, &ctx.request_id, ctx.trace_id.clone())
                .await
            {
                Ok(status) => {
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
            };
        }

        let suffix = path.strip_prefix(IDENTITY_PREFIX).unwrap_or_default();
        let (server_name, authorize) = match suffix.strip_suffix("/authorize") {
            Some(server) => (server, true),
            None => (suffix, false),
        };
        if server_name.is_empty() || server_name.contains('/') {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "mcp_identity_not_found",
                "MCP identity endpoint was not found",
                &ctx.request_id,
            )
            .await;
        }

        let required_scope = if *method == Method::GET {
            "tools.read"
        } else {
            "tools.execute"
        };
        let auth = match authenticate(&state, headers, required_scope, &ctx.request_id) {
            Ok(auth) => auth,
            Err(error) => {
                return write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await;
            }
        };
        let target = format!("mcp:{server_name}/identity");

        if authorize && *method == Method::POST {
            return match state.start_mcp_oauth(&auth, server_name).await {
                Ok(view) => {
                    state.record_admin_audit_event(admin_audit_event_draft_for_target(
                        ctx,
                        &auth,
                        "mcp.identity.authorize",
                        target,
                        "created",
                        format!("server={server_name} decision=allow authorization flow created"),
                    ));
                    write_json_response(session, StatusCode::OK, &view, &ctx.request_id).await
                }
                Err(error) => {
                    state.record_admin_audit_event(admin_audit_event_draft_for_target(
                        ctx,
                        &auth,
                        "mcp.identity.authorize",
                        target,
                        "rejected",
                        format!("server={server_name} decision=deny code={}", error.code),
                    ));
                    write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
                        &ctx.request_id,
                    )
                    .await
                }
            };
        }
        if !authorize && *method == Method::GET {
            return match state.mcp_identity_status(&auth, server_name).await {
                Ok(view) => {
                    write_json_response(session, StatusCode::OK, &view, &ctx.request_id).await
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
            };
        }
        if !authorize && *method == Method::DELETE {
            return match state.revoke_mcp_identity(&auth, server_name).await {
                Ok(view) => {
                    state.record_admin_audit_event(admin_audit_event_draft_for_target(
                        ctx,
                        &auth,
                        "mcp.identity.revoke",
                        target,
                        "revoked",
                        format!(
                            "server={server_name} subject={} decision=allow",
                            view.subject.as_deref().unwrap_or("unknown")
                        ),
                    ));
                    write_json_response(session, StatusCode::OK, &view, &ctx.request_id).await
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
            };
        }

        write_json_error(
            session,
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "unsupported MCP identity method",
            &ctx.request_id,
        )
        .await
    }
}

fn oauth_callback_params(query: Option<&str>) -> Option<(String, String)> {
    let url = reqwest::Url::parse(&format!("http://localhost/?{}", query?)).ok()?;
    let mut code = None;
    let mut state = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "code" if code.is_none() => code = Some(value.into_owned()),
            "state" if state.is_none() => state = Some(value.into_owned()),
            _ => {}
        }
    }
    match (code, state) {
        (Some(code), Some(state)) if !code.is_empty() && !state.is_empty() => Some((code, state)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_parser_decodes_values_without_accepting_missing_fields() {
        assert_eq!(
            oauth_callback_params(Some("code=a%2Fb&state=s%2B1")),
            Some(("a/b".into(), "s+1".into()))
        );
        assert!(oauth_callback_params(Some("code=only")).is_none());
        assert!(oauth_callback_params(None).is_none());
    }
}
