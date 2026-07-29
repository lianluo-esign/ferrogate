// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Immutable Guardrail policy revision administration, activation, rollback, and dry-run.

use http::{Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use ferrogate_guardrails::{
    DetectorDefinition, DetectorStage, PolicyAction, PolicyRevision, PolicyRevisionView,
    PolicySelectionContext,
};

use super::body::read_request_body;
use super::local::admin_audit_event_draft_for_target;
use super::{FerroGateway, ProxyContext};
use crate::auth::{AuthContext, AuthError, CallerScope};
use crate::{
    auth::authenticate,
    responses::{write_json_error, write_json_error_and_close, write_json_response, AdminList},
    state::AppState,
};

#[derive(Debug, Clone, Copy)]
enum GuardrailPermission {
    Read,
    CreateRevision,
    Activate,
    Rollback,
    Archive,
    DryRun,
}

impl GuardrailPermission {
    fn key(self) -> &'static str {
        match self {
            Self::Read => "guardrails.policy.read",
            Self::CreateRevision => "guardrails.policy.create_revision",
            Self::Activate => "guardrails.policy.activate",
            Self::Rollback => "guardrails.policy.rollback",
            Self::Archive => "guardrails.policy.archive",
            Self::DryRun => "guardrails.policy.dry_run",
        }
    }

    fn admin_scope(self) -> &'static str {
        match self {
            Self::Read | Self::DryRun => "admin.read",
            Self::CreateRevision | Self::Activate | Self::Rollback | Self::Archive => "admin.write",
        }
    }
}

#[derive(Debug, Serialize)]
struct GuardrailPolicyRevisionResponse {
    object: &'static str,
    policy: PolicyRevisionView,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevisionSelection {
    revision: u32,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackSelection {
    #[serde(default)]
    revision: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuardrailDryRunRequest {
    #[serde(default)]
    revision: Option<u32>,
    stage: DetectorStage,
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default)]
    project_id: Option<String>,
    #[serde(default)]
    workspace_id: Option<String>,
    #[serde(default)]
    api_key_id: Option<String>,
    #[serde(default)]
    service_account_id: Option<String>,
    #[serde(default)]
    gateway_config_id: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    text: String,
}

#[derive(Debug, Serialize)]
struct GuardrailDryRunResponse {
    object: &'static str,
    policy_revision: String,
    selected: bool,
    result: &'static str,
    checks: Vec<GuardrailDryRunCheck>,
    on_pass: Vec<PolicyAction>,
    on_fail: Vec<PolicyAction>,
    on_error: Vec<PolicyAction>,
    provider_dispatched: bool,
    external_action_dispatched: bool,
}

#[derive(Debug, Serialize)]
struct GuardrailDryRunCheck {
    id: String,
    detector: &'static str,
    result: &'static str,
}

impl FerroGateway {
    pub(super) async fn handle_guardrail_policies(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
    ) -> PingoraResult<()> {
        if path == "/admin/v1/guardrail-policies" {
            return match *method {
                Method::GET => {
                    let Some(auth) = require_guardrail_auth(
                        session,
                        ctx,
                        headers,
                        &self.state.current(),
                        GuardrailPermission::Read,
                    )
                    .await?
                    else {
                        return Ok(());
                    };
                    self.list_guardrail_revisions(session, ctx, &auth, None)
                        .await
                }
                Method::POST => {
                    self.create_guardrail_revision(session, ctx, headers, None)
                        .await
                }
                _ => {
                    write_json_error(
                        session,
                        StatusCode::METHOD_NOT_ALLOWED,
                        "method_not_allowed",
                        "guardrail policy collection supports GET and POST",
                        &ctx.request_id,
                    )
                    .await
                }
            };
        }

        let Some(rest) = path.strip_prefix("/admin/v1/guardrail-policies/") else {
            return guardrail_not_found(session, ctx).await;
        };
        let parts = rest.split('/').collect::<Vec<_>>();
        let policy_id = parts.first().copied().filter(|part| !part.is_empty());
        let Some(policy_id) = policy_id else {
            return guardrail_not_found(session, ctx).await;
        };
        match (parts.as_slice(), method) {
            ([_], &Method::GET) | ([_, "revisions"], &Method::GET) => {
                let Some(auth) = require_guardrail_auth(
                    session,
                    ctx,
                    headers,
                    &self.state.current(),
                    GuardrailPermission::Read,
                )
                .await?
                else {
                    return Ok(());
                };
                self.list_guardrail_revisions(session, ctx, &auth, Some(policy_id))
                    .await
            }
            ([_, "revisions"], &Method::POST) => {
                self.create_guardrail_revision(session, ctx, headers, Some(policy_id))
                    .await
            }
            ([_, "revisions", revision], &Method::GET) => {
                let Some(auth) = require_guardrail_auth(
                    session,
                    ctx,
                    headers,
                    &self.state.current(),
                    GuardrailPermission::Read,
                )
                .await?
                else {
                    return Ok(());
                };
                let Some(revision) = parse_revision(revision) else {
                    return invalid_revision(session, ctx).await;
                };
                self.get_guardrail_revision(session, ctx, &auth, policy_id, revision)
                    .await
            }
            ([_, "revisions", revision], &Method::DELETE) => {
                let Some(revision) = parse_revision(revision) else {
                    return invalid_revision(session, ctx).await;
                };
                self.archive_guardrail_revision(session, ctx, headers, policy_id, revision)
                    .await
            }
            ([_, "activate"], &Method::POST) => {
                self.activate_guardrail_revision(session, ctx, headers, policy_id, false)
                    .await
            }
            ([_, "rollback"], &Method::POST) => {
                self.activate_guardrail_revision(session, ctx, headers, policy_id, true)
                    .await
            }
            ([_, "dry-run"], &Method::POST) => {
                self.dry_run_guardrail_revision(session, ctx, headers, policy_id)
                    .await
            }
            _ => guardrail_not_found(session, ctx).await,
        }
    }

    async fn list_guardrail_revisions(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        auth: &AuthContext,
        policy_id: Option<&str>,
    ) -> PingoraResult<()> {
        match self
            .state
            .current()
            .guardrail_policy_revision_views(policy_id)
        {
            Ok(views) => {
                let views = filter_guardrail_views(auth, views);
                if policy_id.is_some() && views.is_empty() {
                    return write_json_error(
                        session,
                        StatusCode::NOT_FOUND,
                        "guardrail_policy_not_found",
                        format!(
                            "guardrail policy {} was not found",
                            policy_id.unwrap_or_default()
                        ),
                        &ctx.request_id,
                    )
                    .await;
                }
                write_json_response(
                    session,
                    StatusCode::OK,
                    &AdminList::new(views),
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => write_guardrail_error(session, ctx, error).await,
        }
    }

    async fn get_guardrail_revision(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        auth: &AuthContext,
        policy_id: &str,
        revision: u32,
    ) -> PingoraResult<()> {
        match self
            .state
            .current()
            .guardrail_policy_revision_view(policy_id, revision)
        {
            Ok(Some(policy)) if guardrail_view_is_visible(auth, &policy) => {
                let response = GuardrailPolicyRevisionResponse {
                    object: "guardrail_policy_revision",
                    policy,
                };
                write_json_response(session, StatusCode::OK, &response, &ctx.request_id).await
            }
            Ok(None) | Ok(Some(_)) => {
                write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "guardrail_policy_revision_not_found",
                    format!("guardrail policy revision {policy_id}@{revision} was not found"),
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => write_guardrail_error(session, ctx, error).await,
        }
    }

    async fn create_guardrail_revision(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        path_policy_id: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let Some(auth) = require_guardrail_auth(
            session,
            ctx,
            headers,
            &state,
            GuardrailPermission::CreateRevision,
        )
        .await?
        else {
            return Ok(());
        };
        let Some(mut revision) = read_guardrail_body::<PolicyRevision>(
            session,
            state.limits().guardrail_policy_body_max_bytes(),
            ctx,
        )
        .await?
        else {
            return Ok(());
        };
        if let Some(path_policy_id) = path_policy_id {
            if !revision.policy_id.is_empty() && revision.policy_id != path_policy_id {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "guardrail_policy_id_mismatch",
                    "body policy_id must match the path",
                    &ctx.request_id,
                )
                .await;
            }
            revision.policy_id = path_policy_id.to_string();
        }
        if revision.policy_id.trim().is_empty() {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_guardrail_policy",
                "policy_id is required",
                &ctx.request_id,
            )
            .await;
        }
        if let Err(error) = authorize_guardrail_scope(&auth, &revision) {
            return write_auth_error(session, ctx, error).await;
        }
        if let Err(error) = authorize_guardrail_secret_refs(&auth, &revision) {
            return write_auth_error(session, ctx, error).await;
        }
        // #515: "not the platform operator", asked of the classification rather
        // than of a missing field -- an unclassified credential must run this
        // clobber check, not skip it.
        if !auth.is_platform_operator() {
            match state.guardrail_policy_revision_views(Some(&revision.policy_id)) {
                Ok(existing)
                    if existing
                        .iter()
                        .any(|view| !guardrail_view_is_visible(&auth, view)) =>
                {
                    return write_auth_error(session, ctx, guardrail_scope_denied()).await;
                }
                Ok(_) => {}
                Err(error) => return write_guardrail_error(session, ctx, error).await,
            }
        }
        revision.revision = match state.next_guardrail_policy_revision(&revision.policy_id) {
            Ok(revision) => revision,
            Err(error) => return write_guardrail_error(session, ctx, error).await,
        };
        revision.created_at_unix = now_unix_seconds();
        revision.created_by = auth
            .api_key_id
            .clone()
            .unwrap_or_else(|| "platform_operator".to_string());
        match self
            .state
            .create_guardrail_policy_revision(revision.clone())
        {
            Ok(view) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "guardrail.policy_revision_create",
                    revision.immutable_id(),
                    "committed",
                    "immutable guardrail policy revision created",
                ));
                let response = GuardrailPolicyRevisionResponse {
                    object: "guardrail_policy_revision",
                    policy: view,
                };
                write_json_response(session, StatusCode::CREATED, &response, &ctx.request_id).await
            }
            Err(error) => write_guardrail_error(session, ctx, error).await,
        }
    }

    async fn activate_guardrail_revision(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        policy_id: &str,
        rollback: bool,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let permission = if rollback {
            GuardrailPermission::Rollback
        } else {
            GuardrailPermission::Activate
        };
        let Some(auth) = require_guardrail_auth(session, ctx, headers, &state, permission).await?
        else {
            return Ok(());
        };
        let revision = if rollback {
            let Some(selection) = read_guardrail_body::<RollbackSelection>(
                session,
                state.limits().guardrail_policy_body_max_bytes(),
                ctx,
            )
            .await?
            else {
                return Ok(());
            };
            match selection.revision {
                Some(revision) => revision,
                None => match state.guardrail_policy_binding(policy_id) {
                    Ok(Some(binding)) => binding
                        .archived_revisions
                        .into_iter()
                        .max()
                        .unwrap_or_default(),
                    Ok(None) => 0,
                    Err(error) => return write_guardrail_error(session, ctx, error).await,
                },
            }
        } else {
            let Some(selection) = read_guardrail_body::<RevisionSelection>(
                session,
                state.limits().guardrail_policy_body_max_bytes(),
                ctx,
            )
            .await?
            else {
                return Ok(());
            };
            selection.revision
        };
        if revision == 0 {
            return invalid_revision(session, ctx).await;
        }
        match state.guardrail_policy_revision_view(policy_id, revision) {
            Ok(Some(view)) if guardrail_view_is_visible(&auth, &view) => {
                // Defense in depth: a tenant-scoped caller must not activate a
                // revision that dereferences a host secret, even one authored by
                // an operator -- activation re-resolves every secret_ref against
                // the host env/Vault.
                if let Err(error) = authorize_guardrail_secret_refs(&auth, &view.revision) {
                    return write_auth_error(session, ctx, error).await;
                }
            }
            Ok(_) => {
                return write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "guardrail_policy_revision_not_found",
                    format!("guardrail policy revision {policy_id}@{revision} was not found"),
                    &ctx.request_id,
                )
                .await;
            }
            Err(error) => return write_guardrail_error(session, ctx, error).await,
        }
        let actor = auth.api_key_id.as_deref().unwrap_or("platform_operator");
        match self.state.activate_guardrail_policy_revision_with_evidence(
            policy_id,
            revision,
            actor,
            now_unix_seconds(),
            rollback,
        ) {
            Ok(activation) => {
                let action = if rollback {
                    "guardrail.policy_rollback"
                } else {
                    "guardrail.policy_activate"
                };
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    action,
                    format!("{policy_id}@{revision}"),
                    "committed",
                    "guardrail policy binding committed and runtime reloaded",
                ));
                write_json_response(
                    session,
                    StatusCode::OK,
                    &serde_json::json!({
                        "object": "guardrail_policy_binding",
                        "policy_id": policy_id,
                        "active_revision": revision,
                        "previous_active_revision": activation.previous_active_revision,
                        "rollback": rollback,
                        "reload": activation.reload,
                    }),
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                record_guardrail_policy_cas_conflict(
                    &state,
                    ctx,
                    &auth,
                    if rollback {
                        "guardrail.policy_rollback"
                    } else {
                        "guardrail.policy_activate"
                    },
                    policy_id,
                    revision,
                    &error,
                );
                write_guardrail_error(session, ctx, error).await
            }
        }
    }

    async fn archive_guardrail_revision(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        policy_id: &str,
        revision: u32,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let Some(auth) =
            require_guardrail_auth(session, ctx, headers, &state, GuardrailPermission::Archive)
                .await?
        else {
            return Ok(());
        };
        match state.guardrail_policy_revision_view(policy_id, revision) {
            Ok(Some(view)) if guardrail_view_is_visible(&auth, &view) => {}
            Ok(_) => {
                return write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "guardrail_policy_revision_not_found",
                    format!("guardrail policy revision {policy_id}@{revision} was not found"),
                    &ctx.request_id,
                )
                .await;
            }
            Err(error) => return write_guardrail_error(session, ctx, error).await,
        }
        let actor = auth.api_key_id.as_deref().unwrap_or("platform_operator");
        match self.state.archive_guardrail_policy_revision(
            policy_id,
            revision,
            actor,
            now_unix_seconds(),
        ) {
            Ok(reload) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "guardrail.policy_archive",
                    format!("{policy_id}@{revision}"),
                    "committed",
                    "guardrail policy revision archived and runtime reloaded",
                ));
                write_json_response(
                    session,
                    StatusCode::OK,
                    &serde_json::json!({
                        "object": "guardrail_policy_revision",
                        "policy_id": policy_id,
                        "revision": revision,
                        "status": "archived",
                        "reload": reload,
                    }),
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                record_guardrail_policy_cas_conflict(
                    &state,
                    ctx,
                    &auth,
                    "guardrail.policy_archive",
                    policy_id,
                    revision,
                    &error,
                );
                write_guardrail_error(session, ctx, error).await
            }
        }
    }

    async fn dry_run_guardrail_revision(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        policy_id: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let Some(auth) =
            require_guardrail_auth(session, ctx, headers, &state, GuardrailPermission::DryRun)
                .await?
        else {
            return Ok(());
        };
        let Some(request) = read_guardrail_body::<GuardrailDryRunRequest>(
            session,
            state.limits().guardrail_policy_body_max_bytes(),
            ctx,
        )
        .await?
        else {
            return Ok(());
        };
        let revision = match request.revision {
            Some(revision) => revision,
            None => match state.guardrail_policy_binding(policy_id) {
                Ok(Some(binding)) => binding.active_revision.unwrap_or_default(),
                Ok(None) => state
                    .guardrail_policy_revision_views(Some(policy_id))
                    .ok()
                    .and_then(|views| {
                        views
                            .into_iter()
                            .find(|view| view.revision.created_by == "static_config")
                            .map(|view| view.revision.revision)
                    })
                    .unwrap_or_default(),
                Err(error) => return write_guardrail_error(session, ctx, error).await,
            },
        };
        let view = match state.guardrail_policy_revision_view(policy_id, revision) {
            Ok(Some(view)) if guardrail_view_is_visible(&auth, &view) => view,
            Ok(None) | Ok(Some(_)) => {
                return write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "guardrail_policy_revision_not_found",
                    format!("guardrail policy revision {policy_id}@{revision} was not found"),
                    &ctx.request_id,
                )
                .await;
            }
            Err(error) => return write_guardrail_error(session, ctx, error).await,
        };
        // #515: only a DECLARED platform operator may let the request body pick
        // the tenant the policy is evaluated against. Read off
        // `organization_id` this was "whoever omitted the field", so an
        // unclassified credential could name any tenant it liked in the body
        // and have that become the selection context.
        let caller_scope = auth.caller_scope();
        if let CallerScope::Tenant(tenant_id) = caller_scope {
            if request
                .organization_id
                .as_deref()
                .is_some_and(|requested| requested != tenant_id)
            {
                return write_auth_error(session, ctx, guardrail_scope_denied()).await;
            }
        }
        let selection = PolicySelectionContext {
            organization_id: match caller_scope {
                CallerScope::PlatformOperator => request.organization_id.as_deref(),
                CallerScope::Tenant(tenant_id) => Some(tenant_id),
            },
            project_id: request.project_id.as_deref(),
            workspace_id: request.workspace_id.as_deref(),
            api_key_id: request.api_key_id.as_deref(),
            service_account_id: request.service_account_id.as_deref(),
            gateway_config_id: request.gateway_config_id.as_deref(),
            model: request.model.as_deref(),
            provider: request.provider.as_deref(),
            managed_action: None,
        };
        let selected = view.revision.scope.matches(selection);
        let checks = if selected {
            view.revision
                .checks
                .iter()
                .filter(|check| check.stage == request.stage)
                .map(|check| dry_run_check(check, &request.text))
                .collect()
        } else {
            Vec::new()
        };
        let response = GuardrailDryRunResponse {
            object: "guardrail_policy_dry_run",
            policy_revision: view.revision.immutable_id(),
            selected,
            result: "planned",
            checks,
            on_pass: view.revision.on_pass.clone(),
            on_fail: view.revision.on_fail.clone(),
            on_error: view.revision.on_error.clone(),
            provider_dispatched: false,
            external_action_dispatched: false,
        };
        state.record_admin_audit_event(admin_audit_event_draft_for_target(
            ctx,
            &auth,
            "guardrail.policy_dry_run",
            response.policy_revision.clone(),
            "planned",
            "guardrail dry-run completed without provider or external detector dispatch",
        ));
        write_json_response(session, StatusCode::OK, &response, &ctx.request_id).await
    }
}

fn dry_run_check(check: &ferrogate_guardrails::CheckBinding, text: &str) -> GuardrailDryRunCheck {
    if !check.enabled {
        return GuardrailDryRunCheck {
            id: check.id.clone(),
            detector: detector_kind(&check.detector),
            result: "disabled",
        };
    }
    let result = match &check.detector {
        DetectorDefinition::CustomHttp { .. }
        | DetectorDefinition::Presidio { .. }
        | DetectorDefinition::LlmGuardPromptInjection { .. }
        | DetectorDefinition::WorkersAiLlamaGuard { .. } => "not_executed",
        DetectorDefinition::Local {
            keywords,
            regex,
            max_input_bytes,
            json,
            request,
            secret_patterns,
            ..
        } => {
            if json.is_some() || request.is_some() || !secret_patterns.is_empty() {
                return GuardrailDryRunCheck {
                    id: check.id.clone(),
                    detector: detector_kind(&check.detector),
                    result: "not_executed",
                };
            }
            let matched = max_input_bytes.is_some_and(|maximum| text.len() > maximum)
                || keywords.iter().any(|keyword| text.contains(keyword))
                || regex.iter().any(|pattern| {
                    regex::Regex::new(pattern).is_ok_and(|compiled| compiled.is_match(text))
                });
            if matched {
                "fail"
            } else {
                "pass"
            }
        }
    };
    GuardrailDryRunCheck {
        id: check.id.clone(),
        detector: detector_kind(&check.detector),
        result,
    }
}

fn detector_kind(detector: &DetectorDefinition) -> &'static str {
    match detector {
        DetectorDefinition::Local { .. } => "local",
        DetectorDefinition::CustomHttp { .. } => "custom_http",
        DetectorDefinition::Presidio { .. } => "presidio",
        DetectorDefinition::LlmGuardPromptInjection { .. } => "llm_guard_prompt_injection",
        DetectorDefinition::WorkersAiLlamaGuard { .. } => "workers_ai_llama_guard",
    }
}

fn filter_guardrail_views(
    auth: &AuthContext,
    views: Vec<PolicyRevisionView>,
) -> Vec<PolicyRevisionView> {
    views
        .into_iter()
        .filter(|view| guardrail_view_is_visible(auth, view))
        .collect()
}

fn guardrail_view_is_visible(auth: &AuthContext, view: &PolicyRevisionView) -> bool {
    authorize_guardrail_scope(auth, &view.revision).is_ok()
}

/// The tenant-isolation chokepoint behind every guardrail read and write: a
/// tenant-scoped caller may only see/author revisions explicitly scoped to its
/// own tenant.
///
/// #515: the "who is unrestricted here" question is [`CallerScope`], not a
/// missing `organization_id`. A credential that declared no identity at all
/// lands in the `Tenant` arm with the unscoped tenant id, which no revision
/// scope can equal, so it sees and writes nothing -- instead of taking the
/// early `Ok(())` that means "platform operator, unrestricted".
fn authorize_guardrail_scope(
    auth: &AuthContext,
    revision: &PolicyRevision,
) -> Result<(), AuthError> {
    let CallerScope::Tenant(tenant_id) = auth.caller_scope() else {
        return Ok(());
    };
    let organization_scopes = revision
        .scope
        .tenant_ids
        .iter()
        .chain(revision.scope.organization_ids.iter())
        .collect::<Vec<_>>();
    if organization_scopes.is_empty()
        || organization_scopes
            .iter()
            .any(|organization_id| organization_id.as_str() != tenant_id)
    {
        return Err(guardrail_scope_denied());
    }
    Ok(())
}

fn guardrail_scope_denied() -> AuthError {
    AuthError {
        status: StatusCode::FORBIDDEN,
        code: "guardrail_policy_scope_denied",
        message: "the Guardrail policy must be explicitly scoped to the caller's tenant".into(),
    }
}

/// True when a detector dereferences a host secret. `CustomHttp.secret_ref` and
/// `Local.fingerprint_secret_ref` are resolved against the GATEWAY's env/Vault
/// (`SecretResolverRegistry::from_env`) during create/activate/reload.
fn detector_references_host_secret(detector: &DetectorDefinition) -> bool {
    matches!(
        detector,
        DetectorDefinition::CustomHttp {
            secret_ref: Some(_),
            ..
        } | DetectorDefinition::Local {
            fingerprint_secret_ref: Some(_),
            ..
        }
        // The native/remote adapters ALWAYS dereference a host secret: their
        // fingerprint_secret_ref is mandatory (and secret_ref is optional on
        // top), so tenant-scoped authors can never register them.
        | DetectorDefinition::Presidio { .. }
        | DetectorDefinition::LlmGuardPromptInjection { .. }
        | DetectorDefinition::WorkersAiLlamaGuard { .. }
    )
}

/// A tenant-scoped (org-scoped) guardrail author must not reference a host
/// secret from any detector. Because those refs resolve against the gateway's
/// own env/Vault -- not a tenant-scoped store -- a tenant could otherwise
/// dereference the host `VAULT_TOKEN`, a sibling tenant's provider key, or the
/// admin JWT secret, and a `CustomHttp` detector would ship the resolved value
/// as a `Bearer` token to a caller-controlled endpoint (arbitrary host/cross-
/// tenant secret exfiltration). Only platform operators may author detectors
/// that carry a secret reference.
///
/// #515: "platform operator" here is [`CallerScope::PlatformOperator`], i.e. a
/// DECLARED `platform_operator`. It used to be `organization_id.is_none()`,
/// which meant an unclassified credential -- one that never named a tenant and
/// never claimed root -- was handed the host-secret exemption by default. That
/// is the wrong direction for a check whose failure mode is exfiltrating the
/// gateway's own `VAULT_TOKEN`.
fn authorize_guardrail_secret_refs(
    auth: &AuthContext,
    revision: &PolicyRevision,
) -> Result<(), AuthError> {
    if auth.is_platform_operator() {
        return Ok(());
    }
    let references_host_secret = revision.checks.iter().any(|check| {
        detector_references_host_secret(&check.detector)
            || check
                .fallback_detector
                .as_ref()
                .is_some_and(detector_references_host_secret)
    });
    if references_host_secret {
        return Err(AuthError {
            status: StatusCode::FORBIDDEN,
            code: "guardrail_secret_ref_forbidden",
            message: "tenant-scoped guardrail authors may not reference a host secret \
                      (secret_ref / fingerprint_secret_ref); this is restricted to \
                      platform-operator keys"
                .into(),
        });
    }
    Ok(())
}

async fn write_auth_error(
    session: &mut Session,
    ctx: &ProxyContext,
    error: AuthError,
) -> PingoraResult<()> {
    write_json_error(
        session,
        error.status,
        error.code,
        error.message,
        &ctx.request_id,
    )
    .await
}

async fn require_guardrail_auth(
    session: &mut Session,
    ctx: &ProxyContext,
    headers: &http::HeaderMap,
    state: &AppState,
    permission: GuardrailPermission,
) -> PingoraResult<Option<AuthContext>> {
    let auth = match authenticate(state, headers, permission.admin_scope(), &ctx.request_id).await {
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
            return Ok(None);
        }
    };
    // #515: a tenant-scoped caller must clear its tenant's RBAC grant; only a
    // declared platform operator skips it. An unclassified credential is a
    // `Tenant` here, so it is checked (and denied) rather than waved through.
    if let CallerScope::Tenant(tenant_id) = auth.caller_scope() {
        match state
            .tenant_has_permission_result(tenant_id, permission.key())
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                write_json_error(
                    session,
                    StatusCode::FORBIDDEN,
                    "guardrail_rbac_denied",
                    format!(
                        "tenant roles do not grant required action {}",
                        permission.key()
                    ),
                    &ctx.request_id,
                )
                .await?;
                return Ok(None);
            }
            Err(error) => {
                write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "guardrail_rbac_unavailable",
                    format!("failed to resolve Guardrail role permissions: {error}"),
                    &ctx.request_id,
                )
                .await?;
                return Ok(None);
            }
        }
    }
    Ok(Some(auth))
}

async fn read_guardrail_body<T: serde::de::DeserializeOwned>(
    session: &mut Session,
    max_bytes: usize,
    ctx: &ProxyContext,
) -> PingoraResult<Option<T>> {
    let body = match read_request_body(session, max_bytes).await? {
        Ok(body) => body,
        Err(limit) => {
            write_json_error_and_close(
                session,
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                format!(
                    "request body exceeds maximum size of {} bytes",
                    limit.max_bytes
                ),
                &ctx.request_id,
            )
            .await?;
            return Ok(None);
        }
    };
    match serde_json::from_slice(&body) {
        Ok(payload) => Ok(Some(payload)),
        Err(error) => {
            write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_request_body",
                format!("request body is not valid JSON: {error}"),
                &ctx.request_id,
            )
            .await?;
            Ok(None)
        }
    }
}

async fn write_guardrail_error(
    session: &mut Session,
    ctx: &ProxyContext,
    error: anyhow::Error,
) -> PingoraResult<()> {
    let message = error.to_string();
    let storage_error = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<ferrogate_storage::StorageError>());
    let (status, code) = match storage_error {
        Some(ferrogate_storage::StorageError::NotFound(_)) => {
            (StatusCode::NOT_FOUND, "guardrail_policy_revision_not_found")
        }
        Some(ferrogate_storage::StorageError::Conflict(_)) => {
            (StatusCode::CONFLICT, "guardrail_policy_conflict")
        }
        Some(
            ferrogate_storage::StorageError::Postgres(_)
            | ferrogate_storage::StorageError::Runtime(_),
        ) => (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable"),
        Some(_) => (StatusCode::INTERNAL_SERVER_ERROR, "storage_error"),
        None if message.contains("was not found") => {
            (StatusCode::NOT_FOUND, "guardrail_policy_revision_not_found")
        }
        None if message.contains("already exists") || message.contains("conflicts") => {
            (StatusCode::CONFLICT, "guardrail_policy_conflict")
        }
        None => (StatusCode::BAD_REQUEST, "invalid_guardrail_policy"),
    };
    write_json_error(session, status, code, message, &ctx.request_id).await
}

fn record_guardrail_policy_cas_conflict(
    state: &AppState,
    ctx: &ProxyContext,
    auth: &AuthContext,
    action: &'static str,
    policy_id: &str,
    revision: u32,
    error: &anyhow::Error,
) {
    let conflict = error.chain().any(|cause| {
        cause
            .downcast_ref::<ferrogate_storage::StorageError>()
            .is_some_and(ferrogate_storage::is_guardrail_policy_binding_cas_conflict)
    });
    if !conflict {
        return;
    }

    state.record_guardrail_policy_cas_conflict();
    state.record_admin_audit_event(admin_audit_event_draft_for_target(
        ctx,
        auth,
        action,
        format!("{policy_id}@{revision}"),
        "conflict",
        "guardrail policy binding generation changed concurrently",
    ));
}

async fn guardrail_not_found(session: &mut Session, ctx: &ProxyContext) -> PingoraResult<()> {
    write_json_error(
        session,
        StatusCode::NOT_FOUND,
        "not_found",
        "guardrail policy endpoint not found",
        &ctx.request_id,
    )
    .await
}

async fn invalid_revision(session: &mut Session, ctx: &ProxyContext) -> PingoraResult<()> {
    write_json_error(
        session,
        StatusCode::BAD_REQUEST,
        "invalid_guardrail_policy_revision",
        "revision must be a positive integer",
        &ctx.request_id,
    )
    .await
}

fn parse_revision(value: &str) -> Option<u32> {
    value.parse::<u32>().ok().filter(|revision| *revision > 0)
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
#[path = "guardrail_policies_test.rs"]
mod guardrail_policies_test;
