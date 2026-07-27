// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Gateway-side authorizer for managed worker external actions.
//!
//! The standalone `agent-worker` process owns handler execution and microVM
//! lifecycle. This module is the gateway/control-plane side of the authorization
//! boundary: it accepts the shared external-action transport envelope, applies a
//! gateway capability policy, records timeline evidence, and returns the shared
//! authorization response before any worker handler can execute the action.

use std::{
    io::{Read, Write},
    path::Path,
    sync::Arc,
    thread,
};

#[cfg(test)]
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};

use anyhow::{Context, Result as AnyResult};
use ferrogate_core::TenantContext;
#[cfg(test)]
use ferrogate_runtime::CapabilityPolicy;
use ferrogate_runtime::{
    authorize_managed_external_action, CapabilityAuthorizationDecision,
    ExternalActionAuthorizationResponse, FrameworkAdapterError,
    GatewayExternalActionTransportRequest, GatewayExternalActionTransportResponse,
    ManagedExternalActionDecision, NormalizedFrameworkEvent, SimpleCapabilityAuthorizer,
};
use ferrogate_storage::StoredAgentRunEvent;

use super::managed_action_guardrail::{
    evaluate_managed_action_guardrail, ManagedActionGuardrailBinding, ManagedActionGuardrailRequest,
};
use crate::config::GuardrailStage;
use crate::state::{AppState, GuardrailMatch, SharedAppState, WorkspaceAttribution};

const EXTERNAL_ACTION_AUTHORIZER_MAX_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub(super) struct GatewayExternalActionAuthorizerService {
    state: GatewayExternalActionAuthorizerState,
}

#[derive(Debug, Clone)]
enum GatewayExternalActionAuthorizerState {
    Dynamic(SharedAppState),
    #[cfg(test)]
    Fixed {
        state: Box<AppState>,
        policy: Box<CapabilityPolicy>,
    },
}

#[cfg(test)]
#[path = "external_actions_target_test.rs"]
mod external_actions_target_test;

impl GatewayExternalActionAuthorizerService {
    pub(super) fn new(state: SharedAppState) -> Self {
        Self {
            state: GatewayExternalActionAuthorizerState::Dynamic(state),
        }
    }

    #[cfg(test)]
    fn new_for_test(state: AppState, policy: CapabilityPolicy) -> Self {
        Self {
            state: GatewayExternalActionAuthorizerState::Fixed {
                state: Box::new(state),
                policy: Box::new(policy),
            },
        }
    }

    pub(super) fn authorize_transport_request(
        &self,
        request: GatewayExternalActionTransportRequest,
    ) -> GatewayExternalActionTransportResponse {
        let expected_request_id = request.authorization.stable_request_id();
        let response = if request.request_id == expected_request_id {
            self.authorize(request.request_id.as_str(), request.authorization)
        } else {
            ExternalActionAuthorizationResponse::rejected(FrameworkAdapterError::InvalidRequest(
                format!(
                    "gateway external action authorization request_id mismatch: expected {expected_request_id}"
                ),
            ))
        };
        GatewayExternalActionTransportResponse {
            request_id: request.request_id,
            response,
        }
    }

    fn authorize(
        &self,
        transport_request_id: &str,
        authorization: ferrogate_runtime::ExternalActionAuthorizationRequest,
    ) -> ExternalActionAuthorizationResponse {
        let managed_request = match authorization.into_managed_request() {
            Ok(request) => request,
            Err(error) => return ExternalActionAuthorizationResponse::rejected(error),
        };
        let (state, policy) = match &self.state {
            GatewayExternalActionAuthorizerState::Dynamic(shared) => {
                let state = shared.current();
                let policy = match super::managed_worker_capability_policy_for_tenant(
                    &state,
                    &managed_request.session.tenant_id,
                ) {
                    Ok(policy) => policy,
                    Err(error) => {
                        return ExternalActionAuthorizationResponse::rejected(
                            FrameworkAdapterError::CapabilityDenied(format!(
                                "managed action RBAC resolution failed closed: {error}"
                            )),
                        )
                    }
                };
                (state, policy)
            }
            #[cfg(test)]
            GatewayExternalActionAuthorizerState::Fixed { state, policy } => {
                (state.as_ref().clone(), policy.as_ref().clone())
            }
        };
        // #519: resolved after `state` because the project this workspace rolls
        // up to is read back off the control plane, never inferred from the
        // session (a `FrameworkAdapterSession` carries no project id at all).
        let WorkspaceAttribution {
            tenant: timeline_tenant,
            project: project_attribution,
        } = external_action_attribution(&state, &managed_request.session);
        let workspace_id = managed_request.session.workspace_id.clone();
        // #200: bind the action to the guardrail model before it is consumed by
        // capability authorization, so a managed-action guardrail policy can be
        // evaluated on the allow path below.
        let action_binding = ManagedActionGuardrailBinding::from_action(&managed_request.action);
        let run_id = managed_request.session.run_id.clone();
        // #305: the worker transport frames carry no trace id, but the run the
        // action executes under was created by a dispatching request that did.
        // Resolve that trace from the stored agent-run record so every
        // persisted governance row below carries the run's real trace_id
        // instead of a hard-coded None (None only when the run is unknown or
        // genuinely traceless — never fabricated).
        let run_trace_id = state.agent_run_trace_id(&run_id);
        match authorize_managed_external_action(
            &SimpleCapabilityAuthorizer::new(policy),
            managed_request,
        ) {
            Ok((evidence, mut event)) => {
                event
                    .metadata
                    .insert("request_id".to_string(), transport_request_id.to_string());
                // #200: managed-action INPUT guardrail. Once capability policy
                // allows the action (identity + capability already passed), the
                // action's arguments are evaluated against managed-action
                // guardrail policies *before* the worker can execute it. A
                // blocking match fails the action closed — capability-denied —
                // so no handler ever runs on flagged input. Absent a matching
                // policy this is a no-op; a configured policy that errors fails
                // closed inside `match_guardrail`.
                if evidence.decision == CapabilityAuthorizationDecision::Allowed {
                    // #306: the capability evidence fingerprint
                    // (canonical_target_sha256) rides the guardrail evaluation
                    // so the persisted evidence row carries the same action
                    // identity as the timeline/audit rows.
                    let evidence_fingerprint = Some(evidence.action_fingerprint.as_str())
                        .filter(|fingerprint| !fingerprint.is_empty());
                    // #519 (review): the guardrail below is an ENFORCEMENT
                    // decision on this same tenant context, not an evidence
                    // write, and it runs AFTER capability allow — so the
                    // capability authorizer is not a fail-closed seam above it.
                    // Policy selection matches `project_ids` by equality, so an
                    // unresolved project silently deselects every project-scoped
                    // managed-action policy and the action is allowed on a
                    // `warn!`. That is #519's own failure mode moved onto the
                    // enforcement side, so it fails CLOSED instead: when the
                    // project is not known AND a project-scoped policy exists
                    // that would otherwise have been selected for this action,
                    // the action is refused rather than evaluated against a
                    // silently narrowed policy set.
                    if !project_attribution.is_resolved() {
                        if let Some(policy_id) = state
                            .project_scoped_managed_action_guardrail_policy(
                                &timeline_tenant,
                                ferrogate_guardrails::ManagedActionContext {
                                    class: action_binding.class,
                                    target: Some(action_binding.target.as_str()),
                                },
                            )
                        {
                            let message = format!(
                                "managed action refused: the project workspace {workspace_id} belongs to is unresolved, so project-scoped managed-action guardrail policy {policy_id} could not be evaluated"
                            );
                            Self::record_managed_action_refusal(
                                &state,
                                transport_request_id,
                                run_trace_id.as_deref(),
                                &timeline_tenant,
                                &run_id,
                                &action_binding,
                                evidence_fingerprint,
                                &message,
                            );
                            return ExternalActionAuthorizationResponse::rejected(
                                FrameworkAdapterError::CapabilityDenied(message),
                            );
                        }
                    }
                    if let Some(matched) = Self::evaluate_managed_action_input_guardrail(
                        &state,
                        transport_request_id,
                        run_trace_id.as_deref(),
                        &timeline_tenant,
                        &run_id,
                        &action_binding,
                        evidence_fingerprint,
                    ) {
                        // Record timeline evidence for the guardrail block so the
                        // fail-closed decision is auditable (issue #200) — the
                        // capability-allow event is intentionally not emitted, so
                        // this is the only evidence the action was stopped here.
                        // #304: the enforced guardrail block maps to the
                        // canonical `deny` with the lossless guardrail triple
                        // reason code; the capability evidence fingerprint is
                        // preserved so the blocked action is still correlatable
                        // by exact action identity.
                        let guardrail_decision = ferrogate_runtime::ActionDecision::from(
                            ferrogate_runtime::GuardrailOutcome {
                                verdict: ferrogate_runtime::GuardrailVerdict::Fail,
                                action: ferrogate_runtime::GuardrailTriggeredAction::Block,
                                enforcement: ferrogate_runtime::GuardrailEnforcement::Enforced,
                            },
                        );
                        state.record_agent_run_event(StoredAgentRunEvent {
                            action_fingerprint: Some(evidence.action_fingerprint.clone())
                                .filter(|fingerprint| !fingerprint.is_empty()),
                            decision: Some(guardrail_decision.class_label().to_string()),
                            decision_reason: Some(guardrail_decision.code().to_string()),
                            output_disposition: Some("withheld".to_string()),
                            id: format!("managed-action-guardrail:{run_id}:{transport_request_id}"),
                            run_id: run_id.clone(),
                            request_id: transport_request_id.to_string(),
                            trace_id: run_trace_id.clone(),
                            tenant: timeline_tenant.clone(),
                            turn: 0,
                            kind: "guardrail.blocked".to_string(),
                            target: action_binding.target.clone(),
                            outcome: "blocked".to_string(),
                            tool_call_id: None,
                            message: Some(format!(
                                "managed action blocked by guardrail policy {} ({}): {}",
                                matched.rule_id, matched.code, matched.message
                            )),
                            occurred_at_unix: Some(now_unix_seconds()),
                        });
                        return ExternalActionAuthorizationResponse::rejected(
                            FrameworkAdapterError::CapabilityDenied(format!(
                                "managed action blocked by guardrail policy {} ({}): {}",
                                matched.rule_id, matched.code, matched.message
                            )),
                        );
                    }
                }
                Self::record_timeline_event(
                    &state,
                    transport_request_id,
                    run_trace_id,
                    timeline_tenant,
                    event.clone(),
                );
                ExternalActionAuthorizationResponse::from_decision(ManagedExternalActionDecision {
                    decision: evidence.decision,
                    event,
                })
            }
            Err(error) => ExternalActionAuthorizationResponse::rejected(error),
        }
    }

    /// Evaluate a managed action's input arguments against managed-action
    /// guardrail policies (issue #200). Returns the matched policy when the
    /// action must be blocked, or `None` when no managed-action policy applies.
    /// Delegates to the shared fail-closed evaluator used by every seam.
    #[allow(clippy::too_many_arguments)]
    fn evaluate_managed_action_input_guardrail(
        state: &AppState,
        request_id: &str,
        trace_id: Option<&str>,
        tenant: &TenantContext,
        run_id: &str,
        binding: &ManagedActionGuardrailBinding,
        action_fingerprint: Option<&str>,
    ) -> Option<GuardrailMatch> {
        evaluate_managed_action_guardrail(
            state,
            GuardrailStage::Request,
            &ManagedActionGuardrailRequest {
                request_id,
                trace_id,
                agent_run_id: Some(run_id),
                tenant,
                class: binding.class,
                target: &binding.target,
                // #306: the capability-evidence action fingerprint joins the
                // persisted guardrail evaluation row to the timeline/audit
                // rows of the same action.
                action_fingerprint,
            },
            binding.input_text.clone(),
        )
    }

    /// Persist the timeline evidence for a fail-closed refusal that no
    /// guardrail verdict produced (issue #519 review): the action was stopped
    /// because its project attribution could not be resolved and a
    /// project-scoped managed-action policy could therefore not be evaluated.
    ///
    /// It carries the same canonical deny decision and `withheld` disposition
    /// as a guardrail block, because for a consumer of the timeline this *is* a
    /// guardrail-seam block; the reason is in the message rather than in a new
    /// decision code, so #304's canonical reason vocabulary stays closed.
    #[allow(clippy::too_many_arguments)]
    fn record_managed_action_refusal(
        state: &AppState,
        transport_request_id: &str,
        trace_id: Option<&str>,
        tenant: &TenantContext,
        run_id: &str,
        binding: &ManagedActionGuardrailBinding,
        action_fingerprint: Option<&str>,
        message: &str,
    ) {
        let decision =
            ferrogate_runtime::ActionDecision::from(ferrogate_runtime::GuardrailOutcome {
                verdict: ferrogate_runtime::GuardrailVerdict::Fail,
                action: ferrogate_runtime::GuardrailTriggeredAction::Block,
                enforcement: ferrogate_runtime::GuardrailEnforcement::Enforced,
            });
        state.record_agent_run_event(StoredAgentRunEvent {
            action_fingerprint: action_fingerprint.map(str::to_string),
            decision: Some(decision.class_label().to_string()),
            decision_reason: Some(decision.code().to_string()),
            output_disposition: Some("withheld".to_string()),
            id: format!("managed-action-attribution:{run_id}:{transport_request_id}"),
            run_id: run_id.to_string(),
            request_id: transport_request_id.to_string(),
            trace_id: trace_id.map(str::to_string),
            tenant: tenant.clone(),
            turn: 0,
            kind: "guardrail.blocked".to_string(),
            target: binding.target.clone(),
            outcome: "blocked".to_string(),
            tool_call_id: None,
            message: Some(message.to_string()),
            occurred_at_unix: Some(now_unix_seconds()),
        });
    }

    fn record_timeline_event(
        state: &AppState,
        transport_request_id: &str,
        run_trace_id: Option<String>,
        tenant: TenantContext,
        event: NormalizedFrameworkEvent,
    ) {
        let Ok(record) = event.timeline_record() else {
            return;
        };
        state.record_agent_run_event(StoredAgentRunEvent {
            // #304: the capability-authorizer evidence (fingerprint under the
            // canonical_target_sha256 contract + canonical decision) survives
            // persistence instead of being dropped at this boundary.
            action_fingerprint: record.action_fingerprint,
            decision: record.decision,
            decision_reason: record.decision_reason,
            output_disposition: None,
            id: record.event_id,
            run_id: record.run_id,
            request_id: transport_request_id.to_string(),
            // #305: the run's dispatching-request trace id (resolved from the
            // stored agent-run record) — no longer hard-coded None.
            trace_id: run_trace_id,
            tenant,
            turn: 0,
            kind: record.kind,
            target: record.target,
            outcome: record.outcome,
            tool_call_id: None,
            message: record.message,
            occurred_at_unix: Some(now_unix_seconds()),
        });
    }
}

#[cfg(unix)]
pub(super) fn serve_gateway_external_action_authorizer_unix(
    socket_path: &Path,
    service: GatewayExternalActionAuthorizerService,
    max_requests: Option<usize>,
) -> AnyResult<Vec<GatewayExternalActionTransportResponse>> {
    serve_gateway_external_action_authorizer_unix_with_hooks(
        socket_path,
        service,
        max_requests,
        || {},
        || {},
    )
}

#[cfg(unix)]
#[cfg(test)]
fn serve_gateway_external_action_authorizer_unix_with_pre_bind_hook<F>(
    socket_path: &Path,
    service: GatewayExternalActionAuthorizerService,
    max_requests: Option<usize>,
    pre_bind_hook: F,
) -> AnyResult<Vec<GatewayExternalActionTransportResponse>>
where
    F: FnOnce(),
{
    serve_gateway_external_action_authorizer_unix_with_hooks(
        socket_path,
        service,
        max_requests,
        pre_bind_hook,
        || {},
    )
}

#[cfg(unix)]
fn serve_gateway_external_action_authorizer_unix_with_hooks<F, B>(
    socket_path: &Path,
    service: GatewayExternalActionAuthorizerService,
    max_requests: Option<usize>,
    pre_bind_hook: F,
    bound_hook: B,
) -> AnyResult<Vec<GatewayExternalActionTransportResponse>>
where
    F: FnOnce(),
    B: FnOnce(),
{
    use std::os::unix::net::UnixListener;

    if max_requests == Some(0) {
        anyhow::bail!("max_requests must be greater than zero");
    }
    let validated = validate_external_action_authorizer_socket_parent(socket_path)?;
    pre_bind_hook();
    validated.revalidate_path()?;
    let anchored_socket_path = validated.anchored_socket_path()?;
    if anchored_socket_path.exists() {
        std::fs::remove_file(&anchored_socket_path).with_context(|| {
            format!(
                "failed to remove stale gateway external action authorizer socket {}",
                validated.canonical_socket_path.display()
            )
        })?;
    }
    validated.revalidate_path()?;
    let listener = UnixListener::bind(&anchored_socket_path).with_context(|| {
        format!(
            "failed to bind gateway external action authorizer socket {}",
            validated.canonical_socket_path.display()
        )
    })?;
    listener.set_nonblocking(true)?;
    let _socket_cleanup = UnixSocketPathCleanup(anchored_socket_path.clone());
    use std::os::unix::fs::PermissionsExt;
    validated.revalidate_path()?;
    if let Err(error) = std::fs::set_permissions(
        &anchored_socket_path,
        std::fs::Permissions::from_mode(0o600),
    ) {
        let _ = std::fs::remove_file(&anchored_socket_path);
        return Err(error).with_context(|| {
            format!(
                "failed to restrict gateway external action authorizer socket {} to mode 0600",
                validated.canonical_socket_path.display()
            )
        });
    }
    validated.verify_bound_socket(&anchored_socket_path)?;
    bound_hook();
    let service = Arc::new(service);
    let mut handles = Vec::with_capacity(max_requests.unwrap_or(0));
    let mut responses = Vec::with_capacity(max_requests.unwrap_or(0));
    let mut accepted_requests = 0_usize;
    while !external_action_request_limit_reached(accepted_requests, max_requests) {
        validated.verify_bound_socket(&anchored_socket_path)?;
        let (stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(5));
                continue;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to accept gateway external action authorizer connection at {}",
                        validated.canonical_socket_path.display()
                    )
                })
            }
        };
        accepted_requests = accepted_requests.saturating_add(1);
        let service = Arc::clone(&service);
        handles.push(thread::spawn(move || {
            handle_gateway_external_action_authorizer_stream(stream, service)
        }));
        reap_finished_authorizer_threads(&mut handles, &mut responses)?;
    }
    for handle in handles {
        responses.push(handle.join().map_err(|_| {
            anyhow::anyhow!("gateway external action authorizer thread panicked")
        })??);
    }
    Ok(responses)
}

#[cfg(unix)]
struct UnixSocketPathCleanup(std::path::PathBuf);

#[cfg(unix)]
impl Drop for UnixSocketPathCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct ValidatedExternalActionAuthorizerSocketPath {
    canonical_socket_path: std::path::PathBuf,
    canonical_parent: std::path::PathBuf,
    file_name: std::ffi::OsString,
    parent_device: u64,
    parent_inode: u64,
    parent_dir: std::fs::File,
    effective_uid: u32,
}

#[cfg(unix)]
impl ValidatedExternalActionAuthorizerSocketPath {
    fn revalidate_path(&self) -> AnyResult<()> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let current_parent = std::fs::canonicalize(&self.canonical_parent).with_context(|| {
            format!(
                "gateway external action authorizer socket parent {} changed after validation",
                self.canonical_parent.display()
            )
        })?;
        let metadata = std::fs::symlink_metadata(&self.canonical_parent)?;
        if current_parent != self.canonical_parent
            || metadata.dev() != self.parent_device
            || metadata.ino() != self.parent_inode
        {
            anyhow::bail!(
                "gateway external action authorizer socket parent {} changed after validation",
                self.canonical_parent.display()
            );
        }
        validate_external_action_authorizer_parent_access(
            metadata.uid(),
            metadata.permissions().mode() & 0o777,
            self.effective_uid,
        )?;
        validate_external_action_authorizer_ancestor_chain(
            &self.canonical_parent,
            self.effective_uid,
        )
    }

    #[cfg(target_os = "linux")]
    fn anchored_socket_path(&self) -> AnyResult<std::path::PathBuf> {
        use std::os::fd::AsRawFd;

        Ok(std::path::PathBuf::from(format!(
            "/proc/self/fd/{}/{}",
            self.parent_dir.as_raw_fd(),
            self.file_name.to_string_lossy()
        )))
    }

    #[cfg(not(target_os = "linux"))]
    fn anchored_socket_path(&self) -> AnyResult<std::path::PathBuf> {
        anyhow::bail!("race-resistant Unix authorizer socket binding requires Linux procfs")
    }

    fn verify_bound_socket(&self, anchored_socket_path: &Path) -> AnyResult<()> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

        self.revalidate_path()?;
        let anchored = std::fs::symlink_metadata(anchored_socket_path)?;
        let canonical =
            std::fs::symlink_metadata(&self.canonical_socket_path).with_context(|| {
                format!(
                    "gateway external action authorizer socket {} changed after bind",
                    self.canonical_socket_path.display()
                )
            })?;
        if !anchored.file_type().is_socket()
            || !canonical.file_type().is_socket()
            || anchored.dev() != canonical.dev()
            || anchored.ino() != canonical.ino()
            || canonical.permissions().mode() & 0o777 != 0o600
        {
            anyhow::bail!(
                "gateway external action authorizer socket {} failed identity or mode verification",
                self.canonical_socket_path.display()
            );
        }
        Ok(())
    }
}

#[cfg(unix)]
fn validate_external_action_authorizer_socket_parent(
    socket_path: &Path,
) -> AnyResult<ValidatedExternalActionAuthorizerSocketPath> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if !socket_path.is_absolute() {
        anyhow::bail!("gateway external action authorizer socket path must be absolute");
    }
    let file_name = socket_path
        .file_name()
        .filter(|name| !name.is_empty())
        .context("gateway external action authorizer socket path has no filename")?
        .to_os_string();
    let parent = socket_path.parent().with_context(|| {
        format!(
            "gateway external action authorizer socket {} has no parent directory",
            socket_path.display()
        )
    })?;
    let parent = std::fs::canonicalize(parent).with_context(|| {
        format!(
            "gateway external action authorizer socket parent {} must already exist",
            parent.display()
        )
    })?;
    if socket_path.parent() != Some(parent.as_path()) {
        anyhow::bail!(
            "gateway external action authorizer socket lexical parent must equal its canonical parent; symlinked or non-normalized parents are rejected"
        );
    }
    let metadata = std::fs::symlink_metadata(&parent).with_context(|| {
        format!(
            "failed to inspect gateway external action authorizer socket parent {}",
            parent.display()
        )
    })?;
    if !metadata.is_dir() {
        anyhow::bail!(
            "gateway external action authorizer socket parent {} is not a directory",
            parent.display()
        );
    }
    let effective_uid = rustix::process::geteuid().as_raw();
    let mode = metadata.permissions().mode() & 0o777;
    validate_external_action_authorizer_parent_access(metadata.uid(), mode, effective_uid)
        .map_err(|error| {
            anyhow::anyhow!(
                "gateway external action authorizer socket parent {} is insecure: {error}",
                parent.display()
            )
        })?;
    validate_external_action_authorizer_ancestor_chain(&parent, effective_uid)?;
    use rustix::fs::{open, Mode, OFlags};
    let parent_fd = open(
        &parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    let parent_dir: std::fs::File = parent_fd.into();
    let opened_metadata = parent_dir.metadata()?;
    if opened_metadata.dev() != metadata.dev() || opened_metadata.ino() != metadata.ino() {
        anyhow::bail!(
            "gateway external action authorizer socket parent changed while opening directory"
        );
    }
    Ok(ValidatedExternalActionAuthorizerSocketPath {
        canonical_socket_path: parent.join(&file_name),
        canonical_parent: parent,
        file_name,
        parent_device: metadata.dev(),
        parent_inode: metadata.ino(),
        parent_dir,
        effective_uid,
    })
}

#[cfg(unix)]
fn validate_external_action_authorizer_ancestor_chain(
    parent: &Path,
    effective_uid: u32,
) -> AnyResult<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mut child = parent;
    for ancestor in parent.ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        let mode = metadata.permissions().mode();
        let child_metadata = std::fs::symlink_metadata(child)?;
        validate_external_action_authorizer_ancestor_access(
            metadata.uid(),
            mode,
            child_metadata.uid(),
            effective_uid,
        )
        .with_context(|| format!("insecure socket path ancestor {}", ancestor.display()))?;
        child = ancestor;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_external_action_authorizer_ancestor_access(
    owner_uid: u32,
    mode: u32,
    child_owner_uid: u32,
    effective_uid: u32,
) -> AnyResult<()> {
    if owner_uid != 0 && owner_uid != effective_uid {
        anyhow::bail!(
            "socket path ancestor owner uid {owner_uid} is neither root nor effective uid {effective_uid}"
        );
    }
    if mode & 0o022 != 0 {
        if mode & 0o1000 == 0 {
            anyhow::bail!("writable socket path ancestor must have the sticky bit");
        }
        if child_owner_uid != effective_uid {
            anyhow::bail!(
                "child beneath sticky writable ancestor must be owned by effective uid {effective_uid}"
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_external_action_authorizer_parent_access(
    owner_uid: u32,
    mode: u32,
    effective_uid: u32,
) -> AnyResult<()> {
    if owner_uid != effective_uid {
        anyhow::bail!(
            "socket parent must be owned by effective uid {effective_uid} (actual uid={owner_uid})"
        );
    }
    if mode != 0o700 {
        anyhow::bail!("socket parent must have mode 0700 (mode={mode:04o})");
    }
    Ok(())
}

#[cfg(test)]
fn serve_gateway_external_action_authorizer_http(
    listen: SocketAddr,
    service: GatewayExternalActionAuthorizerService,
    max_requests: Option<usize>,
) -> AnyResult<Vec<GatewayExternalActionTransportResponse>> {
    if max_requests == Some(0) {
        anyhow::bail!("max_requests must be greater than zero");
    }
    let listener = TcpListener::bind(listen).with_context(|| {
        format!("failed to bind gateway external action HTTP authorizer at {listen}")
    })?;
    let service = Arc::new(service);
    let mut handles = Vec::with_capacity(max_requests.unwrap_or(0));
    let mut responses = Vec::with_capacity(max_requests.unwrap_or(0));
    let mut accepted_requests = 0_usize;
    while !external_action_request_limit_reached(accepted_requests, max_requests) {
        let (stream, _) = listener.accept().with_context(|| {
            format!(
                "failed to accept gateway external action HTTP authorizer connection at {listen}"
            )
        })?;
        accepted_requests = accepted_requests.saturating_add(1);
        let service = Arc::clone(&service);
        handles.push(thread::spawn(move || {
            handle_gateway_external_action_authorizer_http_stream(stream, service)
        }));
        reap_finished_authorizer_threads(&mut handles, &mut responses)?;
    }
    for handle in handles {
        responses.push(handle.join().map_err(|_| {
            anyhow::anyhow!("gateway external action HTTP authorizer thread panicked")
        })??);
    }
    Ok(responses)
}

fn external_action_request_limit_reached(
    accepted_requests: usize,
    max_requests: Option<usize>,
) -> bool {
    max_requests.is_some_and(|limit| accepted_requests >= limit)
}

fn reap_finished_authorizer_threads(
    handles: &mut Vec<thread::JoinHandle<AnyResult<GatewayExternalActionTransportResponse>>>,
    responses: &mut Vec<GatewayExternalActionTransportResponse>,
) -> AnyResult<()> {
    let mut index = 0;
    while index < handles.len() {
        if handles[index].is_finished() {
            let handle = handles.remove(index);
            let response = handle.join().map_err(|_| {
                anyhow::anyhow!("gateway external action authorizer thread panicked")
            })??;
            responses.push(response);
        } else {
            index += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
fn handle_gateway_external_action_authorizer_http_stream(
    mut stream: TcpStream,
    service: Arc<GatewayExternalActionAuthorizerService>,
) -> AnyResult<GatewayExternalActionTransportResponse> {
    let body = read_external_action_authorizer_http_request(&mut stream)?;
    let request: GatewayExternalActionTransportRequest = serde_json::from_str(&body)
        .context("failed to decode external action HTTP authorization request")?;
    let response = service.authorize_transport_request(request);
    write_external_action_authorizer_http_response(&mut stream, 200, &response)?;
    stream.shutdown(Shutdown::Write).ok();
    Ok(response)
}

#[cfg(test)]
fn read_external_action_authorizer_http_request(stream: &mut TcpStream) -> AnyResult<String> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    let header_end = loop {
        let read = stream
            .read(&mut buffer)
            .context("failed to read external action HTTP authorization request")?;
        if read == 0 {
            anyhow::bail!("external action HTTP authorization request closed before headers");
        }
        request.extend_from_slice(&buffer[..read]);
        if request.len() > EXTERNAL_ACTION_AUTHORIZER_MAX_MESSAGE_BYTES {
            anyhow::bail!(
                "gateway external action HTTP authorization request exceeds maximum message size"
            );
        }
        if let Some(index) = find_header_end(&request) {
            break index;
        }
    };
    let headers = std::str::from_utf8(&request[..header_end])
        .context("external action HTTP authorization request headers are not valid UTF-8")?;
    let mut lines = headers.lines();
    let request_line = lines.next().unwrap_or_default();
    if request_line != "POST /v1/agent-worker/external-actions/authorize HTTP/1.1" {
        anyhow::bail!(
            "gateway external action HTTP authorizer requires POST /v1/agent-worker/external-actions/authorize"
        );
    }
    let mut content_length = None;
    let mut content_type_ok = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .context("external action HTTP authorization content-length is invalid")?,
            );
        }
        if name.eq_ignore_ascii_case("content-type")
            && value
                .trim()
                .split(';')
                .next()
                .is_some_and(|media_type| media_type.eq_ignore_ascii_case("application/json"))
        {
            content_type_ok = true;
        }
    }
    if !content_type_ok {
        anyhow::bail!("gateway external action HTTP authorizer requires application/json");
    }
    let content_length =
        content_length.context("gateway external action HTTP authorizer missing content-length")?;
    if content_length > EXTERNAL_ACTION_AUTHORIZER_MAX_MESSAGE_BYTES {
        anyhow::bail!(
            "gateway external action HTTP authorization content-length exceeds maximum message size"
        );
    }
    let body_start = header_end + 4;
    while request.len().saturating_sub(body_start) < content_length {
        let read = stream
            .read(&mut buffer)
            .context("failed to read external action HTTP authorization body")?;
        if read == 0 {
            anyhow::bail!("external action HTTP authorization request closed before body");
        }
        request.extend_from_slice(&buffer[..read]);
        if request.len() > EXTERNAL_ACTION_AUTHORIZER_MAX_MESSAGE_BYTES + body_start {
            anyhow::bail!(
                "gateway external action HTTP authorization body exceeds maximum message size"
            );
        }
    }
    let body = &request[body_start..body_start + content_length];
    let body = std::str::from_utf8(body)
        .context("external action HTTP authorization body is not valid UTF-8")?;
    Ok(body.to_string())
}

#[cfg(test)]
fn write_external_action_authorizer_http_response(
    stream: &mut TcpStream,
    status: u16,
    response: &GatewayExternalActionTransportResponse,
) -> AnyResult<()> {
    let body = serde_json::to_string(response)?;
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(response.as_bytes())
        .context("failed to write external action HTTP authorization response")
}

#[cfg(test)]
fn find_header_end(request: &[u8]) -> Option<usize> {
    request.windows(4).position(|window| window == b"\r\n\r\n")
}

#[cfg(unix)]
fn handle_gateway_external_action_authorizer_stream(
    mut stream: std::os::unix::net::UnixStream,
    service: Arc<GatewayExternalActionAuthorizerService>,
) -> AnyResult<GatewayExternalActionTransportResponse> {
    let mut input = String::new();
    read_external_action_authorizer_stream(&mut stream, &mut input)?;
    let request: GatewayExternalActionTransportRequest = serde_json::from_str(&input)
        .context("failed to decode external action authorization request")?;
    let response = service.authorize_transport_request(request);
    stream
        .write_all(serde_json::to_string(&response)?.as_bytes())
        .context("failed to write external action authorization response")?;
    stream
        .write_all(b"\n")
        .context("failed to finish external action authorization response")?;
    Ok(response)
}

fn read_external_action_authorizer_stream<R: Read>(
    reader: &mut R,
    output: &mut String,
) -> AnyResult<()> {
    let mut limited = reader.take((EXTERNAL_ACTION_AUTHORIZER_MAX_MESSAGE_BYTES + 1) as u64);
    limited.read_to_string(output)?;
    if output.len() > EXTERNAL_ACTION_AUTHORIZER_MAX_MESSAGE_BYTES {
        anyhow::bail!("gateway external action authorization request exceeds maximum message size");
    }
    Ok(())
}

/// #519: the session declares only `(tenant_id, workspace_id)`; the project the
/// workspace belongs to is resolved from the control plane. Writing the
/// workspace id into `project_id` -- what this did before -- pointed
/// project-scoped quota, billing attribution and every audit row at an id that
/// names no project.
///
/// The resolution *outcome* rides along with the context because this path has
/// an enforcement seam on it (guardrail policy selection), which must
/// distinguish "no project" from "no answer".
fn external_action_attribution(
    state: &AppState,
    session: &ferrogate_runtime::FrameworkAdapterSession,
) -> WorkspaceAttribution {
    state.workspace_attribution(&session.tenant_id, &session.workspace_id)
}

fn now_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        io::{Read, Write},
        net::{Shutdown, TcpListener, TcpStream},
        os::unix::{fs::PermissionsExt, net::UnixStream},
        time::Duration,
    };

    use ferrogate_guardrails::DetectorStage;
    use ferrogate_runtime::{
        CapabilityAction, ExternalActionAuthorizationRequest, ExternalActionDecision,
        ExternalActionMode, FrameworkAdapterMode, GatewayExternalActionTransportRequest,
        GatewayExternalActionTransportResponse, ManagedExternalAction,
        ManagedExternalActionRequest, ManagedNetworkEgressAction, ManagedToolAction,
    };

    use super::*;

    #[test]
    fn gateway_external_action_authorizer_allows_and_records_timeline_event() {
        let state = AppState::new(crate::config::Config::default());
        // #519: `workspace-1` belongs to `project-1`; the timeline row must be
        // attributed to that project, not to the workspace id.
        register_workspace(&state, "workspace-1", "project-1", "tenant-1");
        let service = GatewayExternalActionAuthorizerService::new_for_test(
            state.clone(),
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
                ..CapabilityPolicy::default()
            },
        );
        let authorization =
            ExternalActionAuthorizationRequest::from_managed_request(managed_tool_request());
        let response = service.authorize_transport_request(GatewayExternalActionTransportRequest {
            request_id: authorization.stable_request_id(),
            authorization,
        });

        assert!(response.response.accepted);
        assert_eq!(
            response.response.decision,
            Some(ExternalActionDecision::Allowed)
        );
        let timeline = state
            .agent_run_timeline("run-1", crate::state::AgentRunFilter::default())
            .expect("allowed external action should record timeline evidence");
        assert_eq!(timeline.agent_events.len(), 1);
        let event = &timeline.agent_events[0];
        assert_eq!(event.kind, "capability.allowed");
        assert_eq!(event.target, "tool:native.echo");
        assert_eq!(event.outcome, "allowed");
        assert_eq!(event.tenant.organization_id.as_deref(), Some("tenant-1"));
        assert_eq!(event.tenant.project_id.as_deref(), Some("project-1"));
        assert_eq!(event.tenant.workspace_id.as_deref(), Some("workspace-1"));
        assert!(event
            .message
            .as_deref()
            .unwrap()
            .contains("tool allowed by capability policy"));
        // #304: the canonical decision survives into the stored columns. This
        // class-only tool action has no canonical target, so no fingerprint.
        assert_eq!(event.decision.as_deref(), Some("allow"));
        assert_eq!(
            event.decision_reason.as_deref(),
            Some(ferrogate_runtime::decision_codes::CAPABILITY_ALLOWED)
        );
        assert_eq!(event.action_fingerprint, None);
    }

    fn register_workspace(state: &AppState, id: &str, project_id: &str, tenant_id: &str) {
        crate::gateway::block_on_sync_bridge(state.upsert_workspace(
            ferrogate_storage::StoredWorkspace {
                id: id.to_string(),
                project_id: project_id.to_string(),
                tenant_id: tenant_id.to_string(),
                name: id.to_string(),
                slug: id.to_string(),
                environment: "dev".to_string(),
                status: "active".to_string(),
                created_at_unix: 0,
                updated_at_unix: 0,
            },
        ))
        .expect("workspace upsert should succeed");
    }

    fn project_budget_policy(
        scope_id: &str,
        monthly_budget_usd: f64,
    ) -> ferrogate_storage::StoredQuotaPolicy {
        ferrogate_storage::StoredQuotaPolicy {
            id: ferrogate_storage::quota_policy_id(
                ferrogate_storage::QuotaScopeKind::Project,
                scope_id,
            ),
            scope_type: ferrogate_storage::QuotaScopeKind::Project,
            scope_id: scope_id.to_string(),
            model_allowlist: vec![],
            rpm_limit: None,
            tpm_limit: None,
            monthly_budget_usd: Some(monthly_budget_usd),
            asset_storage_quota_bytes: None,
            asset_max_object_bytes: None,
            agent_cost_budget_usd: None,
            alert_threshold_pcts: vec![],
            monthly_egress_bytes_budget: None,
            download_rpm_limit: None,
            enabled: true,
            created_at_unix: 1,
            updated_at_unix: 1,
        }
    }

    /// #519: the project the external-action producer resolves is the scope a
    /// quota lookup on that context binds to.
    ///
    /// Scope of the claim, exactly (the #519 review corrected an earlier
    /// overclaim here): the external-action authorize path does NOT resolve
    /// quota and emits no metering row -- it reaches capability policy, the
    /// guardrail evaluator, and `record_agent_run_event`, which is an evidence
    /// write. So this test pins the *producer* (the project attribution the
    /// path builds) composed with the *shared consumer*
    /// `resolve_effective_quota`, the same resolver `auth::finalize_auth` uses.
    /// The end-to-end "drive a run, inspect the emitted metering row" probe
    /// (issue #519 Ask-2) is NOT delivered by this test and remains open.
    ///
    /// A project-scoped quota policy written against the run's REAL project
    /// must bind; a policy written against the workspace id under
    /// `QuotaScopeKind::Project` -- the scope the pre-#519 code would have
    /// looked up -- must not.
    #[test]
    fn external_action_resolved_project_is_the_scope_a_quota_lookup_binds() {
        let state = AppState::new(crate::config::Config::default());
        register_workspace(&state, "workspace-1", "project-1", "tenant-1");
        // A decoy at (Project, "workspace-1"): the id the old code put in the
        // project slot. It is tighter, so if it ever bound it would win the
        // `min`-across-the-chain merge and be unmissable here.
        for (scope_id, budget) in [("project-1", 500.0_f64), ("workspace-1", 1.0_f64)] {
            crate::gateway::block_on_sync_bridge(
                state.upsert_quota_policy(project_budget_policy(scope_id, budget)),
            )
            .expect("quota policy upsert should succeed");
        }

        let session = managed_tool_request().session;
        let attribution = external_action_attribution(&state, &session);
        let tenant = attribution.tenant;
        assert_eq!(tenant.project_id.as_deref(), Some("project-1"));
        assert_eq!(
            attribution.project,
            crate::state::ProjectAttribution::Resolved("project-1".to_string())
        );

        let quota = crate::gateway::block_on_sync_bridge(state.resolve_effective_quota(&tenant))
            .expect("quota resolution should succeed");
        assert_eq!(
            quota.monthly_budget_scope,
            Some(ferrogate_policy::QuotaScopeSelector {
                kind: ferrogate_storage::QuotaScopeKind::Project,
                id: "project-1".to_string(),
            })
        );
        assert_eq!(quota.monthly_budget_usd, Some(500.0));
    }

    /// #519: an unknown workspace yields no project scope at all rather than a
    /// fabricated one. The pre-fix code would have bound a project-scoped quota
    /// lookup to `(Project, "workspace-1")`.
    #[test]
    fn external_action_attribution_has_no_project_scope_when_workspace_is_unknown() {
        let state = AppState::new(crate::config::Config::default());
        crate::gateway::block_on_sync_bridge(
            state.upsert_quota_policy(project_budget_policy("workspace-1", 1.0)),
        )
        .expect("quota policy upsert should succeed");

        let session = managed_tool_request().session;
        let attribution = external_action_attribution(&state, &session);
        let tenant = attribution.tenant;
        assert_eq!(tenant.project_id, None);
        assert_eq!(tenant.workspace_id.as_deref(), Some("workspace-1"));
        // Not a read failure: the control plane answered, it just holds no
        // chain for this workspace.
        assert_eq!(
            attribution.project,
            crate::state::ProjectAttribution::Unknown
        );

        let quota = crate::gateway::block_on_sync_bridge(state.resolve_effective_quota(&tenant))
            .expect("quota resolution should succeed");
        assert_eq!(quota.monthly_budget_scope, None);
        assert_eq!(quota.monthly_budget_usd, None);
    }

    /// #304 acceptance: capability-authorizer evidence survives persistence
    /// end to end. A governed external action with a canonical target (managed
    /// MCP tool call) must produce a timeline row whose `action_fingerprint`
    /// EQUALS the authorizer evidence fingerprint (canonical_target_sha256
    /// contract) and whose decision matches the authorization decision.
    #[test]
    fn timeline_row_action_fingerprint_equals_authorizer_evidence_fingerprint() {
        let state = AppState::new(crate::config::Config::default());
        let service = GatewayExternalActionAuthorizerService::new_for_test(
            state.clone(),
            mcp_allowing_capability_policy(),
        );
        let request = managed_mcp_request(serde_json::json!({"body": "file a routine bug"}));
        let expected_fingerprint = ferrogate_runtime::canonical_target_for_managed_action(
            &request.action,
            &request.session.adapter_name,
            request.high_risk,
        )
        .expect("managed MCP actions with inline arguments have a canonical target")
        .fingerprint();
        let authorization = ExternalActionAuthorizationRequest::from_managed_request(request);
        let response = service.authorize_transport_request(GatewayExternalActionTransportRequest {
            request_id: authorization.stable_request_id(),
            authorization,
        });

        assert!(response.response.accepted);
        // The authorizer evidence fingerprint rides in the normalized event
        // metadata; the persisted timeline row must carry the SAME value.
        let event = response.response.event.as_ref().unwrap();
        assert_eq!(
            event["metadata"]["action_fingerprint"].as_str(),
            Some(expected_fingerprint.as_str()),
        );
        let timeline = state
            .agent_run_timeline("run-1", crate::state::AgentRunFilter::default())
            .expect("allowed external action should record timeline evidence");
        assert_eq!(timeline.agent_events.len(), 1);
        let stored = &timeline.agent_events[0];
        assert_eq!(stored.kind, "capability.allowed");
        assert_eq!(
            stored.action_fingerprint.as_deref(),
            Some(expected_fingerprint.as_str()),
            "the authorizer evidence fingerprint must survive persistence verbatim"
        );
        assert!(stored
            .action_fingerprint
            .as_deref()
            .unwrap()
            .starts_with("sha256:"));
        assert_eq!(stored.decision.as_deref(), Some("allow"));
        assert_eq!(
            stored.decision_reason.as_deref(),
            Some(ferrogate_runtime::decision_codes::CAPABILITY_ALLOWED)
        );
    }

    /// #305: the authorizer transport frames carry no trace id, so the
    /// persisted timeline row must inherit the trace id of the dispatching
    /// request that created the run (resolved from the stored agent-run
    /// record) instead of hard-coding None.
    #[test]
    fn timeline_row_inherits_trace_id_from_the_dispatching_runs_record() {
        let state = AppState::new(crate::config::Config::default());
        state.record_agent_run(ferrogate_storage::StoredAgentRun {
            id: "run-1".to_string(),
            request_id: "fg-dispatch-1".to_string(),
            trace_id: Some("trace-dispatch-1".to_string()),
            tenant: TenantContext {
                organization_id: Some("tenant-1".to_string()),
                ..TenantContext::default()
            },
            status: "running".to_string(),
            provider: "ferrogate.external".to_string(),
            turns_executed: 0,
            output_recorded: false,
            started_at_unix: Some(1),
            completed_at_unix: None,
        });
        let service = GatewayExternalActionAuthorizerService::new_for_test(
            state.clone(),
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
                ..CapabilityPolicy::default()
            },
        );
        let authorization =
            ExternalActionAuthorizationRequest::from_managed_request(managed_tool_request());
        let response = service.authorize_transport_request(GatewayExternalActionTransportRequest {
            request_id: authorization.stable_request_id(),
            authorization,
        });

        assert!(response.response.accepted);
        let timeline = state
            .agent_run_timeline("run-1", crate::state::AgentRunFilter::default())
            .expect("allowed external action should record timeline evidence");
        assert_eq!(timeline.agent_events.len(), 1);
        assert_eq!(
            timeline.agent_events[0].trace_id.as_deref(),
            Some("trace-dispatch-1"),
            "the persisted timeline row must carry the dispatching run's trace id"
        );
    }

    /// #305: when the run is unknown (no stored agent-run record), the trace
    /// id stays None — nothing is fabricated.
    #[test]
    fn timeline_row_trace_id_stays_none_for_unknown_runs() {
        let state = AppState::new(crate::config::Config::default());
        let service = GatewayExternalActionAuthorizerService::new_for_test(
            state.clone(),
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
                ..CapabilityPolicy::default()
            },
        );
        let authorization =
            ExternalActionAuthorizationRequest::from_managed_request(managed_tool_request());
        let response = service.authorize_transport_request(GatewayExternalActionTransportRequest {
            request_id: authorization.stable_request_id(),
            authorization,
        });

        assert!(response.response.accepted);
        let timeline = state
            .agent_run_timeline("run-1", crate::state::AgentRunFilter::default())
            .expect("allowed external action should record timeline evidence");
        assert_eq!(timeline.agent_events[0].trace_id, None);
    }

    #[test]
    fn gateway_external_action_authorizer_denies_and_records_timeline_event() {
        let state = AppState::new(crate::config::Config::default());
        let service = GatewayExternalActionAuthorizerService::new_for_test(
            state.clone(),
            CapabilityPolicy::default(),
        );
        let authorization =
            ExternalActionAuthorizationRequest::from_managed_request(managed_tool_request());
        let response = service.authorize_transport_request(GatewayExternalActionTransportRequest {
            request_id: authorization.stable_request_id(),
            authorization,
        });

        assert!(!response.response.accepted);
        assert_eq!(
            response.response.decision,
            Some(ExternalActionDecision::Denied)
        );
        assert!(response.response.event.is_some());
        let timeline = state
            .agent_run_timeline("run-1", crate::state::AgentRunFilter::default())
            .expect("denied external action should record timeline evidence");
        assert_eq!(timeline.agent_events.len(), 1);
        let event = &timeline.agent_events[0];
        assert_eq!(event.kind, "capability.denied");
        assert_eq!(event.target, "tool:native.echo");
        assert_eq!(event.outcome, "denied");
        // #304: the canonical deny decision is persisted alongside the
        // free-text outcome.
        assert_eq!(event.decision.as_deref(), Some("deny"));
        assert_eq!(
            event.decision_reason.as_deref(),
            Some(ferrogate_runtime::decision_codes::CAPABILITY_DENIED)
        );
    }

    fn managed_mcp_request(arguments: serde_json::Value) -> ManagedExternalActionRequest {
        ManagedExternalActionRequest {
            session: managed_session(),
            action: ManagedExternalAction::McpTool(ferrogate_runtime::ManagedMcpToolAction {
                server_name: "github".to_string(),
                tool_name: "create_issue".to_string(),
                arguments_policy: "inline".to_string(),
                arguments,
            }),
            high_risk: false,
        }
    }

    /// A durable, enforced guardrail policy scoped to managed MCP actions that
    /// blocks when `keyword` appears in the scanned input (issue #200).
    fn managed_mcp_block_policy(keyword: &str) -> ferrogate_guardrails::PolicyRevision {
        ferrogate_guardrails::PolicyRevision {
            policy_id: "mcp-guard".to_string(),
            revision: 1,
            name: "mcp guard".to_string(),
            description: None,
            enforced: true,
            scope: ferrogate_guardrails::PolicyScopeSelector {
                managed_action: Some(ferrogate_guardrails::ManagedActionSelector {
                    classes: vec![ferrogate_guardrails::ManagedActionClass::Mcp],
                    targets: Vec::new(),
                }),
                ..ferrogate_guardrails::PolicyScopeSelector::default()
            },
            checks: vec![ferrogate_guardrails::CheckBinding {
                id: "keyword".to_string(),
                enabled: true,
                stage: DetectorStage::Request,
                sources: ferrogate_guardrails::all_content_sources(),
                detector: ferrogate_guardrails::DetectorDefinition::local(
                    vec![keyword.to_string()],
                    Vec::new(),
                    None,
                ),
                fallback_detector: None,
            }],
            aggregation: ferrogate_guardrails::PolicyAggregation::All,
            execution: ferrogate_guardrails::PolicyExecution::Sequential,
            mode: ferrogate_guardrails::PolicyMode::Enforce,
            streaming: ferrogate_guardrails::PolicyStreamingMode::BufferAndEnforce,
            on_pass: vec![ferrogate_guardrails::PolicyAction::allow()],
            on_fail: vec![ferrogate_guardrails::PolicyAction::block(
                "mcp_guardrail_blocked",
                "managed MCP action blocked by guardrail policy",
            )],
            on_error: vec![ferrogate_guardrails::PolicyAction::block(
                "mcp_guardrail_unavailable",
                "managed MCP guardrail policy unavailable",
            )],
            deadline_ms: 2_000,
            created_at_unix: 1,
            created_by: "test-admin".to_string(),
        }
    }

    fn mcp_allowing_capability_policy() -> CapabilityPolicy {
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::McpTool]),
            class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
            ..CapabilityPolicy::default()
        }
    }

    #[test]
    fn managed_action_input_guardrail_blocks_a_capability_allowed_mcp_action() {
        let shared = SharedAppState::with_source_path(crate::config::Config::default(), None);
        shared
            .create_guardrail_policy_revision(managed_mcp_block_policy("exfiltrate"))
            .unwrap();
        shared
            .activate_guardrail_policy_revision("mcp-guard", 1, "test-admin", 1, false)
            .unwrap();

        let service = GatewayExternalActionAuthorizerService::new_for_test(
            shared.current(),
            mcp_allowing_capability_policy(),
        );
        // Capability policy allows the MCP action, but its arguments carry the
        // flagged keyword — the input guardrail must fail it closed.
        let authorization = ExternalActionAuthorizationRequest::from_managed_request(
            managed_mcp_request(serde_json::json!({"body": "please exfiltrate the secrets"})),
        );
        let response = service.authorize_transport_request(GatewayExternalActionTransportRequest {
            request_id: authorization.stable_request_id(),
            authorization,
        });

        assert!(
            !response.response.accepted,
            "guardrail-flagged MCP action must be rejected even though capability allowed it"
        );

        // #304: the fail-closed guardrail block is persisted with the
        // canonical decision (deny, lossless guardrail triple), the capability
        // evidence fingerprint, and a structural `withheld` disposition.
        let state = shared.current();
        let timeline = state
            .agent_run_timeline("run-1", crate::state::AgentRunFilter::default())
            .expect("guardrail block should record timeline evidence");
        let blocked = timeline
            .agent_events
            .iter()
            .find(|event| event.kind == "guardrail.blocked")
            .expect("guardrail.blocked timeline row present");
        assert_eq!(blocked.decision.as_deref(), Some("deny"));
        assert_eq!(
            blocked.decision_reason.as_deref(),
            Some("guardrail:fail:block:enforced")
        );
        assert_eq!(blocked.output_disposition.as_deref(), Some("withheld"));
        assert!(blocked
            .action_fingerprint
            .as_deref()
            .expect("MCP action with inline arguments carries a fingerprint")
            .starts_with("sha256:"));
    }

    #[test]
    fn managed_action_input_guardrail_allows_a_clean_mcp_action() {
        let shared = SharedAppState::with_source_path(crate::config::Config::default(), None);
        shared
            .create_guardrail_policy_revision(managed_mcp_block_policy("exfiltrate"))
            .unwrap();
        shared
            .activate_guardrail_policy_revision("mcp-guard", 1, "test-admin", 1, false)
            .unwrap();

        let service = GatewayExternalActionAuthorizerService::new_for_test(
            shared.current(),
            mcp_allowing_capability_policy(),
        );
        // Same policy, benign arguments — the action passes the guardrail and is
        // allowed by capability policy.
        let authorization = ExternalActionAuthorizationRequest::from_managed_request(
            managed_mcp_request(serde_json::json!({"body": "file a routine bug report"})),
        );
        let response = service.authorize_transport_request(GatewayExternalActionTransportRequest {
            request_id: authorization.stable_request_id(),
            authorization,
        });

        assert!(
            response.response.accepted,
            "a clean MCP action must remain allowed when no guardrail fires"
        );
        assert_eq!(
            response.response.decision,
            Some(ExternalActionDecision::Allowed)
        );
    }

    /// The same policy, narrowed to a project (issue #519 review).
    fn project_scoped_managed_mcp_block_policy(
        keyword: &str,
        project_id: &str,
    ) -> ferrogate_guardrails::PolicyRevision {
        let mut policy = managed_mcp_block_policy(keyword);
        policy.scope.project_ids = vec![project_id.to_string()];
        policy
    }

    fn activated_mcp_guard(policy: ferrogate_guardrails::PolicyRevision) -> SharedAppState {
        let shared = SharedAppState::with_source_path(crate::config::Config::default(), None);
        shared.create_guardrail_policy_revision(policy).unwrap();
        shared
            .activate_guardrail_policy_revision("mcp-guard", 1, "test-admin", 1, false)
            .unwrap();
        shared
    }

    /// #519 review: guardrail policy *selection* is an enforcement decision fed
    /// by the very attribution #519 fixed, and it runs AFTER capability allow —
    /// so the capability authorizer is not a fail-closed seam above it.
    ///
    /// `PolicyScopeSelector::matches` compares `project_ids` by equality, so a
    /// context with `project_id: None` deselects every project-scoped policy
    /// and the action would be ALLOWED — a control-plane read failure or an
    /// unknown workspace silently downgrading project-scoped guardrail
    /// enforcement, evidenced only by a `warn!`. It must fail closed instead.
    ///
    /// The arguments here are deliberately CLEAN: pre-review this action was
    /// allowed on both counts (policy deselected, and nothing to flag anyway),
    /// so the refusal can only come from the unresolved attribution.
    #[test]
    fn unresolvable_workspace_refuses_an_action_a_project_scoped_guardrail_would_have_governed() {
        let shared = activated_mcp_guard(project_scoped_managed_mcp_block_policy(
            "exfiltrate",
            "project-1",
        ));
        // `workspace-1` is deliberately NOT registered, so the control plane
        // cannot say which project the run belongs to.
        let service = GatewayExternalActionAuthorizerService::new_for_test(
            shared.current(),
            mcp_allowing_capability_policy(),
        );
        let authorization = ExternalActionAuthorizationRequest::from_managed_request(
            managed_mcp_request(serde_json::json!({"body": "file a routine bug report"})),
        );
        let response = service.authorize_transport_request(GatewayExternalActionTransportRequest {
            request_id: authorization.stable_request_id(),
            authorization,
        });

        assert!(
            !response.response.accepted,
            "an unresolved project must not silently deselect a project-scoped managed-action guardrail policy"
        );
        let error = response
            .response
            .error
            .expect("a refusal carries an error")
            .message;
        assert!(
            error.contains("unresolved") && error.contains("mcp-guard"),
            "the refusal must name the unresolved attribution and the policy it could not evaluate, got: {error}"
        );

        // The fail-closed decision is auditable, not just returned.
        let state = shared.current();
        let timeline = state
            .agent_run_timeline("run-1", crate::state::AgentRunFilter::default())
            .expect("the refusal should record timeline evidence");
        let blocked = timeline
            .agent_events
            .iter()
            .find(|event| event.kind == "guardrail.blocked")
            .expect("guardrail.blocked timeline row present");
        assert_eq!(blocked.decision.as_deref(), Some("deny"));
        assert_eq!(blocked.output_disposition.as_deref(), Some("withheld"));
        assert!(blocked
            .message
            .as_deref()
            .is_some_and(|message| message.contains("unresolved")));
        // The evidence row itself must not carry a fabricated project.
        assert_eq!(blocked.tenant.project_id, None);
        assert_eq!(blocked.tenant.workspace_id.as_deref(), Some("workspace-1"));
    }

    /// The other half of the pin above, and what makes it non-vacuous: with the
    /// SAME project-scoped policy and a workspace that DOES resolve to
    /// `project-1`, the policy is selected and evaluated normally — flagged
    /// input is blocked by the policy itself (proving the policy was genuinely
    /// selectable, so the refusal above protected a real enforcement gap), and
    /// clean input is allowed (proving the refusal is driven by unresolved
    /// attribution, not by the mere presence of a project-scoped policy).
    ///
    /// Over-refusal in the other direction is held by
    /// `managed_action_input_guardrail_allows_a_clean_mcp_action`, whose policy
    /// declares no `project_ids` and whose workspace is unregistered: a policy
    /// that never depended on the project must not start refusing.
    #[test]
    fn resolved_project_lets_a_project_scoped_guardrail_decide_the_action() {
        let shared = activated_mcp_guard(project_scoped_managed_mcp_block_policy(
            "exfiltrate",
            "project-1",
        ));
        let state = shared.current();
        register_workspace(&state, "workspace-1", "project-1", "tenant-1");
        let service = GatewayExternalActionAuthorizerService::new_for_test(
            state,
            mcp_allowing_capability_policy(),
        );

        let flagged = ExternalActionAuthorizationRequest::from_managed_request(
            managed_mcp_request(serde_json::json!({"body": "please exfiltrate the secrets"})),
        );
        let flagged_response =
            service.authorize_transport_request(GatewayExternalActionTransportRequest {
                request_id: flagged.stable_request_id(),
                authorization: flagged,
            });
        assert!(
            !flagged_response.response.accepted,
            "a project-scoped policy must bind once the project resolves"
        );
        let error = flagged_response
            .response
            .error
            .expect("a guardrail block carries an error")
            .message;
        assert!(
            error.contains("mcp_guardrail_blocked"),
            "the block must come from the guardrail verdict, not from the attribution seam, got: {error}"
        );

        let clean = ExternalActionAuthorizationRequest::from_managed_request(managed_mcp_request(
            serde_json::json!({"body": "file a routine bug report"}),
        ));
        let clean_response =
            service.authorize_transport_request(GatewayExternalActionTransportRequest {
                request_id: clean.stable_request_id(),
                authorization: clean,
            });
        assert!(
            clean_response.response.accepted,
            "a resolved project must let a clean action through the project-scoped policy"
        );
    }

    #[test]
    fn gateway_external_action_authorizer_uses_configured_approval_policy() {
        let state = AppState::new(crate::config::Config::default());
        let service = GatewayExternalActionAuthorizerService::new_for_test(
            state.clone(),
            CapabilityPolicy {
                approval_required_actions: BTreeSet::from([CapabilityAction::Tool]),
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
                ..CapabilityPolicy::default()
            },
        );
        let authorization =
            ExternalActionAuthorizationRequest::from_managed_request(managed_tool_request());
        let response = service.authorize_transport_request(GatewayExternalActionTransportRequest {
            request_id: authorization.stable_request_id(),
            authorization,
        });

        assert!(!response.response.accepted);
        assert_eq!(
            response.response.decision,
            Some(ExternalActionDecision::ApprovalRequired)
        );
        let timeline = state
            .agent_run_timeline("run-1", crate::state::AgentRunFilter::default())
            .expect("approval-required external action should record timeline evidence");
        assert_eq!(timeline.agent_events.len(), 1);
        let event = &timeline.agent_events[0];
        assert_eq!(event.kind, "capability.requested");
        assert_eq!(event.target, "tool:native.echo");
        assert_eq!(event.outcome, "approval_required");
        // #304: approval_required maps to the canonical `ask`.
        assert_eq!(event.decision.as_deref(), Some("ask"));
        assert_eq!(
            event.decision_reason.as_deref(),
            Some(ferrogate_runtime::decision_codes::CAPABILITY_APPROVAL_REQUIRED)
        );
    }

    #[test]
    fn gateway_external_action_authorizer_can_allow_direct_network_egress_by_policy() {
        let state = AppState::new(crate::config::Config::default());
        let service = GatewayExternalActionAuthorizerService::new_for_test(
            state.clone(),
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::NetworkEgress]),
                allow_direct_network_egress: true,
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
                ..CapabilityPolicy::default()
            },
        );
        let authorization =
            ExternalActionAuthorizationRequest::from_managed_request(managed_network_request());
        let response = service.authorize_transport_request(GatewayExternalActionTransportRequest {
            request_id: authorization.stable_request_id(),
            authorization,
        });

        assert!(response.response.accepted);
        assert_eq!(
            response.response.decision,
            Some(ExternalActionDecision::Allowed)
        );
        let timeline = state
            .agent_run_timeline("run-1", crate::state::AgentRunFilter::default())
            .expect("network egress authorization should record timeline evidence");
        assert_eq!(timeline.agent_events.len(), 1);
        assert_eq!(timeline.agent_events[0].kind, "capability.allowed");
        assert_eq!(timeline.agent_events[0].target, "api.example.com:443");
    }

    #[test]
    fn gateway_external_action_authorizer_rejects_mismatched_request_id_without_timeline_event() {
        let state = AppState::new(crate::config::Config::default());
        let service = GatewayExternalActionAuthorizerService::new_for_test(
            state.clone(),
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
                ..CapabilityPolicy::default()
            },
        );
        let authorization =
            ExternalActionAuthorizationRequest::from_managed_request(managed_tool_request());
        let response = service.authorize_transport_request(GatewayExternalActionTransportRequest {
            request_id: "wrong-request-id".to_string(),
            authorization,
        });

        assert!(!response.response.accepted);
        assert_eq!(
            response
                .response
                .error
                .as_ref()
                .map(|error| error.code.as_str()),
            Some("invalid_request")
        );
        assert!(state
            .agent_run_timeline("run-1", crate::state::AgentRunFilter::default())
            .is_none());
    }

    #[cfg(unix)]
    #[test]
    fn gateway_external_action_authorizer_serves_shared_unix_transport_contract() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket_path = temp.path().join("gateway-external-action-authorizer.sock");
        let state = AppState::new(crate::config::Config::default());
        let service = GatewayExternalActionAuthorizerService::new_for_test(
            state.clone(),
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
                ..CapabilityPolicy::default()
            },
        );
        let server_socket = socket_path.clone();
        let server = thread::spawn(move || {
            serve_gateway_external_action_authorizer_unix(&server_socket, service, Some(1))
        });
        wait_for_socket(&socket_path);

        let authorization =
            ExternalActionAuthorizationRequest::from_managed_request(managed_tool_request());
        let request = GatewayExternalActionTransportRequest {
            request_id: authorization.stable_request_id(),
            authorization,
        };
        let response = send_unix_authorization_request(&socket_path, &request);
        let served = server.join().unwrap().unwrap();

        assert_eq!(served.len(), 1);
        assert_eq!(served[0].request_id, request.request_id);
        assert_eq!(response.request_id, request.request_id);
        assert!(response.response.accepted);
        assert_eq!(
            response.response.decision,
            Some(ExternalActionDecision::Allowed)
        );
        let timeline = state
            .agent_run_timeline("run-1", crate::state::AgentRunFilter::default())
            .expect("Unix authorizer transport should record timeline evidence");
        assert_eq!(timeline.agent_events.len(), 1);
        assert_eq!(timeline.agent_events[0].kind, "capability.allowed");
    }

    #[test]
    fn gateway_external_action_authorizer_serves_shared_http_transport_contract() {
        let state = AppState::new(crate::config::Config::default());
        let service = GatewayExternalActionAuthorizerService::new_for_test(
            state.clone(),
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
                ..CapabilityPolicy::default()
            },
        );
        let listen = free_tcp_addr();
        let server = thread::spawn(move || {
            serve_gateway_external_action_authorizer_http(listen, service, Some(1))
        });

        let authorization =
            ExternalActionAuthorizationRequest::from_managed_request(managed_tool_request());
        let request = GatewayExternalActionTransportRequest {
            request_id: authorization.stable_request_id(),
            authorization,
        };
        let response = send_http_authorization_request(listen, &request);
        let served = server.join().unwrap().unwrap();

        assert_eq!(served.len(), 1);
        assert_eq!(served[0].request_id, request.request_id);
        assert_eq!(response.request_id, request.request_id);
        assert!(response.response.accepted);
        assert_eq!(
            response.response.decision,
            Some(ExternalActionDecision::Allowed)
        );
        let timeline = state
            .agent_run_timeline("run-1", crate::state::AgentRunFilter::default())
            .expect("HTTP authorizer transport should record timeline evidence");
        assert_eq!(timeline.agent_events.len(), 1);
        assert_eq!(timeline.agent_events[0].kind, "capability.allowed");
    }

    fn managed_tool_request() -> ManagedExternalActionRequest {
        ManagedExternalActionRequest {
            session: managed_session(),
            action: ManagedExternalAction::Tool(ManagedToolAction {
                tool_name: "native.echo".to_string(),
                arguments_policy: "redacted_json".to_string(),
            }),
            high_risk: false,
        }
    }

    fn managed_network_request() -> ManagedExternalActionRequest {
        ManagedExternalActionRequest {
            session: managed_session(),
            action: ManagedExternalAction::NetworkEgress(ManagedNetworkEgressAction {
                host: "api.example.com".to_string(),
                port: 443,
                protocol: "tcp".to_string(),
                resolved_ips: Vec::new(),
            }),
            high_risk: false,
        }
    }

    fn managed_session() -> ferrogate_runtime::FrameworkAdapterSession {
        ferrogate_runtime::FrameworkAdapterSession {
            session_id: "session-1".to_string(),
            run_id: "run-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            workspace_id: "workspace-1".to_string(),
            worker_id: "agent-worker-1".to_string(),
            isolation_backend: "firecracker".to_string(),
            adapter_name: "native-harness".to_string(),
            adapter_version: "2026.6.22".to_string(),
            framework: ferrogate_runtime::SupportedFramework::NativeHarness,
            mode: FrameworkAdapterMode::Managed,
        }
    }

    #[cfg(unix)]
    fn wait_for_socket(socket_path: &Path) {
        for _ in 0..100 {
            if socket_path.exists() {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("timed out waiting for socket {}", socket_path.display());
    }

    #[cfg(unix)]
    fn send_unix_authorization_request(
        socket_path: &Path,
        request: &GatewayExternalActionTransportRequest,
    ) -> GatewayExternalActionTransportResponse {
        let mut stream = UnixStream::connect(socket_path).unwrap();
        stream
            .write_all(serde_json::to_string(request).unwrap().as_bytes())
            .unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        serde_json::from_str(&response).unwrap()
    }

    fn free_tcp_addr() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    }

    fn send_http_authorization_request(
        addr: std::net::SocketAddr,
        request: &GatewayExternalActionTransportRequest,
    ) -> GatewayExternalActionTransportResponse {
        let body = serde_json::to_string(request).unwrap();
        let mut stream = (0..100)
            .find_map(|_| match TcpStream::connect(addr) {
                Ok(stream) => Some(stream),
                Err(_) => {
                    thread::sleep(Duration::from_millis(5));
                    None
                }
            })
            .unwrap_or_else(|| panic!("timed out connecting to TCP listener {addr}"));
        let request = format!(
            "POST /v1/agent-worker/external-actions/authorize HTTP/1.1\r\n\
             host: {addr}\r\n\
             content-type: application/json\r\n\
             content-length: {}\r\n\
             connection: close\r\n\
             \r\n\
             {body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let body = response
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap_or_default();
        serde_json::from_str(body).unwrap()
    }

    #[test]
    fn external_action_session_default_mode_stays_managed_for_transport_contracts() {
        let request = serde_json::json!({
            "session": {
                "session_id": "session-1",
                "run_id": "run-1",
                "tenant_id": "tenant-1",
                "workspace_id": "workspace-1",
                "worker_id": "agent-worker-1",
                "isolation_backend": "firecracker",
                "adapter_name": "native-harness",
                "adapter_version": "2026.6.22",
                "framework": "native_harness"
            },
            "action": {
                "kind": "tool",
                "tool_name": "native.echo",
                "arguments_policy": "redacted_json"
            }
        });
        let decoded: ExternalActionAuthorizationRequest = serde_json::from_value(request).unwrap();

        assert_eq!(decoded.session.mode, ExternalActionMode::Managed);
        let managed = decoded.into_managed_request().unwrap();
        assert_eq!(managed.session.mode, FrameworkAdapterMode::Managed);
    }
}
