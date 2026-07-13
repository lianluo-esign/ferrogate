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
    authorize_managed_external_action, ExternalActionAuthorizationResponse, FrameworkAdapterError,
    GatewayExternalActionTransportRequest, GatewayExternalActionTransportResponse,
    ManagedExternalActionDecision, NormalizedFrameworkEvent, SimpleCapabilityAuthorizer,
};
use ferrogate_storage::StoredAgentRunEvent;

use crate::state::{AppState, SharedAppState};

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
        let timeline_tenant = tenant_context_from_external_action(&managed_request.session);
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
        match authorize_managed_external_action(
            &SimpleCapabilityAuthorizer::new(policy),
            managed_request,
        ) {
            Ok((evidence, mut event)) => {
                event
                    .metadata
                    .insert("request_id".to_string(), transport_request_id.to_string());
                Self::record_timeline_event(
                    &state,
                    transport_request_id,
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

    fn record_timeline_event(
        state: &AppState,
        transport_request_id: &str,
        tenant: TenantContext,
        event: NormalizedFrameworkEvent,
    ) {
        let Ok(record) = event.timeline_record() else {
            return;
        };
        state.record_agent_run_event(StoredAgentRunEvent {
            id: record.event_id,
            run_id: record.run_id,
            request_id: transport_request_id.to_string(),
            trace_id: None,
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

fn tenant_context_from_external_action(
    session: &ferrogate_runtime::FrameworkAdapterSession,
) -> TenantContext {
    TenantContext {
        organization_id: Some(session.tenant_id.clone()),
        team_id: None,
        project_id: Some(session.workspace_id.clone()),
        workspace_id: Some(session.workspace_id.clone()),
        user_id: None,
        api_key_id: None,
    }
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
        assert_eq!(event.tenant.project_id.as_deref(), Some("workspace-1"));
        assert!(event
            .message
            .as_deref()
            .unwrap()
            .contains("tool allowed by capability policy"));
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
