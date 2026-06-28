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
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::Arc,
    thread,
};

use anyhow::{Context, Result as AnyResult};
use ferrogate_core::TenantContext;
use ferrogate_runtime::{
    authorize_managed_external_action, CapabilityPolicy, ExternalActionAuthorizationResponse,
    FrameworkAdapterError, GatewayExternalActionTransportRequest,
    GatewayExternalActionTransportResponse, ManagedExternalActionDecision,
    NormalizedFrameworkEvent, SimpleCapabilityAuthorizer,
};
use ferrogate_storage::StoredAgentRunEvent;

use crate::state::AppState;

const EXTERNAL_ACTION_AUTHORIZER_MAX_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub(super) struct GatewayExternalActionAuthorizerService {
    state: AppState,
    policy: CapabilityPolicy,
}

impl GatewayExternalActionAuthorizerService {
    pub(super) fn new(state: AppState, policy: CapabilityPolicy) -> Self {
        Self { state, policy }
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
        match authorize_managed_external_action(
            &SimpleCapabilityAuthorizer::new(self.policy.clone()),
            managed_request,
        ) {
            Ok((evidence, event)) => {
                self.record_timeline_event(transport_request_id, timeline_tenant, event.clone());
                ExternalActionAuthorizationResponse::from_decision(ManagedExternalActionDecision {
                    decision: evidence.decision,
                    event,
                })
            }
            Err(error) => ExternalActionAuthorizationResponse::rejected(error),
        }
    }

    fn record_timeline_event(
        &self,
        transport_request_id: &str,
        tenant: TenantContext,
        event: NormalizedFrameworkEvent,
    ) {
        let Ok(record) = event.timeline_record() else {
            return;
        };
        self.state.record_agent_run_event(StoredAgentRunEvent {
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
    use std::os::unix::net::UnixListener;

    if max_requests == Some(0) {
        anyhow::bail!("max_requests must be greater than zero");
    }
    if socket_path.exists() {
        std::fs::remove_file(socket_path).with_context(|| {
            format!(
                "failed to remove stale gateway external action authorizer socket {}",
                socket_path.display()
            )
        })?;
    }
    let listener = UnixListener::bind(socket_path).with_context(|| {
        format!(
            "failed to bind gateway external action authorizer socket {}",
            socket_path.display()
        )
    })?;
    let service = Arc::new(service);
    let mut handles = Vec::with_capacity(max_requests.unwrap_or(0));
    while max_requests.is_none_or(|limit| handles.len() < limit) {
        let (stream, _) = listener.accept().with_context(|| {
            format!(
                "failed to accept gateway external action authorizer connection at {}",
                socket_path.display()
            )
        })?;
        let service = Arc::clone(&service);
        handles.push(thread::spawn(move || {
            handle_gateway_external_action_authorizer_stream(stream, service)
        }));
        reap_finished_authorizer_threads(&mut handles)?;
    }
    let _ = std::fs::remove_file(socket_path);
    let mut responses = Vec::with_capacity(handles.len());
    for handle in handles {
        responses.push(handle.join().map_err(|_| {
            anyhow::anyhow!("gateway external action authorizer thread panicked")
        })??);
    }
    Ok(responses)
}

pub(super) fn serve_gateway_external_action_authorizer_http(
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
    while max_requests.is_none_or(|limit| handles.len() < limit) {
        let (stream, _) = listener.accept().with_context(|| {
            format!(
                "failed to accept gateway external action HTTP authorizer connection at {listen}"
            )
        })?;
        let service = Arc::clone(&service);
        handles.push(thread::spawn(move || {
            handle_gateway_external_action_authorizer_http_stream(stream, service)
        }));
        reap_finished_authorizer_threads(&mut handles)?;
    }
    let mut responses = Vec::with_capacity(handles.len());
    for handle in handles {
        responses.push(handle.join().map_err(|_| {
            anyhow::anyhow!("gateway external action HTTP authorizer thread panicked")
        })??);
    }
    Ok(responses)
}

fn reap_finished_authorizer_threads(
    handles: &mut Vec<thread::JoinHandle<AnyResult<GatewayExternalActionTransportResponse>>>,
) -> AnyResult<()> {
    let mut index = 0;
    while index < handles.len() {
        if handles[index].is_finished() {
            let handle = handles.remove(index);
            handle.join().map_err(|_| {
                anyhow::anyhow!("gateway external action authorizer thread panicked")
            })??;
        } else {
            index += 1;
        }
    }
    Ok(())
}

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
        os::unix::net::UnixStream,
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
        let service = GatewayExternalActionAuthorizerService::new(
            state.clone(),
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
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
        let service =
            GatewayExternalActionAuthorizerService::new(state.clone(), CapabilityPolicy::default());
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
        let service = GatewayExternalActionAuthorizerService::new(
            state.clone(),
            CapabilityPolicy {
                approval_required_actions: BTreeSet::from([CapabilityAction::Tool]),
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
        let service = GatewayExternalActionAuthorizerService::new(
            state.clone(),
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::NetworkEgress]),
                allow_direct_network_egress: true,
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
        let service = GatewayExternalActionAuthorizerService::new(
            state.clone(),
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
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
        let socket_path = temp.path().join("gateway-external-action-authorizer.sock");
        let state = AppState::new(crate::config::Config::default());
        let service = GatewayExternalActionAuthorizerService::new(
            state.clone(),
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
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
        let service = GatewayExternalActionAuthorizerService::new(
            state.clone(),
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
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
