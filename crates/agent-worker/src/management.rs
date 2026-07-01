// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{
    collections::HashMap,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::net::UnixListener,
    path::Path,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use ferrogate_runtime::{
    AgentWorkerManagementAction, AgentWorkerManagementEnvelope, AgentWorkerManagementErrorCode,
    AgentWorkerManagementFrame, AgentWorkerManagementKey, AgentWorkerManagementResponse,
    AgentWorkerManagementResult, AgentWorkerManagementSecurity, AgentWorkerManagementTransport,
    AgentWorkerManagementVerifier, AgentWorkerSecurityAlgorithm, AgentWorkerTransportSecurity,
    InMemoryAgentWorkerManagementTransport, ManagedWorkerError,
    AGENT_WORKER_MANAGEMENT_MAX_MESSAGE_BYTES, AGENT_WORKER_PROTOCOL_VERSION,
};

use crate::{
    backends::isolation_backends,
    external_actions::{GatewayExternalActionAuthorizer, HttpGatewayExternalActionAuthorizer},
    handlers::framework_handlers,
    lifecycle::dispatch_lifecycle_action,
    state::{AgentWorkerStateStore, InMemoryAgentWorkerStateStore},
};

const SMOKE_SHARED_SECRET: &str = "agent-worker-smoke-secret";

#[derive(Default)]
struct AgentWorkerRuntime {
    external_action_authorizer: Option<Box<dyn GatewayExternalActionAuthorizer + Send + Sync>>,
}

impl AgentWorkerRuntime {
    fn with_http_external_action_authorizer(endpoint: SocketAddr) -> Self {
        Self {
            external_action_authorizer: Some(Box::new(HttpGatewayExternalActionAuthorizer::new(
                endpoint,
            ))),
        }
    }

    fn external_action_authorizer(&self) -> Option<&dyn GatewayExternalActionAuthorizer> {
        self.external_action_authorizer
            .as_deref()
            .map(|authorizer| authorizer as &dyn GatewayExternalActionAuthorizer)
    }
}

pub(crate) fn protocol_smoke() -> Result<()> {
    let mut transport =
        InMemoryAgentWorkerManagementTransport::new(AgentWorkerManagementVerifier::new(vec![
            AgentWorkerManagementKey {
                key_id: "agent-worker-smoke-key".to_string(),
                shared_secret: SMOKE_SHARED_SECRET.to_string(),
            },
        ])?);
    let envelope = smoke_envelope()?;
    let mut state = InMemoryAgentWorkerStateStore::new();
    let runtime = AgentWorkerRuntime::default();
    let response =
        accept_management_envelope(&mut transport, &mut state, &runtime, envelope, 1_000);
    if !response.accepted {
        anyhow::bail!(
            "agent-worker management protocol smoke rejected request: {:?}",
            response.error
        );
    }
    println!(
        "agent-worker protocol smoke accepted request_id={} action={}",
        response.request_id,
        response.action.as_str()
    );
    Ok(())
}

pub(crate) fn firecracker_lifecycle_smoke_command() -> Result<()> {
    let mut transport =
        InMemoryAgentWorkerManagementTransport::new(AgentWorkerManagementVerifier::new(vec![
            AgentWorkerManagementKey {
                key_id: "agent-worker-smoke-key".to_string(),
                shared_secret: SMOKE_SHARED_SECRET.to_string(),
            },
        ])?);
    let mut state = InMemoryAgentWorkerStateStore::new();
    let runtime = AgentWorkerRuntime::default();
    let now = 1_000;
    let provision = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        lifecycle_smoke_envelope(AgentWorkerManagementAction::Provision, "provision")?,
        now,
    );
    let status = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        lifecycle_smoke_envelope(AgentWorkerManagementAction::StreamStatus, "status")?,
        now,
    );
    let artifacts = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        lifecycle_smoke_envelope(AgentWorkerManagementAction::CollectArtifacts, "artifacts")?,
        now,
    );
    let exec = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        lifecycle_smoke_envelope(AgentWorkerManagementAction::ExecOrAttach, "exec")?,
        now,
    );
    let snapshot = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        lifecycle_smoke_envelope(
            AgentWorkerManagementAction::SnapshotOrCheckpoint,
            "snapshot",
        )?,
        now,
    );
    let stop = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        lifecycle_smoke_envelope(AgentWorkerManagementAction::Stop, "stop")?,
        now,
    );
    let status_after_stop = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        lifecycle_smoke_envelope(
            AgentWorkerManagementAction::StreamStatus,
            "status-after-stop",
        )?,
        now,
    );
    let cleanup = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        lifecycle_smoke_envelope(AgentWorkerManagementAction::Cleanup, "cleanup")?,
        now,
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "process": "agent-worker",
            "smoke": "firecracker_lifecycle",
            "provision": provision,
            "status": status,
            "artifacts": artifacts,
            "exec": exec,
            "snapshot": snapshot,
            "stop": stop,
            "status_after_stop": status_after_stop,
            "cleanup": cleanup,
        }))?
    );
    Ok(())
}

pub(crate) fn accept_management_json_command(
    key_id: &str,
    shared_secret: &str,
    now_unix_millis: Option<u64>,
) -> Result<()> {
    let mut input = String::new();
    read_management_stream(&mut io::stdin(), &mut input)?;
    let response = accept_management_json(
        &input,
        key_id,
        shared_secret,
        now_unix_millis.unwrap_or_else(current_unix_millis),
    )?;
    println!("{response}");
    Ok(())
}

pub(crate) fn serve_management_unix_command(
    socket_path: &Path,
    key_id: &str,
    shared_secret: &str,
    now_unix_millis: Option<u64>,
    max_requests: usize,
    idle_timeout_millis: Option<u64>,
) -> Result<()> {
    let responses = serve_management_unix(
        socket_path,
        key_id,
        shared_secret,
        now_unix_millis,
        max_requests,
        idle_timeout_millis,
    )?;
    if let Some(response) = responses.last() {
        println!(
            "agent-worker unix management served requests={} last_request_id={} last_accepted={}",
            responses.len(),
            response.request_id,
            response.accepted
        );
    } else {
        println!("agent-worker unix management served requests=0 idle_timeout=true");
    }
    Ok(())
}

pub(crate) fn serve_management_http_command(
    listen: SocketAddr,
    key_id: &str,
    shared_secret: &str,
    now_unix_millis: Option<u64>,
    max_requests: usize,
    idle_timeout_millis: Option<u64>,
    external_action_authorizer_http_endpoint: Option<SocketAddr>,
) -> Result<()> {
    let responses = serve_management_http(
        listen,
        key_id,
        shared_secret,
        now_unix_millis,
        max_requests,
        idle_timeout_millis,
        external_action_authorizer_http_endpoint,
    )?;
    if let Some(response) = responses.last() {
        println!(
            "agent-worker http management served requests={} last_request_id={} last_accepted={}",
            responses.len(),
            response.request_id,
            response.accepted
        );
    } else {
        println!("agent-worker http management served requests=0 idle_timeout=true");
    }
    Ok(())
}

fn serve_management_http(
    listen: SocketAddr,
    key_id: &str,
    shared_secret: &str,
    now_unix_millis: Option<u64>,
    max_requests: usize,
    idle_timeout_millis: Option<u64>,
    external_action_authorizer_http_endpoint: Option<SocketAddr>,
) -> Result<Vec<ferrogate_runtime::AgentWorkerManagementResponse>> {
    if max_requests == 0 {
        anyhow::bail!("max_requests must be greater than zero");
    }
    let listener = TcpListener::bind(listen)?;
    serve_management_http_listener(
        listener,
        key_id,
        shared_secret,
        now_unix_millis,
        max_requests,
        idle_timeout_millis,
        external_action_authorizer_http_endpoint,
    )
}

fn serve_management_http_listener(
    listener: TcpListener,
    key_id: &str,
    shared_secret: &str,
    now_unix_millis: Option<u64>,
    max_requests: usize,
    idle_timeout_millis: Option<u64>,
    external_action_authorizer_http_endpoint: Option<SocketAddr>,
) -> Result<Vec<ferrogate_runtime::AgentWorkerManagementResponse>> {
    if max_requests == 0 {
        anyhow::bail!("max_requests must be greater than zero");
    }
    let transport = Arc::new(Mutex::new(InMemoryAgentWorkerManagementTransport::new(
        AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: key_id.to_string(),
            shared_secret: shared_secret.to_string(),
        }])?,
    )));
    let state = Arc::new(Mutex::new(InMemoryAgentWorkerStateStore::new()));
    let runtime = Arc::new(match external_action_authorizer_http_endpoint {
        Some(endpoint) => AgentWorkerRuntime::with_http_external_action_authorizer(endpoint),
        None => AgentWorkerRuntime::default(),
    });
    let now_unix_millis = now_unix_millis.unwrap_or_else(current_unix_millis);
    let mut handles = Vec::with_capacity(max_requests);
    let idle_timeout = idle_timeout_millis.map(Duration::from_millis);
    if let Some(timeout) = idle_timeout {
        if timeout.is_zero() {
            anyhow::bail!("idle_timeout_millis must be greater than zero");
        }
        listener.set_nonblocking(true)?;
    }
    let mut idle_started = Instant::now();
    while handles.len() < max_requests {
        match listener.accept() {
            Ok((stream, _)) => {
                let transport = Arc::clone(&transport);
                let state = Arc::clone(&state);
                let runtime = Arc::clone(&runtime);
                let shared_secret = shared_secret.to_string();
                handles.push(thread::spawn(move || {
                    handle_management_http_stream(
                        stream,
                        transport,
                        state,
                        runtime,
                        &shared_secret,
                        now_unix_millis,
                    )
                }));
                idle_started = Instant::now();
            }
            Err(error) if idle_timeout.is_some() && is_idle_accept_error(&error) => {
                let timeout = idle_timeout.expect("guarded by idle_timeout.is_some()");
                if idle_started.elapsed() >= timeout {
                    break;
                }
                std::thread::sleep(
                    timeout
                        .saturating_sub(idle_started.elapsed())
                        .min(Duration::from_millis(10)),
                );
            }
            Err(error) => return Err(error.into()),
        }
    }
    let mut responses = Vec::with_capacity(handles.len());
    for handle in handles {
        responses.push(
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("agent-worker HTTP management thread panicked"))??,
        );
    }
    Ok(responses)
}

fn handle_management_http_stream(
    mut stream: TcpStream,
    transport: Arc<Mutex<InMemoryAgentWorkerManagementTransport>>,
    state: Arc<Mutex<InMemoryAgentWorkerStateStore>>,
    runtime: Arc<AgentWorkerRuntime>,
    shared_secret: &str,
    now_unix_millis: u64,
) -> Result<ferrogate_runtime::AgentWorkerManagementResponse> {
    stream.set_nonblocking(false)?;
    let request = read_http_management_request(&mut stream)?;
    let response = match request {
        Ok(body) => {
            let envelope = decode_management_input(&body, shared_secret)?;
            let response = {
                let mut transport = transport.lock().map_err(|_| {
                    anyhow::anyhow!("agent-worker HTTP management transport lock poisoned")
                })?;
                transport.accept_management_request(envelope.clone(), now_unix_millis)
            };
            let mut state = state
                .lock()
                .map_err(|_| anyhow::anyhow!("agent-worker HTTP management state lock poisoned"))?;
            accept_verified_management_response(&mut *state, &runtime, envelope, response)
        }
        Err(response) => response,
    };
    write_http_json_response(&mut stream, &response)?;
    Ok(response)
}

fn read_http_management_request(
    stream: &mut TcpStream,
) -> Result<Result<String, AgentWorkerManagementResponse>> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end;
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Ok(Err(http_invalid_request_response(
                "agent-worker HTTP management request closed before headers",
            )));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > AGENT_WORKER_MANAGEMENT_MAX_MESSAGE_BYTES {
            return Ok(Err(http_invalid_request_response(
                "agent-worker HTTP management request exceeds maximum message size",
            )));
        }
        if let Some(position) = find_http_header_end(&buffer) {
            header_end = position;
            break;
        }
    }

    let headers = String::from_utf8(buffer[..header_end].to_vec()).map_err(|_| {
        anyhow::anyhow!("agent-worker HTTP management request headers are not valid UTF-8")
    })?;
    let mut lines = headers.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    if request_line != "POST /v1/agent-worker/management HTTP/1.1" {
        return Ok(Err(http_invalid_request_response(
            "agent-worker HTTP management endpoint requires POST /v1/agent-worker/management",
        )));
    }
    let headers = parse_http_headers(lines);
    let content_type = headers
        .get("content-type")
        .map(String::as_str)
        .unwrap_or_default();
    if !content_type.starts_with("application/json") {
        return Ok(Err(http_invalid_request_response(
            "agent-worker HTTP management endpoint requires application/json",
        )));
    }
    let transport_security = headers
        .get("x-ferrogate-transport-security")
        .map(String::as_str)
        .unwrap_or_default();
    if !matches!(transport_security, "mutual_tls" | "symmetric_aead") {
        return Ok(Err(http_invalid_request_response(
            "agent-worker HTTP management requires x-ferrogate-transport-security=mutual_tls or symmetric_aead",
        )));
    }
    let Some(content_length) = headers.get("content-length") else {
        return Ok(Err(http_invalid_request_response(
            "agent-worker HTTP management request missing content-length",
        )));
    };
    let content_length = match content_length.parse::<usize>() {
        Ok(value) if value <= AGENT_WORKER_MANAGEMENT_MAX_MESSAGE_BYTES => value,
        _ => {
            return Ok(Err(http_invalid_request_response(
                "agent-worker HTTP management content-length is invalid or too large",
            )));
        }
    };
    let body_start = header_end + 4;
    let mut body = buffer[body_start..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Ok(Err(http_invalid_request_response(
                "agent-worker HTTP management request closed before body",
            )));
        }
        body.extend_from_slice(&chunk[..read]);
        if body.len() > AGENT_WORKER_MANAGEMENT_MAX_MESSAGE_BYTES {
            return Ok(Err(http_invalid_request_response(
                "agent-worker HTTP management body exceeds maximum message size",
            )));
        }
    }
    body.truncate(content_length);
    let body = String::from_utf8(body)
        .map_err(|_| anyhow::anyhow!("agent-worker HTTP management body is not valid UTF-8"))?;
    Ok(Ok(body))
}

fn find_http_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_http_headers<'a>(lines: impl Iterator<Item = &'a str>) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    headers
}

fn write_http_json_response(
    stream: &mut TcpStream,
    response: &AgentWorkerManagementResponse,
) -> Result<()> {
    let status = if response.accepted {
        "200 OK"
    } else {
        "400 Bad Request"
    };
    let body = serde_json::to_string(response)?;
    write!(
        stream,
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )?;
    Ok(())
}

fn http_invalid_request_response(message: impl Into<String>) -> AgentWorkerManagementResponse {
    let envelope = AgentWorkerManagementEnvelope {
        protocol_version: AGENT_WORKER_PROTOCOL_VERSION,
        action: AgentWorkerManagementAction::ProbeHandlers,
        request_id: "invalid-http-management-request".to_string(),
        idempotency_key: "invalid-http-management-request".to_string(),
        issued_at_unix_millis: 0,
        deadline_unix_millis: 1,
        tenant_id: "unknown".to_string(),
        workspace_id: "unknown".to_string(),
        worker_id: "unknown".to_string(),
        session_id: None,
        run_id: None,
        framework_adapter: None,
        security: AgentWorkerManagementSecurity {
            key_id: "unknown".to_string(),
            nonce: "unknown".to_string(),
            signature: "unknown".to_string(),
            algorithm: AgentWorkerSecurityAlgorithm::SharedSecretBlake2b,
            transport_security: AgentWorkerTransportSecurity::MutualTls,
            encrypted: true,
        },
    };
    AgentWorkerManagementResponse::rejected(
        &envelope,
        &ManagedWorkerError::management_protocol_error(
            AgentWorkerManagementErrorCode::InvalidRequest,
            message,
        ),
    )
}

fn serve_management_unix(
    socket_path: &Path,
    key_id: &str,
    shared_secret: &str,
    now_unix_millis: Option<u64>,
    max_requests: usize,
    idle_timeout_millis: Option<u64>,
) -> Result<Vec<ferrogate_runtime::AgentWorkerManagementResponse>> {
    if max_requests == 0 {
        anyhow::bail!("max_requests must be greater than zero");
    }
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    let transport = Arc::new(Mutex::new(InMemoryAgentWorkerManagementTransport::new(
        AgentWorkerManagementVerifier::new(vec![AgentWorkerManagementKey {
            key_id: key_id.to_string(),
            shared_secret: shared_secret.to_string(),
        }])?,
    )));
    let state = Arc::new(Mutex::new(InMemoryAgentWorkerStateStore::new()));
    let now_unix_millis = now_unix_millis.unwrap_or_else(current_unix_millis);
    let mut handles = Vec::with_capacity(max_requests);
    let idle_timeout = idle_timeout_millis.map(Duration::from_millis);
    if let Some(timeout) = idle_timeout {
        if timeout.is_zero() {
            anyhow::bail!("idle_timeout_millis must be greater than zero");
        }
        listener.set_nonblocking(true)?;
    }
    let mut idle_started = Instant::now();
    while handles.len() < max_requests {
        match listener.accept() {
            Ok((stream, _)) => {
                let transport = Arc::clone(&transport);
                let state = Arc::clone(&state);
                let shared_secret = shared_secret.to_string();
                handles.push(thread::spawn(move || {
                    handle_management_unix_stream(
                        stream,
                        transport,
                        state,
                        &shared_secret,
                        now_unix_millis,
                    )
                }));
                idle_started = Instant::now();
            }
            Err(error) if idle_timeout.is_some() && is_idle_accept_error(&error) => {
                let timeout = idle_timeout.expect("guarded by idle_timeout.is_some()");
                if idle_started.elapsed() >= timeout {
                    break;
                }
                std::thread::sleep(
                    timeout
                        .saturating_sub(idle_started.elapsed())
                        .min(Duration::from_millis(10)),
                );
            }
            Err(error) => return Err(error.into()),
        }
    }
    let _ = std::fs::remove_file(socket_path);
    let mut responses = Vec::with_capacity(handles.len());
    for handle in handles {
        responses.push(
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("agent-worker Unix management thread panicked"))??,
        );
    }
    Ok(responses)
}

fn is_idle_accept_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

fn handle_management_unix_stream(
    mut stream: std::os::unix::net::UnixStream,
    transport: Arc<Mutex<InMemoryAgentWorkerManagementTransport>>,
    state: Arc<Mutex<InMemoryAgentWorkerStateStore>>,
    shared_secret: &str,
    now_unix_millis: u64,
) -> Result<ferrogate_runtime::AgentWorkerManagementResponse> {
    stream.set_nonblocking(false)?;
    let mut input = String::new();
    read_management_stream(&mut stream, &mut input)?;
    let envelope = decode_management_input(&input, shared_secret)?;
    let response = {
        let mut transport = transport
            .lock()
            .map_err(|_| anyhow::anyhow!("agent-worker management transport lock poisoned"))?;
        transport.accept_management_request(envelope.clone(), now_unix_millis)
    };
    let mut state = state
        .lock()
        .map_err(|_| anyhow::anyhow!("agent-worker management state lock poisoned"))?;
    let runtime = AgentWorkerRuntime::default();
    let response = accept_verified_management_response(&mut *state, &runtime, envelope, response);
    let response_json = serde_json::to_string(&response)?;
    stream.write_all(response_json.as_bytes())?;
    stream.write_all(b"\n")?;
    Ok(response)
}

fn accept_management_json(
    input: &str,
    key_id: &str,
    shared_secret: &str,
    now_unix_millis: u64,
) -> Result<String> {
    if input.len() > AGENT_WORKER_MANAGEMENT_MAX_MESSAGE_BYTES {
        anyhow::bail!("agent-worker management request exceeds maximum message size");
    }
    let envelope = decode_management_input(input, shared_secret)?;
    let mut transport =
        InMemoryAgentWorkerManagementTransport::new(AgentWorkerManagementVerifier::new(vec![
            AgentWorkerManagementKey {
                key_id: key_id.to_string(),
                shared_secret: shared_secret.to_string(),
            },
        ])?);
    let mut state = InMemoryAgentWorkerStateStore::new();
    let runtime = AgentWorkerRuntime::default();
    let response = accept_management_envelope(
        &mut transport,
        &mut state,
        &runtime,
        envelope,
        now_unix_millis,
    );
    Ok(serde_json::to_string(&response)?)
}

fn decode_management_input(
    input: &str,
    shared_secret: &str,
) -> Result<AgentWorkerManagementEnvelope> {
    if let Ok(envelope) = serde_json::from_str::<AgentWorkerManagementEnvelope>(input) {
        return Ok(envelope);
    }
    let frame: AgentWorkerManagementFrame = serde_json::from_str(input)?;
    frame.decode_envelope(shared_secret).map_err(Into::into)
}

fn read_management_stream<R: Read>(reader: &mut R, output: &mut String) -> Result<()> {
    let mut limited = reader.take((AGENT_WORKER_MANAGEMENT_MAX_MESSAGE_BYTES + 1) as u64);
    limited.read_to_string(output)?;
    if output.len() > AGENT_WORKER_MANAGEMENT_MAX_MESSAGE_BYTES {
        anyhow::bail!("agent-worker management request exceeds maximum message size");
    }
    Ok(())
}

fn accept_management_envelope(
    transport: &mut InMemoryAgentWorkerManagementTransport,
    state: &mut impl AgentWorkerStateStore,
    runtime: &AgentWorkerRuntime,
    envelope: AgentWorkerManagementEnvelope,
    now_unix_millis: u64,
) -> AgentWorkerManagementResponse {
    let response = transport.accept_management_request(envelope.clone(), now_unix_millis);
    accept_verified_management_response(state, runtime, envelope, response)
}

fn accept_verified_management_response(
    state: &mut impl AgentWorkerStateStore,
    runtime: &AgentWorkerRuntime,
    envelope: AgentWorkerManagementEnvelope,
    response: AgentWorkerManagementResponse,
) -> AgentWorkerManagementResponse {
    if !response.accepted {
        return response;
    }
    if response.duplicate_idempotency_key {
        if let Some(replayed) = state.replay_idempotent_response(&envelope, &response) {
            return replayed;
        }
    }
    match dispatch_management_action(state, runtime, envelope.clone()) {
        Ok(Some(result)) => state
            .record_management_response(&envelope, response.with_result(result))
            .map(|outcome| outcome.into_response())
            .unwrap_or_else(|error| AgentWorkerManagementResponse::rejected(&envelope, &error)),
        Ok(None) => state
            .record_management_response(&envelope, response)
            .map(|outcome| outcome.into_response())
            .unwrap_or_else(|error| AgentWorkerManagementResponse::rejected(&envelope, &error)),
        Err(error) => {
            let rejected = AgentWorkerManagementResponse::rejected(&envelope, &error);
            state
                .record_management_response(&envelope, rejected)
                .map(|outcome| outcome.into_response())
                .unwrap_or_else(|error| AgentWorkerManagementResponse::rejected(&envelope, &error))
        }
    }
}

fn dispatch_management_action(
    state: &mut impl AgentWorkerStateStore,
    runtime: &AgentWorkerRuntime,
    envelope: AgentWorkerManagementEnvelope,
) -> Result<Option<AgentWorkerManagementResult>, ManagedWorkerError> {
    match envelope.action {
        AgentWorkerManagementAction::ProbeHandlers => {
            let handlers = framework_handlers();
            if handlers.iter().any(|handler| handler.ready) {
                Ok(Some(AgentWorkerManagementResult::FrameworkHandlers {
                    handlers,
                }))
            } else {
                Err(ManagedWorkerError::management_protocol_error(
                    AgentWorkerManagementErrorCode::HandlerUnavailable,
                    "agent-worker reported no ready framework handlers",
                ))
            }
        }
        AgentWorkerManagementAction::ListBackends => {
            Ok(Some(AgentWorkerManagementResult::IsolationBackends {
                registry_implemented: true,
                backends: isolation_backends(),
            }))
        }
        AgentWorkerManagementAction::Provision
        | AgentWorkerManagementAction::ExecOrAttach
        | AgentWorkerManagementAction::Stop
        | AgentWorkerManagementAction::SnapshotOrCheckpoint
        | AgentWorkerManagementAction::Cleanup
        | AgentWorkerManagementAction::StreamStatus
        | AgentWorkerManagementAction::CollectArtifacts => {
            dispatch_lifecycle_action(state, &envelope, runtime.external_action_authorizer())
        }
    }
}

fn current_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn smoke_envelope() -> Result<AgentWorkerManagementEnvelope> {
    let mut envelope = AgentWorkerManagementEnvelope {
        protocol_version: AGENT_WORKER_PROTOCOL_VERSION,
        action: AgentWorkerManagementAction::ProbeHandlers,
        request_id: "agent-worker-smoke-request".to_string(),
        idempotency_key: "agent-worker-smoke-idempotency".to_string(),
        issued_at_unix_millis: 900,
        deadline_unix_millis: 2_000,
        tenant_id: "smoke-tenant".to_string(),
        workspace_id: "smoke-workspace".to_string(),
        worker_id: "agent-worker-smoke".to_string(),
        session_id: None,
        run_id: None,
        framework_adapter: None,
        security: AgentWorkerManagementSecurity {
            key_id: "agent-worker-smoke-key".to_string(),
            nonce: "agent-worker-smoke-nonce".to_string(),
            signature: String::new(),
            algorithm: AgentWorkerSecurityAlgorithm::SharedSecretBlake2b,
            transport_security: AgentWorkerTransportSecurity::LocalUnixSocket,
            encrypted: true,
        },
    };
    envelope.security.signature = envelope.shared_secret_signature(SMOKE_SHARED_SECRET)?;
    Ok(envelope)
}

fn lifecycle_smoke_envelope(
    action: AgentWorkerManagementAction,
    suffix: &str,
) -> Result<AgentWorkerManagementEnvelope> {
    let mut envelope = smoke_envelope()?;
    envelope.action = action;
    envelope.request_id = format!("agent-worker-firecracker-lifecycle-{suffix}-request");
    envelope.idempotency_key = format!("agent-worker-firecracker-lifecycle-{suffix}-idempotency");
    envelope.session_id = Some("agent-worker-firecracker-lifecycle-session".to_string());
    envelope.run_id = Some("agent-worker-firecracker-lifecycle-run".to_string());
    envelope.framework_adapter = Some("native-harness".to_string());
    envelope.security.nonce = format!("agent-worker-firecracker-lifecycle-{suffix}-nonce");
    envelope.security.signature = envelope.shared_secret_signature(SMOKE_SHARED_SECRET)?;
    Ok(envelope)
}

#[cfg(test)]
#[path = "management_test.rs"]
mod tests;
