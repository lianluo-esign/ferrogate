// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Handler-facing external action gate.
//!
//! Framework handlers in the standalone `agent-worker` process call this gate
//! before touching tools, MCP, CLI, REST, filesystem, browser automation,
//! secrets, memory, or network egress. The worker may prepare typed action
//! requests, but the authorization decision must come from the gateway-mediated
//! capability boundary.

use std::{
    collections::BTreeMap,
    collections::BTreeSet,
    io::{self, Read, Write},
    net::TcpListener,
    net::{Shutdown, SocketAddr, TcpStream},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use ferrogate_runtime::{
    authorize_managed_external_action, managed_external_action_transport_failure_event,
    CapabilityAction, CapabilityAuthorizationDecision, CapabilityAuthorizer, CapabilityPolicy,
    ExternalActionAuthorizationRequest, ExternalActionAuthorizationResponse, FrameworkAdapterError,
    FrameworkAdapterEventKind, FrameworkAdapterMode, FrameworkAdapterSession,
    GatewayExternalActionTransportRequest, GatewayExternalActionTransportResponse,
    ManagedCliAction, ManagedExternalAction, ManagedExternalActionDecision,
    ManagedExternalActionRequest, ManagedFilesystemAccess, ManagedFilesystemAction,
    ManagedRestAction, ManagedToolAction, NormalizedFrameworkEvent, SimpleCapabilityAuthorizer,
    SupportedFramework,
};

const EXTERNAL_ACTION_MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const DEFAULT_EXTERNAL_ACTION_HTTP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalActionGateRequest {
    pub(crate) session: FrameworkAdapterSession,
    pub(crate) action: ManagedExternalAction,
    pub(crate) high_risk: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalActionGateDecision {
    pub(crate) decision: CapabilityAuthorizationDecision,
    pub(crate) event: NormalizedFrameworkEvent,
}

impl ExternalActionGateDecision {
    pub(crate) fn allowed(&self) -> bool {
        self.decision == CapabilityAuthorizationDecision::Allowed
    }
}

pub(crate) trait GatewayExternalActionAuthorizer {
    fn authorize_external_action(
        &self,
        request: ManagedExternalActionRequest,
    ) -> Result<ExternalActionGateDecision, FrameworkAdapterError>;
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeGatewayExternalActionAuthorizer<A> {
    authorizer: A,
}

impl<A> RuntimeGatewayExternalActionAuthorizer<A> {
    pub(crate) fn new(authorizer: A) -> Self {
        Self { authorizer }
    }
}

impl<A> GatewayExternalActionAuthorizer for RuntimeGatewayExternalActionAuthorizer<A>
where
    A: CapabilityAuthorizer,
{
    fn authorize_external_action(
        &self,
        request: ManagedExternalActionRequest,
    ) -> Result<ExternalActionGateDecision, FrameworkAdapterError> {
        let (evidence, event) = authorize_managed_external_action(&self.authorizer, request)?;
        Ok(ExternalActionGateDecision {
            decision: evidence.decision,
            event,
        })
    }
}

pub(crate) fn authorize_handler_external_action<A>(
    authorizer: Option<&A>,
    request: ExternalActionGateRequest,
) -> Result<ExternalActionGateDecision, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    let decision = request_handler_external_action_decision(authorizer, request)?;
    if decision.allowed() {
        Ok(decision)
    } else {
        Err(FrameworkAdapterError::CapabilityDenied(format!(
            "managed external action denied before handler execution: {}",
            decision
                .event
                .message
                .as_deref()
                .unwrap_or("gateway authorization was not allowed")
        )))
    }
}

pub(crate) fn request_handler_external_action_decision<A>(
    authorizer: Option<&A>,
    request: ExternalActionGateRequest,
) -> Result<ExternalActionGateDecision, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    validate_managed_worker_session(&request.session)?;
    let Some(authorizer) = authorizer else {
        return Err(FrameworkAdapterError::CapabilityDenied(
            "managed external action denied: gateway authorization client is unavailable"
                .to_string(),
        ));
    };
    authorizer.authorize_external_action(ManagedExternalActionRequest {
        session: request.session,
        action: request.action,
        high_risk: request.high_risk,
    })
}

pub(crate) fn external_action_smoke_command() -> Result<()> {
    let decision = external_action_smoke()?;
    println!("{}", decision.event.canonical_json());
    Ok(())
}

pub(crate) fn accept_external_action_json_command() -> Result<()> {
    let mut input = String::new();
    read_external_action_stream(&mut io::stdin(), &mut input)?;
    let response = accept_external_action_json(
        &input,
        &RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                ..CapabilityPolicy::default()
            },
        )),
    )?;
    println!("{}", serde_json::to_string(&response)?);
    Ok(())
}

pub(crate) fn external_action_unix_transport_smoke_command() -> Result<()> {
    let socket_path = std::env::temp_dir().join(format!(
        "ferrogate-agent-worker-external-action-{}-{}.sock",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    ));
    let server_socket_path = socket_path.clone();
    let server = thread::spawn(move || {
        serve_gateway_authorizer_unix(
            &server_socket_path,
            RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
                CapabilityPolicy {
                    allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                    ..CapabilityPolicy::default()
                },
            )),
            1,
        )
    });
    wait_for_authorizer_socket(&socket_path)?;
    let client = UnixGatewayExternalActionAuthorizer::new(&socket_path);
    let decision = authorize_handler_external_action(
        Some(&client),
        ExternalActionGateRequest {
            session: smoke_session(),
            action: ManagedExternalAction::Tool(ManagedToolAction {
                tool_name: "native.echo".to_string(),
                arguments_policy: "redacted_json".to_string(),
            }),
            high_risk: false,
        },
    )?;
    let _ = server
        .join()
        .map_err(|_| anyhow::anyhow!("gateway authorizer Unix smoke thread panicked"))??;
    println!("{}", decision.event.canonical_json());
    Ok(())
}

pub(crate) fn external_action_http_transport_smoke_command(endpoint: SocketAddr) -> Result<()> {
    let client = HttpGatewayExternalActionAuthorizer::new(endpoint);
    let decision = authorize_handler_external_action(
        Some(&client),
        ExternalActionGateRequest {
            session: smoke_session(),
            action: ManagedExternalAction::Tool(ManagedToolAction {
                tool_name: "native.echo".to_string(),
                arguments_policy: "redacted_json".to_string(),
            }),
            high_risk: false,
        },
    )?;
    println!("{}", decision.event.canonical_json());
    Ok(())
}

pub(crate) fn governed_cli_execution_smoke_command() -> Result<()> {
    let action = ManagedCliAction {
        command: "/bin/sh".to_string(),
        args: vec![
            "-c".to_string(),
            "printf 'ferrogate governed cli smoke\\n'".to_string(),
        ],
        working_dir: std::env::current_dir()?.display().to_string(),
        env_policy: "deny_all".to_string(),
        timeout_millis: 2_000,
        stdout_limit_bytes: 4096,
        stderr_limit_bytes: 4096,
        artifact_capture: false,
    };
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Cli]),
            ..CapabilityPolicy::default()
        },
    ));
    let events = execute_governed_cli_action(&gate, smoke_session(), action, false)?;
    println!(
        "{}",
        serde_json::to_string(
            &events
                .into_iter()
                .map(|event| event.canonical_json())
                .collect::<Vec<_>>()
        )?
    );
    Ok(())
}

pub(crate) fn governed_rest_execution_smoke_command() -> Result<()> {
    let server = spawn_one_shot_rest_smoke_server();
    let action = ManagedRestAction {
        method: "GET".to_string(),
        url: format!("http://{}/governed-rest-smoke", server.endpoint),
        headers_policy: "deny_credentials".to_string(),
        body_policy: "empty_body".to_string(),
        timeout_millis: 2_000,
        retry_limit: 0,
    };
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Rest]),
            ..CapabilityPolicy::default()
        },
    ));
    let events = execute_governed_rest_action(&gate, smoke_session(), action, false)?;
    let served_request = server.join()?;
    let output = serde_json::json!({
        "events": events
            .into_iter()
            .map(|event| event.canonical_json())
            .collect::<Vec<_>>(),
        "served_request": served_request,
    });
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

pub(crate) fn governed_filesystem_execution_smoke_command() -> Result<()> {
    let workspace = std::env::temp_dir().join(format!(
        "ferrogate-agent-worker-filesystem-smoke-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    std::fs::create_dir(&workspace)?;
    let result = (|| -> Result<()> {
        let file_path = workspace.join("governed-filesystem-smoke.txt");
        std::fs::write(&file_path, "ferrogate governed filesystem smoke\n")?;
        let action = ManagedFilesystemAction {
            path: "governed-filesystem-smoke.txt".to_string(),
            access: ManagedFilesystemAccess::Read,
            workspace_relative: true,
        };
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Filesystem]),
                ..CapabilityPolicy::default()
            },
        ));
        let events =
            execute_governed_filesystem_action(&gate, smoke_session(), action, &workspace, false)?;
        println!(
            "{}",
            serde_json::to_string(
                &events
                    .into_iter()
                    .map(|event| event.canonical_json())
                    .collect::<Vec<_>>()
            )?
        );
        Ok(())
    })();
    let cleanup = std::fs::remove_dir_all(&workspace);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(error)) => Err(error.into()),
        (Err(error), _) => Err(error),
    }
}

pub(crate) fn serve_gateway_authorizer_unix(
    socket_path: &Path,
    authorizer: impl GatewayExternalActionAuthorizer + Send + Sync + 'static,
    max_requests: usize,
) -> Result<Vec<GatewayExternalActionTransportResponse>> {
    if max_requests == 0 {
        anyhow::bail!("max_requests must be greater than zero");
    }
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    let authorizer = Arc::new(authorizer);
    let mut handles = Vec::with_capacity(max_requests);
    while handles.len() < max_requests {
        let (stream, _) = listener.accept()?;
        let authorizer = Arc::clone(&authorizer);
        handles.push(thread::spawn(move || {
            handle_gateway_authorizer_stream(stream, authorizer)
        }));
    }
    let _ = std::fs::remove_file(socket_path);
    let mut responses = Vec::with_capacity(handles.len());
    for handle in handles {
        responses.push(
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("gateway authorizer Unix thread panicked"))??,
        );
    }
    Ok(responses)
}

fn wait_for_authorizer_socket(socket_path: &Path) -> Result<()> {
    for _ in 0..100 {
        if socket_path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(5));
    }
    anyhow::bail!(
        "timed out waiting for gateway authorizer socket {}",
        socket_path.display()
    );
}

fn handle_gateway_authorizer_stream<A>(
    mut stream: UnixStream,
    authorizer: Arc<A>,
) -> Result<GatewayExternalActionTransportResponse>
where
    A: GatewayExternalActionAuthorizer,
{
    let mut input = String::new();
    read_external_action_stream(&mut stream, &mut input)?;
    let request: GatewayExternalActionTransportRequest = serde_json::from_str(&input)?;
    let response = accept_external_action_authorization_request(request, authorizer.as_ref());
    stream.write_all(serde_json::to_string(&response)?.as_bytes())?;
    stream.write_all(b"\n")?;
    Ok(response)
}

pub(crate) struct UnixGatewayExternalActionAuthorizer {
    socket_path: std::path::PathBuf,
}

impl UnixGatewayExternalActionAuthorizer {
    pub(crate) fn new(socket_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }
}

impl GatewayExternalActionAuthorizer for UnixGatewayExternalActionAuthorizer {
    fn authorize_external_action(
        &self,
        request: ManagedExternalActionRequest,
    ) -> Result<ExternalActionGateDecision, FrameworkAdapterError> {
        let authorization =
            ExternalActionAuthorizationRequest::from_managed_request(request.clone());
        let transport_request = GatewayExternalActionTransportRequest {
            request_id: authorization.stable_request_id(),
            authorization,
        };
        let mut stream = match UnixStream::connect(&self.socket_path) {
            Ok(stream) => stream,
            Err(error) => {
                return transport_failure_decision(
                    &request,
                    format!("gateway external action authorizer transport unavailable: {error}"),
                );
            }
        };
        let payload = serde_json::to_string(&transport_request).map_err(|error| {
            FrameworkAdapterError::InvalidRequest(format!(
                "gateway external action authorization request serialization failed: {error}"
            ))
        })?;
        if payload.len() > EXTERNAL_ACTION_MAX_MESSAGE_BYTES {
            return Err(FrameworkAdapterError::InvalidRequest(
                "gateway external action authorization request exceeds maximum message size"
                    .to_string(),
            ));
        }
        if let Err(error) = stream.write_all(payload.as_bytes()) {
            return transport_failure_decision(
                &request,
                format!("gateway external action authorizer write failed: {error}"),
            );
        }
        if let Err(error) = stream.shutdown(std::net::Shutdown::Write) {
            return transport_failure_decision(
                &request,
                format!("gateway external action authorizer request shutdown failed: {error}"),
            );
        }
        let mut response_json = String::new();
        if let Err(error) = read_external_action_stream(&mut stream, &mut response_json) {
            return transport_failure_decision(
                &request,
                format!("gateway external action authorizer response read failed: {error}"),
            );
        }
        let response: GatewayExternalActionTransportResponse = serde_json::from_str(&response_json)
            .map_err(|error| {
                FrameworkAdapterError::InvalidRequest(format!(
                    "gateway external action authorization response decode failed: {error}"
                ))
            })?;
        if response.request_id != transport_request.request_id {
            return Err(FrameworkAdapterError::InvalidRequest(
                "gateway external action authorization response request_id mismatch".to_string(),
            ));
        }
        response
            .response
            .into_decision()
            .map(|decision| ExternalActionGateDecision {
                decision: decision.decision,
                event: decision.event,
            })
    }
}

pub(crate) struct HttpGatewayExternalActionAuthorizer {
    endpoint: SocketAddr,
    timeout: Duration,
}

impl HttpGatewayExternalActionAuthorizer {
    pub(crate) fn new(endpoint: SocketAddr) -> Self {
        Self::new_with_timeout(endpoint, DEFAULT_EXTERNAL_ACTION_HTTP_TIMEOUT)
    }

    pub(crate) fn new_with_timeout(endpoint: SocketAddr, timeout: Duration) -> Self {
        Self { endpoint, timeout }
    }
}

impl GatewayExternalActionAuthorizer for HttpGatewayExternalActionAuthorizer {
    fn authorize_external_action(
        &self,
        request: ManagedExternalActionRequest,
    ) -> Result<ExternalActionGateDecision, FrameworkAdapterError> {
        let authorization =
            ExternalActionAuthorizationRequest::from_managed_request(request.clone());
        let transport_request = GatewayExternalActionTransportRequest {
            request_id: authorization.stable_request_id(),
            authorization,
        };
        let payload = serde_json::to_string(&transport_request).map_err(|error| {
            FrameworkAdapterError::InvalidRequest(format!(
                "gateway external action HTTP authorization request serialization failed: {error}"
            ))
        })?;
        if payload.len() > EXTERNAL_ACTION_MAX_MESSAGE_BYTES {
            return Err(FrameworkAdapterError::InvalidRequest(
                "gateway external action HTTP authorization request exceeds maximum message size"
                    .to_string(),
            ));
        }
        let mut stream = match TcpStream::connect_timeout(&self.endpoint, self.timeout) {
            Ok(stream) => stream,
            Err(error) => {
                return transport_failure_decision(
                    &request,
                    format!(
                        "gateway external action HTTP authorizer transport unavailable: {error}"
                    ),
                );
            }
        };
        if let Err(error) = stream.set_read_timeout(Some(self.timeout)) {
            return transport_failure_decision(
                &request,
                format!(
                    "gateway external action HTTP authorizer read timeout setup failed: {error}"
                ),
            );
        }
        if let Err(error) = stream.set_write_timeout(Some(self.timeout)) {
            return transport_failure_decision(
                &request,
                format!(
                    "gateway external action HTTP authorizer write timeout setup failed: {error}"
                ),
            );
        }
        let http_request = format!(
            "POST /v1/agent-worker/external-actions/authorize HTTP/1.1\r\n\
             host: {}\r\n\
             content-type: application/json\r\n\
             content-length: {}\r\n\
             connection: close\r\n\
             \r\n\
             {}",
            self.endpoint,
            payload.len(),
            payload
        );
        if let Err(error) = stream.write_all(http_request.as_bytes()) {
            return transport_failure_decision(
                &request,
                format!("gateway external action HTTP authorizer write failed: {error}"),
            );
        }
        if let Err(error) = stream.shutdown(Shutdown::Write) {
            return transport_failure_decision(
                &request,
                format!("gateway external action HTTP authorizer request shutdown failed: {error}"),
            );
        }
        let mut response = Vec::new();
        if let Err(error) = stream.read_to_end(&mut response) {
            return transport_failure_decision(
                &request,
                format!("gateway external action HTTP authorizer response read failed: {error}"),
            );
        }
        if response.len() > EXTERNAL_ACTION_MAX_MESSAGE_BYTES {
            return Err(FrameworkAdapterError::InvalidRequest(
                "gateway external action HTTP authorization response exceeds maximum message size"
                    .to_string(),
            ));
        }
        let response = match decode_http_authorizer_response(&response) {
            Ok(response) => response,
            Err(error) if matches!(error, FrameworkAdapterError::CapabilityDenied(_)) => {
                return transport_failure_decision(&request, error.to_string());
            }
            Err(error) => return Err(error),
        };
        if response.request_id != transport_request.request_id {
            return Err(FrameworkAdapterError::InvalidRequest(
                "gateway external action HTTP authorization response request_id mismatch"
                    .to_string(),
            ));
        }
        response
            .response
            .into_decision()
            .map(|decision| ExternalActionGateDecision {
                decision: decision.decision,
                event: decision.event,
            })
    }
}

fn transport_failure_decision(
    request: &ManagedExternalActionRequest,
    reason: impl Into<String>,
) -> Result<ExternalActionGateDecision, FrameworkAdapterError> {
    Ok(ExternalActionGateDecision {
        decision: CapabilityAuthorizationDecision::Denied,
        event: managed_external_action_transport_failure_event(request, reason)?,
    })
}

fn decode_http_authorizer_response(
    response: &[u8],
) -> Result<GatewayExternalActionTransportResponse, FrameworkAdapterError> {
    let response = std::str::from_utf8(response).map_err(|_| {
        FrameworkAdapterError::InvalidRequest(
            "gateway external action HTTP authorizer response is not valid UTF-8".to_string(),
        )
    })?;
    let Some(header_end) = response.find("\r\n\r\n") else {
        return Err(FrameworkAdapterError::InvalidRequest(
            "gateway external action HTTP authorizer response missing header terminator"
                .to_string(),
        ));
    };
    let (headers, body) = response.split_at(header_end);
    let status_line = headers.lines().next().unwrap_or_default();
    let status_code = parse_http_status_code(status_line)?;
    if status_code != 200 {
        return Err(FrameworkAdapterError::CapabilityDenied(format!(
            "gateway external action HTTP authorizer returned status {status_code}"
        )));
    }
    serde_json::from_str(body[4..].trim()).map_err(|error| {
        FrameworkAdapterError::InvalidRequest(format!(
            "gateway external action HTTP authorization response decode failed: {error}"
        ))
    })
}

fn parse_http_status_code(status_line: &str) -> Result<u16, FrameworkAdapterError> {
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(FrameworkAdapterError::InvalidRequest(format!(
            "gateway external action HTTP authorizer response has invalid status line: {status_line}"
        )));
    }
    parts
        .next()
        .unwrap_or_default()
        .parse::<u16>()
        .map_err(|_| {
            FrameworkAdapterError::InvalidRequest(format!(
                "gateway external action HTTP authorizer response has invalid status code: {status_line}"
            ))
        })
}

fn accept_external_action_json<A>(
    input: &str,
    authorizer: &A,
) -> Result<ExternalActionAuthorizationResponse>
where
    A: GatewayExternalActionAuthorizer,
{
    if input.len() > EXTERNAL_ACTION_MAX_MESSAGE_BYTES {
        anyhow::bail!("agent-worker external action request exceeds maximum message size");
    }
    let request: ExternalActionAuthorizationRequest = serde_json::from_str(input)?;
    Ok(accept_external_action_authorization(request, authorizer))
}

pub(crate) fn accept_external_action_authorization_request<A>(
    request: GatewayExternalActionTransportRequest,
    authorizer: &A,
) -> GatewayExternalActionTransportResponse
where
    A: GatewayExternalActionAuthorizer,
{
    GatewayExternalActionTransportResponse {
        request_id: request.request_id,
        response: accept_external_action_authorization(request.authorization, authorizer),
    }
}

fn accept_external_action_authorization<A>(
    request: ExternalActionAuthorizationRequest,
    authorizer: &A,
) -> ExternalActionAuthorizationResponse
where
    A: GatewayExternalActionAuthorizer,
{
    let managed_request = match request.into_managed_request() {
        Ok(request) => request,
        Err(error) => return ExternalActionAuthorizationResponse::rejected(error),
    };
    match request_handler_external_action_decision(
        Some(authorizer),
        ExternalActionGateRequest {
            session: managed_request.session,
            action: managed_request.action,
            high_risk: managed_request.high_risk,
        },
    ) {
        Ok(decision) => {
            ExternalActionAuthorizationResponse::from_decision(ManagedExternalActionDecision {
                decision: decision.decision,
                event: decision.event,
            })
        }
        Err(error) => ExternalActionAuthorizationResponse::rejected(error),
    }
}

fn external_action_smoke() -> Result<ExternalActionGateDecision> {
    let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
        CapabilityPolicy {
            allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
            ..CapabilityPolicy::default()
        },
    ));
    authorize_handler_external_action(
        Some(&gate),
        ExternalActionGateRequest {
            session: smoke_session(),
            action: ManagedExternalAction::Tool(ManagedToolAction {
                tool_name: "native.echo".to_string(),
                arguments_policy: "redacted_json".to_string(),
            }),
            high_risk: false,
        },
    )
    .map_err(Into::into)
}

fn execute_governed_cli_action<A>(
    authorizer: &A,
    session: FrameworkAdapterSession,
    action: ManagedCliAction,
    high_risk: bool,
) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    let decision = authorize_handler_external_action(
        Some(authorizer),
        ExternalActionGateRequest {
            session: session.clone(),
            action: ManagedExternalAction::Cli(action.clone()),
            high_risk,
        },
    )?;
    let execution = run_authorized_cli_action(&action)?;
    Ok(vec![
        decision.event,
        NormalizedFrameworkEvent {
            session_id: session.session_id,
            run_id: session.run_id,
            adapter_name: session.adapter_name,
            adapter_version: session.adapter_version,
            framework: session.framework,
            mode: session.mode,
            kind: FrameworkAdapterEventKind::CliRequested,
            message: Some("managed CLI action executed after gateway authorization".to_string()),
            metadata: execution.metadata(&action),
        },
    ])
}

fn execute_governed_rest_action<A>(
    authorizer: &A,
    session: FrameworkAdapterSession,
    action: ManagedRestAction,
    high_risk: bool,
) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    let decision = authorize_handler_external_action(
        Some(authorizer),
        ExternalActionGateRequest {
            session: session.clone(),
            action: ManagedExternalAction::Rest(action.clone()),
            high_risk,
        },
    )?;
    let execution = run_authorized_rest_action(&action)?;
    Ok(vec![
        decision.event,
        NormalizedFrameworkEvent {
            session_id: session.session_id,
            run_id: session.run_id,
            adapter_name: session.adapter_name,
            adapter_version: session.adapter_version,
            framework: session.framework,
            mode: session.mode,
            kind: FrameworkAdapterEventKind::RestRequested,
            message: Some("managed REST action executed after gateway authorization".to_string()),
            metadata: execution.metadata(&action),
        },
    ])
}

fn execute_governed_filesystem_action<A>(
    authorizer: &A,
    session: FrameworkAdapterSession,
    action: ManagedFilesystemAction,
    workspace_root: &Path,
    high_risk: bool,
) -> Result<Vec<NormalizedFrameworkEvent>, FrameworkAdapterError>
where
    A: GatewayExternalActionAuthorizer + ?Sized,
{
    let decision = authorize_handler_external_action(
        Some(authorizer),
        ExternalActionGateRequest {
            session: session.clone(),
            action: ManagedExternalAction::Filesystem(action.clone()),
            high_risk,
        },
    )?;
    let execution = run_authorized_filesystem_action(&action, workspace_root)?;
    Ok(vec![
        decision.event,
        NormalizedFrameworkEvent {
            session_id: session.session_id,
            run_id: session.run_id,
            adapter_name: session.adapter_name,
            adapter_version: session.adapter_version,
            framework: session.framework,
            mode: session.mode,
            kind: FrameworkAdapterEventKind::FilesystemRequested,
            message: Some(
                "managed filesystem action executed after gateway authorization".to_string(),
            ),
            metadata: execution.metadata(&action),
        },
    ])
}

struct GovernedFilesystemExecution {
    resolved_path: PathBuf,
    byte_len: usize,
    content_excerpt: String,
}

impl GovernedFilesystemExecution {
    fn metadata(self, action: &ManagedFilesystemAction) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("external_action".to_string(), "filesystem".to_string()),
            (
                "external_target".to_string(),
                format!("{}:{}", action.access.as_str(), action.path),
            ),
            ("path".to_string(), action.path.clone()),
            (
                "filesystem_access".to_string(),
                action.access.as_str().to_string(),
            ),
            (
                "workspace_relative".to_string(),
                action.workspace_relative.to_string(),
            ),
            (
                "resolved_path".to_string(),
                self.resolved_path.display().to_string(),
            ),
            ("byte_len".to_string(), self.byte_len.to_string()),
            ("content_excerpt".to_string(), self.content_excerpt),
            (
                "executed_after_authorization".to_string(),
                "true".to_string(),
            ),
        ])
    }
}

fn run_authorized_filesystem_action(
    action: &ManagedFilesystemAction,
    workspace_root: &Path,
) -> Result<GovernedFilesystemExecution, FrameworkAdapterError> {
    if action.access != ManagedFilesystemAccess::Read {
        return Err(FrameworkAdapterError::InvalidRequest(
            "managed filesystem smoke currently supports read access only".to_string(),
        ));
    }
    if !action.workspace_relative {
        return Err(FrameworkAdapterError::InvalidRequest(
            "managed filesystem smoke requires workspace_relative=true".to_string(),
        ));
    }
    let relative = Path::new(&action.path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(FrameworkAdapterError::InvalidRequest(
            "managed filesystem smoke path must stay inside the workspace".to_string(),
        ));
    }
    let resolved_path = workspace_root.join(relative);
    let bytes = std::fs::read(&resolved_path).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed filesystem action read failed after gateway authorization: {error}"
        ))
    })?;
    Ok(GovernedFilesystemExecution {
        resolved_path,
        byte_len: bytes.len(),
        content_excerpt: bounded_utf8_excerpt(&bytes, 512),
    })
}

struct GovernedCliExecution {
    status_code: Option<i32>,
    stdout_excerpt: String,
    stderr_excerpt: String,
}

impl GovernedCliExecution {
    fn metadata(self, action: &ManagedCliAction) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("external_action".to_string(), "cli".to_string()),
            ("external_target".to_string(), action.command.clone()),
            ("command".to_string(), action.command.clone()),
            ("args".to_string(), action.args.join("\n")),
            ("working_dir".to_string(), action.working_dir.clone()),
            ("env_policy".to_string(), action.env_policy.clone()),
            (
                "timeout_millis".to_string(),
                action.timeout_millis.to_string(),
            ),
            (
                "stdout_limit_bytes".to_string(),
                action.stdout_limit_bytes.to_string(),
            ),
            (
                "stderr_limit_bytes".to_string(),
                action.stderr_limit_bytes.to_string(),
            ),
            (
                "artifact_capture".to_string(),
                action.artifact_capture.to_string(),
            ),
            (
                "executed_after_authorization".to_string(),
                "true".to_string(),
            ),
            (
                "status_code".to_string(),
                self.status_code
                    .map(|code| code.to_string())
                    .unwrap_or_default(),
            ),
            ("stdout_excerpt".to_string(), self.stdout_excerpt),
            ("stderr_excerpt".to_string(), self.stderr_excerpt),
        ])
    }
}

fn run_authorized_cli_action(
    action: &ManagedCliAction,
) -> Result<GovernedCliExecution, FrameworkAdapterError> {
    let mut command = Command::new(&action.command);
    command
        .args(&action.args)
        .current_dir(&action.working_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if action.env_policy == "deny_all" {
        command.env_clear();
    }
    let mut child = command.spawn().map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed CLI action spawn failed after gateway authorization: {error}"
        ))
    })?;
    let started_at = Instant::now();
    let timeout = Duration::from_millis(action.timeout_millis.max(1));
    loop {
        if child
            .try_wait()
            .map_err(|error| {
                FrameworkAdapterError::CapabilityDenied(format!(
                    "managed CLI action status check failed: {error}"
                ))
            })?
            .is_some()
        {
            break;
        }
        if started_at.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(FrameworkAdapterError::CapabilityDenied(format!(
                "managed CLI action timed out after {}ms",
                timeout.as_millis()
            )));
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed CLI action output collection failed: {error}"
        ))
    })?;
    if !output.status.success() {
        return Err(FrameworkAdapterError::CapabilityDenied(format!(
            "managed CLI action exited with status {:?}",
            output.status.code()
        )));
    }
    Ok(GovernedCliExecution {
        status_code: output.status.code(),
        stdout_excerpt: bounded_utf8_excerpt(&output.stdout, action.stdout_limit_bytes),
        stderr_excerpt: bounded_utf8_excerpt(&output.stderr, action.stderr_limit_bytes),
    })
}

fn bounded_utf8_excerpt(bytes: &[u8], limit: u64) -> String {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    String::from_utf8_lossy(&bytes[..bytes.len().min(limit)]).to_string()
}

struct GovernedRestExecution {
    status_code: u16,
    response_excerpt: String,
}

impl GovernedRestExecution {
    fn metadata(self, action: &ManagedRestAction) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("external_action".to_string(), "rest".to_string()),
            (
                "external_target".to_string(),
                format!("{} {}", action.method, action.url),
            ),
            ("method".to_string(), action.method.clone()),
            ("url".to_string(), action.url.clone()),
            ("headers_policy".to_string(), action.headers_policy.clone()),
            ("body_policy".to_string(), action.body_policy.clone()),
            (
                "timeout_millis".to_string(),
                action.timeout_millis.to_string(),
            ),
            ("retry_limit".to_string(), action.retry_limit.to_string()),
            (
                "executed_after_authorization".to_string(),
                "true".to_string(),
            ),
            ("status_code".to_string(), self.status_code.to_string()),
            ("response_excerpt".to_string(), self.response_excerpt),
        ])
    }
}

fn run_authorized_rest_action(
    action: &ManagedRestAction,
) -> Result<GovernedRestExecution, FrameworkAdapterError> {
    if action.method != "GET" {
        return Err(FrameworkAdapterError::InvalidRequest(
            "managed REST smoke currently supports GET only".to_string(),
        ));
    }
    let target = parse_local_http_url(&action.url)?;
    let timeout = Duration::from_millis(action.timeout_millis.max(1));
    let mut stream = TcpStream::connect_timeout(&target.endpoint, timeout).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action transport failed after gateway authorization: {error}"
        ))
    })?;
    stream.set_read_timeout(Some(timeout)).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action read timeout setup failed: {error}"
        ))
    })?;
    stream.set_write_timeout(Some(timeout)).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action write timeout setup failed: {error}"
        ))
    })?;
    let request = format!(
        "GET {} HTTP/1.1\r\nhost: {}\r\nconnection: close\r\n\r\n",
        target.path, target.endpoint
    );
    stream.write_all(request.as_bytes()).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action request write failed: {error}"
        ))
    })?;
    stream.shutdown(Shutdown::Write).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action request shutdown failed: {error}"
        ))
    })?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).map_err(|error| {
        FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action response read failed: {error}"
        ))
    })?;
    let response = String::from_utf8_lossy(&response);
    let status_code = parse_smoke_http_status(response.lines().next().unwrap_or_default())?;
    if !(200..300).contains(&status_code) {
        return Err(FrameworkAdapterError::CapabilityDenied(format!(
            "managed REST action returned status {status_code}"
        )));
    }
    Ok(GovernedRestExecution {
        status_code,
        response_excerpt: response.chars().take(512).collect(),
    })
}

struct LocalHttpTarget {
    endpoint: SocketAddr,
    path: String,
}

fn parse_local_http_url(raw: &str) -> Result<LocalHttpTarget, FrameworkAdapterError> {
    let Some(rest) = raw.strip_prefix("http://") else {
        return Err(FrameworkAdapterError::InvalidRequest(
            "managed REST smoke only supports http:// local URLs".to_string(),
        ));
    };
    let (authority, path) = rest
        .split_once('/')
        .map(|(authority, path)| (authority, format!("/{path}")))
        .unwrap_or((rest, "/".to_string()));
    let endpoint = authority.parse::<SocketAddr>().map_err(|error| {
        FrameworkAdapterError::InvalidRequest(format!(
            "managed REST smoke URL endpoint is invalid: {error}"
        ))
    })?;
    if !endpoint.ip().is_loopback() {
        return Err(FrameworkAdapterError::InvalidRequest(
            "managed REST smoke only supports loopback endpoints".to_string(),
        ));
    }
    Ok(LocalHttpTarget { endpoint, path })
}

fn parse_smoke_http_status(status_line: &str) -> Result<u16, FrameworkAdapterError> {
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(FrameworkAdapterError::InvalidRequest(format!(
            "managed REST action response has invalid status line: {status_line}"
        )));
    }
    parts
        .next()
        .unwrap_or_default()
        .parse::<u16>()
        .map_err(|_| {
            FrameworkAdapterError::InvalidRequest(format!(
                "managed REST action response has invalid status code: {status_line}"
            ))
        })
}

struct RestSmokeServer {
    endpoint: SocketAddr,
    handle: thread::JoinHandle<Result<String>>,
}

impl RestSmokeServer {
    fn join(self) -> Result<String> {
        self.handle
            .join()
            .map_err(|_| anyhow::anyhow!("REST smoke server thread panicked"))?
    }
}

fn spawn_one_shot_rest_smoke_server() -> RestSmokeServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept()?;
        let mut buffer = [0_u8; 1024];
        let read = stream.read(&mut buffer)?;
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = "ferrogate governed rest smoke\n";
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        )?;
        Ok(request.lines().next().unwrap_or_default().to_string())
    });
    RestSmokeServer { endpoint, handle }
}

fn smoke_session() -> FrameworkAdapterSession {
    FrameworkAdapterSession {
        session_id: "agent-worker-external-action-smoke-session".to_string(),
        run_id: "agent-worker-external-action-smoke-run".to_string(),
        tenant_id: "smoke-tenant".to_string(),
        workspace_id: "smoke-workspace".to_string(),
        worker_id: "agent-worker-smoke".to_string(),
        isolation_backend: "firecracker".to_string(),
        adapter_name: "native-harness".to_string(),
        adapter_version: env!("CARGO_PKG_VERSION").to_string(),
        framework: SupportedFramework::NativeHarness,
        mode: FrameworkAdapterMode::Managed,
    }
}

fn read_external_action_stream<R: Read>(reader: &mut R, output: &mut String) -> Result<()> {
    let mut limited = reader.take((EXTERNAL_ACTION_MAX_MESSAGE_BYTES + 1) as u64);
    limited.read_to_string(output)?;
    if output.len() > EXTERNAL_ACTION_MAX_MESSAGE_BYTES {
        anyhow::bail!("agent-worker external action request exceeds maximum message size");
    }
    Ok(())
}

fn validate_managed_worker_session(
    session: &FrameworkAdapterSession,
) -> Result<(), FrameworkAdapterError> {
    require_non_empty("session_id", &session.session_id)?;
    require_non_empty("run_id", &session.run_id)?;
    require_non_empty("tenant_id", &session.tenant_id)?;
    require_non_empty("workspace_id", &session.workspace_id)?;
    require_non_empty("worker_id", &session.worker_id)?;
    require_non_empty("isolation_backend", &session.isolation_backend)?;
    require_non_empty("adapter_name", &session.adapter_name)?;
    if session.mode != FrameworkAdapterMode::Managed {
        return Err(FrameworkAdapterError::InvalidRequest(
            "handler external action gate only enforces managed worker sessions".to_string(),
        ));
    }
    Ok(())
}

fn require_non_empty(field: &str, value: &str) -> Result<(), FrameworkAdapterError> {
    if value.trim().is_empty() {
        return Err(FrameworkAdapterError::InvalidRequest(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrogate_runtime::{
        ExternalActionBrowserOperation, ExternalActionDecision, ExternalActionFilesystemAccess,
        ExternalActionFramework, ExternalActionMemoryAccess, ExternalActionMode,
        ExternalActionSession, ExternalActionSpec, ManagedCliAction, ManagedMcpToolAction,
        ManagedRestAction,
    };
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn managed_tool_action_must_pass_gateway_authorization_before_execution() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                ..CapabilityPolicy::default()
            },
        ));

        let decision = authorize_handler_external_action(
            Some(&gate),
            ExternalActionGateRequest {
                session: session(),
                action: ManagedExternalAction::Tool(ManagedToolAction {
                    tool_name: "native.echo".to_string(),
                    arguments_policy: "redacted_json".to_string(),
                }),
                high_risk: false,
            },
        )
        .unwrap();

        assert!(decision.allowed());
        assert_eq!(decision.event.kind.as_str(), "capability.allowed");
        assert_eq!(
            decision.event.metadata.get("tenant_id").map(String::as_str),
            Some("tenant-1")
        );
        assert_eq!(
            decision.event.metadata.get("worker_id").map(String::as_str),
            Some("worker-1")
        );
        assert_eq!(
            decision
                .event
                .metadata
                .get("isolation_backend")
                .map(String::as_str),
            Some("firecracker")
        );
        assert_eq!(
            decision
                .event
                .metadata
                .get("external_target")
                .map(String::as_str),
            Some("tool:native.echo")
        );
    }

    #[test]
    fn managed_cli_action_is_blocked_when_gateway_requires_approval() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Cli]),
                approval_required_actions: BTreeSet::from([CapabilityAction::Cli]),
                ..CapabilityPolicy::default()
            },
        ));

        let error = authorize_handler_external_action(
            Some(&gate),
            ExternalActionGateRequest {
                session: session(),
                action: ManagedExternalAction::Cli(ManagedCliAction {
                    command: "bash".to_string(),
                    args: vec!["-lc".to_string(), "curl https://example.test".to_string()],
                    working_dir: "/workspace".to_string(),
                    env_policy: "deny_all_except_path".to_string(),
                    timeout_millis: 1_000,
                    stdout_limit_bytes: 4096,
                    stderr_limit_bytes: 4096,
                    artifact_capture: false,
                }),
                high_risk: true,
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("requires approval"));
    }

    #[test]
    fn managed_rest_action_fails_closed_without_gateway_authorizer() {
        let error = authorize_handler_external_action::<
            RuntimeGatewayExternalActionAuthorizer<SimpleCapabilityAuthorizer>,
        >(
            None,
            ExternalActionGateRequest {
                session: session(),
                action: ManagedExternalAction::Rest(ManagedRestAction {
                    method: "POST".to_string(),
                    url: "https://api.example.test/v1/jobs".to_string(),
                    headers_policy: "strip_credentials".to_string(),
                    body_policy: "redact_and_scan".to_string(),
                    timeout_millis: 2_000,
                    retry_limit: 0,
                }),
                high_risk: false,
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("gateway authorization client"));
    }

    #[test]
    fn managed_mcp_action_denial_happens_before_handler_execution() {
        let gate =
            RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::default());

        let error = authorize_handler_external_action(
            Some(&gate),
            ExternalActionGateRequest {
                session: session(),
                action: ManagedExternalAction::McpTool(ManagedMcpToolAction {
                    server_name: "filesystem".to_string(),
                    tool_name: "read_file".to_string(),
                    arguments_policy: "workspace_only".to_string(),
                }),
                high_risk: false,
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("not allowed"));
    }

    #[test]
    fn governed_cli_execution_runs_only_after_gateway_authorization() {
        let temp = tempfile::tempdir().unwrap();
        let binary_path = temp.path().join("governed-cli-smoke");
        let marker_path = temp.path().join("executed-marker");
        std::fs::write(
            &binary_path,
            format!(
                "#!/bin/sh\nprintf 'executed %s\\n' \"$1\"\nprintf done > {}\n",
                marker_path.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            let mut permissions = std::fs::metadata(&binary_path).unwrap().permissions();
            permissions.set_mode(0o700);
            std::fs::set_permissions(&binary_path, permissions).unwrap();
        }
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Cli]),
                ..CapabilityPolicy::default()
            },
        ));

        let events = execute_governed_cli_action(
            &gate,
            session(),
            ManagedCliAction {
                command: binary_path.display().to_string(),
                args: vec!["ok".to_string()],
                working_dir: temp.path().display().to_string(),
                env_policy: "deny_all".to_string(),
                timeout_millis: 1_000,
                stdout_limit_bytes: 128,
                stderr_limit_bytes: 128,
                artifact_capture: false,
            },
            false,
        )
        .unwrap();

        assert_eq!(events[0].kind.as_str(), "capability.allowed");
        assert_eq!(events[1].kind.as_str(), "cli.requested");
        assert_eq!(
            events[1]
                .metadata
                .get("executed_after_authorization")
                .map(String::as_str),
            Some("true")
        );
        assert!(events[1]
            .metadata
            .get("stdout_excerpt")
            .is_some_and(|stdout| stdout.contains("executed ok")));
        assert!(marker_path.exists());
    }

    #[test]
    fn governed_cli_execution_denial_happens_before_process_spawn() {
        let temp = tempfile::tempdir().unwrap();
        let binary_path = temp.path().join("must-not-run");
        let marker_path = temp.path().join("executed-marker");
        std::fs::write(
            &binary_path,
            format!("#!/bin/sh\nprintf done > {}\n", marker_path.display()),
        )
        .unwrap();
        #[cfg(unix)]
        {
            let mut permissions = std::fs::metadata(&binary_path).unwrap().permissions();
            permissions.set_mode(0o700);
            std::fs::set_permissions(&binary_path, permissions).unwrap();
        }
        let gate =
            RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::default());

        let error = execute_governed_cli_action(
            &gate,
            session(),
            ManagedCliAction {
                command: binary_path.display().to_string(),
                args: vec!["blocked".to_string()],
                working_dir: temp.path().display().to_string(),
                env_policy: "deny_all".to_string(),
                timeout_millis: 1_000,
                stdout_limit_bytes: 128,
                stderr_limit_bytes: 128,
                artifact_capture: false,
            },
            false,
        )
        .unwrap_err();

        assert!(error.to_string().contains("not allowed"));
        assert!(!marker_path.exists());
    }

    #[test]
    fn governed_rest_execution_runs_only_after_gateway_authorization() {
        let server = spawn_one_shot_rest_smoke_server();
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Rest]),
                ..CapabilityPolicy::default()
            },
        ));

        let events = execute_governed_rest_action(
            &gate,
            session(),
            ManagedRestAction {
                method: "GET".to_string(),
                url: format!("http://{}/authorized", server.endpoint),
                headers_policy: "deny_credentials".to_string(),
                body_policy: "empty_body".to_string(),
                timeout_millis: 1_000,
                retry_limit: 0,
            },
            false,
        )
        .unwrap();
        let served_request = server.join().unwrap();

        assert_eq!(events[0].kind.as_str(), "capability.allowed");
        assert_eq!(events[1].kind.as_str(), "rest.requested");
        assert_eq!(
            events[1]
                .metadata
                .get("executed_after_authorization")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            events[1].metadata.get("status_code").map(String::as_str),
            Some("200")
        );
        assert!(events[1]
            .metadata
            .get("response_excerpt")
            .is_some_and(|body| body.contains("ferrogate governed rest smoke")));
        assert_eq!(served_request, "GET /authorized HTTP/1.1");
    }

    #[test]
    fn governed_rest_execution_denial_happens_before_http_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener
            .set_nonblocking(true)
            .expect("set test listener nonblocking");
        let endpoint = listener.local_addr().unwrap();
        let gate =
            RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::default());

        let error = execute_governed_rest_action(
            &gate,
            session(),
            ManagedRestAction {
                method: "GET".to_string(),
                url: format!("http://{endpoint}/blocked"),
                headers_policy: "deny_credentials".to_string(),
                body_policy: "empty_body".to_string(),
                timeout_millis: 1_000,
                retry_limit: 0,
            },
            false,
        )
        .unwrap_err();
        let accepted = listener.accept();

        assert!(error.to_string().contains("not allowed"));
        assert!(matches!(
            accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn governed_filesystem_execution_reads_only_after_gateway_authorization() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("allowed.txt"),
            "ferrogate governed filesystem smoke\n",
        )
        .unwrap();
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Filesystem]),
                ..CapabilityPolicy::default()
            },
        ));

        let events = execute_governed_filesystem_action(
            &gate,
            session(),
            ManagedFilesystemAction {
                path: "allowed.txt".to_string(),
                access: ManagedFilesystemAccess::Read,
                workspace_relative: true,
            },
            temp.path(),
            false,
        )
        .unwrap();

        assert_eq!(events[0].kind.as_str(), "capability.allowed");
        assert_eq!(events[1].kind.as_str(), "filesystem.requested");
        assert_eq!(
            events[1]
                .metadata
                .get("executed_after_authorization")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            events[1]
                .metadata
                .get("filesystem_access")
                .map(String::as_str),
            Some("read")
        );
        assert_eq!(
            events[1].metadata.get("byte_len").map(String::as_str),
            Some("36")
        );
        assert!(events[1]
            .metadata
            .get("content_excerpt")
            .is_some_and(|content| content.contains("governed filesystem smoke")));
    }

    #[test]
    fn governed_filesystem_execution_denial_happens_before_read() {
        let temp = tempfile::tempdir().unwrap();
        let gate =
            RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::default());

        let error = execute_governed_filesystem_action(
            &gate,
            session(),
            ManagedFilesystemAction {
                path: "missing-after-denial.txt".to_string(),
                access: ManagedFilesystemAccess::Read,
                workspace_relative: true,
            },
            temp.path(),
            false,
        )
        .unwrap_err();

        assert!(error.to_string().contains("not allowed"));
        assert!(!error.to_string().contains("read failed"));
    }

    #[test]
    fn governed_filesystem_execution_rejects_workspace_escape_after_authorization() {
        let temp = tempfile::tempdir().unwrap();
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Filesystem]),
                ..CapabilityPolicy::default()
            },
        ));

        let error = execute_governed_filesystem_action(
            &gate,
            session(),
            ManagedFilesystemAction {
                path: "../secret.txt".to_string(),
                access: ManagedFilesystemAccess::Read,
                workspace_relative: true,
            },
            temp.path(),
            false,
        )
        .unwrap_err();

        assert!(error.to_string().contains("must stay inside the workspace"));
    }

    #[test]
    fn self_hosted_sessions_do_not_use_managed_enforcement_gate() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                ..CapabilityPolicy::default()
            },
        ));
        let mut self_hosted = session();
        self_hosted.mode = FrameworkAdapterMode::SelfHosted;

        let error = authorize_handler_external_action(
            Some(&gate),
            ExternalActionGateRequest {
                session: self_hosted,
                action: ManagedExternalAction::Tool(ManagedToolAction {
                    tool_name: "native.echo".to_string(),
                    arguments_policy: "redacted_json".to_string(),
                }),
                high_risk: false,
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("managed worker sessions"));
    }

    #[test]
    fn external_action_smoke_emits_allowed_gateway_capability_event() {
        let decision = external_action_smoke().unwrap();
        let json = decision.event.canonical_json();

        assert_eq!(json["kind"], "capability.allowed");
        assert_eq!(json["metadata"]["external_action"], "tool");
        assert_eq!(json["metadata"]["external_target"], "tool:native.echo");
        assert_eq!(json["metadata"]["tenant_id"], "smoke-tenant");
        assert_eq!(json["metadata"]["worker_id"], "agent-worker-smoke");
    }

    #[test]
    fn external_action_json_contract_allows_tool_without_executing_it() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                ..CapabilityPolicy::default()
            },
        ));
        let input = serde_json::to_string(&tool_json_request()).unwrap();

        let response = accept_external_action_json(&input, &gate).unwrap();

        assert!(response.accepted);
        assert_eq!(response.decision, Some(ExternalActionDecision::Allowed));
        let event = response.event.unwrap();
        assert_eq!(event["kind"], "capability.allowed");
        assert_eq!(event["metadata"]["external_target"], "tool:native.echo");
    }

    #[test]
    fn external_action_json_contract_rejects_cli_approval_before_execution() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Cli]),
                approval_required_actions: BTreeSet::from([CapabilityAction::Cli]),
                ..CapabilityPolicy::default()
            },
        ));
        let mut request = tool_json_request();
        request.high_risk = true;
        request.action = ExternalActionSpec::Cli {
            command: "bash".to_string(),
            args: vec!["-lc".to_string(), "curl https://example.test".to_string()],
            working_dir: "/workspace".to_string(),
            env_policy: "deny_all_except_path".to_string(),
            timeout_millis: 1_000,
            stdout_limit_bytes: 4096,
            stderr_limit_bytes: 4096,
            artifact_capture: false,
        };
        let input = serde_json::to_string(&request).unwrap();

        let response = accept_external_action_json(&input, &gate).unwrap();

        assert!(!response.accepted);
        assert_eq!(
            response.decision,
            Some(ExternalActionDecision::ApprovalRequired)
        );
        let event = response.event.unwrap();
        assert_eq!(event["kind"], "capability.requested");
        assert_eq!(event["metadata"]["decision"], "approval_required");
        assert_eq!(event["metadata"]["external_action"], "cli");
        assert_eq!(
            response.error.as_ref().map(|error| error.code.as_str()),
            None
        );
    }

    #[test]
    fn external_action_json_contract_rejects_self_hosted_enforcement() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                ..CapabilityPolicy::default()
            },
        ));
        let mut request = tool_json_request();
        request.session.mode = ExternalActionMode::SelfHosted;
        let input = serde_json::to_string(&request).unwrap();

        let response = accept_external_action_json(&input, &gate).unwrap();

        assert!(!response.accepted);
        assert_eq!(
            response.error.as_ref().map(|error| error.code.as_str()),
            Some("invalid_request")
        );
    }

    #[test]
    fn external_action_json_contract_covers_every_managed_action_surface() {
        let allowed_actions = BTreeSet::from([
            CapabilityAction::Tool,
            CapabilityAction::McpTool,
            CapabilityAction::Cli,
            CapabilityAction::Skill,
            CapabilityAction::Filesystem,
            CapabilityAction::Browser,
            CapabilityAction::Rest,
            CapabilityAction::Secret,
            CapabilityAction::MemoryRead,
            CapabilityAction::MemoryWrite,
            CapabilityAction::NetworkEgress,
        ]);
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions,
                allow_direct_network_egress: true,
                ..CapabilityPolicy::default()
            },
        ));

        for (action, expected_action, expected_target) in external_action_contract_cases() {
            let mut request = tool_json_request();
            request.action = action;
            let input = serde_json::to_string(&request).unwrap();

            let response = accept_external_action_json(&input, &gate).unwrap();

            assert!(response.accepted, "{expected_action}:{expected_target}");
            assert_eq!(response.decision, Some(ExternalActionDecision::Allowed));
            let event = response.event.unwrap();
            assert_eq!(event["kind"], "capability.allowed");
            assert_eq!(event["metadata"]["external_action"], expected_action);
            assert_eq!(event["metadata"]["external_target"], expected_target);
            assert_eq!(event["metadata"]["tenant_id"], "tenant-1");
            assert_eq!(event["metadata"]["worker_id"], "worker-1");
            assert_eq!(event["metadata"]["isolation_backend"], "firecracker");
        }
    }

    #[test]
    fn external_action_json_contract_keeps_network_egress_fail_closed_by_default() {
        let gate = RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::NetworkEgress]),
                allow_direct_network_egress: false,
                ..CapabilityPolicy::default()
            },
        ));
        let mut request = tool_json_request();
        request.action = ExternalActionSpec::NetworkEgress {
            host: "api.example.test".to_string(),
            port: 443,
            protocol: "https".to_string(),
        };
        let input = serde_json::to_string(&request).unwrap();

        let response = accept_external_action_json(&input, &gate).unwrap();

        assert!(!response.accepted);
        assert_eq!(response.decision, Some(ExternalActionDecision::Denied));
        let event = response.event.unwrap();
        assert_eq!(event["kind"], "capability.denied");
        assert_eq!(event["metadata"]["decision"], "denied");
        assert_eq!(event["metadata"]["external_action"], "network.egress");
        assert_eq!(
            response.error.as_ref().map(|error| error.code.as_str()),
            None
        );
    }

    #[test]
    fn unix_gateway_authorizer_transport_allows_managed_handler_action() {
        let temp = tempfile::tempdir().unwrap();
        let socket_path = temp.path().join("external-action-authorizer.sock");
        let server_socket_path = socket_path.clone();
        let server = thread::spawn(move || {
            serve_gateway_authorizer_unix(
                &server_socket_path,
                RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
                    CapabilityPolicy {
                        allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                        ..CapabilityPolicy::default()
                    },
                )),
                1,
            )
        });
        wait_for_authorizer_socket(&socket_path).unwrap();
        let client = UnixGatewayExternalActionAuthorizer::new(&socket_path);

        let decision = authorize_handler_external_action(
            Some(&client),
            ExternalActionGateRequest {
                session: session(),
                action: ManagedExternalAction::Tool(ManagedToolAction {
                    tool_name: "native.echo".to_string(),
                    arguments_policy: "redacted_json".to_string(),
                }),
                high_risk: false,
            },
        )
        .unwrap();
        let served = server.join().unwrap().unwrap();

        assert!(decision.allowed());
        assert_eq!(decision.event.kind.as_str(), "capability.allowed");
        assert_eq!(
            decision
                .event
                .metadata
                .get("external_target")
                .map(String::as_str),
            Some("tool:native.echo")
        );
        assert_eq!(served.len(), 1);
        assert!(served[0].response.accepted);
        assert_eq!(
            served[0].request_id,
            "run-1:session-1:worker-1:native-harness:tool"
        );
    }

    #[test]
    fn unix_gateway_authorizer_transport_rejects_denied_gateway_decision() {
        let temp = tempfile::tempdir().unwrap();
        let socket_path = temp.path().join("external-action-authorizer-deny.sock");
        let server_socket_path = socket_path.clone();
        let server = thread::spawn(move || {
            serve_gateway_authorizer_unix(
                &server_socket_path,
                RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::default()),
                1,
            )
        });
        wait_for_authorizer_socket(&socket_path).unwrap();
        let client = UnixGatewayExternalActionAuthorizer::new(&socket_path);

        let error = authorize_handler_external_action(
            Some(&client),
            ExternalActionGateRequest {
                session: session(),
                action: ManagedExternalAction::Tool(ManagedToolAction {
                    tool_name: "native.echo".to_string(),
                    arguments_policy: "redacted_json".to_string(),
                }),
                high_risk: false,
            },
        )
        .unwrap_err();
        let served = server.join().unwrap().unwrap();

        assert!(error.to_string().contains("not allowed"));
        assert_eq!(served.len(), 1);
        assert!(!served[0].response.accepted);
        assert_eq!(
            served[0].response.decision,
            Some(ExternalActionDecision::Denied)
        );
        assert_eq!(
            served[0].response.event.as_ref().unwrap()["kind"],
            "capability.denied"
        );
        assert_eq!(
            served[0]
                .response
                .error
                .as_ref()
                .map(|error| error.code.as_str()),
            None
        );
    }

    #[test]
    fn unix_gateway_authorizer_transport_rejects_response_identity_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let socket_path = temp.path().join("external-action-authorizer-bad-id.sock");
        let server_socket_path = socket_path.clone();
        let server = thread::spawn(move || {
            if server_socket_path.exists() {
                std::fs::remove_file(&server_socket_path).unwrap();
            }
            let listener = UnixListener::bind(&server_socket_path).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            let mut input = String::new();
            read_external_action_stream(&mut stream, &mut input).unwrap();
            let request: GatewayExternalActionTransportRequest =
                serde_json::from_str(&input).unwrap();
            let response = GatewayExternalActionTransportResponse {
                request_id: format!("{}-tampered", request.request_id),
                response: ExternalActionAuthorizationResponse {
                    accepted: true,
                    decision: Some(ExternalActionDecision::Allowed),
                    event: Some(allowed_tool_event_json()),
                    error: None,
                },
            };
            stream
                .write_all(serde_json::to_string(&response).unwrap().as_bytes())
                .unwrap();
        });
        wait_for_authorizer_socket(&socket_path).unwrap();
        let client = UnixGatewayExternalActionAuthorizer::new(&socket_path);

        let error = authorize_handler_external_action(
            Some(&client),
            ExternalActionGateRequest {
                session: session(),
                action: ManagedExternalAction::Tool(ManagedToolAction {
                    tool_name: "native.echo".to_string(),
                    arguments_policy: "redacted_json".to_string(),
                }),
                high_risk: false,
            },
        )
        .unwrap_err();
        server.join().unwrap();

        assert!(error.to_string().contains("request_id mismatch"));
    }

    #[test]
    fn http_gateway_authorizer_transport_allows_managed_handler_action() {
        let expected_response = GatewayExternalActionTransportResponse {
            request_id: "run-1:session-1:worker-1:native-harness:tool".to_string(),
            response: ExternalActionAuthorizationResponse {
                accepted: true,
                decision: Some(ExternalActionDecision::Allowed),
                event: Some(allowed_tool_event_json()),
                error: None,
            },
        };
        let server = spawn_http_authorizer_contract_server(
            |request| {
                assert!(request
                    .starts_with("POST /v1/agent-worker/external-actions/authorize HTTP/1.1\r\n"));
                assert!(request.contains("\r\ncontent-type: application/json\r\n"));
                let body = http_request_body(&request);
                let request: GatewayExternalActionTransportRequest =
                    serde_json::from_str(body).unwrap();
                assert_eq!(
                    request.request_id,
                    "run-1:session-1:worker-1:native-harness:tool"
                );
            },
            expected_response,
            200,
        );
        let client = HttpGatewayExternalActionAuthorizer::new(server.endpoint);

        let decision = authorize_handler_external_action(
            Some(&client),
            ExternalActionGateRequest {
                session: session(),
                action: ManagedExternalAction::Tool(ManagedToolAction {
                    tool_name: "native.echo".to_string(),
                    arguments_policy: "redacted_json".to_string(),
                }),
                high_risk: false,
            },
        )
        .unwrap();
        server.join();

        assert!(decision.allowed());
        assert_eq!(decision.event.kind.as_str(), "capability.allowed");
    }

    #[test]
    fn http_gateway_authorizer_transport_rejects_response_identity_mismatch() {
        let response = GatewayExternalActionTransportResponse {
            request_id: "tampered-request-id".to_string(),
            response: ExternalActionAuthorizationResponse {
                accepted: true,
                decision: Some(ExternalActionDecision::Allowed),
                event: Some(allowed_tool_event_json()),
                error: None,
            },
        };
        let server = spawn_http_authorizer_contract_server(|_| {}, response, 200);
        let client = HttpGatewayExternalActionAuthorizer::new(server.endpoint);

        let error = authorize_handler_external_action(
            Some(&client),
            ExternalActionGateRequest {
                session: session(),
                action: ManagedExternalAction::Tool(ManagedToolAction {
                    tool_name: "native.echo".to_string(),
                    arguments_policy: "redacted_json".to_string(),
                }),
                high_risk: false,
            },
        )
        .unwrap_err();
        server.join();

        assert!(error.to_string().contains("request_id mismatch"));
    }

    #[test]
    fn http_gateway_authorizer_transport_times_out_fail_closed() {
        let server = spawn_stalled_http_authorizer_server();
        let client = HttpGatewayExternalActionAuthorizer::new_with_timeout(
            server.endpoint,
            Duration::from_millis(50),
        );

        let decision = request_handler_external_action_decision(
            Some(&client),
            ExternalActionGateRequest {
                session: session(),
                action: ManagedExternalAction::Tool(ManagedToolAction {
                    tool_name: "native.echo".to_string(),
                    arguments_policy: "redacted_json".to_string(),
                }),
                high_risk: false,
            },
        )
        .unwrap();
        server.join();

        assert_eq!(decision.decision, CapabilityAuthorizationDecision::Denied);
        assert_eq!(decision.event.kind.as_str(), "capability.denied");
        assert_eq!(
            decision.event.metadata.get("decision").map(String::as_str),
            Some("denied")
        );
        assert_eq!(
            decision
                .event
                .metadata
                .get("failure_source")
                .map(String::as_str),
            Some("gateway_authorizer_transport")
        );
        assert!(decision
            .event
            .message
            .as_deref()
            .is_some_and(|message| message.contains("response read failed")));
    }

    #[test]
    fn http_gateway_authorizer_transport_timeout_blocks_handler_execution() {
        let server = spawn_stalled_http_authorizer_server();
        let client = HttpGatewayExternalActionAuthorizer::new_with_timeout(
            server.endpoint,
            Duration::from_millis(50),
        );

        let error = authorize_handler_external_action(
            Some(&client),
            ExternalActionGateRequest {
                session: session(),
                action: ManagedExternalAction::Tool(ManagedToolAction {
                    tool_name: "native.echo".to_string(),
                    arguments_policy: "redacted_json".to_string(),
                }),
                high_risk: false,
            },
        )
        .unwrap_err();
        server.join();

        assert!(error.to_string().contains("response read failed"));
    }

    fn session() -> FrameworkAdapterSession {
        FrameworkAdapterSession {
            session_id: "session-1".to_string(),
            run_id: "run-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            workspace_id: "workspace-1".to_string(),
            worker_id: "worker-1".to_string(),
            isolation_backend: "firecracker".to_string(),
            adapter_name: "native-harness".to_string(),
            adapter_version: env!("CARGO_PKG_VERSION").to_string(),
            framework: SupportedFramework::NativeHarness,
            mode: FrameworkAdapterMode::Managed,
        }
    }

    struct HttpAuthorizerContractServer {
        endpoint: SocketAddr,
        handle: thread::JoinHandle<()>,
    }

    impl HttpAuthorizerContractServer {
        fn join(self) {
            self.handle.join().unwrap();
        }
    }

    fn spawn_http_authorizer_contract_server<F>(
        inspect_request: F,
        response: GatewayExternalActionTransportResponse,
        status_code: u16,
    ) -> HttpAuthorizerContractServer
    where
        F: FnOnce(String) + Send + 'static,
    {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            let request = String::from_utf8(request).unwrap();
            inspect_request(request);
            let body = serde_json::to_string(&response).unwrap();
            let reason = match status_code {
                200 => "OK",
                400 => "Bad Request",
                _ => "Error",
            };
            let response = format!(
                "HTTP/1.1 {status_code} {reason}\r\n\
                 content-type: application/json\r\n\
                 content-length: {}\r\n\
                 connection: close\r\n\
                 \r\n\
                 {}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        HttpAuthorizerContractServer { endpoint, handle }
    }

    fn spawn_stalled_http_authorizer_server() -> HttpAuthorizerContractServer {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer).unwrap();
            thread::sleep(Duration::from_millis(150));
        });
        HttpAuthorizerContractServer { endpoint, handle }
    }

    fn http_request_body(request: &str) -> &str {
        request
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap_or_default()
    }

    fn tool_json_request() -> ExternalActionAuthorizationRequest {
        ExternalActionAuthorizationRequest {
            session: ExternalActionSession {
                session_id: "session-1".to_string(),
                run_id: "run-1".to_string(),
                tenant_id: "tenant-1".to_string(),
                workspace_id: "workspace-1".to_string(),
                worker_id: "worker-1".to_string(),
                isolation_backend: "firecracker".to_string(),
                adapter_name: "native-harness".to_string(),
                adapter_version: env!("CARGO_PKG_VERSION").to_string(),
                framework: ExternalActionFramework::NativeHarness,
                mode: ExternalActionMode::Managed,
            },
            action: ExternalActionSpec::Tool {
                tool_name: "native.echo".to_string(),
                arguments_policy: "redacted_json".to_string(),
            },
            high_risk: false,
        }
    }

    fn external_action_contract_cases() -> Vec<(ExternalActionSpec, &'static str, &'static str)> {
        vec![
            (
                ExternalActionSpec::Tool {
                    tool_name: "native.echo".to_string(),
                    arguments_policy: "redacted_json".to_string(),
                },
                "tool",
                "tool:native.echo",
            ),
            (
                ExternalActionSpec::McpTool {
                    server_name: "filesystem".to_string(),
                    tool_name: "read_file".to_string(),
                    arguments_policy: "workspace_only".to_string(),
                },
                "mcp.tool",
                "mcp:filesystem:read_file",
            ),
            (
                ExternalActionSpec::Cli {
                    command: "cargo".to_string(),
                    args: vec!["test".to_string()],
                    working_dir: "/workspace".to_string(),
                    env_policy: "allowlist".to_string(),
                    timeout_millis: 30_000,
                    stdout_limit_bytes: 65_536,
                    stderr_limit_bytes: 65_536,
                    artifact_capture: true,
                },
                "cli",
                "cargo",
            ),
            (
                ExternalActionSpec::Skill {
                    skill_id: "repo-test".to_string(),
                    declared_capabilities: vec!["cli".to_string(), "filesystem".to_string()],
                },
                "skill",
                "skill:repo-test",
            ),
            (
                ExternalActionSpec::Filesystem {
                    path: "src/lib.rs".to_string(),
                    access: ExternalActionFilesystemAccess::Read,
                    workspace_relative: true,
                },
                "filesystem",
                "read:src/lib.rs",
            ),
            (
                ExternalActionSpec::Browser {
                    operation: ExternalActionBrowserOperation::Navigate,
                    url: "https://docs.example.test".to_string(),
                    timeout_millis: 5_000,
                },
                "browser",
                "browser:navigate:https://docs.example.test",
            ),
            (
                ExternalActionSpec::Rest {
                    method: "POST".to_string(),
                    url: "https://api.example.test/v1/jobs".to_string(),
                    headers_policy: "redact_authorization".to_string(),
                    body_policy: "guardrail_scan".to_string(),
                    timeout_millis: 10_000,
                    retry_limit: 2,
                },
                "rest",
                "POST https://api.example.test/v1/jobs",
            ),
            (
                ExternalActionSpec::Secret {
                    secret_id: "openai-api-key".to_string(),
                    purpose: "provider_call".to_string(),
                },
                "secret",
                "secret:openai-api-key",
            ),
            (
                ExternalActionSpec::Memory {
                    access: ExternalActionMemoryAccess::Read,
                    namespace: "session".to_string(),
                    key: "plan".to_string(),
                },
                "memory.read",
                "memory:read:session:plan",
            ),
            (
                ExternalActionSpec::Memory {
                    access: ExternalActionMemoryAccess::Write,
                    namespace: "session".to_string(),
                    key: "summary".to_string(),
                },
                "memory.write",
                "memory:write:session:summary",
            ),
            (
                ExternalActionSpec::NetworkEgress {
                    host: "api.example.test".to_string(),
                    port: 443,
                    protocol: "https".to_string(),
                },
                "network.egress",
                "api.example.test:443",
            ),
        ]
    }

    fn allowed_tool_event_json() -> serde_json::Value {
        RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(
            CapabilityPolicy {
                allowed_actions: BTreeSet::from([CapabilityAction::Tool]),
                ..CapabilityPolicy::default()
            },
        ))
        .authorize_external_action(ManagedExternalActionRequest {
            session: session(),
            action: ManagedExternalAction::Tool(ManagedToolAction {
                tool_name: "native.echo".to_string(),
                arguments_policy: "redacted_json".to_string(),
            }),
            high_risk: false,
        })
        .unwrap()
        .event
        .canonical_json()
    }
}
