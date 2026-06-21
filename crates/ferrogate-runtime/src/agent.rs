// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Bounded agent harness boundary.

use std::{
    error::Error,
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use ferrogate_core::{RequestContext, ToolCall, ToolResult};

const DEFAULT_MAX_TURNS: u32 = 4;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentHarnessConfig {
    pub max_turns: u32,
    pub timeout: Option<Duration>,
}

impl Default for AgentHarnessConfig {
    fn default() -> Self {
        Self {
            max_turns: DEFAULT_MAX_TURNS,
            timeout: Some(DEFAULT_TIMEOUT),
        }
    }
}

impl AgentHarnessConfig {
    pub fn validate(&self) -> AgentRuntimeResult<()> {
        if self.max_turns == 0 {
            return Err(AgentRuntimeError::InvalidConfig(
                "max_turns must be greater than zero".to_string(),
            ));
        }
        if self.timeout == Some(Duration::ZERO) {
            return Err(AgentRuntimeError::InvalidConfig(
                "timeout must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AgentCancellation {
    cancelled: Arc<AtomicBool>,
}

impl Default for AgentCancellation {
    fn default() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl AgentCancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone)]
pub struct AgentRunInput {
    pub request: RequestContext,
    pub cancellation: AgentCancellation,
}

impl AgentRunInput {
    pub fn new(request: RequestContext) -> Self {
        Self {
            request,
            cancellation: AgentCancellation::default(),
        }
    }

    fn run_id(&self) -> String {
        self.request
            .agent_run_id
            .clone()
            .filter(|id| !id.trim().is_empty())
            .unwrap_or_else(|| format!("agent-run-{}", self.request.request_id))
    }
}

#[derive(Debug)]
pub struct AgentContext<'a> {
    pub run_id: &'a str,
    pub request: &'a RequestContext,
    pub turn: u32,
    pub tool_results: &'a [ToolResult],
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentStep {
    Continue,
    ToolCall(ToolCall),
    Finish { output: String },
}

pub trait AgentProvider {
    fn next_step(&mut self, context: &AgentContext<'_>) -> AgentRuntimeResult<AgentStep>;
}

#[derive(Debug)]
pub struct AgentToolDispatchRequest<'a> {
    pub run_id: &'a str,
    pub turn: u32,
    pub request: &'a RequestContext,
    pub tool_call: &'a ToolCall,
}

/// Tool execution boundary for agent runs.
///
/// Implementations must call the existing gateway-mediated tool path so auth,
/// policy, approvals, billing, and audit remain outside this runtime loop.
pub trait GovernedAgentToolDispatcher {
    fn dispatch_tool(
        &mut self,
        request: AgentToolDispatchRequest<'_>,
    ) -> AgentRuntimeResult<ToolResult>;
}

pub trait AgentRunEventSink {
    fn record(&mut self, event: AgentRunEvent);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRunEvent {
    pub id: String,
    pub run_id: String,
    pub turn: u32,
    pub kind: AgentRunEventKind,
    pub tool_call_id: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRunEventKind {
    RunStarted,
    TurnStarted,
    ToolCallRequested,
    ToolCallCompleted,
    RunCompleted,
    RunStopped,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentRunOutcome {
    pub run_id: String,
    pub status: AgentRunStatus,
    pub turns_executed: u32,
    pub output: Option<String>,
    pub tool_results: Vec<ToolResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRunStatus {
    Completed,
    MaxTurnsExceeded,
    Cancelled,
    TimedOut,
    Failed,
}

#[derive(Debug, Clone)]
pub struct AgentHarness {
    config: AgentHarnessConfig,
}

impl AgentHarness {
    pub fn new(config: AgentHarnessConfig) -> AgentRuntimeResult<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn run<P, D, S>(
        &self,
        input: AgentRunInput,
        provider: &mut P,
        tool_dispatcher: &mut D,
        event_sink: &mut S,
    ) -> AgentRuntimeResult<AgentRunOutcome>
    where
        P: AgentProvider,
        D: GovernedAgentToolDispatcher,
        S: AgentRunEventSink,
    {
        let run_id = input.run_id();
        let started_at = Instant::now();
        let mut tool_results = Vec::new();
        let mut turns_executed = 0;
        event_sink.record(run_event(
            &run_id,
            0,
            AgentRunEventKind::RunStarted,
            None,
            None,
        ));

        for turn in 1..=self.config.max_turns {
            if let Some(outcome) = self.stop_outcome(
                &run_id,
                turns_executed,
                &tool_results,
                started_at,
                &input.cancellation,
                event_sink,
            ) {
                return Ok(outcome);
            }

            turns_executed = turn;
            event_sink.record(run_event(
                &run_id,
                turn,
                AgentRunEventKind::TurnStarted,
                None,
                None,
            ));
            let context = AgentContext {
                run_id: &run_id,
                request: &input.request,
                turn,
                tool_results: &tool_results,
            };
            let step = provider.next_step(&context).map_err(|error| {
                self.failure(&run_id, turn, error, tool_results.clone(), event_sink)
            })?;

            if let Some(outcome) = self.stop_outcome(
                &run_id,
                turns_executed,
                &tool_results,
                started_at,
                &input.cancellation,
                event_sink,
            ) {
                return Ok(outcome);
            }

            match step {
                AgentStep::Continue => {}
                AgentStep::Finish { output } => {
                    event_sink.record(run_event(
                        &run_id,
                        turn,
                        AgentRunEventKind::RunCompleted,
                        None,
                        Some("agent run completed".to_string()),
                    ));
                    return Ok(AgentRunOutcome {
                        run_id,
                        status: AgentRunStatus::Completed,
                        turns_executed,
                        output: Some(output),
                        tool_results,
                    });
                }
                AgentStep::ToolCall(tool_call) => {
                    event_sink.record(run_event(
                        &run_id,
                        turn,
                        AgentRunEventKind::ToolCallRequested,
                        Some(tool_call.id.clone()),
                        Some(tool_call.name.clone()),
                    ));
                    let result = tool_dispatcher
                        .dispatch_tool(AgentToolDispatchRequest {
                            run_id: &run_id,
                            turn,
                            request: &input.request,
                            tool_call: &tool_call,
                        })
                        .map_err(|error| {
                            self.failure(&run_id, turn, error, tool_results.clone(), event_sink)
                        })?;
                    event_sink.record(run_event(
                        &run_id,
                        turn,
                        AgentRunEventKind::ToolCallCompleted,
                        Some(tool_call.id),
                        None,
                    ));
                    tool_results.push(result);
                }
            }
        }

        event_sink.record(run_event(
            &run_id,
            turns_executed,
            AgentRunEventKind::RunStopped,
            None,
            Some("max turns exceeded".to_string()),
        ));
        Ok(AgentRunOutcome {
            run_id,
            status: AgentRunStatus::MaxTurnsExceeded,
            turns_executed,
            output: None,
            tool_results,
        })
    }

    fn stop_outcome<S>(
        &self,
        run_id: &str,
        turns_executed: u32,
        tool_results: &[ToolResult],
        started_at: Instant,
        cancellation: &AgentCancellation,
        event_sink: &mut S,
    ) -> Option<AgentRunOutcome>
    where
        S: AgentRunEventSink,
    {
        let (status, message) = if cancellation.is_cancelled() {
            (AgentRunStatus::Cancelled, "agent run cancelled")
        } else if self
            .config
            .timeout
            .is_some_and(|timeout| started_at.elapsed() >= timeout)
        {
            (AgentRunStatus::TimedOut, "agent run timed out")
        } else {
            return None;
        };

        event_sink.record(run_event(
            run_id,
            turns_executed,
            AgentRunEventKind::RunStopped,
            None,
            Some(message.to_string()),
        ));
        Some(AgentRunOutcome {
            run_id: run_id.to_string(),
            status,
            turns_executed,
            output: None,
            tool_results: tool_results.to_vec(),
        })
    }

    fn failure<S>(
        &self,
        run_id: &str,
        turn: u32,
        error: AgentRuntimeError,
        tool_results: Vec<ToolResult>,
        event_sink: &mut S,
    ) -> AgentRuntimeError
    where
        S: AgentRunEventSink,
    {
        event_sink.record(run_event(
            run_id,
            turn,
            AgentRunEventKind::RunStopped,
            None,
            Some(error.to_string()),
        ));
        AgentRuntimeError::RunFailed {
            outcome: Box::new(AgentRunOutcome {
                run_id: run_id.to_string(),
                status: AgentRunStatus::Failed,
                turns_executed: turn,
                output: None,
                tool_results,
            }),
            source: Box::new(error),
        }
    }
}

fn run_event(
    run_id: &str,
    turn: u32,
    kind: AgentRunEventKind,
    tool_call_id: Option<String>,
    message: Option<String>,
) -> AgentRunEvent {
    let suffix = match kind {
        AgentRunEventKind::RunStarted => "run-started",
        AgentRunEventKind::TurnStarted => "turn-started",
        AgentRunEventKind::ToolCallRequested => "tool-call-requested",
        AgentRunEventKind::ToolCallCompleted => "tool-call-completed",
        AgentRunEventKind::RunCompleted => "run-completed",
        AgentRunEventKind::RunStopped => "run-stopped",
    };
    AgentRunEvent {
        id: match tool_call_id.as_deref() {
            Some(tool_call_id) => format!("{run_id}:{turn:04}:{suffix}:{tool_call_id}"),
            None => format!("{run_id}:{turn:04}:{suffix}"),
        },
        run_id: run_id.to_string(),
        turn,
        kind,
        tool_call_id,
        message,
    }
}

pub type AgentRuntimeResult<T> = Result<T, AgentRuntimeError>;

#[derive(Debug, Clone, PartialEq)]
pub enum AgentRuntimeError {
    InvalidConfig(String),
    Provider(String),
    ToolDispatch(String),
    RunFailed {
        outcome: Box<AgentRunOutcome>,
        source: Box<AgentRuntimeError>,
    },
}

impl fmt::Display for AgentRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(formatter, "invalid agent config: {message}"),
            Self::Provider(message) => write!(formatter, "agent provider failed: {message}"),
            Self::ToolDispatch(message) => {
                write!(formatter, "agent tool dispatch failed: {message}")
            }
            Self::RunFailed { source, .. } => write!(formatter, "agent run failed: {source}"),
        }
    }
}

impl Error for AgentRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RunFailed { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn default_harness_finishes_with_stable_run_events() {
        let harness = AgentHarness::new(AgentHarnessConfig::default()).unwrap();
        let mut provider = ScriptedProvider::new(vec![AgentStep::Finish {
            output: "done".to_string(),
        }]);
        let mut dispatcher = CapturingDispatcher::default();
        let mut sink = VecEventSink::default();

        let outcome = harness
            .run(
                AgentRunInput::new(request("req-1", Some("run-1"))),
                &mut provider,
                &mut dispatcher,
                &mut sink,
            )
            .unwrap();

        assert_eq!(outcome.run_id, "run-1");
        assert_eq!(outcome.status, AgentRunStatus::Completed);
        assert_eq!(outcome.output.as_deref(), Some("done"));
        assert_eq!(
            event_ids(&sink.events),
            vec![
                "run-1:0000:run-started",
                "run-1:0001:turn-started",
                "run-1:0001:run-completed",
            ]
        );
    }

    #[test]
    fn dispatches_tool_calls_through_governed_boundary() {
        let harness = AgentHarness::new(AgentHarnessConfig::default()).unwrap();
        let tool_call = ToolCall {
            id: "call-1".to_string(),
            name: "tool.echo".to_string(),
            arguments: json!({"text": "hello"}),
        };
        let mut provider = ScriptedProvider::new(vec![
            AgentStep::ToolCall(tool_call),
            AgentStep::Finish {
                output: "done".to_string(),
            },
        ]);
        let mut dispatcher = CapturingDispatcher::default();
        let mut sink = VecEventSink::default();

        let outcome = harness
            .run(
                AgentRunInput::new(request("req-2", Some("run-2"))),
                &mut provider,
                &mut dispatcher,
                &mut sink,
            )
            .unwrap();

        assert_eq!(outcome.status, AgentRunStatus::Completed);
        assert_eq!(outcome.tool_results.len(), 1);
        assert_eq!(dispatcher.calls, vec!["run-2:1:tool.echo:call-1:req-2"]);
        assert_eq!(
            event_ids(&sink.events),
            vec![
                "run-2:0000:run-started",
                "run-2:0001:turn-started",
                "run-2:0001:tool-call-requested:call-1",
                "run-2:0001:tool-call-completed:call-1",
                "run-2:0002:turn-started",
                "run-2:0002:run-completed",
            ]
        );
    }

    #[test]
    fn derives_stable_run_id_from_request_when_missing() {
        let harness = AgentHarness::new(AgentHarnessConfig::default()).unwrap();
        let mut provider = ScriptedProvider::new(vec![AgentStep::Finish {
            output: "done".to_string(),
        }]);
        let mut dispatcher = CapturingDispatcher::default();
        let mut sink = VecEventSink::default();

        let outcome = harness
            .run(
                AgentRunInput::new(request("req-3", None)),
                &mut provider,
                &mut dispatcher,
                &mut sink,
            )
            .unwrap();

        assert_eq!(outcome.run_id, "agent-run-req-3");
        assert_eq!(sink.events[0].id, "agent-run-req-3:0000:run-started");
    }

    #[test]
    fn stops_at_max_turns() {
        let harness = AgentHarness::new(AgentHarnessConfig {
            max_turns: 2,
            timeout: None,
        })
        .unwrap();
        let mut provider = ScriptedProvider::new(vec![AgentStep::Continue, AgentStep::Continue]);
        let mut dispatcher = CapturingDispatcher::default();
        let mut sink = VecEventSink::default();

        let outcome = harness
            .run(
                AgentRunInput::new(request("req-4", Some("run-4"))),
                &mut provider,
                &mut dispatcher,
                &mut sink,
            )
            .unwrap();

        assert_eq!(outcome.status, AgentRunStatus::MaxTurnsExceeded);
        assert_eq!(outcome.turns_executed, 2);
        assert_eq!(sink.events.last().unwrap().id, "run-4:0002:run-stopped");
        assert_eq!(
            sink.events.last().unwrap().message.as_deref(),
            Some("max turns exceeded")
        );
    }

    #[test]
    fn stops_when_cancelled_during_tool_dispatch() {
        let cancellation = AgentCancellation::default();
        let harness = AgentHarness::new(AgentHarnessConfig::default()).unwrap();
        let tool_call = ToolCall {
            id: "call-cancel".to_string(),
            name: "tool.echo".to_string(),
            arguments: json!({}),
        };
        let mut provider = ScriptedProvider::new(vec![AgentStep::ToolCall(tool_call)]);
        let mut dispatcher = CapturingDispatcher {
            cancellation_to_trigger: Some(cancellation.clone()),
            ..CapturingDispatcher::default()
        };
        let mut sink = VecEventSink::default();

        let outcome = harness
            .run(
                AgentRunInput {
                    request: request("req-5", Some("run-5")),
                    cancellation,
                },
                &mut provider,
                &mut dispatcher,
                &mut sink,
            )
            .unwrap();

        assert_eq!(outcome.status, AgentRunStatus::Cancelled);
        assert_eq!(outcome.turns_executed, 1);
        assert_eq!(
            sink.events.last().unwrap().message.as_deref(),
            Some("agent run cancelled")
        );
    }

    #[test]
    fn stops_after_timeout_is_observed() {
        let harness = AgentHarness::new(AgentHarnessConfig {
            max_turns: 2,
            timeout: Some(Duration::from_millis(1)),
        })
        .unwrap();
        let mut provider = ScriptedProvider {
            steps: vec![AgentStep::Continue],
            sleep_before_step: Some(Duration::from_millis(5)),
        };
        let mut dispatcher = CapturingDispatcher::default();
        let mut sink = VecEventSink::default();

        let outcome = harness
            .run(
                AgentRunInput::new(request("req-6", Some("run-6"))),
                &mut provider,
                &mut dispatcher,
                &mut sink,
            )
            .unwrap();

        assert_eq!(outcome.status, AgentRunStatus::TimedOut);
        assert_eq!(outcome.turns_executed, 1);
        assert_eq!(
            sink.events.last().unwrap().message.as_deref(),
            Some("agent run timed out")
        );
    }

    #[test]
    fn rejects_invalid_harness_limits() {
        let error = AgentHarness::new(AgentHarnessConfig {
            max_turns: 0,
            timeout: None,
        })
        .unwrap_err();
        assert!(matches!(error, AgentRuntimeError::InvalidConfig(_)));

        let error = AgentHarness::new(AgentHarnessConfig {
            max_turns: 1,
            timeout: Some(Duration::ZERO),
        })
        .unwrap_err();
        assert!(matches!(error, AgentRuntimeError::InvalidConfig(_)));
    }

    #[derive(Debug)]
    struct ScriptedProvider {
        steps: Vec<AgentStep>,
        sleep_before_step: Option<Duration>,
    }

    impl ScriptedProvider {
        fn new(steps: Vec<AgentStep>) -> Self {
            Self {
                steps,
                sleep_before_step: None,
            }
        }
    }

    impl AgentProvider for ScriptedProvider {
        fn next_step(&mut self, context: &AgentContext<'_>) -> AgentRuntimeResult<AgentStep> {
            if let Some(duration) = self.sleep_before_step.take() {
                std::thread::sleep(duration);
            }
            if let Some(agent_run_id) = context.request.agent_run_id.as_deref() {
                assert_eq!(context.run_id, agent_run_id);
            }
            Ok(if self.steps.is_empty() {
                AgentStep::Continue
            } else {
                self.steps.remove(0)
            })
        }
    }

    #[derive(Debug, Default)]
    struct CapturingDispatcher {
        calls: Vec<String>,
        cancellation_to_trigger: Option<AgentCancellation>,
    }

    impl GovernedAgentToolDispatcher for CapturingDispatcher {
        fn dispatch_tool(
            &mut self,
            request: AgentToolDispatchRequest<'_>,
        ) -> AgentRuntimeResult<ToolResult> {
            self.calls.push(format!(
                "{}:{}:{}:{}:{}",
                request.run_id,
                request.turn,
                request.tool_call.name,
                request.tool_call.id,
                request.request.request_id
            ));
            if let Some(cancellation) = &self.cancellation_to_trigger {
                cancellation.cancel();
            }
            Ok(ToolResult {
                tool_call_id: request.tool_call.id.clone(),
                content: json!({"ok": true}),
                is_error: false,
            })
        }
    }

    #[derive(Debug, Default)]
    struct VecEventSink {
        events: Vec<AgentRunEvent>,
    }

    impl AgentRunEventSink for VecEventSink {
        fn record(&mut self, event: AgentRunEvent) {
            self.events.push(event);
        }
    }

    fn request(request_id: &str, agent_run_id: Option<&str>) -> RequestContext {
        RequestContext {
            request_id: request_id.to_string(),
            agent_run_id: agent_run_id.map(str::to_string),
            ..RequestContext::default()
        }
    }

    fn event_ids(events: &[AgentRunEvent]) -> Vec<&str> {
        events.iter().map(|event| event.id.as_str()).collect()
    }
}
