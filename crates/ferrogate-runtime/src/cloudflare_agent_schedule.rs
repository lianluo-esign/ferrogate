// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Typed scheduling verbs over the agent-gateway Worker's /schedule/* routes
//   (issue #426): schedule_create / schedule_list / schedule_cancel for one-shot, cron, and
//   interval tasks, reusing the #427 instance-naming scheme and the #413 transport seam.

//! FerroGate access to a Cloudflare agent's **in-agent scheduler** (issue
//! #426).
//!
//! Cloudflare agents schedule future work with `this.schedule(when, method,
//! payload)` — rows in the Durable Object's `cf_agents_schedules` table,
//! multiplexed through the DO's **single alarm**, surviving hibernation and
//! restart. There is **no external enqueue endpoint**: scheduling is in-agent
//! only, so FerroGate schedules/lists/cancels through the agent-gateway
//! Worker's authenticated `/schedule/*` routes (the tethered principle),
//! exactly like the #413 control and #427 memory surfaces.
//!
//! Three task kinds:
//!
//! * **once** — a delay in seconds or an absolute RFC3339 instant (SDK types
//!   `delayed`/`scheduled`).
//! * **cron** — a cron expression, minute precision, auto-rescheduled by the
//!   SDK's alarm handler.
//! * **interval** — repeat every N seconds. The pinned Agents SDK (0.0.109)
//!   has **no `scheduleEvery`** (verified against the package dist), so the
//!   Worker emulates intervals as delayed one-shots whose dispatcher re-arms
//!   itself; it probes for a native `scheduleEvery` defensively for future
//!   SDK upgrades.
//!
//! Two governance decisions ride in the Worker (see
//! `workers/agent-gateway/src/schedule.ts` and
//! `docs/cloudflare-agent-scheduling.md`):
//!
//! * **Pinned callback** — every schedule fires the agent's single
//!   `runScheduledTask` dispatcher; FerroGate callers can never schedule
//!   arbitrary agent methods (which would let a schedule invoke `destroyRun`
//!   or any RPC verb).
//! * **Duplicate guard** — every create is cancel-before-recreate keyed by
//!   `task_id`, guarding the `scheduleEvery` duplicate-row bug
//!   (github.com/cloudflare/agents #1049) and making create idempotent.
//!
//! Instance naming reuses [`AgentInstanceIdentity`] from the #427 memory
//! module (`fg.{tenant}.{session}.{run}` — per-instance DO isolation IS
//! tenant isolation), and HTTP reuses the synchronous
//! [`GatewayControlTransport`] seam, so every verb is unit-tested against a
//! scripted mock with no network.

use serde::Deserialize;
use serde_json::json;
use std::{error::Error, fmt};

use crate::cloudflare_agent_memory::AgentInstanceIdentity;
use crate::cloudflare_gateway_control::GatewayControlTransport;
use ferrogate_cloudflare::{HttpMethod, HttpRequest, HttpResponse};

/// Maximum length of a FerroGate schedule task id.
pub const SCHEDULE_TASK_ID_MAX_LEN: usize = 128;

/// FerroGate schedule kinds (the Worker maps them onto the SDK's
/// `delayed`/`scheduled`/`cron` row types).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentScheduleKind {
    Once,
    Cron,
    Interval,
}

impl AgentScheduleKind {
    /// Wire spelling used by the Worker routes.
    pub fn as_wire(&self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Cron => "cron",
            Self::Interval => "interval",
        }
    }
}

/// When a task runs. Each variant maps onto one Worker `task` shape.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentScheduleWhen {
    /// One-shot after this many seconds (SDK type `delayed`).
    DelaySeconds(u64),
    /// One-shot at an absolute RFC3339 instant (SDK type `scheduled`).
    At(String),
    /// Cron expression — minute precision, auto-rescheduling (SDK type `cron`).
    Cron(String),
    /// Repeat every N seconds (emulated on the pinned SDK; see module docs).
    EverySeconds(u64),
}

impl AgentScheduleWhen {
    fn kind(&self) -> AgentScheduleKind {
        match self {
            Self::DelaySeconds(_) | Self::At(_) => AgentScheduleKind::Once,
            Self::Cron(_) => AgentScheduleKind::Cron,
            Self::EverySeconds(_) => AgentScheduleKind::Interval,
        }
    }
}

/// One task to schedule: the stable dedup key, when to run, opaque payload.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentScheduleTaskSpec {
    /// FerroGate's stable task key — the cancel-before-recreate dedup key.
    pub task_id: String,
    pub when: AgentScheduleWhen,
    /// Opaque payload handed to the agent's dispatcher (JSON ≤ 2 MB).
    pub data: serde_json::Value,
}

impl AgentScheduleTaskSpec {
    pub fn new(task_id: impl Into<String>, when: AgentScheduleWhen) -> Self {
        Self {
            task_id: task_id.into(),
            when,
            data: serde_json::Value::Null,
        }
    }

    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = data;
        self
    }
}

/// Optional list filter (server-side, in the Worker verb).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AgentScheduleListCriteria {
    pub task_id: Option<String>,
    pub kind: Option<AgentScheduleKind>,
}

/// What to cancel: every row of a FerroGate task, or one raw SDK row.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentScheduleCancelSelector {
    /// Cancel all schedule rows minted for this FerroGate `task_id`.
    TaskId(String),
    /// Cancel one row by its raw SDK schedule id (`cf_agents_schedules.id`).
    ScheduleId(String),
}

/// Failure surfaced by an agent-schedule verb.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentScheduleError {
    /// The identity triple cannot be turned into a safe instance name.
    InvalidIdentity(String),
    /// The task spec is invalid (client-side, or the Worker's 422
    /// `invalid_task` — validation aborts, nothing is scheduled).
    InvalidTask(String),
    /// The instance's per-instance schedule-row cap is exhausted (HTTP 429
    /// `schedule_limit`). Cancel stale tasks before retrying.
    LimitExceeded(String),
    /// The Worker rejected the bearer credential (HTTP 401/403).
    Denied(String),
    /// Any other non-2xx from a schedule route.
    RequestFailed {
        verb: &'static str,
        status: u16,
        body: String,
    },
    /// Connect/decoding failure talking to the Worker.
    Transport(String),
}

impl fmt::Display for AgentScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentity(m) => write!(f, "invalid agent instance identity: {m}"),
            Self::InvalidTask(m) => write!(f, "invalid schedule task: {m}"),
            Self::LimitExceeded(m) => write!(f, "agent schedule limit exceeded: {m}"),
            Self::Denied(m) => write!(f, "agent schedule access denied: {m}"),
            Self::RequestFailed { verb, status, body } => {
                write!(f, "agent schedule {verb} failed: HTTP {status}: {body}")
            }
            Self::Transport(m) => write!(f, "agent schedule transport failed: {m}"),
        }
    }
}

impl Error for AgentScheduleError {}

/// One schedule row as reported by the Worker (create/list).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentScheduleRecord {
    /// Raw SDK schedule row id (`cf_agents_schedules.id`).
    pub id: String,
    /// FerroGate task key; `None` for rows FerroGate did not mint.
    #[serde(default)]
    pub task_id: Option<String>,
    /// FerroGate kind (`once`/`cron`/`interval`); `None` for foreign rows.
    #[serde(default)]
    pub kind: Option<String>,
    /// Raw SDK row type (`scheduled`/`delayed`/`cron`).
    pub sdk_type: String,
    /// The agent method the row calls back into (the pinned dispatcher).
    pub callback: String,
    /// Next execution time (epoch SECONDS — the SDK's unit), if known.
    #[serde(default)]
    pub time: Option<u64>,
    #[serde(default)]
    pub cron: Option<String>,
    #[serde(default)]
    pub every_seconds: Option<u64>,
    #[serde(default)]
    pub data: serde_json::Value,
}

/// Outcome of `schedule_create` (the duplicate guard reports what it replaced).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AgentScheduleCreated {
    pub instance: String,
    pub schedule: AgentScheduleRecord,
    /// Rows cancelled by the cancel-before-recreate guard (issue #1049).
    pub replaced: u64,
}

/// Outcome of `schedule_list`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AgentScheduleList {
    pub instance: String,
    pub schedules: Vec<AgentScheduleRecord>,
    pub count: u64,
}

/// Outcome of `schedule_cancel` — how many rows were actually removed.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AgentScheduleCancelOutcome {
    pub instance: String,
    pub cancelled: u64,
}

#[derive(Debug, Deserialize)]
struct ScheduleErrorBody {
    #[serde(default)]
    error: String,
    #[serde(default)]
    message: String,
}

fn validate_task_id(task_id: &str) -> Result<(), AgentScheduleError> {
    if task_id.is_empty() || task_id.len() > SCHEDULE_TASK_ID_MAX_LEN {
        return Err(AgentScheduleError::InvalidTask(format!(
            "task_id must be 1..={SCHEDULE_TASK_ID_MAX_LEN} characters"
        )));
    }
    if let Some(bad) = task_id
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
    {
        return Err(AgentScheduleError::InvalidTask(format!(
            "task_id contains {bad:?}; allowed: [A-Za-z0-9._-]"
        )));
    }
    Ok(())
}

/// Typed client for the gateway Worker's `/schedule/*` routes.
///
/// Reuses the synchronous [`GatewayControlTransport`] seam (and its production
/// block-on bridge) from the #413 control surface, and presents the same DIY
/// bearer credential — scheduling rides the exact governed channel the
/// lifecycle and memory verbs do.
pub struct AgentScheduleClient<T: GatewayControlTransport> {
    base_url: String,
    control_token: String,
    transport: T,
}

impl<T: GatewayControlTransport> AgentScheduleClient<T> {
    /// Build a schedule client for a Worker at `base_url` presenting
    /// `control_token`.
    pub fn new(
        base_url: impl Into<String>,
        control_token: impl Into<String>,
        transport: T,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            control_token: control_token.into(),
            transport,
        }
    }

    /// Borrow the underlying transport (tests inspect the mock through this).
    pub fn transport(&self) -> &T {
        &self.transport
    }

    fn post(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<HttpResponse, AgentScheduleError> {
        let bytes = serde_json::to_vec(&body)
            .map_err(|e| AgentScheduleError::Transport(format!("failed to encode body: {e}")))?;
        let url = format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        self.transport
            .send(HttpRequest {
                method: HttpMethod::Post,
                url,
                bearer_token: self.control_token.clone(),
                body: Some(bytes),
                content_type: None,
            })
            .map_err(|e| AgentScheduleError::Transport(e.to_string()))
    }

    fn call<R: for<'de> Deserialize<'de>>(
        &self,
        verb: &'static str,
        path: &str,
        body: serde_json::Value,
    ) -> Result<R, AgentScheduleError> {
        let response = self.post(path, body)?;
        if !(200..300).contains(&response.status) {
            return Err(map_error(verb, &response));
        }
        serde_json::from_slice(&response.body)
            .map_err(|e| AgentScheduleError::Transport(format!("failed to decode {verb}: {e}")))
    }

    fn instance_name(
        &self,
        identity: &AgentInstanceIdentity,
    ) -> Result<String, AgentScheduleError> {
        identity
            .instance_name()
            .map_err(|e| AgentScheduleError::InvalidIdentity(e.to_string()))
    }

    /// Schedule one task (once/cron/interval). The Worker cancels any
    /// existing rows for `task_id` first (cancel-before-recreate — the
    /// duplicate guard for github.com/cloudflare/agents #1049), so create is
    /// idempotent; `replaced` reports what the guard removed.
    pub fn schedule_create(
        &self,
        identity: &AgentInstanceIdentity,
        spec: &AgentScheduleTaskSpec,
    ) -> Result<AgentScheduleCreated, AgentScheduleError> {
        let instance = self.instance_name(identity)?;
        validate_task_id(&spec.task_id)?;
        let mut task = json!({
            "taskId": spec.task_id,
            "kind": spec.when.kind().as_wire(),
            "data": spec.data,
        });
        match &spec.when {
            AgentScheduleWhen::DelaySeconds(secs) => task["delaySeconds"] = json!(secs),
            AgentScheduleWhen::At(at) => task["at"] = json!(at),
            AgentScheduleWhen::Cron(cron) => {
                if cron.trim().is_empty() {
                    return Err(AgentScheduleError::InvalidTask(
                        "cron expression must not be empty".into(),
                    ));
                }
                task["cron"] = json!(cron);
            }
            AgentScheduleWhen::EverySeconds(secs) => {
                if *secs == 0 {
                    return Err(AgentScheduleError::InvalidTask(
                        "interval everySeconds must be >= 1".into(),
                    ));
                }
                task["everySeconds"] = json!(secs);
            }
        }
        self.call(
            "schedule_create",
            "schedule/create",
            json!({ "instance": instance, "task": task }),
        )
    }

    /// List the instance's schedule rows, optionally filtered by
    /// `task_id`/`kind` (filtering runs server-side in the Worker verb).
    pub fn schedule_list(
        &self,
        identity: &AgentInstanceIdentity,
        criteria: &AgentScheduleListCriteria,
    ) -> Result<AgentScheduleList, AgentScheduleError> {
        let instance = self.instance_name(identity)?;
        let mut body = json!({ "instance": instance });
        if let Some(task_id) = &criteria.task_id {
            body["taskId"] = json!(task_id);
        }
        if let Some(kind) = &criteria.kind {
            body["kind"] = json!(kind.as_wire());
        }
        self.call("schedule_list", "schedule/list", body)
    }

    /// Cancel by FerroGate task id (all rows for the task) or by one raw SDK
    /// schedule id. `cancelled` counts rows actually removed — cancelling a
    /// missing task/row is `Ok` with `cancelled == 0`, not an error.
    pub fn schedule_cancel(
        &self,
        identity: &AgentInstanceIdentity,
        selector: &AgentScheduleCancelSelector,
    ) -> Result<AgentScheduleCancelOutcome, AgentScheduleError> {
        let instance = self.instance_name(identity)?;
        let body = match selector {
            AgentScheduleCancelSelector::TaskId(task_id) => {
                validate_task_id(task_id)?;
                json!({ "instance": instance, "taskId": task_id })
            }
            AgentScheduleCancelSelector::ScheduleId(id) => {
                if id.is_empty() {
                    return Err(AgentScheduleError::InvalidTask(
                        "scheduleId must not be empty".into(),
                    ));
                }
                json!({ "instance": instance, "scheduleId": id })
            }
        };
        self.call("schedule_cancel", "schedule/cancel", body)
    }
}

/// Map a non-2xx schedule-route response onto the typed error vocabulary.
fn map_error(verb: &'static str, response: &HttpResponse) -> AgentScheduleError {
    let body_text = String::from_utf8_lossy(&response.body).into_owned();
    let parsed: ScheduleErrorBody =
        serde_json::from_slice(&response.body).unwrap_or(ScheduleErrorBody {
            error: String::new(),
            message: String::new(),
        });
    let detail = if parsed.message.is_empty() {
        body_text.clone()
    } else {
        parsed.message
    };
    match (response.status, parsed.error.as_str()) {
        (401 | 403, _) => {
            AgentScheduleError::Denied(format!("HTTP {}: {body_text}", response.status))
        }
        (422, _) | (_, "invalid_task") => AgentScheduleError::InvalidTask(detail),
        (429, _) | (_, "schedule_limit") => AgentScheduleError::LimitExceeded(detail),
        (status, _) => AgentScheduleError::RequestFailed {
            verb,
            status,
            body: body_text,
        },
    }
}

#[cfg(test)]
#[path = "cloudflare_agent_schedule_test.rs"]
mod tests;
