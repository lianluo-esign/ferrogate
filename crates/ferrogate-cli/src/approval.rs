// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use blake2::{Blake2b512, Digest};
use ferrogate_core::{ApprovalPolicy, TenantContext};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Notify;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

impl ApprovalStatus {
    pub(crate) fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ToolApprovalRecord {
    pub(crate) id: String,
    pub(crate) request_id: String,
    pub(crate) trace_id: Option<String>,
    /// #305 correlation context (all optional; absent on records persisted
    /// before the fields existed and on approvals created outside an agent
    /// run / workflow execution). `serde(default)` keeps legacy persisted
    /// records readable; `skip_serializing_if` keeps legacy JSON byte-stable.
    /// Deliberately NOT part of `fingerprint_for` — the invocation-level
    /// approval binding fingerprint is unchanged by these fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) agent_run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) workflow_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) workflow_node_id: Option<String>,
    pub(crate) tenant: TenantContext,
    pub(crate) actor_api_key_id: Option<String>,
    pub(crate) tool_name: String,
    pub(crate) server_name: Option<String>,
    pub(crate) route: Option<String>,
    pub(crate) approval_policy: ApprovalPolicy,
    pub(crate) approval_timeout_secs: u64,
    pub(crate) fingerprint: String,
    pub(crate) arguments_summary: String,
    pub(crate) risk_reason: String,
    pub(crate) status: ApprovalStatus,
    pub(crate) reviewer_api_key_id: Option<String>,
    pub(crate) reviewer_authority: Option<String>,
    pub(crate) terminal_reason: Option<String>,
    pub(crate) requested_at_unix: u64,
    pub(crate) expires_at_unix: u64,
    pub(crate) decided_at_unix: Option<u64>,
}

#[derive(Debug, Clone)]
pub(crate) struct ToolApprovalDraft {
    pub(crate) request_id: String,
    pub(crate) trace_id: Option<String>,
    /// #305 correlation context from the tool-governance execution context
    /// (`ToolExecutionContext`). Carried onto the record verbatim; NEVER part
    /// of the fingerprint input.
    pub(crate) agent_run_id: Option<String>,
    pub(crate) workflow_id: Option<String>,
    pub(crate) workflow_node_id: Option<String>,
    pub(crate) tenant: TenantContext,
    pub(crate) actor_api_key_id: Option<String>,
    pub(crate) tool_name: String,
    pub(crate) server_name: Option<String>,
    pub(crate) route: Option<String>,
    pub(crate) approval_policy: ApprovalPolicy,
    pub(crate) approval_timeout_secs: u64,
    pub(crate) config_snapshot: String,
    pub(crate) arguments: Value,
    pub(crate) can_log_bodies: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ToolApprovalDecisionRequest {
    #[serde(default)]
    pub(crate) fingerprint: Option<String>,
    #[serde(default)]
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ApprovalRegistry {
    inner: Arc<Mutex<HashMap<String, ApprovalEntry>>>,
    next_id: Arc<AtomicU64>,
}

#[derive(Debug, Clone)]
struct ApprovalEntry {
    record: ToolApprovalRecord,
    notify: Arc<Notify>,
}

#[derive(Debug, Clone)]
pub(crate) enum ApprovalDecisionError {
    NotFound(String),
    FingerprintMismatch {
        id: String,
        expected: String,
        provided: String,
    },
    Terminal(Box<ToolApprovalRecord>),
}

#[derive(Debug, Clone)]
pub(crate) enum ApprovalWaitError {
    NotFound(String),
}

impl ApprovalRegistry {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    pub(crate) fn create_pending(&self, draft: ToolApprovalDraft) -> ToolApprovalRecord {
        let now = now_unix_seconds();
        let expires_at = now.saturating_add(draft.approval_timeout_secs.max(1));
        let id = format!(
            "approval-{:016x}",
            self.next_id.fetch_add(1, Ordering::Relaxed)
        );
        let fingerprint = fingerprint_for(&draft);
        let arguments_summary = summarize_arguments(&draft.arguments, draft.can_log_bodies);
        let record = ToolApprovalRecord {
            id: id.clone(),
            request_id: draft.request_id,
            trace_id: draft.trace_id,
            agent_run_id: draft.agent_run_id,
            workflow_id: draft.workflow_id,
            workflow_node_id: draft.workflow_node_id,
            tenant: draft.tenant,
            actor_api_key_id: draft.actor_api_key_id,
            tool_name: draft.tool_name,
            server_name: draft.server_name,
            route: draft.route,
            approval_policy: draft.approval_policy,
            approval_timeout_secs: draft.approval_timeout_secs.max(1),
            fingerprint,
            arguments_summary,
            risk_reason: approval_risk_reason(draft.approval_policy),
            status: ApprovalStatus::Pending,
            reviewer_api_key_id: None,
            reviewer_authority: None,
            terminal_reason: None,
            requested_at_unix: now,
            expires_at_unix: expires_at,
            decided_at_unix: None,
        };
        let entry = ApprovalEntry {
            record: record.clone(),
            notify: Arc::new(Notify::new()),
        };
        if let Ok(mut inner) = self.inner.lock() {
            inner.insert(id, entry);
        }
        record
    }

    pub(crate) fn list(&self) -> Vec<ToolApprovalRecord> {
        self.inner
            .lock()
            .map(|inner| inner.values().map(|entry| entry.record.clone()).collect())
            .unwrap_or_default()
    }

    pub(crate) fn get(&self, id: &str) -> Option<ToolApprovalRecord> {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.get(id).map(|entry| entry.record.clone()))
    }

    pub(crate) fn approve(
        &self,
        id: &str,
        fingerprint: &str,
        reviewer_api_key_id: Option<String>,
        reason: Option<String>,
    ) -> Result<ToolApprovalRecord, ApprovalDecisionError> {
        self.decision(
            id,
            Some(fingerprint),
            ApprovalStatus::Approved,
            reviewer_api_key_id,
            reason,
        )
    }

    pub(crate) fn deny(
        &self,
        id: &str,
        reviewer_api_key_id: Option<String>,
        reason: Option<String>,
    ) -> Result<ToolApprovalRecord, ApprovalDecisionError> {
        self.decision(
            id,
            None,
            ApprovalStatus::Denied,
            reviewer_api_key_id,
            reason,
        )
    }

    pub(crate) fn expire(
        &self,
        id: &str,
        reviewer_api_key_id: Option<String>,
        reason: Option<String>,
    ) -> Result<ToolApprovalRecord, ApprovalDecisionError> {
        self.decision(
            id,
            None,
            ApprovalStatus::Expired,
            reviewer_api_key_id,
            reason,
        )
    }

    pub(crate) async fn wait_for_resolution(
        &self,
        id: &str,
        timeout: Duration,
    ) -> Result<ToolApprovalRecord, ApprovalWaitError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        loop {
            let (record, notify) = {
                let mut inner = self
                    .inner
                    .lock()
                    .map_err(|_| ApprovalWaitError::NotFound(id.to_string()))?;
                let Some(entry) = inner.get_mut(id) else {
                    return Err(ApprovalWaitError::NotFound(id.to_string()));
                };
                if entry.record.status.is_terminal() {
                    return Ok(entry.record.clone());
                }
                if now_unix_seconds() >= entry.record.expires_at_unix {
                    entry.record.status = ApprovalStatus::Expired;
                    entry.record.decided_at_unix = Some(now_unix_seconds());
                    entry.record.terminal_reason = Some("approval_expired".into());
                    let record = entry.record.clone();
                    entry.notify.notify_waiters();
                    return Ok(record);
                }
                (entry.record.clone(), Arc::clone(&entry.notify))
            };

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return self
                    .expire_pending(id)
                    .ok_or_else(|| ApprovalWaitError::NotFound(id.into()));
            }
            if tokio::time::timeout(remaining, notify.notified())
                .await
                .is_err()
            {
                return self
                    .expire_pending(id)
                    .ok_or_else(|| ApprovalWaitError::NotFound(id.into()));
            }
            if record.status.is_terminal() {
                return Ok(record);
            }
        }
    }

    fn decision(
        &self,
        id: &str,
        fingerprint: Option<&str>,
        status: ApprovalStatus,
        reviewer_api_key_id: Option<String>,
        reason: Option<String>,
    ) -> Result<ToolApprovalRecord, ApprovalDecisionError> {
        let now = now_unix_seconds();
        let mut inner = self.inner.lock().map_err(|_| {
            ApprovalDecisionError::NotFound(format!("approval {id} is unavailable"))
        })?;
        let Some(entry) = inner.get_mut(id) else {
            return Err(ApprovalDecisionError::NotFound(format!(
                "approval {id} was not found"
            )));
        };
        if entry.record.status.is_terminal() {
            return Err(ApprovalDecisionError::Terminal(Box::new(
                entry.record.clone(),
            )));
        }
        if now >= entry.record.expires_at_unix {
            entry.record.status = ApprovalStatus::Expired;
            entry.record.reviewer_api_key_id = reviewer_api_key_id;
            entry.record.reviewer_authority = Some("admin.write".into());
            entry.record.terminal_reason = Some("approval_expired".into());
            entry.record.decided_at_unix = Some(now);
            let record = entry.record.clone();
            entry.notify.notify_waiters();
            return Err(ApprovalDecisionError::Terminal(Box::new(record)));
        }
        if let Some(provided) = fingerprint {
            if entry.record.fingerprint != provided {
                entry.record.status = ApprovalStatus::Denied;
                entry.record.reviewer_api_key_id = reviewer_api_key_id;
                entry.record.reviewer_authority = Some("admin.write".into());
                entry.record.terminal_reason = Some("approval_fingerprint_mismatch".into());
                entry.record.decided_at_unix = Some(now);
                let record = entry.record.clone();
                entry.notify.notify_waiters();
                return Err(ApprovalDecisionError::FingerprintMismatch {
                    id: id.to_string(),
                    expected: record.fingerprint,
                    provided: provided.to_string(),
                });
            }
        }
        entry.record.status = status;
        entry.record.reviewer_api_key_id = reviewer_api_key_id;
        entry.record.reviewer_authority = Some("admin.write".into());
        entry.record.terminal_reason = Some(reason.unwrap_or_else(|| match status {
            ApprovalStatus::Approved => "approval_granted".into(),
            ApprovalStatus::Denied => "approval_denied".into(),
            ApprovalStatus::Expired => "approval_expired".into(),
            ApprovalStatus::Pending => "approval_pending".into(),
        }));
        entry.record.decided_at_unix = Some(now);
        let record = entry.record.clone();
        entry.notify.notify_waiters();
        Ok(record)
    }

    fn expire_pending(&self, id: &str) -> Option<ToolApprovalRecord> {
        let now = now_unix_seconds();
        let mut inner = self.inner.lock().ok()?;
        let entry = inner.get_mut(id)?;
        if entry.record.status.is_terminal() {
            return Some(entry.record.clone());
        }
        entry.record.status = ApprovalStatus::Expired;
        entry.record.decided_at_unix = Some(now);
        entry.record.terminal_reason = Some("approval_expired".into());
        let record = entry.record.clone();
        entry.notify.notify_waiters();
        Some(record)
    }
}

fn approval_risk_reason(policy: ApprovalPolicy) -> String {
    match policy {
        ApprovalPolicy::Never => "approval_policy=never".into(),
        ApprovalPolicy::Always => "approval_policy=always".into(),
    }
}

fn summarize_arguments(arguments: &Value, can_log_bodies: bool) -> String {
    if can_log_bodies {
        let canonical = canonicalize_json(arguments);
        serde_json::to_string(&canonical).unwrap_or_else(|_| "[unserializable]".into())
    } else {
        redact_json(arguments)
    }
}

fn redact_json(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(_) => "\"[REDACTED]\"".into(),
        Value::Number(_) => "\"[REDACTED]\"".into(),
        Value::String(_) => "\"[REDACTED]\"".into(),
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(redact_json).collect::<Vec<_>>().join(",")
        ),
        Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            let rendered = entries
                .into_iter()
                .map(|(key, value)| format!("\"{key}\":{}", redact_json(value)))
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{rendered}}}")
        }
    }
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize_json).collect()),
        Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            let mut canonical = serde_json::Map::new();
            for (key, value) in entries {
                canonical.insert(key.clone(), canonicalize_json(value));
            }
            Value::Object(canonical)
        }
        _ => value.clone(),
    }
}

/// INVOCATION-level approval binding fingerprint (issue #303 two-level
/// contract): Blake2b512 over the canonicalized 9-field invocation struct
/// below, binding one granted approval to one concrete invocation including
/// its arguments and config snapshot. This is deliberately DISTINCT from the
/// TARGET-level `canonical_target_sha256` action fingerprint
/// (`ferrogate_runtime::ActionIdentity::action_fingerprint`), which identifies
/// the external action independent of caller and arguments. Both keep their
/// semantics; see `ferrogate_runtime::action_identity` module docs.
fn fingerprint_for(draft: &ToolApprovalDraft) -> String {
    #[derive(Serialize)]
    struct FingerprintInput<'a> {
        request_id: &'a str,
        trace_id: &'a Option<String>,
        tenant: &'a TenantContext,
        actor_api_key_id: &'a Option<String>,
        tool_name: &'a str,
        server_name: &'a Option<String>,
        route: &'a Option<String>,
        approval_policy: ApprovalPolicy,
        config_snapshot: &'a str,
        arguments: Value,
    }

    let input = FingerprintInput {
        request_id: &draft.request_id,
        trace_id: &draft.trace_id,
        tenant: &draft.tenant,
        actor_api_key_id: &draft.actor_api_key_id,
        tool_name: &draft.tool_name,
        server_name: &draft.server_name,
        route: &draft.route,
        approval_policy: draft.approval_policy,
        config_snapshot: &draft.config_snapshot,
        arguments: canonicalize_json(&draft.arguments),
    };
    let bytes = serde_json::to_vec(&input).expect("approval fingerprint serialization");
    let mut hasher = Blake2b512::new();
    hasher.update(bytes);
    format!(
        "{:016x}",
        u64::from_be_bytes(hasher.finalize()[..8].try_into().unwrap())
    )
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Lossless mapping into the canonical governance decision (issue #303). The
/// impl lives here — next to the source vocabulary — because ferrogate-cli
/// depends on ferrogate-runtime, never the reverse.
///
/// * `Pending` → `ask` (`approval_pending`): the gate is open, awaiting a
///   reviewer.
/// * `Approved` → `allow` (`approval_approved`).
/// * `Denied` → `deny` (`approval_denied`).
/// * `Expired` → `deny` (`approval_expired`): the window elapsed without a
///   grant, which is a terminal refusal at the chokepoint. `Denied` and
///   `Expired` collapse onto `deny` but stay distinguishable (lossless) via
///   the reason code — see [`approval_status_from_action_decision`].
impl From<ApprovalStatus> for ferrogate_runtime::ActionDecision {
    fn from(status: ApprovalStatus) -> Self {
        use ferrogate_runtime::decision_codes;
        match status {
            ApprovalStatus::Pending => Self::ask(decision_codes::APPROVAL_PENDING),
            ApprovalStatus::Approved => Self::allow(decision_codes::APPROVAL_APPROVED),
            ApprovalStatus::Denied => Self::deny(decision_codes::APPROVAL_DENIED),
            ApprovalStatus::Expired => Self::deny(decision_codes::APPROVAL_EXPIRED),
        }
    }
}

/// Reverse of `From<ApprovalStatus> for ActionDecision`, keyed on the reason
/// code. Returns `None` for decisions that did not originate from an approval
/// status.
#[allow(dead_code)] // consumed by #306 (guardrails/approvals adoption); tested below
pub(crate) fn approval_status_from_action_decision(
    decision: &ferrogate_runtime::ActionDecision,
) -> Option<ApprovalStatus> {
    use ferrogate_runtime::decision_codes;
    match decision.code() {
        decision_codes::APPROVAL_PENDING => Some(ApprovalStatus::Pending),
        decision_codes::APPROVAL_APPROVED => Some(ApprovalStatus::Approved),
        decision_codes::APPROVAL_DENIED => Some(ApprovalStatus::Denied),
        decision_codes::APPROVAL_EXPIRED => Some(ApprovalStatus::Expired),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrogate_runtime::{decision_codes, ActionDecision};

    fn fingerprint_regression_draft(
        agent_run_id: Option<&str>,
        workflow_id: Option<&str>,
        workflow_node_id: Option<&str>,
    ) -> ToolApprovalDraft {
        ToolApprovalDraft {
            request_id: "fg-fingerprint-regression".into(),
            trace_id: Some("trace-fingerprint-regression".into()),
            agent_run_id: agent_run_id.map(str::to_string),
            workflow_id: workflow_id.map(str::to_string),
            workflow_node_id: workflow_node_id.map(str::to_string),
            tenant: TenantContext {
                organization_id: Some("org-1".into()),
                team_id: None,
                project_id: Some("proj-1".into()),
                workspace_id: Some("ws-1".into()),
                user_id: None,
                api_key_id: Some("key-1".into()),
            },
            actor_api_key_id: Some("key-1".into()),
            tool_name: "github.search".into(),
            server_name: Some("mcp.github".into()),
            route: Some("tools.execute".into()),
            approval_policy: ApprovalPolicy::Always,
            approval_timeout_secs: 60,
            config_snapshot: "config-snapshot-regression".into(),
            arguments: serde_json::json!({"query": "ferrogate", "page": 2}),
            can_log_bodies: false,
        }
    }

    /// #305 regression: the invocation-level approval binding fingerprint must
    /// stay byte-identical after the correlation fields were added. The pinned
    /// literal was captured by running `fingerprint_for` on this exact draft
    /// BEFORE `agent_run_id`/`workflow_id`/`workflow_node_id` existed on
    /// `ToolApprovalDraft`; any drift here breaks the fingerprint binding of
    /// already-granted approvals.
    #[test]
    fn approval_fingerprint_is_byte_identical_to_pre_correlation_contract() {
        let draft = fingerprint_regression_draft(None, None, None);
        assert_eq!(fingerprint_for(&draft), "8b1210f2fe1c907a");
    }

    /// #305: the correlation context fields must not influence the approval
    /// fingerprint — an approval created inside an agent run binds to exactly
    /// the same invocation fingerprint as one created outside it.
    #[test]
    fn approval_fingerprint_ignores_correlation_context_fields() {
        let without_context = fingerprint_regression_draft(None, None, None);
        let with_context =
            fingerprint_regression_draft(Some("run-1"), Some("workflow-1"), Some("node-1"));
        assert_eq!(
            fingerprint_for(&without_context),
            fingerprint_for(&with_context)
        );
        assert_eq!(fingerprint_for(&with_context), "8b1210f2fe1c907a");
    }

    /// #305 backward compatibility: a persisted approval record from before
    /// the correlation fields deserializes with the fields defaulted to None,
    /// and a record without them serializes byte-stable (no new keys).
    #[test]
    fn approval_record_json_is_backward_compatible_with_legacy_records() {
        let legacy = serde_json::json!({
            "id": "approval-1",
            "request_id": "fg-legacy",
            "trace_id": null,
            "tenant": TenantContext::default(),
            "actor_api_key_id": null,
            "tool_name": "tool.echo",
            "server_name": null,
            "route": null,
            "approval_policy": "always",
            "approval_timeout_secs": 60,
            "fingerprint": "deadbeefdeadbeef",
            "arguments_summary": "{}",
            "risk_reason": "approval_policy=always",
            "status": "pending",
            "reviewer_api_key_id": null,
            "reviewer_authority": null,
            "terminal_reason": null,
            "requested_at_unix": 1,
            "expires_at_unix": 2,
            "decided_at_unix": null
        });
        let record: ToolApprovalRecord = serde_json::from_value(legacy).unwrap();
        assert_eq!(record.agent_run_id, None);
        assert_eq!(record.workflow_id, None);
        assert_eq!(record.workflow_node_id, None);
        let serialized = serde_json::to_value(&record).unwrap();
        assert!(serialized.get("agent_run_id").is_none());
        assert!(serialized.get("workflow_id").is_none());
        assert!(serialized.get("workflow_node_id").is_none());
    }

    #[test]
    fn approval_status_maps_losslessly_to_canonical_action_decision() {
        for status in [
            ApprovalStatus::Pending,
            ApprovalStatus::Approved,
            ApprovalStatus::Denied,
            ApprovalStatus::Expired,
        ] {
            let canonical = ActionDecision::from(status);
            assert_eq!(
                approval_status_from_action_decision(&canonical),
                Some(status),
                "status {status:?} must round-trip through the canonical decision"
            );
        }
    }

    #[test]
    fn approval_status_decision_classes_and_codes() {
        assert_eq!(
            ActionDecision::from(ApprovalStatus::Pending),
            ActionDecision::ask(decision_codes::APPROVAL_PENDING)
        );
        assert_eq!(
            ActionDecision::from(ApprovalStatus::Approved),
            ActionDecision::allow(decision_codes::APPROVAL_APPROVED)
        );
        // Denied and Expired both refuse, but remain distinguishable by code.
        let denied = ActionDecision::from(ApprovalStatus::Denied);
        let expired = ActionDecision::from(ApprovalStatus::Expired);
        assert!(matches!(denied, ActionDecision::Deny { .. }));
        assert!(matches!(expired, ActionDecision::Deny { .. }));
        assert_ne!(denied.code(), expired.code());
        // Foreign codes never masquerade as approval statuses.
        assert_eq!(
            approval_status_from_action_decision(&ActionDecision::deny(
                decision_codes::CAPABILITY_DENIED
            )),
            None
        );
    }
}
