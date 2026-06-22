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
