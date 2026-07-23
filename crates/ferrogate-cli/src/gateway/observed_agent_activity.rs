// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Admin agent-activity surface (#357): tenant-scoped "Unknown"
// running activity observed through a durable virtual API key that carries NO
// verified managed-worker session, self-hosted worker/run, or agent-run
// identity.
//
// SEMANTIC CONTRACT (do not soften): this is a third *presentation/source
// category*, NOT a third `WorkerType` and NOT a synthetic persistent Agent
// entity. One virtual key may be shared by many agents/SDKs/scripts/users, so
// the gateway cannot infer process identity or cardinality from the credential.
// The stable identity is the OBSERVED KEY ACTIVITY (`observed:<tenant>:<key>`),
// with `identity_status = unattributed` and `display_name = "Unknown"` -- it
// never claims exactly one real agent exists.
//
// This slice is READ/PRESENTATION-ONLY. Detection reuses evidence FerroGate
// already records on the request path (request logs + settled billing/metering
// events); it adds no new hot-path write, allocation, or synchronous storage
// work. `running` is derived from a recency window over that existing evidence.

use std::collections::{BTreeMap, HashMap, HashSet};

use http::{Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use serde::Serialize;

use ferrogate_storage::StoredRequestLog;

use super::{FerroGateway, ProxyContext};
use crate::{
    auth::authenticate,
    responses::{write_json_error, write_json_response, AdminList},
};

/// Environment override for the running-presence TTL (#357). Lets an operator
/// retune the window without editing/reloading the config file; when unset or
/// unparseable, the typed `observability.observed_activity_running_ttl_secs`
/// config value (default 60) is used. See
/// [`resolve_observed_activity_running_ttl_seconds`].
pub(crate) const OBSERVED_ACTIVITY_RUNNING_TTL_ENV: &str =
    "FERROGATE_OBSERVED_ACTIVITY_RUNNING_TTL_SECONDS";

/// Resolve the effective running-presence TTL: a key whose most recent observed
/// request is within this many seconds is reported `running`; older evidence
/// expires to `inactive` automatically (it never fabricates a stop event). The
/// value is surfaced on every row as `running_ttl_seconds` so the window is
/// operator-visible.
///
/// Precedence: a well-formed, positive env override wins; otherwise the typed
/// config value is used as-is. A zero/blank/garbage env value is ignored (a
/// zero TTL would report every key inactive) rather than silently clamping the
/// operator's config choice -- explicit config wins over a malformed override.
pub(crate) fn resolve_observed_activity_running_ttl_seconds(
    config_value: u64,
    env_value: Option<&str>,
) -> u64 {
    match env_value.map(str::trim) {
        Some(raw) if !raw.is_empty() => match raw.parse::<u64>() {
            Ok(parsed) if parsed > 0 => parsed,
            _ => config_value,
        },
        _ => config_value,
    }
}

// Contract-level constants. These strings are part of the API surface: the UI
// and other consumers key off them to keep the trust levels distinct.
const OBSERVED_SOURCE_VIRTUAL_API_KEY: &str = "virtual_api_key";
const OBSERVED_IDENTITY_STATUS_UNATTRIBUTED: &str = "unattributed";
const OBSERVED_DISPLAY_NAME_UNKNOWN: &str = "Unknown";
const OBSERVED_STATUS_BASIS: &str = "recent_api_key_activity";
const OBSERVED_STATUS_RUNNING: &str = "running";
const OBSERVED_STATUS_INACTIVE: &str = "inactive";
const OBSERVED_EVIDENCE_SOURCE: &str = "request_logs";

/// One observed-unattributed-activity row. This is a presentation view, not a
/// stored entity: it is re-derived from evidence on every read.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct ObservedAgentActivity {
    /// Stable identity of the OBSERVED ACTIVITY (`observed:<tenant>:<key>`),
    /// deliberately NOT a per-process/agent UUID.
    pub(crate) id: String,
    pub(crate) source: &'static str,
    pub(crate) identity_status: &'static str,
    pub(crate) display_name: &'static str,
    pub(crate) status: &'static str,
    pub(crate) status_basis: &'static str,
    pub(crate) tenant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) workspace_id: Option<String>,
    pub(crate) api_key_id: String,
    /// Redacted operator hint (the virtual key's name) the tenant is already
    /// authorized to view. NEVER the inferred agent name. Absent when the key
    /// record cannot be resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) credential_name: Option<String>,
    pub(crate) first_seen_at_unix: u64,
    pub(crate) last_seen_at_unix: u64,
    pub(crate) running_ttl_seconds: u64,
    /// Inspectable evidence for the operational decision (AGENTS.md: do not
    /// hide the "why is this Unknown running" answer).
    pub(crate) evidence: ObservedAgentActivityEvidence,
}

/// The evidence that justifies the row's `status`. Makes the recency decision
/// auditable instead of an opaque flag.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct ObservedAgentActivityEvidence {
    pub(crate) evidence_source: &'static str,
    pub(crate) request_count: u64,
    pub(crate) seconds_since_last_seen: u64,
    pub(crate) running_ttl_seconds: u64,
    pub(crate) within_running_window: bool,
    /// #357: whether the durable presence store contributed the recency used
    /// for the `running` decision (its last-seen was at least as fresh as the
    /// request-log evidence). Makes the "which signal decided running" answer
    /// inspectable rather than an opaque merge.
    pub(crate) durable_presence_backed: bool,
    /// Token/cost activity for the SAME key+requests, folded from settled
    /// billing/metering evidence. `None`/`false` when no such evidence exists
    /// for the observed requests -- shown as unavailable, never invented.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) prompt_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) completion_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) total_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cost_usd: Option<f64>,
    pub(crate) usage_evidence_available: bool,
    pub(crate) reason: String,
}

/// Token/cost contribution of a single settled request, keyed by request_id.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct UsageContribution {
    pub(crate) prompt_tokens: u64,
    pub(crate) completion_tokens: u64,
    pub(crate) total_tokens: u64,
    pub(crate) cost_usd: Option<f64>,
}

/// Inputs for the pure detection pass. All evidence is already recorded; this
/// function only reads it.
pub(crate) struct ObservedActivityInputs<'a> {
    /// Recorded request logs (the recency + request-count evidence).
    pub(crate) request_logs: &'a [StoredRequestLog],
    /// Run ids attributed to a VERIFIED execution identity (managed-worker
    /// session, self-hosted run dispatch, or a recorded agent run). A request
    /// whose `agent_run_id` is in this set is attributed and never surfaced as
    /// Unknown. A caller-supplied `agent_run_id` that matches no recorded run
    /// is NOT in this set, so spoofed headers cannot suppress the row.
    pub(crate) attributed_run_ids: &'a HashSet<String>,
    /// Token/cost contribution per request_id, from settled billing/metering.
    pub(crate) usage_by_request_id: &'a HashMap<String, UsageContribution>,
    /// `api_key_id` -> redacted credential hint (the key's name).
    pub(crate) credential_names: &'a HashMap<String, String>,
    /// Durable coalesced presence (#357): `(tenant_id, api_key_id)` -> the MAX
    /// last-seen timestamp recorded by the presence store. This is the durable,
    /// cheaply-updated recency signal that backs the `running` decision, so the
    /// window survives request-log retention pruning and does not depend on a
    /// full request-log scan. Attribution and token/cost evidence still come
    /// from `request_logs`/`usage_by_request_id`; presence only refines
    /// recency. A group with no presence row falls back to its request-log
    /// last-seen.
    pub(crate) presence_last_seen: &'a HashMap<(String, String), u64>,
    /// When `Some`, only this tenant's activity is considered (tenant-scoped
    /// caller). `None` is the platform operator's cross-tenant view.
    pub(crate) tenant_scope: Option<&'a str>,
    pub(crate) now_unix: u64,
    pub(crate) running_ttl_seconds: u64,
}

#[derive(Default)]
struct ObservedActivityAccumulator {
    project_id: Option<String>,
    workspace_id: Option<String>,
    first_seen: u64,
    last_seen: u64,
    request_count: u64,
    prompt_tokens: u64,
    completion_tokens: u64,
    total_tokens: u64,
    cost_usd: f64,
    cost_evidence: bool,
    usage_evidence: bool,
}

/// Derive the observed unattributed-activity rows from already-recorded
/// evidence. Pure and deterministic: `now_unix` is injected so recency/TTL
/// behavior is testable without sleeps.
pub(crate) fn derive_observed_agent_activity(
    inputs: &ObservedActivityInputs<'_>,
) -> Vec<ObservedAgentActivity> {
    // Keyed (tenant_id, api_key_id); BTreeMap gives a stable base order before
    // the final recency sort.
    let mut groups: BTreeMap<(String, String), ObservedActivityAccumulator> = BTreeMap::new();

    for log in inputs.request_logs {
        // Out of scope: a durable virtual key always resolves to a tenant
        // owner. YAML/static keys without a durable tenant owner are excluded.
        let Some(tenant_id) = log.tenant.organization_id.as_deref() else {
            continue;
        };
        if tenant_id.is_empty() {
            continue;
        }
        // Tenant isolation (defense in depth; the caller is already scoped).
        if let Some(scope) = inputs.tenant_scope {
            if scope != tenant_id {
                continue;
            }
        }
        let Some(api_key_id) = log.tenant.api_key_id.as_deref() else {
            continue;
        };
        if api_key_id.is_empty() {
            continue;
        }
        // Attribution precedence: a verified managed/self-hosted/agent-run
        // identity owns this traffic, so it keeps that identity and is never
        // duplicated as Unknown.
        if let Some(run_id) = log.agent_run_id.as_deref() {
            if inputs.attributed_run_ids.contains(run_id) {
                continue;
            }
        }
        // Need at least one timestamp to reason about recency; a log with no
        // temporal evidence cannot justify `running`.
        let Some(last_candidate) = log.completed_at_unix.or(log.started_at_unix) else {
            continue;
        };
        let first_candidate = log
            .started_at_unix
            .or(log.completed_at_unix)
            .unwrap_or(last_candidate);

        let entry = groups
            .entry((tenant_id.to_string(), api_key_id.to_string()))
            .or_insert_with(|| ObservedActivityAccumulator {
                first_seen: first_candidate,
                last_seen: last_candidate,
                ..ObservedActivityAccumulator::default()
            });
        entry.first_seen = entry.first_seen.min(first_candidate);
        entry.last_seen = entry.last_seen.max(last_candidate);
        entry.request_count = entry.request_count.saturating_add(1);
        // Fill scope hints from the first log that carries them; never
        // overwrite a present value with an absent one.
        if entry.project_id.is_none() {
            entry.project_id = log.tenant.project_id.clone();
        }
        if entry.workspace_id.is_none() {
            entry.workspace_id = log.tenant.workspace_id.clone();
        }
        if let Some(usage) = inputs.usage_by_request_id.get(&log.request_id) {
            entry.usage_evidence = true;
            entry.prompt_tokens = entry.prompt_tokens.saturating_add(usage.prompt_tokens);
            entry.completion_tokens = entry
                .completion_tokens
                .saturating_add(usage.completion_tokens);
            entry.total_tokens = entry.total_tokens.saturating_add(usage.total_tokens);
            if let Some(cost) = usage.cost_usd {
                entry.cost_evidence = true;
                entry.cost_usd += cost;
            }
        }
    }

    let mut rows: Vec<ObservedAgentActivity> = groups
        .into_iter()
        .map(|((tenant_id, api_key_id), acc)| {
            // Refine recency with the durable presence signal: the running
            // decision uses the FRESHER of the request-log last-seen and the
            // durable presence last-seen. Presence survives request-log
            // retention pruning and is a single-row upsert, so it is the
            // authoritative recency source when it is at least as fresh.
            let presence_last_seen = inputs
                .presence_last_seen
                .get(&(tenant_id.clone(), api_key_id.clone()))
                .copied()
                .unwrap_or(0);
            let durable_presence_backed = presence_last_seen >= acc.last_seen;
            let effective_last_seen = acc.last_seen.max(presence_last_seen);
            let seconds_since_last_seen = inputs.now_unix.saturating_sub(effective_last_seen);
            let within_running_window = seconds_since_last_seen <= inputs.running_ttl_seconds;
            let status = if within_running_window {
                OBSERVED_STATUS_RUNNING
            } else {
                OBSERVED_STATUS_INACTIVE
            };
            let reason = if within_running_window {
                format!(
                    "observed {} request(s) authenticated by this virtual API key with no verified \
                     managed/self-hosted/agent-run identity; last seen {}s ago is within the {}s \
                     running window",
                    acc.request_count, seconds_since_last_seen, inputs.running_ttl_seconds
                )
            } else {
                format!(
                    "last observed {}s ago, beyond the {}s running window; reported inactive (no \
                     stop event is fabricated)",
                    seconds_since_last_seen, inputs.running_ttl_seconds
                )
            };
            let credential_name = inputs.credential_names.get(&api_key_id).cloned();
            let evidence = ObservedAgentActivityEvidence {
                evidence_source: OBSERVED_EVIDENCE_SOURCE,
                request_count: acc.request_count,
                seconds_since_last_seen,
                running_ttl_seconds: inputs.running_ttl_seconds,
                within_running_window,
                durable_presence_backed,
                prompt_tokens: acc.usage_evidence.then_some(acc.prompt_tokens),
                completion_tokens: acc.usage_evidence.then_some(acc.completion_tokens),
                total_tokens: acc.usage_evidence.then_some(acc.total_tokens),
                cost_usd: acc.cost_evidence.then_some(acc.cost_usd),
                usage_evidence_available: acc.usage_evidence,
                reason,
            };
            ObservedAgentActivity {
                id: format!("observed:{tenant_id}:{api_key_id}"),
                source: OBSERVED_SOURCE_VIRTUAL_API_KEY,
                identity_status: OBSERVED_IDENTITY_STATUS_UNATTRIBUTED,
                display_name: OBSERVED_DISPLAY_NAME_UNKNOWN,
                status,
                status_basis: OBSERVED_STATUS_BASIS,
                tenant_id,
                project_id: acc.project_id,
                workspace_id: acc.workspace_id,
                api_key_id,
                credential_name,
                first_seen_at_unix: acc.first_seen,
                last_seen_at_unix: effective_last_seen,
                running_ttl_seconds: inputs.running_ttl_seconds,
                evidence,
            }
        })
        .collect();

    // Most recently observed first; stable tiebreak on the observed id.
    rows.sort_by(|left, right| {
        right
            .last_seen_at_unix
            .cmp(&left.last_seen_at_unix)
            .then_with(|| left.id.cmp(&right.id))
    });
    rows
}

impl FerroGateway {
    /// `GET /admin/v1/observed-agent-activity`: tenant-scoped list of Unknown
    /// (unattributed virtual-API-key) activity, presented alongside -- but
    /// never conflated with -- real managed/self-hosted worker identities.
    pub(super) async fn handle_admin_observed_agent_activity(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        if method != Method::GET {
            return write_json_error(
                session,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "observed agent-activity visibility supports GET only",
                &ctx.request_id,
            )
            .await;
        }
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(auth) => {
                // Tenant isolation BEFORE pagination/aggregation: a tenant-scoped
                // caller only ever sees its own tenant's observed activity; the
                // platform operator (organization_id == None) gets the
                // cross-tenant view.
                let rows = state.observed_agent_activity(auth.organization_id.as_deref());
                let pagination = state.admin_pagination(query);
                let total = rows.len();
                let data = rows
                    .into_iter()
                    .skip(pagination.offset)
                    .take(pagination.limit)
                    .collect();
                let body = AdminList::paginated(data, total, pagination.offset, pagination.limit);
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }
}

#[cfg(test)]
#[path = "observed_agent_activity_test.rs"]
mod observed_agent_activity_test;
