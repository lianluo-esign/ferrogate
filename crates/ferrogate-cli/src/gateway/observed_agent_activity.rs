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
/// `status_basis` for a row whose status could NOT be decided because the
/// durable presence feed did not answer (#494). Distinct from
/// [`OBSERVED_STATUS_BASIS`] so a consumer can tell "we looked and it is not
/// recent" from "we could not look".
const OBSERVED_STATUS_BASIS_PRESENCE_UNAVAILABLE: &str = "presence_feed_unavailable";
const OBSERVED_STATUS_RUNNING: &str = "running";
const OBSERVED_STATUS_INACTIVE: &str = "inactive";
/// Third, honest status (#494): the recency evidence available is not enough to
/// decide. NEVER collapse this into `inactive` -- an operator who reads
/// "inactive" for a process that is in fact running may restart it.
const OBSERVED_STATUS_UNKNOWN: &str = "unknown";
const OBSERVED_PRESENCE_FEED_AVAILABLE: &str = "available";
const OBSERVED_PRESENCE_FEED_UNAVAILABLE: &str = "unavailable";
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
    /// `running` | `inactive` | `unknown`. `unknown` (#494) is a real answer,
    /// not a fallback: it is emitted when the durable presence feed failed to
    /// answer and the request-log evidence alone cannot decide.
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
    /// Freshest recency actually observed. When
    /// `evidence.presence_feed_status == "unavailable"` this is a LOWER BOUND:
    /// the durable presence feed could only ever have reported something
    /// fresher, so the true last-seen may be later than this value.
    pub(crate) last_seen_at_unix: u64,
    pub(crate) running_ttl_seconds: u64,
    /// Inspectable evidence for the operational decision (AGENTS.md: do not
    /// hide the "why is this Unknown running" answer).
    pub(crate) evidence: ObservedAgentActivityEvidence,
}

/// Availability of the durable observed-agent presence feed for one derivation
/// pass (#494).
///
/// A failed presence read used to default to an empty map, which the derivation
/// could not distinguish from "the store answered and nothing is present" -- so
/// a transient D1/proxy-Worker failure rendered running agents as a confident
/// `inactive`. Making the feed a two-state value forces every caller to say
/// which of the two it has.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ObservedPresenceFeed<'a> {
    /// The presence store answered. The map is authoritative for the window:
    /// a key absent from it genuinely has no presence row in `[now - ttl, now]`.
    Available(&'a HashMap<(String, String), u64>),
    /// The presence read FAILED. Nothing about durable presence is known; the
    /// storage diagnostic is carried so the surface can name the condition
    /// rather than collapse it into a generic negative.
    Unavailable(&'a str),
}

impl<'a> ObservedPresenceFeed<'a> {
    /// The durable last-seen for one group. `None` means the feed did not
    /// answer (unknown), `Some(0)` means the feed answered and has no row.
    fn last_seen_for(&self, group: &(String, String)) -> Option<u64> {
        match self {
            Self::Available(map) => Some(map.get(group).copied().unwrap_or(0)),
            Self::Unavailable(_) => None,
        }
    }

    pub(crate) fn feed_status(&self) -> &'static str {
        match self {
            Self::Available(_) => OBSERVED_PRESENCE_FEED_AVAILABLE,
            Self::Unavailable(_) => OBSERVED_PRESENCE_FEED_UNAVAILABLE,
        }
    }

    /// The named condition, or `None` when the feed answered.
    pub(crate) fn unavailable_reason(&self) -> Option<&'a str> {
        match self {
            Self::Available(_) => None,
            Self::Unavailable(reason) => Some(reason),
        }
    }
}

/// The observed-activity read as a whole (#494): the derived rows plus the
/// availability of the presence feed they were derived from.
///
/// The feed status is reported at list level as well as per row because an
/// EMPTY row set is itself an answer, and a failed presence read makes that
/// answer unsound: `rows_may_be_incomplete` says so instead of letting an empty
/// list read as "nothing is running".
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct ObservedPresenceFeedStatus {
    /// `available` | `unavailable`.
    pub(crate) status: &'static str,
    /// The storage diagnostic when `status == "unavailable"`; `null` otherwise.
    /// Rendered as an explicit `null` (never omitted) so the field's presence
    /// is not itself a signal.
    pub(crate) unavailable_reason: Option<String>,
    /// `true` when the feed did not answer, so absent/`inactive` rows are NOT
    /// evidence that nothing is running.
    pub(crate) rows_may_be_incomplete: bool,
}

impl ObservedPresenceFeedStatus {
    fn from_feed(feed: ObservedPresenceFeed<'_>) -> Self {
        Self {
            status: feed.feed_status(),
            unavailable_reason: feed.unavailable_reason().map(str::to_string),
            rows_may_be_incomplete: feed.unavailable_reason().is_some(),
        }
    }
}

/// One observed-activity read: rows plus the presence-feed availability that
/// qualifies them.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ObservedActivityReport {
    pub(crate) rows: Vec<ObservedAgentActivity>,
    pub(crate) presence_feed: ObservedPresenceFeedStatus,
}

/// The `GET /admin/v1/observed-agent-activity` body: the standard paginated
/// list, flattened, plus the `presence_feed` qualifier (#494).
#[derive(Debug, Serialize)]
struct ObservedAgentActivityListResponse {
    #[serde(flatten)]
    list: AdminList<ObservedAgentActivity>,
    presence_feed: ObservedPresenceFeedStatus,
}

/// The evidence that justifies the row's `status`. Makes the recency decision
/// auditable instead of an opaque flag.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct ObservedAgentActivityEvidence {
    pub(crate) evidence_source: &'static str,
    pub(crate) request_count: u64,
    /// Age of [`ObservedAgentActivity::last_seen_at_unix`]. An UPPER BOUND when
    /// `presence_feed_status == "unavailable"` (the unread feed could only have
    /// been fresher).
    pub(crate) seconds_since_last_seen: u64,
    pub(crate) running_ttl_seconds: u64,
    /// `Some(true)`/`Some(false)` when the window question is decidable;
    /// `null` (#494) when the presence feed did not answer and the request-log
    /// evidence alone is outside the window -- the one case where the missing
    /// feed is exactly the signal that could have flipped the answer.
    pub(crate) within_running_window: Option<bool>,
    /// #357: whether the durable presence store contributed the recency used
    /// for the `running` decision (its last-seen was at least as fresh as the
    /// request-log evidence). Makes the "which signal decided running" answer
    /// inspectable rather than an opaque merge. `null` (#494) when the presence
    /// read failed -- `false` would claim the store was consulted and lost.
    pub(crate) durable_presence_backed: Option<bool>,
    /// `available` | `unavailable` (#494): whether the durable presence read
    /// succeeded for this derivation pass.
    pub(crate) presence_feed_status: &'static str,
    /// The named storage condition when the presence read failed; `null` when
    /// it succeeded. Always serialized so `unknown` is never unexplained.
    pub(crate) presence_unavailable_reason: Option<String>,
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
    ///
    /// #494: this is a two-state feed, not a map. An unreadable presence store
    /// is [`ObservedPresenceFeed::Unavailable`], which the derivation reports
    /// as `unknown` rather than silently behaving like an empty map.
    pub(crate) presence: ObservedPresenceFeed<'a>,
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
///
/// Returns an [`ObservedActivityReport`] rather than a bare `Vec` (#494): the
/// availability of the presence feed qualifies the row set as a whole, and an
/// empty `Vec` alone cannot carry "we could not tell".
pub(crate) fn derive_observed_agent_activity(
    inputs: &ObservedActivityInputs<'_>,
) -> ObservedActivityReport {
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
            // #494: `None` here means the presence read FAILED, which is not
            // the same as the store reporting no row (`Some(0)`).
            let presence_last_seen =
                inputs.presence.last_seen_for(&(tenant_id.clone(), api_key_id.clone()));
            let durable_presence_backed = presence_last_seen.map(|seen| seen >= acc.last_seen);
            let effective_last_seen = acc.last_seen.max(presence_last_seen.unwrap_or(0));
            let seconds_since_last_seen = inputs.now_unix.saturating_sub(effective_last_seen);
            let observed_within_window = seconds_since_last_seen <= inputs.running_ttl_seconds;
            // Asymmetry that makes an unreadable feed safe: presence can only
            // ever move recency FORWARD, so evidence already inside the window
            // stays a sound `running` even with the feed down. The negative is
            // NOT sound -- the unread feed is exactly the signal that could
            // have flipped it -- so it degrades to `unknown`, never `inactive`.
            let (status, status_basis, within_running_window) =
                match (observed_within_window, presence_last_seen.is_some()) {
                    (true, _) => (
                        OBSERVED_STATUS_RUNNING,
                        OBSERVED_STATUS_BASIS,
                        Some(true),
                    ),
                    (false, true) => (
                        OBSERVED_STATUS_INACTIVE,
                        OBSERVED_STATUS_BASIS,
                        Some(false),
                    ),
                    (false, false) => (
                        OBSERVED_STATUS_UNKNOWN,
                        OBSERVED_STATUS_BASIS_PRESENCE_UNAVAILABLE,
                        None,
                    ),
                };
            let reason = match status {
                OBSERVED_STATUS_RUNNING => format!(
                    "observed {} request(s) authenticated by this virtual API key with no verified \
                     managed/self-hosted/agent-run identity; last seen {}s ago is within the {}s \
                     running window",
                    acc.request_count, seconds_since_last_seen, inputs.running_ttl_seconds
                ),
                OBSERVED_STATUS_INACTIVE => format!(
                    "last observed {}s ago, beyond the {}s running window; reported inactive (no \
                     stop event is fabricated)",
                    seconds_since_last_seen, inputs.running_ttl_seconds
                ),
                _ => format!(
                    "durable presence feed unavailable ({}); request-log evidence alone is {}s old, \
                     beyond the {}s running window, and the unread feed could only have been \
                     fresher -- reported unknown, NOT inactive",
                    inputs
                        .presence
                        .unavailable_reason()
                        .unwrap_or("read failed"),
                    seconds_since_last_seen,
                    inputs.running_ttl_seconds
                ),
            };
            let credential_name = inputs.credential_names.get(&api_key_id).cloned();
            let evidence = ObservedAgentActivityEvidence {
                evidence_source: OBSERVED_EVIDENCE_SOURCE,
                request_count: acc.request_count,
                seconds_since_last_seen,
                running_ttl_seconds: inputs.running_ttl_seconds,
                within_running_window,
                durable_presence_backed,
                presence_feed_status: inputs.presence.feed_status(),
                presence_unavailable_reason: inputs
                    .presence
                    .unavailable_reason()
                    .map(str::to_string),
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
                status_basis,
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
    ObservedActivityReport {
        rows,
        presence_feed: ObservedPresenceFeedStatus::from_feed(inputs.presence),
    }
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
        match authenticate(&state, headers, "admin.read", &ctx.request_id).await {
            Ok(auth) => {
                // Tenant isolation BEFORE pagination/aggregation: a tenant-scoped
                // caller only ever sees its own tenant's observed activity; the
                // DECLARED platform operator (#515) gets the cross-tenant view.
                // `tenant_filter()` is the classification, so a credential that
                // merely omitted `organization_id` no longer lands in the
                // unfiltered branch.
                let report = state.observed_agent_activity(auth.tenant_filter());
                let pagination = state.admin_pagination(query);
                let total = report.rows.len();
                let data = report
                    .rows
                    .into_iter()
                    .skip(pagination.offset)
                    .take(pagination.limit)
                    .collect();
                // #494: the list carries the presence-feed status alongside the
                // rows, so an EMPTY page is never mistaken for "nothing is
                // running" when the feed simply did not answer.
                let body = ObservedAgentActivityListResponse {
                    list: AdminList::paginated(data, total, pagination.offset, pagination.limit),
                    presence_feed: report.presence_feed,
                };
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
