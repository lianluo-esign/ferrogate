// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, the governed decision as a
// value (#470): a canonically serialisable `GovernedDecisionRecord`, the
// governed error vocabulary with its per-code fixture-coverage obligation, and
// the directional-conformance predicate a veto-only second host is graded by.

//! The governed decision, extracted from the response writer (#470).
//!
//! Before this module the AI proxy's governed outcomes existed only as
//! side effects: `handle_ai_request` wrote every rejection straight into the
//! Pingora [`Session`](pingora::proxy::Session) through `write_json_error`, so
//! there was no point at which "what did the gateway decide" was a value you
//! could serialise, diff, or compare against a second host.
//!
//! [`GovernedDecisionRecord`] is that value. It is deliberately *small*: it
//! carries only what a second host must reproduce identically (outcome,
//! status, stable code, metered amounts, the ordered kinds of durable write and
//! audit event), and nothing about how the decision is delivered (the client
//! message, the tenant attribution used for the request log, whether the
//! connection is closed). Delivery context lives on the enclosing
//! [`GovernedDecision`] and is explicitly *not* part of the canonical form.
//!
//! ## Scope of the seam today
//!
//! `decide_ai_request` / `decide_ai_workflow_admission` (in
//! [`super::chat`]) cover the **admission** half of the governed path -- steps
//! 13-32 of `docs/cloudflare-data-plane-decision.md` §1, i.e. everything up to
//! (but not including) the per-candidate dispatch loop. Those are the steps
//! that authenticate, resolve the quota scope chain, enforce the monthly
//! budget, check the prepaid wallet, consume the RPM window, validate and
//! route the request, and apply workflow policy.
//!
//! The dispatch half (steps 33-52: guardrails, policy engine, cache, TPM
//! consume, wallet hold, provider dispatch, billing) is **not** a value yet;
//! its codes are listed in [`GOVERNED_ERROR_VOCABULARY`] with
//! [`FixtureCoverage::PendingDispatchSeam`] so the boundary is visible in code
//! and cannot shrink silently.

use std::collections::BTreeSet;

use ferrogate_core::TenantContext;
use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::model_routing::ModelRoutingDecision;

/// Bumped whenever the canonical shape changes. Fixtures declare the schema
/// they were written against so a shape change is a loud, reviewable failure
/// rather than a silent re-interpretation of a golden file.
pub(crate) const GOVERNED_DECISION_SCHEMA: u32 = 1;

/// What the gateway decided to do with the request.
///
/// `Defer` is not produced by the authority. It exists for a veto-only second
/// host (the §6 Worker shell): "I made no governed call; ask the authority."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GovernedOutcome {
    Allow,
    Deny,
    CacheHit,
    Defer,
}

impl GovernedOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::CacheHit => "cache_hit",
            Self::Defer => "defer",
        }
    }
}

/// Metered amounts authored by the decision.
///
/// Credit amounts are **decimal strings parsed as integers**, never floats and
/// never compared lexically -- the #469 discipline applied to the wire format
/// itself, so a conformance corpus cannot re-introduce the rounding bug it
/// exists to prevent. Token counts are plain integers because they are counts,
/// not money.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GovernedMetered {
    #[serde(default)]
    pub(crate) prompt_tokens: u64,
    #[serde(default)]
    pub(crate) completion_tokens: u64,
    #[serde(default = "zero_amount")]
    pub(crate) credits_reserved: String,
    #[serde(default = "zero_amount")]
    pub(crate) credits_captured: String,
}

fn zero_amount() -> String {
    "0".to_string()
}

impl Default for GovernedMetered {
    fn default() -> Self {
        Self {
            prompt_tokens: 0,
            completion_tokens: 0,
            credits_reserved: zero_amount(),
            credits_captured: zero_amount(),
        }
    }
}

impl GovernedMetered {
    /// True when the decision authored no metered amount at all. This is the
    /// property a veto-only host must satisfy unconditionally.
    pub(crate) fn is_empty(&self) -> bool {
        self.prompt_tokens == 0
            && self.completion_tokens == 0
            && parse_amount(&self.credits_reserved) == Ok(0)
            && parse_amount(&self.credits_captured) == Ok(0)
    }

    /// Rejects a float, a sign, whitespace padding or an empty string in a
    /// credit field before it can be compared.
    pub(crate) fn validate(&self) -> Result<(), String> {
        parse_amount(&self.credits_reserved)
            .map_err(|reason| format!("credits_reserved: {reason}"))?;
        parse_amount(&self.credits_captured)
            .map_err(|reason| format!("credits_captured: {reason}"))?;
        Ok(())
    }
}

/// Parses a credit amount the only way a money field may ever be parsed here:
/// as a base-10 integer in a string, with no sign, separator or fraction.
pub(crate) fn parse_amount(raw: &str) -> Result<i128, String> {
    if raw.is_empty() {
        return Err("empty amount".to_string());
    }
    if !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "{raw:?} is not a non-negative base-10 integer in a decimal string"
        ));
    }
    raw.parse::<i128>()
        .map_err(|error| format!("{raw:?} does not fit an i128: {error}"))
}

/// The canonical, host-independent form of a governed decision.
///
/// Field set is deliberately narrow -- see the module docs. `quota` and
/// `guardrail` from the §8a sketch are *not* here: at admission there is no
/// guardrail verdict and no reservation to report, so emitting permanently-null
/// objects would be decoration. They join the record when the dispatch seam
/// lands, together with a `GOVERNED_DECISION_SCHEMA` bump.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GovernedDecisionRecord {
    pub(crate) schema: u32,
    pub(crate) outcome: GovernedOutcome,
    pub(crate) status: u16,
    #[serde(default)]
    pub(crate) code: Option<String>,
    #[serde(default)]
    pub(crate) metered: GovernedMetered,
    #[serde(default)]
    pub(crate) durable_writes: Vec<String>,
    #[serde(default)]
    pub(crate) audit_events: Vec<String>,
}

impl GovernedDecisionRecord {
    pub(crate) fn deny(status: StatusCode, code: &'static str) -> Self {
        Self {
            schema: GOVERNED_DECISION_SCHEMA,
            outcome: GovernedOutcome::Deny,
            status: status.as_u16(),
            code: Some(code.to_string()),
            metered: GovernedMetered::default(),
            // Every AI-path rejection lands exactly one request-log row (see
            // `record_ai_error_log` / `record_ai_workflow_rejection`).
            durable_writes: vec!["request_log".to_string()],
            audit_events: Vec::new(),
        }
    }

    pub(crate) fn admitted() -> Self {
        Self {
            schema: GOVERNED_DECISION_SCHEMA,
            outcome: GovernedOutcome::Allow,
            status: StatusCode::OK.as_u16(),
            code: None,
            metered: GovernedMetered::default(),
            durable_writes: Vec::new(),
            audit_events: Vec::new(),
        }
    }

    /// Canonical serialisation: sorted keys, stable field set, no whitespace.
    ///
    /// `serde_json`'s `Map` is a `BTreeMap` in this workspace (the
    /// `preserve_order` feature is not enabled anywhere), so round-tripping
    /// through `Value` sorts every key at every depth. Two hosts that agree on
    /// the decision therefore produce byte-identical strings.
    pub(crate) fn canonical_json(&self) -> String {
        let value = serde_json::to_value(self).expect("GovernedDecisionRecord is always JSON");
        serde_json::to_string(&value).expect("serde_json::Value always serialises")
    }
}

/// Workflow attribution carried alongside a decision so the request-log row a
/// workflow rejection writes keeps the shape it had before the extraction.
#[derive(Debug, Clone, Default)]
pub(crate) struct GovernedWorkflowContext {
    pub(crate) agent_run_id: String,
    pub(crate) workflow_id: Option<String>,
    pub(crate) workflow_version: Option<u32>,
    pub(crate) workflow_node_id: Option<String>,
    pub(crate) gateway_config_id: Option<String>,
    pub(crate) gateway_config_revision: Option<u32>,
    pub(crate) now_unix: u64,
}

/// A governed decision plus the context needed to deliver it. Only
/// [`GovernedDecision::record`] is canonical; everything else is transport and
/// observability and is excluded from cross-host comparison on purpose.
#[derive(Debug, Clone)]
pub(crate) struct GovernedDecision {
    pub(crate) record: GovernedDecisionRecord,
    pub(crate) message: String,
    pub(crate) tenant: TenantContext,
    pub(crate) logical_model: Option<String>,
    /// `payload_too_large` must close the connection rather than drain an
    /// oversized body; nothing else on the admission path does.
    pub(crate) close_connection: bool,
    pub(crate) workflow: Option<GovernedWorkflowContext>,
    /// Non-canonical delivery context for a routing rejection. The typed
    /// decision is persisted by the normal audit sink at delivery time; only
    /// its ordered audit action names enter the canonical record.
    pub(crate) model_routing: Option<GovernedModelRoutingContext>,
}

#[derive(Debug, Clone)]
pub(crate) struct GovernedModelRoutingContext {
    pub(crate) decision: ModelRoutingDecision,
    pub(crate) agent_run_id: String,
    pub(crate) workflow_id: Option<String>,
    pub(crate) workflow_version: Option<u32>,
    pub(crate) workflow_node_id: Option<String>,
    pub(crate) actor_api_key_id: Option<String>,
}

impl GovernedDecision {
    pub(crate) fn deny(
        status: StatusCode,
        code: &'static str,
        message: impl Into<String>,
        tenant: TenantContext,
        logical_model: Option<String>,
    ) -> Self {
        Self {
            record: GovernedDecisionRecord::deny(status, code),
            message: message.into(),
            tenant,
            logical_model,
            close_connection: false,
            workflow: None,
            model_routing: None,
        }
    }

    pub(crate) fn closing(mut self) -> Self {
        self.close_connection = true;
        self
    }

    pub(crate) fn with_workflow(mut self, workflow: GovernedWorkflowContext) -> Self {
        self.workflow = Some(workflow);
        self
    }

    pub(crate) fn with_model_routing(mut self, routing: GovernedModelRoutingContext) -> Self {
        self.record.audit_events = routing.decision.audit_event_actions();
        self.model_routing = Some(routing);
        self
    }

    pub(crate) fn status(&self) -> StatusCode {
        StatusCode::from_u16(self.record.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    pub(crate) fn code(&self) -> &str {
        self.record.code.as_deref().unwrap_or("")
    }
}

/// Where in the governed path a code is produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GovernedStage {
    /// Produced by `decide_ai_request` / `decide_ai_workflow_admission`:
    /// steps 13-32. A value today.
    Admission,
    /// Produced inside the per-candidate dispatch loop: steps 33-52. Still a
    /// side effect today.
    Dispatch,
    /// Emitted by the admin/control-plane gate in `auth.rs`, never on the AI
    /// proxy path. Listed only so the source scan over `auth.rs` has a home
    /// for it and cannot be silenced by an unknown code.
    AdminGate,
}

/// Why a governed code does or does not carry a fixture obligation.
///
/// The suite treats [`FixtureCoverage::Required`] as a hard gate: a code
/// declared reproducible with no fixture fails. Every other variant must carry
/// a non-empty reason, which is itself asserted -- so "no fixture" is always an
/// argued, reviewable position rather than an omission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FixtureCoverage {
    /// Reproducible from a fixture `world` alone. A fixture is mandatory.
    Required,
    /// Needs a backend fault (control-plane store, counter backend or external
    /// auth service unavailable) that the fixture world cannot inject yet.
    RequiresFaultInjection(&'static str),
    /// Needs seeded agent-run/workflow-run state that the fixture world cannot
    /// express yet.
    RequiresRunState(&'static str),
    /// Produced after the dispatch seam, which is not a value yet.
    PendingDispatchSeam(&'static str),
    /// Not on the AI proxy path at all.
    NotOnAiPath(&'static str),
}

impl FixtureCoverage {
    pub(crate) fn is_required(self) -> bool {
        matches!(self, Self::Required)
    }

    pub(crate) fn reason(self) -> Option<&'static str> {
        match self {
            Self::Required => None,
            Self::RequiresFaultInjection(reason)
            | Self::RequiresRunState(reason)
            | Self::PendingDispatchSeam(reason)
            | Self::NotOnAiPath(reason) => Some(reason),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GovernedErrorCode {
    pub(crate) code: &'static str,
    pub(crate) stage: GovernedStage,
    pub(crate) coverage: FixtureCoverage,
}

/// The governed error vocabulary.
///
/// This is the list the coverage gate in
/// `governed_decision_conformance_test.rs` runs against, in both directions:
///
/// * every literal error code the scanner finds in `gateway/chat.rs` and
///   `auth.rs` must appear here, so adding a governed outcome forces a
///   vocabulary entry and a coverage decision; and
/// * every entry marked [`FixtureCoverage::Required`] must appear in at least
///   one fixture, so a reproducible governed outcome cannot ship unfixtured.
pub(crate) const GOVERNED_ERROR_VOCABULARY: &[GovernedErrorCode] = &[
    // --- authentication and key state (auth.rs, via `authenticate`) ---
    code(
        "missing_api_key",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "invalid_api_key",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "api_key_disabled",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "api_key_expired",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "scope_denied",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    // #515: a credential that declares neither `platform_operator` nor an
    // `organization_id`, with the compatibility switch off, is unclassifiable.
    // `finalize_auth` refuses it rather than guessing a tenancy, so it is an
    // admission-stage refusal like the rest of this group. A fixture is
    // required: it is reachable only through a specific config posture
    // (the `[tenancy] implicit_platform_operator = false` default plus an under-declared
    // key), which is exactly the kind of combination a conformance fixture
    // exists to hold.
    code(
        "tenant_identity_required",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    // --- quota, budget and money (auth.rs, via `finalize_auth`) ---
    code(
        "token_budget_exceeded",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "quota_scope_disabled",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "monthly_budget_exceeded",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "wallet_balance_exhausted",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "rate_limit_exceeded",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "quota_resolution_unavailable",
        GovernedStage::Admission,
        FixtureCoverage::RequiresFaultInjection(
            "needs the control-plane store to fail mid-lookup; the fixture world seeds an \
             in-memory store that cannot be made to error yet",
        ),
    ),
    code(
        "governance_counter_unavailable",
        GovernedStage::Admission,
        FixtureCoverage::RequiresFaultInjection(
            "needs the cluster counter backend to error; the in-memory backend never does, and \
             pointing it at an unreachable Redis would make the suite network-dependent",
        ),
    ),
    // --- external auth / RBAC (auth.rs) ---
    code(
        "external_auth_denied",
        GovernedStage::Admission,
        FixtureCoverage::RequiresFaultInjection(
            "needs a live external auth service; the fixture world has no HTTP stub yet",
        ),
    ),
    code(
        "external_auth_unavailable",
        GovernedStage::Admission,
        FixtureCoverage::RequiresFaultInjection(
            "needs a live external auth service; the fixture world has no HTTP stub yet",
        ),
    ),
    code(
        "rbac_denied",
        GovernedStage::Admission,
        FixtureCoverage::RequiresFaultInjection(
            "needs a live external auth service; the fixture world has no HTTP stub yet",
        ),
    ),
    // --- ingress headers and node state (chat.rs, `build_ai_ingress_plan`) ---
    code(
        "invalid_agent_run_id_header",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "invalid_workflow_header",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "invalid_gateway_config_header",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "gateway_config_not_found",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "gateway_config_disabled",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "gateway_config_not_allowed",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "node_draining",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    // --- body and request shape (chat.rs, `build_ai_request_plan`) ---
    code(
        "payload_too_large",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "invalid_json",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "invalid_request",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "invalid_request_metadata",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    // --- model admission and routing (chat.rs, `build_ai_request_plan`) ---
    code(
        "model_not_allowed",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "model_not_found",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "model_disabled",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "model_not_visible",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "region_not_allowed",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    // --- workflow policy (chat.rs, `enforce_ai_workflow_policy`) ---
    code(
        "workflow_not_found",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "workflow_disabled",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "workflow_not_allowed",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "workflow_node_required",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "workflow_node_not_found",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "workflow_node_not_model",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "workflow_model_not_allowed",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "workflow_iteration_limit_exceeded",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "workflow_token_budget_exceeded",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "workflow_provider_not_allowed",
        GovernedStage::Admission,
        FixtureCoverage::Required,
    ),
    code(
        "workflow_edge_not_allowed",
        GovernedStage::Admission,
        FixtureCoverage::RequiresRunState(
            "needs a seeded agent-run edge history; the fixture world cannot express prior node \
             transitions yet",
        ),
    ),
    code(
        "workflow_model_call_limit_exceeded",
        GovernedStage::Admission,
        FixtureCoverage::RequiresRunState(
            "needs a seeded per-workflow model-call counter; the fixture world cannot express \
             prior calls yet",
        ),
    ),
    code(
        "workflow_timeout_exceeded",
        GovernedStage::Admission,
        FixtureCoverage::RequiresRunState(
            "needs a seeded workflow-run start timestamp; the fixture world cannot express a \
             run already in flight yet",
        ),
    ),
    // --- dispatch loop: steps 33-52, not a value yet ---
    code(
        "provider_not_found",
        GovernedStage::Dispatch,
        FixtureCoverage::PendingDispatchSeam(
            "emitted inside the per-candidate loop, which still writes into the Session",
        ),
    ),
    code(
        "provider_circuit_open",
        GovernedStage::Dispatch,
        FixtureCoverage::PendingDispatchSeam(
            "emitted inside the per-candidate loop, which still writes into the Session",
        ),
    ),
    code(
        "provider_not_allowed",
        GovernedStage::Dispatch,
        FixtureCoverage::PendingDispatchSeam(
            "emitted inside the per-candidate loop, which still writes into the Session",
        ),
    ),
    code(
        "provider_adapter_error",
        GovernedStage::Dispatch,
        FixtureCoverage::PendingDispatchSeam(
            "emitted inside the per-candidate loop, which still writes into the Session",
        ),
    ),
    code(
        "provider_dispatch_error",
        GovernedStage::Dispatch,
        FixtureCoverage::PendingDispatchSeam(
            "emitted inside the per-candidate loop, which still writes into the Session",
        ),
    ),
    code(
        "tpm_limit_exceeded",
        GovernedStage::Dispatch,
        FixtureCoverage::PendingDispatchSeam(
            "TPM is consumed once per logical request inside the candidate loop (step 41)",
        ),
    ),
    code(
        "wallet_reservation_unavailable",
        GovernedStage::Dispatch,
        FixtureCoverage::PendingDispatchSeam(
            "the wallet hold (step 42) is taken inside the candidate loop",
        ),
    ),
    code(
        "guardrail_stream_buffer_limit_exceeded",
        GovernedStage::Dispatch,
        FixtureCoverage::PendingDispatchSeam(
            "produced while capturing a streamed provider response (step 46)",
        ),
    ),
    code(
        "guardrail_stream_buffer_timeout",
        GovernedStage::Dispatch,
        FixtureCoverage::PendingDispatchSeam(
            "produced while capturing a streamed provider response (step 46)",
        ),
    ),
    // --- admin/control-plane gate: never on the AI proxy path ---
    code(
        "tenant_scope_denied",
        GovernedStage::AdminGate,
        FixtureCoverage::NotOnAiPath("emitted by the admin tenant-scope gate, not by the AI path"),
    ),
    code(
        "platform_operator_required",
        GovernedStage::AdminGate,
        FixtureCoverage::NotOnAiPath("emitted by the admin operator gate, not by the AI path"),
    ),
];

const fn code(
    code: &'static str,
    stage: GovernedStage,
    coverage: FixtureCoverage,
) -> GovernedErrorCode {
    GovernedErrorCode {
        code,
        stage,
        coverage,
    }
}

pub(crate) fn governed_error_code(code: &str) -> Option<&'static GovernedErrorCode> {
    GOVERNED_ERROR_VOCABULARY
        .iter()
        .find(|entry| entry.code == code)
}

/// The set of codes a conformant host may return. Any deny carrying a code
/// outside this set is a divergence by definition -- the two hosts are not even
/// speaking the same vocabulary.
pub(crate) fn governed_error_code_set() -> BTreeSet<&'static str> {
    GOVERNED_ERROR_VOCABULARY
        .iter()
        .map(|entry| entry.code)
        .collect()
}

/// The directional-conformance predicate for a veto-only second host
/// (`docs/cloudflare-data-plane-decision.md` §8d).
///
/// A host under this contract is never an authorisation, only a veto, and may
/// never author a metered amount. Concretely:
///
/// 1. `candidate.outcome ∈ { Defer, authority.outcome, Deny }` -- it may agree,
///    it may abstain, it may deny. It may never *allow* on its own account, and
///    it may never turn an authority deny into anything but a deny.
/// 2. `candidate.metered == ∅` -- no token estimate, no reservation, no
///    capture, ever.
/// 3. A candidate deny carries a code from the shared vocabulary.
///
/// This is how a fail-closed pre-filter is *proven* fail-closed rather than
/// asserted to be.
pub(crate) fn directional_conformance(
    authority: &GovernedDecisionRecord,
    candidate: &GovernedDecisionRecord,
) -> Result<(), String> {
    if !candidate.metered.is_empty() {
        return Err(format!(
            "veto-only host authored a metered amount: {:?}",
            candidate.metered
        ));
    }
    candidate
        .metered
        .validate()
        .map_err(|reason| format!("veto-only host emitted a malformed amount: {reason}"))?;
    match candidate.outcome {
        GovernedOutcome::Defer => Ok(()),
        GovernedOutcome::Deny => {
            let Some(code) = candidate.code.as_deref() else {
                return Err("veto-only host denied without a code".to_string());
            };
            if governed_error_code(code).is_none() {
                return Err(format!(
                    "veto-only host denied with {code:?}, which is not in the governed vocabulary"
                ));
            }
            Ok(())
        }
        GovernedOutcome::Allow | GovernedOutcome::CacheHit => Err(format!(
            "veto-only host returned {:?}; a veto-only host may never author an allow or serve \
             from cache (authority said {:?})",
            candidate.outcome.as_str(),
            authority.outcome.as_str()
        )),
    }
}

#[cfg(test)]
#[path = "governed_decision_test.rs"]
mod governed_decision_test;
