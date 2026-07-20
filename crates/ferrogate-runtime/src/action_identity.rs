// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-20
// description: Canonical ActionIdentity model shared by every governance layer (issue #303).

//! Canonical action-identity model (issue #303) — MODEL ONLY, no seam wiring.
//!
//! Every governance layer (MCP ingress, the tool-governance chokepoint, the
//! capability boundary, approvals, guardrails, dispatch leases, A2A handoff)
//! should emit the SAME action identity so budgets, approvals and execution
//! audit compose as one state transition. This module promotes the fragmented
//! per-layer shapes into one shared tuple:
//!
//! ```text
//! ActionIdentity = (
//!     action,               // capability action class, e.g. "mcp.tool"
//!     canonical_target,     // CanonicalCapabilityTarget::canonical_json()
//!     principal,            // subject/api-key id + tenant + worker + delegated user
//!     context,              // request/trace/agent-run/workflow/session/lease ids
//!     action_fingerprint,   // canonical_target_sha256 contract, "sha256:<hex>"
//! )
//! ```
//!
//! It is a promotion/generalization of
//! [`crate::CapabilityAuthorizationEvidence`] — the one existing struct that
//! already carries the full tuple — decoupled from the capability boundary so
//! other layers can emit it without going through the authorizer.
//!
//! # Two-level fingerprint contract
//!
//! There are deliberately TWO fingerprints with different semantics:
//!
//! 1. **Target-level action identity** — [`ActionIdentity::action_fingerprint`]
//!    follows the existing `canonical_target_sha256` contract (the
//!    `action_fingerprint_contract: "canonical_target_sha256"` label exposed by
//!    the admin managed-worker surface): `"sha256:" + hex(SHA-256(canonical
//!    JSON of the CanonicalCapabilityTarget))`, exactly
//!    [`crate::CanonicalCapabilityTarget::fingerprint`]. It identifies *which
//!    exact external action* is being performed, independent of who asked or
//!    which request carried it. All layers correlate on this value.
//! 2. **Invocation-level approval binding** — the tool-approval fingerprint in
//!    `ferrogate-cli/src/approval.rs` (`fingerprint_for`, Blake2b512 over a
//!    canonicalized invocation struct: request id, trace id, tenant, actor,
//!    tool/server/route, approval policy, config snapshot, arguments). It binds
//!    one granted approval to one concrete invocation *including its
//!    arguments*, and KEEPS those semantics unchanged. The two compose: an
//!    approval grants one invocation (invocation fingerprint) of one action
//!    identity (target fingerprint); the invocation fingerprint is NOT a
//!    substitute for the target fingerprint and vice versa.
//!
//! # Canonical decision vocabulary
//!
//! [`ActionDecision`] (`allow` / `deny` / `ask` / `degrade`, snake_case serde,
//! each variant carrying a structured [`DecisionReason`]) unifies the four
//! existing vocabularies. Mappings and their losslessness:
//!
//! * [`crate::CapabilityAuthorizationDecision`] (`Allowed`/`Denied`/
//!   `ApprovalRequired`) — `From` impl here; lossless (reverse:
//!   [`capability_decision_from_action_decision`]).
//! * `ApprovalStatus` (`pending`/`approved`/`denied`/`expired`, lives in
//!   ferrogate-cli, which depends on this crate) — the `From` impl lives next
//!   to the source type in `ferrogate-cli/src/approval.rs`; lossless via the
//!   reason codes [`decision_codes::APPROVAL_DENIED`] vs
//!   [`decision_codes::APPROVAL_EXPIRED`] (both map to `deny`).
//! * The guardrail evidence triple `verdict`/`action`/`enforcement_status`
//!   (recorded as strings in `StoredGuardrailEvaluation`) — parsed by
//!   [`GuardrailOutcome::parse`] and mapped by `From<GuardrailOutcome>`;
//!   lossless because the full triple is re-encoded into the reason code
//!   (reverse: [`guardrail_outcome_from_action_decision`]). See
//!   [`GuardrailOutcome`] for the enforcement-preserving decision matrix.
//! * Free-text audit `outcome` strings at the tool chokepoint
//!   (`execute_tool_request_with_governance`) — [`AuditOutcome::parse`] is
//!   infallible and preserves unrecognized strings losslessly in
//!   [`AuditOutcome::Unknown`]; the decision mapping
//!   ([`AuditOutcome::decision`]) is fallible and refuses to invent a decision
//!   for unknown outcomes, so round-trips never lie.
//!
//! # Follow-up wiring (this slice is model-only)
//!
//! * #304 — persistence: durable storage of [`ActionReceipt`] rows.
//! * #305 — correlation keys: shared correlation keys across evidence stores.
//! * #306 — guardrails/approvals adoption of the canonical decision enum.
//! * #307 — handoff propagation (A2A / dispatch leases) of the identity tuple.

use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::{CanonicalCapabilityTarget, CapabilityAuthorizationDecision};

/// Contract label for the target-level fingerprint scheme, as exposed by the
/// admin managed-worker capability policy surface
/// (`action_fingerprint_contract`).
pub const ACTION_FINGERPRINT_CONTRACT: &str = "canonical_target_sha256";

/// Stable reason codes carried by [`DecisionReason::code`]. Codes are the
/// lossless discriminator when several source values collapse onto one
/// canonical decision (e.g. approval `denied` vs `expired` are both `deny`).
pub mod decision_codes {
    /// [`crate::CapabilityAuthorizationDecision::Allowed`].
    pub const CAPABILITY_ALLOWED: &str = "capability_allowed";
    /// [`crate::CapabilityAuthorizationDecision::Denied`].
    pub const CAPABILITY_DENIED: &str = "capability_denied";
    /// [`crate::CapabilityAuthorizationDecision::ApprovalRequired`].
    pub const CAPABILITY_APPROVAL_REQUIRED: &str = "capability_approval_required";

    /// ferrogate-cli `ApprovalStatus::Pending`.
    pub const APPROVAL_PENDING: &str = "approval_pending";
    /// ferrogate-cli `ApprovalStatus::Approved`.
    pub const APPROVAL_APPROVED: &str = "approval_approved";
    /// ferrogate-cli `ApprovalStatus::Denied`.
    pub const APPROVAL_DENIED: &str = "approval_denied";
    /// ferrogate-cli `ApprovalStatus::Expired` (terminal refusal: the window
    /// elapsed without a grant, so the action must not run).
    pub const APPROVAL_EXPIRED: &str = "approval_expired";

    /// Prefix for guardrail-triple codes:
    /// `guardrail:<verdict>:<action>:<enforcement_status>`.
    pub const GUARDRAIL_PREFIX: &str = "guardrail:";

    /// Prefix for tool-chokepoint audit outcome codes: `audit_<outcome>`.
    pub const AUDIT_PREFIX: &str = "audit_";
}

/// Who is performing the action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActingPrincipal {
    /// Authenticated subject — the api-key id (or worker subject string) that
    /// authorizes the action.
    pub subject: String,
    /// Tenant the subject acts within.
    pub tenant_id: String,
    /// Managed/self-hosted worker performing the action on the subject's
    /// behalf, when one is involved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    /// End user the subject is acting for under delegation, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_user: Option<String>,
}

/// Where in the request/run/workflow topology the action occurs. `request_id`
/// is the only mandatory correlation key; everything else is present when the
/// corresponding layer is involved (correlation-key unification is #305).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionContext {
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
}

impl ActionContext {
    /// Context carrying only the mandatory request id.
    pub fn for_request(request_id: impl Into<String>) -> Self {
        Self {
            request_id: request_id.into(),
            trace_id: None,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            session_id: None,
            lease_id: None,
        }
    }
}

/// The one canonical action-identity tuple (see module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionIdentity {
    /// Capability action class in its stable string form, e.g. `"mcp.tool"`,
    /// `"cli"` ([`crate::CapabilityAction::as_str`] values).
    pub action: String,
    /// Canonical target in ONE format: the canonical JSON rendering of
    /// [`CanonicalCapabilityTarget`] ([`CanonicalCapabilityTarget::canonical_json`]),
    /// the same string [`crate::CapabilityAuthorizationEvidence::canonical_target`]
    /// carries today.
    pub canonical_target: String,
    pub principal: ActingPrincipal,
    pub context: ActionContext,
    /// Target-level fingerprint under the `canonical_target_sha256` contract
    /// ([`ACTION_FINGERPRINT_CONTRACT`]): `"sha256:<hex>"` over
    /// `canonical_target`. NOT the invocation-level approval fingerprint — see
    /// the module docs for the two-level contract.
    pub action_fingerprint: String,
}

impl ActionIdentity {
    /// Build an identity from a resolved canonical target, deriving both the
    /// canonical target string and the fingerprint from the same value so the
    /// two can never disagree.
    pub fn from_canonical_target(
        action: impl Into<String>,
        target: &CanonicalCapabilityTarget,
        principal: ActingPrincipal,
        context: ActionContext,
    ) -> Self {
        Self {
            action: action.into(),
            canonical_target: target.canonical_json(),
            principal,
            context,
            action_fingerprint: target.fingerprint(),
        }
    }
}

/// Structured reason attached to every [`ActionDecision`] variant. `code` is a
/// stable machine-readable discriminator (see [`decision_codes`]); `detail` is
/// optional human-readable prose and never participates in mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReason {
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl DecisionReason {
    pub fn new(code: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// Canonical governance decision. Serialized snake_case with an internal
/// `decision` tag, e.g. `{"decision":"allow","reason":{"code":"..."}}`.
///
/// * `allow` — the action may proceed / proceeded.
/// * `deny` — the action is terminally refused.
/// * `ask` — a human/policy gate must resolve before the action can proceed.
/// * `degrade` — the action proceeds but its effect is reduced (e.g. output
///   redaction); the caller gets less than it asked for, not nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum ActionDecision {
    Allow { reason: DecisionReason },
    Deny { reason: DecisionReason },
    Ask { reason: DecisionReason },
    Degrade { reason: DecisionReason },
}

impl ActionDecision {
    pub fn allow(code: impl Into<String>) -> Self {
        Self::Allow {
            reason: DecisionReason::new(code),
        }
    }

    pub fn deny(code: impl Into<String>) -> Self {
        Self::Deny {
            reason: DecisionReason::new(code),
        }
    }

    pub fn ask(code: impl Into<String>) -> Self {
        Self::Ask {
            reason: DecisionReason::new(code),
        }
    }

    pub fn degrade(code: impl Into<String>) -> Self {
        Self::Degrade {
            reason: DecisionReason::new(code),
        }
    }

    pub fn reason(&self) -> &DecisionReason {
        match self {
            Self::Allow { reason }
            | Self::Deny { reason }
            | Self::Ask { reason }
            | Self::Degrade { reason } => reason,
        }
    }

    pub fn code(&self) -> &str {
        &self.reason().code
    }

    /// The snake_case decision-class label, identical to the serde `decision`
    /// tag: `"allow"` / `"deny"` / `"ask"` / `"degrade"`. This is the compact
    /// value persisted in the queryable `decision` columns on timeline/audit
    /// rows (issue #304), alongside `decision_reason` = [`Self::code`].
    pub fn class_label(&self) -> &'static str {
        match self {
            Self::Allow { .. } => "allow",
            Self::Deny { .. } => "deny",
            Self::Ask { .. } => "ask",
            Self::Degrade { .. } => "degrade",
        }
    }
}

/// Lossless mapping from the capability-boundary decision.
///
/// * `Allowed` → `allow` ([`decision_codes::CAPABILITY_ALLOWED`])
/// * `Denied` → `deny` ([`decision_codes::CAPABILITY_DENIED`])
/// * `ApprovalRequired` → `ask` ([`decision_codes::CAPABILITY_APPROVAL_REQUIRED`])
impl From<CapabilityAuthorizationDecision> for ActionDecision {
    fn from(decision: CapabilityAuthorizationDecision) -> Self {
        match decision {
            CapabilityAuthorizationDecision::Allowed => {
                Self::allow(decision_codes::CAPABILITY_ALLOWED)
            }
            CapabilityAuthorizationDecision::Denied => {
                Self::deny(decision_codes::CAPABILITY_DENIED)
            }
            CapabilityAuthorizationDecision::ApprovalRequired => {
                Self::ask(decision_codes::CAPABILITY_APPROVAL_REQUIRED)
            }
        }
    }
}

/// Reverse of `From<CapabilityAuthorizationDecision>`, keyed on the reason
/// code. Returns `None` for decisions that did not originate at the capability
/// boundary.
pub fn capability_decision_from_action_decision(
    decision: &ActionDecision,
) -> Option<CapabilityAuthorizationDecision> {
    match decision.code() {
        decision_codes::CAPABILITY_ALLOWED => Some(CapabilityAuthorizationDecision::Allowed),
        decision_codes::CAPABILITY_DENIED => Some(CapabilityAuthorizationDecision::Denied),
        decision_codes::CAPABILITY_APPROVAL_REQUIRED => {
            Some(CapabilityAuthorizationDecision::ApprovalRequired)
        }
        _ => None,
    }
}

/// Guardrail evaluation verdict, matching the recorded evidence strings
/// (`guardrail_aggregate_outcome_name`): `pass` / `fail` / `error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailVerdict {
    Pass,
    Fail,
    Error,
}

impl GuardrailVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Error => "error",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "pass" => Some(Self::Pass),
            "fail" => Some(Self::Fail),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

/// Guardrail policy action selected for the verdict, matching the recorded
/// evidence strings (`guardrail_evidence_action`): `block` / `redact` /
/// `record` / `allow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailTriggeredAction {
    Block,
    Redact,
    Record,
    Allow,
}

impl GuardrailTriggeredAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Redact => "redact",
            Self::Record => "record",
            Self::Allow => "allow",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "block" => Some(Self::Block),
            "redact" => Some(Self::Redact),
            "record" => Some(Self::Record),
            "allow" => Some(Self::Allow),
            _ => None,
        }
    }
}

/// Whether the selected guardrail action was actually applied, matching the
/// recorded evidence strings: `enforced` / `shadow_only` / `not_enforced`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailEnforcement {
    Enforced,
    ShadowOnly,
    NotEnforced,
}

impl GuardrailEnforcement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enforced => "enforced",
            Self::ShadowOnly => "shadow_only",
            Self::NotEnforced => "not_enforced",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "enforced" => Some(Self::Enforced),
            "shadow_only" => Some(Self::ShadowOnly),
            "not_enforced" => Some(Self::NotEnforced),
            _ => None,
        }
    }
}

/// The guardrail evidence triple as one typed value.
///
/// # Decision matrix (enforcement-preserving)
///
/// The canonical decision reflects the *effective runtime behavior*, never the
/// counterfactual intent — a shadowed block did NOT block, and pretending
/// otherwise would corrupt budgets/audit built on the canonical decision. The
/// intent is preserved losslessly in the reason code
/// (`guardrail:<verdict>:<action>:<enforcement_status>`), so adopting layers
/// (#306) can still alert on shadow denials.
///
/// * `enforcement != enforced` → `allow` (nothing was applied), regardless of
///   verdict/action.
/// * `verdict == pass` → `allow` (there is no finding to act on; on-pass
///   actions such as `record` do not gate traffic).
/// * `verdict ∈ {fail, error}` and enforced:
///   * `block` → `deny` (for `error` this encodes the fail-closed on-error
///     policy that selected `block`),
///   * `redact` → `degrade` (the action proceeds with reduced output),
///   * `record` / `allow` → `allow` (finding recorded, traffic not gated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardrailOutcome {
    pub verdict: GuardrailVerdict,
    pub action: GuardrailTriggeredAction,
    pub enforcement: GuardrailEnforcement,
}

/// A guardrail evidence string fell outside the closed recorded vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardrailOutcomeParseError {
    /// Which field failed: `"verdict"`, `"action"`, or `"enforcement_status"`.
    pub field: &'static str,
    /// The offending value, preserved verbatim.
    pub value: String,
}

impl fmt::Display for GuardrailOutcomeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown guardrail {} value: {:?}",
            self.field, self.value
        )
    }
}

impl Error for GuardrailOutcomeParseError {}

impl GuardrailOutcome {
    /// Parse the triple exactly as recorded in guardrail evidence rows. The
    /// vocabulary is closed, so unknown strings are an error (with the value
    /// preserved) rather than a guess.
    pub fn parse(
        verdict: &str,
        action: &str,
        enforcement_status: &str,
    ) -> Result<Self, GuardrailOutcomeParseError> {
        Ok(Self {
            verdict: GuardrailVerdict::parse(verdict).ok_or_else(|| {
                GuardrailOutcomeParseError {
                    field: "verdict",
                    value: verdict.to_string(),
                }
            })?,
            action: GuardrailTriggeredAction::parse(action).ok_or_else(|| {
                GuardrailOutcomeParseError {
                    field: "action",
                    value: action.to_string(),
                }
            })?,
            enforcement: GuardrailEnforcement::parse(enforcement_status).ok_or_else(|| {
                GuardrailOutcomeParseError {
                    field: "enforcement_status",
                    value: enforcement_status.to_string(),
                }
            })?,
        })
    }

    /// The lossless reason code carrying the full triple:
    /// `guardrail:<verdict>:<action>:<enforcement_status>`.
    pub fn reason_code(self) -> String {
        format!(
            "{}{}:{}:{}",
            decision_codes::GUARDRAIL_PREFIX,
            self.verdict.as_str(),
            self.action.as_str(),
            self.enforcement.as_str()
        )
    }
}

/// See [`GuardrailOutcome`] for the decision matrix and losslessness notes.
impl From<GuardrailOutcome> for ActionDecision {
    fn from(outcome: GuardrailOutcome) -> Self {
        let code = outcome.reason_code();
        if outcome.enforcement != GuardrailEnforcement::Enforced
            || outcome.verdict == GuardrailVerdict::Pass
        {
            return Self::allow(code);
        }
        match outcome.action {
            GuardrailTriggeredAction::Block => Self::deny(code),
            GuardrailTriggeredAction::Redact => Self::degrade(code),
            GuardrailTriggeredAction::Record | GuardrailTriggeredAction::Allow => Self::allow(code),
        }
    }
}

/// Reverse of `From<GuardrailOutcome>`: recover the exact triple from the
/// reason code. Returns `None` for decisions that did not originate from a
/// guardrail evaluation.
pub fn guardrail_outcome_from_action_decision(
    decision: &ActionDecision,
) -> Option<GuardrailOutcome> {
    let triple = decision
        .code()
        .strip_prefix(decision_codes::GUARDRAIL_PREFIX)?;
    let mut parts = triple.splitn(3, ':');
    let verdict = parts.next()?;
    let action = parts.next()?;
    let enforcement = parts.next()?;
    GuardrailOutcome::parse(verdict, action, enforcement).ok()
}

/// The free-text audit `outcome` vocabulary observed at the tool-governance
/// chokepoint (`execute_tool_request_with_governance` and its audit drafts).
/// Parsing is infallible: strings outside the known set are preserved
/// verbatim in [`AuditOutcome::Unknown`], and `as_str`/serde round-trip every
/// value byte-for-byte, so nothing is lost and nothing is invented.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum AuditOutcome {
    /// `"success"` — the tool executed and its result was returned.
    Success,
    /// `"error"` — lookup, persistence, or execution failed terminally.
    ErrorOutcome,
    /// `"rejected"` — governance refused the action (guardrail block/withhold,
    /// approval denied/expired, identity resolution denied).
    Rejected,
    /// `"approval_required"` — a guardrail escalated the action to the
    /// approval gate.
    ApprovalRequired,
    /// `"pending"` — an approval was created and is awaiting a decision.
    Pending,
    /// `"approved"` — the approval was granted before execution.
    Approved,
    /// `"allowed"` — an inline authorization step (e.g. MCP identity
    /// resolution) permitted the action.
    Allowed,
    /// `"redacted"` — the tool ran but its output was rewritten by a
    /// redact-effect guardrail.
    Redacted,
    /// Any other string, preserved verbatim for lossless round-trips.
    Unknown(String),
}

impl AuditOutcome {
    pub fn parse(value: &str) -> Self {
        match value {
            "success" => Self::Success,
            "error" => Self::ErrorOutcome,
            "rejected" => Self::Rejected,
            "approval_required" => Self::ApprovalRequired,
            "pending" => Self::Pending,
            "approved" => Self::Approved,
            "allowed" => Self::Allowed,
            "redacted" => Self::Redacted,
            other => Self::Unknown(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Success => "success",
            Self::ErrorOutcome => "error",
            Self::Rejected => "rejected",
            Self::ApprovalRequired => "approval_required",
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Allowed => "allowed",
            Self::Redacted => "redacted",
            Self::Unknown(value) => value,
        }
    }

    /// Fallible mapping to the canonical decision. Known outcomes map with a
    /// lossless `audit_<outcome>` reason code:
    ///
    /// * `success` / `allowed` / `approved` → `allow`
    /// * `error` → `deny` (`audit_error`: the request terminated without the
    ///   action's effect; execution-failure detail belongs to
    ///   [`OutputDisposition::Errored`], not to a fabricated allow)
    /// * `rejected` → `deny`
    /// * `approval_required` / `pending` → `ask`
    /// * `redacted` → `degrade`
    ///
    /// Unknown outcomes return the preserved string as an error instead of a
    /// guessed decision.
    pub fn decision(&self) -> Result<ActionDecision, UnknownAuditOutcome> {
        let code = |suffix: &str| format!("{}{}", decision_codes::AUDIT_PREFIX, suffix);
        match self {
            Self::Success => Ok(ActionDecision::allow(code("success"))),
            Self::Allowed => Ok(ActionDecision::allow(code("allowed"))),
            Self::Approved => Ok(ActionDecision::allow(code("approved"))),
            Self::ErrorOutcome => Ok(ActionDecision::deny(code("error"))),
            Self::Rejected => Ok(ActionDecision::deny(code("rejected"))),
            Self::ApprovalRequired => Ok(ActionDecision::ask(code("approval_required"))),
            Self::Pending => Ok(ActionDecision::ask(code("pending"))),
            Self::Redacted => Ok(ActionDecision::degrade(code("redacted"))),
            Self::Unknown(value) => Err(UnknownAuditOutcome(value.clone())),
        }
    }
}

impl From<String> for AuditOutcome {
    fn from(value: String) -> Self {
        Self::parse(&value)
    }
}

impl From<AuditOutcome> for String {
    fn from(outcome: AuditOutcome) -> Self {
        outcome.as_str().to_string()
    }
}

/// An audit outcome string outside the known vocabulary; carries the original
/// value so callers can persist it without loss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownAuditOutcome(pub String);

impl fmt::Display for UnknownAuditOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown audit outcome: {:?}", self.0)
    }
}

impl Error for UnknownAuditOutcome {}

/// Reverse of [`AuditOutcome::decision`], keyed on the `audit_` reason code.
/// Returns `None` for decisions that did not originate from an audit outcome.
pub fn audit_outcome_from_action_decision(decision: &ActionDecision) -> Option<AuditOutcome> {
    let suffix = decision.code().strip_prefix(decision_codes::AUDIT_PREFIX)?;
    let outcome = AuditOutcome::parse(suffix);
    match outcome {
        AuditOutcome::Unknown(_) => None,
        known => Some(known),
    }
}

/// What happened to the action's output. Replaces today's prose-only audit
/// messages ("tool output redacted/withheld by guardrail policy") with a
/// closed enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputDisposition {
    /// The full output was returned to the caller.
    Returned,
    /// The output was rewritten by a redact-effect guardrail before return.
    Redacted,
    /// The output was withheld entirely (fail-closed guardrail block).
    Withheld,
    /// Execution failed; there is no output to dispose of.
    Errored,
}

/// Receipt for one executed (or refused) action: the identity, the canonical
/// decision that governed it, and what happened to its output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionReceipt {
    pub identity: ActionIdentity,
    pub decision: ActionDecision,
    pub output_disposition: OutputDisposition,
    /// End-to-end latency of the execution attempt in milliseconds; `None`
    /// when the action never executed (denied / still asking).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    /// 1-based execution attempt this receipt describes.
    #[serde(default = "default_attempt")]
    pub attempt: u32,
}

fn default_attempt() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TargetOperation;

    fn sample_target() -> CanonicalCapabilityTarget {
        CanonicalCapabilityTarget::Filesystem {
            path: "reports/summary.md".to_string(),
            operation: TargetOperation::Read,
        }
    }

    fn sample_identity() -> ActionIdentity {
        ActionIdentity::from_canonical_target(
            "filesystem",
            &sample_target(),
            ActingPrincipal {
                subject: "api-key-1".to_string(),
                tenant_id: "tenant-a".to_string(),
                worker_id: Some("worker-7".to_string()),
                delegated_user: None,
            },
            ActionContext {
                request_id: "req-1".to_string(),
                trace_id: Some("trace-1".to_string()),
                agent_run_id: Some("run-1".to_string()),
                workflow_id: None,
                workflow_version: None,
                workflow_node_id: None,
                session_id: Some("session-1".to_string()),
                lease_id: None,
            },
        )
    }

    #[test]
    fn action_fingerprint_follows_canonical_target_sha256_contract() {
        let target = sample_target();
        let identity = sample_identity();
        assert_eq!(ACTION_FINGERPRINT_CONTRACT, "canonical_target_sha256");
        assert_eq!(identity.action_fingerprint, target.fingerprint());
        assert_eq!(identity.canonical_target, target.canonical_json());
        assert!(identity.action_fingerprint.starts_with("sha256:"));
        // "sha256:" + 64 lowercase hex chars.
        assert_eq!(identity.action_fingerprint.len(), "sha256:".len() + 64);
        assert!(identity.action_fingerprint["sha256:".len()..]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn action_identity_serde_snapshot() {
        let identity = sample_identity();
        let json = serde_json::to_value(&identity).expect("serialize identity");
        assert_eq!(json["action"], "filesystem");
        assert_eq!(json["principal"]["subject"], "api-key-1");
        assert_eq!(json["principal"]["tenant_id"], "tenant-a");
        assert_eq!(json["principal"]["worker_id"], "worker-7");
        assert!(json["principal"].get("delegated_user").is_none());
        assert_eq!(json["context"]["request_id"], "req-1");
        assert!(json["context"].get("workflow_id").is_none());
        assert_eq!(
            json["action_fingerprint"],
            sample_target().fingerprint().as_str()
        );
        let restored: ActionIdentity = serde_json::from_value(json).expect("deserialize identity");
        assert_eq!(restored, identity);
    }

    #[test]
    fn action_decision_serde_snake_case_snapshots() {
        let cases = [
            (
                ActionDecision::allow("capability_allowed"),
                r#"{"decision":"allow","reason":{"code":"capability_allowed"}}"#,
            ),
            (
                ActionDecision::deny("capability_denied"),
                r#"{"decision":"deny","reason":{"code":"capability_denied"}}"#,
            ),
            (
                ActionDecision::ask("approval_pending"),
                r#"{"decision":"ask","reason":{"code":"approval_pending"}}"#,
            ),
            (
                ActionDecision::degrade("guardrail:fail:redact:enforced"),
                r#"{"decision":"degrade","reason":{"code":"guardrail:fail:redact:enforced"}}"#,
            ),
        ];
        for (decision, expected) in cases {
            let json = serde_json::to_string(&decision).expect("serialize decision");
            assert_eq!(json, expected);
            let restored: ActionDecision =
                serde_json::from_str(&json).expect("deserialize decision");
            assert_eq!(restored, decision);
        }
        let detailed = ActionDecision::Deny {
            reason: DecisionReason::new("approval_expired").with_detail("timed out after 300s"),
        };
        assert_eq!(
            serde_json::to_string(&detailed).expect("serialize"),
            r#"{"decision":"deny","reason":{"code":"approval_expired","detail":"timed out after 300s"}}"#
        );
    }

    #[test]
    fn class_label_matches_the_serde_decision_tag() {
        let cases = [
            (ActionDecision::allow("c"), "allow"),
            (ActionDecision::deny("c"), "deny"),
            (ActionDecision::ask("c"), "ask"),
            (ActionDecision::degrade("c"), "degrade"),
        ];
        for (decision, expected) in cases {
            assert_eq!(decision.class_label(), expected);
            let json = serde_json::to_value(&decision).expect("serialize decision");
            assert_eq!(json["decision"], expected, "label must equal the serde tag");
        }
    }

    #[test]
    fn output_disposition_serde_snake_case_snapshots() {
        let cases = [
            (OutputDisposition::Returned, "\"returned\""),
            (OutputDisposition::Redacted, "\"redacted\""),
            (OutputDisposition::Withheld, "\"withheld\""),
            (OutputDisposition::Errored, "\"errored\""),
        ];
        for (disposition, expected) in cases {
            let json = serde_json::to_string(&disposition).expect("serialize disposition");
            assert_eq!(json, expected);
            let restored: OutputDisposition =
                serde_json::from_str(&json).expect("deserialize disposition");
            assert_eq!(restored, disposition);
        }
    }

    #[test]
    fn guardrail_vocabulary_serde_snake_case_snapshots() {
        assert_eq!(
            serde_json::to_string(&GuardrailVerdict::Pass).unwrap(),
            "\"pass\""
        );
        assert_eq!(
            serde_json::to_string(&GuardrailVerdict::Fail).unwrap(),
            "\"fail\""
        );
        assert_eq!(
            serde_json::to_string(&GuardrailVerdict::Error).unwrap(),
            "\"error\""
        );
        assert_eq!(
            serde_json::to_string(&GuardrailTriggeredAction::Block).unwrap(),
            "\"block\""
        );
        assert_eq!(
            serde_json::to_string(&GuardrailTriggeredAction::Redact).unwrap(),
            "\"redact\""
        );
        assert_eq!(
            serde_json::to_string(&GuardrailTriggeredAction::Record).unwrap(),
            "\"record\""
        );
        assert_eq!(
            serde_json::to_string(&GuardrailTriggeredAction::Allow).unwrap(),
            "\"allow\""
        );
        assert_eq!(
            serde_json::to_string(&GuardrailEnforcement::Enforced).unwrap(),
            "\"enforced\""
        );
        assert_eq!(
            serde_json::to_string(&GuardrailEnforcement::ShadowOnly).unwrap(),
            "\"shadow_only\""
        );
        assert_eq!(
            serde_json::to_string(&GuardrailEnforcement::NotEnforced).unwrap(),
            "\"not_enforced\""
        );
    }

    #[test]
    fn capability_decision_mapping_round_trips_losslessly() {
        for source in [
            CapabilityAuthorizationDecision::Allowed,
            CapabilityAuthorizationDecision::Denied,
            CapabilityAuthorizationDecision::ApprovalRequired,
        ] {
            let canonical = ActionDecision::from(source);
            assert_eq!(
                capability_decision_from_action_decision(&canonical),
                Some(source)
            );
        }
        assert_eq!(
            ActionDecision::from(CapabilityAuthorizationDecision::Allowed),
            ActionDecision::allow(decision_codes::CAPABILITY_ALLOWED)
        );
        assert_eq!(
            ActionDecision::from(CapabilityAuthorizationDecision::Denied),
            ActionDecision::deny(decision_codes::CAPABILITY_DENIED)
        );
        assert_eq!(
            ActionDecision::from(CapabilityAuthorizationDecision::ApprovalRequired),
            ActionDecision::ask(decision_codes::CAPABILITY_APPROVAL_REQUIRED)
        );
        assert_eq!(
            capability_decision_from_action_decision(&ActionDecision::allow("audit_success")),
            None
        );
    }

    #[test]
    fn guardrail_triple_round_trips_losslessly_across_full_vocabulary() {
        for verdict in ["pass", "fail", "error"] {
            for action in ["block", "redact", "record", "allow"] {
                for enforcement in ["enforced", "shadow_only", "not_enforced"] {
                    let outcome = GuardrailOutcome::parse(verdict, action, enforcement)
                        .expect("known vocabulary parses");
                    let canonical = ActionDecision::from(outcome);
                    assert_eq!(
                        guardrail_outcome_from_action_decision(&canonical),
                        Some(outcome),
                        "triple ({verdict},{action},{enforcement}) must round-trip"
                    );
                }
            }
        }
    }

    #[test]
    fn guardrail_decision_matrix_preserves_enforcement_status() {
        let decide = |verdict, action, enforcement| {
            ActionDecision::from(GuardrailOutcome::parse(verdict, action, enforcement).unwrap())
        };
        // Enforced findings gate traffic by their action.
        assert!(matches!(
            decide("fail", "block", "enforced"),
            ActionDecision::Deny { .. }
        ));
        assert!(matches!(
            decide("error", "block", "enforced"),
            ActionDecision::Deny { .. }
        ));
        assert!(matches!(
            decide("fail", "redact", "enforced"),
            ActionDecision::Degrade { .. }
        ));
        assert!(matches!(
            decide("fail", "record", "enforced"),
            ActionDecision::Allow { .. }
        ));
        // A pass never gates, even with an aggressive on-pass action config.
        assert!(matches!(
            decide("pass", "block", "enforced"),
            ActionDecision::Allow { .. }
        ));
        // Shadow / not-enforced evaluations did not change runtime behavior:
        // the canonical decision is allow, and the would-be action survives in
        // the reason code.
        let shadow = decide("fail", "block", "shadow_only");
        assert!(matches!(shadow, ActionDecision::Allow { .. }));
        assert_eq!(shadow.code(), "guardrail:fail:block:shadow_only");
        let unenforced = decide("fail", "redact", "not_enforced");
        assert!(matches!(unenforced, ActionDecision::Allow { .. }));
        assert_eq!(unenforced.code(), "guardrail:fail:redact:not_enforced");
    }

    #[test]
    fn guardrail_parse_rejects_unknown_values_with_field_and_value() {
        let error = GuardrailOutcome::parse("maybe", "block", "enforced").unwrap_err();
        assert_eq!(error.field, "verdict");
        assert_eq!(error.value, "maybe");
        let error = GuardrailOutcome::parse("fail", "explode", "enforced").unwrap_err();
        assert_eq!(error.field, "action");
        assert_eq!(error.value, "explode");
        let error = GuardrailOutcome::parse("fail", "block", "sometimes").unwrap_err();
        assert_eq!(error.field, "enforcement_status");
        assert_eq!(error.value, "sometimes");
    }

    #[test]
    fn audit_outcome_known_values_round_trip_through_decision() {
        let known = [
            ("success", "audit_success"),
            ("error", "audit_error"),
            ("rejected", "audit_rejected"),
            ("approval_required", "audit_approval_required"),
            ("pending", "audit_pending"),
            ("approved", "audit_approved"),
            ("allowed", "audit_allowed"),
            ("redacted", "audit_redacted"),
        ];
        for (outcome_str, expected_code) in known {
            let outcome = AuditOutcome::parse(outcome_str);
            assert_eq!(outcome.as_str(), outcome_str, "string round-trip");
            let decision = outcome.decision().expect("known outcome maps");
            assert_eq!(decision.code(), expected_code);
            assert_eq!(
                audit_outcome_from_action_decision(&decision),
                Some(outcome),
                "outcome {outcome_str} must round-trip through the decision"
            );
        }
        // Canonical decision classes for the known vocabulary.
        assert!(matches!(
            AuditOutcome::Success.decision().unwrap(),
            ActionDecision::Allow { .. }
        ));
        assert!(matches!(
            AuditOutcome::ErrorOutcome.decision().unwrap(),
            ActionDecision::Deny { .. }
        ));
        assert!(matches!(
            AuditOutcome::Rejected.decision().unwrap(),
            ActionDecision::Deny { .. }
        ));
        assert!(matches!(
            AuditOutcome::ApprovalRequired.decision().unwrap(),
            ActionDecision::Ask { .. }
        ));
        assert!(matches!(
            AuditOutcome::Pending.decision().unwrap(),
            ActionDecision::Ask { .. }
        ));
        assert!(matches!(
            AuditOutcome::Redacted.decision().unwrap(),
            ActionDecision::Degrade { .. }
        ));
    }

    #[test]
    fn audit_outcome_unknown_values_are_preserved_and_never_mapped() {
        let outcome = AuditOutcome::parse("partially_frobnicated");
        assert_eq!(
            outcome,
            AuditOutcome::Unknown("partially_frobnicated".to_string())
        );
        assert_eq!(outcome.as_str(), "partially_frobnicated");
        // Serde round-trips the unknown string byte-for-byte.
        let json = serde_json::to_string(&outcome).expect("serialize outcome");
        assert_eq!(json, "\"partially_frobnicated\"");
        let restored: AuditOutcome = serde_json::from_str(&json).expect("deserialize outcome");
        assert_eq!(restored, outcome);
        // The decision mapping refuses to guess and keeps the original value.
        let error = outcome.decision().unwrap_err();
        assert_eq!(error.0, "partially_frobnicated");
    }

    #[test]
    fn audit_outcome_serde_snapshots_for_known_variants() {
        let cases = [
            (AuditOutcome::Success, "\"success\""),
            (AuditOutcome::ErrorOutcome, "\"error\""),
            (AuditOutcome::Rejected, "\"rejected\""),
            (AuditOutcome::ApprovalRequired, "\"approval_required\""),
            (AuditOutcome::Pending, "\"pending\""),
            (AuditOutcome::Approved, "\"approved\""),
            (AuditOutcome::Allowed, "\"allowed\""),
            (AuditOutcome::Redacted, "\"redacted\""),
        ];
        for (outcome, expected) in cases {
            let json = serde_json::to_string(&outcome).expect("serialize outcome");
            assert_eq!(json, expected);
            let restored: AuditOutcome = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(restored, outcome);
        }
    }

    #[test]
    fn action_receipt_serde_round_trip() {
        let receipt = ActionReceipt {
            identity: sample_identity(),
            decision: ActionDecision::degrade("guardrail:fail:redact:enforced"),
            output_disposition: OutputDisposition::Redacted,
            latency_ms: Some(42),
            attempt: 1,
        };
        let json = serde_json::to_value(&receipt).expect("serialize receipt");
        assert_eq!(json["output_disposition"], "redacted");
        assert_eq!(json["decision"]["decision"], "degrade");
        assert_eq!(json["latency_ms"], 42);
        assert_eq!(json["attempt"], 1);
        let restored: ActionReceipt = serde_json::from_value(json).expect("deserialize receipt");
        assert_eq!(restored, receipt);
        // A refused action has no latency; attempt defaults to 1 on the wire.
        let refused = serde_json::json!({
            "identity": serde_json::to_value(sample_identity()).unwrap(),
            "decision": {"decision": "deny", "reason": {"code": "capability_denied"}},
            "output_disposition": "withheld",
        });
        let restored: ActionReceipt =
            serde_json::from_value(refused).expect("deserialize refused receipt");
        assert_eq!(restored.latency_ms, None);
        assert_eq!(restored.attempt, 1);
    }
}
