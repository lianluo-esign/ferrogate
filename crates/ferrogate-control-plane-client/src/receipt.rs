// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! The mutation decision receipt: the one sanctioned output shape of a
//! state-changing CLI verb (issue #505).
//!
//! # The gap this closes
//!
//! Before this module the CLI had the *inputs* of a governed surface and none
//! of the *output contract*. A mutating verb printed the server's response
//! body — or a line of success prose — and the operator could not tell which
//! principal the call was attributed to, which policy decision permitted it,
//! which audit row records it, what exact object version changed, or how to
//! reverse it. The runtime already owns the canonical vocabulary
//! (`ferrogate_runtime::action_identity`: `ActionIdentity`, `ActionDecision`,
//! the `canonical_target_sha256` fingerprint contract); the CLI simply did not
//! surface it, which made it a privileged side channel next to the UI/API
//! rather than another view onto the same governance plane.
//!
//! # Absent is a finding, not a silence
//!
//! Every governance field is an [`Attested<T>`]: `{"value": …, "absent_reason":
//! …}` with **both keys always serialized**. A field the Control Plane API does
//! not return is `null` *with a stated reason code*, never omitted. That is
//! deliberate — an absent audit id is itself the finding. A structural scan of
//! `docs/openapi/admin-api.openapi.json` finds **135** mutating operations
//! (`POST`/`PUT`/`PATCH`/`DELETE`), of which **117** are covered by this
//! registry, and **none** declares an audit identifier in any resolved 2xx
//! response schema; zero declare a `dry_run` echo. That scan is not a
//! historical note — `no_mutating_operation_in_the_contract_returns_an_audit_id`
//! re-derives it from the contract on every run and prints the full
//! enumeration, so the claim fails the day it stops being true. Issue #505 is
//! explicit that this slice must *record* that gap, not add the server-side
//! write path, so the receipt reports it in a machine-greppable way:
//!
//! ```sh
//! ferrogate ctl <group> <verb> … --output json | jq -e '.audit_id.absent_reason.code'
//! ```
//!
//! # Scope: the `ctl` registry, and what is knowingly outside it
//!
//! The gate is total over the **registry**, which is every `ferrogate ctl
//! <group> <verb>` command. It is not total over the binary. These shipped
//! mutating commands are hand-written verticals that predate the registry and
//! still print a bare body or a line of prose, and closing them is follow-up
//! work, not a silence:
//!
//! * `ferrogate assets push` (PUT) / `ferrogate assets delete` (DELETE)
//! * `ferrogate plans create` (POST) / `ferrogate plans assign`
//! * `ferrogate reload --admin-url …`, which mutates a *running* gateway's
//!   live config and prints prose
//! * `ferrogate storage migrate-to-supabase`, which still carries its own
//!   ad-hoc `--dry-run`/`--execute` pair — the per-resource pattern the
//!   uniform `--dry-run` replaces inside `ctl`
//! * `ferrogate context create/use/delete`, which are local mutations:
//!   [`VerbEffect::Local`] exists for them but no shipped verb uses it yet, so
//!   they never meet the gate at all
//!
//! Each is a real CLI mutation with no receipt. Naming them here rather than
//! leaving the reader to infer coverage from the module title is the same rule
//! the receipt itself follows: an absence is a finding, not a silence.
//!
//! **This list is not the audit-attribution boundary**, and issue #548 borrowed
//! it once as if it were. Two things differ. It is scoped to *mutating* verbs,
//! and #548 covers reads as well, so `assets pull`, `assets list` and
//! `plans list` belong to that question and not to this one. And `assets` and
//! `plans` are no longer outside it: their raw-TCP client now takes a
//! [`crate::action_identity::ClientActionIdentity`] as a required argument, so
//! they carry an `action_id` while still printing a bare body. The attribution
//! boundary is stated in [`crate::action_identity`]'s module docs, and it names
//! `ferrogate reload --admin-url` as what is still outside it.
//!
//! # Registry-level enforcement (structural, not a convention)
//!
//! Two compile-time barriers, not a lint:
//!
//! 1. **Classification is mandatory.** [`VerbDescriptor`] has no effect-less
//!    API constructor: an author must pick [`VerbDescriptor::read`] or
//!    [`VerbDescriptor::mutating`]. A new verb nobody classified does not
//!    compile.
//! 2. **A mutating verb has no path to a bare body.** [`VerbDescriptor::render_gate`]
//!    returns a [`RenderGate`] whose `Bare` arm carries a [`BareRenderer`] —
//!    the only type with a `render(Value)` method — and whose `Receipt` arm
//!    carries a [`ReceiptRenderer`], whose `render` accepts only a
//!    [`MutationReceipt`]. Neither token is publicly constructible (private
//!    fields, no public constructor), and [`VerbOutput`] wraps a private
//!    payload enum, so no caller anywhere can fabricate one. Writing
//!    "mutating verb renders a raw body" is therefore a type error, and the
//!    exhaustive `match` on [`RenderGate`] forces the author to confront the
//!    receipt arm.
//!
//! Misclassification — the residual risk, since the effect is *data* — is
//! caught by `receipt_test.rs`, which rebuilds every registered verb's
//! [`RequestSpec`] through the real family builders and fails when a verb's
//! declared effect disagrees with the HTTP method the builder actually emits.
//!
//! # `--dry-run` is structural too
//!
//! [`MutationPlan::dry_run`] takes **no transport parameter at all**: it is a
//! pure function with no `Transport` in scope, so it cannot issue a request.
//! [`MutationPlan::execute`] routes to it before the client is ever borrowed.
//! The test asserts on a recording [`Transport`] (zero requests seen), not on
//! output text.
//!
//! # `outcome` reports authority, not success
//!
//! [`MutationOutcome`] is the field an audit pipeline selects on, so its
//! boundary is *did the server decide*, not *did the call succeed*. A `4xx` is
//! the server having read the request and refused it — `rejected`, and every
//! server-derived field may say "no artifact exists". A `5xx`, or one of the
//! retryable-timeout statuses `408`/`425`/`429`, is **not** a decision: the
//! canonical case is a `guardrail-policies activate` the gateway committed and
//! an intermediary answered `504` for. Those report `unknown`, because the only
//! two claims available — "it landed" and "it did not" — are both unprovable
//! from here, and the second is the one that silently loses a change.
//!
//! [`MutationOutcome::from_http_status`] derives this from
//! [`ExitClass::from_http_status`] rather than from a parallel status table, so
//! a receipt cannot assert an authoritative refusal on an invocation whose
//! process exit code says the request never produced an authoritative answer.
//! [`MutationReceipt::validate`] then holds the pair: an outcome that
//! contradicts the `http_status` the same receipt reports is a validation
//! failure.
//!
//! # Client action identity (issue #548)
//!
//! [`MutationReceipt::client_identity`] closes the other half of the
//! correlation. #505 could only report `audit_id: null` because no operation
//! returns one; [`crate::action_identity`] mints an `action_id` client-side and
//! sends it on every request, and the receipt echoes back the identity the
//! transport actually used — the same value, from the same
//! [`crate::action_identity::ClientActionIdentity`], not a second one minted
//! here. So an operator can now join what they sent to what came back without
//! waiting for the server-side audit-write path.
//!
//! Three things about that field are load-bearing and easy to get wrong:
//!
//! * **`client_sent_at` is server-issued or null, and today it is always null.**
//!   It is never filled from the local clock; a request that presented no token
//!   reports [`absence_codes::NO_SERVER_TIME_TOKEN`], which is a finding, not a
//!   silence. And no deployment issues a token yet — the issuing endpoint is
//!   server-side work #548 defers — so on every receipt this CLI renders today
//!   the field is `null` with that code. It is stated here, in
//!   [`crate::action_identity`], and in `docs/cli-audit-attribution.md`, in the
//!   same spirit as `--tenant`'s "NOT HONORED BY THE SERVER TODAY", so an
//!   operator reads a documented state rather than guessing at a null.
//! * **`client_clock_unverified_unix` is a different fact.** It is the client's
//!   own reading, carried beside the server's so an auditor can measure skew.
//!   The two are never merged, and nothing may order or authorize on the second.
//! * **`action_id` is not `idempotency_key`.** Both are on the receipt, and the
//!   `idempotency_key` field documents why.
//!
//! # Fingerprint contract
//!
//! [`CliActionTarget`] is a byte-compatible mirror of the runtime
//! `CanonicalCapabilityTarget::Network` variant, and [`CliActionTarget::fingerprint`]
//! reproduces the `canonical_target_sha256` contract verbatim: `"sha256:" +
//! hex(SHA-256(canonical JSON))`. `ferrogate-control-plane-client` deliberately does not
//! depend on `ferrogate-runtime` (which pulls in storage, TLS, and a tokio
//! runtime — the wrong weight for a client library), so the equality is proven
//! rather than assumed: `crates/ferrogate-cli/src/ctl/fingerprint_parity_test.rs`
//! asserts byte equality against the real
//! `CanonicalCapabilityTarget::fingerprint` for the same target.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::action_identity::{ClientActionIdentity, ServerIssuedTime};
use crate::auth::AuthSource;
use crate::command::{VerbDescriptor, VerbEffect};
use crate::context::EffectiveContext;
use crate::error::{CliError, CliResult, ExitClass};
use crate::transport::{build_url, ApiResponse, ControlPlaneClient, RequestSpec, Transport};

/// `object` discriminator every receipt carries, so a mixed audit stream can
/// tell a receipt from a resource document.
pub const RECEIPT_OBJECT: &str = "mutation_receipt";

/// Schema version of the receipt envelope. Bumped only on a breaking field
/// change, so a downstream audit query can pin it.
pub const RECEIPT_VERSION: u32 = 1;

/// Contract label for the target-level fingerprint scheme. Byte-identical to
/// `ferrogate_runtime::action_identity::ACTION_FINGERPRINT_CONTRACT`; the CLI
/// reuses the runtime contract rather than inventing one.
pub const ACTION_FINGERPRINT_CONTRACT: &str = "canonical_target_sha256";

/// Capability action class for a Control Plane API call, matching
/// `ferrogate_runtime::CapabilityAction::Rest::as_str()`.
pub const CLI_ACTION_CLASS: &str = "rest";

/// Stable reason codes for an absent receipt field. A consumer keys on these,
/// never on the prose in [`AbsenceReason::detail`].
pub mod absence_codes {
    /// The endpoint's 2xx schema declares no audit identifier. Applies to all
    /// 135 mutating operations in the contract today — the 117 this registry
    /// covers and the 18 it does not (issue #505, acceptance box 6); the
    /// enumeration is re-derived by
    /// `no_mutating_operation_in_the_contract_returns_an_audit_id`.
    pub const NO_AUDIT_ID_IN_CONTRACT: &str = "endpoint_returns_no_audit_id";
    /// The endpoint's 2xx schema declares no approval identifier.
    pub const NO_APPROVAL_ID_IN_CONTRACT: &str = "endpoint_returns_no_approval_id";
    /// The endpoint's 2xx schema declares no policy decision.
    pub const NO_DECISION_IN_CONTRACT: &str = "endpoint_returns_no_policy_decision";
    /// The call was a dry run, so nothing executed and no server-side artifact
    /// exists to point at.
    pub const DRY_RUN_NOT_EXECUTED: &str = "dry_run_not_executed";
    /// The resource family has no server-side revision chain, so there is no
    /// rollback pointer to hand back.
    pub const RESOURCE_HAS_NO_REVISIONS: &str = "resource_has_no_revisions";
    /// The family is revisioned but the response body named no revision.
    pub const RESPONSE_CARRIES_NO_REVISION: &str = "response_carries_no_revision";
    /// The created revision is the first in its chain: there is no earlier
    /// revision to restore, so reversal is an archive, not a rollback.
    pub const NO_PRIOR_REVISION: &str = "no_prior_revision_to_restore";
    /// The response body carried no version/revision/etag for the object.
    pub const NO_OBJECT_VERSION: &str = "response_carries_no_object_version";
    /// The invocation resolved no value for this scope field.
    pub const CONTEXT_DECLARES_NO_SCOPE: &str = "context_declares_no_scope";
    /// The CLI holds a bearer token, not a resolved subject, and no mutating
    /// response echoes the authenticated principal back.
    pub const SUBJECT_NOT_LOCALLY_RESOLVABLE: &str = "subject_not_locally_resolvable";
    /// The response carried no `x-request-id` / `x-trace-id`.
    pub const NO_CORRELATION_ID: &str = "response_carries_no_correlation_id";
    /// The verb addresses a collection and nothing was executed, so no id
    /// exists yet: the server assigns one only when the call is made.
    pub const COLLECTION_SCOPED_MUTATION: &str = "collection_scoped_mutation";
    /// The verb addressed a collection, the call was made, and the response
    /// document named no id for the object it created (or named more than one
    /// candidate, which is the same thing: the client cannot tell which).
    pub const RESPONSE_NAMES_NO_RESOURCE_ID: &str = "response_names_no_resource_id";
    /// The request document carried no `idempotency_key`, so a retry is not
    /// provably the same call.
    pub const NO_IDEMPOTENCY_KEY_SUPPLIED: &str = "request_carries_no_idempotency_key";
    /// A local verb never reached the Control Plane API.
    pub const LOCAL_VERB: &str = "local_verb_issues_no_request";
    /// The server refused the mutation, so no server-side artifact of the
    /// change exists to point at.
    pub const MUTATION_NOT_APPLIED: &str = "mutation_not_applied";
    /// The client obtained no authoritative answer, so whether the artifact
    /// exists server-side is not knowable from here.
    pub const MUTATION_OUTCOME_UNKNOWN: &str = "mutation_outcome_unknown";
    /// The request never left the process, so nothing changed.
    pub const REQUEST_NOT_SENT: &str = "request_not_sent";
    /// No HTTP response was obtained at all (connect, timeout, TLS, decode).
    pub const NO_HTTP_RESPONSE: &str = "no_authoritative_http_response";
    /// The call succeeded, so there is no failure to report.
    pub const MUTATION_SUCCEEDED: &str = "mutation_succeeded";
    /// No server-issued time token was held when this request was prepared, so
    /// `client_sent_at` has no authoritative value (issue #548).
    ///
    /// This is the ordinary case for the first request of an invocation, and it
    /// is reported as an absence **on purpose**: the local clock is not used to
    /// fill the field. The server's own receive time still bounds the action.
    pub const NO_SERVER_TIME_TOKEN: &str = "no_server_issued_time_token";
    /// The operator disclosed no client-side address
    /// ([`crate::action_identity::REPORTED_IP_ENV`]). The authoritative address
    /// is the one the *server* observes; this field is opt-in extra evidence.
    pub const NO_CLIENT_REPORTED_IP: &str = "client_reported_no_ip";
}

/// Why a receipt field is `null`. `code` is the stable discriminator; `detail`
/// is required prose so the null is self-explaining in a table render.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbsenceReason {
    pub code: String,
    pub detail: String,
}

impl AbsenceReason {
    pub fn new(code: impl Into<String>, detail: impl Into<String>) -> AbsenceReason {
        AbsenceReason {
            code: code.into(),
            detail: detail.into(),
        }
    }
}

/// A receipt field that is either present, or explicitly absent **with a
/// stated reason**.
///
/// Both keys are always serialized (no `skip_serializing_if`): a consumer can
/// therefore write `.audit_id.value` and `.audit_id.absent_reason.code`
/// unconditionally, which is what makes the JSON stable enough to pipe into an
/// audit query. Omitting the key on absence would make "the field is missing"
/// and "the field is null for a reason" indistinguishable — the exact silence
/// issue #505 forbids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attested<T> {
    pub value: Option<T>,
    pub absent_reason: Option<AbsenceReason>,
}

impl<T> Attested<T> {
    /// A present value.
    pub fn present(value: T) -> Attested<T> {
        Attested {
            value: Some(value),
            absent_reason: None,
        }
    }

    /// An absent value with its stable reason code and human detail.
    pub fn absent(code: impl Into<String>, detail: impl Into<String>) -> Attested<T> {
        Attested {
            value: None,
            absent_reason: Some(AbsenceReason::new(code, detail)),
        }
    }

    /// Promote an `Option` to an `Attested`, stating the reason for `None`.
    pub fn or_absent(
        value: Option<T>,
        code: impl Into<String>,
        detail: impl Into<String>,
    ) -> Attested<T> {
        match value {
            Some(value) => Attested::present(value),
            None => Attested::absent(code, detail),
        }
    }

    /// The invariant every receipt field must hold: exactly one of `value` and
    /// `absent_reason` is set. Checked by [`MutationReceipt::validate`] so a
    /// hand-built or round-tripped receipt cannot carry a silent null.
    pub fn is_well_formed(&self) -> bool {
        self.value.is_some() != self.absent_reason.is_some()
    }

    /// The absence code, when absent.
    pub fn absent_code(&self) -> Option<&str> {
        self.absent_reason
            .as_ref()
            .map(|reason| reason.code.as_str())
    }
}

// ---------------------------------------------------------------------------
// Canonical action target and the reused fingerprint contract.
// ---------------------------------------------------------------------------

/// Byte-compatible mirror of `ferrogate_runtime::CanonicalCapabilityTarget`'s
/// `Network` variant.
///
/// The serde shape — internally tagged on `kind`, `snake_case` variant names,
/// field order `scheme, host, port, method, path, resolved_ips, redirects` —
/// reproduces the runtime enum exactly, so `canonical_json()` and
/// `fingerprint()` are byte-identical to the runtime's for the same target.
/// `resolved_ips` is `Vec<IpAddr>` (not `Vec<String>`) for the same reason.
///
/// Only the `Network` variant is mirrored: a Control Plane API call *is* a
/// network target, and mirroring the filesystem/CLI/MCP/secret variants would
/// be dead surface the CLI can never construct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CliActionTarget {
    Network {
        scheme: String,
        host: String,
        port: u16,
        method: Option<String>,
        path: String,
        /// Always empty: the CLI does not pin DNS resolution, so it has no
        /// resolved-IP evidence to record. Stated here rather than silently
        /// implied — a fingerprint that claimed pinned IPs it never observed
        /// would be worse than one that admits it has none.
        resolved_ips: Vec<IpAddr>,
        /// Always empty: the CLI records no redirect chain evidence.
        redirects: Vec<String>,
    },
}

impl CliActionTarget {
    /// Derive the canonical target for a prepared Control Plane API call.
    ///
    /// `path` carries the request path **and** its encoded query string, since
    /// query parameters can select the object a mutation addresses; both come
    /// from the same URL the transport will actually send, so the fingerprint
    /// cannot describe a different call than the one issued.
    pub fn for_request(endpoint: &str, spec: &RequestSpec) -> CliResult<CliActionTarget> {
        let url = build_url(endpoint, &spec.path, &spec.query)?;
        let url = reqwest::Url::parse(&url)
            .map_err(|error| CliError::usage(format!("invalid request URL '{url}': {error}")))?;
        let scheme = url.scheme().to_string();
        let host = url
            .host_str()
            .ok_or_else(|| {
                CliError::usage(format!("endpoint '{endpoint}' has no host to attribute"))
            })?
            .to_string();
        let port = url.port_or_known_default().ok_or_else(|| {
            CliError::usage(format!(
                "endpoint '{endpoint}' uses scheme '{scheme}', which has no default port"
            ))
        })?;
        let path = match url.query() {
            Some(query) if !query.is_empty() => format!("{}?{query}", url.path()),
            _ => url.path().to_string(),
        };
        Ok(CliActionTarget::Network {
            scheme,
            host,
            port,
            method: Some(spec.method.as_str().to_string()),
            path,
            resolved_ips: Vec::new(),
            redirects: Vec::new(),
        })
    }

    /// Canonical JSON rendering — the exact string the fingerprint digests.
    pub fn canonical_json(&self) -> String {
        serde_json::to_string(self).expect("canonical target serialization is infallible")
    }

    /// `"sha256:" + hex(SHA-256(canonical_json))` — the
    /// [`ACTION_FINGERPRINT_CONTRACT`] scheme, verbatim.
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.canonical_json().as_bytes());
        format!("sha256:{digest:x}")
    }
}

/// Whether `value` is a well-formed fingerprint under
/// [`ACTION_FINGERPRINT_CONTRACT`]: `"sha256:"` plus exactly 64 lowercase hex
/// characters. Mirrors `ferrogate_runtime::action_identity::is_canonical_action_fingerprint`.
pub fn is_canonical_action_fingerprint(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
}

// ---------------------------------------------------------------------------
// Receipt body.
// ---------------------------------------------------------------------------

/// Who the mutation was attributed to, and under which scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptActor {
    /// The resolved principal. Absent today on every endpoint: the CLI holds a
    /// bearer token, and no mutating response echoes the authenticated subject.
    pub subject: Attested<String>,
    /// How the credential was obtained (`env:VAR`, `stdin`, `inline`, `none`).
    /// Never the credential itself.
    pub credential_source: String,
    pub tenant: Attested<String>,
    pub project: Attested<String>,
    pub workspace: Attested<String>,
    /// The named context that authorized the call, when one was selected.
    pub context_name: Attested<String>,
    /// The Control Plane API endpoint the call was made against.
    pub endpoint: String,
}

/// What object the mutation addressed, at which version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptTarget {
    /// Resource family (registry group name).
    pub group: String,
    /// Id path segments the invocation addressed, joined with `/`.
    pub resource_id: Attested<String>,
    pub method: String,
    pub path: String,
    /// Capability action class, matching the runtime taxonomy ([`CLI_ACTION_CLASS`]).
    pub action: String,
    /// `CanonicalCapabilityTarget::canonical_json()`-shaped target string.
    pub canonical_target: String,
    /// `"sha256:<hex>"` over `canonical_target`.
    pub action_fingerprint: String,
    /// Always [`ACTION_FINGERPRINT_CONTRACT`]; carried so a consumer can tell
    /// which scheme produced the fingerprint without inferring it.
    pub action_fingerprint_contract: String,
    /// The object version/revision the mutation produced, when the response
    /// named one.
    pub object_version: Attested<String>,
}

/// Canonical decision classes, matching `ferrogate_runtime::ActionDecision`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionClass {
    Allow,
    Deny,
    Ask,
    Degrade,
}

impl DecisionClass {
    /// Stable spelling, matching the runtime `ActionDecision` serde tags.
    pub fn as_str(self) -> &'static str {
        match self {
            DecisionClass::Allow => "allow",
            DecisionClass::Deny => "deny",
            DecisionClass::Ask => "ask",
            DecisionClass::Degrade => "degrade",
        }
    }
}

/// A **governance verdict on this CLI call**, as reported by the Control Plane
/// API. Field names mirror the runtime `ActionDecision` serde shape so a
/// receipt and a runtime audit row join without translation.
///
/// # Why this is always absent today
///
/// It is deliberately *not* whatever the response happens to spell `decision`.
/// `ToolApprovalRecord`, `AdminPaymentAttempt` and `GuardrailEvaluation` each
/// declare a `decision` field, but those describe the **resource's own state**
/// — the approval verdict a `tool-approvals deny` just recorded, the payment
/// attempt's outcome — not whether the control plane permitted the operator to
/// make the call. Harvesting them conflated the two: a *successful* `ctl
/// tool-approvals deny ta_9` returned HTTP 200 and rendered
/// `decision.value.decision == "deny"`, so an audit query selecting refused
/// mutations picked up every successful denial as a refusal of itself.
///
/// No mutating operation in the contract returns a verdict on the call, so the
/// honest value is [`absence_codes::NO_DECISION_IN_CONTRACT`] on all of them.
/// The type stays because the vocabulary is the contract the day an endpoint
/// does return one; nothing populates it until then, and
/// `decision_is_never_harvested_from_the_resources_own_state` pins that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptDecision {
    pub decision: DecisionClass,
    pub reason: DecisionReason,
}

/// Stable reason attached to a [`ReceiptDecision`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReason {
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// How to reverse this mutation, for a family with a server-side revision
/// chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackPointer {
    /// Argv **after** the `ferrogate` program name that reverses the change.
    /// Complete: an operator (or a script) runs it without typing an
    /// identifier by hand.
    pub command: Vec<String>,
    /// The revision this mutation created.
    pub created_revision: Attested<String>,
    /// The revision `command` restores.
    pub restores_revision: Attested<String>,
    /// Why `command` is the reversal (rollback vs archive).
    pub note: String,
}

/// What actually became of the mutation — the field an audit pipeline reads to
/// decide whether the change happened.
///
/// A receipt is emitted on **every** terminal path, including the failing ones,
/// because "no output at all" is the one answer an operator cannot audit. The
/// distinction that matters is the last two variants: a server that refused the
/// call changed nothing, while a client that got no authoritative answer knows
/// nothing — the 504-after-commit case, where the mutation may well have
/// landed.
///
/// Crucially, "got an HTTP response" is **not** the same as "got an
/// authoritative answer". A `504` from an intermediary, or a `429` from an edge
/// throttle, is an error envelope that says nothing about whether the write
/// committed. See [`MutationOutcome::from_http_status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationOutcome {
    /// The Control Plane API answered 2xx: the change is applied.
    Applied,
    /// The Control Plane API answered with a **client-error** envelope (a 4xx
    /// other than the retryable-timeout statuses). The server made an
    /// authoritative decision not to apply the change.
    Rejected,
    /// No authoritative answer was obtained: either no HTTP response at all
    /// (connect, timeout, TLS, or a response that could not be read), or a
    /// response whose status is not a decision about the write — a 5xx, or one
    /// of the retryable-timeout statuses `408`/`425`/`429`. The mutation **may
    /// or may not** have been applied server-side; the client cannot tell, and
    /// neither should a consumer of this receipt assume either way.
    Unknown,
    /// Nothing left the process: a `--dry-run`, or a request the client refused
    /// to send. Nothing changed.
    NotSent,
}

impl MutationOutcome {
    /// Stable spelling, matching the serde tag.
    pub fn as_str(self) -> &'static str {
        match self {
            MutationOutcome::Applied => "applied",
            MutationOutcome::Rejected => "rejected",
            MutationOutcome::Unknown => "unknown",
            MutationOutcome::NotSent => "not_sent",
        }
    }

    /// Whether the change is known to have taken effect.
    pub fn is_applied(self) -> bool {
        matches!(self, MutationOutcome::Applied)
    }

    /// What an HTTP status permits the receipt to claim about the write.
    ///
    /// This is derived from [`ExitClass::from_http_status`] rather than from a
    /// second status table, and that is the point: the exit class a `429`
    /// invocation returns is [`ExitClass::Transport`], documented as *"the
    /// request never produced an authoritative server answer"*. If the outcome
    /// were classified independently, one command could exit on the
    /// non-authoritative class while its receipt asserted the server made an
    /// authoritative decision — two fields of one invocation contradicting each
    /// other. Sharing the table makes that unrepresentable, and a status later
    /// moved into the `Transport` arm changes both at once.
    ///
    /// The boundary is *authority*, not success:
    ///
    /// - **2xx** → [`Applied`](MutationOutcome::Applied). The server said yes.
    /// - **4xx except `408`/`425`/`429`** → [`Rejected`](MutationOutcome::Rejected).
    ///   A client error is the server having looked at the request and refused
    ///   it; nothing was applied, and the receipt may say so.
    /// - **5xx** → [`Unknown`](MutationOutcome::Unknown). A `500` after the row
    ///   was written, or a `504` from an intermediary that gave up while the
    ///   gateway committed, is indistinguishable from a `504` before the write.
    /// - **`408`/`425`/`429`** → [`Unknown`](MutationOutcome::Unknown). These
    ///   are timeouts and throttles, and a throttle may be applied at the edge
    ///   *after* the origin accepted the call. They are also exactly the
    ///   statuses this crate already treats as non-authoritative.
    /// - **anything else** (1xx, 3xx, out-of-range) → [`Unknown`](MutationOutcome::Unknown).
    ///   The client has no idea what such a response means for the write, and
    ///   "no idea" is what `unknown` spells.
    pub fn from_http_status(status: u16) -> MutationOutcome {
        match ExitClass::from_http_status(status) {
            ExitClass::Success => MutationOutcome::Applied,
            // The authoritative-refusal classes; every status mapping here is a
            // 4xx the server itself decided.
            ExitClass::Auth | ExitClass::NotFoundConflict | ExitClass::Validation => {
                MutationOutcome::Rejected
            }
            // `Transport` is "no authoritative answer" by its own definition;
            // `Server` is the server failing *after* accepting the request.
            ExitClass::Server | ExitClass::Transport => MutationOutcome::Unknown,
            // `from_http_status` never yields `Usage` today. If a future status
            // is routed there, the honest default is the one that claims least.
            ExitClass::Usage => MutationOutcome::Unknown,
        }
    }
}

/// The failure a non-applied mutation ended on, in the receipt's own
/// vocabulary. Carries no stack of prose: `class` and `code` are what a query
/// selects on, `message` is what a human reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptFailure {
    /// `api` (the server answered with an error envelope), `transport` (no
    /// authoritative answer), `usage`, or `auth`.
    pub class: String,
    /// The server's stable error code, or `client_error` when the failure never
    /// reached the server.
    pub code: String,
    pub message: String,
}

/// Correlation ids the server returned, for joining to gateway evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptCorrelation {
    pub request_id: Attested<String>,
    pub trace_id: Attested<String>,
}

/// The authoritative `client_sent_at`: a time the **server** issued and the
/// client echoed (issue #548).
///
/// Every field states where it came from, so a consumer never has to assume.
///
/// # What "no path from a local clock" does and does not mean
///
/// An earlier draft of this doc claimed flatly that "there is no path from a
/// local clock into this struct". That was false, and worth correcting rather
/// than leaving as reassurance: the fields are `pub`, the type derives
/// `Deserialize`, and both are load-bearing — the CLI's own `ctl` renderers read
/// the fields, and an audit consumer must be able to parse a receipt back.
/// Anyone holding this type can therefore write any number they like into
/// `issued_at_unix`.
///
/// The guarantee that does hold is narrower and checkable, and it is about
/// *production*, not about the type:
///
/// 1. [`ServerIssuedClientSentAt::from_server_time`] is the **only** expression
///    in this crate that constructs the struct, pinned by
///    `the_only_way_to_mint_a_client_sent_at_is_from_a_parsed_server_token`,
///    which scans the crate's own source for a second struct literal.
/// 2. Its only argument is a [`crate::action_identity::ServerIssuedTime`], which
///    has no constructor taking an instant — only
///    [`crate::action_identity::ServerIssuedTime::parse`], over bytes a server
///    sent.
///
/// So a local clock cannot reach this struct along any path the CLI takes, and
/// adding one is a red test rather than a review finding. Deserializing a
/// receipt someone else wrote is *reading a record*, not minting an instant, and
/// [`MutationReceipt::validate`] is what judges a record read back in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerIssuedClientSentAt {
    /// Seconds since the Unix epoch, as the server stated them.
    pub issued_at_unix: u64,
    /// The window the server declared the token valid for. Short by design: a
    /// long TTL lets an attacker pre-fetch tokens and replay them later to
    /// backdate an action.
    pub ttl_seconds: u64,
    /// The action the token was issued for. A token presented with any other
    /// action id is refused before it can reach this struct.
    pub bound_action_id: String,
    /// Always [`crate::action_identity::SERVER_TIME_AUTHORITY`]. Present so the
    /// serialized record names its own authority rather than leaving a reader to
    /// infer it from the field name.
    pub authority: String,
}

impl ServerIssuedClientSentAt {
    /// The single expression in this crate that mints one of these.
    ///
    /// It takes a [`ServerIssuedTime`] and nothing else, and `ServerIssuedTime`
    /// can only be obtained by parsing bytes a server sent. That is the whole
    /// chain, and `the_only_way_to_mint_a_client_sent_at_is_from_a_parsed_server_token`
    /// holds the "single expression" half of it by scanning this crate's source
    /// for a second struct literal.
    pub(crate) fn from_server_time(time: &ServerIssuedTime) -> Self {
        ServerIssuedClientSentAt {
            issued_at_unix: time.issued_at_unix(),
            ttl_seconds: time.ttl_seconds(),
            bound_action_id: time.bound_action_id().to_string(),
            authority: crate::action_identity::SERVER_TIME_AUTHORITY.to_string(),
        }
    }
}

/// What the CLI asserted about itself when it issued this action (issue #548).
///
/// Read the authority column of every field before using one:
///
/// | field | authority |
/// |---|---|
/// | `action_id` | client-minted — an identifier, not a claim |
/// | `client_sent_at` | **server**-issued, client-echoed |
/// | `client_clock_unverified_unix` | client-asserted; evidence about the client, never the event time |
/// | `client_fingerprint` | client-asserted |
/// | `client_reported_ip` | client-asserted; the authoritative source IP is the one the **server** observes and is not in this receipt at all |
///
/// `client_sent_at` and `client_clock_unverified_unix` are both carried on
/// purpose. One field cannot express clock skew: their difference is the finding
/// — a host running hours behind, a suspended VM, a backdated workstation — and
/// it is invisible if only one of the two is recorded. They are never merged,
/// the same rule as the two IPs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptClientIdentity {
    /// The id of the operator action, sent on every request this invocation
    /// issued. Distinct from `idempotency_key`: see the field's own docs.
    pub action_id: String,
    /// The server-issued instant this action echoed, when it held one.
    pub client_sent_at: Attested<ServerIssuedClientSentAt>,
    /// The client's own clock, in seconds since the Unix epoch, read once at
    /// mint time. **Unverified and untrusted.** No authorization or ordering
    /// path may read it; it exists so an auditor can measure the client's skew
    /// against the server-issued instant beside it.
    pub client_clock_unverified_unix: u64,
    /// The rendered client fingerprint. **Not** the `canonical_target_sha256`
    /// action fingerprint on [`ReceiptTarget`] — that digests the *target* of
    /// the call; this describes the *client*, and is not a digest.
    pub client_fingerprint: String,
    /// An address the operator chose to disclose. Client-asserted, opt-in, and
    /// never to be merged with the address the server observes.
    pub client_reported_ip: Attested<String>,
}

/// The decision receipt for one mutating CLI verb — the **only** sanctioned
/// return shape of a mutating command, in both `table` and `json` output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MutationReceipt {
    /// Always [`RECEIPT_OBJECT`].
    pub object: String,
    /// Always [`RECEIPT_VERSION`].
    pub receipt_version: u32,
    pub group: String,
    pub verb: String,
    /// The OpenAPI operation the verb invoked.
    pub operation_id: Attested<String>,
    /// Explicit on every mutation, **never inferred from the verb name**. A
    /// resource whose API happens to spell a verb `dry-run` still reports
    /// `dry_run: false` when it actually issued that call, because this field
    /// describes the client's execution decision, not the endpoint's name.
    pub dry_run: bool,
    /// Whether the change is applied, refused, unknown, or never sent. Read
    /// this before anything else on the receipt: every server-derived field
    /// below is meaningless unless this says `applied`.
    pub outcome: MutationOutcome,
    /// The failure the call ended on, absent when it succeeded.
    pub failure: Attested<ReceiptFailure>,
    pub actor: ReceiptActor,
    pub target: ReceiptTarget,
    pub decision: Attested<ReceiptDecision>,
    pub approval_id: Attested<String>,
    /// The immutable audit id. Null-with-reason on every endpoint today.
    pub audit_id: Attested<String>,
    pub rollback: Attested<RollbackPointer>,
    /// The idempotency key the *request document* carried, when it carried one.
    ///
    /// **Not the same thing as [`ReceiptClientIdentity::action_id`]**, and
    /// merging them would lose information in both directions. An idempotency
    /// key says "do not apply this effect twice"; an action id says "this is the
    /// same operator action, here is its thread". Only `billing` and `agent
    /// submit` thread a key today; every verb carries an action id. A shell loop
    /// re-running one `billing` POST is two actions with one idempotency key,
    /// and an `--all-pages` walk is one action with none at all — an audit trail
    /// that could not tell those apart would misreport both.
    pub idempotency_key: Attested<String>,
    /// When and where this action was issued from, as the client asserted it and
    /// as the server timed it (issue #548).
    pub client_identity: ReceiptClientIdentity,
    pub correlation: ReceiptCorrelation,
    pub http_status: Attested<u16>,
    /// The server's response document verbatim, nested under the envelope.
    /// `null` on a dry run. This is not a "bare body": it is a labelled field
    /// of an attested receipt, so the operator still gets the created object
    /// without the receipt becoming optional.
    pub response: Option<Value>,
}

impl MutationReceipt {
    /// Every [`Attested`] field holds exactly one of a value or a reason, and
    /// the envelope discriminators are the expected constants. Returns the
    /// list of violations; empty means well formed.
    ///
    /// This exists because "null with a stated reason" is only a contract if
    /// something checks it. A receipt that round-trips through JSON with a
    /// bare `null` and no reason would satisfy the type but break the promise.
    pub fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.object != RECEIPT_OBJECT {
            problems.push(format!(
                "object must be '{RECEIPT_OBJECT}', got '{}'",
                self.object
            ));
        }
        if self.receipt_version != RECEIPT_VERSION {
            problems.push(format!(
                "receipt_version must be {RECEIPT_VERSION}, got {}",
                self.receipt_version
            ));
        }
        if self.target.action_fingerprint_contract != ACTION_FINGERPRINT_CONTRACT {
            problems.push(format!(
                "action_fingerprint_contract must be '{ACTION_FINGERPRINT_CONTRACT}', got '{}'",
                self.target.action_fingerprint_contract
            ));
        }
        if !is_canonical_action_fingerprint(&self.target.action_fingerprint) {
            problems.push(format!(
                "action_fingerprint '{}' is not sha256:<64 lowercase hex>",
                self.target.action_fingerprint
            ));
        }
        let mut check = |name: &str, ok: bool| {
            if !ok {
                problems.push(format!(
                    "{name} must carry exactly one of value / absent_reason"
                ));
            }
        };
        check("operation_id", self.operation_id.is_well_formed());
        check("actor.subject", self.actor.subject.is_well_formed());
        check("actor.tenant", self.actor.tenant.is_well_formed());
        check("actor.project", self.actor.project.is_well_formed());
        check("actor.workspace", self.actor.workspace.is_well_formed());
        check(
            "actor.context_name",
            self.actor.context_name.is_well_formed(),
        );
        check(
            "target.resource_id",
            self.target.resource_id.is_well_formed(),
        );
        check(
            "target.object_version",
            self.target.object_version.is_well_formed(),
        );
        check("decision", self.decision.is_well_formed());
        check("failure", self.failure.is_well_formed());
        check("approval_id", self.approval_id.is_well_formed());
        check("audit_id", self.audit_id.is_well_formed());
        check("rollback", self.rollback.is_well_formed());
        check("idempotency_key", self.idempotency_key.is_well_formed());
        check(
            "correlation.request_id",
            self.correlation.request_id.is_well_formed(),
        );
        check(
            "correlation.trace_id",
            self.correlation.trace_id.is_well_formed(),
        );
        check("http_status", self.http_status.is_well_formed());
        check(
            "client_identity.client_sent_at",
            self.client_identity.client_sent_at.is_well_formed(),
        );
        check(
            "client_identity.client_reported_ip",
            self.client_identity.client_reported_ip.is_well_formed(),
        );
        if let Some(pointer) = &self.rollback.value {
            check(
                "rollback.created_revision",
                pointer.created_revision.is_well_formed(),
            );
            check(
                "rollback.restores_revision",
                pointer.restores_revision.is_well_formed(),
            );
        }
        // The action id is what the whole correlation rests on, so a receipt
        // carrying a malformed one is malformed: an id that is not the minted
        // shape is either fabricated or truncated, and either way it will not
        // join to the request the server saw.
        if !crate::action_identity::is_well_formed_action_id(&self.client_identity.action_id) {
            problems.push(format!(
                "client_identity.action_id '{}' is not {}<32 lowercase hex>",
                self.client_identity.action_id,
                crate::action_identity::ACTION_ID_PREFIX
            ));
        }
        // The two fingerprints on this receipt describe different things and
        // are the confusion issue #548 warned about: `target.action_fingerprint`
        // is a `sha256:<64 hex>` digest of the CALL, mirrored from
        // ferrogate-runtime, and `client_identity.client_fingerprint` is a
        // `v1;k=v;...` description of the CLIENT and is not a digest at all.
        // Only the first was pinned here, so a receipt rendering the client
        // fingerprint as `sha256:<hex>` validated clean and re-created exactly
        // that confusion for an audit consumer joining on digests. Both
        // directions are now checked: the shape it must have, and the shape it
        // must not be mistaken for.
        let client_fingerprint = &self.client_identity.client_fingerprint;
        if !client_fingerprint.starts_with(crate::action_identity::IDENTITY_SCHEMA_VERSION) {
            problems.push(format!(
                "client_identity.client_fingerprint '{client_fingerprint}' does not start with \
                 the '{}' schema marker",
                crate::action_identity::IDENTITY_SCHEMA_VERSION
            ));
        }
        if is_canonical_action_fingerprint(client_fingerprint) {
            problems.push(format!(
                "client_identity.client_fingerprint '{client_fingerprint}' is rendered as a \
                 canonical ACTION fingerprint; the client fingerprint describes the client and \
                 is not a digest, and an audit consumer joining the two would join the wrong \
                 records"
            ));
        }
        // A `client_sent_at` bound to a different action than the receipt
        // reports would be a token moved off another action - exactly what the
        // binding exists to prevent, restated here so a hand-built or
        // round-tripped receipt cannot assert it either.
        if let Some(sent_at) = &self.client_identity.client_sent_at.value {
            if sent_at.bound_action_id != self.client_identity.action_id {
                problems.push(format!(
                    "client_sent_at is bound to action '{}' but this receipt reports action '{}'",
                    sent_at.bound_action_id, self.client_identity.action_id
                ));
            }
            if sent_at.authority != crate::action_identity::SERVER_TIME_AUTHORITY {
                problems.push(format!(
                    "client_sent_at.authority must be '{}', got '{}'",
                    crate::action_identity::SERVER_TIME_AUTHORITY,
                    sent_at.authority
                ));
            }
        }
        // Cross-field invariants. Without these the outcome field could
        // disagree with the rest of the receipt and still validate — an
        // `applied` receipt carrying a failure, or a dry run claiming the
        // change landed, are exactly the contradictions an audit consumer
        // cannot resolve from the outside.
        if self.dry_run && self.outcome != MutationOutcome::NotSent {
            problems.push(format!(
                "dry_run receipts must report outcome 'not_sent', got '{}'",
                self.outcome.as_str()
            ));
        }
        if self.outcome.is_applied() && self.failure.value.is_some() {
            problems.push("an applied mutation cannot carry a failure".to_string());
        }
        if matches!(
            self.outcome,
            MutationOutcome::Rejected | MutationOutcome::Unknown
        ) && self.failure.value.is_none()
        {
            problems.push(format!(
                "outcome '{}' must name the failure it ended on",
                self.outcome.as_str()
            ));
        }
        if !self.outcome.is_applied() && self.response.is_some() {
            problems.push(format!(
                "outcome '{}' carries a response document; only an applied mutation has one",
                self.outcome.as_str()
            ));
        }
        // A status the receipt itself reports is the strongest evidence about
        // the write it holds, so the outcome may not contradict it. This is
        // what stops the whole class the field was added for: a `504` receipt
        // claiming `rejected` — "the server decided not to apply the change" —
        // when the write may have committed, or the mirror-image `409`
        // claiming `unknown` and sending an operator to reconcile a mutation
        // the server explicitly refused.
        if let Some(status) = self.http_status.value {
            let implied = MutationOutcome::from_http_status(status);
            if self.outcome != implied {
                problems.push(format!(
                    "outcome '{}' contradicts HTTP {status}, which permits only '{}'",
                    self.outcome.as_str(),
                    implied.as_str()
                ));
            }
        }
        problems
    }

    /// Flat `FIELD`/`VALUE` rows for the `--output table` rendering. An absent
    /// field renders as `null (<code>)` so the table says the same thing the
    /// JSON does — a table that quietly dropped the nulls would re-introduce
    /// the silence in the human format.
    pub fn table_rows(&self) -> Vec<(String, String)> {
        fn cell<T: std::fmt::Display>(field: &Attested<T>) -> String {
            match (&field.value, &field.absent_reason) {
                (Some(value), _) => value.to_string(),
                (None, Some(reason)) => format!("null ({})", reason.code),
                (None, None) => "null (UNATTESTED)".to_string(),
            }
        }
        let mut rows = vec![
            ("object".to_string(), self.object.clone()),
            (
                "receipt_version".to_string(),
                self.receipt_version.to_string(),
            ),
            (
                "command".to_string(),
                format!("{} {}", self.group, self.verb),
            ),
            ("operation_id".to_string(), cell(&self.operation_id)),
            ("dry_run".to_string(), self.dry_run.to_string()),
            ("outcome".to_string(), self.outcome.as_str().to_string()),
            (
                "failure".to_string(),
                match (&self.failure.value, &self.failure.absent_reason) {
                    (Some(failure), _) => {
                        format!("{}/{}: {}", failure.class, failure.code, failure.message)
                    }
                    (None, Some(reason)) => format!("null ({})", reason.code),
                    (None, None) => "null (UNATTESTED)".to_string(),
                },
            ),
            ("actor.subject".to_string(), cell(&self.actor.subject)),
            (
                "actor.credential_source".to_string(),
                self.actor.credential_source.clone(),
            ),
            ("actor.tenant".to_string(), cell(&self.actor.tenant)),
            ("actor.project".to_string(), cell(&self.actor.project)),
            ("actor.workspace".to_string(), cell(&self.actor.workspace)),
            ("actor.context".to_string(), cell(&self.actor.context_name)),
            ("actor.endpoint".to_string(), self.actor.endpoint.clone()),
            (
                "target".to_string(),
                format!("{} {}", self.target.method, self.target.path),
            ),
            (
                "target.resource_id".to_string(),
                cell(&self.target.resource_id),
            ),
            (
                "target.action_fingerprint".to_string(),
                self.target.action_fingerprint.clone(),
            ),
            (
                "target.action_fingerprint_contract".to_string(),
                self.target.action_fingerprint_contract.clone(),
            ),
            (
                "target.object_version".to_string(),
                cell(&self.target.object_version),
            ),
            (
                "decision".to_string(),
                match (&self.decision.value, &self.decision.absent_reason) {
                    (Some(decision), _) => {
                        format!("{} ({})", decision.decision.as_str(), decision.reason.code)
                    }
                    (None, Some(reason)) => format!("null ({})", reason.code),
                    (None, None) => "null (UNATTESTED)".to_string(),
                },
            ),
            ("approval_id".to_string(), cell(&self.approval_id)),
            ("audit_id".to_string(), cell(&self.audit_id)),
            ("idempotency_key".to_string(), cell(&self.idempotency_key)),
            (
                "client.action_id".to_string(),
                self.client_identity.action_id.clone(),
            ),
            (
                // Named for its authority in the human rendering too: an
                // operator reading a table must not have to remember which of
                // the two instants the server stood behind.
                "client.client_sent_at (server-issued)".to_string(),
                match (
                    &self.client_identity.client_sent_at.value,
                    &self.client_identity.client_sent_at.absent_reason,
                ) {
                    (Some(sent_at), _) => format!(
                        "{} (ttl {}s, bound to {})",
                        sent_at.issued_at_unix, sent_at.ttl_seconds, sent_at.bound_action_id
                    ),
                    (None, Some(reason)) => format!("null ({})", reason.code),
                    (None, None) => "null (UNATTESTED)".to_string(),
                },
            ),
            (
                "client.clock (unverified, client-asserted)".to_string(),
                self.client_identity
                    .client_clock_unverified_unix
                    .to_string(),
            ),
            (
                "client.fingerprint".to_string(),
                self.client_identity.client_fingerprint.clone(),
            ),
            (
                "client.reported_ip (client-asserted)".to_string(),
                cell(&self.client_identity.client_reported_ip),
            ),
            ("request_id".to_string(), cell(&self.correlation.request_id)),
            ("trace_id".to_string(), cell(&self.correlation.trace_id)),
            ("http_status".to_string(), cell(&self.http_status)),
        ];
        match (&self.rollback.value, &self.rollback.absent_reason) {
            (Some(pointer), _) => {
                rows.push((
                    "rollback.command".to_string(),
                    format!("ferrogate {}", pointer.command.join(" ")),
                ));
                rows.push((
                    "rollback.created_revision".to_string(),
                    cell(&pointer.created_revision),
                ));
                rows.push((
                    "rollback.restores_revision".to_string(),
                    cell(&pointer.restores_revision),
                ));
            }
            (None, Some(reason)) => {
                rows.push(("rollback".to_string(), format!("null ({})", reason.code)));
            }
            (None, None) => {
                rows.push(("rollback".to_string(), "null (UNATTESTED)".to_string()));
            }
        }
        rows
    }
}

// ---------------------------------------------------------------------------
// The render gate: the structural half of the enforcement.
// ---------------------------------------------------------------------------

/// Rendered payload for a dispatched verb. The inner payload is private, so a
/// `VerbOutput` can only come from [`BareRenderer::render`] or
/// [`ReceiptRenderer::render`] — there is no way to hand the renderer a raw
/// body on behalf of a mutating verb.
#[derive(Debug, Clone, PartialEq)]
pub struct VerbOutput(Payload);

#[derive(Debug, Clone, PartialEq)]
enum Payload {
    Bare(Value),
    Receipt(Box<MutationReceipt>),
}

impl VerbOutput {
    /// The raw body, for a non-mutating verb.
    pub fn body(&self) -> Option<&Value> {
        match &self.0 {
            Payload::Bare(body) => Some(body),
            Payload::Receipt(_) => None,
        }
    }

    /// The receipt, for a mutating verb.
    pub fn receipt(&self) -> Option<&MutationReceipt> {
        match &self.0 {
            Payload::Bare(_) => None,
            Payload::Receipt(receipt) => Some(receipt),
        }
    }

    /// Whether this output is a receipt.
    pub fn is_receipt(&self) -> bool {
        matches!(self.0, Payload::Receipt(_))
    }
}

/// Permission token to render a **bare response body**.
///
/// Has no public constructor and a private field, so the only way to obtain
/// one is [`VerbDescriptor::render_gate`] returning [`RenderGate::Bare`] —
/// which it does exactly for [`VerbEffect::Read`] and [`VerbEffect::Local`]
/// verbs.
#[derive(Debug)]
pub struct BareRenderer<'a> {
    verb: &'a VerbDescriptor,
}

impl<'a> BareRenderer<'a> {
    /// Render the server's document verbatim.
    pub fn render(self, body: Value) -> VerbOutput {
        VerbOutput(Payload::Bare(body))
    }

    /// The verb this token was issued for.
    pub fn verb(&self) -> &'a VerbDescriptor {
        self.verb
    }
}

/// Obligation token for a **mutating** verb: the only thing it will render is
/// a [`MutationReceipt`]. It has no `render(Value)` method, so a mutating verb
/// rendering a bare body is a type error, not a review finding.
#[derive(Debug)]
pub struct ReceiptRenderer<'a> {
    verb: &'a VerbDescriptor,
}

impl<'a> ReceiptRenderer<'a> {
    /// Render the receipt.
    pub fn render(self, receipt: MutationReceipt) -> VerbOutput {
        VerbOutput(Payload::Receipt(Box::new(receipt)))
    }

    /// The verb this obligation was issued for.
    pub fn verb(&self) -> &'a VerbDescriptor {
        self.verb
    }
}

/// The registry's render gate for one resolved verb. Exhaustively matched by
/// every caller, so the receipt arm cannot be forgotten.
#[derive(Debug)]
pub enum RenderGate<'a> {
    /// Non-mutating: a bare body is a legitimate rendering.
    Bare(BareRenderer<'a>),
    /// Mutating: only a receipt is renderable.
    Receipt(ReceiptRenderer<'a>),
}

impl<'a> RenderGate<'a> {
    /// The verb the gate was opened for.
    pub fn verb(&self) -> &'a VerbDescriptor {
        match self {
            RenderGate::Bare(renderer) => renderer.verb(),
            RenderGate::Receipt(renderer) => renderer.verb(),
        }
    }

    /// Whether this gate demands a receipt.
    pub fn requires_receipt(&self) -> bool {
        matches!(self, RenderGate::Receipt(_))
    }
}

impl VerbDescriptor {
    /// Open the render gate for this verb (issue #505).
    ///
    /// This is the single seam between "the registry says what this verb does"
    /// and "the process is allowed to print X". It is total over
    /// [`VerbEffect`], so a new effect variant forces every call site to be
    /// revisited.
    pub fn render_gate(&self) -> RenderGate<'_> {
        match self.effect {
            VerbEffect::Read | VerbEffect::Local => RenderGate::Bare(BareRenderer { verb: self }),
            VerbEffect::Mutating => RenderGate::Receipt(ReceiptRenderer { verb: self }),
        }
    }
}

// ---------------------------------------------------------------------------
// Method/effect exceptions: where the HTTP verb does not predict the effect.
// ---------------------------------------------------------------------------

/// One verb whose declared [`VerbEffect`] deliberately disagrees with the HTTP
/// method its builder emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodEffectException {
    pub group: &'static str,
    pub verb: &'static str,
    /// The method the family builder emits for this verb. Stated so a builder
    /// change invalidates the exception instead of silently widening it.
    pub method: &'static str,
    /// The effect that is true of the verb, regardless of the method.
    pub effect: VerbEffect,
    /// Why the method is not the truth here. Required prose: an exception with
    /// no stated reason is indistinguishable from a misclassification someone
    /// silenced.
    pub why: &'static str,
}

/// Every verb whose effect the HTTP method gets wrong.
///
/// The classification guard in `receipt_test.rs` derives a verb's effect
/// independently by rebuilding its request through the real family builder and
/// reading the method. That is the right instinct — it is the only witness the
/// test has that is not the field under test — but the method is a *proxy* for
/// the effect, not the effect itself, and a bare `assert_eq!(!method_is_safe,
/// verb.is_mutating())` made the proxy authoritative. It therefore did not
/// detect misclassification of effect; it detected disagreement with the
/// method, and it **pinned the one known-wrong classification in place**:
/// correcting `mcp-identity callback` to `mutating` used to fail the guard.
///
/// This list is that guard's escape hatch, and it is deliberately narrow: an
/// entry must name the method it expects, so it stops applying the moment the
/// builder changes, and `method_effect_exceptions_are_all_live_and_needed`
/// fails on any entry that names an unregistered verb, states the wrong
/// method, or agrees with the method (i.e. is no longer an exception at all).
pub const METHOD_EFFECT_EXCEPTIONS: &[MethodEffectException] = &[MethodEffectException {
    group: "mcp-identity",
    verb: "callback",
    method: "GET",
    effect: VerbEffect::Mutating,
    why: "completeMcpIdentityOauth is a GET only because it is the OAuth redirect target the \
          authorization server sends the browser to. It exchanges the authorization code and \
          persists an identity grant, so it changes Control-Plane state and owes the operator a \
          receipt exactly like `authorize` does.",
}];

/// The declared effect for `group verb` when the HTTP method is not a reliable
/// witness, or `None` when the method is.
pub fn method_effect_exception(group: &str, verb: &str) -> Option<&'static MethodEffectException> {
    METHOD_EFFECT_EXCEPTIONS
        .iter()
        .find(|exception| exception.group == group && exception.verb == verb)
}

// ---------------------------------------------------------------------------
// Revision chains and rollback pointers.
// ---------------------------------------------------------------------------

/// A resource family with a server-side revision chain, and how a mutation to
/// it is reversed.
///
/// Membership is not "the family's response happens to contain the word
/// `revision`". It is the conjunction of two facts, both checkable:
///
/// 1. the family's objects really are an append-only chain of revisions, and
/// 2. the family's **own request builder** accepts `rollback_verb` and
///    `archive_verb` with the argument shape [`RollbackPointer::command`]
///    emits — because that doc promises the argv is safe to execute verbatim.
///
/// `rollback_pointer_argv_round_trips_through_every_familys_own_builder` holds
/// (2) for every entry in [`REVISIONED_FAMILIES`], so an entry no test names
/// cannot exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevisionedFamily {
    /// Registry group name.
    pub group: &'static str,
    /// Verb that promotes an earlier revision back to live. Takes the chain id
    /// plus `--data {"revision":N}`.
    pub rollback_verb: &'static str,
    /// Verb that retires the revision this mutation created, used when the
    /// created revision is the first in its chain and there is nothing to roll
    /// back *to*. Takes the chain id plus the revision as a second segment.
    pub archive_verb: &'static str,
    /// Response field naming the revision number.
    pub revision_key: &'static str,
    /// Response field naming the chain id, when it differs from `id`.
    pub chain_id_keys: &'static [&'static str],
}

/// The families whose objects are revision chains **and** whose builders accept
/// the reversal argv the pointer emits. Everything else gets a rollback pointer
/// that is explicitly absent with
/// [`absence_codes::RESOURCE_HAS_NO_REVISIONS`] rather than a missing key.
///
/// # Why this list is one entry
///
/// It used to carry `agent-schedules` and `gateway-configs` as well, on the
/// strength of their objects carrying a `revision` counter. Neither is a
/// revision chain: both route through `build_crud`, so `revision` is a
/// concurrency token on a single mutable row, and neither has a verb that
/// restores an earlier one. The pointer emitted for them was therefore not
/// merely uninformative, it was **destructive**: a `gateway-configs update` at
/// revision 4 produced
/// `ctl gateway-configs replace prod --data '{"revision":3}'`, which is a
/// `PUT /admin/v1/gateway-configs/prod` that replaces the whole config profile
/// with a one-field document — and the note above it claimed revisions were
/// append-only. On a first revision the archive arm produced
/// `ctl agent-schedules delete <id> 1`, addressing
/// `DELETE /admin/v1/agent-schedules/<id>/1`, a path the API does not have.
/// A receipt is an audit artifact, so a field that is wrong is worse than a
/// field that is absent; both now report
/// [`absence_codes::RESOURCE_HAS_NO_REVISIONS`], which is true of them.
pub const REVISIONED_FAMILIES: &[RevisionedFamily] = &[RevisionedFamily {
    // `rollback` is POST /guardrail-policies/{id}/rollback with a revision
    // body; `archive` is DELETE /guardrail-policies/{id}/revisions/{revision}.
    // Both are real verbs of this family's own builder — see
    // `guardrail::build_guardrail_policies`.
    group: "guardrail-policies",
    rollback_verb: "rollback",
    archive_verb: "archive",
    revision_key: "revision",
    chain_id_keys: &["policy_id", "id"],
}];

/// The revisioned-family entry for `group`, if any.
pub fn revisioned_family(group: &str) -> Option<&'static RevisionedFamily> {
    REVISIONED_FAMILIES
        .iter()
        .find(|family| family.group == group)
}

// ---------------------------------------------------------------------------
// Planning and executing one mutation.
// ---------------------------------------------------------------------------

/// The response fields a receipt harvests, in priority order. Every list is
/// checked against the contract and currently yields nothing for the audit and
/// approval keys — which is the point: the receipt reports the gap rather than
/// pretending the identifier does not exist.
///
/// Priority is load-bearing, not cosmetic: `revision` outranks `version`
/// outranks `etag` because that is the order of specificity with which the
/// contract names *the changed object's* version, and
/// `object_version_prefers_the_most_specific_key` pins it.
const AUDIT_ID_KEYS: &[&str] = &["audit_id", "audit_event_id", "audit_log_id"];
const APPROVAL_ID_KEYS: &[&str] = &["approval_id", "tool_approval_id"];
const OBJECT_VERSION_KEYS: &[&str] = &["revision", "version", "etag", "updated_at_unix"];
/// Keys naming the object a mutation addressed, in priority order.
const RESOURCE_ID_KEYS: &[&str] = &["id", "policy_id"];

/// One planned mutating invocation: the verb obligation, the request it will
/// issue, and whether it is a dry run.
///
/// Construction *requires* a [`ReceiptRenderer`], which only a mutating verb's
/// render gate produces. A read verb therefore cannot even build a plan, and a
/// mutating verb cannot escape one.
#[derive(Debug)]
pub struct MutationPlan<'a> {
    renderer: ReceiptRenderer<'a>,
    group: String,
    spec: RequestSpec,
    dry_run: bool,
    target: CliActionTarget,
    actor: ReceiptActor,
    /// The id path segments the invocation addressed, joined with `/`. `None`
    /// for a collection-scoped verb.
    resource_id: Option<String>,
    idempotency_key: Attested<String>,
    /// The identity the transport will send. A clone of the caller's, sharing
    /// its server-time slot, so the receipt reports the action that was
    /// actually issued rather than a second one minted here.
    identity: ClientActionIdentity,
}

/// What the client learned about the mutation, and the only input
/// [`MutationPlan::build_receipt`] reads. Total over the four terminal states,
/// so no path through [`MutationPlan::execute`] can end without a receipt.
#[derive(Debug)]
enum Executed<'a> {
    /// `--dry-run`: nothing left the process.
    NotSent,
    /// The Control Plane API answered 2xx.
    Applied(&'a ApiResponse),
    /// The call failed. The `MutationOutcome` is derived from the error class,
    /// because "the server refused" and "we never found out" are different
    /// facts an operator acts on differently.
    Failed(&'a CliError),
}

/// The result of executing a mutation: **always** a receipt, plus the failure
/// when there was one.
///
/// This type exists because `Result<VerbOutput, CliError>` cannot express the
/// contract. Under the old signature a non-2xx returned `Err` before rendering,
/// so `--output json` printed an empty stdout and a line of prose on stderr: a
/// `guardrail-policies activate` that 504s after the server committed recorded
/// *nothing* in an audit pipeline — no `dry_run`, no status, no fingerprint, no
/// statement that the outcome is unknown. The receipt is the output contract of
/// a mutating verb; a contract with no way to say "this did not happen" fails
/// exactly where an operator needs it.
///
/// The caller renders `output` to stdout and then propagates `failure`, so the
/// process still exits on the error's own exit class.
#[derive(Debug)]
pub struct MutationReport {
    output: VerbOutput,
    failure: Option<CliError>,
}

impl MutationReport {
    /// The receipt, produced on every path.
    pub fn output(&self) -> &VerbOutput {
        &self.output
    }

    /// The failure this mutation ended on, if any.
    pub fn failure(&self) -> Option<&CliError> {
        self.failure.as_ref()
    }

    /// Split into the renderable receipt and the failure to propagate. The
    /// caller is expected to print the receipt **before** returning the error.
    pub fn into_parts(self) -> (VerbOutput, Option<CliError>) {
        (self.output, self.failure)
    }

    /// Collapse to a plain result, discarding the failing receipt. Only for
    /// callers that have no stdout to write to (tests, internal probes) —
    /// the shipped command path must use [`MutationReport::into_parts`].
    pub fn into_result(self) -> CliResult<VerbOutput> {
        match self.failure {
            Some(error) => Err(error),
            None => Ok(self.output),
        }
    }
}

impl From<VerbOutput> for MutationReport {
    /// A receipt with no failure — the dry-run path, which cannot fail once the
    /// plan exists.
    fn from(output: VerbOutput) -> MutationReport {
        MutationReport {
            output,
            failure: None,
        }
    }
}

impl<'a> MutationPlan<'a> {
    /// Plan a mutation. Pure: derives the canonical target and actor identity
    /// from the same [`RequestSpec`] and [`EffectiveContext`] the transport
    /// will use, so the receipt cannot describe a different call.
    pub fn new(
        renderer: ReceiptRenderer<'a>,
        group: impl Into<String>,
        spec: RequestSpec,
        segments: &[String],
        context: &EffectiveContext,
        identity: &ClientActionIdentity,
        dry_run: bool,
    ) -> CliResult<MutationPlan<'a>> {
        let group = group.into();
        let target = CliActionTarget::for_request(&context.endpoint, &spec)?;
        let actor = ReceiptActor {
            subject: Attested::absent(
                absence_codes::SUBJECT_NOT_LOCALLY_RESOLVABLE,
                "the CLI authenticates with a bearer token and no Control Plane API mutation \
                 response echoes the authenticated subject back; resolve it from the audit \
                 plane once one does",
            ),
            credential_source: credential_source(&context.auth),
            tenant: Attested::or_absent(
                context.tenant.clone(),
                absence_codes::CONTEXT_DECLARES_NO_SCOPE,
                "no tenant was resolved from --tenant, FERROGATE_TENANT, or the selected context",
            ),
            project: Attested::or_absent(
                context.project.clone(),
                absence_codes::CONTEXT_DECLARES_NO_SCOPE,
                "the selected context declares no project",
            ),
            workspace: Attested::or_absent(
                context.workspace.clone(),
                absence_codes::CONTEXT_DECLARES_NO_SCOPE,
                "the selected context declares no workspace",
            ),
            context_name: Attested::or_absent(
                context.context_name.clone(),
                absence_codes::CONTEXT_DECLARES_NO_SCOPE,
                "the invocation used flags/env only; no named context was selected",
            ),
            endpoint: context.endpoint.clone(),
        };
        // The id the *invocation* addressed. A collection verb has none until
        // the server assigns one, which `harvested_resource_id` picks up off
        // the response — this is only the fallback for the paths where no
        // response exists (dry run, refusal, ambiguous failure).
        let resource_id = (!segments.is_empty()).then(|| segments.join("/"));
        let idempotency_key = Attested::or_absent(
            spec.body
                .as_ref()
                .and_then(|body| body.get("idempotency_key"))
                .and_then(Value::as_str)
                .map(str::to_string),
            absence_codes::NO_IDEMPOTENCY_KEY_SUPPLIED,
            "the request document carried no idempotency_key, so a retry is not provably the \
             same call",
        );
        Ok(MutationPlan {
            renderer,
            group,
            spec,
            dry_run,
            target,
            actor,
            resource_id,
            idempotency_key,
            identity: identity.clone(),
        })
    }

    /// The request this plan *would* issue. Exposed so a caller can inspect it
    /// (and so a dry run can print it) without executing.
    pub fn spec(&self) -> &RequestSpec {
        &self.spec
    }

    /// Whether this plan is a dry run.
    pub fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    /// Produce the dry-run receipt.
    ///
    /// **Takes no transport.** There is no `Transport` and no
    /// [`ControlPlaneClient`] in this function's signature or body, so it
    /// cannot issue a request — the guarantee is structural, not a matter of
    /// remembering an early return. Every server-derived field comes back
    /// `null` with [`absence_codes::DRY_RUN_NOT_EXECUTED`].
    pub fn dry_run(self) -> VerbOutput {
        let verb = self.renderer.verb().clone();
        let receipt = self.build_receipt(&verb, Executed::NotSent, None);
        self.renderer.render(receipt)
    }

    /// Issue the mutation and produce its receipt — **on every path**,
    /// including a non-2xx and a transport failure that never got an answer.
    /// See [`MutationReport`].
    pub async fn send<T: Transport>(self, client: &ControlPlaneClient<T>) -> MutationReport {
        let verb = self.renderer.verb().clone();
        // Read the server-issued time the identity holds BEFORE the call. The
        // client harvests a fresh token off the response, and reading afterwards
        // would have the receipt claim the request carried an instant that in
        // fact arrived with the answer to it.
        let presented = self.identity.server_issued_time();
        let (receipt, failure) = match client.send(&self.spec).await {
            Ok(response) => (
                self.build_receipt(&verb, Executed::Applied(&response), presented),
                None,
            ),
            Err(error) => (
                self.build_receipt(&verb, Executed::Failed(&error), presented),
                Some(error),
            ),
        };
        MutationReport {
            output: self.renderer.render(receipt),
            failure,
        }
    }

    /// Route on the dry-run flag. The dry-run arm never borrows `client`.
    pub async fn execute<T: Transport>(self, client: &ControlPlaneClient<T>) -> MutationReport {
        if self.dry_run {
            return MutationReport {
                output: self.dry_run(),
                failure: None,
            };
        }
        self.send(client).await
    }

    fn build_receipt(
        &self,
        verb: &VerbDescriptor,
        executed: Executed<'_>,
        presented_time: Option<ServerIssuedTime>,
    ) -> MutationReceipt {
        let response = match executed {
            Executed::Applied(response) => Some(response),
            Executed::NotSent | Executed::Failed(_) => None,
        };
        let body = response.map(|response| &response.body);
        let outcome = match &executed {
            Executed::NotSent => MutationOutcome::NotSent,
            Executed::Applied(_) => MutationOutcome::Applied,
            Executed::Failed(error) => match error {
                // An error envelope is NOT automatically a refusal. A 4xx is
                // the server having looked at the request and said no; a 5xx or
                // a 408/425/429 is the server (or an intermediary) failing to
                // answer for the write at all - the 504-after-commit case,
                // where the gateway committed and a proxy gave up. Folding the
                // second into `rejected` would have the receipt state
                // authoritatively that nothing happened on exactly the
                // invocation where the operator most needs to reconcile.
                CliError::Api(api) => MutationOutcome::from_http_status(api.http_status),
                // No authoritative answer. The request may have been delivered
                // and committed before the connection died, so claiming it did
                // not happen would be a fabrication in the opposite direction.
                CliError::Transport(_) => MutationOutcome::Unknown,
                // `ControlPlaneClient::send` only raises these from
                // `prepare_request`, i.e. before the transport is touched.
                CliError::Usage(_) | CliError::Auth(_) => MutationOutcome::NotSent,
            },
        };
        // The reason every server-derived field is null, stated once and used
        // everywhere so a failing receipt cannot claim `dry_run` semantics on
        // one field and something else on the next.
        let (missing_code, missing_detail): (&str, String) = match outcome {
            MutationOutcome::Applied => ("", String::new()),
            MutationOutcome::NotSent if self.dry_run => (
                absence_codes::DRY_RUN_NOT_EXECUTED,
                "this invocation was a dry run: no state-changing request was issued".to_string(),
            ),
            MutationOutcome::NotSent => (
                absence_codes::REQUEST_NOT_SENT,
                "the request was rejected locally and never left the process, so nothing changed"
                    .to_string(),
            ),
            MutationOutcome::Rejected => (
                absence_codes::MUTATION_NOT_APPLIED,
                "the Control Plane API refused this mutation, so no server-side artifact of the \
                 change exists"
                    .to_string(),
            ),
            // The code is the stable discriminator and does not vary. The prose
            // names *which* silence it was, because "the API answered 504" and
            // "nothing came back at all" are reconciled differently — the first
            // has a status and correlation ids to join on.
            MutationOutcome::Unknown => (
                absence_codes::MUTATION_OUTCOME_UNKNOWN,
                match &executed {
                    Executed::Failed(CliError::Api(api)) => format!(
                        "the Control Plane API answered {}, which is not an authoritative answer \
                         about the write: the mutation may or may not have been applied \
                         server-side, and this client cannot tell which",
                        api.http_status
                    ),
                    _ => "no authoritative response was obtained: the mutation may or may not \
                          have been applied server-side, and this client cannot tell which"
                        .to_string(),
                },
            ),
        };
        let missing_detail = missing_detail.as_str();
        MutationReceipt {
            object: RECEIPT_OBJECT.to_string(),
            receipt_version: RECEIPT_VERSION,
            group: self.group.clone(),
            verb: verb.name.clone(),
            operation_id: Attested::or_absent(
                verb.operation_id.clone(),
                absence_codes::LOCAL_VERB,
                "this verb maps to no Control Plane API operation",
            ),
            dry_run: self.dry_run,
            outcome,
            failure: match &executed {
                Executed::Failed(error) => Attested::present(receipt_failure(error)),
                Executed::Applied(_) => Attested::absent(
                    absence_codes::MUTATION_SUCCEEDED,
                    "the Control Plane API accepted this mutation",
                ),
                Executed::NotSent => Attested::absent(missing_code, missing_detail),
            },
            actor: self.actor.clone(),
            target: ReceiptTarget {
                group: self.group.clone(),
                resource_id: self.attested_resource_id(body),
                method: self.spec.method.as_str().to_string(),
                path: self.spec.path.clone(),
                action: CLI_ACTION_CLASS.to_string(),
                canonical_target: self.target.canonical_json(),
                action_fingerprint: self.target.fingerprint(),
                action_fingerprint_contract: ACTION_FINGERPRINT_CONTRACT.to_string(),
                object_version: match body {
                    Some(body) => Attested::or_absent(
                        envelope_scalar(body, OBJECT_VERSION_KEYS),
                        absence_codes::NO_OBJECT_VERSION,
                        "the response document named no revision, version, or etag for the \
                         changed object",
                    ),
                    None => Attested::absent(missing_code, missing_detail),
                },
            },
            // Never harvested from the response. See `ReceiptDecision`: the
            // `decision` a response carries is the resource's own state, not a
            // verdict on this call, and no operation in the contract returns
            // the latter.
            decision: Attested::absent(
                absence_codes::NO_DECISION_IN_CONTRACT,
                "no Control Plane API operation returns a governance verdict on the CLI call \
                 itself; the `decision` a response may carry describes the resource's own state \
                 (an approval's verdict, a payment attempt's outcome) and is deliberately not \
                 reported here - see issue #505",
            ),
            approval_id: match body {
                Some(body) => Attested::or_absent(
                    envelope_scalar(body, APPROVAL_ID_KEYS),
                    absence_codes::NO_APPROVAL_ID_IN_CONTRACT,
                    "this endpoint's response schema declares no approval identifier; the \
                     mutation crossed no approval gate",
                ),
                None => Attested::absent(missing_code, missing_detail),
            },
            audit_id: match body {
                Some(body) => Attested::or_absent(
                    envelope_scalar(body, AUDIT_ID_KEYS),
                    absence_codes::NO_AUDIT_ID_IN_CONTRACT,
                    "this endpoint returns no audit identifier (none of the 135 mutating \
                     operations in the contract does); the audit row exists server-side but \
                     cannot be addressed from this response - see issue #505",
                ),
                None => Attested::absent(missing_code, missing_detail),
            },
            // "This family has no revision chain" is a fact about the family,
            // not about this call, so it is reported even on a dry run or a
            // refusal - `rollback_pointer` checks the family before it looks
            // at the body.
            rollback: self.rollback_pointer(body, missing_code, missing_detail),
            idempotency_key: self.idempotency_key.clone(),
            client_identity: self.client_identity(&executed, presented_time),
            correlation: ReceiptCorrelation {
                request_id: match (response, &executed) {
                    (Some(response), _) => Attested::or_absent(
                        response.request_id.clone(),
                        absence_codes::NO_CORRELATION_ID,
                        "the response carried no x-request-id header or envelope request_id",
                    ),
                    // A refusal still correlates: the server's error envelope
                    // carries the same ids, and a failed mutation is precisely
                    // when an operator needs to join to gateway evidence.
                    (None, Executed::Failed(CliError::Api(api))) => Attested::or_absent(
                        api.request_id.clone(),
                        absence_codes::NO_CORRELATION_ID,
                        "the error response carried no x-request-id header or envelope request_id",
                    ),
                    _ => Attested::absent(missing_code, missing_detail),
                },
                trace_id: match (response, &executed) {
                    (Some(response), _) => Attested::or_absent(
                        response.trace_id.clone(),
                        absence_codes::NO_CORRELATION_ID,
                        "the response carried no x-trace-id header",
                    ),
                    (None, Executed::Failed(CliError::Api(api))) => Attested::or_absent(
                        api.trace_id.clone(),
                        absence_codes::NO_CORRELATION_ID,
                        "the error response carried no x-trace-id header",
                    ),
                    _ => Attested::absent(missing_code, missing_detail),
                },
            },
            http_status: match (response, &executed) {
                (Some(response), _) => Attested::present(response.status),
                (None, Executed::Failed(CliError::Api(api))) => Attested::present(api.http_status),
                (None, Executed::Failed(CliError::Transport(_))) => Attested::absent(
                    absence_codes::NO_HTTP_RESPONSE,
                    "the transport obtained no authoritative HTTP response",
                ),
                _ => Attested::absent(missing_code, missing_detail),
            },
            response: body.cloned(),
        }
    }

    /// Project the invocation's [`ClientActionIdentity`] onto the receipt
    /// (issue #548).
    ///
    /// `presented_time` is the server-issued instant the request **carried**,
    /// read before the call. Three things are deliberate here:
    ///
    /// 1. **A dry run reports no `client_sent_at`.** Nothing was sent, so no
    ///    instant was presented, and the absence code says exactly that rather
    ///    than reusing a token the identity happens to hold.
    /// 2. **A sent request with no token also reports an absence**, coded
    ///    [`absence_codes::NO_SERVER_TIME_TOKEN`], not a local clock reading.
    ///    That is the whole point of the design: the audit instant is the
    ///    server's or it is null.
    ///
    ///    **This is the arm that runs, in every deployment that exists.** No
    ///    control plane issues a time token today, and a mutating verb is always
    ///    the first request of its action anyway, so `(true, None)` is the arm
    ///    100% of real receipts take — which is exactly why it needs a test of
    ///    its own rather than inheriting confidence from the dry-run arm beside
    ///    it. `an_executed_mutation_with_no_token_refuses_to_stand_the_local_clock_in`
    ///    is that test, and the mutation it exists to catch is filling this arm
    ///    with `self.identity.client_clock().unverified_unix_seconds()`: the
    ///    local clock wearing the server's authority, producing a perfectly
    ///    plausible instant that nothing else in the receipt contradicts.
    ///    `validate()` cannot see it (a forger sets `bound_action_id` and
    ///    `authority` too) and the `SystemTime::now()` source guard cannot see it
    ///    (it adds no clock read — it launders one that was already taken).
    /// 3. **`client_clock_unverified_unix` is always present**, because it is
    ///    always knowable and it is the only evidence of client skew. It is a
    ///    plain `u64` rather than an [`Attested`] for that reason — it is never
    ///    absent, and dressing it as attested would put it on the same footing
    ///    as the server-issued field beside it.
    fn client_identity(
        &self,
        executed: &Executed<'_>,
        presented_time: Option<ServerIssuedTime>,
    ) -> ReceiptClientIdentity {
        let sent = !matches!(executed, Executed::NotSent);
        let client_sent_at = match (sent, presented_time) {
            (true, Some(time)) => {
                Attested::present(ServerIssuedClientSentAt::from_server_time(&time))
            }
            (true, None) => Attested::absent(
                absence_codes::NO_SERVER_TIME_TOKEN,
                "no server-issued time token was held when this request was prepared (the \
                 control plane issues none today, and the first request of an invocation has \
                 nothing to echo yet); the client clock is deliberately NOT used to fill this \
                 field, and the server's own receive time still bounds the action",
            ),
            (false, _) => Attested::absent(
                absence_codes::REQUEST_NOT_SENT,
                "no request left the process, so no server-issued instant was presented",
            ),
        };
        ReceiptClientIdentity {
            action_id: self.identity.action_id().to_string(),
            client_sent_at,
            client_clock_unverified_unix: self.identity.client_clock().unverified_unix_seconds(),
            client_fingerprint: self.identity.fingerprint().render(),
            client_reported_ip: Attested::or_absent(
                self.identity
                    .fingerprint()
                    .reported_ip()
                    .map(str::to_string),
                absence_codes::NO_CLIENT_REPORTED_IP,
                "the operator disclosed no client-side address; the authoritative source IP is \
                 the one the server observes, which this client cannot see and must not guess",
            ),
        }
    }

    /// The id of the object the mutation addressed — harvested from the
    /// response when the server assigned it, and otherwise the id segments the
    /// invocation named.
    ///
    /// The response is consulted *first* for a collection verb, because that is
    /// the whole point: `ctl projects create` used to leave this `null` with
    /// "the server assigns the id in the response" even though the response had
    /// already arrived carrying `proj_1`, so an audit query keyed on
    /// `target.resource_id` could not say what was created and the operator had
    /// to parse the nested raw body — the bare-body reading this receipt exists
    /// to remove.
    fn attested_resource_id(&self, body: Option<&Value>) -> Attested<String> {
        if let Some(addressed) = &self.resource_id {
            return Attested::present(addressed.clone());
        }
        match body {
            Some(body) => Attested::or_absent(
                envelope_scalar(body, RESOURCE_ID_KEYS),
                absence_codes::RESPONSE_NAMES_NO_RESOURCE_ID,
                "the verb addressed a collection and the response document named no single id \
                 for the object it created",
            ),
            None => Attested::absent(
                absence_codes::COLLECTION_SCOPED_MUTATION,
                "the verb addresses a collection and no response was obtained, so no id was \
                 assigned to name",
            ),
        }
    }

    /// Derive the reversal pointer for the changed object.
    fn rollback_pointer(
        &self,
        body: Option<&Value>,
        missing_code: &str,
        missing_detail: &str,
    ) -> Attested<RollbackPointer> {
        let Some(family) = revisioned_family(&self.group) else {
            return Attested::absent(
                absence_codes::RESOURCE_HAS_NO_REVISIONS,
                "this resource family has no server-side revision chain, so there is no \
                 revision to roll back to; reverse it by re-applying the prior document",
            );
        };
        let Some(body) = body else {
            return Attested::absent(missing_code, missing_detail);
        };
        let Some(revision) = envelope_scalar(body, &[family.revision_key]) else {
            return Attested::absent(
                absence_codes::RESPONSE_CARRIES_NO_REVISION,
                "the response named no revision, so the reversal target cannot be derived \
                 without a follow-up read",
            );
        };
        // The chain id comes from the response when the server named it, and
        // otherwise from the id segments the operator addressed - never from
        // prose, so the emitted command is always complete.
        let chain_id = envelope_scalar(body, family.chain_id_keys)
            .or_else(|| self.resource_id.clone())
            .unwrap_or_default();
        let previous = revision
            .parse::<u64>()
            .ok()
            .filter(|revision| *revision > 1)
            .map(|revision| (revision - 1).to_string());
        let pointer = match previous {
            Some(previous) => RollbackPointer {
                command: vec![
                    "ctl".to_string(),
                    self.group.clone(),
                    family.rollback_verb.to_string(),
                    chain_id,
                    "--data".to_string(),
                    format!("{{\"revision\":{previous}}}"),
                ],
                created_revision: Attested::present(revision.clone()),
                restores_revision: Attested::present(previous),
                note: format!(
                    "revisions are append-only, so reversing revision {revision} means \
                     promoting its predecessor with `{}`",
                    family.rollback_verb
                ),
            },
            None => RollbackPointer {
                command: vec![
                    "ctl".to_string(),
                    self.group.clone(),
                    family.archive_verb.to_string(),
                    chain_id,
                    revision.clone(),
                ],
                created_revision: Attested::present(revision),
                restores_revision: Attested::absent(
                    absence_codes::NO_PRIOR_REVISION,
                    "this is the first revision in its chain; there is no earlier revision to \
                     restore, so the reversal retires it instead",
                ),
                note: format!(
                    "no predecessor exists, so the reversal is `{}`, not a rollback",
                    family.archive_verb
                ),
            },
        };
        Attested::present(pointer)
    }
}

/// Project a [`CliError`] onto the receipt's failure vocabulary.
///
/// The server's own `code` survives when there is one, so an audit query can
/// select `failure.code == "revision_conflict"` without parsing prose.
fn receipt_failure(error: &CliError) -> ReceiptFailure {
    match error {
        CliError::Api(api) => ReceiptFailure {
            class: "api".to_string(),
            code: api.code.clone(),
            message: api.message.clone(),
        },
        CliError::Transport(message) => ReceiptFailure {
            class: "transport".to_string(),
            code: "no_authoritative_response".to_string(),
            message: message.clone(),
        },
        CliError::Usage(message) => ReceiptFailure {
            class: "usage".to_string(),
            code: "client_error".to_string(),
            message: message.clone(),
        },
        CliError::Auth(message) => ReceiptFailure {
            class: "auth".to_string(),
            code: "client_error".to_string(),
            message: message.clone(),
        },
    }
}

/// How the credential was obtained — never the credential itself.
///
/// `AuthSource::Inline { token }` holds a plaintext bearer token, and this
/// function is the only thing standing between it and a receipt piped into an
/// audit query. Returning `"inline"` — the *shape* of the source, never the
/// material — is the whole contract;
/// `receipt_never_carries_the_token_it_authenticated_with` pins it by asserting
/// on the rendered JSON and table, not on this function's return value.
///
/// Since #548 the rule has one definition, [`AuthSource::audit_source`], shared
/// with the client fingerprint. Two copies of "what is safe to print about a
/// credential" is one copy too many: the second would be the one nobody
/// remembered to update.
fn credential_source(auth: &AuthSource) -> String {
    auth.audit_source()
}

/// A scalar the receipt is willing to attest: a non-empty string or a number.
fn attestable_scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(text) if !text.is_empty() => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// The single resource object a Control Plane API response envelope wraps, if
/// the envelope is unambiguous about which one it is.
///
/// Every mutating 2xx schema in the contract is either the object itself or
/// `{"object": "<type>", "<resource>": { … }}`. So the resource is: the one
/// object-valued sibling other than the `object` discriminator. Two of them
/// means the envelope names no single subject, and the honest answer is to
/// harvest nothing rather than to pick one.
fn wrapped_resource(body: &Value) -> Option<&Value> {
    let map = body.as_object()?;
    let mut nested = map
        .iter()
        .filter(|(key, value)| key.as_str() != "object" && value.is_object());
    let (_, only) = nested.next()?;
    match nested.next() {
        Some(_) => None,
        None => Some(only),
    }
}

/// The first scalar found under any of `keys`, searched **only** where the
/// contract puts the changed object: the envelope's top level, and then the one
/// resource object it wraps.
///
/// This replaced a depth-4 depth-first walk of the whole document, which was
/// wrong in two compounding ways. Sibling order is alphabetical (`serde_json`
/// is built without `preserve_order` here), so which of several equally-deep
/// matches won was decided by key spelling; and the walk descended into nested
/// sub-documents, where a rule's or plugin's own `version` — `SkillPackage`,
/// `AssetSummary`, `AdminPlugin`, `X402ConversionRule` all declare one — would
/// be attested as `target.object_version`, a field documented as the version of
/// the *changed object*. Bounding the search to the envelope makes the answer a
/// function of the contract's shape instead of a function of alphabetization.
fn envelope_scalar(body: &Value, keys: &[&str]) -> Option<String> {
    let map = body.as_object()?;
    for key in keys {
        if let Some(found) = map.get(*key).and_then(attestable_scalar) {
            return Some(found);
        }
    }
    let resource = wrapped_resource(body)?.as_object()?;
    for key in keys {
        if let Some(found) = resource.get(*key).and_then(attestable_scalar) {
            return Some(found);
        }
    }
    None
}

#[cfg(test)]
#[path = "receipt_test.rs"]
mod receipt_test;
