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
//! `docs/openapi/admin-api.openapi.json` at the time of writing found that
//! **117 of 117** coverable mutating operations declare no audit identifier in
//! any 2xx response schema, and zero declare a `dry_run` echo. Issue #505 is
//! explicit that this slice must *record* that gap, not add the server-side
//! write path, so the receipt reports it in a machine-greppable way:
//!
//! ```sh
//! ferrogate ctl <group> <verb> … --output json | jq -e '.audit_id.absent_reason.code'
//! ```
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
//! # Fingerprint contract
//!
//! [`CliActionTarget`] is a byte-compatible mirror of the runtime
//! `CanonicalCapabilityTarget::Network` variant, and [`CliActionTarget::fingerprint`]
//! reproduces the `canonical_target_sha256` contract verbatim: `"sha256:" +
//! hex(SHA-256(canonical JSON))`. `ferrogate-cli-core` deliberately does not
//! depend on `ferrogate-runtime` (which pulls in storage, TLS, and a tokio
//! runtime — the wrong weight for a client library), so the equality is proven
//! rather than assumed: `crates/ferrogate-cli/src/ctl/fingerprint_parity_test.rs`
//! asserts byte equality against the real
//! `CanonicalCapabilityTarget::fingerprint` for the same target.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::auth::AuthSource;
use crate::command::{VerbDescriptor, VerbEffect};
use crate::context::EffectiveContext;
use crate::error::{CliError, CliResult};
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
    /// 117 coverable mutating operations in the contract today (issue #505,
    /// acceptance box 6).
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
    /// The verb addresses a collection, so the mutation names no single id
    /// until the server assigns one.
    pub const COLLECTION_SCOPED_MUTATION: &str = "collection_scoped_mutation";
    /// The request document carried no `idempotency_key`, so a retry is not
    /// provably the same call.
    pub const NO_IDEMPOTENCY_KEY_SUPPLIED: &str = "request_carries_no_idempotency_key";
    /// A local verb never reached the Control Plane API.
    pub const LOCAL_VERB: &str = "local_verb_issues_no_request";
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

/// A policy decision as reported by the Control Plane API. Field names mirror
/// the runtime `ActionDecision` serde shape so a receipt and a runtime audit
/// row join without translation.
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

/// Correlation ids the server returned, for joining to gateway evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptCorrelation {
    pub request_id: Attested<String>,
    pub trace_id: Attested<String>,
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
    pub actor: ReceiptActor,
    pub target: ReceiptTarget,
    pub decision: Attested<ReceiptDecision>,
    pub approval_id: Attested<String>,
    /// The immutable audit id. Null-with-reason on every endpoint today.
    pub audit_id: Attested<String>,
    pub rollback: Attested<RollbackPointer>,
    pub idempotency_key: Attested<String>,
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
// Revision chains and rollback pointers.
// ---------------------------------------------------------------------------

/// A resource family with a server-side revision chain, and how a mutation to
/// it is reversed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevisionedFamily {
    /// Registry group name.
    pub group: &'static str,
    /// Verb that promotes an earlier revision back to live.
    pub rollback_verb: &'static str,
    /// Verb that retires the revision this mutation created, used when the
    /// created revision is the first in its chain and there is nothing to roll
    /// back *to*.
    pub archive_verb: &'static str,
    /// Response field naming the revision number.
    pub revision_key: &'static str,
    /// Response field naming the chain id, when it differs from `id`.
    pub chain_id_keys: &'static [&'static str],
}

/// The families whose objects are revision chains. Derived from the OpenAPI
/// contract: these are the mutating groups whose 2xx schemas declare a
/// `revision`. Everything else gets a rollback pointer that is explicitly
/// absent with [`absence_codes::RESOURCE_HAS_NO_REVISIONS`] rather than a
/// missing key.
pub const REVISIONED_FAMILIES: &[RevisionedFamily] = &[
    RevisionedFamily {
        group: "guardrail-policies",
        rollback_verb: "rollback",
        archive_verb: "archive",
        revision_key: "revision",
        chain_id_keys: &["policy_id", "id"],
    },
    RevisionedFamily {
        group: "agent-schedules",
        rollback_verb: "replace",
        archive_verb: "delete",
        revision_key: "revision",
        chain_id_keys: &["id"],
    },
    RevisionedFamily {
        group: "gateway-configs",
        rollback_verb: "replace",
        archive_verb: "delete",
        revision_key: "revision",
        chain_id_keys: &["id"],
    },
];

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
const AUDIT_ID_KEYS: &[&str] = &["audit_id", "audit_event_id", "audit_log_id"];
const APPROVAL_ID_KEYS: &[&str] = &["approval_id", "tool_approval_id"];
const OBJECT_VERSION_KEYS: &[&str] = &["revision", "version", "etag", "updated_at_unix"];
const DECISION_KEYS: &[&str] = &["decision"];
const DECISION_REASON_KEYS: &[&str] = &["decision_reason", "reason"];

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
    resource_id: Attested<String>,
    idempotency_key: Attested<String>,
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
        let resource_id = Attested::or_absent(
            (!segments.is_empty()).then(|| segments.join("/")),
            absence_codes::COLLECTION_SCOPED_MUTATION,
            "the verb addresses a collection; the server assigns the id in the response",
        );
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
        let receipt = self.build_receipt(&verb, None);
        self.renderer.render(receipt)
    }

    /// Issue the mutation and produce its receipt.
    pub async fn send<T: Transport>(self, client: &ControlPlaneClient<T>) -> CliResult<VerbOutput> {
        let response = client.send(&self.spec).await?;
        let verb = self.renderer.verb().clone();
        let receipt = self.build_receipt(&verb, Some(&response));
        Ok(self.renderer.render(receipt))
    }

    /// Route on the dry-run flag. The dry-run arm never borrows `client`.
    pub async fn execute<T: Transport>(
        self,
        client: &ControlPlaneClient<T>,
    ) -> CliResult<VerbOutput> {
        if self.dry_run {
            return Ok(self.dry_run());
        }
        self.send(client).await
    }

    fn build_receipt(
        &self,
        verb: &VerbDescriptor,
        response: Option<&ApiResponse>,
    ) -> MutationReceipt {
        let body = response.map(|response| &response.body);
        let dry_detail = "this invocation was a dry run: no state-changing request was issued";
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
            actor: self.actor.clone(),
            target: ReceiptTarget {
                group: self.group.clone(),
                resource_id: self.resource_id.clone(),
                method: self.spec.method.as_str().to_string(),
                path: self.spec.path.clone(),
                action: CLI_ACTION_CLASS.to_string(),
                canonical_target: self.target.canonical_json(),
                action_fingerprint: self.target.fingerprint(),
                action_fingerprint_contract: ACTION_FINGERPRINT_CONTRACT.to_string(),
                object_version: match body {
                    Some(body) => Attested::or_absent(
                        first_scalar(body, OBJECT_VERSION_KEYS),
                        absence_codes::NO_OBJECT_VERSION,
                        "the response document named no revision, version, or etag for the \
                         changed object",
                    ),
                    None => Attested::absent(absence_codes::DRY_RUN_NOT_EXECUTED, dry_detail),
                },
            },
            decision: match body {
                Some(body) => Attested::or_absent(
                    decision_from_body(body),
                    absence_codes::NO_DECISION_IN_CONTRACT,
                    "this endpoint's response schema declares no policy decision; the mutation \
                     was authorized by the bearer token's scope alone",
                ),
                None => Attested::absent(absence_codes::DRY_RUN_NOT_EXECUTED, dry_detail),
            },
            approval_id: match body {
                Some(body) => Attested::or_absent(
                    first_scalar(body, APPROVAL_ID_KEYS),
                    absence_codes::NO_APPROVAL_ID_IN_CONTRACT,
                    "this endpoint's response schema declares no approval identifier; the \
                     mutation crossed no approval gate",
                ),
                None => Attested::absent(absence_codes::DRY_RUN_NOT_EXECUTED, dry_detail),
            },
            audit_id: match body {
                Some(body) => Attested::or_absent(
                    first_scalar(body, AUDIT_ID_KEYS),
                    absence_codes::NO_AUDIT_ID_IN_CONTRACT,
                    "this endpoint returns no audit identifier (no coverable mutating operation \
                     in the contract does); the audit row exists server-side but cannot be \
                     addressed from this response - see issue #505",
                ),
                None => Attested::absent(absence_codes::DRY_RUN_NOT_EXECUTED, dry_detail),
            },
            rollback: self.rollback_pointer(body),
            idempotency_key: self.idempotency_key.clone(),
            correlation: ReceiptCorrelation {
                request_id: match response {
                    Some(response) => Attested::or_absent(
                        response.request_id.clone(),
                        absence_codes::NO_CORRELATION_ID,
                        "the response carried no x-request-id header or envelope request_id",
                    ),
                    None => Attested::absent(absence_codes::DRY_RUN_NOT_EXECUTED, dry_detail),
                },
                trace_id: match response {
                    Some(response) => Attested::or_absent(
                        response.trace_id.clone(),
                        absence_codes::NO_CORRELATION_ID,
                        "the response carried no x-trace-id header",
                    ),
                    None => Attested::absent(absence_codes::DRY_RUN_NOT_EXECUTED, dry_detail),
                },
            },
            http_status: match response {
                Some(response) => Attested::present(response.status),
                None => Attested::absent(absence_codes::DRY_RUN_NOT_EXECUTED, dry_detail),
            },
            response: body.cloned(),
        }
    }

    /// Derive the reversal pointer for the changed object.
    fn rollback_pointer(&self, body: Option<&Value>) -> Attested<RollbackPointer> {
        let Some(family) = revisioned_family(&self.group) else {
            return Attested::absent(
                absence_codes::RESOURCE_HAS_NO_REVISIONS,
                "this resource family has no server-side revision chain, so there is no \
                 revision to roll back to; reverse it by re-applying the prior document",
            );
        };
        let Some(body) = body else {
            return Attested::absent(
                absence_codes::DRY_RUN_NOT_EXECUTED,
                "this invocation was a dry run: no revision was created, so there is nothing \
                 to roll back",
            );
        };
        let Some(revision) = first_scalar(body, &[family.revision_key]) else {
            return Attested::absent(
                absence_codes::RESPONSE_CARRIES_NO_REVISION,
                "the response named no revision, so the reversal target cannot be derived \
                 without a follow-up read",
            );
        };
        // The chain id comes from the response when the server named it, and
        // otherwise from the id segments the operator addressed - never from
        // prose, so the emitted command is always complete.
        let chain_id = first_scalar(body, family.chain_id_keys)
            .or_else(|| self.resource_id.value.clone())
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

/// How the credential was obtained — never the credential itself.
fn credential_source(auth: &AuthSource) -> String {
    match auth {
        AuthSource::None => "none".to_string(),
        AuthSource::Env { var } => format!("env:{var}"),
        AuthSource::Stdin => "stdin".to_string(),
        AuthSource::Inline { .. } => "inline".to_string(),
    }
}

/// The first scalar value found under any of `keys`, searching the document
/// depth-first. Response documents wrap the object one level down
/// (`{"object": "...", "policy": {...}}`), so a top-level-only lookup would
/// miss every identifier the server actually returns.
fn first_scalar(body: &Value, keys: &[&str]) -> Option<String> {
    fn scalar(value: &Value) -> Option<String> {
        match value {
            Value::String(text) if !text.is_empty() => Some(text.clone()),
            Value::Number(number) => Some(number.to_string()),
            _ => None,
        }
    }
    fn walk(value: &Value, keys: &[&str], depth: usize) -> Option<String> {
        if depth > 4 {
            return None;
        }
        match value {
            Value::Object(map) => {
                for key in keys {
                    if let Some(found) = map.get(*key).and_then(scalar) {
                        return Some(found);
                    }
                }
                map.values().find_map(|value| walk(value, keys, depth + 1))
            }
            Value::Array(items) => items.iter().find_map(|item| walk(item, keys, depth + 1)),
            _ => None,
        }
    }
    walk(body, keys, 0)
}

/// Project a response's decision fields onto the canonical decision vocabulary
/// (`allow`/`deny`/`ask`/`degrade`) the runtime uses. An unrecognized value is
/// **not** coerced to `allow`: it yields `None`, so the receipt reports the
/// field as absent rather than inventing a permissive decision.
fn decision_from_body(body: &Value) -> Option<ReceiptDecision> {
    let raw = first_scalar(body, DECISION_KEYS)?;
    let class = match raw.to_ascii_lowercase().as_str() {
        "allow" | "allowed" | "approve" | "approved" => DecisionClass::Allow,
        "deny" | "denied" | "reject" | "rejected" | "expired" => DecisionClass::Deny,
        "ask" | "pending" | "approval_required" => DecisionClass::Ask,
        "degrade" | "degraded" => DecisionClass::Degrade,
        _ => return None,
    };
    Some(ReceiptDecision {
        decision: class,
        reason: DecisionReason {
            code: raw,
            detail: first_scalar(body, DECISION_REASON_KEYS),
        },
    })
}

#[cfg(test)]
#[path = "receipt_test.rs"]
mod receipt_test;
