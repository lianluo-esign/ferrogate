// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Admin effective-policy diagnostics for the typed Solana x402
// spend policy (issue #351): `/admin/v1/x402-spend-policies`,
// `/admin/v1/x402-spend-policies/effective`, and
// `/admin/v1/x402-spend-policies/evaluate`. Read-only surface over the
// operator-declared config: it reports which declaration is in force for a
// tenant/project/workspace/key/run chain, at which revision, and what the pure
// policy decision is for a concrete x402 challenge -- decisions and revisions,
// never signer material or secrets.

//! Effective x402 spend-policy diagnostics (issue #351).
//!
//! The gate this surface closes is the #188 failure mode: an admin endpoint that
//! returns `200` while the runtime reads something else. Every response here is
//! derived from *the same* `config.x402_spend_policies` declarations and *the
//! same* `ferrogate_policy::authorize_x402_payment` the payment path evaluates,
//! so what an operator reads back is by construction what policy reads.
//!
//! Three operations, all read-only (no state is mutated, no payment is made, no
//! transaction is signed):
//!
//! - `GET /admin/v1/x402-spend-policies` — every declaration the operator wrote,
//!   scoped to what the caller is allowed to see.
//! - `GET /admin/v1/x402-spend-policies/effective?tenant_id=…` — the single
//!   declaration in force for a scope chain, its revision, and the inheritance
//!   evidence that explains why it won.
//! - `POST /admin/v1/x402-spend-policies/evaluate` — a dry run: parse an
//!   untrusted x402 challenge with the frozen wire contract, evaluate the
//!   effective policy against it, return the full decision evidence (reason
//!   code, policy revision, matched rule, original atomic units, computed
//!   credits, conversion snapshot, challenge hash).
//!
//! **No secret or signer field is exposed.** Responses are built from explicit,
//! closed projection structs (never a passthrough of config or runtime state),
//! and the policy model itself holds no key material — the signer lives in
//! `ferrogate-payments` and is never reachable from here. A regression test
//! asserts the serialized response carries no secret/signer-shaped field.

use http::{Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use serde::{Deserialize, Serialize};

use ferrogate_config::{
    normalize_x402_scope_id, resolve_effective_x402_spend_policy, X402PolicyScopeKind,
    X402PolicyScopeRef, X402ScopeChain, X402ScopedSpendPolicy,
};
use ferrogate_payments::{
    parse_payment_required, select_requirement, PaymentIntent, PaymentIntentDraft,
    PaymentIntentIdentity, RequestBodyHash, RequirementFilter, SCHEME_EXACT, X402_VERSION,
};
use ferrogate_policy::{
    authorize_x402_payment, ConversionSnapshot, PaymentAuthorization, PaymentAuthorizationRequest,
    PaymentDecision, ResourceRule, Rounding, SpendScope, SpendSnapshot, X402SpendPolicy,
};
use ferrogate_storage::QuotaScopeKind;

use super::admin_list_query::query_value;
use super::body::read_request_body;
use super::{FerroGateway, ProxyContext};
use crate::{
    auth::{authenticate, authorize_scoped_resource},
    responses::{write_json_error, write_json_response, AdminList},
    state::AppState,
};
use ferrogate_gateway::auth::AuthContext;

/// Cap on the evaluate request body. A base64 `PAYMENT-REQUIRED` header is
/// bounded by the wire contract's own `MAX_HEADER_BYTES`; this leaves ample room
/// for the surrounding JSON without letting an admin caller stream an unbounded
/// body into the gateway.
const MAX_EVALUATION_BODY_BYTES: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Request shapes
// ---------------------------------------------------------------------------

/// The scope chain a diagnostics call is made at. `tenant_id` is mandatory; the
/// narrower levels are optional and simply absent from resolution when omitted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct X402ScopeRequest {
    pub(crate) tenant_id: String,
    #[serde(default)]
    pub(crate) project_id: Option<String>,
    #[serde(default)]
    pub(crate) workspace_id: Option<String>,
    #[serde(default)]
    pub(crate) key_id: Option<String>,
    #[serde(default)]
    pub(crate) run_id: Option<String>,
}

impl X402ScopeRequest {
    /// Read a scope chain out of a query string
    /// (`?tenant_id=…&project_id=…&…`). Blank values are treated as absent by
    /// [`query_value`], so `?project_id=` never resolves as an empty-id scope.
    fn from_query(query: Option<&str>) -> Option<Self> {
        let tenant_id = query_value(query, "tenant_id")?;
        Some(Self {
            tenant_id,
            project_id: query_value(query, "project_id"),
            workspace_id: query_value(query, "workspace_id"),
            key_id: query_value(query, "key_id"),
            run_id: query_value(query, "run_id"),
        })
    }

    /// This request's scope chain with every id put through the config crate's
    /// single [`normalize_x402_scope_id`] definition, and blank narrower levels
    /// dropped.
    ///
    /// `GET …/effective` reads its ids through `query_value`, which trims;
    /// `POST …/evaluate` reads them out of a JSON body verbatim. Normalizing
    /// here — the one constructor both handlers, the tenancy check, the
    /// inheritance evidence and the echoed `scope` view go through — is what
    /// makes the two surfaces answer identically for the same input, which is
    /// the whole promise of an effective-policy diagnostic.
    fn normalized(&self) -> Self {
        let level = |id: &Option<String>| {
            id.as_deref()
                .map(normalize_x402_scope_id)
                .filter(|id| !id.is_empty())
                .map(str::to_string)
        };
        Self {
            tenant_id: normalize_x402_scope_id(&self.tenant_id).to_string(),
            project_id: level(&self.project_id),
            workspace_id: level(&self.workspace_id),
            key_id: level(&self.key_id),
            run_id: level(&self.run_id),
        }
    }

    fn chain(&self) -> X402ScopeChain<'_> {
        X402ScopeChain {
            tenant_id: self.tenant_id.as_str(),
            project_id: self.project_id.as_deref(),
            workspace_id: self.workspace_id.as_deref(),
            key_id: self.key_id.as_deref(),
            run_id: self.run_id.as_deref(),
        }
    }

    fn view(&self) -> X402ScopeView {
        X402ScopeView {
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            workspace_id: self.workspace_id.clone(),
            key_id: self.key_id.clone(),
            run_id: self.run_id.clone(),
        }
    }
}

/// Already-committed spend the caller wants the dry run to account for, read
/// from the durable ledger owned by #352/#354. Absent ⇒ a fresh run/window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct X402SpentRequest {
    #[serde(default)]
    pub(crate) run_spent_credits: u64,
    #[serde(default)]
    pub(crate) window_spent_credits: u64,
    /// The caller's clock, used ONLY to test the conversion rule's validity
    /// window. Absent ⇒ a policy whose conversion declares an expiry denies,
    /// because unprovable freshness must not authorize a spend.
    #[serde(default)]
    pub(crate) now_unix: Option<i64>,
}

/// A dry-run payment-authorization request: the untrusted merchant challenge
/// bound to the egress URL FerroGate would have already authorized.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct X402EvaluationRequest {
    pub(crate) scope: X402ScopeRequest,
    /// The base64 `PAYMENT-REQUIRED` header value exactly as a merchant sent it.
    /// Parsed by the frozen wire contract — never trusted as display text.
    pub(crate) payment_required: String,
    /// The resource URL the gateway already authorized egress to. A challenge
    /// whose own resource differs is a payment-redirect attempt and denies.
    pub(crate) authorized_resource_url: String,
    /// HTTP method of the already-authorized request. Defaults to `GET`, the
    /// only method that is bodyless by definition, so an omitted method can
    /// never be silently read as "any method".
    #[serde(default = "default_authorized_method")]
    pub(crate) authorized_method: String,
    /// Lowercase-hex SHA-256 of the already-authorized request body. Absent ⇒
    /// the bodyless hash, which is a concrete value, not a wildcard.
    #[serde(default)]
    pub(crate) authorized_request_body_sha256_hex: Option<String>,
    /// Already-committed spend to account for. ABSENT is materially different
    /// from zero -- a real run with committed spend would deny where a fresh
    /// one allows -- so the response reports which of the two it assumed.
    #[serde(default)]
    pub(crate) spent: Option<X402SpentRequest>,
}

fn default_authorized_method() -> String {
    "GET".to_string()
}

// ---------------------------------------------------------------------------
// Response projections (explicit, closed, secret-free)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct X402ScopeView {
    pub(crate) tenant_id: String,
    pub(crate) project_id: Option<String>,
    pub(crate) workspace_id: Option<String>,
    pub(crate) key_id: Option<String>,
    pub(crate) run_id: Option<String>,
}

/// One level of the resolved inheritance chain, broadest first, with whether a
/// declaration exists at that level. This is the "why did this policy win"
/// evidence an operator needs under incident pressure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct X402InheritanceLevel {
    pub(crate) scope_type: X402PolicyScopeKind,
    pub(crate) scope_id: String,
    pub(crate) declared: bool,
    /// True for the single level whose declaration is in force.
    pub(crate) effective: bool,
}

/// One operator declaration as listed on the admin surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct X402DeclaredPolicyView {
    pub(crate) object: &'static str,
    pub(crate) scope_type: X402PolicyScopeKind,
    pub(crate) scope_id: String,
    pub(crate) enabled: bool,
    pub(crate) revision: u64,
    pub(crate) policy: X402SpendPolicy,
}

/// The effective policy for one scope chain plus the evidence of where it came
/// from. Always defined: an unconfigured chain reports the disabled deny-all
/// default rather than 404, so "no policy" can never read as "no limit".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct X402EffectivePolicyView {
    pub(crate) object: &'static str,
    pub(crate) scope: X402ScopeView,
    pub(crate) declared: bool,
    pub(crate) resolved_scope: Option<X402PolicyScopeRef>,
    pub(crate) policy_revision: u64,
    pub(crate) policy: X402SpendPolicy,
    pub(crate) inheritance: Vec<X402InheritanceLevel>,
}

/// The atomic→credits conversion in effect for a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct X402ConversionView {
    pub(crate) numerator: u64,
    pub(crate) denominator: u64,
    pub(crate) rounding: Rounding,
    pub(crate) version: String,
    /// The validity deadline the rate declared, if any. `None` = never expires.
    pub(crate) expires_at_unix: Option<i64>,
    /// `None` iff the conversion overflowed or the ratio was impossible — which
    /// denies. Never coerced to zero.
    pub(crate) computed_credits: Option<u64>,
}

impl X402ConversionView {
    fn from_snapshot(snapshot: &ConversionSnapshot) -> Self {
        Self {
            numerator: snapshot.numerator,
            denominator: snapshot.denominator,
            rounding: snapshot.rounding,
            version: snapshot.version.clone(),
            expires_at_unix: snapshot.expires_at_unix,
            computed_credits: snapshot.computed_credits.map(|credits| credits.0),
        }
    }
}

/// The immutable decision evidence, projected field-by-field from
/// [`PaymentAuthorization`]. Nothing is forwarded wholesale, so a future field
/// added upstream cannot silently appear on the admin surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct X402DecisionView {
    /// `allow` | `approval_required` | `deny`.
    pub(crate) decision: &'static str,
    /// Stable `x402_*` reason code from the policy crate's `REASON_*` set.
    pub(crate) reason_code: &'static str,
    pub(crate) message: String,
    /// Present only for `approval_required`.
    pub(crate) approval_threshold_credits: Option<u64>,
    pub(crate) policy_revision: u64,
    pub(crate) network_caip2: String,
    pub(crate) mint: String,
    pub(crate) recipient: String,
    /// The resource the challenge claims to unlock.
    pub(crate) resource_url: String,
    /// The egress URL FerroGate already authorized, echoed for binding evidence.
    pub(crate) authorized_resource_url: String,
    /// HTTP method of the authorized request this decision is bound to.
    pub(crate) http_method: String,
    /// SHA-256 (hex) of the authorized request body.
    pub(crate) request_body_sha256_hex: String,
    /// Deterministic hash of the whole payment intent this decision authorized.
    pub(crate) intent_hash_hex: String,
    /// Deterministic seal over the decision's load-bearing content, so an audit
    /// sink can prove the decision it stored is the one policy made.
    pub(crate) decision_hash_hex: String,
    /// Deterministic challenge hash (hex) — the audit/idempotency key.
    pub(crate) challenge_hash_hex: String,
    /// The ORIGINAL on-chain atomic amount, losslessly (integer, never a float).
    pub(crate) atomic_amount: u64,
    /// The computed internal credits, or `None` when conversion failed.
    pub(crate) computed_credits: Option<u64>,
    pub(crate) conversion: X402ConversionView,
    /// The resource rule that matched, when the decision reached that stage.
    pub(crate) matched_resource: Option<ResourceRule>,
}

impl X402DecisionView {
    fn from_authorization(authorization: &PaymentAuthorization) -> Self {
        let (decision, approval_threshold_credits) = match authorization.decision() {
            PaymentDecision::Allow => ("allow", None),
            PaymentDecision::ApprovalRequired { threshold_credits } => {
                ("approval_required", Some(*threshold_credits))
            }
            PaymentDecision::Deny => ("deny", None),
        };
        let conversion = authorization.conversion();
        Self {
            decision,
            reason_code: authorization.reason_code(),
            message: authorization.message().to_string(),
            approval_threshold_credits,
            policy_revision: authorization.policy_revision(),
            network_caip2: authorization.network_caip2().to_string(),
            mint: authorization.mint().to_string(),
            recipient: authorization.recipient().to_string(),
            resource_url: authorization.resource_url().to_string(),
            authorized_resource_url: authorization.authorized_resource_url().to_string(),
            http_method: authorization.http_method().to_string(),
            request_body_sha256_hex: authorization.request_body_hash_hex().to_string(),
            intent_hash_hex: authorization.intent_hash_hex().to_string(),
            decision_hash_hex: authorization.decision_hash_hex(),
            challenge_hash_hex: authorization.challenge_hash_hex().to_string(),
            atomic_amount: conversion.atomic_amount.0,
            computed_credits: conversion.computed_credits.map(|c| c.0),
            conversion: X402ConversionView::from_snapshot(conversion),
            matched_resource: authorization.matched_resource().cloned(),
        }
    }
}

/// The ledger figures the dry run actually used, and whether the caller
/// supplied them. Echoed back because an omitted ledger makes a dry run answer
/// `allow` where the real run would `deny x402_over_run_cap`; the operator
/// reading this response must be able to see which assumption produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct X402SpentView {
    pub(crate) run_spent_credits: u64,
    pub(crate) window_spent_credits: u64,
    pub(crate) now_unix: Option<i64>,
    /// False ⇒ the caller sent no `spent` object and these are assumed zeroes,
    /// i.e. this decision describes a FRESH run/window, not the current one.
    pub(crate) supplied: bool,
}

/// A dry-run evaluation result: which policy was in force, and what it decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct X402EvaluationView {
    pub(crate) object: &'static str,
    pub(crate) scope: X402ScopeView,
    pub(crate) declared: bool,
    pub(crate) resolved_scope: Option<X402PolicyScopeRef>,
    pub(crate) policy_revision: u64,
    pub(crate) spent: X402SpentView,
    pub(crate) decision: X402DecisionView,
}

// ---------------------------------------------------------------------------
// Pure projection / evaluation
// ---------------------------------------------------------------------------

/// Build the effective-policy view for a scope chain. Pure: declarations in,
/// view out, no I/O.
pub(crate) fn build_effective_policy_view(
    declared: &[X402ScopedSpendPolicy],
    scope: &X402ScopeRequest,
) -> X402EffectivePolicyView {
    let scope = &scope.normalized();
    let chain = scope.chain();
    let effective = resolve_effective_x402_spend_policy(declared, &chain);
    let inheritance = chain
        .levels()
        .into_iter()
        .map(|(scope_type, scope_id)| {
            let is_declared = declared
                .iter()
                .any(|entry| entry.matches_scope(scope_type, scope_id));
            let effective_level = effective.source.as_ref().is_some_and(|source| {
                source.scope_type == scope_type && source.scope_id == scope_id
            });
            X402InheritanceLevel {
                scope_type,
                scope_id: scope_id.to_string(),
                declared: is_declared,
                effective: effective_level,
            }
        })
        .collect();

    X402EffectivePolicyView {
        object: "x402_effective_spend_policy",
        scope: scope.view(),
        declared: effective.is_declared(),
        resolved_scope: effective.source.clone(),
        policy_revision: effective.revision(),
        policy: effective.policy.clone(),
        inheritance,
    }
}

/// Why a dry-run evaluation could not produce a decision. Each variant maps to
/// one explicit HTTP status + stable error code; there is no catch-all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum X402EvaluationError {
    /// The merchant challenge could not be parsed/selected by the frozen wire
    /// contract (bad base64, wrong x402 version, unsupported scheme/network,
    /// ambiguous accepts entries, non-canonical amount, ...).
    InvalidChallenge(String),
    /// `authorized_resource_url` was blank — the binding target a challenge must
    /// match cannot be empty, or a challenge could unlock anything.
    MissingAuthorizedResource,
    /// The already-authorized request could not be expressed as a payment
    /// intent (unusable body hash, method, or URL). Refused rather than
    /// evaluated against a weaker binding.
    InvalidIntent(String),
    /// The declared policy that resolved for this scope failed structural
    /// validation. Config load rejects such a policy, so reaching this means the
    /// running config and the validator disagree: report it, never evaluate.
    InvalidPolicy(String),
}

impl X402EvaluationError {
    pub(crate) fn status(&self) -> StatusCode {
        match self {
            Self::InvalidChallenge(_)
            | Self::MissingAuthorizedResource
            | Self::InvalidIntent(_) => StatusCode::BAD_REQUEST,
            Self::InvalidPolicy(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::InvalidChallenge(_) => "invalid_x402_challenge",
            Self::MissingAuthorizedResource | Self::InvalidIntent(_) => {
                "invalid_x402_evaluation_request"
            }
            Self::InvalidPolicy(_) => "invalid_x402_spend_policy",
        }
    }

    pub(crate) fn message(&self) -> String {
        match self {
            Self::InvalidChallenge(reason) => {
                format!("x402 challenge could not be parsed: {reason}")
            }
            Self::MissingAuthorizedResource => {
                "authorized_resource_url must be a non-empty URL".to_string()
            }
            Self::InvalidIntent(reason) => {
                format!("the authorized request is not a valid payment intent: {reason}")
            }
            Self::InvalidPolicy(reason) => {
                format!("the effective x402 spend policy is invalid: {reason}")
            }
        }
    }
}

/// Evaluate a dry-run payment authorization against the operator-declared
/// policies. Pure: no storage, no signer, no network — it parses the challenge
/// with the frozen wire contract and calls the same
/// [`authorize_x402_payment`] the payment path uses.
///
/// The requirement filter is deliberately EMPTY (accept any recognised Solana
/// `exact` entry) so an off-policy network/mint reaches the policy layer and
/// comes back as an explicit `Deny` with a stable reason code, instead of being
/// masked as a selection error. Policy, not selection, is what an operator is
/// diagnosing here — and policy fails closed either way.
pub(crate) fn evaluate_x402_payment_request(
    declared: &[X402ScopedSpendPolicy],
    request: &X402EvaluationRequest,
) -> Result<X402EvaluationView, X402EvaluationError> {
    if request.authorized_resource_url.trim().is_empty() {
        return Err(X402EvaluationError::MissingAuthorizedResource);
    }
    // The same normalization `GET …/effective` applies, so an id that resolves
    // to a policy on the read side resolves to the SAME policy on the decision
    // side. Applied here rather than in the handler so the pure entry point --
    // which is what the unit tests and any future caller drive -- cannot be
    // reached with un-normalized ids.
    let scope = request.scope.normalized();

    let required = parse_payment_required(&request.payment_required)
        .map_err(|error| X402EvaluationError::InvalidChallenge(error.to_string()))?;
    let selected = select_requirement(&required, &RequirementFilter::default())
        .map_err(|error| X402EvaluationError::InvalidChallenge(error.to_string()))?;

    let effective = resolve_effective_x402_spend_policy(declared, &scope.chain());
    let validated = effective
        .validate()
        .map_err(|error| X402EvaluationError::InvalidPolicy(error.to_string()))?;

    // The immutable intent: the challenge bound to the method + body + URL the
    // gateway would have authorized. Built here from the SAME `selected` the
    // decision sees, so the dry run exercises the real binding rather than a
    // looser stand-in.
    let body_hash = match request.authorized_request_body_sha256_hex.as_deref() {
        Some(hex) => RequestBodyHash::from_hex(hex.trim())
            .map_err(|error| X402EvaluationError::InvalidIntent(error.to_string()))?,
        None => RequestBodyHash::empty(),
    };
    let intent = PaymentIntent::new(PaymentIntentDraft {
        x402_version: X402_VERSION,
        scheme: SCHEME_EXACT.to_string(),
        network_caip2: selected.network.caip2().to_string(),
        mint: selected.mint.clone(),
        atomic_amount: selected.atomic_amount,
        recipient: selected.recipient.clone(),
        authorized_resource_url: request.authorized_resource_url.clone(),
        http_method: request.authorized_method.clone(),
        request_body_hash: body_hash,
        challenge_hash_hex: selected.challenge_hash_hex(),
        max_timeout_seconds: selected.max_timeout_seconds,
        identity: PaymentIntentIdentity {
            tenant_id: scope.tenant_id.clone(),
            project_id: scope.project_id.clone(),
            workspace_id: scope.workspace_id.clone(),
            key_id: scope.key_id.clone(),
            run_id: scope.run_id.clone(),
            worker_id: None,
            // A dry run has no gateway request of its own to attribute to; the
            // deterministic challenge hash is the stable per-payment identity.
            request_id: selected.challenge_hash_hex(),
        },
    })
    .map_err(|error| X402EvaluationError::InvalidIntent(error.to_string()))?;

    let spent = request.spent.unwrap_or_default();
    let authorization = authorize_x402_payment(
        &validated,
        &PaymentAuthorizationRequest {
            selected: &selected,
            intent: &intent,
            scope: SpendScope {
                tenant_id: scope.tenant_id.as_str(),
                project_id: scope.project_id.as_deref(),
                workspace_id: scope.workspace_id.as_deref(),
                key_id: scope.key_id.as_deref(),
                run_id: scope.run_id.as_deref(),
            },
        },
        &SpendSnapshot {
            run_spent_credits: spent.run_spent_credits,
            window_spent_credits: spent.window_spent_credits,
            now_unix: spent.now_unix,
        },
    );

    Ok(X402EvaluationView {
        object: "x402_spend_policy_evaluation",
        scope: scope.view(),
        declared: effective.is_declared(),
        resolved_scope: effective.source.clone(),
        policy_revision: effective.revision(),
        spent: X402SpentView {
            run_spent_credits: spent.run_spent_credits,
            window_spent_credits: spent.window_spent_credits,
            now_unix: spent.now_unix,
            supplied: request.spent.is_some(),
        },
        decision: X402DecisionView::from_authorization(&authorization),
    })
}

/// Project one declaration onto the list surface.
pub(crate) fn declared_policy_view(entry: &X402ScopedSpendPolicy) -> X402DeclaredPolicyView {
    let policy = entry.policy.policy();
    X402DeclaredPolicyView {
        object: "x402_spend_policy",
        scope_type: entry.scope_type,
        // The normalized id, i.e. the id a request must name to resolve this
        // declaration -- never the raw padded text, which would tell an operator
        // to send a scope id that then resolves to something else.
        scope_id: entry.normalized_scope_id().to_string(),
        enabled: policy.enabled,
        revision: policy.revision,
        policy: policy.clone(),
    }
}

/// Map an x402 policy scope onto the tenancy scope kind the shared authorizer
/// understands. `Run` has no tenancy-store equivalent yet (an agent-run id
/// cannot be resolved to its tenant at this surface until #354's run ledger
/// lands), so it returns `None` and callers must fail closed rather than guess.
fn tenancy_scope_kind(kind: X402PolicyScopeKind) -> Option<QuotaScopeKind> {
    match kind {
        X402PolicyScopeKind::Tenant => Some(QuotaScopeKind::Tenant),
        X402PolicyScopeKind::Project => Some(QuotaScopeKind::Project),
        X402PolicyScopeKind::Workspace => Some(QuotaScopeKind::Workspace),
        X402PolicyScopeKind::Key => Some(QuotaScopeKind::Key),
        X402PolicyScopeKind::Run => None,
    }
}

/// Authorize every level of a requested scope chain for a tenant-scoped caller.
///
/// A platform operator (no `organization_id`) passes everything. A tenant-scoped
/// caller must own each named tenant/project/workspace/key — naming another
/// tenant's project is a `403`, not a silent read of someone else's money
/// policy. A run-scoped lookup is refused for a tenant-scoped caller because the
/// run→tenant mapping does not exist at this surface yet; refusing is the
/// fail-closed choice (the alternative would leak another tenant's run policy).
pub(crate) async fn authorize_scope_chain(
    state: &AppState,
    auth: &AuthContext,
    scope: &X402ScopeRequest,
) -> Result<(), ferrogate_gateway::auth::AuthError> {
    // #515: platform root is a declared property of the credential, not the
    // absence of an `organization_id`.
    if auth.is_platform_operator() {
        return Ok(());
    }
    // Normalized, so a padded id cannot be authorized at one spelling and then
    // resolved at another.
    let scope = scope.normalized();
    for (kind, id) in scope.chain().levels() {
        match tenancy_scope_kind(kind) {
            Some(tenancy) => authorize_scoped_resource(state, auth, tenancy, id).await?,
            None => {
                return Err(ferrogate_gateway::auth::AuthError {
                    status: StatusCode::FORBIDDEN,
                    code: "run_scope_requires_platform_operator",
                    message: "run-scoped x402 policy diagnostics require a platform-operator \
                              key; an agent-run id cannot yet be resolved to its tenant"
                        .into(),
                })
            }
        }
    }
    Ok(())
}

/// The declarations `auth` is allowed to see, projected for the list surface.
///
/// A platform operator (no `organization_id`) sees every declaration. A
/// tenant-scoped caller sees only the scopes that resolve to its own tenant:
/// another tenant's spend caps, payee allowlist and policy revision are a
/// competitor-visible spend profile, not public config. `Run`-scoped
/// declarations have no run→tenant mapping at this surface yet
/// (see [`tenancy_scope_kind`]), so they are omitted for tenant-scoped callers
/// rather than guessed at.
///
/// Split out of the handler so the filter is reachable without a live
/// `Session`: an access control nobody can call in a test is an access control
/// nobody can prove.
pub(crate) async fn visible_declared_policies(
    state: &AppState,
    auth: &AuthContext,
    declared: &[X402ScopedSpendPolicy],
) -> Vec<X402DeclaredPolicyView> {
    let mut data = Vec::new();
    for entry in declared {
        // #515: see `authorize_scope_chain` -- only a declared platform
        // operator sees every tenant's spend profile.
        if !auth.is_platform_operator() {
            let Some(tenancy) = tenancy_scope_kind(entry.scope_type) else {
                continue;
            };
            if authorize_scoped_resource(state, auth, tenancy, entry.normalized_scope_id())
                .await
                .is_err()
            {
                continue;
            }
        }
        data.push(declared_policy_view(entry));
    }
    data
}

impl FerroGateway {
    /// Dispatches the three read-only x402 spend-policy diagnostics operations.
    pub(super) async fn handle_admin_x402_spend_policies(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        match path {
            "/admin/v1/x402-spend-policies" => {
                self.handle_x402_spend_policy_list(session, ctx, headers, method)
                    .await
            }
            "/admin/v1/x402-spend-policies/effective" => {
                self.handle_x402_effective_spend_policy(session, ctx, headers, method, query)
                    .await
            }
            "/admin/v1/x402-spend-policies/evaluate" => {
                self.handle_x402_spend_policy_evaluation(session, ctx, headers, method)
                    .await
            }
            _ => {
                write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "x402 spend policy endpoint not found",
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    /// `GET /admin/v1/x402-spend-policies`: every operator declaration the
    /// caller is allowed to see. A tenant-scoped caller sees only the scopes it
    /// owns; run-scoped declarations are visible to the platform operator only
    /// (see [`authorize_scope_chain`]).
    async fn handle_x402_spend_policy_list(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
    ) -> PingoraResult<()> {
        if method != Method::GET {
            return write_json_error(
                session,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "x402 spend policy declarations support GET only",
                &ctx.request_id,
            )
            .await;
        }
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.read", &ctx.request_id).await {
            Ok(auth) => auth,
            Err(error) => {
                return write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        };

        let data =
            visible_declared_policies(&state, &auth, &state.config.x402_spend_policies).await;
        write_json_response(
            session,
            StatusCode::OK,
            &AdminList::new(data),
            &ctx.request_id,
        )
        .await
    }

    /// `GET /admin/v1/x402-spend-policies/effective?tenant_id=…`: the single
    /// declaration in force for a scope chain, its revision, and why it won.
    async fn handle_x402_effective_spend_policy(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        if method != Method::GET {
            return write_json_error(
                session,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "effective x402 spend policy supports GET only",
                &ctx.request_id,
            )
            .await;
        }
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.read", &ctx.request_id).await {
            Ok(auth) => auth,
            Err(error) => {
                return write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        };
        let Some(scope) = X402ScopeRequest::from_query(query) else {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_x402_scope",
                "tenant_id is required",
                &ctx.request_id,
            )
            .await;
        };
        if let Err(error) = authorize_scope_chain(&state, &auth, &scope).await {
            return write_json_error(
                session,
                error.status,
                error.code,
                error.message,
                &ctx.request_id,
            )
            .await;
        }

        let body = build_effective_policy_view(&state.config.x402_spend_policies, &scope);
        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
    }

    /// `POST /admin/v1/x402-spend-policies/evaluate`: dry-run the effective
    /// policy against a concrete, untrusted x402 challenge. Read-only — it makes
    /// no payment, signs nothing, and mutates no state.
    async fn handle_x402_spend_policy_evaluation(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
    ) -> PingoraResult<()> {
        if method != Method::POST {
            return write_json_error(
                session,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "x402 spend policy evaluation supports POST only",
                &ctx.request_id,
            )
            .await;
        }
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.read", &ctx.request_id).await {
            Ok(auth) => auth,
            Err(error) => {
                return write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        };
        let raw = match read_request_body(session, MAX_EVALUATION_BODY_BYTES).await? {
            Ok(body) => body,
            Err(too_large) => {
                return write_json_error(
                    session,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request_body_too_large",
                    format!(
                        "x402 evaluation request body exceeds {} bytes",
                        too_large.max_bytes
                    ),
                    &ctx.request_id,
                )
                .await
            }
        };
        let request: X402EvaluationRequest = match serde_json::from_slice(&raw) {
            Ok(request) => request,
            Err(error) => {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_x402_evaluation_request",
                    format!("invalid x402 evaluation request: {error}"),
                    &ctx.request_id,
                )
                .await
            }
        };
        if request.scope.tenant_id.trim().is_empty() {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_x402_scope",
                "scope.tenant_id is required",
                &ctx.request_id,
            )
            .await;
        }
        if let Err(error) = authorize_scope_chain(&state, &auth, &request.scope).await {
            return write_json_error(
                session,
                error.status,
                error.code,
                error.message,
                &ctx.request_id,
            )
            .await;
        }

        match evaluate_x402_payment_request(&state.config.x402_spend_policies, &request) {
            Ok(body) => write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await,
            Err(error) => {
                write_json_error(
                    session,
                    error.status(),
                    error.code(),
                    error.message(),
                    &ctx.request_id,
                )
                .await
            }
        }
    }
}

#[cfg(test)]
#[path = "x402_spend_policy_test.rs"]
mod x402_spend_policy_test;
