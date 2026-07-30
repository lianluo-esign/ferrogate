// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: Admission control for requests arriving at the private FerroGate
// upstream from the pay.sh x402 sidecar (issue #356). Decides whether a request
// is genuinely sidecar-forwarded, and derives request attribution from FerroGate's
// own identity rather than from caller-supplied headers.

//! Sidecar admission for the inbound x402 monetized route (issue #356).
//!
//! The product topology is `external x402 client -> pay.sh pay server -> private
//! FerroGate upstream`. The sidecar is the only party allowed to reach the
//! protected handler, and everything the sidecar says about *who paid* is
//! evidence, never authorization. This module is the boundary that makes both
//! statements enforceable:
//!
//! 1. **Bypass refusal.** [`SidecarTransport::Untrusted`] — a request that did
//!    not arrive over the declared sidecar transport — can only ever produce
//!    [`InboundX402AdmissionError::UntrustedTransport`]. The refusal is a
//!    type-level obligation: [`SidecarAdmissionPolicy::admit`] matches on the
//!    transport before it looks at a single header, so a caller that reaches the
//!    upstream directly cannot be admitted by any header it controls.
//! 2. **Spoofed-attribution refusal.** [`RESERVED_ATTRIBUTION_HEADERS`] are the
//!    header names FerroGate itself mints downstream. A forwarded request that
//!    carries any of them is refused outright rather than having the value
//!    dropped, because a silently-stripped spoof and an honest request are
//!    indistinguishable in a log. Duplicate occurrences of a header this module
//!    reads are [`InboundX402AdmissionError::AmbiguousHeader`], never
//!    first-one-wins: a proxy chain that disagrees with itself about the payment
//!    proof must not have the disagreement resolved by header order.
//! 3. **Credential rotation without a gap.** [`SidecarCredential`] holds an
//!    active secret and an optional rotating-out secret, compares in constant
//!    time, and reports *which* matched, so an operator can watch the
//!    rotating-out counter fall to zero before retiring the old value.
//!
//! The FerroGate tenant for the monetized route is supplied by the operator's
//! config and copied verbatim onto [`AdmittedRequest`]. The payer wallet from
//! the on-chain settlement is attribution evidence carried on the revenue record
//! ([`crate::x402_inbound::InboundX402RevenueRecord::payer`]) and is never mapped
//! into [`TenantContext`] — issue #356 is explicit that payer wallet identity and
//! FerroGate tenant identity must not be silently mixed.
//!
//! No clock and no I/O live here: `now_unix` is a caller parameter throughout the
//! inbound stack, which is what keeps it usable from the Pingora hot path and
//! exhaustively testable.

use std::fmt;

use ferrogate_core::TenantContext;
use subtle::ConstantTimeEq;

/// Header the pay.sh sidecar presents to prove it is the sidecar. Its *value* is
/// the shared secret from [`SidecarCredential`]; the name is public.
pub const HEADER_SIDECAR_CREDENTIAL: &str = "x-ferrogate-sidecar-credential";

/// Header carrying the sidecar's own request identity, correlated into
/// FerroGate's request log so a paid call can be traced across the hop.
pub const HEADER_SIDECAR_REQUEST_ID: &str = "x-ferrogate-sidecar-request-id";

/// Header names FerroGate mints for its own attribution. A sidecar-forwarded
/// request that carries any of these is refused: on the monetized route the
/// caller has no legitimate reason to assert FerroGate identity, and accepting
/// (or silently stripping) one would let a payer choose the tenant its call is
/// billed and audited against.
///
/// Scope note: this refusal applies only to the monetized inbound route's
/// [`SidecarAdmissionPolicy::admit`]. `x-ferrogate-tenant` is used legitimately
/// elsewhere by the control-plane surfaces, and those paths do not run through
/// this gate.
pub const RESERVED_ATTRIBUTION_HEADERS: &[&str] = &[
    "x-ferrogate-tenant",
    "x-ferrogate-organization-id",
    "x-ferrogate-project-id",
    "x-ferrogate-workspace-id",
    "x-ferrogate-user-id",
    "x-ferrogate-api-key-id",
    "x-ferrogate-request-id",
    "x-ferrogate-trace-id",
    "x-ferrogate-payer",
    "x-ferrogate-x402-amount",
    "x-ferrogate-x402-network",
    "x-ferrogate-x402-transaction",
];

/// How the request reached the private upstream, as observed by the listener —
/// not as asserted by the request itself.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SidecarTransport {
    /// The request did not arrive over the declared sidecar transport (e.g. it
    /// hit the upstream directly on the public interface). Always refused.
    Untrusted,
    /// Plain HTTP on the private sidecar network, authenticated only by the
    /// shared credential header. Admissible only when the policy does not
    /// require mTLS.
    PrivateNetwork,
    /// Mutual TLS, with the verified client-certificate subject the listener
    /// extracted. `subject` comes from the completed TLS handshake, so it is not
    /// caller-controlled.
    MutualTls { subject: String },
}

impl SidecarTransport {
    /// Stable tag for logs and audit evidence.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Untrusted => "untrusted",
            Self::PrivateNetwork => "private_network",
            Self::MutualTls { .. } => "mutual_tls",
        }
    }
}

/// Which stored secret a presented credential matched. Surfaced so rotation is
/// observable: an operator retires the old secret when the rotating-out count
/// has been zero for a full deployment window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidecarCredentialMatch {
    /// Matched the active secret.
    Active,
    /// Matched the previous secret, still accepted during rotation.
    RotatingOut,
}

/// The shared secret(s) the sidecar presents, resolved from the environment by
/// the config layer. Never carries a value read out of a config document.
///
/// `Debug` is hand-written and redacted: a derived `Debug` would put the secret
/// into every `tracing` event that formats an admission policy.
#[derive(Clone, PartialEq, Eq)]
pub struct SidecarCredential {
    active: String,
    rotating_out: Option<String>,
}

impl fmt::Debug for SidecarCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SidecarCredential")
            .field("active", &"<redacted>")
            .field(
                "rotating_out",
                &self.rotating_out.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Why a [`SidecarCredential`] could not be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SidecarCredentialError {
    /// The active secret is empty or shorter than [`MIN_CREDENTIAL_BYTES`].
    TooShort { field: &'static str, len: usize },
    /// The rotating-out secret equals the active one, which makes rotation a
    /// no-op that looks like it is in progress.
    RotationIsIdentity,
}

impl fmt::Display for SidecarCredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { field, len } => write!(
                f,
                "{field} sidecar credential is {len} bytes, minimum is {MIN_CREDENTIAL_BYTES}"
            ),
            Self::RotationIsIdentity => {
                write!(f, "rotating-out credential is identical to the active one")
            }
        }
    }
}

impl std::error::Error for SidecarCredentialError {}

/// Minimum accepted secret length. The credential is compared in constant time
/// but a short secret is guessable regardless, so the floor is enforced at
/// construction rather than left to operator discipline.
pub const MIN_CREDENTIAL_BYTES: usize = 32;

impl SidecarCredential {
    /// Build a credential from the active secret and, during rotation, the
    /// secret being retired.
    pub fn new(
        active: impl Into<String>,
        rotating_out: Option<String>,
    ) -> Result<Self, SidecarCredentialError> {
        let active = active.into();
        if active.len() < MIN_CREDENTIAL_BYTES {
            return Err(SidecarCredentialError::TooShort {
                field: "active",
                len: active.len(),
            });
        }
        if let Some(previous) = &rotating_out {
            if previous.len() < MIN_CREDENTIAL_BYTES {
                return Err(SidecarCredentialError::TooShort {
                    field: "rotating_out",
                    len: previous.len(),
                });
            }
            if previous == &active {
                return Err(SidecarCredentialError::RotationIsIdentity);
            }
        }
        Ok(Self {
            active,
            rotating_out,
        })
    }

    /// Whether a rotation is currently in progress.
    pub fn is_rotating(&self) -> bool {
        self.rotating_out.is_some()
    }

    /// Constant-time match of a presented secret against the active and
    /// rotating-out values.
    ///
    /// Both comparisons always run — returning early on the active match would
    /// leak, through timing, whether a rotation is in progress. Length is
    /// compared first only because `ConstantTimeEq` on byte slices requires
    /// equal lengths; unequal lengths are not secret (the header length is
    /// observable on the wire anyway).
    pub fn matches(&self, presented: &str) -> Option<SidecarCredentialMatch> {
        let active_hit = constant_time_eq(presented.as_bytes(), self.active.as_bytes());
        let rotating_hit = match &self.rotating_out {
            Some(previous) => constant_time_eq(presented.as_bytes(), previous.as_bytes()),
            None => false,
        };
        match (active_hit, rotating_hit) {
            (true, _) => Some(SidecarCredentialMatch::Active),
            (false, true) => Some(SidecarCredentialMatch::RotatingOut),
            (false, false) => None,
        }
    }
}

/// Constant-time byte equality. Unequal lengths short-circuit to `false`; equal
/// lengths are compared with `subtle`'s data-independent path so a partial
/// prefix match is not measurable.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.ct_eq(right).into()
}

/// The operator-declared rules a forwarded request must satisfy before it can
/// reach the protected handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarAdmissionPolicy {
    credential: SidecarCredential,
    require_mutual_tls: bool,
    pinned_subjects: Vec<String>,
    tenant: TenantContext,
}

/// Why a policy could not be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SidecarPolicyError {
    /// mTLS is required but no client-certificate subject is pinned, which would
    /// accept any certificate the trust store happens to chain to.
    MutualTlsWithoutPinnedSubject,
    /// A pinned subject is declared while mTLS is not required — the pin would
    /// silently never be enforced.
    PinnedSubjectWithoutMutualTls,
    /// A pinned subject entry is empty.
    EmptyPinnedSubject,
}

impl fmt::Display for SidecarPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MutualTlsWithoutPinnedSubject => write!(
                f,
                "require_mutual_tls is set but no client-certificate subject is pinned"
            ),
            Self::PinnedSubjectWithoutMutualTls => write!(
                f,
                "pinned client-certificate subjects are declared but require_mutual_tls is false"
            ),
            Self::EmptyPinnedSubject => write!(f, "pinned client-certificate subject is empty"),
        }
    }
}

impl std::error::Error for SidecarPolicyError {}

impl SidecarAdmissionPolicy {
    /// Build an admission policy.
    ///
    /// The two cross-field rules exist because either half alone is a policy
    /// that reads as stricter than it is: mTLS without a pin accepts any client
    /// certificate the trust store chains, and a pin without mTLS is never
    /// consulted.
    pub fn new(
        credential: SidecarCredential,
        require_mutual_tls: bool,
        pinned_subjects: Vec<String>,
        tenant: TenantContext,
    ) -> Result<Self, SidecarPolicyError> {
        if pinned_subjects.iter().any(|subject| subject.is_empty()) {
            return Err(SidecarPolicyError::EmptyPinnedSubject);
        }
        if require_mutual_tls && pinned_subjects.is_empty() {
            return Err(SidecarPolicyError::MutualTlsWithoutPinnedSubject);
        }
        if !require_mutual_tls && !pinned_subjects.is_empty() {
            return Err(SidecarPolicyError::PinnedSubjectWithoutMutualTls);
        }
        Ok(Self {
            credential,
            require_mutual_tls,
            pinned_subjects,
            tenant,
        })
    }

    /// Whether mutual TLS is mandatory for this policy.
    pub fn require_mutual_tls(&self) -> bool {
        self.require_mutual_tls
    }

    /// The FerroGate tenant every paid call on this route is attributed to.
    pub fn tenant(&self) -> &TenantContext {
        &self.tenant
    }

    /// Header names the gateway must remove from a forwarded request before it
    /// reaches the protected handler. Admission already refuses a request that
    /// carries a reserved attribution header, so this list is the belt to that
    /// braces: it also covers the credential header, which is legitimately
    /// present and must not travel further.
    pub fn headers_to_strip(&self) -> Vec<&'static str> {
        let mut names = vec![HEADER_SIDECAR_CREDENTIAL];
        names.extend_from_slice(RESERVED_ATTRIBUTION_HEADERS);
        names
    }

    /// Admit a sidecar-forwarded request, or refuse it with a distinct reason.
    ///
    /// Order is deliberate and load-bearing: transport is decided before any
    /// header is read, so no header can rescue an untrusted path; the reserved
    /// header sweep runs before the credential check, so a spoofing attempt is
    /// reported as spoofing rather than masked by a credential failure.
    pub fn admit<'a>(
        &self,
        request: &ForwardedRequest<'a>,
    ) -> Result<AdmittedRequest, InboundX402AdmissionError> {
        match &request.transport {
            SidecarTransport::Untrusted => {
                return Err(InboundX402AdmissionError::UntrustedTransport)
            }
            SidecarTransport::PrivateNetwork => {
                if self.require_mutual_tls {
                    return Err(InboundX402AdmissionError::MutualTlsRequired);
                }
            }
            SidecarTransport::MutualTls { subject } => {
                if !self.pinned_subjects.iter().any(|pinned| pinned == subject) {
                    return Err(InboundX402AdmissionError::UnpinnedMutualTlsSubject {
                        subject: subject.clone(),
                    });
                }
            }
        }

        for reserved in RESERVED_ATTRIBUTION_HEADERS {
            if request.contains(reserved) {
                return Err(InboundX402AdmissionError::ReservedHeaderPresent { header: reserved });
            }
        }

        let presented = request
            .single(HEADER_SIDECAR_CREDENTIAL)?
            .ok_or(InboundX402AdmissionError::MissingCredential)?;
        let credential_match = self
            .credential
            .matches(presented)
            .ok_or(InboundX402AdmissionError::CredentialMismatch)?;

        let sidecar_request_id = request
            .single(HEADER_SIDECAR_REQUEST_ID)?
            .ok_or(InboundX402AdmissionError::MissingSidecarRequestId)?;
        if sidecar_request_id.is_empty() || sidecar_request_id.len() > MAX_SIDECAR_REQUEST_ID_BYTES
        {
            return Err(InboundX402AdmissionError::InvalidSidecarRequestId {
                len: sidecar_request_id.len(),
            });
        }

        Ok(AdmittedRequest {
            tenant: self.tenant.clone(),
            transport: request.transport.clone(),
            credential_match,
            sidecar_request_id: sidecar_request_id.to_string(),
            method: request.method.to_string(),
            path: request.path.to_string(),
        })
    }
}

/// Upper bound on the sidecar request id, so an unbounded header value cannot be
/// copied into every downstream log line.
pub const MAX_SIDECAR_REQUEST_ID_BYTES: usize = 200;

/// A request as observed at the private upstream listener.
///
/// Headers are borrowed name/value pairs rather than an owned map: this type is
/// built per request on the Pingora hot path, and copying the header map to make
/// an admission decision would be pure waste.
#[derive(Debug, Clone)]
pub struct ForwardedRequest<'a> {
    /// How the request reached the listener. Not caller-assertable.
    pub transport: SidecarTransport,
    /// HTTP method of the priced call.
    pub method: &'a str,
    /// Request path of the priced call.
    pub path: &'a str,
    /// All header name/value pairs, in wire order. Names are matched
    /// case-insensitively.
    pub headers: &'a [(&'a str, &'a str)],
}

impl<'a> ForwardedRequest<'a> {
    /// Whether any header with this name is present (case-insensitive).
    pub fn contains(&self, name: &str) -> bool {
        self.headers
            .iter()
            .any(|(header, _)| header.eq_ignore_ascii_case(name))
    }

    /// The single value for `name`, or `None` when absent.
    ///
    /// A duplicate occurrence is an error, never first-one-wins: on this route
    /// the headers decide who is admitted and which payment is claimed, and a
    /// proxy chain that disagrees with itself must not have the disagreement
    /// resolved by header order.
    pub fn single(&self, name: &str) -> Result<Option<&'a str>, InboundX402AdmissionError> {
        let mut found: Option<&'a str> = None;
        for (header, value) in self.headers {
            if header.eq_ignore_ascii_case(name) {
                if found.is_some() {
                    return Err(InboundX402AdmissionError::AmbiguousHeader {
                        header: name.to_string(),
                    });
                }
                found = Some(value);
            }
        }
        Ok(found)
    }
}

/// A request that passed [`SidecarAdmissionPolicy::admit`]. Holding one is the
/// proof that the request came from the sidecar; nothing downstream re-derives
/// that from headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedRequest {
    /// The FerroGate tenant from operator config — never from a caller header.
    pub tenant: TenantContext,
    /// The verified transport the request arrived on.
    pub transport: SidecarTransport,
    /// Which stored credential matched, so rotation progress is observable.
    pub credential_match: SidecarCredentialMatch,
    /// The sidecar's own request identity, for cross-hop correlation.
    pub sidecar_request_id: String,
    /// HTTP method of the priced call.
    pub method: String,
    /// Request path of the priced call.
    pub path: String,
}

impl AdmittedRequest {
    /// Whether this call was admitted on the secret being retired. A non-zero
    /// rate here means the rotation is not finished.
    pub fn used_rotating_out_credential(&self) -> bool {
        self.credential_match == SidecarCredentialMatch::RotatingOut
    }

    /// Log/audit evidence fields for this admission.
    ///
    /// Deliberately excludes the presented credential and any payment proof: the
    /// evidence surface exists to correlate a paid call, not to reproduce it.
    pub fn evidence_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("sidecar_transport", self.transport.as_str().to_string()),
            (
                "sidecar_credential",
                match self.credential_match {
                    SidecarCredentialMatch::Active => "active".to_string(),
                    SidecarCredentialMatch::RotatingOut => "rotating_out".to_string(),
                },
            ),
            ("sidecar_request_id", self.sidecar_request_id.clone()),
            ("method", self.method.clone()),
            ("path", self.path.clone()),
        ];
        if let SidecarTransport::MutualTls { subject } = &self.transport {
            fields.push(("sidecar_mtls_subject", subject.clone()));
        }
        if let Some(organization_id) = &self.tenant.organization_id {
            fields.push(("tenant", organization_id.clone()));
        }
        fields
    }
}

/// Fail-closed admission refusals. Every variant means the protected handler is
/// NOT reached.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboundX402AdmissionError {
    /// The request did not arrive over the declared sidecar transport — a direct
    /// hit on the private upstream.
    UntrustedTransport,
    /// The policy requires mutual TLS and the request arrived without it.
    MutualTlsRequired,
    /// Mutual TLS completed but the client-certificate subject is not pinned.
    UnpinnedMutualTlsSubject { subject: String },
    /// The sidecar credential header is absent.
    MissingCredential,
    /// The presented credential matched neither the active nor the rotating-out
    /// secret.
    CredentialMismatch,
    /// A header FerroGate mints for its own attribution was supplied by the
    /// caller.
    ReservedHeaderPresent { header: &'static str },
    /// A header this gate reads occurred more than once.
    AmbiguousHeader { header: String },
    /// The sidecar request-id header is absent.
    MissingSidecarRequestId,
    /// The sidecar request id is empty or oversized.
    InvalidSidecarRequestId { len: usize },
}

impl InboundX402AdmissionError {
    /// HTTP status the private upstream returns for this refusal.
    ///
    /// Everything here is 403: the caller is not the sidecar, or is asserting
    /// identity it does not own. None of it is retryable by paying, so none of
    /// it is a 402.
    pub fn http_status(&self) -> u16 {
        403
    }

    /// Stable machine-readable refusal code for logs and admin surfaces.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UntrustedTransport => "x402_inbound_untrusted_transport",
            Self::MutualTlsRequired => "x402_inbound_mutual_tls_required",
            Self::UnpinnedMutualTlsSubject { .. } => "x402_inbound_unpinned_mtls_subject",
            Self::MissingCredential => "x402_inbound_missing_credential",
            Self::CredentialMismatch => "x402_inbound_credential_mismatch",
            Self::ReservedHeaderPresent { .. } => "x402_inbound_reserved_header",
            Self::AmbiguousHeader { .. } => "x402_inbound_ambiguous_header",
            Self::MissingSidecarRequestId => "x402_inbound_missing_sidecar_request_id",
            Self::InvalidSidecarRequestId { .. } => "x402_inbound_invalid_sidecar_request_id",
        }
    }
}

impl fmt::Display for InboundX402AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UntrustedTransport => write!(
                f,
                "request did not arrive over the declared sidecar transport"
            ),
            Self::MutualTlsRequired => {
                write!(f, "mutual TLS is required for the sidecar transport")
            }
            Self::UnpinnedMutualTlsSubject { subject } => {
                write!(f, "client-certificate subject {subject:?} is not pinned")
            }
            Self::MissingCredential => write!(
                f,
                "missing {HEADER_SIDECAR_CREDENTIAL} sidecar credential header"
            ),
            Self::CredentialMismatch => write!(f, "sidecar credential did not match"),
            Self::ReservedHeaderPresent { header } => write!(
                f,
                "caller supplied reserved FerroGate attribution header {header}"
            ),
            Self::AmbiguousHeader { header } => {
                write!(f, "header {header} occurred more than once")
            }
            Self::MissingSidecarRequestId => write!(
                f,
                "missing {HEADER_SIDECAR_REQUEST_ID} sidecar request-id header"
            ),
            Self::InvalidSidecarRequestId { len } => write!(
                f,
                "sidecar request id length {len} is empty or exceeds {MAX_SIDECAR_REQUEST_ID_BYTES} bytes"
            ),
        }
    }
}

impl std::error::Error for InboundX402AdmissionError {}

#[cfg(test)]
#[path = "x402_inbound_admission_test.rs"]
mod x402_inbound_admission_test;
