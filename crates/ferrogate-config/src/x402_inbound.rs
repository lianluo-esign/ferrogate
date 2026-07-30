// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: Operator-facing config surface for the inbound (merchant-side)
// fixed-price x402 route behind the pay.sh sidecar (issue #356). Owns only the
// document shape and secret-by-reference indirection; the enforced model and its
// validation live in `ferrogate-billing`.

//! Inbound x402 monetization config (issue #356).
//!
//! One operator document declares the single monetized route: its fixed price,
//! the sidecar admission rules, and the forward-once claim bounds. This module
//! owns the *document*; every rule it validates is the billing crate's own
//! constructor, so a config that loads is one the runtime can be built from and
//! config validity cannot drift from runtime enforcement.
//!
//! Two properties are structural rather than documented:
//!
//! - **No secret can live in a config file.** The credential fields are
//!   `*_secret_env` names only ([`InboundX402SidecarConfig`]). There is no field
//!   a secret value could be typed into, so a leaked config document leaks
//!   nothing, and [`InboundX402Config::resolve`] is the only path from a name to
//!   a value.
//! - **Exactly one route.** [`InboundX402Config::endpoint`] is a struct, not a
//!   `Vec`. "Only one fixed-price non-streaming route is enabled" is enforced by
//!   the type, not by an operator remembering to keep the list at length one.
//!
//! Disabled by default: an omitted section is [`InboundX402Config::disabled`],
//! which resolves to no gate at all. Inbound monetization is never on by
//! accident.

use std::fmt;

use ferrogate_billing::{
    ForwardClaimGuardError, InMemoryForwardClaimGuard, InboundX402ConfigError, InboundX402Endpoint,
    SidecarAdmissionPolicy, SidecarCredential, SidecarCredentialError, SidecarPolicyError,
};
use ferrogate_core::TenantContext;
use serde::{Deserialize, Serialize};

/// Default forward-claim capacity when the operator does not pin one.
pub const DEFAULT_FORWARD_CLAIM_CAPACITY: usize = 16_384;

/// The operator-authored inbound x402 section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundX402Config {
    /// Off unless explicitly enabled.
    #[serde(default)]
    pub enabled: bool,
    /// The single fixed-price endpoint. Required when `enabled`.
    #[serde(default)]
    pub endpoint: Option<InboundX402Endpoint>,
    /// Sidecar admission rules. Required when `enabled`.
    #[serde(default)]
    pub sidecar: Option<InboundX402SidecarConfig>,
    /// The FerroGate tenant every paid call on this route is attributed to.
    /// Required when `enabled` — the payer's wallet is never used as a tenant.
    #[serde(default)]
    pub attribution: Option<InboundX402AttributionConfig>,
    /// How long a forward-once claim is held, in seconds. Must be at least the
    /// endpoint's `max_timeout_seconds` (see [`InboundX402Config::validate_structure`]).
    #[serde(default)]
    pub forward_claim_ttl_secs: Option<u64>,
    /// Live-claim ceiling before the guard fails closed.
    #[serde(default)]
    pub forward_claim_capacity: Option<usize>,
}

/// Sidecar admission rules. Contains no secret value — only the *names* of
/// environment variables the secrets are read from.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundX402SidecarConfig {
    /// Environment variable holding the active shared secret the sidecar
    /// presents.
    pub credential_secret_env: String,
    /// Environment variable holding the secret being retired, during rotation.
    #[serde(default)]
    pub rotating_out_secret_env: Option<String>,
    /// Require mutual TLS between the sidecar and the private upstream.
    #[serde(default)]
    pub require_mutual_tls: bool,
    /// Pinned client-certificate subjects. Required when `require_mutual_tls`.
    #[serde(default)]
    pub pinned_client_subjects: Vec<String>,
}

/// The FerroGate identity paid calls are attributed to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundX402AttributionConfig {
    /// Tenant (organization) id. Required and non-empty.
    pub tenant_id: String,
    /// Optional project id within the tenant.
    #[serde(default)]
    pub project_id: Option<String>,
    /// Optional workspace id within the project.
    #[serde(default)]
    pub workspace_id: Option<String>,
}

impl InboundX402AttributionConfig {
    fn to_tenant_context(&self) -> TenantContext {
        TenantContext {
            organization_id: Some(self.tenant_id.clone()),
            project_id: self.project_id.clone(),
            workspace_id: self.workspace_id.clone(),
            ..TenantContext::default()
        }
    }
}

/// Structured failures for the inbound x402 section. Each variant is a distinct
/// rejection class an admin/diagnostic surface renders without string matching.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboundX402SectionError {
    /// `enabled` is true but a required sub-section is absent.
    MissingSection { section: &'static str },
    /// The fixed-price endpoint failed the billing crate's own validation.
    Endpoint(InboundX402ConfigError),
    /// A required non-empty string field is empty.
    EmptyField { field: &'static str },
    /// The sidecar admission policy is internally inconsistent.
    SidecarPolicy(SidecarPolicyError),
    /// The resolved credential is unusable.
    Credential(SidecarCredentialError),
    /// The forward-claim bounds are unusable.
    ForwardClaim(ForwardClaimGuardError),
    /// The claim TTL is shorter than the payment validity window, which would
    /// expire a claim while the very payment that created it is still spendable
    /// — the replay floor.
    ClaimTtlBelowPaymentWindow {
        /// Configured claim TTL in seconds.
        ttl_secs: u64,
        /// The endpoint's payment validity window in seconds.
        max_timeout_seconds: u64,
    },
    /// A referenced environment variable is absent or empty at resolve time.
    SecretUnresolved { env: String },
    /// The active and rotating-out secrets are read from the same variable, so
    /// the rotation could never actually differ.
    DuplicateSecretEnv { env: String },
}

impl fmt::Display for InboundX402SectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSection { section } => {
                write!(f, "inbound x402 is enabled but [{section}] is missing")
            }
            Self::Endpoint(error) => write!(f, "inbound x402 endpoint is invalid: {error}"),
            Self::EmptyField { field } => write!(f, "inbound x402 {field} must be non-empty"),
            Self::SidecarPolicy(error) => write!(f, "inbound x402 sidecar policy: {error}"),
            Self::Credential(error) => write!(f, "inbound x402 sidecar credential: {error}"),
            Self::ForwardClaim(error) => write!(f, "inbound x402 forward claim: {error}"),
            Self::ClaimTtlBelowPaymentWindow {
                ttl_secs,
                max_timeout_seconds,
            } => write!(
                f,
                "forward_claim_ttl_secs ({ttl_secs}) is below the endpoint payment window \
                 ({max_timeout_seconds}s); a claim would expire while its payment is still \
                 spendable"
            ),
            Self::SecretUnresolved { env } => {
                write!(f, "environment variable {env} is unset or empty")
            }
            Self::DuplicateSecretEnv { env } => write!(
                f,
                "active and rotating-out secrets both read {env}; rotation would be a no-op"
            ),
        }
    }
}

impl std::error::Error for InboundX402SectionError {}

/// The section after structural validation: everything that can be checked
/// without touching the environment has been.
///
/// Holding one does NOT mean the secrets exist — that is
/// [`ValidatedInboundX402Config::resolve`]'s job, deliberately separated so
/// `ferrogate check` can validate an operator's document on a machine that does
/// not hold production secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedInboundX402Config {
    endpoint: ferrogate_billing::ValidatedInboundX402Endpoint,
    sidecar: InboundX402SidecarConfig,
    tenant: TenantContext,
    forward_claim_ttl_secs: u64,
    forward_claim_capacity: usize,
}

/// A fully resolved inbound x402 configuration: validated document plus secrets
/// read from the environment. This is what the runtime builds its gate from.
#[derive(Debug, Clone)]
pub struct ResolvedInboundX402Config {
    /// The validated fixed-price endpoint.
    pub endpoint: ferrogate_billing::ValidatedInboundX402Endpoint,
    /// The sidecar admission policy, with secrets resolved.
    pub policy: SidecarAdmissionPolicy,
    /// The forward-once claim guard sized from the document.
    pub claims: InMemoryForwardClaimGuard,
}

impl InboundX402Config {
    /// The safe default: a disabled section.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Validate everything that does not require the environment.
    ///
    /// Returns `Ok(None)` when the section is disabled, so a caller can treat
    /// "absent" and "explicitly off" identically without a second branch.
    pub fn validate_structure(
        &self,
    ) -> Result<Option<ValidatedInboundX402Config>, InboundX402SectionError> {
        if !self.enabled {
            return Ok(None);
        }

        let endpoint = self
            .endpoint
            .clone()
            .ok_or(InboundX402SectionError::MissingSection {
                section: "x402_inbound.endpoint",
            })?;
        let sidecar = self
            .sidecar
            .clone()
            .ok_or(InboundX402SectionError::MissingSection {
                section: "x402_inbound.sidecar",
            })?;
        let attribution =
            self.attribution
                .clone()
                .ok_or(InboundX402SectionError::MissingSection {
                    section: "x402_inbound.attribution",
                })?;

        if attribution.tenant_id.trim().is_empty() {
            return Err(InboundX402SectionError::EmptyField {
                field: "attribution.tenant_id",
            });
        }
        if sidecar.credential_secret_env.trim().is_empty() {
            return Err(InboundX402SectionError::EmptyField {
                field: "sidecar.credential_secret_env",
            });
        }
        if let Some(rotating) = &sidecar.rotating_out_secret_env {
            if rotating.trim().is_empty() {
                return Err(InboundX402SectionError::EmptyField {
                    field: "sidecar.rotating_out_secret_env",
                });
            }
            if rotating == &sidecar.credential_secret_env {
                return Err(InboundX402SectionError::DuplicateSecretEnv {
                    env: rotating.clone(),
                });
            }
        }

        let max_timeout_seconds = endpoint.max_timeout_seconds;
        let endpoint = endpoint
            .validate()
            .map_err(InboundX402SectionError::Endpoint)?;

        // Cross-field rules are checked against the *validated* endpoint, so a
        // TTL can never be judged against an unvalidated payment window.
        let ttl_secs = self.forward_claim_ttl_secs.unwrap_or(max_timeout_seconds);
        if ttl_secs < max_timeout_seconds {
            return Err(InboundX402SectionError::ClaimTtlBelowPaymentWindow {
                ttl_secs,
                max_timeout_seconds,
            });
        }
        let capacity = self
            .forward_claim_capacity
            .unwrap_or(DEFAULT_FORWARD_CLAIM_CAPACITY);
        // Pre-flight the very constructor the runtime will call, so a config
        // that validates is one the guard can be built from.
        InMemoryForwardClaimGuard::new(ttl_secs, capacity)
            .map_err(InboundX402SectionError::ForwardClaim)?;

        // Same pre-flight for the admission policy's cross-field rules, using a
        // placeholder credential: the real secret is not needed to decide
        // whether mTLS and the subject pins agree.
        let placeholder =
            SidecarCredential::new("0".repeat(ferrogate_billing::MIN_CREDENTIAL_BYTES), None)
                .map_err(InboundX402SectionError::Credential)?;
        SidecarAdmissionPolicy::new(
            placeholder,
            sidecar.require_mutual_tls,
            sidecar.pinned_client_subjects.clone(),
            attribution.to_tenant_context(),
        )
        .map_err(InboundX402SectionError::SidecarPolicy)?;

        Ok(Some(ValidatedInboundX402Config {
            endpoint,
            sidecar,
            tenant: attribution.to_tenant_context(),
            forward_claim_ttl_secs: ttl_secs,
            forward_claim_capacity: capacity,
        }))
    }
}

impl ValidatedInboundX402Config {
    /// The validated fixed-price endpoint.
    pub fn endpoint(&self) -> &ferrogate_billing::ValidatedInboundX402Endpoint {
        &self.endpoint
    }

    /// The claim TTL this document resolved to.
    pub fn forward_claim_ttl_secs(&self) -> u64 {
        self.forward_claim_ttl_secs
    }

    /// The claim capacity this document resolved to.
    pub fn forward_claim_capacity(&self) -> usize {
        self.forward_claim_capacity
    }

    /// Read the referenced secrets from the process environment and build the
    /// runtime pieces.
    ///
    /// `lookup` is a parameter rather than a direct `std::env::var` call so the
    /// resolution path is testable without mutating process-global environment
    /// state from a concurrent test binary. [`Self::resolve`] supplies the real
    /// environment.
    pub fn resolve_with<F>(
        &self,
        lookup: F,
    ) -> Result<ResolvedInboundX402Config, InboundX402SectionError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let read = |env: &str| -> Result<String, InboundX402SectionError> {
            match lookup(env) {
                Some(value) if !value.is_empty() => Ok(value),
                _ => Err(InboundX402SectionError::SecretUnresolved {
                    env: env.to_string(),
                }),
            }
        };

        let active = read(&self.sidecar.credential_secret_env)?;
        let rotating_out = match &self.sidecar.rotating_out_secret_env {
            Some(env) => Some(read(env)?),
            None => None,
        };
        let credential = SidecarCredential::new(active, rotating_out)
            .map_err(InboundX402SectionError::Credential)?;
        let policy = SidecarAdmissionPolicy::new(
            credential,
            self.sidecar.require_mutual_tls,
            self.sidecar.pinned_client_subjects.clone(),
            self.tenant.clone(),
        )
        .map_err(InboundX402SectionError::SidecarPolicy)?;
        let claims = InMemoryForwardClaimGuard::new(
            self.forward_claim_ttl_secs,
            self.forward_claim_capacity,
        )
        .map_err(InboundX402SectionError::ForwardClaim)?;

        Ok(ResolvedInboundX402Config {
            endpoint: self.endpoint.clone(),
            policy,
            claims,
        })
    }

    /// Resolve against the process environment.
    pub fn resolve(&self) -> Result<ResolvedInboundX402Config, InboundX402SectionError> {
        self.resolve_with(|env| std::env::var(env).ok())
    }
}

/// Parse an inbound x402 section from a TOML document containing a top-level
/// `[x402_inbound]` table, and structurally validate it.
///
/// A document with no such table is a disabled section, not an error.
pub fn load_inbound_x402_toml(
    raw: &str,
) -> Result<Option<ValidatedInboundX402Config>, InboundX402TomlError> {
    #[derive(Deserialize)]
    struct Document {
        #[serde(default)]
        x402_inbound: InboundX402Config,
    }

    let document: Document = toml::from_str(raw).map_err(|error| InboundX402TomlError::Parse {
        reason: error.to_string(),
    })?;
    document
        .x402_inbound
        .validate_structure()
        .map_err(InboundX402TomlError::Section)
}

/// Failure modes of [`load_inbound_x402_toml`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboundX402TomlError {
    /// The document is not valid TOML, or the section shape does not match.
    Parse { reason: String },
    /// The section parsed but failed structural validation.
    Section(InboundX402SectionError),
}

impl fmt::Display for InboundX402TomlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse { reason } => write!(f, "invalid x402_inbound TOML: {reason}"),
            Self::Section(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for InboundX402TomlError {}

#[cfg(test)]
#[path = "x402_inbound_test.rs"]
mod x402_inbound_test;
