// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Typed, disabled-by-default x402 spend-policy configuration surface
// (issue #351). Config in -> validated typed policy out. This module owns only
// the operator-facing config wiring; the policy model, its `validate()`, and the
// structured `X402PolicyConfigError` are reused verbatim from `ferrogate-policy`.

//! Typed x402 spend-policy configuration (issue #351).
//!
//! An operator declares an x402 spend policy through FerroGate's normal
//! structured config. This module is the config-crate half of that surface: it
//! deserializes the operator's document into the frozen policy shape and hands
//! it to the policy crate's own [`X402SpendPolicy::validate`], returning a
//! [`ValidatedX402SpendPolicy`] the runtime (#354) can evaluate — or a
//! structured error an admin/diagnostic surface can render without string
//! matching.
//!
//! Two design invariants carried over from the policy slice:
//!
//! - **Disabled by default.** An operator who omits the section (or the whole
//!   config file) gets [`X402SpendPolicyConfig::disabled`], a fully-off policy
//!   that denies every payment. x402 spending is never on by accident.
//! - **No re-implemented model.** The typed policy, its validation, and its
//!   error taxonomy live in `ferrogate-policy`; this crate re-exports them and
//!   adds only the parse/validate/default wiring. There is one source of truth
//!   for what a valid policy is, so config validation can never drift from the
//!   runtime's own definition.

use serde::{Deserialize, Serialize};

// Re-export the frozen policy model so a consumer can name the whole x402 config
// shape through `ferrogate_config` without depending on `ferrogate_policy`
// directly. These are thin re-exports — the definitions stay in the policy crate.
pub use ferrogate_policy::{
    AllowedAsset, ApprovalPolicy, ConversionRule, PolicyNetwork, ResourceRule, Rounding,
    ValidatedX402SpendPolicy, X402PolicyConfigError, X402SpendCaps, X402SpendPolicy,
};

/// The operator-authored x402 spend-policy config section.
///
/// A transparent newtype over [`X402SpendPolicy`] whose only reason to exist is
/// [`Default`]: the underlying policy deliberately has no `Default` impl (a
/// "default" money policy is a footgun), but a config section must degrade to
/// something safe when omitted. That safe value is [`X402SpendPolicy::disabled`]
/// — a policy that denies every payment. Because the wrapper is
/// `#[serde(transparent)]`, it (de)serializes exactly as the bare policy, so a
/// config document is just the policy's own fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct X402SpendPolicyConfig(pub X402SpendPolicy);

impl Default for X402SpendPolicyConfig {
    fn default() -> Self {
        Self(X402SpendPolicy::disabled())
    }
}

impl X402SpendPolicyConfig {
    /// The safe default: a disabled section that denies every payment. Equivalent
    /// to [`Default::default`]; named for readability at call sites that want to
    /// express "no x402 config present".
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Borrow the raw, not-yet-validated policy the operator declared.
    pub fn policy(&self) -> &X402SpendPolicy {
        &self.0
    }

    /// Consume the section into the underlying raw policy.
    pub fn into_inner(self) -> X402SpendPolicy {
        self.0
    }

    /// Validate the declared policy into a [`ValidatedX402SpendPolicy`], reusing
    /// the policy crate's [`X402SpendPolicy::validate`] and its structured
    /// [`X402PolicyConfigError`]. This is the config → validated-policy boundary
    /// the runtime (#354) evaluates against; it never invents its own checks.
    pub fn validate(self) -> Result<ValidatedX402SpendPolicy, X402PolicyConfigError> {
        self.0.validate()
    }
}

impl From<X402SpendPolicy> for X402SpendPolicyConfig {
    fn from(policy: X402SpendPolicy) -> Self {
        Self(policy)
    }
}

/// A failure loading the x402 spend-policy config section.
///
/// Kept structurally distinct so an operator-facing surface can tell a *syntax*
/// error (the document did not shape into the typed policy at all) from a
/// *policy-invariant* violation (it shaped fine but broke a rule), without
/// parsing human strings. The invariant case carries the policy crate's own
/// [`X402PolicyConfigError`] verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X402ConfigError {
    /// The config document could not be deserialized into the typed policy shape
    /// (e.g. malformed TOML, an unknown CAIP-2 network string, a wrong type).
    /// Holds the underlying parser diagnostic as text.
    Parse(String),
    /// The document deserialized into a policy but failed structural validation.
    Invalid(X402PolicyConfigError),
}

impl std::fmt::Display for X402ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(message) => {
                write!(f, "failed to parse x402 spend policy config: {message}")
            }
            Self::Invalid(error) => write!(f, "invalid x402 spend policy config: {error}"),
        }
    }
}

impl std::error::Error for X402ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(_) => None,
            Self::Invalid(error) => Some(error),
        }
    }
}

impl From<X402PolicyConfigError> for X402ConfigError {
    fn from(error: X402PolicyConfigError) -> Self {
        Self::Invalid(error)
    }
}

/// The disabled default policy, already validated.
///
/// Returned when no x402 config section is present. Validation of the disabled
/// policy cannot fail (its conversion ratio is `1/1`), so this never panics.
pub fn default_x402_spend_policy() -> ValidatedX402SpendPolicy {
    X402SpendPolicyConfig::disabled()
        .validate()
        .expect("the disabled default x402 policy is always valid")
}

/// Parse an x402 spend-policy section from a TOML document and validate it into
/// a [`ValidatedX402SpendPolicy`].
///
/// This is the standalone config-in → validated-policy-out entry point (the
/// same TOML the runtime's structured config uses). Deserialization failures
/// surface as [`X402ConfigError::Parse`]; structural policy-invariant failures
/// surface as [`X402ConfigError::Invalid`] carrying the policy crate's
/// structured error.
///
/// A present section must be fully specified (only
/// `allow_insecure_local_resources` defaults); "no policy configured" is
/// expressed by *omitting* the section at the parent config level, which yields
/// [`default_x402_spend_policy`], not by passing an empty document here.
pub fn load_x402_spend_policy_toml(raw: &str) -> Result<ValidatedX402SpendPolicy, X402ConfigError> {
    let section: X402SpendPolicyConfig =
        toml::from_str(raw).map_err(|error| X402ConfigError::Parse(error.to_string()))?;
    section.validate().map_err(X402ConfigError::Invalid)
}

#[cfg(test)]
#[path = "x402_test.rs"]
mod x402_test;
