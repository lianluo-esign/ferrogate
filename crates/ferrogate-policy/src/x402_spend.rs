// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Typed Solana x402 spend policy + immutable payment-authorization
// decision (issue #351). Pure, side-effect-free policy layer: it reads a
// payment requirement shaped by the frozen x402/SVM wire contract (#350) and
// returns an explicit Allow / ApprovalRequired / Deny decision with a stable
// reason code and a conversion snapshot. No signer, storage, or network calls.

//! Typed x402 (Solana SVM `exact`) spend policy and the pure payment
//! authorization decision (issue #351).
//!
//! An x402 challenge is untrusted merchant input. The wire crate
//! ([`ferrogate_payments`]) parses and structurally validates it into a
//! [`SelectedPayment`]; this module decides whether a *tenant's* policy
//! actually permits paying it, at a given scope, without ever mutating state.
//!
//! Two money domains are kept strictly separate and integer-only:
//!
//! - **atomic token units** ([`AtomicAmount`]) — the on-chain SPL amount from
//!   the challenge, exactly as the wire contract parsed it.
//! - **internal wallet credits** ([`Credits`]) — the tenant's own budget
//!   domain, in which every cap and approval threshold is expressed.
//!
//! They are bridged only through a checked-integer [`ConversionRule`] with a
//! persisted [`ConversionSnapshot`]. There is no `f32`/`f64` anywhere in the
//! money path; overflow or a missing/impossible ratio denies rather than
//! silently coercing to zero.
//!
//! The decision function [`authorize_x402_payment`] is pure and deterministic:
//! same policy + request + spend snapshot always yields the same
//! [`PaymentAuthorization`]. Per-run / time-window caps are enforced against a
//! caller-supplied [`SpendSnapshot`] (read from the durable ledger owned by
//! issues #352/#354); this layer never reads or writes that ledger itself.

use std::fmt;

use ferrogate_payments::{validate_solana_address, SelectedPayment, SolanaNetwork};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Money domains
// ---------------------------------------------------------------------------

/// An on-chain SPL token amount in the mint's smallest (atomic) unit, exactly
/// as the frozen wire contract parsed it. Integer-only; never `f64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AtomicAmount(pub u64);

/// Internal wallet credits — the tenant's own money domain, in which all spend
/// caps and approval thresholds are denominated. Integer-only; never `f64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Credits(pub u64);

impl fmt::Display for AtomicAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for Credits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Policy-facing network representation
// ---------------------------------------------------------------------------

/// Policy-layer representation of a recognised Solana network. Wraps the frozen
/// wire enum ([`SolanaNetwork`]) but serialises as its canonical CAIP-2 string
/// so persisted policy is never coupled to a Rust variant name and a mainnet
/// pin is always explicit and self-describing on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PolicyNetwork(pub SolanaNetwork);

impl PolicyNetwork {
    /// Solana mainnet-beta.
    pub const MAINNET: Self = Self(SolanaNetwork::Mainnet);
    /// Solana devnet.
    pub const DEVNET: Self = Self(SolanaNetwork::Devnet);

    /// The wrapped wire-contract network.
    pub fn network(self) -> SolanaNetwork {
        self.0
    }

    /// The canonical CAIP-2 identifier for this network.
    pub fn caip2(self) -> &'static str {
        self.0.caip2()
    }

    /// True iff this is a production (mainnet) network. Mainnet requires an
    /// explicit, non-wildcard config (see [`X402SpendPolicy::validate`]).
    pub fn is_mainnet(self) -> bool {
        matches!(self.0, SolanaNetwork::Mainnet)
    }
}

impl From<SolanaNetwork> for PolicyNetwork {
    fn from(value: SolanaNetwork) -> Self {
        Self(value)
    }
}

impl Serialize for PolicyNetwork {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.caip2())
    }
}

impl<'de> Deserialize<'de> for PolicyNetwork {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let id = String::deserialize(deserializer)?;
        SolanaNetwork::from_caip2(&id)
            .map(PolicyNetwork)
            .ok_or_else(|| serde::de::Error::custom(format!("unrecognised CAIP-2 network {id:?}")))
    }
}

// ---------------------------------------------------------------------------
// Conversion rule (atomic token units -> internal credits)
// ---------------------------------------------------------------------------

/// Rounding direction applied when a conversion does not divide evenly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rounding {
    /// Round the computed credits DOWN (floor). Favours the payer.
    Down,
    /// Round the computed credits UP (ceil). Favours the treasury; the safe
    /// default for cap enforcement because it never under-counts a spend.
    Up,
}

/// Checked-integer conversion from atomic token units to internal credits:
/// `credits = round(atomic * numerator / denominator)`.
///
/// The ratio is rational and integer-only. A zero numerator or denominator is
/// an *impossible* ratio and is rejected at config validation. All arithmetic
/// is performed in `u128` and the result is range-checked back into `u64`;
/// overflow yields `None` (which the decision layer turns into a deny), never a
/// silent zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversionRule {
    /// Credits numerator. Must be non-zero.
    pub numerator: u64,
    /// Atomic-unit denominator. Must be non-zero.
    pub denominator: u64,
    /// Rounding direction for inexact divisions.
    pub rounding: Rounding,
    /// Opaque, operator-set version tag for this ratio. Persisted verbatim into
    /// every [`ConversionSnapshot`] so an auditor can tie a decision back to the
    /// exact rate that produced it.
    pub version: String,
}

impl ConversionRule {
    /// Convert an atomic amount into credits, or `None` on overflow / an
    /// impossible ratio. Never returns a coerced zero for a non-zero input with
    /// a valid ratio (unless the true rounded result is genuinely zero).
    pub fn convert(&self, atomic: AtomicAmount) -> Option<Credits> {
        if self.numerator == 0 || self.denominator == 0 {
            return None;
        }
        let scaled = u128::from(atomic.0).checked_mul(u128::from(self.numerator))?;
        let den = u128::from(self.denominator);
        let credits = match self.rounding {
            Rounding::Down => scaled / den,
            Rounding::Up => scaled.div_ceil(den),
        };
        u64::try_from(credits).ok().map(Credits)
    }

    /// Produce the immutable [`ConversionSnapshot`] evidence for `atomic`.
    pub fn snapshot(&self, atomic: AtomicAmount) -> ConversionSnapshot {
        ConversionSnapshot {
            atomic_amount: atomic,
            computed_credits: self.convert(atomic),
            numerator: self.numerator,
            denominator: self.denominator,
            rounding: self.rounding,
            version: self.version.clone(),
        }
    }
}

/// Immutable record of a single atomic→credits conversion, attached to every
/// decision as inspectable evidence. `computed_credits` is `None` iff the
/// conversion overflowed or the ratio was impossible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversionSnapshot {
    /// The original atomic token amount from the challenge.
    pub atomic_amount: AtomicAmount,
    /// The computed internal credits, or `None` on overflow / impossible ratio.
    pub computed_credits: Option<Credits>,
    /// Ratio numerator in effect at decision time.
    pub numerator: u64,
    /// Ratio denominator in effect at decision time.
    pub denominator: u64,
    /// Rounding direction in effect at decision time.
    pub rounding: Rounding,
    /// The conversion-rule version tag in effect at decision time.
    pub version: String,
}

// ---------------------------------------------------------------------------
// Typed policy config
// ---------------------------------------------------------------------------

/// One explicitly allowlisted `(network, mint)` pair. The mint is a canonical
/// base58 SPL mint address — NEVER a token symbol such as `USDC`, which config
/// validation rejects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowedAsset {
    /// Network the mint lives on.
    pub network: PolicyNetwork,
    /// Canonical base58 SPL mint address (validated 32 bytes).
    pub mint: String,
}

/// A canonicalised resource rule: which HTTPS origin + path prefix a payment
/// may unlock. Both the challenge's `resource` and the gateway's
/// already-authorized egress URL must match one of these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRule {
    /// Canonical origin, `scheme://host[:port]`. Must be `https` unless the
    /// policy explicitly enables insecure local test resources.
    pub origin: String,
    /// Path prefix that gates the origin. `"/"` allows the whole origin.
    pub path_prefix: String,
}

/// Spend caps, all denominated in internal credits except the two explicit
/// atomic bounds, which act directly on the on-chain amount. `None` means the
/// dimension is uncapped at this policy. A `Some(0)` cap is rejected by
/// validation (a zero cap can never allow anything and is almost always a
/// config mistake — use `enabled = false` to disable payments).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct X402SpendCaps {
    /// Max credits a single payment may cost.
    pub max_credits_per_payment: Option<u64>,
    /// Max credits an agent run may spend in total (enforced against the
    /// run-scoped ledger snapshot supplied by the caller).
    pub max_credits_per_run: Option<u64>,
    /// Max credits spendable within one rolling time window.
    pub max_credits_per_window: Option<u64>,
    /// Informational width of the time window in seconds. The durable window
    /// ledger is owned by #354; this field documents the intended window so the
    /// config round-trips, but this pure layer only reads the pre-aggregated
    /// [`SpendSnapshot::window_spent_credits`].
    pub window_seconds: Option<u64>,
    /// Optional hard upper bound on the raw atomic amount of a single payment,
    /// independent of the credit conversion (mirrors pay.sh's local amount cap).
    pub max_atomic_per_payment: Option<u64>,
    /// Optional lower bound on the raw atomic amount of a single payment, to
    /// reject dust / zero-value griefing challenges.
    pub min_atomic_per_payment: Option<u64>,
}

/// Approval-mode policy: payments whose computed credits exceed the threshold
/// require explicit out-of-band approval instead of auto-allow.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalPolicy {
    /// Credit threshold above which a payment (still within the hard caps)
    /// yields [`PaymentDecision::ApprovalRequired`]. `None` = never require
    /// approval (auto-allow up to the hard caps).
    pub threshold_credits: Option<u64>,
}

/// The typed, disabled-by-default x402 spend policy for one scope. This is the
/// operator-authored config the runtime reads; the decision function can only
/// be called on a [`ValidatedX402SpendPolicy`], guaranteeing the runtime never
/// evaluates a policy that failed validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X402SpendPolicy {
    /// Master switch. x402 spending is OFF unless this is explicitly `true`.
    pub enabled: bool,
    /// Monotonic policy revision for audit/diagnostics. Echoed into every
    /// decision so an operator can tie a decision to the exact config version.
    pub revision: u64,
    /// Networks payments may occur on. A mainnet entry requires an explicit,
    /// non-wildcard mint + recipient allowlist (see [`Self::validate`]).
    pub allowed_networks: Vec<PolicyNetwork>,
    /// Explicit `(network, mint)` allowlist. Empty ⇒ nothing is payable.
    pub allowed_assets: Vec<AllowedAsset>,
    /// Explicit recipient (`payTo`) allowlist, canonical base58. Empty ⇒
    /// nothing is payable.
    pub allowed_recipients: Vec<String>,
    /// Canonical resource rules the payment may unlock.
    pub allowed_resources: Vec<ResourceRule>,
    /// Spend caps and atomic bounds.
    pub caps: X402SpendCaps,
    /// Atomic→credits conversion rule + version.
    pub conversion: ConversionRule,
    /// Approval-mode policy.
    pub approval: ApprovalPolicy,
    /// Test-only escape hatch permitting `http://` resource origins. MUST be
    /// `false` in any production config; validation rejects http origins unless
    /// this is set.
    #[serde(default)]
    pub allow_insecure_local_resources: bool,
}

impl X402SpendPolicy {
    /// A fully disabled policy: the safe default. Denies every payment with
    /// [`REASON_DISABLED`].
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            revision: 0,
            allowed_networks: Vec::new(),
            allowed_assets: Vec::new(),
            allowed_recipients: Vec::new(),
            allowed_resources: Vec::new(),
            caps: X402SpendCaps::default(),
            conversion: ConversionRule {
                numerator: 1,
                denominator: 1,
                rounding: Rounding::Up,
                version: "disabled".to_string(),
            },
            approval: ApprovalPolicy::default(),
            allow_insecure_local_resources: false,
        }
    }

    /// Structurally validate this config, returning a [`ValidatedX402SpendPolicy`]
    /// on success or the first structured [`X402PolicyConfigError`] on failure.
    ///
    /// Checks run in a fixed order so the reported error is deterministic. A
    /// *disabled* policy is validated leniently (only its conversion ratio must
    /// be sane) because none of its allowlists can ever authorise a payment; an
    /// *enabled* policy must satisfy every invariant the issue names.
    pub fn validate(self) -> Result<ValidatedX402SpendPolicy, X402PolicyConfigError> {
        // The conversion ratio must be sane even when disabled: a stored policy
        // with a `0/0` ratio is corrupt regardless of the master switch.
        if self.conversion.numerator == 0 {
            return Err(X402PolicyConfigError::ImpossibleConversion {
                reason: "conversion numerator is zero".to_string(),
            });
        }
        if self.conversion.denominator == 0 {
            return Err(X402PolicyConfigError::ImpossibleConversion {
                reason: "conversion denominator is zero".to_string(),
            });
        }

        if self.enabled {
            self.validate_enabled()?;
        }

        Ok(ValidatedX402SpendPolicy(self))
    }

    fn validate_enabled(&self) -> Result<(), X402PolicyConfigError> {
        if self.allowed_networks.is_empty() {
            return Err(X402PolicyConfigError::EmptyAllowlist { field: "networks" });
        }
        if self.allowed_assets.is_empty() {
            return Err(X402PolicyConfigError::EmptyAllowlist { field: "assets" });
        }
        if self.allowed_recipients.is_empty() {
            return Err(X402PolicyConfigError::EmptyAllowlist {
                field: "recipients",
            });
        }

        // No duplicate networks.
        reject_duplicates(
            self.allowed_networks.iter().map(|n| n.caip2().to_string()),
            "network",
        )?;

        // Assets: canonical base58 mint (never a symbol), network must itself be
        // allowed, no duplicate (network, mint) pairs.
        for asset in &self.allowed_assets {
            if validate_solana_address("mint", &asset.mint).is_err() {
                return Err(X402PolicyConfigError::TokenSymbolMint {
                    value: asset.mint.clone(),
                });
            }
            if !self.allowed_networks.contains(&asset.network) {
                return Err(X402PolicyConfigError::AssetNetworkNotAllowed {
                    network: asset.network.caip2().to_string(),
                    mint: asset.mint.clone(),
                });
            }
        }
        reject_duplicates(
            self.allowed_assets
                .iter()
                .map(|a| format!("{}|{}", a.network.caip2(), a.mint)),
            "asset",
        )?;

        // Recipients: canonical base58, no duplicates.
        for recipient in &self.allowed_recipients {
            if validate_solana_address("recipient", recipient).is_err() {
                return Err(X402PolicyConfigError::InvalidRecipient {
                    value: recipient.clone(),
                });
            }
        }
        reject_duplicates(self.allowed_recipients.iter().cloned(), "recipient")?;

        // Mainnet must never be a wildcard: it needs at least one explicit
        // mainnet mint AND at least one recipient (already guaranteed non-empty
        // above, but the mainnet mint requirement is the specific guard).
        if self.allowed_networks.iter().any(|n| n.is_mainnet())
            && !self.allowed_assets.iter().any(|a| a.network.is_mainnet())
        {
            return Err(X402PolicyConfigError::WildcardMainnet);
        }

        // Resource rules: https-only (unless local test mode), no duplicates.
        for rule in &self.allowed_resources {
            let origin = canonical_origin(&rule.origin).ok_or_else(|| {
                X402PolicyConfigError::InvalidResourceOrigin {
                    origin: rule.origin.clone(),
                }
            })?;
            if origin.scheme != "https" && !self.allow_insecure_local_resources {
                return Err(X402PolicyConfigError::InsecureResource {
                    origin: rule.origin.clone(),
                });
            }
            if origin.scheme != "https" && origin.scheme != "http" {
                return Err(X402PolicyConfigError::InvalidResourceOrigin {
                    origin: rule.origin.clone(),
                });
            }
        }
        reject_duplicates(
            self.allowed_resources
                .iter()
                .map(|r| format!("{}|{}", r.origin, r.path_prefix)),
            "resource",
        )?;

        // Caps: reject any explicit zero cap and an inverted atomic band.
        self.validate_caps()?;
        // Approval threshold: a Some(0) threshold means "approve everything",
        // which is a legitimate but easy-to-mistype value; treat 0 as a config
        // error to force the operator to be explicit (use enabled=false or a
        // real threshold).
        if self.approval.threshold_credits == Some(0) {
            return Err(X402PolicyConfigError::ZeroCap {
                field: "approval.threshold_credits",
            });
        }
        Ok(())
    }

    fn validate_caps(&self) -> Result<(), X402PolicyConfigError> {
        let c = &self.caps;
        for (field, value) in [
            ("caps.max_credits_per_payment", c.max_credits_per_payment),
            ("caps.max_credits_per_run", c.max_credits_per_run),
            ("caps.max_credits_per_window", c.max_credits_per_window),
            ("caps.window_seconds", c.window_seconds),
            ("caps.max_atomic_per_payment", c.max_atomic_per_payment),
            ("caps.min_atomic_per_payment", c.min_atomic_per_payment),
        ] {
            if value == Some(0) {
                return Err(X402PolicyConfigError::ZeroCap { field });
            }
        }
        if let (Some(min), Some(max)) = (c.min_atomic_per_payment, c.max_atomic_per_payment) {
            if min > max {
                return Err(X402PolicyConfigError::InvertedAtomicBand { min, max });
            }
        }
        Ok(())
    }
}

/// A [`X402SpendPolicy`] that has passed [`X402SpendPolicy::validate`]. The
/// decision function only accepts this type, so an unvalidated (possibly
/// corrupt) policy can never be evaluated by the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedX402SpendPolicy(X402SpendPolicy);

impl ValidatedX402SpendPolicy {
    /// Borrow the underlying validated config.
    pub fn policy(&self) -> &X402SpendPolicy {
        &self.0
    }
}

fn reject_duplicates(
    items: impl Iterator<Item = String>,
    kind: &'static str,
) -> Result<(), X402PolicyConfigError> {
    let mut seen: Vec<String> = Vec::new();
    for item in items {
        if seen.contains(&item) {
            return Err(X402PolicyConfigError::DuplicateRule { kind, value: item });
        }
        seen.push(item);
    }
    Ok(())
}

/// Structured config-validation failures. Each variant is a distinct rejection
/// class an operator/admin surface can render without string matching.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum X402PolicyConfigError {
    /// An enabled policy left a required allowlist empty (nothing payable).
    EmptyAllowlist { field: &'static str },
    /// A mint value is not a valid base58 32-byte address — e.g. a token symbol
    /// like `USDC` was used where a canonical mint address is required.
    TokenSymbolMint { value: String },
    /// A recipient value is not a valid base58 32-byte Solana address.
    InvalidRecipient { value: String },
    /// An allowlisted asset names a network that is not itself allowlisted.
    AssetNetworkNotAllowed { network: String, mint: String },
    /// Mainnet is allowed but no explicit mainnet mint pins it — a wildcard
    /// mainnet allow is forbidden.
    WildcardMainnet,
    /// A resource origin is not `https` and local insecure resources are not
    /// enabled.
    InsecureResource { origin: String },
    /// A resource origin could not be canonicalised (bad scheme/host).
    InvalidResourceOrigin { origin: String },
    /// A cap/threshold was explicitly set to zero.
    ZeroCap { field: &'static str },
    /// The atomic band is inverted (`min > max`).
    InvertedAtomicBand { min: u64, max: u64 },
    /// A duplicate rule was found in an allowlist.
    DuplicateRule { kind: &'static str, value: String },
    /// The conversion ratio is impossible (zero numerator or denominator).
    ImpossibleConversion { reason: String },
}

impl fmt::Display for X402PolicyConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAllowlist { field } => {
                write!(f, "enabled x402 policy has an empty {field} allowlist")
            }
            Self::TokenSymbolMint { value } => write!(
                f,
                "mint {value:?} is not a canonical base58 mint address \
                 (token symbols are not accepted)"
            ),
            Self::InvalidRecipient { value } => {
                write!(
                    f,
                    "recipient {value:?} is not a valid base58 Solana address"
                )
            }
            Self::AssetNetworkNotAllowed { network, mint } => write!(
                f,
                "asset mint {mint} names network {network}, which is not in allowed_networks"
            ),
            Self::WildcardMainnet => write!(
                f,
                "mainnet is allowed without an explicit mainnet mint (wildcard mainnet forbidden)"
            ),
            Self::InsecureResource { origin } => {
                write!(f, "resource origin {origin:?} is not https")
            }
            Self::InvalidResourceOrigin { origin } => {
                write!(f, "resource origin {origin:?} is not a valid origin")
            }
            Self::ZeroCap { field } => write!(f, "cap {field} is zero"),
            Self::InvertedAtomicBand { min, max } => {
                write!(f, "min_atomic_per_payment {min} exceeds max {max}")
            }
            Self::DuplicateRule { kind, value } => {
                write!(f, "duplicate {kind} rule: {value}")
            }
            Self::ImpossibleConversion { reason } => write!(f, "impossible conversion: {reason}"),
        }
    }
}

impl std::error::Error for X402PolicyConfigError {}

// ---------------------------------------------------------------------------
// Decision input
// ---------------------------------------------------------------------------

/// The scope chain a payment is evaluated at. `tenant_id` is mandatory; the
/// finer scopes are optional and carried purely as decision evidence (the
/// caller has already resolved which scope's policy to pass in).
#[derive(Debug, Clone, Copy, Default)]
pub struct SpendScope<'a> {
    pub tenant_id: &'a str,
    pub project_id: Option<&'a str>,
    pub workspace_id: Option<&'a str>,
    pub key_id: Option<&'a str>,
    pub run_id: Option<&'a str>,
}

/// A caller-supplied snapshot of already-committed spend, read from the durable
/// ledger owned by #352/#354. This pure layer never reads the ledger; it only
/// checks the *proposed* payment against these pre-aggregated totals.
#[derive(Debug, Clone, Copy, Default)]
pub struct SpendSnapshot {
    /// Credits already committed by the current agent run.
    pub run_spent_credits: u64,
    /// Credits already committed within the current rolling window.
    pub window_spent_credits: u64,
}

/// A payment-authorization request: the untrusted challenge (already parsed +
/// validated by the wire contract) bound to the egress request the gateway
/// already authorized, at a scope.
#[derive(Debug, Clone, Copy)]
pub struct PaymentAuthorizationRequest<'a> {
    /// The selected, wire-validated payment requirement from the x402 challenge.
    pub selected: &'a SelectedPayment,
    /// The resource URL FerroGate already authorized egress to. The challenge's
    /// own `resource` must canonically match this — a challenge cannot redirect
    /// payment to a different URL.
    pub authorized_resource_url: &'a str,
    /// The scope this payment is evaluated at.
    pub scope: SpendScope<'a>,
}

// ---------------------------------------------------------------------------
// Decision output
// ---------------------------------------------------------------------------

/// The three-valued payment decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum PaymentDecision {
    /// The payment is authorized to proceed.
    Allow,
    /// The payment is within the hard caps but exceeds the approval threshold;
    /// it needs explicit out-of-band approval before proceeding.
    ApprovalRequired { threshold_credits: u64 },
    /// The payment is refused.
    Deny,
}

// Stable reason codes. These are part of the decision contract: callers,
// audit logs, and admin diagnostics branch on them, so they must not change.

/// Auto-allowed within every cap.
pub const REASON_ALLOWED: &str = "x402_allowed";
/// Denied: x402 spending is disabled for this scope.
pub const REASON_DISABLED: &str = "x402_disabled";
/// Denied: the challenge's network is not allowlisted.
pub const REASON_NETWORK_NOT_ALLOWED: &str = "x402_network_not_allowed";
/// Denied: the `(network, mint)` pair is not allowlisted.
pub const REASON_MINT_NOT_ALLOWED: &str = "x402_mint_not_allowed";
/// Denied: the recipient (`payTo`) is not allowlisted.
pub const REASON_RECIPIENT_NOT_ALLOWED: &str = "x402_recipient_not_allowed";
/// Denied: the challenge's resource does not match the already-authorized
/// egress URL (attempted payment redirect).
pub const REASON_RESOURCE_MISMATCH: &str = "x402_resource_mismatch";
/// Denied: the authorized resource is not covered by any resource rule.
pub const REASON_RESOURCE_NOT_ALLOWED: &str = "x402_resource_not_allowed";
/// Denied: the atomic amount is below the configured minimum.
pub const REASON_AMOUNT_BELOW_MIN: &str = "x402_amount_below_min";
/// Denied: the atomic amount exceeds the configured hard atomic cap.
pub const REASON_ATOMIC_CAP_EXCEEDED: &str = "x402_atomic_cap_exceeded";
/// Denied: the conversion overflowed or its ratio was unavailable/impossible.
pub const REASON_CONVERSION_UNAVAILABLE: &str = "x402_conversion_unavailable";
/// Denied: the payment's credits exceed the per-payment cap.
pub const REASON_OVER_PER_PAYMENT_CAP: &str = "x402_over_per_payment_cap";
/// Denied: the payment would exceed the per-run credit cap.
pub const REASON_OVER_RUN_CAP: &str = "x402_over_run_cap";
/// Denied: the payment would exceed the per-window credit cap.
pub const REASON_OVER_WINDOW_CAP: &str = "x402_over_window_cap";
/// ApprovalRequired: within caps but above the approval threshold.
pub const REASON_APPROVAL_REQUIRED: &str = "x402_approval_required";

/// The immutable, fully self-describing result of evaluating one payment
/// authorization request. Carries enough evidence to explain the decision after
/// the fact without re-running policy: the reason code, the matched rule, the
/// original atomic units, the computed credits, the conversion snapshot, and
/// the deterministic challenge hash.
///
/// This is a produced-only artifact (evidence), so it derives `Serialize` but
/// not `Deserialize`: `reason_code` is a stable `&'static str` from the
/// `REASON_*` set, which keeps the code path typed for callers at the cost of
/// not being reconstructable from arbitrary text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaymentAuthorization {
    /// The three-valued decision.
    pub decision: PaymentDecision,
    /// Stable reason code (one of the `REASON_*` constants).
    pub reason_code: &'static str,
    /// Human-readable explanation. Never load-bearing; the `reason_code` is.
    pub message: String,
    /// The policy revision that produced this decision.
    pub policy_revision: u64,
    /// CAIP-2 network of the evaluated payment.
    pub network_caip2: String,
    /// SPL mint of the evaluated payment.
    pub mint: String,
    /// Recipient (`payTo`) of the evaluated payment.
    pub recipient: String,
    /// The resource URL the payment claims to unlock.
    pub resource_url: String,
    /// Deterministic challenge hash (hex) from the wire contract — a stable
    /// idempotency / audit key.
    pub challenge_hash_hex: String,
    /// The atomic→credits conversion snapshot in effect for this decision.
    pub conversion: ConversionSnapshot,
    /// The resource rule that authorized this payment, when a decision reached
    /// the resource-match stage successfully.
    pub matched_resource: Option<ResourceRule>,
}

impl PaymentAuthorization {
    /// True iff the decision is [`PaymentDecision::Allow`].
    pub fn is_allowed(&self) -> bool {
        matches!(self.decision, PaymentDecision::Allow)
    }

    /// The computed internal credits for this payment, if the conversion
    /// succeeded.
    pub fn computed_credits(&self) -> Option<Credits> {
        self.conversion.computed_credits
    }
}

// ---------------------------------------------------------------------------
// Decision function
// ---------------------------------------------------------------------------

/// Pure, deterministic payment-authorization decision (issue #351).
///
/// Given a validated policy, a payment request shaped by the frozen wire
/// contract, and a caller-supplied spend snapshot, return an immutable
/// [`PaymentAuthorization`]. The function performs NO signer, storage, or
/// network I/O and mutates nothing; the same inputs always yield the same
/// output.
///
/// Evaluation fails closed: every check defaults to Deny, and any ambiguity
/// (unknown network/mint/recipient, resource redirect, conversion overflow,
/// checked-add overflow) is a Deny with a stable reason code.
pub fn authorize_x402_payment(
    policy: &ValidatedX402SpendPolicy,
    request: &PaymentAuthorizationRequest<'_>,
    spent: &SpendSnapshot,
) -> PaymentAuthorization {
    let p = policy.policy();
    let selected = request.selected;
    let atomic = AtomicAmount(selected.atomic_amount);
    let conversion = p.conversion.snapshot(atomic);

    // Evidence common to every branch.
    let build = |decision: PaymentDecision,
                 reason_code: &'static str,
                 message: String,
                 matched_resource: Option<ResourceRule>| PaymentAuthorization {
        decision,
        reason_code,
        message,
        policy_revision: p.revision,
        network_caip2: selected.network.caip2().to_string(),
        mint: selected.mint.clone(),
        recipient: selected.recipient.clone(),
        resource_url: selected.resource_url.clone(),
        challenge_hash_hex: selected.challenge_hash_hex(),
        conversion: conversion.clone(),
        matched_resource,
    };
    let deny = |reason_code: &'static str, message: String| {
        build(PaymentDecision::Deny, reason_code, message, None)
    };

    // 1. Master switch.
    if !p.enabled {
        return deny(
            REASON_DISABLED,
            "x402 spending is disabled for this scope".to_string(),
        );
    }

    // 2. Network allowlist.
    let network = PolicyNetwork(selected.network);
    if !p.allowed_networks.contains(&network) {
        return deny(
            REASON_NETWORK_NOT_ALLOWED,
            format!("network {} is not allowlisted", network.caip2()),
        );
    }

    // 3. (network, mint) allowlist.
    let mint_allowed = p
        .allowed_assets
        .iter()
        .any(|a| a.network == network && a.mint == selected.mint);
    if !mint_allowed {
        return deny(
            REASON_MINT_NOT_ALLOWED,
            format!(
                "mint {} on {} is not allowlisted",
                selected.mint,
                network.caip2()
            ),
        );
    }

    // 4. Recipient allowlist.
    if !p
        .allowed_recipients
        .iter()
        .any(|r| r == &selected.recipient)
    {
        return deny(
            REASON_RECIPIENT_NOT_ALLOWED,
            format!("recipient {} is not allowlisted", selected.recipient),
        );
    }

    // 5. Resource binding: the challenge's resource must equal the egress URL
    //    the gateway already authorized (no redirect), and that URL must be
    //    covered by a resource rule.
    match (
        canonical_url(&selected.resource_url),
        canonical_url(request.authorized_resource_url),
    ) {
        (Some(challenge), Some(authorized)) if challenge == authorized => {
            let matched = p
                .allowed_resources
                .iter()
                .find(|rule| resource_rule_matches(rule, &authorized));
            match matched {
                Some(rule) => {
                    // Passed binding + rule match; fall through with the rule.
                    evaluate_amount(p, &conversion, atomic, spent, &build, rule.clone())
                }
                None => deny(
                    REASON_RESOURCE_NOT_ALLOWED,
                    format!(
                        "authorized resource {} is not covered by any resource rule",
                        request.authorized_resource_url
                    ),
                ),
            }
        }
        _ => deny(
            REASON_RESOURCE_MISMATCH,
            format!(
                "challenge resource {:?} does not match authorized egress {:?}",
                selected.resource_url, request.authorized_resource_url
            ),
        ),
    }
}

/// Amount / cap / approval evaluation, reached only after identity + resource
/// binding have passed. Split out to keep [`authorize_x402_payment`] readable.
fn evaluate_amount(
    p: &X402SpendPolicy,
    conversion: &ConversionSnapshot,
    atomic: AtomicAmount,
    spent: &SpendSnapshot,
    build: &dyn Fn(
        PaymentDecision,
        &'static str,
        String,
        Option<ResourceRule>,
    ) -> PaymentAuthorization,
    rule: ResourceRule,
) -> PaymentAuthorization {
    let deny = |code: &'static str, msg: String| build(PaymentDecision::Deny, code, msg, None);
    let caps = &p.caps;

    // 6. Atomic bounds (direct, independent of the credit conversion).
    if let Some(min) = caps.min_atomic_per_payment {
        if atomic.0 < min {
            return deny(
                REASON_AMOUNT_BELOW_MIN,
                format!("atomic amount {} is below the minimum {min}", atomic.0),
            );
        }
    }
    if let Some(max) = caps.max_atomic_per_payment {
        if atomic.0 > max {
            return deny(
                REASON_ATOMIC_CAP_EXCEEDED,
                format!("atomic amount {} exceeds the hard cap {max}", atomic.0),
            );
        }
    }

    // 7. Conversion to credits. Overflow / impossible ratio denies.
    let Some(credits) = conversion.computed_credits else {
        return deny(
            REASON_CONVERSION_UNAVAILABLE,
            format!(
                "atomic amount {} could not be converted to credits \
                 (overflow or impossible ratio, version {:?})",
                atomic.0, conversion.version
            ),
        );
    };

    // 8. Per-payment credit cap.
    if let Some(cap) = caps.max_credits_per_payment {
        if credits.0 > cap {
            return deny(
                REASON_OVER_PER_PAYMENT_CAP,
                format!("payment costs {credits} credits, over the per-payment cap {cap}"),
            );
        }
    }

    // 9. Per-run cap: already-spent + proposed, with checked add (overflow
    //    denies rather than wrapping into a spuriously-small total).
    if let Some(cap) = caps.max_credits_per_run {
        match spent.run_spent_credits.checked_add(credits.0) {
            Some(total) if total <= cap => {}
            Some(total) => {
                return deny(
                    REASON_OVER_RUN_CAP,
                    format!(
                    "run spend {} + payment {credits} = {total} credits, over the run cap {cap}",
                    spent.run_spent_credits
                ),
                )
            }
            None => {
                return deny(
                    REASON_CONVERSION_UNAVAILABLE,
                    "run spend + payment overflows u64 credits".to_string(),
                )
            }
        }
    }

    // 10. Per-window cap: same checked-add discipline.
    if let Some(cap) = caps.max_credits_per_window {
        match spent.window_spent_credits.checked_add(credits.0) {
            Some(total) if total <= cap => {}
            Some(total) => {
                return deny(
                    REASON_OVER_WINDOW_CAP,
                    format!(
                        "window spend {} + payment {credits} = {total} credits, \
                         over the window cap {cap}",
                        spent.window_spent_credits
                    ),
                )
            }
            None => {
                return deny(
                    REASON_CONVERSION_UNAVAILABLE,
                    "window spend + payment overflows u64 credits".to_string(),
                )
            }
        }
    }

    // 11. Approval threshold: within the hard caps but above the threshold.
    if let Some(threshold) = p.approval.threshold_credits {
        if credits.0 > threshold {
            return build(
                PaymentDecision::ApprovalRequired {
                    threshold_credits: threshold,
                },
                REASON_APPROVAL_REQUIRED,
                format!(
                    "payment costs {credits} credits, above the approval threshold {threshold}"
                ),
                Some(rule),
            );
        }
    }

    // 12. Auto-allow.
    build(
        PaymentDecision::Allow,
        REASON_ALLOWED,
        format!("payment of {credits} credits authorized"),
        Some(rule),
    )
}

// ---------------------------------------------------------------------------
// Minimal URL canonicalisation (no external URL dependency)
// ---------------------------------------------------------------------------

/// A canonical origin: lowercased scheme + host, default port dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CanonicalOrigin {
    scheme: String,
    /// `host[:port]`, port present only when non-default.
    authority: String,
}

/// A canonical URL: origin + normalised path (no query/fragment, no trailing
/// slash except root).
#[derive(Debug, Clone, PartialEq, Eq)]
struct CanonicalUrl {
    origin: CanonicalOrigin,
    path: String,
}

impl CanonicalOrigin {
    fn as_string(&self) -> String {
        format!("{}://{}", self.scheme, self.authority)
    }
}

fn default_port(scheme: &str) -> Option<&'static str> {
    match scheme {
        "https" => Some("443"),
        "http" => Some("80"),
        _ => None,
    }
}

/// Canonicalise a `scheme://host[:port]` origin. Returns `None` for anything
/// that is not a well-formed origin.
fn canonical_origin(origin: &str) -> Option<CanonicalOrigin> {
    let (scheme, rest) = origin.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme.is_empty() || rest.is_empty() {
        return None;
    }
    // The origin string must not carry a path; reject a stray '/'.
    let host_port = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host_port != rest || host_port.is_empty() {
        return None;
    }
    Some(canonical_authority(&scheme, host_port))
}

fn canonical_authority(scheme: &str, host_port: &str) -> CanonicalOrigin {
    let (host, port) = match host_port.rsplit_once(':') {
        // Only treat the suffix as a port when it is all digits (avoids
        // mangling IPv6 — out of scope here, but this stays conservative).
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            (h, Some(p.to_string()))
        }
        _ => (host_port, None),
    };
    let authority = match port {
        Some(p) if default_port(scheme) == Some(p.as_str()) => host.to_ascii_lowercase(),
        Some(p) => format!("{}:{}", host.to_ascii_lowercase(), p),
        None => host.to_ascii_lowercase(),
    };
    CanonicalOrigin {
        scheme: scheme.to_string(),
        authority,
    }
}

/// Canonicalise a full URL down to origin + path, dropping query and fragment.
fn canonical_url(url: &str) -> Option<CanonicalUrl> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme.is_empty() || rest.is_empty() {
        return None;
    }
    let path_start = rest.find(['/', '?', '#']);
    let (host_port, tail) = match path_start {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if host_port.is_empty() {
        return None;
    }
    let origin = canonical_authority(&scheme, host_port);
    // Path is everything from the first '/' up to '?' or '#'.
    let path = if tail.starts_with('/') {
        let end = tail.find(['?', '#']).unwrap_or(tail.len());
        normalise_path(&tail[..end])
    } else {
        // tail began with '?' or '#', or was empty -> root path.
        "/".to_string()
    };
    Some(CanonicalUrl { origin, path })
}

/// Normalise a path: ensure a leading slash and strip a trailing slash except
/// for the root. Does not attempt `.`/`..` resolution (the wire contract
/// already validated the URL; this is a conservative equality key).
fn normalise_path(path: &str) -> String {
    let with_leading = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    if with_leading.len() > 1 {
        with_leading.trim_end_matches('/').to_string()
    } else {
        with_leading
    }
}

/// Does a resource rule cover a canonical URL? Origin must match exactly and the
/// URL's path must be at or under the rule's path prefix.
fn resource_rule_matches(rule: &ResourceRule, url: &CanonicalUrl) -> bool {
    let Some(rule_origin) = canonical_origin(&rule.origin) else {
        return false;
    };
    if rule_origin.as_string() != url.origin.as_string() {
        return false;
    }
    path_is_under(&url.path, &rule.path_prefix)
}

/// Is `path` at or beneath `prefix`? A `"/"` prefix matches everything; a
/// non-root prefix matches an exact hit or a `/`-delimited descendant, so
/// `/pay` covers `/pay` and `/pay/x` but never `/payment`.
fn path_is_under(path: &str, prefix: &str) -> bool {
    let prefix = normalise_path(prefix);
    if prefix == "/" {
        return true;
    }
    if path == prefix {
        return true;
    }
    path.starts_with(&prefix) && path.as_bytes().get(prefix.len()) == Some(&b'/')
}

#[cfg(test)]
#[path = "x402_spend_test.rs"]
mod x402_spend_test;
