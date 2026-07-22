// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Typed error surface for the x402/SVM payment adapter.
//!
//! Every rejection is a distinct variant so callers (policy, billing,
//! observability) can branch on the failure class without string matching.
//! Invalid input is NEVER coerced into a default value — in particular an
//! invalid atomic amount is a hard error, never `0`.

use std::error::Error;
use std::fmt;

/// Failure classes for parsing, selecting, proving, and settling an x402 V2
/// payment over the Solana SVM `exact` scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PaymentError {
    /// Header or embedded JSON is syntactically invalid (bad base64, bad
    /// JSON, wrong types, missing required fields, conflicting `accepts`
    /// entries).
    MalformedHeader {
        /// Which wire artifact was being parsed (e.g. `PAYMENT-REQUIRED`).
        header: &'static str,
        /// Human-readable reason; never contains payload bytes.
        reason: String,
    },
    /// Header exceeds the adapter's hard size cap (pre-decode bytes).
    OversizedHeader {
        header: &'static str,
        limit: usize,
        actual: usize,
    },
    /// `x402Version` is present but not the supported protocol version (2).
    UnsupportedVersion {
        /// The version value found on the wire (stringified if non-integer).
        found: String,
    },
    /// The `accepts` array contained no entry this adapter can satisfy
    /// (no supported scheme/network combination at all).
    NoAcceptableRequirement,
    /// A requirement matched on scheme but named a network this adapter does
    /// not recognise / was not configured to accept.
    UnsupportedNetwork { network: String },
    /// A requirement named a payment scheme other than `exact`.
    UnsupportedScheme { scheme: String },
    /// The token mint (`asset`) is not in the caller-supplied allowlist.
    UnsupportedMint { mint: String },
    /// The atomic amount is invalid: empty, non-digit, signed, fractional,
    /// zero, non-canonical (leading zeros), or overflows `u64`.
    InvalidAmount { amount: String, reason: String },
    /// `payTo` / `extra.feePayer` is not a valid base58-encoded 32-byte
    /// Solana address.
    InvalidRecipient { field: &'static str, value: String },
    /// `maxTimeoutSeconds` is missing, non-integer, zero/negative (already
    /// expired), or above the safety cap.
    InvalidTimeout { reason: String },
    /// The injected signer refused to sign the transfer intent.
    SignerRejected { reason: String },
    /// The signer produced output the adapter cannot turn into a valid
    /// `PAYMENT-SIGNATURE` proof (empty / oversized transaction bytes, ...).
    ProofBuildFailed { reason: String },
    /// The `PAYMENT-RESPONSE` settlement header is malformed or inconsistent
    /// (bad base64/JSON, wrong network, invalid transaction signature).
    MalformedSettlement { reason: String },
    /// The optional payment SDK is not usable in this build (MSRV or
    /// dependency incompatibility). Carries the qualification evidence tag.
    SdkIncompatible { detail: &'static str },
}

impl fmt::Display for PaymentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedHeader { header, reason } => {
                write!(f, "malformed {header} header: {reason}")
            }
            Self::OversizedHeader {
                header,
                limit,
                actual,
            } => write!(
                f,
                "oversized {header} header: {actual} bytes exceeds cap of {limit}"
            ),
            Self::UnsupportedVersion { found } => {
                write!(f, "unsupported x402 version {found} (supported: 2)")
            }
            Self::NoAcceptableRequirement => {
                write!(f, "no acceptable payment requirement in accepts")
            }
            Self::UnsupportedNetwork { network } => {
                write!(f, "unsupported network {network}")
            }
            Self::UnsupportedScheme { scheme } => {
                write!(f, "unsupported payment scheme {scheme}")
            }
            Self::UnsupportedMint { mint } => write!(f, "unsupported token mint {mint}"),
            Self::InvalidAmount { amount, reason } => {
                write!(f, "invalid atomic amount {amount:?}: {reason}")
            }
            Self::InvalidRecipient { field, value } => {
                write!(f, "invalid recipient in {field}: {value:?}")
            }
            Self::InvalidTimeout { reason } => write!(f, "invalid maxTimeoutSeconds: {reason}"),
            Self::SignerRejected { reason } => write!(f, "signer rejected payment: {reason}"),
            Self::ProofBuildFailed { reason } => write!(f, "proof build failed: {reason}"),
            Self::MalformedSettlement { reason } => {
                write!(f, "malformed PAYMENT-RESPONSE settlement header: {reason}")
            }
            Self::SdkIncompatible { detail } => {
                write!(f, "payment SDK incompatible with this build: {detail}")
            }
        }
    }
}

impl Error for PaymentError {}
