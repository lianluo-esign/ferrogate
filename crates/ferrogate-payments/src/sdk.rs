// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! `solana-pay-kit` qualification record (issue #350).
//!
//! This module is gated behind the non-default `sdk-solana-pay-kit` feature.
//! It intentionally contains NO dependency on the SDK: qualification on
//! 2026-07-23 found `solana-pay-kit 0.2.0` incompatible with the workspace
//! MSRV (Rust 1.88), so the crate ships hand-rolled wire parsing and this
//! machine-readable verdict instead. See the crate README for the full
//! evidence chain and the re-qualification checklist.

use crate::error::PaymentError;

/// Qualification outcome for an external payment SDK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdkVerdict {
    /// Usable as-is at the qualified version.
    UsableAsIs,
    /// Usable only when pinned to a specific version.
    UsablePinned,
    /// Not usable yet; the recorded evidence explains why.
    NotUsableYet,
}

/// SDK crate name under qualification.
pub const SDK_NAME: &str = "solana-pay-kit";
/// Exact version qualified.
pub const SDK_VERSION: &str = "0.2.0";
/// Verdict for [`SDK_NAME`] [`SDK_VERSION`] against workspace MSRV 1.88.
pub const SDK_VERDICT: SdkVerdict = SdkVerdict::NotUsableYet;
/// One-line evidence summary (full record in the crate README).
pub const SDK_EVIDENCE: &str =
    "solana-pay-kit 0.2.0 (default-features=false, features=[\"x402\"]) \
     fails `cargo +1.88.0 check`: 16 mandatory transitive packages require \
     rustc >= 1.89 (solana-address 2.6.1, solana-pubkey 4.2.0, solana-message \
     4.4.0, wincode 0.5.5, ...; cargo-platform 0.3.3 requires 1.91) with no \
     1.88-compatible pin, and the minimal feature set still locks 553 \
     packages including the full Solana RPC client stack (solana-client, \
     solana-rpc-client are non-optional).";

/// The error any SDK-backed code path returns in this build.
pub fn sdk_unavailable() -> PaymentError {
    PaymentError::SdkIncompatible {
        detail: "solana-pay-kit 0.2.0 requires rustc >= 1.89; workspace MSRV is 1.88 \
             (see ferrogate-payments README, issue #350)",
    }
}
